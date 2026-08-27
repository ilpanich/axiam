//! Actix-Web middleware that automatically logs HTTP requests to the audit trail.
//!
//! Captures: HTTP method, path, authenticated user, client IP, and response
//! status code. Audit writes are dispatched to a bounded background worker so
//! they don't block the response and backpressure is controlled.
//!
//! Unauthenticated requests are logged with `ActorType::System`, nil UUIDs,
//! and `"authenticated": false` in metadata so they remain distinguishable.

use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use actix_web::HttpMessage;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::AuditLogRepository;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Paths that should not generate audit entries.
const SKIP_PATHS: &[&str] = &["/health", "/ready"];

/// Which tenant and organization a request concerns, for a request that carries
/// no usable access token.
///
/// The middleware normally learns this from the verified JWT. The requests that
/// matter most to a security notification rule — a failed login, a lockout, a
/// password reset — have no token by definition: the whole point is that the
/// caller did not authenticate. Those entries were therefore written with
/// `ActorType::System` and a **nil** tenant id, which is why a notification rule
/// for `login_failure` or `account_locked` could never match one: rules are
/// looked up by tenant.
///
/// A handler that has established which tenant a request is about — `/auth/login`
/// proves the tenant∈organization binding before it touches a credential —
/// inserts one of these into the request extensions. The value comes from the
/// handler's own verified lookup, never from the request body, so it is not a
/// client-supplied tenant id being trusted.
///
/// The verified token still wins where both are present.
///
/// # Examples
///
/// ```ignore
/// // Inside an unauthenticated handler, once the tenant is proven:
/// use actix_web::HttpMessage;
/// req.extensions_mut()
///     .insert(AuditAttribution { tenant_id, org_id });
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditAttribution {
    /// The tenant the request concerns.
    pub tenant_id: Uuid,
    /// That tenant's organization.
    pub org_id: Uuid,
}

/// One audit entry plus the organization it belongs to.
///
/// `CreateAuditLogEntry` carries a tenant but no organization, and the
/// notification dispatcher needs both: the tenant to find matching rules, the
/// organization to resolve the effective email configuration the mail consumer
/// will send with. Rather than widening the persisted audit row — the
/// organization is derivable from the tenant and storing it would be a second
/// copy that can disagree — it travels beside the entry on the channel and is
/// dropped before the write.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// The entry to append.
    pub entry: CreateAuditLogEntry,
    /// The organization owning `entry.tenant_id`, or nil when unknown.
    pub org_id: Uuid,
}

/// Something that reacts to an audit event after it has been recorded.
///
/// Exactly one implementation today — the notification-rule dispatcher, which
/// turns "a certificate was revoked" into email to the addresses an
/// administrator listed. It is a trait rather than a direct call because the
/// dispatcher is generic over its rule repository and its mail publisher, and
/// `AuditMiddleware` is deliberately not generic over anything: it wraps every
/// route in the application, so a type parameter here would spread through the
/// whole server builder.
///
/// Runs **after** the append and never blocks the response — the worker is
/// already off the request path. An implementation must not propagate errors;
/// audit recording is the guarantee here, and notification is best-effort on top
/// of it.
pub trait AuditEventSink: Send + Sync {
    /// React to `event`. Errors must be logged and swallowed, not returned.
    fn on_event<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// Default capacity for the audit write channel.
const CHANNEL_CAPACITY: usize = 4096;

/// Middleware factory for audit logging.
///
/// Wraps every HTTP request/response pair and emits an audit log entry for
/// each handled request. A bounded channel dispatches entries to a
/// background worker task.
#[derive(Clone)]
pub struct AuditMiddleware {
    tx: mpsc::Sender<AuditEvent>,
    shutting_down: Arc<AtomicBool>,
}

impl AuditMiddleware {
    /// Create the middleware and spawn its background worker.
    ///
    /// The worker reads from a bounded channel and appends entries to the
    /// given `AuditLogRepository`. The channel capacity defaults to
    /// [`CHANNEL_CAPACITY`]; when full, new audit entries are dropped
    /// (with a warning) to avoid blocking request handling.
    ///
    /// No [`AuditEventSink`], so no notification rules fire. Use
    /// [`Self::spawn_with_sink`] in the composition root.
    pub fn spawn<A: AuditLogRepository + 'static>(repo: A) -> Self {
        Self::spawn_with_sink(repo, None)
    }

    /// As [`Self::spawn`], plus a sink that reacts to every recorded event.
    ///
    /// This is how notification rules reach the audit stream. Without a sink
    /// the rules an administrator configures are stored, listed by the API,
    /// shown in the admin UI — and consulted by nothing.
    pub fn spawn_with_sink<A: AuditLogRepository + 'static>(
        repo: A,
        sink: Option<Arc<dyn AuditEventSink>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let shutting_down = Arc::new(AtomicBool::new(false));
        tokio::spawn(audit_worker(rx, repo, sink, Arc::clone(&shutting_down)));
        Self { tx, shutting_down }
    }

    /// Tell the worker that the channel is about to close on purpose.
    ///
    /// The worker cannot tell the two reasons apart on its own. Its channel
    /// closes when the last sender drops, and at shutdown that is exactly what
    /// a clean teardown does — so every orderly stop logged
    /// `Audit worker channel closed — no more entries will be written` at WARN,
    /// once per boot, describing nothing wrong. A warning that fires on every
    /// healthy run is one operators learn to scroll past, which is precisely
    /// the wrong reflex for the one line that says the audit trail stopped
    /// while the server was still answering requests.
    ///
    /// The composition root calls this immediately before it begins tearing
    /// down. Anything that closes the channel *without* this having been called
    /// keeps the warning, because that case is real: audit entries are being
    /// discarded by a process that is still serving.
    pub fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
    }

    /// Whether [`Self::begin_shutdown`] has been called.
    ///
    /// The worker consults this when its channel closes, to decide whether the
    /// close was the orderly one it was told to expect.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }
}

async fn audit_worker<A: AuditLogRepository>(
    mut rx: mpsc::Receiver<AuditEvent>,
    repo: A,
    sink: Option<Arc<dyn AuditEventSink>>,
    shutting_down: Arc<AtomicBool>,
) {
    let mut written: u64 = 0;
    while let Some(event) = rx.recv().await {
        // Append first. The audit record is the guarantee; a notification is
        // best-effort on top of it, and an event nobody was emailed about is a
        // far smaller failure than one that was never recorded.
        if let Err(e) = repo.append(event.entry.clone()).await {
            tracing::warn!(error = %e, "Failed to write audit log entry");
        }

        written += 1;

        if let Some(ref sink) = sink {
            sink.on_event(&event).await;
        }
    }
    if shutting_down.load(Ordering::SeqCst) {
        tracing::info!(
            entries_written = written,
            "audit worker drained and stopped"
        );
    } else {
        tracing::warn!(
            entries_written = written,
            "Audit worker channel closed while the server is still running — no more \
             entries will be written"
        );
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuditMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = AuditMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuditMiddlewareService {
            service,
            tx: self.tx.clone(),
        }))
    }
}

pub struct AuditMiddlewareService<S> {
    service: S,
    tx: mpsc::Sender<AuditEvent>,
}

impl<S, B> Service<ServiceRequest> for AuditMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        ctx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_string();

        // Skip health/readiness endpoints.
        if SKIP_PATHS.iter().any(|p| path.starts_with(p)) {
            return Box::pin(self.service.call(req));
        }

        let method = req.method().to_string();
        let ip_address = req
            .connection_info()
            .realip_remote_addr()
            .map(|s| s.to_owned());

        // Extract cached claims from extensions (set by middleware or
        // extractor) or try to validate the JWT now and cache the result.
        let user_info = extract_or_cache_user_info(&req);

        // A handler may name the tenant an unauthenticated request concerns —
        // see [`AuditAttribution`]. It can only do so *while running*, so this
        // is read from the response's extensions after the call, not from the
        // request's before it.
        let tx = self.tx.clone();
        let fut = self.service.call(req);

        Box::pin(async move {
            let (status, result, attribution) = match fut.await {
                Ok(res) => {
                    let s = res.status().as_u16();
                    let attribution = res
                        .request()
                        .extensions()
                        .get::<AuditAttribution>()
                        .copied();
                    (s, Ok(res), attribution)
                }
                Err(err) => {
                    let s = err.as_response_error().status_code().as_u16();
                    (s, Err(err), None)
                }
            };

            let outcome = if status < 400 {
                AuditOutcome::Success
            } else if status == 403 {
                AuditOutcome::Denied
            } else {
                AuditOutcome::Failure
            };

            // The verified token first: it is proof, where an attribution is a
            // handler's assertion. They agree in practice; where they cannot
            // both exist, whichever is present is used.
            let (actor_id, tenant_id, org_id, actor_type) = match user_info {
                Some((uid, tid, oid)) => (uid, tid, oid, ActorType::User),
                None => match attribution {
                    Some(a) => (Uuid::nil(), a.tenant_id, a.org_id, ActorType::System),
                    None => (Uuid::nil(), Uuid::nil(), Uuid::nil(), ActorType::System),
                },
            };

            let entry = CreateAuditLogEntry {
                tenant_id,
                actor_id,
                actor_type,
                action: format!("{method} {path}"),
                resource_id: None,
                outcome,
                ip_address,
                metadata: Some(serde_json::json!({
                    "http_status": status,
                    "authenticated": user_info.is_some(),
                })),
            };

            if tx.try_send(AuditEvent { entry, org_id }).is_err() {
                tracing::error!(
                    audit_dropped = true,
                    method = %method,
                    path = %path,
                    "Audit channel full — entry dropped. Investigate CHANNEL_CAPACITY."
                );
            }

            result
        })
    }
}

/// Extract `(user_id, tenant_id, org_id)` from cached extensions, or validate
/// the JWT and cache it.
///
/// The organization is returned as well as the tenant because the notification
/// dispatcher needs it to resolve the effective email configuration — it was
/// already being parsed here for the cache and then thrown away.
fn extract_or_cache_user_info(req: &ServiceRequest) -> Option<(Uuid, Uuid, Uuid)> {
    use actix_web::web;
    use axiam_auth::config::AuthConfig;
    use axiam_auth::token::{CachedUserIdentity, validate_access_token};

    // Check cache first.
    if let Some(cached) = req.extensions().get::<Arc<CachedUserIdentity>>() {
        return Some((cached.user_id, cached.tenant_id, cached.org_id));
    }

    let config = req.app_data::<web::Data<AuthConfig>>()?;

    // Prefer an `Authorization: Bearer <jwt>` header (service-to-service / API
    // clients), but fall back to the `axiam_access` cookie. The admin UI uses
    // cookie-based auth, so authenticated browser requests carry the access token
    // as a cookie, not a header — without this fallback every UI action was logged
    // as `System` with a nil tenant_id and never appeared in the tenant audit log.
    let credentials: String = match req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
    {
        Some(header) => {
            let header = header.trim();
            let mut parts = header.splitn(2, char::is_whitespace);
            let scheme = parts.next().unwrap_or("");
            let creds = parts.next().unwrap_or("").trim();
            if !scheme.eq_ignore_ascii_case("bearer") || creds.is_empty() {
                return None;
            }
            creds.to_owned()
        }
        None => req.cookie("axiam_access")?.value().to_owned(),
    };

    let validated = validate_access_token(&credentials, config).ok()?;
    let user_id = Uuid::parse_str(&validated.0.sub).ok()?;
    let tenant_id = Uuid::parse_str(&validated.0.tenant_id).ok()?;
    let org_id = Uuid::parse_str(&validated.0.org_id).ok()?;

    let identity = Arc::new(CachedUserIdentity {
        user_id,
        tenant_id,
        org_id,
        claims: validated,
    });

    req.extensions_mut().insert(identity);

    Some((user_id, tenant_id, org_id))
}
