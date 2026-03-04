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

use actix_web::HttpMessage;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::AuditLogRepository;
use tokio::sync::mpsc;
use tracing::warn;
use uuid::Uuid;

/// Paths that should not generate audit entries.
const SKIP_PATHS: &[&str] = &["/health", "/ready"];

/// Default capacity for the audit write channel.
const CHANNEL_CAPACITY: usize = 4096;

/// Middleware factory for audit logging.
///
/// Wraps every HTTP request/response pair and emits an audit log entry for
/// authenticated requests. A bounded channel dispatches entries to a
/// background worker task.
#[derive(Clone)]
pub struct AuditMiddleware {
    tx: mpsc::Sender<CreateAuditLogEntry>,
}

impl AuditMiddleware {
    /// Create the middleware and spawn its background worker.
    ///
    /// The worker reads from a bounded channel and appends entries to the
    /// given `AuditLogRepository`. The channel capacity defaults to
    /// [`CHANNEL_CAPACITY`]; when full, new audit entries are dropped
    /// (with a warning) to avoid blocking request handling.
    pub fn spawn<A: AuditLogRepository + 'static>(repo: A) -> Self {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        tokio::spawn(audit_worker(rx, repo));
        Self { tx }
    }
}

async fn audit_worker<A: AuditLogRepository>(mut rx: mpsc::Receiver<CreateAuditLogEntry>, repo: A) {
    while let Some(entry) = rx.recv().await {
        if let Err(e) = repo.append(entry).await {
            warn!(error = %e, "Failed to write audit log entry");
        }
    }
    warn!("Audit worker channel closed — no more entries will be written");
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
    tx: mpsc::Sender<CreateAuditLogEntry>,
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

        let tx = self.tx.clone();
        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            let status = res.status().as_u16();

            let outcome = if status < 400 {
                AuditOutcome::Success
            } else if status == 403 {
                AuditOutcome::Denied
            } else {
                AuditOutcome::Failure
            };

            let (actor_id, tenant_id, actor_type) = match user_info {
                Some((uid, tid)) => (uid, tid, ActorType::User),
                None => (Uuid::nil(), Uuid::nil(), ActorType::System),
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

            if tx.try_send(entry).is_err() {
                warn!("Audit channel full — dropping audit entry for {method} {path}");
            }

            Ok(res)
        })
    }
}

/// Cached validated user identity stored in request extensions.
///
/// Allows the `AuthenticatedUser` extractor to skip re-validating the JWT
/// when the audit middleware has already done so.
#[derive(Debug, Clone)]
pub struct CachedUserIdentity {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub claims: axiam_auth::token::ValidatedClaims,
}

/// Extract user info from cached extensions, or validate JWT and cache it.
fn extract_or_cache_user_info(req: &ServiceRequest) -> Option<(Uuid, Uuid)> {
    use actix_web::web;
    use axiam_auth::config::AuthConfig;
    use axiam_auth::token::validate_access_token;

    // Check cache first.
    if let Some(cached) = req.extensions().get::<Arc<CachedUserIdentity>>() {
        return Some((cached.user_id, cached.tenant_id));
    }

    let config = req.app_data::<web::Data<AuthConfig>>()?;

    let header = req.headers().get("Authorization")?.to_str().ok()?;
    let header = header.trim();
    let mut parts = header.splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    let credentials = parts.next()?.trim();

    if !scheme.eq_ignore_ascii_case("bearer") || credentials.is_empty() {
        return None;
    }

    let validated = validate_access_token(credentials, config).ok()?;
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

    Some((user_id, tenant_id))
}
