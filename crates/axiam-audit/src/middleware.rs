//! Actix-Web middleware that automatically logs HTTP requests to the audit trail.
//!
//! Captures: HTTP method, path, authenticated user (optional), client IP,
//! and response status code. Audit writes are performed asynchronously via
//! `tokio::spawn` so they don't block the response.

use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::sync::Arc;

use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::web;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::validate_access_token;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::AuditLogRepository;
use tracing::warn;
use uuid::Uuid;

/// Paths that should not generate audit entries.
const SKIP_PATHS: &[&str] = &["/health", "/ready"];

/// Middleware factory for audit logging.
///
/// Wraps every HTTP request/response pair and emits an audit log entry.
/// The `AuditLogRepository` is shared via `Arc` so it can be moved into
/// spawned tasks.
pub struct AuditMiddleware<A> {
    repo: Arc<A>,
}

impl<A> AuditMiddleware<A> {
    pub fn new(repo: A) -> Self {
        Self {
            repo: Arc::new(repo),
        }
    }
}

impl<A: Clone> Clone for AuditMiddleware<A> {
    fn clone(&self) -> Self {
        Self {
            repo: self.repo.clone(),
        }
    }
}

impl<S, B, A> Transform<S, ServiceRequest> for AuditMiddleware<A>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
    A: AuditLogRepository + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = AuditMiddlewareService<S, A>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuditMiddlewareService {
            service,
            repo: self.repo.clone(),
        }))
    }
}

pub struct AuditMiddlewareService<S, A> {
    service: S,
    repo: Arc<A>,
}

impl<S, B, A> Service<ServiceRequest> for AuditMiddlewareService<S, A>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
    A: AuditLogRepository + 'static,
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

        // Try to extract authenticated user from JWT (optional).
        let user_info = extract_user_info(&req);

        let repo = self.repo.clone();
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

            let action = format!("{method} {path}");

            let (actor_id, tenant_id, actor_type) = match user_info {
                Some((uid, tid)) => (uid, tid, ActorType::User),
                None => {
                    // Unauthenticated request — use nil UUIDs.
                    (Uuid::nil(), Uuid::nil(), ActorType::System)
                }
            };

            let entry = CreateAuditLogEntry {
                tenant_id,
                actor_id,
                actor_type,
                action,
                resource_id: None,
                outcome,
                ip_address,
                metadata: Some(serde_json::json!({
                    "http_status": status,
                })),
            };

            tokio::spawn(async move {
                if let Err(e) = repo.append(entry).await {
                    warn!(error = %e, "Failed to write audit log entry");
                }
            });

            Ok(res)
        })
    }
}

/// Try to extract (user_id, tenant_id) from the JWT Authorization header.
///
/// Returns `None` if no valid bearer token is present (unauthenticated
/// endpoints). This intentionally never fails — missing/invalid tokens
/// just result in `None`.
fn extract_user_info(req: &ServiceRequest) -> Option<(Uuid, Uuid)> {
    let config = req.app_data::<web::Data<AuthConfig>>()?;

    let header = req.headers().get("Authorization")?.to_str().ok()?;

    let header = header.trim();
    let mut parts = header.splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    let credentials = parts.next()?.trim();

    if !scheme.eq_ignore_ascii_case("bearer") || credentials.is_empty() {
        return None;
    }

    let claims = validate_access_token(credentials, config).ok()?;
    let user_id = Uuid::parse_str(&claims.0.sub).ok()?;
    let tenant_id = Uuid::parse_str(&claims.0.tenant_id).ok()?;

    Some((user_id, tenant_id))
}
