//! Sync-safe auth + tenant `tonic::service::Interceptor` (D-04, Pattern 3,
//! Pitfall 3).
//!
//! `tonic::service::Interceptor::call` is a **synchronous** function. This
//! interceptor MUST NOT `.lock().await` the async single-flight refresh
//! `Mutex` owned by [`crate::token::manager::TokenManager`] — it only reads
//! the currently cached access token via
//! [`crate::token::manager::TokenManager::cached_access_token`], a
//! non-blocking `RwLock`-backed read primitive built specifically for this
//! synchronous call site (RESEARCH.md Pitfall 3).
//!
//! On `Status::code() == tonic::Code::Unauthenticated`, the ASYNC call-site
//! wrapper (`src/grpc/client.rs`) — never this interceptor — drives the
//! shared single-flight refresh and retries once (§9, T-16-17).

use tonic::service::Interceptor;
use tonic::{Request, Status};

use crate::token::TokenManager;

/// Injects `authorization: Bearer <token>` and `x-tenant-id` (UUID form)
/// metadata on every outgoing RPC (CONTRACT.md §5). Never logs the token —
/// `expose()` is only called at the metadata-insertion boundary.
#[derive(Clone)]
pub struct AuthInterceptor {
    token_manager: std::sync::Arc<TokenManager>,
    /// The UUID form of the tenant identifier, resolved once at login by
    /// decoding the access token's `tenant_id` claim (RESEARCH.md Open
    /// Question #1). The server cross-validates this against
    /// `ValidatedClaims.tenant_id` and rejects a slug or mismatched value
    /// (`crates/axiam-api-grpc/src/services/authorization.rs:81-94`).
    tenant_id: uuid::Uuid,
}

impl AuthInterceptor {
    /// Construct a new interceptor bound to the given [`TokenManager`] and
    /// the resolved tenant UUID (never the slug form — see the `tenant_id`
    /// field doc comment).
    pub fn new(token_manager: std::sync::Arc<TokenManager>, tenant_id: uuid::Uuid) -> Self {
        Self {
            token_manager,
            tenant_id,
        }
    }
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        // Non-blocking cached-token read — NEVER the async refresh Mutex
        // (Pitfall 3). Absence means the caller has not logged in yet, or a
        // prior single-flight refresh has not yet completed.
        let token = self
            .token_manager
            .cached_access_token()
            .ok_or_else(|| Status::unauthenticated("no cached access token"))?;

        let auth_value = format!("Bearer {}", token.expose())
            .parse()
            .map_err(|_| Status::internal("failed to construct authorization metadata"))?;
        req.metadata_mut().insert("authorization", auth_value);

        let tenant_value = self
            .tenant_id
            .to_string()
            .parse()
            .map_err(|_| Status::internal("failed to construct x-tenant-id metadata"))?;
        req.metadata_mut().insert("x-tenant-id", tenant_value);

        Ok(req)
    }
}
