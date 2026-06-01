//! Tenant context extractor.
//!
//! [`TenantContext`] provides the tenant and organization IDs from
//! the JWT. Use it when a handler only needs tenant scoping, not the
//! full [`AuthenticatedUser`].

use std::future::Future;
use std::pin::Pin;

use actix_web::HttpRequest;
use actix_web::dev::Payload;
use uuid::Uuid;

use super::auth::AuthenticatedUser;
use crate::error::AxiamApiError;

/// Tenant context extracted from the JWT claims.
#[derive(Debug, Clone)]
pub struct TenantContext {
    pub tenant_id: Uuid,
    pub org_id: Uuid,
}

impl actix_web::FromRequest for TenantContext {
    type Error = AxiamApiError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        // Delegate to AuthenticatedUser (now async — it performs the per-request
        // session-validity check), then project to tenant scoping.
        let fut = AuthenticatedUser::from_request(req, payload);
        Box::pin(async move {
            let user = fut.await?;
            Ok(TenantContext {
                tenant_id: user.tenant_id,
                org_id: user.org_id,
            })
        })
    }
}
