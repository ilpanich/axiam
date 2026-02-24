//! Tenant context extractor.
//!
//! [`TenantContext`] provides the tenant and organization IDs from
//! the JWT. Use it when a handler only needs tenant scoping, not the
//! full [`AuthenticatedUser`].

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
    type Future = std::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        // AuthenticatedUser::from_request returns Ready, so we can
        // extract it synchronously via into_inner().
        let result = AuthenticatedUser::from_request(req, payload)
            .into_inner()
            .map(|u| TenantContext {
                tenant_id: u.tenant_id,
                org_id: u.org_id,
            });
        std::future::ready(result)
    }
}
