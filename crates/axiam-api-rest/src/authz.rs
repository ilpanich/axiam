//! Authorization guard and type-erased checker.
//!
//! [`AuthzChecker`] wraps the generic `AuthorizationEngine` behind a
//! trait object so handlers don't carry its five type parameters.
//!
//! [`RequirePermission`] is a guard that endpoints call to enforce
//! an authorization check before proceeding.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axiam_authz::AuthorizationEngine;
use axiam_authz::types::{AccessDecision, AccessRequest};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::repository::{
    GroupRepository, PermissionRepository, ResourceRepository, RoleRepository, ScopeRepository,
};
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

/// Type-erased authorization checker.
///
/// Store as `web::Data<Arc<dyn AuthzChecker>>` in Actix-Web app data.
pub trait AuthzChecker: Send + Sync {
    fn check_access<'a>(
        &'a self,
        request: &'a AccessRequest,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<AccessDecision>> + Send + 'a>>;
}

impl<R, P, Res, S, G> AuthzChecker for AuthorizationEngine<R, P, Res, S, G>
where
    R: RoleRepository,
    P: PermissionRepository,
    Res: ResourceRepository,
    S: ScopeRepository,
    G: GroupRepository,
{
    fn check_access<'a>(
        &'a self,
        request: &'a AccessRequest,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<AccessDecision>> + Send + 'a>> {
        Box::pin(AuthorizationEngine::check_access(self, request))
    }
}

/// Authorization requirement that a handler can check.
///
/// # Example
///
/// ```ignore
/// async fn get_resource(
///     user: AuthenticatedUser,
///     authz: web::Data<Arc<dyn AuthzChecker>>,
///     path: web::Path<Uuid>,
/// ) -> Result<HttpResponse, AxiamApiError> {
///     let resource_id = path.into_inner();
///     RequirePermission::new("read", resource_id)
///         .check(&user, authz.get_ref().as_ref())
///         .await?;
///     // ... handler logic
/// }
/// ```
pub struct RequirePermission {
    pub action: String,
    pub resource_id: Uuid,
    pub scope: Option<String>,
}

impl RequirePermission {
    pub fn new(action: impl Into<String>, resource_id: Uuid) -> Self {
        Self {
            action: action.into(),
            resource_id,
            scope: None,
        }
    }

    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Run the authorization check.
    ///
    /// Returns `Ok(())` on [`AccessDecision::Allow`], or
    /// `Err(AxiamApiError)` with HTTP 403 on deny.
    pub async fn check(
        &self,
        user: &AuthenticatedUser,
        authz: &dyn AuthzChecker,
    ) -> Result<(), AxiamApiError> {
        let request = AccessRequest {
            tenant_id: user.tenant_id,
            subject_id: user.user_id,
            action: self.action.clone(),
            resource_id: self.resource_id,
            scope: self.scope.clone(),
        };

        match authz
            .check_access(&request)
            .await
            .map_err(AxiamApiError::from)?
        {
            AccessDecision::Allow => Ok(()),
            AccessDecision::Deny(reason) => Err(AxiamError::AuthorizationDenied { reason }.into()),
        }
    }
}

/// Convenience alias for the app-data type.
pub type AuthzData = actix_web::web::Data<Arc<dyn AuthzChecker>>;
