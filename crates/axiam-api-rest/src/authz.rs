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

    /// Evaluate an ordered batch of checks, returning decisions in input order
    /// (result `i` ↔ `requests[i]`).
    ///
    /// The default implementation simply calls [`Self::check_access`] per item;
    /// the real [`AuthorizationEngine`] overrides it with a **coalesced** path
    /// that resolves the shared role-assignment / ancestor / scope lookups once
    /// per `(tenant, subject)` / `(tenant, resource)` group instead of once per
    /// item (D1). Both the REST and gRPC batch handlers route through this.
    fn check_access_batch<'a>(
        &'a self,
        requests: &'a [AccessRequest],
    ) -> Pin<Box<dyn Future<Output = AxiamResult<Vec<AccessDecision>>> + Send + 'a>> {
        Box::pin(async move {
            let mut out = Vec::with_capacity(requests.len());
            for req in requests {
                out.push(self.check_access(req).await?);
            }
            Ok(out)
        })
    }
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

    fn check_access_batch<'a>(
        &'a self,
        requests: &'a [AccessRequest],
    ) -> Pin<Box<dyn Future<Output = AxiamResult<Vec<AccessDecision>>> + Send + 'a>> {
        Box::pin(AuthorizationEngine::check_access_batch(self, requests))
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
            AccessDecision::Deny(reason) => {
                // SDK-Q02: surface the checked action/resource so clients can
                // parse them from the 403 body. `Uuid::nil()` is the
                // "global" (not resource-scoped) sentinel — omit it.
                let resource_id = if self.resource_id.is_nil() {
                    None
                } else {
                    Some(self.resource_id.to_string())
                };
                Err(AxiamError::AuthorizationDenied {
                    reason,
                    action: Some(self.action.clone()),
                    resource_id,
                }
                .into())
            }
        }
    }
}

/// Convenience alias for the app-data type.
pub type AuthzData = actix_web::web::Data<Arc<dyn AuthzChecker>>;

/// Check if the caller is accessing their own resource (self-service).
///
/// Returns `true` when `caller.user_id == target_user_id`, allowing
/// self-service endpoints to skip the authorization engine check.
pub fn is_own_resource(caller: &AuthenticatedUser, target_user_id: Uuid) -> bool {
    caller.user_id == target_user_id
}

/// Marker inserted into request extensions after a successful
/// [`RequirePermission`] check.
///
/// Handlers can insert this after calling `RequirePermission::check()` to
/// signal to the outer middleware (and integration tests) that authorization
/// was explicitly performed:
///
/// ```ignore
/// req.extensions_mut().insert(AuthzChecked);
/// ```
pub struct AuthzChecked;

/// Always-allow [`AuthzChecker`] for integration tests.
///
/// Production code should never use this. Register it as
/// `web::Data::new(Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>)`
/// in test fixtures that don't exercise RBAC decisions — it lets handlers'
/// `RequirePermission::check()` calls pass without seeding role/permission
/// data in the test DB.
pub struct AllowAllAuthzChecker;

impl AuthzChecker for AllowAllAuthzChecker {
    fn check_access<'a>(
        &'a self,
        _request: &'a AccessRequest,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<AccessDecision>> + Send + 'a>> {
        Box::pin(async move { Ok(AccessDecision::Allow) })
    }
}

/// Always-deny [`AuthzChecker`] for integration tests.
///
/// The mirror of [`AllowAllAuthzChecker`]: it returns
/// [`AccessDecision::Deny`] for every request, simulating a caller who
/// lacks the required permission. Register it as
/// `web::Data::new(Arc::new(DenyAllAuthzChecker) as Arc<dyn AuthzChecker>)`
/// in test fixtures that need to assert a handler's *forbidden* path
/// (e.g. a non-admin caller hitting an admin-gated endpoint) without
/// seeding role/permission data in the test DB.
pub struct DenyAllAuthzChecker;

impl AuthzChecker for DenyAllAuthzChecker {
    fn check_access<'a>(
        &'a self,
        _request: &'a AccessRequest,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<AccessDecision>> + Send + 'a>> {
        Box::pin(async move {
            Ok(AccessDecision::Deny(
                "caller lacks the required permission".into(),
            ))
        })
    }
}
