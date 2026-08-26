//! X2 — the two adapters that connect [`UmaService`] to the running system.
//!
//! `axiam-oauth2` defines the UMA grant against two narrow traits
//! ([`PermissionEvaluator`], [`ScopeCatalog`]) rather than against the RBAC
//! engine and the scope store directly, so that its own tests can drive it
//! without a datastore. Those traits need production implementations, and this
//! is where they live: `axiam-api-rest` is the first crate that has both an
//! [`AuthzChecker`] and the repositories in scope.
//!
//! Both adapters are deliberately thin. Any logic that lands here is logic the
//! UMA unit tests cannot see.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axiam_authz::types::{AccessDecision, AccessRequest, SubjectScope};
use axiam_core::repository::ScopeRepository;
use axiam_oauth2::uma::{PairOutcome, PermissionEvaluator, ScopeCatalog};
use uuid::Uuid;

use crate::authz::AuthzChecker;

/// Evaluates a UMA `(resource, scope)` pair as an ordinary access check.
///
/// # The mapping, and why it is not configurable
///
/// A UMA resource scope is the AXIAM **`action`**, evaluated against the
/// registered resource with no AXIAM scope named
/// (`claude_dev/uma-mapping-design.md`):
///
/// ```text
/// AccessRequest { tenant_id, subject_id, action: <uma scope>, resource_id, scope: None }
/// ```
///
/// Riding UMA scopes on the AXIAM `scope` field instead would be unsafe, not
/// merely different: `grant_applies` treats a grant with an empty `scope_ids`
/// as matching *any* requested scope, so one unscoped grant of a fixed
/// `uma:access` action would satisfy every scope on the resource at once —
/// registering a new `delete` scope would silently widen every existing grant
/// to include it.
///
/// # Deny-override comes for free
///
/// Because this **is** the same check a live request makes, a
/// `PermissionEffect::Deny` grant vetoes an RPT exactly as it vetoes a live
/// check (B1). That is X2's stated requirement, and it holds here without any
/// UMA-specific code — which is the point of the mapping, and the reason
/// `DeniedByRule` is carried through as its own outcome instead of being
/// flattened into "not allowed".
pub struct EngineEvaluator {
    authz: Arc<dyn AuthzChecker>,
}

impl EngineEvaluator {
    pub fn new(authz: Arc<dyn AuthzChecker>) -> Self {
        Self { authz }
    }
}

impl PermissionEvaluator for EngineEvaluator {
    fn evaluate<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_id: Uuid,
        resource_id: Uuid,
        scope: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<PairOutcome, String>> + Send + 'a>> {
        Box::pin(async move {
            let request = AccessRequest {
                tenant_id,
                subject_scope: SubjectScope::Tenant,
                subject_id,
                action: scope.to_string(),
                resource_id,
                scope: None,
            };

            match self.authz.check_access(&request).await {
                Ok(AccessDecision::Allow) => Ok(PairOutcome::Allowed),
                Ok(AccessDecision::Deny(_)) => Ok(PairOutcome::NoGrant),
                Ok(AccessDecision::DeniedByRule(_)) => Ok(PairOutcome::DeniedByRule),
                // A failed check is not a denial. Reporting it as one would
                // turn a datastore blip into `access_denied`, which tells the
                // resource server the requesting party lacks authority — a
                // claim this adapter is in no position to make.
                Err(e) => Err(e.to_string()),
            }
        })
    }
}

/// Answers "which scope names has this resource declared", from the ordinary
/// AXIAM scope rows on that resource.
///
/// UMA's `_id` **is** the AXIAM resource id — there is no parallel resource
/// store to translate through — so a resource's declared scopes are just its
/// `Scope` rows. That set is the allow-list of names a resource server may ask
/// for, not an input to any decision: an undeclared scope is refused when the
/// ticket is minted, so the resource server learns it named something that does
/// not exist rather than being told the requesting party was denied.
pub struct ResourceScopeCatalog<R> {
    scopes: R,
}

impl<R> ResourceScopeCatalog<R> {
    pub fn new(scopes: R) -> Self {
        Self { scopes }
    }
}

impl<R> ScopeCatalog for ResourceScopeCatalog<R>
where
    R: ScopeRepository + Send + Sync,
{
    fn declared_scopes<'a>(
        &'a self,
        tenant_id: Uuid,
        resource_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>> {
        Box::pin(async move {
            let scopes = self
                .scopes
                .list_by_resource(tenant_id, resource_id)
                .await
                .map_err(|e| e.to_string())?;
            Ok(scopes.into_iter().map(|s| s.name).collect())
        })
    }
}
