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
use axiam_core::error::AxiamError;
use axiam_core::repository::{ResourceRepository, ScopeRepository};
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
/// AXIAM scope rows on that resource, to the resource server that registered
/// it and to no other (#745).
///
/// UMA's `_id` **is** the AXIAM resource id — there is no parallel resource
/// store to translate through — so a resource's declared scopes are just its
/// `Scope` rows. That set is the allow-list of names a resource server may ask
/// for, not an input to any decision: an undeclared scope is refused when the
/// ticket is minted, so the resource server learns it named something that does
/// not exist rather than being told the requesting party was denied.
pub struct ResourceScopeCatalog<S, R> {
    scopes: S,
    resources: R,
}

impl<S, R> ResourceScopeCatalog<S, R> {
    pub fn new(scopes: S, resources: R) -> Self {
        Self { scopes, resources }
    }
}

impl<S, R> ScopeCatalog for ResourceScopeCatalog<S, R>
where
    S: ScopeRepository + Send + Sync,
    R: ResourceRepository + Send + Sync,
{
    /// #745 (R111W3-02) — the declared scopes of a resource `client_id`
    /// registered through `/uma2/rreg`; for any other resource (another
    /// resource server's set, one made through `/api/v1/resources`, which
    /// carries no `uma_registered_by`) none, which is what an id that does not
    /// exist answers. Every scope asked of it is then undeclared, so the
    /// permission endpoint's refusal is the same status and body in all three
    /// cases: it echoes only the id and scope the caller sent.
    fn declared_scopes<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
        resource_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>> {
        Box::pin(async move {
            let resource = match self.resources.get_by_id(tenant_id, resource_id).await {
                Ok(resource) => resource,
                Err(AxiamError::NotFound { .. }) => return Ok(Vec::new()),
                Err(e) => return Err(e.to_string()),
            };
            if resource.uma_registered_by.as_deref() != Some(client_id) {
                return Ok(Vec::new());
            }
            let scopes = self
                .scopes
                .list_by_resource(tenant_id, resource_id)
                .await
                .map_err(|e| e.to_string())?;
            Ok(scopes.into_iter().map(|s| s.name).collect())
        })
    }
}
