//! SA-18 (N15, D-1) — the `roles` scope and the access token's `roles` claim.
//!
//! # Why the claim exists
//!
//! Three SDKs implemented `require_role` by reading the OAuth2 `scope` claim,
//! because the server issued nothing else that named a role. A scope is chosen
//! by the *client* and bounded only by its registration; it says nothing about
//! what the *user* holds. So a client registered for a scope named `admin`
//! passed `require_role("admin")` for every user it signed in (N15).
//!
//! D-1 settles the fix on both sides: the SDKs read only a dedicated `roles`
//! claim and fail closed without it, and the server emits that claim — the
//! names of the subject's **global** roles in the token's tenant — when, and
//! only when, the grant carries the `roles` scope.
//!
//! # The rules
//!
//! 1. `roles` is an ordinary scope. A client obtains it only when it is in the
//!    client's registered scopes (and, for an externally registered client,
//!    the tenant's `dcr_allowed_scopes`), exactly as for any other scope.
//!    Nothing grants it by default. A service account, which registers no
//!    scopes, may ask for `roles` and for nothing else: it is a statement about
//!    the account's own assignments, which is all its authority already is.
//! 2. Granted, the claim lists the names of the roles assigned to the subject
//!    **with no resource** — directly or through a group — in the token's
//!    tenant, sorted and de-duplicated. An assignment scoped to a resource is
//!    not a tenant-wide role and is left out.
//! 3. Not granted, the claim is **absent** — never `[]` — so a consumer can
//!    tell "not requested" from "holds no roles". A subject that holds none
//!    (or an OAuth2 client, which cannot hold roles) gets `[]`.
//! 4. It is computed at mint time, by every grant that mints an access token:
//!    a refresh recomputes it, and a token exchange recomputes it only when
//!    `roles` survives the narrowing. ID tokens and UserInfo never carry it.
//!
//! # A snapshot, not an authority
//!
//! The claim is stale for at most one access-token lifetime: a role withdrawn
//! after minting stays in the token until it expires. It is a coarse,
//! cacheable hint for UI gating and `require_role`; the authoritative check is
//! still the server's `require_access` decision. `docs/api/roles-claim.md`
//! says so to integrators.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::role::RoleAssignment;
use axiam_core::repository::RoleRepository;
use uuid::Uuid;

use crate::error::OAuth2Error;

/// The scope that asks for the `roles` claim.
pub const ROLES_SCOPE: &str = "roles";

/// The access-token claim the [`ROLES_SCOPE`] scope adds.
pub const ROLES_CLAIM: &str = "roles";

/// Where the subject's global role names are read from.
///
/// A port, like [`crate::scope_ceiling::ExternalClientScopePolicy`], so the
/// token services keep their type parameters and the composition root builds
/// one value that every service shares.
pub trait GlobalRoleSource: Send + Sync {
    /// The subject's global role names in `tenant_id`, as the claim carries
    /// them (sorted, de-duplicated). `subject_id` is a user or a service
    /// account.
    ///
    /// An `Err` is a failed read, never "no roles": the caller refuses.
    fn global_role_names<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<Vec<String>>> + Send + 'a>>;
}

/// The shared form every service holds.
pub type SharedRoleSource = Arc<dyn GlobalRoleSource>;

/// The source a service holds until its composition root wires a real one.
///
/// Refuses every read, so a grant that carries the `roles` scope is refused
/// with `server_error` rather than minting a token whose claim says "no roles"
/// when nobody looked. A grant without the scope never reads it.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnwiredRoleSource;

impl GlobalRoleSource for UnwiredRoleSource {
    fn global_role_names<'a>(
        &'a self,
        _tenant_id: Uuid,
        _subject_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<Vec<String>>> + Send + 'a>> {
        Box::pin(async {
            Err(AxiamError::Internal(
                "no role source is wired into this service".into(),
            ))
        })
    }
}

/// A [`SharedRoleSource`] that refuses — see [`UnwiredRoleSource`].
pub fn unwired() -> SharedRoleSource {
    Arc::new(UnwiredRoleSource)
}

/// The role repository as a [`GlobalRoleSource`].
///
/// Reads `get_user_role_assignments`, which resolves the subject in both
/// principal tables (user and service account) and follows group membership,
/// and keeps the assignments [`global_role_names`] keeps.
#[derive(Debug, Clone)]
pub struct RepositoryRoleSource<R> {
    roles: R,
}

impl<R> RepositoryRoleSource<R> {
    /// Wrap a role repository.
    pub fn new(roles: R) -> Self {
        Self { roles }
    }
}

impl<R> GlobalRoleSource for RepositoryRoleSource<R>
where
    R: RoleRepository + 'static,
{
    fn global_role_names<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<Vec<String>>> + Send + 'a>> {
        Box::pin(async move {
            let assignments = self
                .roles
                .get_user_role_assignments(tenant_id, subject_id)
                .await?;
            Ok(global_role_names(&assignments, tenant_id))
        })
    }
}

/// The names of the assignments that carry no resource and reach `tenant_id`,
/// sorted and de-duplicated.
///
/// A role held both directly and through a group appears once. An assignment
/// scoped to a resource is left out whatever the role's `is_global` flag says:
/// the claim names tenant-wide assignments, and a resource-scoped one is not.
pub fn global_role_names(assignments: &[RoleAssignment], tenant_id: Uuid) -> Vec<String> {
    assignments
        .iter()
        .filter(|a| a.resource_id.is_none() && a.reaches_tenant(tenant_id))
        .map(|a| a.role.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Whether a granted scope set asks for the claim.
pub fn grants_roles(scopes: &[String]) -> bool {
    scopes.iter().any(|s| s == ROLES_SCOPE)
}

/// Who a token's `roles` claim describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RolesSubject {
    /// A user or a service account: its assignments are read.
    Principal(Uuid),
    /// An OAuth2 client (client credentials): it cannot hold roles, so a
    /// granted scope yields `[]` with no read.
    Client,
}

/// The claim for a token whose granted scopes are `scopes`.
///
/// `Ok(None)` — the claim is absent — whenever `roles` is not granted; no read
/// is made. Otherwise the subject's global role names, read now.
///
/// # Errors
///
/// `server_error` when the role source cannot be read: a token that says "no
/// roles" because the read failed would be a false statement in a signed
/// credential.
pub async fn roles_claim(
    source: &dyn GlobalRoleSource,
    tenant_id: Uuid,
    subject: RolesSubject,
    scopes: &[String],
) -> Result<Option<Vec<String>>, OAuth2Error> {
    if !grants_roles(scopes) {
        return Ok(None);
    }
    let subject_id = match subject {
        RolesSubject::Client => return Ok(Some(Vec::new())),
        RolesSubject::Principal(id) => id,
    };
    match source.global_role_names(tenant_id, subject_id).await {
        Ok(names) => Ok(Some(names)),
        Err(e) => {
            tracing::error!(
                error = %e,
                tenant_id = %tenant_id,
                subject_id = %subject_id,
                "could not read the subject's global roles for the roles claim; refusing \
                 rather than minting a token that claims none"
            );
            Err(OAuth2Error::ServerError(
                "the subject's roles could not be read".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::role::Role;

    fn assignment(
        name: &str,
        resource: Option<Uuid>,
        tenants: Option<Vec<Uuid>>,
    ) -> RoleAssignment {
        RoleAssignment {
            role: Role {
                id: Uuid::new_v4(),
                tenant_id: Uuid::nil(),
                name: name.into(),
                description: String::new(),
                is_global: resource.is_some(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
            resource_id: resource,
            tenant_scope: tenants,
            inherit: true,
        }
    }

    #[test]
    fn keeps_unscoped_assignments_sorted_and_deduplicated() {
        let tenant = Uuid::new_v4();
        let names = global_role_names(
            &[
                assignment("zeta", None, None),
                assignment("alpha", None, None),
                assignment("zeta", None, None),
                assignment("scoped", Some(Uuid::new_v4()), None),
                assignment("elsewhere", None, Some(vec![Uuid::new_v4()])),
                assignment("here", None, Some(vec![tenant])),
            ],
            tenant,
        );
        assert_eq!(names, ["alpha", "here", "zeta"]);
    }

    #[tokio::test]
    async fn absent_without_the_scope_and_no_read_is_made() {
        let claim = roles_claim(
            &UnwiredRoleSource,
            Uuid::new_v4(),
            RolesSubject::Principal(Uuid::new_v4()),
            &["openid".to_owned()],
        )
        .await
        .unwrap();
        assert_eq!(claim, None);
    }

    #[tokio::test]
    async fn a_client_subject_is_an_empty_array_and_a_failed_read_refuses() {
        let scopes = ["roles".to_owned()];
        let client = roles_claim(
            &UnwiredRoleSource,
            Uuid::new_v4(),
            RolesSubject::Client,
            &scopes,
        )
        .await
        .unwrap();
        assert_eq!(client, Some(Vec::new()));

        let refused = roles_claim(
            &UnwiredRoleSource,
            Uuid::new_v4(),
            RolesSubject::Principal(Uuid::new_v4()),
            &scopes,
        )
        .await;
        assert!(matches!(refused, Err(OAuth2Error::ServerError(_))));
    }
}
