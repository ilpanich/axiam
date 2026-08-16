//! SCIM authorization: the dedicated `scim:provision` permission (B4).
//!
//! # Tenant scoping — the code path
//!
//! SCIM reuses `axiam-api-rest`'s [`AuthenticatedUser`] extractor unchanged:
//! every `/scim/v2/*` handler takes `user: AuthenticatedUser` exactly like a
//! native `/api/v1/users` handler does, and the middleware chain in front of
//! it (`AuthzMiddleware`, wired in `crate::routes`) is the same one every
//! other authenticated scope uses. `AuthenticatedUser::tenant_id` comes
//! **only** from the validated JWT's `tenant_id` claim — never from anything
//! in the SCIM request path or body. Every repository call this crate makes
//! (`UserRepository`/`GroupRepository`) takes that same `tenant_id` as an
//! explicit, mandatory parameter and every generated SurrealDB query filters
//! on it (see `axiam-db`'s `user.rs`/`group.rs`). A caller cannot name
//! another tenant's resources into existence in the query, and a token
//! minted for tenant A therefore cannot read or mutate tenant B's data
//! through this crate — not because SCIM adds a check, but because it never
//! introduces a second source of tenant identity for the check to miss.
//!
//! This is call-time enforcement (checked on every request), not a
//! provisioning-time assumption: even a handler bug that forgot to call
//! [`require_scim_provision`] would still be unable to cross tenants, because
//! the cross-tenant channel does not exist in the repository calls it would
//! make. `tests/contract_test.rs`'s tenant-isolation tests exercise exactly
//! this property adversarially (cross-tenant GET/PUT/PATCH/DELETE/list by
//! UUID, not merely "no token").
//!
//! # What `scim:provision` actually confers (SEC-098) — read before granting
//!
//! **A holder of `scim:provision` can set any user's password in this tenant,
//! including a tenant administrator's, and then log in as them.**
//!
//! RFC 7643 §4.1.1 defines `password` as a writable User attribute and
//! `PATCH /scim/v2/Users/{id}` honours it ([`crate::users::patch`]). The
//! native admin API has no equivalent — `handlers::users::update` never
//! writes `password_hash`, and the only native password writes are
//! self-service change and reset inside `AuthService`. So this single
//! permission is strictly more powerful than `users:create` +
//! `users:update` combined, and the provisioning guide's own advice ("grant
//! it to your Okta/Entra integration identity") is therefore advice to grant
//! tenant-wide account takeover to an external system.
//!
//! That is the correct reading of the RFC and it is not being changed here;
//! what was wrong was that nothing said it. If a deployment federates and
//! never pushes a password — which is most Okta/Entra deployments — the
//! integration identity does not need this capability and splitting it behind
//! a second permission is a reasonable follow-on.
//!
//! Two consequences that ARE fixed rather than documented, in
//! [`crate::users`]: a SCIM password write, an `active: false`, and a
//! `DELETE /Users/{id}` each revoke every live session and OAuth2 refresh
//! token for the target. Before SEC-098 they flushed only the authorization
//! *decision* cache, so a password rotated to lock out a compromised account
//! left the attacker's session and refresh token spendable.
//!
//! # Principal — a note for operators (see `docs/api/scim-provisioning.md`)
//!
//! The bearer principal is deliberately whichever tenant-scoped AXIAM
//! identity holds `scim:provision` — in practice a dedicated tenant user
//! (e.g. `scim-provisioner`) created and role-granted through the existing
//! `/api/v1/users` + `/api/v1/roles` APIs, **not** a `service_account` row:
//! AXIAM's RBAC role-assignment edge (`has_role`) is hard-scoped to the
//! `user` table today (`axiam-db`'s `RoleRepository::assign_to_user`/
//! `get_user_role_assignments` both query `type::record('user', $id)`), so a
//! `service_account` subject cannot currently hold ANY RBAC permission,
//! `scim:provision` included. That gap predates this crate and is out of
//! R3.1's file scope (`axiam-db`, `axiam-authz`) to close; it is flagged
//! here, in the provisioning guide, and in this task's final report so a
//! follow-on (the planned SCIM token-management UI, or a dedicated fix) has
//! a precise pointer.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest, web};
use axiam_api_rest::authz::{AuthzChecker, RequirePermission};
use axiam_api_rest::extractors::auth::AuthenticatedUser;
use axiam_api_rest::extractors::scim_token::{ScimTokenPrincipal, ScimTokenResolver};
use axiam_core::models::scim_token::SCIM_TOKEN_PREFIX;
use uuid::Uuid;

use crate::error::ScimError;

/// The permission every `/scim/v2/*` route requires (B4: "a DEDICATED
/// `scim:provision` permission"). Declared here, and separately registered
/// in `axiam_api_rest::permissions::PERMISSION_REGISTRY` (the same array
/// every other AXIAM permission is declared in) so it is seeded per-tenant
/// exactly like `users:create`, `groups:list`, etc.
pub use axiam_core::models::scim_token::SCIM_PROVISION_ACTION as SCIM_PROVISION_PERMISSION;

/// What authenticated a `/scim/v2/*` request.
///
/// Two arms because SCIM accepts two credential shapes and they resolve
/// differently, not because they are authorized differently — both end up in
/// [`require_scim_provision`] against a `(tenant, user)` pair, and the RBAC
/// decision is identical.
pub enum ScimPrincipal {
    /// A JWT-bearing tenant user — the path that existed before provisioning
    /// tokens, unchanged.
    Jwt(Box<AuthenticatedUser>),
    /// A provisioning token, resolved to the user it is bound to.
    Token(ScimTokenPrincipal),
}

impl ScimPrincipal {
    pub fn tenant_id(&self) -> Uuid {
        match self {
            Self::Jwt(u) => u.tenant_id,
            Self::Token(t) => t.tenant_id,
        }
    }

    pub fn user_id(&self) -> Uuid {
        match self {
            Self::Jwt(u) => u.user_id,
            Self::Token(t) => t.user_id,
        }
    }

    /// The provisioning token's id, when one authenticated this request.
    /// `None` for a JWT caller.
    pub fn token_id(&self) -> Option<Uuid> {
        match self {
            Self::Jwt(_) => None,
            Self::Token(t) => Some(t.token_id),
        }
    }
}

/// Read the bearer value from the `Authorization` header, if there is one.
///
/// Header only — never the `axiam_access` cookie. A provisioning token is a
/// machine credential presented by an IdP; accepting it from a cookie would
/// make it reachable from a browser, and therefore CSRF-reachable, for no
/// benefit to any real caller.
fn bearer_value(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get(actix_web::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::to_owned)
}

impl FromRequest for ScimPrincipal {
    type Error = ScimError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        // Dispatch on the handle prefix rather than trying both arms in
        // sequence. Trying JWT-then-token would turn every malformed JWT into
        // a database lookup, and would make "which credential did it think
        // this was?" unanswerable from the response — which is precisely the
        // question an operator asks when provisioning breaks.
        let presented = bearer_value(req);
        let is_provisioning_token = presented
            .as_deref()
            .is_some_and(|t| t.starts_with(SCIM_TOKEN_PREFIX));

        if !is_provisioning_token {
            let fut = AuthenticatedUser::from_request(req, payload);
            return Box::pin(async move {
                fut.await
                    .map(|u| ScimPrincipal::Jwt(Box::new(u)))
                    .map_err(ScimError::from)
            });
        }

        let resolver = req
            .app_data::<web::Data<Arc<dyn ScimTokenResolver>>>()
            .map(|d| d.get_ref().clone());

        Box::pin(async move {
            // A deployment that registered no resolver cannot honour
            // provisioning tokens at all. Failing closed here (rather than
            // falling through to the JWT arm, which would then reject the
            // handle as a malformed JWT) keeps the error honest.
            let resolver = resolver.ok_or_else(|| {
                ScimError::new(
                    actix_web::http::StatusCode::UNAUTHORIZED,
                    "SCIM provisioning tokens are not enabled on this deployment",
                )
            })?;
            let raw = presented.unwrap_or_default();

            let principal = resolver.resolve(&raw).await.ok_or_else(|| {
                ScimError::new(
                    actix_web::http::StatusCode::UNAUTHORIZED,
                    "invalid or expired provisioning token",
                )
            })?;

            resolver
                .touch(principal.tenant_id, principal.token_id)
                .await;

            Ok(ScimPrincipal::Token(principal))
        })
    }
}

/// Enforce `scim:provision` for the calling principal, using the SAME
/// authorization path every native `/api/v1/*` handler uses. Not
/// resource-scoped (SCIM has no notion of an AXIAM `resource` hierarchy), so
/// the check runs against the global sentinel (`Uuid::nil()`), exactly like
/// `users:create`/`groups:create` do today.
///
/// Goes through [`RequirePermission::check_subject`] rather than `check`
/// because the principal may not be an [`AuthenticatedUser`]. That seam
/// already exists for exactly this case ("a caller that may be a machine
/// rather than a user"), so a provisioning token introduces no new
/// authorization code — the same grants, resolved the same way, for the same
/// subject id.
pub async fn require_scim_provision(
    principal: &ScimPrincipal,
    authz: &dyn AuthzChecker,
) -> Result<(), ScimError> {
    RequirePermission::new(SCIM_PROVISION_PERMISSION, Uuid::nil())
        .check_subject(principal.tenant_id(), principal.user_id(), authz)
        .await
        .map_err(ScimError::from)
}
