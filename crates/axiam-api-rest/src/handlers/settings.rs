//! Security settings endpoints for organizations and tenants.

use actix_web::{HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::opaque::{OpaqueMode, OpaqueSuite};
use axiam_core::models::settings::{
    SecuritySettings, SetOrgSettings, TenantSettingsOverride, effective_settings,
    validate_org_settings, validate_tenant_override,
};
use axiam_core::repository::{Pagination, SettingsRepository, TenantRepository};
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

/// Refuse an OPAQUE mode the running server has no keys to serve.
///
/// `validate_org_settings` cannot make this check: it lives in `axiam-core`,
/// which the crate layering keeps below `axiam-api-rest`, so it can never see
/// an `AppState`. The invariant is nonetheless the same one
/// `POST /api/v1/admin/bootstrap` enforces — writing `opaque_mode` above
/// `disabled` onto a server holding no OPAQUE keys configures a tenant into a
/// state where every `/api/v1/auth/opaque/*` route fails at runtime, and the
/// only way back out is another settings write. Refuse at the write instead,
/// with the same two env vars named, so the operator learns what is missing
/// rather than discovering it from a login that stopped working.
fn reject_opaque_without_keys<C: Connection + Clone>(
    mode: OpaqueMode,
    state: &AppState<C>,
) -> Result<(), AxiamApiError> {
    if mode != OpaqueMode::Disabled && state.opaque_server.is_none() {
        return Err(AxiamApiError(axiam_core::error::AxiamError::Validation {
            message: "opaque_mode is set but AXIAM__AUTH__OPAQUE_SESSION_KEY and \
                      AXIAM__AUTH__OPAQUE_SETUP_KEY are not configured: saving \
                      this would enable OPAQUE on a server that cannot serve it, \
                      and every /api/v1/auth/opaque/* request would fail"
                .into(),
        }));
    }
    Ok(())
}

/// Mint a tenant's OPAQUE key material now that OPAQUE is switched on.
///
/// `opaque_server_setup` was created lazily, on the first `/auth/opaque/*`
/// request. That is correct — `get_or_create` is idempotent and is still the
/// only way key material comes into existence — but it made "did enabling
/// OPAQUE do anything?" unanswerable: the table stayed empty until somebody
/// tried to sign in, which is exactly when an operator wants to have already
/// found out whether the configuration works.
///
/// Provisioning at the write moves the one operation that can fail for
/// server-side reasons — the AES-GCM seal, a database write — to the request
/// the operator is watching. It stays best-effort: a tenant whose row could
/// not be written here gets it on first use as before, so a transient failure
/// delays visibility rather than refusing a settings change.
async fn provision_opaque_setup<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    suite: OpaqueSuite,
) {
    match crate::handlers::opaque::server_setup(state, tenant_id, suite).await {
        Ok(_) => tracing::info!(
            %tenant_id,
            %suite,
            "provisioned OPAQUE server setup for tenant"
        ),
        Err(e) => tracing::warn!(
            %tenant_id,
            %suite,
            error = %e.0,
            "could not provision OPAQUE server setup; it will be minted on first use"
        ),
    }
}

/// `GET /api/v1/organizations/{org_id}/settings`
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_id}/settings",
    tag = "settings",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
    ),
    responses(
        (status = 200, description = "Organization security settings",
         body = SecuritySettings),
    ),
    security(("bearer" = []))
)]
pub async fn get_org_settings<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    // SECURITY (NEW-2): org-baseline settings are a higher privilege than the
    // per-tenant `settings:*` self-management permissions. Enforce the dedicated
    // org-level permission declared in ROUTE_PERMISSION_MAP so a tenant-scoped
    // `settings:get` grant cannot read the org baseline that cascades to every
    // sibling tenant.
    RequirePermission::new("organizations:get_settings", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let org_id = path.into_inner();

    // Authorization: only allow reads for the authenticated user's own org.
    if org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot read settings for a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let settings = state.settings_repo.get_org_settings(org_id).await?;
    Ok(HttpResponse::Ok().json(settings))
}

/// `PUT /api/v1/organizations/{org_id}/settings`
#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_id}/settings",
    tag = "settings",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
    ),
    request_body = SetOrgSettings,
    responses(
        (status = 200, description = "Organization settings updated",
         body = SecuritySettings),
        (status = 400,
         description = "Settings are internally inconsistent, or enable OPAQUE \
                        on a server holding no OPAQUE keys"),
    ),
    security(("bearer" = []))
)]
pub async fn set_org_settings<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<SetOrgSettings>,
) -> Result<HttpResponse, AxiamApiError> {
    // SECURITY (NEW-2): enforce the dedicated org-level permission (declared in
    // ROUTE_PERMISSION_MAP) rather than the tenant-scoped `settings:update`, so a
    // tenant admin cannot rewrite the org security baseline inherited by every
    // sibling tenant.
    RequirePermission::new("organizations:update_settings", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let org_id = path.into_inner();

    // Authorization: only allow writes to the authenticated user's own org.
    if org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot modify settings for a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let input = body.into_inner();
    validate_org_settings(&input)?;
    reject_opaque_without_keys(input.opaque_mode, &state)?;
    let opaque_mode = input.opaque_mode;
    let opaque_suite = input.opaque_suite;
    let settings = state.settings_repo.set_org_settings(org_id, input).await?;

    // Switching OPAQUE on at the organization switches it on for every tenant
    // that has not tightened past it, so every one of them needs key material.
    // Paged to the end rather than taking the default first page: a partial
    // sweep would leave later tenants looking un-provisioned for no reason
    // anybody could see.
    if opaque_mode != OpaqueMode::Disabled {
        let mut offset = 0u64;
        loop {
            let page = state
                .tenant_repo
                .list_by_organization(org_id, Pagination { offset, limit: 200 })
                .await?;
            let count = page.items.len() as u64;
            for tenant in page.items {
                provision_opaque_setup(&state, tenant.id, opaque_suite).await;
            }
            offset += count;
            if count == 0 || offset >= page.total {
                break;
            }
        }
    }

    Ok(HttpResponse::Ok().json(settings))
}

/// `GET /api/v1/settings`
///
/// Returns the effective (merged) security settings for the
/// authenticated user's tenant. Org baseline + tenant overrides.
#[utoipa::path(
    get,
    path = "/api/v1/settings",
    tag = "settings",
    responses(
        (status = 200, description = "Effective tenant security settings",
         body = SecuritySettings),
    ),
    security(("bearer" = []))
)]
pub async fn get_tenant_settings<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("settings:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let settings = state
        .settings_repo
        .get_effective_settings(user.org_id, user.tenant_id)
        .await?;
    Ok(HttpResponse::Ok().json(settings))
}

/// `PUT /api/v1/settings`
///
/// Set tenant-level overrides. Only fields that are **more restrictive**
/// than the org baseline are accepted. Omit a field (set to `null`) to
/// inherit from the org.
#[utoipa::path(
    put,
    path = "/api/v1/settings",
    tag = "settings",
    request_body = TenantSettingsOverride,
    responses(
        (status = 200, description = "Tenant settings updated",
         body = SecuritySettings),
        (status = 400, description = "Override violates org baseline, or \
                                      enables OPAQUE on a server holding no \
                                      OPAQUE keys"),
    ),
    security(("bearer" = []))
)]
pub async fn set_tenant_settings<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<TenantSettingsOverride>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("settings:update", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let org = state.settings_repo.get_org_settings(user.org_id).await?;
    let overrides = body.into_inner();

    // Validate: tenant can only be more restrictive than org
    validate_tenant_override(&org, &overrides)?;

    // The same runtime-serviceability guard as the org write, but keyed on the
    // override's own value rather than the merged one. A tenant that leaves
    // `opaque_mode` unset inherits whatever the org baseline says and changes
    // nothing, so it has no business being refused here — only an override
    // that itself raises the mode is asking for something the server cannot do.
    if let Some(mode) = overrides.opaque_mode {
        reject_opaque_without_keys(mode, &state)?;
    }

    // Merge org baseline + overrides into a complete settings row.
    // The ID passed here is just a placeholder; the underlying
    // SurrealSettingsRepository derives a deterministic UUID (v5)
    // from (scope, scope_id) and uses that as the canonical ID.
    let merged = effective_settings(&org, &overrides, user.tenant_id, Uuid::nil());

    let result = state
        .settings_repo
        .store_effective_tenant_settings(user.tenant_id, merged)
        .await?;

    if result.opaque.opaque_mode != OpaqueMode::Disabled {
        provision_opaque_setup(&state, user.tenant_id, result.opaque.opaque_suite).await;
    }

    Ok(HttpResponse::Ok().json(result))
}

// -----------------------------------------------------------------------
// Tenant-scoped settings — the same overrides, addressed by tenant id
// -----------------------------------------------------------------------
//
// `GET`/`PUT /api/v1/settings` act on the caller's own tenant implicitly and
// exchange *merged* settings, which is what a tenant administrator editing
// their own policy wants. It is not what the organization's tenant detail page
// needs: that page shows one named tenant and has to distinguish an overridden
// field from an inherited one, which a merged view cannot express.
//
// These three mirror the email-config trio exactly — same `{tenant_id}` path
// segment, same `tenant_id == user.tenant_id` check on top of the permission,
// same "raw own-scope row, never the merged view" rule — so a sibling tenant
// answers `403` here for the same reason and in the same shape it does there.

/// `GET /api/v1/tenants/{tenant_id}/settings`
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{tenant_id}/settings",
    tag = "settings",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 200, description = "The tenant's own overrides, sparse — an absent \
                                      field is inherited from the org baseline",
         body = TenantSettingsOverride),
        (status = 404, description = "This tenant overrides nothing"),
    ),
    security(("bearer" = []))
)]
pub async fn get_tenant_override<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("settings:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();

    if tenant_id != user.tenant_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot read security settings for a different tenant".into(),
            action: None,
            resource_id: None,
        }));
    }

    match state.settings_repo.get_tenant_override(tenant_id).await? {
        Some(overrides) => Ok(HttpResponse::Ok().json(overrides)),
        None => Err(AxiamApiError(AxiamError::NotFound {
            entity: "tenant_settings_override".into(),
            id: tenant_id.to_string(),
        })),
    }
}

/// `PUT /api/v1/tenants/{tenant_id}/settings`
#[utoipa::path(
    put,
    path = "/api/v1/tenants/{tenant_id}/settings",
    tag = "settings",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    request_body = TenantSettingsOverride,
    responses(
        (status = 200, description = "The stored overrides, sparse",
         body = TenantSettingsOverride),
        (status = 400, description = "An override is less restrictive than the org \
                                      baseline, or enables OPAQUE on a server holding \
                                      no OPAQUE keys"),
    ),
    security(("bearer" = []))
)]
pub async fn set_tenant_override<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<TenantSettingsOverride>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("settings:update", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();

    if tenant_id != user.tenant_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot modify security settings for a different tenant".into(),
            action: None,
            resource_id: None,
        }));
    }

    let overrides = body.into_inner();
    let org = state.settings_repo.get_org_settings(user.org_id).await?;
    validate_tenant_override(&org, &overrides)?;
    if let Some(mode) = overrides.opaque_mode {
        reject_opaque_without_keys(mode, &state)?;
    }

    let stored = state
        .settings_repo
        .set_tenant_override(tenant_id, overrides)
        .await?;

    let merged = effective_settings(&org, &stored, tenant_id, Uuid::nil());
    if merged.opaque.opaque_mode != OpaqueMode::Disabled {
        provision_opaque_setup(&state, tenant_id, merged.opaque.opaque_suite).await;
    }

    Ok(HttpResponse::Ok().json(stored))
}

/// `DELETE /api/v1/tenants/{tenant_id}/settings`
#[utoipa::path(
    delete,
    path = "/api/v1/tenants/{tenant_id}/settings",
    tag = "settings",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 204, description = "Overrides cleared; the tenant inherits the \
                                      org baseline entirely"),
    ),
    security(("bearer" = []))
)]
pub async fn delete_tenant_override<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("settings:update", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();

    if tenant_id != user.tenant_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot modify security settings for a different tenant".into(),
            action: None,
            resource_id: None,
        }));
    }

    state
        .settings_repo
        .delete_tenant_override(tenant_id)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}
