//! Security settings endpoints for organizations and tenants.

use actix_web::{HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::opaque::{OpaqueMode, OpaqueSuite};
use axiam_core::models::settings::{
    SecuritySettings, SetOrgSettings, TenantSettingsOverride, clamp_overrides_to_org,
    effective_settings, validate_org_settings, validate_tenant_override,
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

/// Every tenant of an organization, including its own reserved scope.
///
/// Paged to the end rather than taking the default first page: a partial sweep
/// would leave later tenants un-provisioned, unreconciled or unchecked for no
/// reason anybody could see.
async fn all_tenants_of<C: Connection + Clone>(
    state: &AppState<C>,
    org_id: Uuid,
) -> Result<Vec<axiam_core::models::tenant::Tenant>, AxiamApiError> {
    let mut tenants = Vec::new();
    let mut offset = 0u64;
    loop {
        let page = state
            .tenant_repo
            .list_by_organization(
                org_id,
                Pagination {
                    offset,
                    limit: 200,
                    search: None,
                },
            )
            .await?;
        let count = page.items.len() as u64;
        tenants.extend(page.items);
        offset += count;
        if count == 0 || offset >= page.total {
            break;
        }
    }
    Ok(tenants)
}

/// Refuse `opaque_mode = required` while it would strand anybody.
///
/// [`OpaqueMode::Required`] refuses password login for the whole tenant, before
/// any credential is examined — deliberately, because refusing only the enrolled
/// users would turn `/auth/login` into an oracle for who is enrolled. The cost
/// is that every account without a registration record becomes unable to
/// authenticate at all, and **nobody can be enrolled retroactively**: a record
/// can only be built by a client holding the plaintext password, which the
/// server never has.
///
/// So the switch is a one-way door for everyone on the wrong side of it,
/// including the only administrator of the deployment — which is exactly what
/// happened in practice: OPAQUE was turned on, no record had ever been written
/// because the enrolment path was silently omitting them, and the next sign-in
/// simply failed with nothing to say why.
///
/// Refusing here turns that into an error at the moment of the change, naming
/// the tenants and the number of people in each. The way through is the
/// migration the mode's documentation describes: run `optional` until coverage
/// is complete, then switch.
async fn refuse_incomplete_opaque_coverage<C: Connection + Clone>(
    state: &AppState<C>,
    tenants: &[axiam_core::models::tenant::Tenant],
) -> Result<(), AxiamApiError> {
    use axiam_core::repository::OpaqueCredentialRepository as _;

    let mut stranded = Vec::new();
    for tenant in tenants {
        let count = state
            .opaque_credential_repo
            .count_active_users_without_credential(tenant.id)
            .await?;
        if count > 0 {
            stranded.push(format!("{} ({count})", tenant.slug));
        }
    }

    if !stranded.is_empty() {
        return Err(AxiamApiError(AxiamError::Validation {
            message: format!(
                "opaque_mode `required` would lock out active users who have no \
                 OPAQUE registration record, and no record can be created for them \
                 retroactively. Uncovered users by tenant: {}. Run `optional` until \
                 every active user has set a password — creation, change-password \
                 and reset completion each enrol one — then switch to `required`.",
                stranded.join(", "),
            ),
        }));
    }
    Ok(())
}

/// Re-apply the tighten-only rule to every tenant after the baseline moves.
///
/// A tenant override may only ever be *more* restrictive than the organization's
/// baseline, and `validate_tenant_override` enforces that when the override is
/// written. Nothing re-checked it when the **baseline** changed, so raising the
/// organization's floor left every tenant that had written an override for that
/// field sitting below the new one — for good, and invisibly.
///
/// Overrides that are still stricter are untouched: a tenant that chose a
/// 24-character minimum keeps it when the organization moves from 12 to 16.
/// Fields that are now weaker are **cleared** rather than rewritten to the new
/// value, so the tenant tracks the baseline from here on instead of freezing at
/// today's level and needing the same repair after the next change.
///
/// Best-effort per tenant: the read path clamps identically
/// (`clamp_overrides_to_org` in the settings repository), so a tenant this fails
/// to rewrite still *behaves* correctly — only its stored row stays untidy.
/// Failing the operator's settings change over that would be the wrong trade.
async fn reconcile_tenant_overrides<C: Connection + Clone>(
    state: &AppState<C>,
    org: &SecuritySettings,
    tenants: &[axiam_core::models::tenant::Tenant],
) {
    for tenant in tenants {
        let Ok(Some(mut overrides)) = state.settings_repo.get_tenant_override(tenant.id).await
        else {
            continue;
        };
        let cleared = clamp_overrides_to_org(org, &mut overrides);
        if cleared.is_empty() {
            continue;
        }
        match state
            .settings_repo
            .set_tenant_override(tenant.id, overrides)
            .await
        {
            Ok(_) => tracing::info!(
                tenant_id = %tenant.id,
                tenant = %tenant.slug,
                fields = ?cleared,
                "cleared tenant overrides that the new org baseline overtook"
            ),
            Err(e) => tracing::warn!(
                tenant_id = %tenant.id,
                tenant = %tenant.slug,
                fields = ?cleared,
                error = %e,
                "could not rewrite tenant overrides; the read path still clamps them"
            ),
        }
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

    // An organization baseline reaches every tenant, so everything below is
    // organization-wide. Read once and reuse: the coverage gate, the key-material
    // provisioning and the override reconciliation all walk the same list.
    let tenants = all_tenants_of(&state, org_id).await?;

    // Checked BEFORE the write, so a refusal leaves the deployment exactly as it
    // was. `required` at the organization makes every tenant `required` — the
    // tighten-only rule means no tenant can hold itself below the baseline — so
    // every tenant is in scope, the organization's own reserved scope included.
    if opaque_mode == OpaqueMode::Required {
        refuse_incomplete_opaque_coverage(&state, &tenants).await?;
    }

    let settings = state.settings_repo.set_org_settings(org_id, input).await?;

    // Switching OPAQUE on at the organization switches it on for every tenant
    // that has not tightened past it, so every one of them needs key material.
    if opaque_mode != OpaqueMode::Disabled {
        for tenant in &tenants {
            provision_opaque_setup(&state, tenant.id, opaque_suite).await;
        }
    }

    // And every tenant override the new baseline has overtaken is cleared, so
    // the change actually reaches the tenants that had one — which is what
    // "propagated to all the already existing ones" has to mean.
    reconcile_tenant_overrides(&state, &settings, &tenants).await;

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

    // Same one-way door as at the organization, checked against this tenant
    // alone. Read from the *effective* mode rather than the override so that a
    // tenant inheriting `required` from a baseline it is only now writing an
    // unrelated override against is not gated twice — the organization write
    // already established coverage for it.
    let would_be = effective_settings(&org, &overrides, tenant_id, Uuid::nil());
    if would_be.opaque.opaque_mode == OpaqueMode::Required
        && overrides.opaque_mode == Some(OpaqueMode::Required)
    {
        let tenant = state.tenant_repo.get_by_id(tenant_id).await?;
        refuse_incomplete_opaque_coverage(&state, std::slice::from_ref(&tenant)).await?;
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
