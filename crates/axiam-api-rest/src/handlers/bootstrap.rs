//! Admin bootstrap endpoint — first-run setup.
//!
//! On a brand-new deployment the database is empty: there are no organizations,
//! tenants or users. This endpoint performs the entire first-run provisioning
//! in one call — it creates the **organization**, the **default tenant**, seeds
//! the permission set and default roles, and creates the initial **admin user**
//! bound to the super-admin role. Org/tenant creation is get-or-create by slug
//! so a retry after a transient failure reuses them.
//!
//! It is a one-shot operation. First-super-admin creation is atomic (SECHRD-04
//! / SEC-049 / D-03c): a uniqueness-invariant `bootstrap_lock:global` CREATE
//! inside the same transaction that creates the admin user means two concurrent
//! first-run requests can create AT MOST ONE super-admin — the loser gets
//! `AxiamError::AlreadyExists` (409) and its whole transaction rolls back.
//! After the first admin is created, every subsequent call also hits the same
//! `bootstrap_lock:global` uniqueness violation and is refused with 409.
//! Additional organizations/tenants are created afterwards through the
//! authenticated admin API.
//!
//! The endpoint is also gated (D-03a): a request is refused (fail-closed,
//! no admin created) unless EITHER `AXIAM_BOOTSTRAP_ADMIN_EMAIL` is set and
//! matches the request email, OR the request carries a valid one-time
//! setup token (server-minted at first boot, logged once, consumed once —
//! D-03b). An unset/absent gate never allows bootstrap.

use actix_web::{HttpResponse, web};
use axiam_auth::password;
use axiam_core::error::AxiamError;
use axiam_core::id::new_id;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::SrpPolicy;
use axiam_core::models::srp::{SrpEnrollment, SrpGroup, SrpKdf, SrpKdfParams, SrpMode};
use axiam_core::models::tenant::CreateTenant;
use axiam_core::repository::{OrganizationRepository, TenantRepository};
use axiam_db::{seed_default_roles, seed_permissions};
use chrono::{DateTime, Utc};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use surrealdb::types::SurrealValue;
use surrealdb::{Connection, Surreal};
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::permissions::PERMISSION_REGISTRY;
use crate::state::AppState;

// -----------------------------------------------------------------------
// Request / response types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct BootstrapRequest {
    /// Display name of the organization to create (required). On a fresh
    /// deployment nothing exists yet, so bootstrap provisions the org and its
    /// default tenant itself rather than requiring pre-existing IDs.
    pub organization_name: String,
    /// URL-safe slug for the organization. Derived from `organization_name`
    /// when omitted or blank.
    #[serde(default)]
    pub organization_slug: Option<String>,
    /// Display name of the default tenant. Defaults to `"Default"`.
    #[serde(default)]
    pub tenant_name: Option<String>,
    /// URL-safe slug for the default tenant. Defaults to `"default"`.
    #[serde(default)]
    pub tenant_slug: Option<String>,
    /// Admin email address.
    pub email: String,
    /// Admin username.
    pub username: String,
    /// Admin password (hashed with Argon2id before storage).
    pub password: String,
    /// One-time first-run setup token (D-03a/D-03b). Required when
    /// `AXIAM_BOOTSTRAP_ADMIN_EMAIL` is not set; ignored otherwise.
    #[serde(default)]
    pub setup_token: Option<String>,
    /// Secure Remote Password policy to seed as the new organization's
    /// baseline. Omitted means `disabled`, which is what an operator who has
    /// not thought about SRP should get.
    ///
    /// Settable here — rather than only through `PUT /api/v1/settings/org`
    /// afterwards — because the alternative is a window in which the only
    /// account on the deployment exists without a verifier. Turning
    /// `required` on later would then lock the sole administrator out of their
    /// own system, with no second admin to undo it.
    #[serde(default)]
    #[schema(value_type = Option<String>, example = "disabled")]
    pub srp_mode: Option<SrpMode>,
    /// RFC 5054 group for the seeded baseline. Defaults to `rfc5054_4096`.
    #[serde(default)]
    #[schema(value_type = Option<String>, example = "rfc5054_4096")]
    pub srp_group: Option<SrpGroup>,
    /// Client KDF for the seeded baseline. Defaults to `argon2id`.
    #[serde(default)]
    #[schema(value_type = Option<String>, example = "argon2id")]
    pub srp_kdf: Option<SrpKdf>,
    /// The admin's SRP verifier, computed client-side over `username`.
    ///
    /// Mandatory when `srp_mode` is `required`: without it bootstrap would
    /// produce a deployment whose only administrator cannot authenticate by
    /// any route, and which no one has the access to repair.
    #[serde(default)]
    pub srp: Option<SrpEnrollment>,
}

/// Convert an arbitrary display name into a URL-safe slug: ASCII alphanumerics
/// are lower-cased, every other run of characters collapses to a single `-`,
/// and leading/trailing dashes are trimmed.
fn slugify(input: &str) -> String {
    let mut slug = String::with_capacity(input.len());
    for ch in input.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    slug
}

// -----------------------------------------------------------------------
// Setup-token validation
// -----------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct SetupTokenRow {
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct ConsumedTokenRow {
    #[allow(dead_code)]
    consumed_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct BootstrapLockRow {
    #[allow(dead_code)]
    locked_at: DateTime<Utc>,
}

/// sha256 hex hash of `token`.
fn hash_setup_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Returns `Ok(true)` iff `token`'s hash exists in `bootstrap_setup_token`
/// and has NOT already been consumed. This is a fast-fail pre-check only —
/// the authoritative single-use guarantee is the `bootstrap_setup_token_consumed`
/// CREATE inside the same atomic transaction that creates the admin user
/// (Task 3): a replayed token still loses to a UNIQUE-index violation even
/// if two requests race past this pre-check simultaneously.
async fn setup_token_is_valid<C: Connection + Clone>(
    db: &Surreal<C>,
    token_hash: &str,
) -> Result<bool, AxiamApiError> {
    let minted: Vec<SetupTokenRow> = db
        .query("SELECT created_at FROM type::record('bootstrap_setup_token', $hash)")
        .bind(("hash", token_hash.to_string()))
        .await
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?
        .take(0)
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;
    if minted.is_empty() {
        return Ok(false);
    }

    let consumed: Vec<ConsumedTokenRow> = db
        .query("SELECT consumed_at FROM type::record('bootstrap_setup_token_consumed', $hash)")
        .bind(("hash", token_hash.to_string()))
        .await
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?
        .take(0)
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;

    Ok(consumed.is_empty())
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BootstrapResponse {
    pub message: String,
    pub organization_id: Uuid,
    pub organization_slug: String,
    pub tenant_id: Uuid,
    pub tenant_slug: String,
    pub user_id: Uuid,
}

// -----------------------------------------------------------------------
// Handler
// -----------------------------------------------------------------------

/// `POST /api/v1/admin/bootstrap` — first-run admin setup.
///
/// Creates the initial admin user with the super-admin role and seeds the
/// default permission set. First-super-admin creation is atomic (SECHRD-04
/// / D-03c): a uniqueness-invariant `bootstrap_lock` CREATE inside the same
/// transaction means a second call — concurrent OR sequential — against a
/// tenant that already has an admin is refused with 409 Conflict; no
/// partial admin or orphan role RELATE can result. No token is issued —
/// the user must authenticate via `/api/v1/auth/login` (D-11).
///
/// Mandatory gate (D-03a): requires EITHER `AXIAM_BOOTSTRAP_ADMIN_EMAIL` set
/// and matching the request email (403 on mismatch), OR a valid setup_token
/// (403 if missing/invalid/already consumed).
#[utoipa::path(
    post,
    path = "/api/v1/admin/bootstrap",
    tag = "admin",
    request_body = BootstrapRequest,
    responses(
        (status = 201, description = "Organization, tenant and admin user created", body = BootstrapResponse),
        (status = 400, description = "Invalid request (missing required fields)"),
        (status = 403, description = "Bootstrap gate not satisfied (email mismatch or invalid/missing setup token)"),
        (status = 409, description = "Bootstrap already completed"),
    )
)]
pub async fn bootstrap<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    body: web::Json<BootstrapRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();

    // 1. Mandatory fail-closed gate (SECHRD-04 / D-03a): EITHER
    //    AXIAM_BOOTSTRAP_ADMIN_EMAIL must be set and match the request
    //    email (D-10, existing behavior — preserved verbatim), OR the
    //    request must carry a setup token whose hash is minted and not yet
    //    consumed. Both unset/invalid => refuse. An unset gate never
    //    allows bootstrap.
    let mut consumed_token_hash: Option<String> = None;
    match std::env::var("AXIAM_BOOTSTRAP_ADMIN_EMAIL") {
        Ok(expected) => {
            // Env gate IS set — preserve the existing email-match behavior.
            if req.email != expected {
                return Err(AxiamApiError(AxiamError::AuthorizationDenied {
                    reason: "email does not match AXIAM_BOOTSTRAP_ADMIN_EMAIL".into(),
                    action: None,
                    resource_id: None,
                }));
            }
        }
        Err(_) => {
            // Env gate NOT set — fall back to the one-time setup token.
            let token = req.setup_token.as_deref().filter(|t| !t.is_empty());
            let token_hash = match token {
                Some(t) => hash_setup_token(t),
                None => {
                    return Err(AxiamApiError(AxiamError::AuthorizationDenied {
                        reason: "bootstrap gate not satisfied: set \
                                 AXIAM_BOOTSTRAP_ADMIN_EMAIL or provide a valid \
                                 setup_token"
                            .into(),
                        action: None,
                        resource_id: None,
                    }));
                }
            };
            if !setup_token_is_valid(&state.db.current(), &token_hash).await? {
                return Err(AxiamApiError(AxiamError::AuthorizationDenied {
                    reason: "setup token is invalid, unknown, or already consumed".into(),
                    action: None,
                    resource_id: None,
                }));
            }
            consumed_token_hash = Some(token_hash);
        }
    }

    // 2. Validate required fields and derive slugs.
    if req.organization_name.trim().is_empty()
        || req.email.trim().is_empty()
        || req.username.trim().is_empty()
        || req.password.is_empty()
    {
        return Err(AxiamApiError(AxiamError::Validation {
            message: "organization_name, email, username and password are required".into(),
        }));
    }
    let org_slug = req
        .organization_slug
        .as_deref()
        .map(slugify)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| slugify(&req.organization_name));
    if org_slug.is_empty() {
        return Err(AxiamApiError(AxiamError::Validation {
            message: "organization_name must contain at least one alphanumeric character".into(),
        }));
    }
    let tenant_name = req
        .tenant_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("Default")
        .to_string();
    let tenant_slug = req
        .tenant_slug
        .as_deref()
        .map(slugify)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let s = slugify(&tenant_name);
            if s.is_empty() { "default".into() } else { s }
        });

    // 3. Fast-fail one-shot gate: if the global bootstrap lock already exists
    //    the system has been initialized. The authoritative guard is the
    //    `bootstrap_lock:global` CREATE inside the atomic transaction below;
    //    this pre-check just avoids creating a duplicate org on a call that is
    //    going to be refused anyway.
    let existing_lock: Vec<BootstrapLockRow> = state
        .db
        .current()
        .query("SELECT locked_at FROM type::record('bootstrap_lock', 'global')")
        .await
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?
        .take(0)
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;
    if !existing_lock.is_empty() {
        return Err(AxiamApiError(AxiamError::AlreadyExists {
            entity: "bootstrap".into(),
        }));
    }

    // 4. Provision the organization and default tenant. Get-or-create by slug
    //    so a retry after a transient mid-flight failure reuses the same
    //    org/tenant instead of leaking duplicates (the `bootstrap_lock:global`
    //    invariant below still guarantees exactly one successful bootstrap).
    // 3b. Resolve and validate the SRP baseline BEFORE anything is written.
    //
    // Placement is the point: a refusal here must leave the deployment
    // completely untouched. Validating after the organization exists would
    // turn a bad request into a half-initialised system that the next
    // bootstrap attempt then collides with.
    let srp_policy = SrpPolicy {
        srp_mode: req.srp_mode.unwrap_or_default(),
        srp_group: req.srp_group.unwrap_or_default(),
        srp_kdf: req.srp_kdf.unwrap_or_default(),
    };

    // Refuse the one combination that produces an unrecoverable deployment:
    // SRP required, and the sole administrator has no verifier. There is no
    // second admin to fix it and no password path to fall back to.
    let srp_enrollment = match (srp_policy.srp_mode, req.srp.as_ref()) {
        (SrpMode::Required, None) => {
            return Err(AxiamApiError(AxiamError::Validation {
                message: "srp_mode=required requires an `srp` verifier for the \
                          bootstrap admin: without one this deployment would have \
                          no way to authenticate its only administrator"
                    .into(),
            }));
        }
        (SrpMode::Disabled, Some(_)) => {
            return Err(AxiamApiError(AxiamError::Validation {
                message: "an `srp` verifier was supplied but srp_mode is disabled".into(),
            }));
        }
        (_, enrollment) => enrollment,
    };

    // Parse before anything is written, so a malformed verifier is a 400 on an
    // untouched deployment rather than a half-bootstrapped one.
    let parsed_srp = match srp_enrollment {
        Some(enrollment) => {
            let (group, params, salt, verifier) = enrollment.parse()?;
            if group.bits() < srp_policy.srp_group.bits() {
                return Err(AxiamApiError(AxiamError::Validation {
                    message: format!(
                        "srp group {group} is weaker than the seeded baseline {}",
                        srp_policy.srp_group
                    ),
                }));
            }
            Some((group, params, salt, verifier))
        }
        None => None,
    };

    let org = match state.org_repo.get_by_slug(&org_slug).await {
        Ok(o) => o,
        Err(_) => state
            .org_repo
            .create(CreateOrganization {
                name: req.organization_name.trim().to_string(),
                slug: org_slug.clone(),
                metadata: None,
            })
            .await
            .map_err(|e| {
                AxiamApiError(AxiamError::Internal(format!("create organization: {e}")))
            })?,
    };
    let tenant = match state.tenant_repo.get_by_slug(org.id, &tenant_slug).await {
        Ok(t) => t,
        Err(_) => state
            .tenant_repo
            .create(CreateTenant {
                organization_id: org.id,
                name: tenant_name,
                slug: tenant_slug.clone(),
                metadata: None,
            })
            .await
            .map_err(|e| AxiamApiError(AxiamError::Internal(format!("create tenant: {e}"))))?,
    };
    let tenant_id = tenant.id;

    // 4b. Seed the organization's security baseline, including the SRP policy
    // validated above. Written before the admin transaction so the verifier is
    // stored under the policy it was checked against.
    {
        use axiam_core::models::settings::system_defaults;
        use axiam_core::repository::SettingsRepository as _;

        let mut baseline = system_defaults();
        baseline.srp_mode = srp_policy.srp_mode;
        baseline.srp_group = srp_policy.srp_group;
        baseline.srp_kdf = srp_policy.srp_kdf;
        state
            .settings_repo
            .set_org_settings(org.id, baseline)
            .await?;
    }

    // 5. Seed permissions (idempotent).
    seed_permissions(&state.db.current(), tenant_id, PERMISSION_REGISTRY)
        .await
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;

    // 6. Seed default roles and get their IDs.
    let seed_result = seed_default_roles(&state.db.current(), tenant_id, PERMISSION_REGISTRY)
        .await
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;

    // 5+6. SECHRD-04 / D-03c: create the admin user and assign the
    // super-admin role atomically, keyed on a uniqueness invariant instead
    // of the old SELECT-then-branch TOCTOU check.
    //
    // `CREATE type::record('bootstrap_lock', $tenant_id)` is the uniqueness
    // invariant: a concurrent OR sequential second request racing/retrying
    // on the SAME tenant_id hits a UNIQUE-index violation on this CREATE
    // (the record ID itself IS the constraint) and its WHOLE transaction
    // rolls back — no partial admin, no orphan role RELATE. When a setup
    // token was used, its hash is consumed in the SAME transaction
    // (`bootstrap_setup_token_consumed`), so a replay of the same token
    // also loses to the same violation. The admin's initial password hash
    // is seeded into `password_history` in the same transaction too
    // (Pitfall 5 — bootstrap bypasses `create_with_consent`).
    //
    // Password hashing is Argon2id and must happen before the transaction.
    //
    // SurrealDB v3 quirk: BEGIN TRANSACTION occupies result slot 0;
    // the first statement result is at .take(1). (See MEMORY.md)
    let user_id = new_id();
    let user_id_str = user_id.to_string();
    // Captured before `req.username` is consumed by the query bindings below.
    let username_for_srp = req.username.clone();
    let role_id_str = seed_result.super_admin_role_id.to_string();
    let tenant_id_str = tenant_id.to_string();
    let ph_id_str = new_id().to_string();

    // Apply the server-configured password pepper (REQ-14 AC-1) — the same
    // pepper the user repository uses at login-time verification. Previously
    // this hashed with `None`, so a deployment that set AXIAM__AUTH__PEPPER
    // could never authenticate the bootstrap admin (login verifies WITH the
    // pepper, but this stored a hash computed WITHOUT it → "invalid credentials").
    let pepper = state.auth_config.pepper.as_ref().map(|p| p.expose_secret());
    let password_hash = password::hash_password(&req.password, pepper)
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;

    // The RELATE uses backtick record IDs (required when type::record() is not
    // supported inside RELATE per SurrealDB v3 quirk).
    // The `bootstrap_lock:global` CREATE is the global one-shot invariant: a
    // concurrent OR sequential second bootstrap hits a UNIQUE record-ID
    // violation here and its whole transaction rolls back — no partial admin,
    // no duplicate super-admin.
    let mut txn_stmts = vec![
        "BEGIN TRANSACTION".to_string(),
        "CREATE type::record('bootstrap_lock', 'global') SET locked_at = time::now()".to_string(),
        "CREATE type::record('user', $user_id) SET \
           tenant_id = $tenant_id, \
           username = $username, email = $email, \
           password_hash = $password_hash, \
           status = 'Active', \
           mfa_enabled = false, \
           failed_login_attempts = 0, \
           last_failed_login_at = NONE, \
           locked_until = NONE, \
           email_verified_at = NONE, \
           metadata = {}"
            .to_string(),
        format!(
            "RELATE user:`{user_id_str}` -> has_role -> role:`{role_id_str}` \
             SET resource_id = NONE"
        ),
        "CREATE type::record('password_history', $ph_id) SET \
           tenant_id = $tenant_id, user_id = $user_id, password_hash = $password_hash"
            .to_string(),
    ];
    // The verifier goes in the SAME transaction as the admin user, not after
    // it. A failure between the two would leave an administrator with no
    // verifier on a deployment seeded as `required` — precisely the
    // unrecoverable state the validation above exists to prevent, reachable
    // instead by a mid-write crash.
    if parsed_srp.is_some() {
        txn_stmts.push(
            "CREATE type::record('srp_credential', $srp_id) SET \
               tenant_id = $tenant_id, \
               user_id = $user_id, \
               identity = $srp_identity, \
               srp_group = $srp_group, \
               kdf = $srp_kdf, \
               kdf_memory_kib = $srp_memory_kib, \
               kdf_iterations = $srp_iterations, \
               kdf_parallelism = $srp_parallelism, \
               salt = $srp_salt, \
               verifier = $srp_verifier"
                .to_string(),
        );
    }
    if consumed_token_hash.is_some() {
        txn_stmts.push(
            "CREATE type::record('bootstrap_setup_token_consumed', $token_hash) \
             SET consumed_at = time::now()"
                .to_string(),
        );
    }
    txn_stmts.push("COMMIT TRANSACTION".to_string());
    let txn_query = txn_stmts.join("; ");

    // The builder is re-bound below, so it outlives this statement — hold the
    // resolved handle in a named local rather than a temporary.
    let db = state.db.current();
    let mut query = db
        .query(txn_query)
        .bind(("tenant_id", tenant_id_str))
        .bind(("user_id", user_id_str.clone()))
        .bind(("username", req.username))
        .bind(("email", req.email))
        .bind(("password_hash", password_hash))
        .bind(("ph_id", ph_id_str));
    if let Some(token_hash) = consumed_token_hash {
        query = query.bind(("token_hash", token_hash));
    }
    if let Some((group, params, salt, verifier)) = parsed_srp {
        let (memory_kib, iterations, parallelism) = match params {
            SrpKdfParams::Argon2id {
                memory_kib,
                iterations,
                parallelism,
            } => (Some(memory_kib), iterations, Some(parallelism)),
            SrpKdfParams::Pbkdf2Sha256 { iterations } => (None, iterations, None),
        };
        query = query
            .bind(("srp_id", new_id().to_string()))
            // `username_for_srp`, captured before `req.username` is moved into
            // the bindings above: the verifier is bound to the identity, and
            // binding it to anything else produces one no login can satisfy.
            .bind(("srp_identity", username_for_srp))
            .bind(("srp_group", group.to_string()))
            .bind(("srp_kdf", params.kdf().to_string()))
            .bind(("srp_memory_kib", memory_kib))
            .bind(("srp_iterations", iterations))
            .bind(("srp_parallelism", parallelism))
            .bind(("srp_salt", salt))
            .bind(("srp_verifier", verifier));
    }

    let result = query
        .await
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;

    result.check().map_err(|e| {
        let msg = e.to_string();
        // A UNIQUE violation here is `bootstrap_lock`'s implicit record-ID
        // constraint: somebody else won the race to initialise this
        // deployment, and the loser must get a 409 rather than a second admin.
        //
        // What counts as a UNIQUE violation is decided in exactly one place
        // (D-09) -- `axiam_db::helpers::is_unique_violation`. This site calls
        // the predicate rather than a whole classifier so it can keep the
        // "bootstrap transaction:" prefix on the non-conflict branch, which is
        // what makes a failure here findable in the server log.
        if axiam_db::helpers::is_unique_violation(&msg) {
            AxiamApiError(AxiamError::AlreadyExists {
                entity: "bootstrap".into(),
            })
        } else {
            AxiamApiError(AxiamError::Internal(format!(
                "bootstrap transaction: {msg}"
            )))
        }
    })?;

    // 7. Return 201 — no token (user must login via /api/v1/auth/login, per D-11).
    Ok(HttpResponse::Created().json(BootstrapResponse {
        message: "Organization, tenant and admin user created. Login via /api/v1/auth/login."
            .into(),
        organization_id: org.id,
        organization_slug: org_slug,
        tenant_id,
        tenant_slug,
        user_id,
    }))
}
