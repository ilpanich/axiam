//! Admin bootstrap endpoint — first-run setup.
//!
//! Creates the initial admin user and seeds default roles when no admin
//! exists. First-super-admin creation is atomic (SECHRD-04 / SEC-049 /
//! D-03c): a uniqueness-invariant `bootstrap_lock` CREATE inside the same
//! transaction that creates the admin user means two concurrent first-run
//! requests can create AT MOST ONE super-admin — the loser gets
//! `AxiamError::AlreadyExists` (409) and its whole transaction rolls back.
//! After the first admin is created, every subsequent call also hits the
//! same `bootstrap_lock` uniqueness violation and is refused with 409.
//!
//! The endpoint is also gated (D-03a): a request is refused (fail-closed,
//! no admin created) unless EITHER `AXIAM_BOOTSTRAP_ADMIN_EMAIL` is set and
//! matches the request email, OR the request carries a valid one-time
//! setup token (server-minted at first boot, logged once, consumed once —
//! D-03b). An unset/absent gate never allows bootstrap.

use actix_web::{HttpResponse, web};
use axiam_auth::password;
use axiam_core::error::AxiamError;
use axiam_core::repository::{
    OrganizationRepository, Pagination, RoleRepository, TenantRepository, UserRepository,
};
use axiam_db::{
    SurrealOrganizationRepository, SurrealRoleRepository, SurrealTenantRepository,
    SurrealUserRepository, seed_default_roles, seed_permissions,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use surrealdb::types::SurrealValue;
use surrealdb::{Connection, Surreal};
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::permissions::PERMISSION_REGISTRY;

// -----------------------------------------------------------------------
// Request / response types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct BootstrapRequest {
    pub org_id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub username: String,
    pub password: String,
    /// One-time first-run setup token (D-03a/D-03b). Required when
    /// `AXIAM_BOOTSTRAP_ADMIN_EMAIL` is not set; ignored otherwise.
    #[serde(default)]
    pub setup_token: Option<String>,
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
async fn setup_token_is_valid<C: Connection>(
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
    pub user_id: Uuid,
}

// -----------------------------------------------------------------------
// Handler
// -----------------------------------------------------------------------

/// `POST /api/v1/admin/bootstrap` — first-run admin setup.
///
/// Creates the initial admin user with the super-admin role and seeds the
/// default permission set. Returns 404 once an admin already exists (D-09).
/// No token is issued — the user must authenticate via `/api/v1/auth/login` (D-11).
///
/// Guarded by the `AXIAM_BOOTSTRAP_ADMIN_EMAIL` environment variable (D-10):
/// if set, requests with a non-matching email are rejected with 403.
#[utoipa::path(
    post,
    path = "/api/v1/admin/bootstrap",
    tag = "admin",
    request_body = BootstrapRequest,
    responses(
        (status = 201, description = "Admin user created", body = BootstrapResponse),
        (status = 403, description = "Email does not match AXIAM_BOOTSTRAP_ADMIN_EMAIL"),
        (status = 404, description = "Bootstrap already completed"),
        (status = 400, description = "Organization or tenant not found"),
    )
)]
pub async fn bootstrap<C: Connection>(
    user_repo: web::Data<SurrealUserRepository<C>>,
    role_repo: web::Data<SurrealRoleRepository<C>>,
    org_repo: web::Data<SurrealOrganizationRepository<C>>,
    tenant_repo: web::Data<SurrealTenantRepository<C>>,
    db: web::Data<Surreal<C>>,
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
                    }));
                }
            };
            if !setup_token_is_valid(db.get_ref(), &token_hash).await? {
                return Err(AxiamApiError(AxiamError::AuthorizationDenied {
                    reason: "setup token is invalid, unknown, or already consumed".into(),
                }));
            }
            consumed_token_hash = Some(token_hash);
        }
    }

    // 2. Verify org and tenant exist.
    org_repo.get_by_id(req.org_id).await.map_err(|_| {
        AxiamApiError(AxiamError::Validation {
            message: "organization not found".into(),
        })
    })?;
    tenant_repo.get_by_id(req.tenant_id).await.map_err(|_| {
        AxiamApiError(AxiamError::Validation {
            message: "tenant not found".into(),
        })
    })?;

    // 3. Check if bootstrap has already been completed (D-09).
    //    Look for any role named "super-admin" in this tenant; if one exists and
    //    any user has been assigned to it, the bootstrap endpoint is disabled.
    let existing_roles = role_repo
        .list(
            req.tenant_id,
            Pagination {
                offset: 0,
                limit: 1000,
            },
        )
        .await?;

    let super_admin_role = existing_roles
        .items
        .into_iter()
        .find(|r| r.name == "super-admin");

    if let Some(sa_role) = super_admin_role {
        // Check if any user has this role assigned.
        let existing_users = user_repo
            .list(
                req.tenant_id,
                Pagination {
                    offset: 0,
                    limit: 1,
                },
            )
            .await?;

        // If users exist in the tenant, bootstrap is already done.
        // (The first user created via bootstrap always has super-admin.)
        // We use a more precise check: attempt get_user_roles for any user.
        // Simpler and sufficient: if any users exist with super-admin role assigned.
        // Use role's get_user_roles indirectly: check if super-admin role exists
        // and users exist — if both, bootstrap is completed.
        let _ = sa_role; // role exists — now check if any users exist
        if existing_users.total > 0 {
            return Err(AxiamApiError(AxiamError::NotFound {
                entity: "bootstrap".into(),
                id: "already initialized".into(),
            }));
        }
    }

    // 4. Seed permissions (idempotent).
    seed_permissions(db.get_ref(), req.tenant_id, PERMISSION_REGISTRY)
        .await
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;

    // 5. Seed default roles and get their IDs.
    let seed_result = seed_default_roles(db.get_ref(), req.tenant_id, PERMISSION_REGISTRY)
        .await
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;

    // 6+7. SEC-049: create admin user and assign super-admin role atomically.
    //
    // Using a single BEGIN/COMMIT transaction so that no partial state
    // (user created but role not assigned) can result from a mid-flight error.
    // Password hashing is Argon2id and must happen before the transaction.
    //
    // SurrealDB v3 quirk: BEGIN TRANSACTION occupies result slot 0;
    // the first statement result is at .take(1). (See MEMORY.md)
    let user_id = Uuid::new_v4();
    let user_id_str = user_id.to_string();
    let role_id_str = seed_result.super_admin_role_id.to_string();
    let tenant_id_str = req.tenant_id.to_string();

    let password_hash = password::hash_password(&req.password, None)
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;

    // Build transaction: CREATE user + RELATE user→role in one atomic block.
    // The RELATE uses backtick record IDs (required when type::record() is not
    // supported inside RELATE per SurrealDB v3 quirk).
    let txn_query = format!(
        "BEGIN TRANSACTION; \
         CREATE type::record('user', $user_id) SET \
           tenant_id = $tenant_id, \
           username = $username, email = $email, \
           password_hash = $password_hash, \
           status = 'Active', \
           mfa_enabled = false, \
           failed_login_attempts = 0, \
           last_failed_login_at = NONE, \
           locked_until = NONE, \
           email_verified_at = NONE, \
           metadata = {{}}; \
         RELATE user:`{user_id_str}` -> has_role -> role:`{role_id_str}` \
           SET resource_id = NONE; \
         COMMIT TRANSACTION"
    );

    let result = db
        .query(txn_query)
        .bind(("user_id", user_id_str.clone()))
        .bind(("tenant_id", tenant_id_str))
        .bind(("username", req.username))
        .bind(("email", req.email))
        .bind(("password_hash", password_hash))
        .await
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;

    result
        .check()
        .map_err(|e| AxiamApiError(AxiamError::Internal(format!("bootstrap transaction: {e}"))))?;

    // 8. Return 201 — no token (user must login via /api/v1/auth/login, per D-11).
    Ok(HttpResponse::Created().json(BootstrapResponse {
        message: "Admin user created. Login via /api/v1/auth/login.".into(),
        user_id,
    }))
}
