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
use axiam_core::repository::{OrganizationRepository, TenantRepository};
use axiam_db::{seed_default_roles, seed_permissions};
use chrono::{DateTime, Utc};
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
        (status = 201, description = "Admin user created", body = BootstrapResponse),
        (status = 403, description = "Bootstrap gate not satisfied (email mismatch or invalid/missing setup token)"),
        (status = 409, description = "Bootstrap already completed for this tenant"),
        (status = 400, description = "Organization or tenant not found"),
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
            if !setup_token_is_valid(&state.db, &token_hash).await? {
                return Err(AxiamApiError(AxiamError::AuthorizationDenied {
                    reason: "setup token is invalid, unknown, or already consumed".into(),
                    action: None,
                    resource_id: None,
                }));
            }
            consumed_token_hash = Some(token_hash);
        }
    }

    // 2. Verify org and tenant exist.
    state.org_repo.get_by_id(req.org_id).await.map_err(|_| {
        AxiamApiError(AxiamError::Validation {
            message: "organization not found".into(),
        })
    })?;
    state
        .tenant_repo
        .get_by_id(req.tenant_id)
        .await
        .map_err(|_| {
            AxiamApiError(AxiamError::Validation {
                message: "tenant not found".into(),
            })
        })?;

    // 3. Seed permissions (idempotent).
    seed_permissions(&state.db, req.tenant_id, PERMISSION_REGISTRY)
        .await
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;

    // 4. Seed default roles and get their IDs.
    let seed_result = seed_default_roles(&state.db, req.tenant_id, PERMISSION_REGISTRY)
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
    let user_id = Uuid::new_v4();
    let user_id_str = user_id.to_string();
    let role_id_str = seed_result.super_admin_role_id.to_string();
    let tenant_id_str = req.tenant_id.to_string();
    let ph_id_str = Uuid::new_v4().to_string();

    let password_hash = password::hash_password(&req.password, None)
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;

    // The RELATE uses backtick record IDs (required when type::record() is not
    // supported inside RELATE per SurrealDB v3 quirk).
    let mut txn_stmts = vec![
        "BEGIN TRANSACTION".to_string(),
        "CREATE type::record('bootstrap_lock', $tenant_id) SET locked_at = time::now()".to_string(),
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
    if consumed_token_hash.is_some() {
        txn_stmts.push(
            "CREATE type::record('bootstrap_setup_token_consumed', $token_hash) \
             SET consumed_at = time::now()"
                .to_string(),
        );
    }
    txn_stmts.push("COMMIT TRANSACTION".to_string());
    let txn_query = txn_stmts.join("; ");

    let mut query = state
        .db
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

    let result = query
        .await
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;

    result.check().map_err(|e| {
        let msg = e.to_string();
        // SurrealDB v3 UNIQUE index violation message contains "already
        // contains" (e.g. bootstrap_lock's implicit record-ID uniqueness
        // constraint). Also match "already exists" and "unique" as
        // fallback patterns (mirrors saml_replay.rs::insert_assertion).
        if msg.contains("already contains")
            || msg.contains("already exists")
            || msg.contains("unique")
        {
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
        message: "Admin user created. Login via /api/v1/auth/login.".into(),
        user_id,
    }))
}
