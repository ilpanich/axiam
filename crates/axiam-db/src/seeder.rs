//! Startup seeders for populating static data.
//!
//! The permission seeder uses raw SurrealQL `UPSERT` to ensure idempotency
//! under concurrent startup (per D-07). A deterministic UUID derived from
//! `namespace = tenant_id` + `name = action` ensures the same record is
//! always targeted on subsequent restarts — true idempotency via UPSERT.
//!
//! CQ-B42: a sha256 hash of the registry is persisted in `seeder_state` per
//! tenant. On startup, if the hash matches the stored value the UPSERT loop is
//! skipped entirely, eliminating the O(n×95) boot storm on unchanged systems.

use axiam_core::models::role::CreateRole;
use axiam_core::repository::{Pagination, PermissionRepository, RoleRepository};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::helpers::{CountRow, classify_write_error};
use crate::repository::{SurrealPermissionRepository, SurrealRoleRepository};

/// Row struct for reading a seeder_state record.
#[derive(SurrealValue)]
pub struct SeederStateRow {
    pub hash: String,
}

/// Result returned by [`seed_default_roles`].
pub struct SeedRolesResult {
    pub super_admin_role_id: Uuid,
    pub admin_role_id: Uuid,
    pub viewer_role_id: Uuid,
}

/// Seed all permissions in `registry` for the given `tenant_id`.
///
/// # Idempotency
///
/// A deterministic UUID is generated for each `(tenant_id, action)` pair
/// using [`Uuid::new_v5`] with `tenant_id` as the namespace.  The same pair
/// always produces the same record ID, so the UPSERT targets the same row on
/// every restart.
///
/// # SurrealQL
///
/// Uses raw `UPSERT` — NOT `list()` + conditional `create()`.  The hand-rolled
/// pattern is race-prone under concurrent startup (per RESEARCH.md) and is
/// explicitly prohibited by D-07.
pub async fn seed_permissions<C: Connection>(
    db: &Surreal<C>,
    tenant_id: Uuid,
    registry: &[(&str, &str)],
) -> Result<(), DbError> {
    // CQ-B42: compute sha256 hash of the registry to guard against UPSERT storm.
    let registry_hash = {
        let mut h = Sha256::new();
        for (action, desc) in registry {
            h.update(action.as_bytes());
            h.update(b"|");
            h.update(desc.as_bytes());
        }
        hex::encode(h.finalize())
    };

    // Derive a stable per-tenant record ID for seeder_state.
    let state_id = Uuid::new_v5(&tenant_id, b"seeder_state").to_string();

    // Check existing seeder_state; skip UPSERT loop if hash is unchanged.
    let existing: Vec<SeederStateRow> = db
        .query("SELECT hash FROM type::record('seeder_state', $id)")
        .bind(("id", state_id.clone()))
        .await
        .map_err(|e| DbError::Migration(format!("seeder_state read failed: {e}")))?
        .take(0)
        .map_err(|e| DbError::Migration(format!("seeder_state take failed: {e}")))?;

    if existing
        .first()
        .map(|r| r.hash.as_str())
        .is_some_and(|h| h == registry_hash.as_str())
    {
        tracing::debug!(
            %tenant_id,
            "seed_permissions: registry hash unchanged — skipping UPSERT storm (CQ-B42)"
        );
        return Ok(());
    }

    for (action, description) in registry {
        // Deterministic UUID: same tenant + action always produces same ID.
        let id = Uuid::new_v5(&tenant_id, action.as_bytes());
        let id_str = id.to_string();
        let tenant_str = tenant_id.to_string();

        db.query(
            "UPSERT type::record('permission', $id) SET \
             tenant_id = $tenant_id, \
             action = $action, \
             description = $description, \
             created_at = IF (SELECT created_at FROM type::record('permission', $id))[0].created_at \
               THEN (SELECT created_at FROM type::record('permission', $id))[0].created_at \
               ELSE time::now() END, \
             updated_at = time::now()",
        )
        .bind(("id", id_str))
        .bind(("tenant_id", tenant_str))
        .bind(("action", action.to_string()))
        .bind(("description", description.to_string()))
        .await
        .map_err(|e| DbError::Migration(format!("seed_permissions UPSERT failed: {e}")))?
        .check()
        .map_err(|e| DbError::Migration(format!("seed_permissions UPSERT check failed: {e}")))?;
    }

    // Persist the new hash so subsequent restarts can skip this tenant.
    let tenant_str = tenant_id.to_string();
    db.query(
        "UPSERT type::record('seeder_state', $id) SET \
         tenant_id = $tenant_id, hash = $hash, updated_at = time::now()",
    )
    .bind(("id", state_id))
    .bind(("tenant_id", tenant_str))
    .bind(("hash", registry_hash))
    .await
    .map_err(|e| DbError::Migration(format!("seeder_state upsert failed: {e}")))?
    .check()
    .map_err(|e| DbError::Migration(format!("seeder_state upsert check: {e}")))?;

    Ok(())
}

/// Mint a one-time first-run bootstrap setup token if the database has
/// never been bootstrapped (SECHRD-04 / D-03b).
///
/// # Behavior
///
/// - On a fresh (never-bootstrapped) database — no `bootstrap_setup_token`
///   row yet AND no `user` row anywhere — a cryptographically random token
///   is generated, its sha256 hash is persisted as the
///   `bootstrap_setup_token` record ID, and the returned `Some(token)`
///   carries the PLAINTEXT token so the caller can log it exactly once
///   (the one deliberate secret-log exception, per D-03b). Only the HASH
///   is ever persisted to the database.
/// - On any subsequent boot — a setup token already exists, or at least
///   one user already exists — this is a no-op and returns `Ok(None)`;
///   nothing is minted or re-logged.
pub async fn mint_bootstrap_setup_token_if_needed<C: Connection>(
    db: &Surreal<C>,
) -> Result<Option<String>, DbError> {
    // A setup token was already minted — no-op.
    let existing_tokens: Vec<CountRow> = db
        .query("SELECT count() AS total FROM bootstrap_setup_token GROUP ALL")
        .await
        .map_err(|e| DbError::Migration(format!("bootstrap_setup_token count failed: {e}")))?
        .take(0)
        .map_err(|e| DbError::Migration(format!("bootstrap_setup_token count take failed: {e}")))?;
    if existing_tokens.first().map(|r| r.total).unwrap_or(0) > 0 {
        return Ok(None);
    }

    // Bootstrap already completed somewhere — no-op.
    let existing_users: Vec<CountRow> = db
        .query("SELECT count() AS total FROM user GROUP ALL")
        .await
        .map_err(|e| DbError::Migration(format!("user count failed: {e}")))?
        .take(0)
        .map_err(|e| DbError::Migration(format!("user count take failed: {e}")))?;
    if existing_users.first().map(|r| r.total).unwrap_or(0) > 0 {
        return Ok(None);
    }

    // Generate a cryptographically random 32-byte token, base64url-encoded
    // (same shape as `axiam_auth::token::generate_refresh_token`).
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rand::RngExt::random(&mut rng);
    let token = URL_SAFE_NO_PAD.encode(bytes);

    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let token_hash = hex::encode(hasher.finalize());

    db.query("CREATE type::record('bootstrap_setup_token', $hash) SET created_at = time::now()")
        .bind(("hash", token_hash))
        .await
        .map_err(|e| DbError::Migration(format!("bootstrap_setup_token mint failed: {e}")))?
        .check()
        .map_err(|e| DbError::Migration(format!("bootstrap_setup_token mint check failed: {e}")))?;

    Ok(Some(token))
}

/// Seed the three default roles — super-admin, admin, and viewer — for the
/// given tenant, assigning permissions according to D-12.
///
/// # Idempotency
///
/// If all three roles already exist the function returns their IDs without
/// creating duplicates. If only some roles are missing they are created.
///
/// # Permission assignment rules
///
/// - **super-admin**: every permission in the tenant.
/// - **admin**: every permission except `admin:bootstrap`.
/// - **viewer**: permissions whose action ends with `:list` or `:get`.
pub async fn seed_default_roles<C: Connection>(
    db: &Surreal<C>,
    tenant_id: Uuid,
    _permission_registry: &[(&str, &str)],
) -> Result<SeedRolesResult, DbError> {
    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());

    // -----------------------------------------------------------------------
    // 1. Ensure all three roles exist (idempotent)
    // -----------------------------------------------------------------------

    // Fetch existing roles for this tenant in a single list call.
    let existing = role_repo
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 1000,
            },
        )
        .await
        .map_err(|e| DbError::Migration(format!("seed_default_roles list roles failed: {e}")))?;

    let find_role = |name: &str| existing.items.iter().find(|r| r.name == name).map(|r| r.id);

    // SECHRD-04: role creation must tolerate a CONCURRENT racer creating the
    // same default role for the same tenant — `find_or_create_role` treats
    // the `idx_role_tenant_name` UNIQUE-index violation as "a concurrent
    // caller already won" and re-fetches the winner's row instead of
    // failing (see its doc comment for why this is now reachable).
    let super_admin_id = find_or_create_role(
        &role_repo,
        tenant_id,
        find_role("super-admin"),
        "super-admin",
        "Full system access — all permissions",
    )
    .await?;

    let admin_id = find_or_create_role(
        &role_repo,
        tenant_id,
        find_role("admin"),
        "admin",
        "Administrative access — all entity CRUD operations",
    )
    .await?;

    let viewer_id = find_or_create_role(
        &role_repo,
        tenant_id,
        find_role("viewer"),
        "viewer",
        "Read-only access — list and get operations",
    )
    .await?;

    // -----------------------------------------------------------------------
    // 2. Fetch all permissions for this tenant
    // -----------------------------------------------------------------------

    let permissions = perm_repo
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 10_000,
            },
        )
        .await
        .map_err(|e| {
            DbError::Migration(format!("seed_default_roles list permissions failed: {e}"))
        })?;

    // -----------------------------------------------------------------------
    // 3. Grant permissions to roles (idempotent — skip already-granted pairs)
    // -----------------------------------------------------------------------
    //
    // SECHRD-04: `grant_to_role` CREATEs a `grants` edge guarded by a UNIQUE
    // (in, out) index (CQ-B17) — re-granting an already-granted permission
    // is a hard error, not a silent no-op. Before this fix, `seed_default_roles`
    // was only ever called once per tenant (the old bootstrap TOCTOU check
    // disabled the endpoint before a second call could reach here). Now that
    // bootstrap atomicity is enforced by the `bootstrap_lock` uniqueness
    // invariant instead, this function can be reached again — including
    // CONCURRENTLY, by two racing bootstrap requests — for a tenant whose
    // roles+grants already exist. The pre-fetch below skips already-granted
    // pairs in the common (sequential retry) case; `grant_to_role_idempotent`
    // additionally tolerates the residual TOCTOU window between this
    // pre-fetch and the CREATE, for true concurrent callers.

    let super_admin_have = granted_permission_ids(&perm_repo, tenant_id, super_admin_id).await?;
    let admin_have = granted_permission_ids(&perm_repo, tenant_id, admin_id).await?;
    let viewer_have = granted_permission_ids(&perm_repo, tenant_id, viewer_id).await?;

    for perm in &permissions.items {
        // super-admin gets ALL permissions.
        if !super_admin_have.contains(&perm.id) {
            grant_to_role_idempotent(&perm_repo, tenant_id, super_admin_id, perm.id)
                .await
                .map_err(|e| {
                    DbError::Migration(format!(
                        "seed_default_roles grant super-admin permission {} failed: {e}",
                        perm.action
                    ))
                })?;
        }

        // admin gets every permission EXCEPT admin:bootstrap.
        if perm.action != "admin:bootstrap" && !admin_have.contains(&perm.id) {
            grant_to_role_idempotent(&perm_repo, tenant_id, admin_id, perm.id)
                .await
                .map_err(|e| {
                    DbError::Migration(format!(
                        "seed_default_roles grant admin permission {} failed: {e}",
                        perm.action
                    ))
                })?;
        }

        // viewer gets only :list and :get permissions.
        if (perm.action.ends_with(":list") || perm.action.ends_with(":get"))
            && !viewer_have.contains(&perm.id)
        {
            grant_to_role_idempotent(&perm_repo, tenant_id, viewer_id, perm.id)
                .await
                .map_err(|e| {
                    DbError::Migration(format!(
                        "seed_default_roles grant viewer permission {} failed: {e}",
                        perm.action
                    ))
                })?;
        }
    }

    Ok(SeedRolesResult {
        super_admin_role_id: super_admin_id,
        admin_role_id: admin_id,
        viewer_role_id: viewer_id,
    })
}

/// Find an existing role by name, or create it — tolerating a CONCURRENT
/// caller creating the SAME (tenant_id, name) role at the same time.
///
/// `role_repo.create()` CREATEs a fresh-UUID row guarded by the
/// `idx_role_tenant_name` UNIQUE index; two racing bootstrap requests can
/// both observe "role missing" and both attempt a create. The loser's
/// UNIQUE-index violation is NOT a real failure here — a concurrent caller
/// already won and the row exists — so it is treated as "re-fetch and use
/// the winner's ID" rather than propagated (SECHRD-04: `seed_default_roles`
/// is reachable from two concurrent bootstrap requests now that atomicity
/// is enforced by `bootstrap_lock`, not the old TOCTOU check).
async fn find_or_create_role<C: Connection>(
    role_repo: &SurrealRoleRepository<C>,
    tenant_id: Uuid,
    existing_id: Option<Uuid>,
    name: &str,
    description: &str,
) -> Result<Uuid, DbError> {
    if let Some(id) = existing_id {
        return Ok(id);
    }

    match role_repo
        .create(CreateRole {
            tenant_id,
            name: name.to_string(),
            description: description.to_string(),
            is_global: true,
        })
        .await
    {
        Ok(role) => Ok(role.id),
        Err(e) => {
            let msg = e.to_string();
            match classify_write_error(&msg, "role") {
                DbError::AlreadyExists { .. } => {
                    let refreshed = role_repo
                        .list(
                            tenant_id,
                            Pagination {
                                offset: 0,
                                limit: 1000,
                            },
                        )
                        .await
                        .map_err(|e| {
                            DbError::Migration(format!(
                                "find_or_create_role re-list '{name}' failed: {e}"
                            ))
                        })?;
                    refreshed
                        .items
                        .into_iter()
                        .find(|r| r.name == name)
                        .map(|r| r.id)
                        .ok_or_else(|| {
                            DbError::Migration(format!(
                                "find_or_create_role: role '{name}' vanished after concurrent create race"
                            ))
                        })
                }
                _ => Err(DbError::Migration(format!(
                    "find_or_create_role '{name}' failed: {msg}"
                ))),
            }
        }
    }
}

/// The set of permission IDs already granted to `role_id` (tenant-scoped).
///
/// Shared by [`seed_default_roles`] and [`reconcile_default_role_grants`] so
/// neither re-attempts a `grant_to_role` CREATE for a pair that already
/// exists — the `grants` edge table's UNIQUE (in, out) index (CQ-B17) makes
/// a duplicate grant a hard error, not a no-op.
async fn granted_permission_ids<C: Connection>(
    perm_repo: &SurrealPermissionRepository<C>,
    tenant_id: Uuid,
    role_id: Uuid,
) -> Result<std::collections::HashSet<Uuid>, DbError> {
    perm_repo
        .get_role_permissions(tenant_id, role_id)
        .await
        .map(|perms| perms.into_iter().map(|p| p.id).collect())
        .map_err(|e| DbError::Migration(format!("granted_permission_ids failed: {e}")))
}

/// Grant `permission_id` to `role_id`, treating "already granted" (a
/// concurrent caller won the same grant) as success rather than an error.
///
/// Closes the residual TOCTOU between [`granted_permission_ids`]'s pre-fetch
/// and this CREATE for two truly concurrent callers (SECHRD-04).
async fn grant_to_role_idempotent<C: Connection>(
    perm_repo: &SurrealPermissionRepository<C>,
    tenant_id: Uuid,
    role_id: Uuid,
    permission_id: Uuid,
) -> Result<(), DbError> {
    match perm_repo
        .grant_to_role(tenant_id, role_id, permission_id)
        .await
    {
        Ok(()) => Ok(()),
        Err(e) => match classify_write_error(e.to_string(), "permission_grant") {
            DbError::AlreadyExists { .. } => Ok(()),
            other => Err(other),
        },
    }
}

/// Reconcile the default roles' permission grants with the current permission
/// set for a tenant, granting only the permissions each role is MISSING.
///
/// [`seed_default_roles`] runs only at `/bootstrap`, which self-disables after
/// the first admin is created. Server startup, by contrast, runs
/// [`seed_permissions`] on every boot — so a permission ADDED to the registry
/// after the initial bootstrap exists as a row but is granted to no role,
/// causing spurious 403s for actions the super-admin/admin should be allowed
/// to perform (e.g. a newly-added `oauth2_clients:create`). Calling this on
/// startup back-fills those grants.
///
/// Idempotent: existing `grants` edges are left untouched and only missing
/// grants are created, so no duplicate edges accumulate across restarts.
/// Returns the number of grants created. Tenants without the default roles
/// (never bootstrapped) are skipped.
pub async fn reconcile_default_role_grants<C: Connection>(
    db: &Surreal<C>,
    tenant_id: Uuid,
) -> Result<usize, DbError> {
    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());

    let existing_roles = role_repo
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 1000,
            },
        )
        .await
        .map_err(|e| DbError::Migration(format!("reconcile list roles failed: {e}")))?;
    let find_role = |name: &str| {
        existing_roles
            .items
            .iter()
            .find(|r| r.name == name)
            .map(|r| r.id)
    };

    // Only reconcile tenants bootstrapped with the three default roles.
    let (Some(super_admin_id), Some(admin_id), Some(viewer_id)) = (
        find_role("super-admin"),
        find_role("admin"),
        find_role("viewer"),
    ) else {
        return Ok(0);
    };

    let permissions = perm_repo
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 10_000,
            },
        )
        .await
        .map_err(|e| DbError::Migration(format!("reconcile list permissions failed: {e}")))?;

    let sa_have = granted_permission_ids(&perm_repo, tenant_id, super_admin_id).await?;
    let admin_have = granted_permission_ids(&perm_repo, tenant_id, admin_id).await?;
    let viewer_have = granted_permission_ids(&perm_repo, tenant_id, viewer_id).await?;

    let mut created = 0usize;
    for perm in &permissions.items {
        // super-admin gets every permission.
        if !sa_have.contains(&perm.id) {
            perm_repo
                .grant_to_role(tenant_id, super_admin_id, perm.id)
                .await
                .map_err(|e| {
                    DbError::Migration(format!("reconcile grant super-admin failed: {e}"))
                })?;
            created += 1;
        }
        // admin gets every permission except admin:bootstrap.
        if perm.action != "admin:bootstrap" && !admin_have.contains(&perm.id) {
            perm_repo
                .grant_to_role(tenant_id, admin_id, perm.id)
                .await
                .map_err(|e| DbError::Migration(format!("reconcile grant admin failed: {e}")))?;
            created += 1;
        }
        // viewer gets only :list and :get permissions.
        if (perm.action.ends_with(":list") || perm.action.ends_with(":get"))
            && !viewer_have.contains(&perm.id)
        {
            perm_repo
                .grant_to_role(tenant_id, viewer_id, perm.id)
                .await
                .map_err(|e| DbError::Migration(format!("reconcile grant viewer failed: {e}")))?;
            created += 1;
        }
    }

    Ok(created)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::organization::CreateOrganization;
    use axiam_core::repository::{OrganizationRepository, PermissionRepository, TenantRepository};
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;

    async fn setup_db() -> (Surreal<surrealdb::engine::local::Db>, Uuid) {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        crate::schema::run_migrations(&db).await.unwrap();

        let org = crate::repository::SurrealOrganizationRepository::new(db.clone())
            .create(CreateOrganization {
                name: "Org".into(),
                slug: "org".into(),
                metadata: None,
            })
            .await
            .unwrap();
        let tenant = crate::repository::SurrealTenantRepository::new(db.clone())
            .create(axiam_core::models::tenant::CreateTenant {
                organization_id: org.id,
                name: "Tenant".into(),
                slug: "tenant".into(),
                metadata: None,
            })
            .await
            .unwrap();
        (db, tenant.id)
    }

    /// SECHRD-04: `find_or_create_role` must tolerate the UNIQUE-index race
    /// where a concurrent caller creates the same (tenant_id, name) role
    /// between the caller's `existing_id` lookup and this function's own
    /// `create()` call — re-fetching the winner's ID instead of erroring.
    #[tokio::test]
    async fn find_or_create_role_recovers_from_concurrent_create_race() {
        let (db, tenant_id) = setup_db().await;
        let role_repo = SurrealRoleRepository::new(db.clone());

        // Simulate "a concurrent caller already won": a role with this
        // (tenant_id, name) already exists, but we call with existing_id =
        // None (as if OUR pre-fetch ran before the winner's insert).
        let winner = role_repo
            .create(CreateRole {
                tenant_id,
                name: "super-admin".into(),
                description: "concurrent winner".into(),
                is_global: true,
            })
            .await
            .unwrap();

        let resolved = find_or_create_role(
            &role_repo,
            tenant_id,
            None,
            "super-admin",
            "our attempted description",
        )
        .await
        .expect("must recover from the UNIQUE-index race, not error");

        assert_eq!(
            resolved, winner.id,
            "must resolve to the concurrent winner's role ID"
        );
    }

    /// `grant_to_role_idempotent` must treat "already granted" (a concurrent
    /// caller won the same grant) as success.
    #[tokio::test]
    async fn grant_to_role_idempotent_tolerates_duplicate_grant() {
        let (db, tenant_id) = setup_db().await;
        let role_repo = SurrealRoleRepository::new(db.clone());
        let perm_repo = SurrealPermissionRepository::new(db.clone());

        let role = role_repo
            .create(CreateRole {
                tenant_id,
                name: "grant-race-role".into(),
                description: "role".into(),
                is_global: true,
            })
            .await
            .unwrap();
        let perm = perm_repo
            .create(axiam_core::models::permission::CreatePermission {
                tenant_id,
                action: "widgets:list".into(),
                description: "List widgets".into(),
            })
            .await
            .unwrap();

        // First grant succeeds normally.
        grant_to_role_idempotent(&perm_repo, tenant_id, role.id, perm.id)
            .await
            .unwrap();

        // A second grant of the SAME pair hits the UNIQUE (in, out) index —
        // must be swallowed as Ok(()), not propagated as an error.
        grant_to_role_idempotent(&perm_repo, tenant_id, role.id, perm.id)
            .await
            .expect("duplicate grant must be tolerated as already-granted");

        let granted = granted_permission_ids(&perm_repo, tenant_id, role.id)
            .await
            .unwrap();
        assert!(granted.contains(&perm.id));
        assert_eq!(granted.len(), 1, "no duplicate edge must be created");
    }
}
