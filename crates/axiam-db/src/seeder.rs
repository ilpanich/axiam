//! Startup seeders for populating static data.
//!
//! The permission seeder uses raw SurrealQL `UPSERT` to ensure idempotency
//! under concurrent startup (per D-07). A deterministic UUID derived from
//! `namespace = tenant_id` + `name = action` ensures the same record is
//! always targeted on subsequent restarts — true idempotency via UPSERT.

use axiam_core::models::role::CreateRole;
use axiam_core::repository::{Pagination, PermissionRepository, RoleRepository};
use surrealdb::{Connection, Surreal};
use uuid::Uuid;

use crate::error::DbError;
use crate::repository::{SurrealPermissionRepository, SurrealRoleRepository};

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
    Ok(())
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

    let super_admin_id = match find_role("super-admin") {
        Some(id) => id,
        None => {
            let role = role_repo
                .create(CreateRole {
                    tenant_id,
                    name: "super-admin".into(),
                    description: "Full system access — all permissions".into(),
                    is_global: true,
                })
                .await
                .map_err(|e| {
                    DbError::Migration(format!("seed_default_roles create super-admin failed: {e}"))
                })?;
            role.id
        }
    };

    let admin_id = match find_role("admin") {
        Some(id) => id,
        None => {
            let role = role_repo
                .create(CreateRole {
                    tenant_id,
                    name: "admin".into(),
                    description: "Administrative access — all entity CRUD operations".into(),
                    is_global: true,
                })
                .await
                .map_err(|e| {
                    DbError::Migration(format!("seed_default_roles create admin failed: {e}"))
                })?;
            role.id
        }
    };

    let viewer_id = match find_role("viewer") {
        Some(id) => id,
        None => {
            let role = role_repo
                .create(CreateRole {
                    tenant_id,
                    name: "viewer".into(),
                    description: "Read-only access — list and get operations".into(),
                    is_global: true,
                })
                .await
                .map_err(|e| {
                    DbError::Migration(format!("seed_default_roles create viewer failed: {e}"))
                })?;
            role.id
        }
    };

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
    // 3. Grant permissions to roles
    // -----------------------------------------------------------------------

    for perm in &permissions.items {
        // super-admin gets ALL permissions.
        perm_repo
            .grant_to_role(tenant_id, super_admin_id, perm.id)
            .await
            .map_err(|e| {
                DbError::Migration(format!(
                    "seed_default_roles grant super-admin permission {} failed: {e}",
                    perm.action
                ))
            })?;

        // admin gets every permission EXCEPT admin:bootstrap.
        if perm.action != "admin:bootstrap" {
            perm_repo
                .grant_to_role(tenant_id, admin_id, perm.id)
                .await
                .map_err(|e| {
                    DbError::Migration(format!(
                        "seed_default_roles grant admin permission {} failed: {e}",
                        perm.action
                    ))
                })?;
        }

        // viewer gets only :list and :get permissions.
        if perm.action.ends_with(":list") || perm.action.ends_with(":get") {
            perm_repo
                .grant_to_role(tenant_id, viewer_id, perm.id)
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
