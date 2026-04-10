//! Startup seeders for populating static data.
//!
//! The permission seeder uses raw SurrealQL `UPSERT` to ensure idempotency
//! under concurrent startup (per D-07). A deterministic UUID derived from
//! `namespace = tenant_id` + `name = action` ensures the same record is
//! always targeted on subsequent restarts — true idempotency via UPSERT.

use surrealdb::{Connection, Surreal};
use uuid::Uuid;

use crate::error::DbError;

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
            "UPSERT type::record('permissions', $id) SET \
             tenant_id = $tenant_id, \
             action = $action, \
             description = $description, \
             created_at = IF (SELECT created_at FROM type::record('permissions', $id))[0].created_at \
               THEN (SELECT created_at FROM type::record('permissions', $id))[0].created_at \
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
