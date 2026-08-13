//! X3 wave 2 — query-plan pins for the two new indexed lookups (D5/D10),
//! mirroring `authz_query_plan_test.rs`'s `EXPLAIN`-guard convention (see that
//! file's module docs for the `EXPLAIN` vocabulary this reuses).
//!
//! - `mds_entry.aaguid` — `MdsRepository::get_by_aaguid`, the registration-time
//!   policy lookup (D7/D8). This table is server-global and will accumulate
//!   every FIDO-certified authenticator model MDS knows (currently ~340), so a
//!   plan that degrades to `TableScan` turns a per-registration O(1) lookup
//!   into an O(entries) scan on every single WebAuthn registration attempt.
//! - `webauthn_attestation_policy.tenant_id` — the D5 policy-resolution
//!   lookup, on the registration hot path exactly like the authz checks
//!   `authz_query_plan_test.rs` already guards.

use serde_json::Value as Json;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};

/// Boot an in-memory SurrealDB with the production schema applied.
async fn fresh_db() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// Recursively collect every `operator` value in an `EXPLAIN` plan tree.
fn operators(plan: &[Json]) -> Vec<String> {
    fn walk(node: &Json, out: &mut Vec<String>) {
        if let Some(op) = node.get("operator").and_then(|o| o.as_str()) {
            out.push(op.to_owned());
        }
        if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
            for child in children {
                walk(child, out);
            }
        }
    }
    let mut out = Vec::new();
    for row in plan {
        walk(row, &mut out);
    }
    out
}

/// Recursively collect every `index` name referenced by an `IndexScan`.
fn indexes(plan: &[Json]) -> Vec<String> {
    fn walk(node: &Json, out: &mut Vec<String>) {
        if let Some(idx) = node
            .get("attributes")
            .and_then(|a| a.get("index"))
            .and_then(|i| i.as_str())
        {
            out.push(idx.to_owned());
        }
        if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
            for child in children {
                walk(child, out);
            }
        }
    }
    let mut out = Vec::new();
    for row in plan {
        walk(row, &mut out);
    }
    out
}

fn assert_no_table_scan(plan: &[Json], what: &str) {
    let ops = operators(plan);
    assert!(
        !ops.iter().any(|o| o == "TableScan"),
        "{what} must not fall back to a full table scan; operators were {ops:?}, plan {plan:#?}"
    );
}

fn assert_uses_index(plan: &[Json], index: &str, what: &str) {
    let found = indexes(plan);
    assert!(
        found.iter().any(|i| i == index),
        "{what} must be served by index `{index}`; indexes used were {found:?}, plan {plan:#?}"
    );
}

// ---------------------------------------------------------------------------
// mds_entry.aaguid
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mds_entry_aaguid_lookup_is_index_satisfied() {
    let db = fresh_db().await;
    let mut res = db
        .query("SELECT * FROM mds_entry WHERE aaguid = $aaguid LIMIT 1 EXPLAIN")
        .bind(("aaguid", "11111111-1111-1111-1111-111111111111".to_string()))
        .await
        .unwrap();
    let plan: Vec<Json> = res.take(0).unwrap();

    assert_no_table_scan(&plan, "mds_entry.aaguid lookup");
    assert_uses_index(&plan, "idx_mds_entry_aaguid", "mds_entry.aaguid lookup");
}

// ---------------------------------------------------------------------------
// webauthn_attestation_policy.tenant_id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn webauthn_attestation_policy_tenant_lookup_is_index_satisfied() {
    let db = fresh_db().await;
    let mut res = db
        .query("SELECT * FROM webauthn_attestation_policy WHERE tenant_id = $tenant_id EXPLAIN")
        .bind((
            "tenant_id",
            "22222222-2222-2222-2222-222222222222".to_string(),
        ))
        .await
        .unwrap();
    let plan: Vec<Json> = res.take(0).unwrap();

    assert_no_table_scan(&plan, "webauthn_attestation_policy.tenant_id lookup");
    assert_uses_index(
        &plan,
        "idx_webauthn_attestation_policy_tenant",
        "webauthn_attestation_policy.tenant_id lookup",
    );
}
