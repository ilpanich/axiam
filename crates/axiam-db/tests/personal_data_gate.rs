//! T-261's structural gate: the `user` schema and the declared personal-data
//! inventory must agree, in both directions.
//!
//! # What this catches that nothing else does
//!
//! Three code paths used to decide what a `user` column means by writing the
//! column name out by hand — the Art. 17 erasure statement, the administrator's
//! tombstone, and the Art. 15 export's `profile` section — so a column added to
//! `schema.rs` and to none of them survived erasure and never reached an
//! export. The fourth path, SCIM's no-op detection, was guarded because
//! somebody wrote a destructure; that guard does not generalise, because
//! `UpdateUser` is not the `user` table.
//!
//! `axiam_core::personal_data::USER_COLUMNS` is now the single declaration the
//! two erasure statements derive from. This file is the half of the gate that
//! a pure Rust test cannot be: it asks the **live datastore**, after
//! migrations, what columns the `user` table actually has, and requires the
//! answer to match the inventory exactly.
//!
//! The comparison runs both ways on purpose. A column in the schema and not in
//! the inventory is the defect T-261 records. A column in the inventory and not
//! in the schema is a different one — a classification for a column that no
//! longer exists, which reads as coverage and is not.
//!
//! `address.*` sub-fields fold into the `address` row: they are erased and
//! exported with the object they belong to and cannot be reached without it.

use std::collections::BTreeSet;

use axiam_core::personal_data::{USER_COLUMNS, audit_declarations, shared_erasure_fragment};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

/// Every top-level `DEFINE FIELD` on `user`, read from the engine itself.
async fn live_user_columns() -> BTreeSet<String> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let mut response = db.query("INFO FOR TABLE user").await.unwrap();
    // `INFO FOR` answers a single object, which the driver hands back as its
    // own `Value`; round-tripping through JSON keeps this test free of the
    // driver's value model, which has changed shape across majors.
    let info: Option<serde_json::Value> = response.take(0usize).unwrap();
    let info = info.expect("INFO FOR TABLE user returns a row");

    info.get("fields")
        .and_then(serde_json::Value::as_object)
        .expect("INFO FOR TABLE user must report a `fields` object")
        .keys()
        // Fold `address.formatted` and friends into `address`, and drop the
        // `foo[*]` array-member forms the engine also reports.
        .map(|field| {
            field
                .split(['.', '['])
                .next()
                .unwrap_or(field.as_str())
                .to_owned()
        })
        .collect()
}

#[tokio::test]
async fn user_schema_matches_the_declared_inventory() {
    let live = live_user_columns().await;
    let declared: BTreeSet<String> = USER_COLUMNS
        .iter()
        .map(|column| column.name.to_owned())
        .collect();

    let undeclared: Vec<_> = live.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "these `user` columns exist in the schema and are classified nowhere: \
         {undeclared:?}. Add a row to `axiam_core::personal_data::USER_COLUMNS` \
         saying whether erasure clears it, whether the Art. 15 export shows it, \
         and — if neither — why. A column classified nowhere survives erasure \
         and never reaches an export; that is T-261."
    );

    let stale: Vec<_> = declared.difference(&live).collect();
    assert!(
        stale.is_empty(),
        "these columns are classified in \
         `axiam_core::personal_data::USER_COLUMNS` but no longer exist in the \
         `user` schema: {stale:?}. A classification for a column that is gone \
         reads as coverage and is not."
    );
}

/// The gate has to be able to fail, or a green run means nothing. This builds
/// the exact comparison the test above makes, against a schema set that is
/// missing a column the inventory declares, and requires it to be detected.
#[tokio::test]
async fn the_gate_detects_a_column_the_inventory_does_not_declare() {
    let mut live = live_user_columns().await;
    live.insert("a_column_somebody_added".to_owned());

    let declared: BTreeSet<String> = USER_COLUMNS
        .iter()
        .map(|column| column.name.to_owned())
        .collect();

    let undeclared: Vec<_> = live.difference(&declared).collect();
    assert_eq!(
        undeclared,
        vec![&"a_column_somebody_added".to_owned()],
        "the gate must report exactly the unclassified column"
    );
}

/// I4 twin: the inventory as it actually stands passes its own declaration
/// audit, so the assertion above is checking the schema and not papering over
/// a malformed inventory.
#[test]
fn the_inventory_itself_is_well_formed() {
    assert!(audit_declarations().is_empty());
    assert!(!shared_erasure_fragment().is_empty());
}
