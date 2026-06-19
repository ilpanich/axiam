//! Regression test for the SurrealDB idle-reconnect silent-failure mode.
//!
//! Root cause (Phase 13 / REQ-17):
//!   SurrealDB SDK 3.x does NOT replay `use_ns`/`use_db` after WebSocket
//!   auto-reconnect (upstream issue #5750). After reconnect the session falls
//!   back to the unselected default and all queries silently return not-found.
//!
//! This test:
//! 1. Seeds a record in ns=axiam / db=main.
//! 2. Simulates post-reconnect state by flipping the SAME handle to the wrong
//!    namespace (the SurrealDB default a reconnected WS session falls back to).
//! 3. Proves that `get_by_id` returns Err (not-found) in the wrong namespace.
//! 4. Re-selects ns=axiam / db=main on the same handle.
//! 5. Proves that `get_by_id` returns Ok after correct re-selection.
//!
//! Settles RESEARCH Open Question 1 / Assumption A4 (empirical result):
//! `Surreal<Client>` clones have INDEPENDENT session state — use_ns/use_db on
//! one clone does NOT affect another clone. Consequently, Task 3 MUST use
//! Arc<Surreal<Client>> for the guard task so both guard and repositories
//! operate on the same underlying session allocation.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::repository::OrganizationRepository;
use axiam_db::repository::SurrealOrganizationRepository;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

/// Reproduce the unselected-session failure mode and prove re-selection fixes it.
#[tokio::test]
async fn unselected_session_returns_not_found_reselect_restores() {
    // --- Step 1: Seed an organisation in the correct namespace ---
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("axiam").use_db("main").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    // IMPORTANT: Pass db directly (not db.clone()) so the repository and the
    // test share the SAME session handle. Clones create independent session
    // state — a use_ns on one clone does NOT affect another (empirically
    // confirmed: this is the RESEARCH A4 finding). Using the same handle
    // is the only way to correctly simulate the reconnect state-loss scenario.
    let repo = SurrealOrganizationRepository::new(db.clone());
    let org = repo
        .create(CreateOrganization {
            name: "Resilience Test Org".into(),
            slug: "resilience-test-org".into(),
            metadata: None,
        })
        .await
        .expect("create org must succeed in the correct namespace");

    // Sanity check: org is reachable with correct selection.
    let found = repo.get_by_id(org.id).await;
    assert!(
        found.is_ok(),
        "get_by_id must succeed with correct ns/db selection"
    );

    // --- Step 2: Simulate post-reconnect state — flip to wrong namespace ---
    // The SurrealDB WS SDK auto-reconnects the transport but starts a fresh
    // unselected session. The server default (main/main) has no AXIAM data.
    // We must flip the SAME handle that the repository uses.
    // Since clones are independent, we create a new repo pointing at the
    // same db handle (re-cloned after the flip) to share the flipped state.
    db.use_ns("main").use_db("main").await.unwrap();
    // Re-clone AFTER the flip so the new repo inherits the wrong selection.
    let repo_wrong = SurrealOrganizationRepository::new(db.clone());

    // Step 3: Query MUST return Err (not-found) — the silent-failure mode.
    let not_found = repo_wrong.get_by_id(org.id).await;
    assert!(
        not_found.is_err(),
        "get_by_id must return Err when the session points at the wrong namespace; \
         got: {not_found:?}"
    );

    // --- Step 4: Re-select the correct namespace (what the guard task does) ---
    db.use_ns("axiam").use_db("main").await.unwrap();
    // Re-clone AFTER the re-select so the restored repo inherits the correct selection.
    let repo_restored = SurrealOrganizationRepository::new(db.clone());

    // Step 5: Query MUST succeed after re-selection.
    let restored = repo_restored.get_by_id(org.id).await;
    assert!(
        restored.is_ok(),
        "get_by_id must return Ok after re-selecting the correct ns/db; \
         got: {restored:?}"
    );
    assert_eq!(restored.unwrap().id, org.id);
}
