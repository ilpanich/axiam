//! SECHRD-01 — `update_totp_step` compare-and-set concurrency test.
//!
//! Proves that N parallel submissions of one valid TOTP step against a single
//! shared SurrealDB succeed at most once: the guarded
//! `WHERE totp_last_used_step = NONE OR totp_last_used_step < $step` UPDATE
//! must let exactly one caller observe `Ok(true)`.
//!
//! Runs on `surrealkv` — the engine production deploys — rather than the
//! in-memory one this test used until 2026-08. `kv-mem` does not reliably
//! serialise concurrent read-modify-writes, so a green run there said nothing
//! about the shipped system. `tests/common/mod.rs` has the measurements.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use uuid::Uuid;

mod common;

/// Number of concurrent submissions racing for the same TOTP step.
const CONCURRENT_SUBMISSIONS: usize = 20;

#[tokio::test]
async fn totp_step_cas_concurrent() {
    // `surrealkv`, not `Mem`. This test's entire claim is that the engine lets
    // exactly one of N racers through a guarded UPDATE, and `Mem` was measured
    // in 2026-08 not to guarantee that — it admits two winners in ~1% of
    // contended rounds where production's `surrealkv` admits none. See
    // `tests/common/mod.rs`. On `Mem` this test was asserting a property of an
    // engine AXIAM does not deploy.
    let db = common::serialising_db().await;

    let org_repo = SurrealOrganizationRepository::new(db.handle());
    let org = org_repo
        .create(CreateOrganization {
            name: "TOTP CAS Org".into(),
            slug: "totp-cas-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.handle());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "TOTP CAS Tenant".into(),
            slug: "totp-cas-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_id = tenant.id;

    let user_repo = SurrealUserRepository::new(db.handle());
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "totp-cas-user".into(),
            email: "totp-cas-user@example.com".into(),
            password: "SuperSecret123!".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Freshly-created user has totp_last_used_step = NONE (unseeded).
    assert!(user.totp_last_used_step.is_none());

    let step: u64 = 123_456;
    let user_id: Uuid = user.id;

    // Spawn N tasks all racing to advance the SAME step against the SAME
    // shared in-memory DB. Only the caller whose CAS observes
    // `totp_last_used_step = NONE OR totp_last_used_step < step` should win.
    let mut handles = Vec::with_capacity(CONCURRENT_SUBMISSIONS);
    for _ in 0..CONCURRENT_SUBMISSIONS {
        let repo = user_repo.clone();
        handles.push(tokio::spawn(async move {
            repo.update_totp_step(tenant_id, user_id, step).await
        }));
    }

    let mut success_count = 0;
    let mut failure_count = 0;
    for handle in handles {
        match handle
            .await
            .expect("task panicked")
            .expect("update_totp_step errored")
        {
            true => success_count += 1,
            false => failure_count += 1,
        }
    }

    assert_eq!(
        success_count, 1,
        "exactly 1 of {CONCURRENT_SUBMISSIONS} concurrent submissions should return Ok(true)"
    );
    assert_eq!(failure_count, CONCURRENT_SUBMISSIONS - 1);

    // The persisted step reflects the single winner's write.
    let updated = user_repo.get_by_id(tenant_id, user_id).await.unwrap();
    assert_eq!(updated.totp_last_used_step, Some(step));

    // A second submission at the SAME step must now also lose the CAS
    // (replay-reject), proving the guard persists across calls.
    let replay = user_repo
        .update_totp_step(tenant_id, user_id, step)
        .await
        .unwrap();
    assert!(!replay, "replaying the same step after it won must fail");
}
