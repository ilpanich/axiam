//! Criterion micro-benchmarks for the authz hot paths (PERF-05).
//!
//! Group 1 benches a single `AuthorizationEngine::check_access` call against
//! a seeded kv-mem SurrealDB graph — the CPU-cost baseline (kv-mem is
//! near-zero-latency, so this isolates engine overhead).
//!
//! Group 2 benches the sequential-vs-concurrent `BatchCheckAccess` comparison
//! that evidences PERF-02's "faster than sequential" concurrent-batch
//! optimization. Because kv-mem has near-zero latency, a deliberate
//! `tokio::time::sleep(2ms)` per call is injected (bench-only wrapper — does
//! NOT touch `engine.rs`) to simulate a realistic DB round-trip, per
//! RESEARCH Open Question 2. Sequential runs each check in order (equivalent
//! to `buffer_unordered(1)`); concurrent runs `buffer_unordered(16)`.
//!
//! `engine.rs` is never modified — benches only measure around
//! `AuthorizationEngine::check_access` (V6, T-27-40).
//!
//! Run locally with: `cargo bench -p axiam-authz`
//! Not wired into CI (D-15) — manual/local only, documentation-only report.

use std::hint::black_box;
use std::time::Duration;

use axiam_authz::{AccessDecision, AccessRequest, AuthorizationEngine};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::CreatePermission;
use axiam_core::models::resource::CreateResource;
use axiam_core::models::role::CreateRole;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, PermissionRepository, ResourceRepository, RoleRepository,
    TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use criterion::{Criterion, criterion_group, criterion_main};
use futures::stream::{self, StreamExt};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

type TestDb = surrealdb::engine::local::Db;
type TestEngine = AuthorizationEngine<
    SurrealRoleRepository<TestDb>,
    SurrealPermissionRepository<TestDb>,
    SurrealResourceRepository<TestDb>,
    SurrealScopeRepository<TestDb>,
    SurrealGroupRepository<TestDb>,
>;

/// Injected per-call latency simulating a realistic DB round-trip — kv-mem
/// is near-zero latency, so without this the sequential-vs-concurrent
/// comparison would not be meaningful (RESEARCH Open Question 2).
const SIMULATED_CALL_LATENCY: Duration = Duration::from_millis(2);

/// Bound on concurrent in-flight checks — mirrors
/// `AXIAM__AUTHZ__BATCH_MAX_CONCURRENCY`'s default of 16 (see 27-PATTERNS.md).
const BATCH_CONCURRENCY: usize = 16;

fn make_engine(db: &Surreal<TestDb>) -> TestEngine {
    AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    )
}

/// Seed an in-memory DB with one org/tenant/user, `n` resources, and a
/// global role+permission granting "read" on all of them — so every
/// `check_access` request in the returned list resolves to `Allow`.
async fn seed(n: usize) -> (Surreal<TestDb>, Vec<AccessRequest>) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("bench").use_db("bench").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Bench Org".into(),
            slug: "bench-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Bench Tenant".into(),
            slug: "bench-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "bench-user".into(),
            email: "bench-user@example.com".into(),
            password: "pass123456789".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Global role + permission — applies to every resource (D-06 style graph).
    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());
    let role = role_repo
        .create(CreateRole {
            tenant_id: tenant.id,
            name: "bench-reader".into(),
            description: "global read".into(),
            is_global: true,
        })
        .await
        .unwrap();
    let perm = perm_repo
        .create(CreatePermission {
            tenant_id: tenant.id,
            action: "read".into(),
            description: "read".into(),
        })
        .await
        .unwrap();
    perm_repo
        .grant_to_role(tenant.id, role.id, perm.id)
        .await
        .unwrap();
    role_repo
        .assign_to_user(tenant.id, user.id, role.id, None)
        .await
        .unwrap();

    let resource_repo = SurrealResourceRepository::new(db.clone());
    let mut requests = Vec::with_capacity(n);
    for i in 0..n {
        let resource = resource_repo
            .create(CreateResource {
                tenant_id: tenant.id,
                name: format!("bench-resource-{i}"),
                resource_type: "service".into(),
                parent_id: None,
                metadata: None,
            })
            .await
            .unwrap();
        requests.push(AccessRequest {
            tenant_id: tenant.id,
            subject_id: user.id,
            action: "read".into(),
            resource_id: resource.id,
            scope: None,
        });
    }

    (db, requests)
}

/// Bench-only wrapper injecting simulated per-call I/O latency around the
/// real `check_access` call — does not modify `engine.rs`.
async fn timed_check(engine: &TestEngine, request: &AccessRequest) -> AccessDecision {
    tokio::time::sleep(SIMULATED_CALL_LATENCY).await;
    engine.check_access(request).await.unwrap()
}

fn bench_single_check_access(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (db, requests) = rt.block_on(seed(1));
    let engine = make_engine(&db);
    let request = requests.into_iter().next().unwrap();

    c.bench_function("check_access (single, seeded kv-mem)", |b| {
        b.to_async(&rt).iter(|| async {
            let decision = engine.check_access(black_box(&request)).await.unwrap();
            assert_eq!(decision, AccessDecision::Allow);
        })
    });
}

/// N-item batch comparison: sequential (equivalent to buffer_unordered(1))
/// vs. bounded-concurrent buffer_unordered(BATCH_CONCURRENCY), both with
/// injected per-call latency. Evidences PERF-02's concurrent-batch win.
const BATCH_SIZE: usize = 20;

fn bench_batch_sequential_vs_concurrent(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (db, requests) = rt.block_on(seed(BATCH_SIZE));
    let engine = make_engine(&db);

    let mut group = c.benchmark_group("authz_batch_check_access");

    group.bench_function("sequential (baseline)", |b| {
        b.to_async(&rt).iter(|| async {
            for request in &requests {
                let decision = timed_check(&engine, black_box(request)).await;
                assert_eq!(decision, AccessDecision::Allow);
            }
        })
    });

    group.bench_function("concurrent buffer_unordered(16) (optimized)", |b| {
        b.to_async(&rt).iter(|| async {
            let decisions: Vec<AccessDecision> = stream::iter(requests.iter())
                .map(|request| timed_check(&engine, request))
                .buffer_unordered(BATCH_CONCURRENCY)
                .collect()
                .await;
            assert_eq!(decisions.len(), BATCH_SIZE);
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_single_check_access,
    bench_batch_sequential_vs_concurrent
);
criterion_main!(benches);
