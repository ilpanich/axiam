//! In-process tonic test harness for axiam-api-grpc (D-10).
//!
//! Covers:
//! - T19.1: gRPC authorization integration tests (check_access allow/deny/invalid-arg)
//! - T19.2: Batch authorization and concurrent check_access (engine thread-safety)
//!
//! Run with: cargo test -p axiam-api-grpc --features client --test grpc_authz_test

use axiam_authz::AuthorizationEngine;
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
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use uuid::Uuid;

use axiam_api_grpc::proto::authorization_service_client::AuthorizationServiceClient;
use axiam_api_grpc::proto::authorization_service_server::AuthorizationServiceServer;
use axiam_api_grpc::proto::{BatchCheckAccessRequest, CheckAccessRequest};
use axiam_api_grpc::services::AuthorizationServiceImpl;

// ---------------------------------------------------------------------------
// Type aliases (mirrors authz_engine_test.rs)
// ---------------------------------------------------------------------------

type TestDb = surrealdb::engine::local::Db;
type TestEngine = AuthorizationEngine<
    SurrealRoleRepository<TestDb>,
    SurrealPermissionRepository<TestDb>,
    SurrealResourceRepository<TestDb>,
    SurrealScopeRepository<TestDb>,
    SurrealGroupRepository<TestDb>,
>;

// ---------------------------------------------------------------------------
// DB setup (copy pattern from authz_engine_test.rs:34-78)
// ---------------------------------------------------------------------------

async fn setup() -> (
    Surreal<TestDb>,
    Uuid, // tenant_id
    Uuid, // user_id
) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: "pass123456789".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id, user.id)
}

// ---------------------------------------------------------------------------
// Engine construction (copy pattern from authz_engine_test.rs:80-89)
// ---------------------------------------------------------------------------

fn make_engine(db: &Surreal<TestDb>) -> TestEngine {
    AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    )
}

// ---------------------------------------------------------------------------
// Resource helper
// ---------------------------------------------------------------------------

async fn create_resource(db: &Surreal<TestDb>, tenant_id: Uuid, name: &str) -> Uuid {
    let repo = SurrealResourceRepository::new(db.clone());
    let res = repo
        .create(CreateResource {
            tenant_id,
            name: name.into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();
    res.id
}

// ---------------------------------------------------------------------------
// Role+permission grant helper (copy pattern from authz_engine_test.rs:112-155)
// ---------------------------------------------------------------------------

async fn grant_user_role_permission(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    user_id: Uuid,
    role_name: &str,
    is_global: bool,
    action: &str,
    resource_id: Option<Uuid>,
) {
    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());

    let role = role_repo
        .create(CreateRole {
            tenant_id,
            name: role_name.into(),
            description: format!("Role: {role_name}"),
            is_global,
        })
        .await
        .unwrap();

    let perm = perm_repo
        .create(CreatePermission {
            tenant_id,
            action: action.into(),
            description: format!("Can {action}"),
        })
        .await
        .unwrap();

    perm_repo
        .grant_to_role(tenant_id, role.id, perm.id)
        .await
        .unwrap();

    role_repo
        .assign_to_user(tenant_id, user_id, role.id, resource_id)
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// In-process gRPC server harness (D-10)
// DO NOT attach build_grpc_governor_layer — SmartIpKeyExtractor panics without
// a real peer IP on in-process connections.
// ---------------------------------------------------------------------------

async fn start_test_server(engine: TestEngine) -> (String, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let authz_svc = AuthorizationServiceServer::new(AuthorizationServiceImpl::new(engine));

    tokio::spawn(
        Server::builder()
            .add_service(authz_svc)
            .serve_with_incoming_shutdown(incoming, async {
                rx.await.ok();
            }),
    );

    let endpoint = format!("http://{addr}");
    (endpoint, tx)
}

async fn connect_client(endpoint: String) -> AuthorizationServiceClient<Channel> {
    let channel = Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    AuthorizationServiceClient::new(channel)
}

// ---------------------------------------------------------------------------
// T19.1: gRPC authorization integration tests
// ---------------------------------------------------------------------------

/// T19.1 — check_access returns allowed=true when a role grants the permission.
/// ASVS V4.1.1 / T-07-09 default-deny: ensures a valid grant IS allowed.
#[tokio::test]
async fn check_access_allows_when_role_grants_permission() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "svc-read").await;
    grant_user_role_permission(
        &db,
        tenant_id,
        user_id,
        "viewer",
        false,
        "read",
        Some(resource_id),
    )
    .await;

    let engine = make_engine(&db);
    let (endpoint, _shutdown) = start_test_server(engine).await;
    let mut client = connect_client(endpoint).await;

    let resp = client
        .check_access(CheckAccessRequest {
            tenant_id: tenant_id.to_string(),
            subject_id: user_id.to_string(),
            action: "read".into(),
            resource_id: resource_id.to_string(),
            scope: None,
        })
        .await
        .unwrap()
        .into_inner();

    assert!(
        resp.allowed,
        "expected allowed=true, got deny: {}",
        resp.deny_reason
    );
}

/// T19.1 — check_access returns allowed=false when no role assigned.
/// T-07-09: default-deny enforcement (ASVS V4.1.1).
#[tokio::test]
async fn check_access_denies_when_no_role() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "svc-norole").await;

    let engine = make_engine(&db);
    let (endpoint, _shutdown) = start_test_server(engine).await;
    let mut client = connect_client(endpoint).await;

    let resp = client
        .check_access(CheckAccessRequest {
            tenant_id: tenant_id.to_string(),
            subject_id: user_id.to_string(),
            action: "read".into(),
            resource_id: resource_id.to_string(),
            scope: None,
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!resp.allowed, "expected deny, got allowed");
}

/// T19.1 — check_access returns allowed=false when granted action differs.
/// T-07-09: wrong action does not grant access.
#[tokio::test]
async fn check_access_denies_wrong_action() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "svc-wrongact").await;
    grant_user_role_permission(
        &db,
        tenant_id,
        user_id,
        "reader",
        false,
        "read",
        Some(resource_id),
    )
    .await;

    let engine = make_engine(&db);
    let (endpoint, _shutdown) = start_test_server(engine).await;
    let mut client = connect_client(endpoint).await;

    let resp = client
        .check_access(CheckAccessRequest {
            tenant_id: tenant_id.to_string(),
            subject_id: user_id.to_string(),
            action: "write".into(), // user only has "read"
            resource_id: resource_id.to_string(),
            scope: None,
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!resp.allowed, "expected deny for wrong action, got allowed");
}

/// T19.1 — malformed user_id UUID returns Status::invalid_argument.
/// T-07-10: no fallthrough on bad identifiers (ASVS V7).
#[tokio::test]
async fn check_access_rejects_malformed_user_id() {
    let (db, _tenant_id, _user_id) = setup().await;
    let resource_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    let engine = make_engine(&db);
    let (endpoint, _shutdown) = start_test_server(engine).await;
    let mut client = connect_client(endpoint).await;

    let result = client
        .check_access(CheckAccessRequest {
            tenant_id: tenant_id.to_string(),
            subject_id: "not-a-uuid".into(),
            action: "read".into(),
            resource_id: resource_id.to_string(),
            scope: None,
        })
        .await;

    let err = result.expect_err("expected error for malformed subject_id");
    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "expected InvalidArgument, got {:?}",
        err.code()
    );
}

/// T19.1 — malformed tenant_id UUID returns Status::invalid_argument.
/// T-07-10: no fallthrough on bad identifiers (ASVS V7).
#[tokio::test]
async fn check_access_rejects_malformed_tenant_id() {
    let (db, _tenant_id, user_id) = setup().await;
    let resource_id = Uuid::new_v4();

    let engine = make_engine(&db);
    let (endpoint, _shutdown) = start_test_server(engine).await;
    let mut client = connect_client(endpoint).await;

    let result = client
        .check_access(CheckAccessRequest {
            tenant_id: "not-a-valid-uuid".into(),
            subject_id: user_id.to_string(),
            action: "read".into(),
            resource_id: resource_id.to_string(),
            scope: None,
        })
        .await;

    let err = result.expect_err("expected error for malformed tenant_id");
    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "expected InvalidArgument, got {:?}",
        err.code()
    );
}

// ---------------------------------------------------------------------------
// T19.2: Batch authorization tests
// ---------------------------------------------------------------------------

/// T19.2 — batch_check_access returns a mixed allow/deny result set.
#[tokio::test]
async fn batch_check_access_returns_mixed_results() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_a = create_resource(&db, tenant_id, "svc-batch-a").await;
    let resource_b = create_resource(&db, tenant_id, "svc-batch-b").await;

    // Grant access to resource_a only.
    grant_user_role_permission(
        &db,
        tenant_id,
        user_id,
        "batch-viewer",
        false,
        "read",
        Some(resource_a),
    )
    .await;

    let engine = make_engine(&db);
    let (endpoint, _shutdown) = start_test_server(engine).await;
    let mut client = connect_client(endpoint).await;

    let resp = client
        .batch_check_access(BatchCheckAccessRequest {
            requests: vec![
                // Should be allowed (role covers resource_a).
                CheckAccessRequest {
                    tenant_id: tenant_id.to_string(),
                    subject_id: user_id.to_string(),
                    action: "read".into(),
                    resource_id: resource_a.to_string(),
                    scope: None,
                },
                // Should be denied (no role on resource_b).
                CheckAccessRequest {
                    tenant_id: tenant_id.to_string(),
                    subject_id: user_id.to_string(),
                    action: "read".into(),
                    resource_id: resource_b.to_string(),
                    scope: None,
                },
                // Should be denied (wrong action on resource_a).
                CheckAccessRequest {
                    tenant_id: tenant_id.to_string(),
                    subject_id: user_id.to_string(),
                    action: "delete".into(),
                    resource_id: resource_a.to_string(),
                    scope: None,
                },
            ],
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.results.len(), 3, "expected 3 results");
    assert!(resp.results[0].allowed, "result[0] should be allowed");
    assert!(
        !resp.results[1].allowed,
        "result[1] should be denied (no role on resource_b)"
    );
    assert!(
        !resp.results[2].allowed,
        "result[2] should be denied (wrong action)"
    );
}

/// T19.2 — concurrent check_access from >=8 tasks all resolve correctly.
/// T-07-11: exercises AuthorizationEngine Arc Send+Sync thread-safety.
#[tokio::test]
async fn concurrent_check_access_all_resolve_correctly() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "svc-concurrent").await;
    grant_user_role_permission(
        &db,
        tenant_id,
        user_id,
        "concurrent-viewer",
        false,
        "read",
        Some(resource_id),
    )
    .await;

    let engine = make_engine(&db);
    let (endpoint, _shutdown) = start_test_server(engine).await;

    const N: usize = 10;
    let mut handles = Vec::with_capacity(N);

    for i in 0..N {
        let ep = endpoint.clone();
        let tid = tenant_id;
        let uid = user_id;
        let rid = resource_id;
        // Alternate between an action that should be allowed and one that should be denied.
        let action = if i % 2 == 0 { "read" } else { "write" };
        let expected_allowed = i % 2 == 0;

        handles.push(tokio::spawn(async move {
            let mut client = connect_client(ep).await;
            let resp = client
                .check_access(CheckAccessRequest {
                    tenant_id: tid.to_string(),
                    subject_id: uid.to_string(),
                    action: action.into(),
                    resource_id: rid.to_string(),
                    scope: None,
                })
                .await
                .unwrap()
                .into_inner();
            (i, expected_allowed, resp.allowed)
        }));
    }

    for join_result in handles {
        let (i, expected, actual) = join_result.await.unwrap();
        assert_eq!(
            actual, expected,
            "task {i}: expected allowed={expected}, got allowed={actual}"
        );
    }
}
