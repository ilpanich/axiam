//! In-process tonic test harness for `ReactorAdminService` (X1 / R2.3).
//!
//! Mirrors `grpc_authz_test.rs`'s harness shape (real `AuthorizationEngine`,
//! real minted JWT through `AuthInterceptor`, an in-process TCP server) —
//! `ReactorAdminServiceImpl` takes a real engine, not the REST layer's
//! `AllowAllAuthzChecker` stub, so a genuine permission grant is what proves
//! the guard actually runs rather than merely compiling.
//!
//! Run with: cargo test -p axiam-api-grpc --features client --test grpc_reactor_test

use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_authz::AuthorizationEngine;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::CreatePermission;
use axiam_core::models::role::CreateRole;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, PermissionRepository, RoleRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealGroupRepository, SurrealOrganizationRepository,
    SurrealPermissionRepository, SurrealReactorRepository, SurrealResourceRepository,
    SurrealRoleRepository, SurrealScopeRepository, SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use uuid::Uuid;

use axiam_api_grpc::middleware::auth::AuthInterceptor;
use axiam_api_grpc::proto::reactor_admin_service_client::ReactorAdminServiceClient;
use axiam_api_grpc::proto::reactor_admin_service_server::ReactorAdminServiceServer;
use axiam_api_grpc::proto::{
    CreateReactorRequest, DeleteReactorRequest, GetReactorRequest, ListReactorEventsRequest,
    ListReactorsRequest, UpdateReactorRequest,
};
use axiam_api_grpc::services::ReactorAdminServiceImpl;

type TestDb = surrealdb::engine::local::Db;
type TestEngine = AuthorizationEngine<
    SurrealRoleRepository<TestDb>,
    SurrealPermissionRepository<TestDb>,
    SurrealResourceRepository<TestDb>,
    SurrealScopeRepository<TestDb>,
    SurrealGroupRepository<TestDb>,
>;

fn test_auth_config() -> AuthConfig {
    let private_key = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n",
        "-----END PRIVATE KEY-----"
    );
    let public_key = concat!(
        "-----BEGIN PUBLIC KEY-----\n",
        "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
        "-----END PUBLIC KEY-----"
    );
    AuthConfig {
        jwt_private_key_pem: private_key.into(),
        jwt_public_key_pem: public_key.into(),
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

fn mint_token(tenant_id: Uuid, user_id: Uuid, auth_config: &AuthConfig) -> String {
    issue_access_token(
        user_id,
        tenant_id,
        Uuid::nil(),
        &[],
        auth_config,
        Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .expect("test token issuance must succeed")
}

async fn setup() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Reactor gRPC Org".into(),
            slug: "reactor-grpc-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Reactor gRPC Tenant".into(),
            slug: "reactor-grpc-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "reactor-grpc-admin".into(),
            email: "reactor-grpc-admin@example.com".into(),
            // Generated, never a literal. A username/password pair in source is a
            // secret-scanner finding regardless of the value, and this fixture
            // never needs to know what the password is.
            password: format!("pw-{}", Uuid::new_v4()),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id, user.id)
}

fn make_engine(db: &Surreal<TestDb>) -> TestEngine {
    AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    )
}

/// Grants every `reactors:*` action globally to `user_id` — the same
/// resource-nil, global-role shape `RequirePermission::new(action,
/// Uuid::nil())` checks against REST-side.
async fn grant_all_reactor_permissions(db: &Surreal<TestDb>, tenant_id: Uuid, user_id: Uuid) {
    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());

    let role = role_repo
        .create(CreateRole {
            tenant_id,
            name: "reactor-admin".into(),
            description: "Full reactor CRUD".into(),
            is_global: true,
        })
        .await
        .unwrap();

    for action in [
        "reactors:list",
        "reactors:create",
        "reactors:get",
        "reactors:update",
        "reactors:delete",
    ] {
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
    }

    role_repo
        .assign_to_user(tenant_id, user_id, role.id, None)
        .await
        .unwrap();
}

/// In-process server harness. DO NOT attach a governor rate-limit layer —
/// its `SmartIpKeyExtractor` panics without a real peer IP on in-process
/// connections (same caveat `grpc_authz_test.rs` documents).
async fn start_test_server(
    db: &Surreal<TestDb>,
    engine: TestEngine,
    auth_config: AuthConfig,
) -> (String, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let reactor_repo = SurrealReactorRepository::new(db.clone());
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let routing_invalidator: std::sync::Arc<dyn Fn(Uuid) + Send + Sync> =
        std::sync::Arc::new(|_tenant_id| {});

    let reactor_svc = ReactorAdminServiceServer::with_interceptor(
        // SEC-101: this harness stands in for a working transport.
        ReactorAdminServiceImpl::new(reactor_repo, engine, audit_repo, routing_invalidator, true),
        AuthInterceptor::new(auth_config),
    );

    tokio::spawn(
        Server::builder()
            .add_service(reactor_svc)
            .serve_with_incoming_shutdown(incoming, async {
                rx.await.ok();
            }),
    );

    (format!("http://{addr}"), tx)
}

async fn connect_channel(endpoint: String) -> Channel {
    Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap()
}

macro_rules! authed_client {
    ($endpoint:expr, $token:expr) => {{
        let token = $token;
        let channel = connect_channel($endpoint).await;
        ReactorAdminServiceClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            Ok(req)
        })
    }};
}

// ---------------------------------------------------------------------------
// Permission gate
// ---------------------------------------------------------------------------

/// The whole reason this service takes a real `AuthorizationEngine` rather
/// than a stub: a caller with no `reactors:create` grant must be refused,
/// exactly as the REST `RequirePermission` guard refuses it.
#[tokio::test]
async fn create_reactor_is_refused_without_the_permission() {
    let (db, tenant_id, user_id) = setup().await;
    // Deliberately NOT calling grant_all_reactor_permissions.
    let auth_config = test_auth_config();
    let token = mint_token(tenant_id, user_id, &auth_config);
    let engine = make_engine(&db);
    let (endpoint, _shutdown) = start_test_server(&db, engine, auth_config).await;
    let mut client = authed_client!(endpoint, token);

    let status = client
        .create_reactor(CreateReactorRequest {
            name: "should-be-refused".into(),
            description: String::new(),
            events: vec!["login.post_auth".into()],
            mode: "intercept".into(),
            priority: 0,
            timeout_ms: None,
            failure_policy: None,
            enabled: None,
        })
        .await
        .expect_err("no reactors:create grant must be refused");

    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

// ---------------------------------------------------------------------------
// CRUD round trip
// ---------------------------------------------------------------------------

/// Create -> get -> list -> update -> delete, through the wire, mirroring
/// `reactors_test.rs`'s REST coverage of the same lifecycle. Health fields
/// are asserted at zero: nothing has dispatched to this reactor yet, so
/// there is nothing in the audit trail `recent_health` reads from.
#[tokio::test]
async fn full_reactor_lifecycle_round_trips_through_grpc() {
    let (db, tenant_id, user_id) = setup().await;
    grant_all_reactor_permissions(&db, tenant_id, user_id).await;
    let auth_config = test_auth_config();
    let token = mint_token(tenant_id, user_id, &auth_config);
    let engine = make_engine(&db);
    let (endpoint, _shutdown) = start_test_server(&db, engine, auth_config).await;
    let mut client = authed_client!(endpoint, token.clone());

    // list_reactor_events: the registry, verbatim.
    let events = client
        .list_reactor_events(ListReactorEventsRequest {})
        .await
        .unwrap()
        .into_inner()
        .events;
    assert!(
        events.iter().any(|e| e.name == "login.post_auth"),
        "the registry must be served over gRPC identically to REST"
    );

    // create
    let created = client
        .create_reactor(CreateReactorRequest {
            name: "fraud-check".into(),
            description: "Scores logins".into(),
            events: vec!["login.post_auth".into()],
            mode: "intercept".into(),
            priority: 0,
            timeout_ms: Some(750),
            failure_policy: None, // omitted -> registry default (fail_closed)
            enabled: Some(true),
        })
        .await
        .unwrap()
        .into_inner()
        .reactor
        .expect("create response must carry the reactor");

    assert_eq!(created.name, "fraud-check");
    assert_eq!(created.timeout_ms, 750);
    assert_eq!(
        created.failure_policy, "fail_closed",
        "an omitted failure_policy must resolve to the registry default"
    );
    assert_eq!(created.last_seen_at, None);
    assert_eq!(created.recent_timeout_count, 0);
    assert_eq!(created.recent_veto_count, 0);
    let id = created.id.clone();

    // get
    let fetched = client
        .get_reactor(GetReactorRequest { id: id.clone() })
        .await
        .unwrap()
        .into_inner()
        .reactor
        .unwrap();
    assert_eq!(fetched.id, id);
    assert_eq!(fetched.name, "fraud-check");

    // list
    let listed = client
        .list_reactors(ListReactorsRequest {
            offset: 0,
            limit: 50,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.total, 1);
    assert_eq!(listed.items[0].id, id);

    // update: merged-validation path — only `name` is set, `events` is left
    // alone (events_set: false), mirroring REST's PUT semantics.
    let updated = client
        .update_reactor(UpdateReactorRequest {
            id: id.clone(),
            name: Some("fraud-check-v2".into()),
            description: None,
            events: vec![],
            events_set: false,
            mode: None,
            priority: None,
            timeout_ms: None,
            failure_policy: None,
            enabled: None,
        })
        .await
        .unwrap()
        .into_inner()
        .reactor
        .unwrap();
    assert_eq!(updated.name, "fraud-check-v2");
    assert_eq!(
        updated.events,
        vec!["login.post_auth".to_string()],
        "events must be unchanged when events_set is false"
    );

    // delete
    client
        .delete_reactor(DeleteReactorRequest { id: id.clone() })
        .await
        .unwrap();

    let after_delete = client.get_reactor(GetReactorRequest { id }).await;
    assert!(
        after_delete.is_err(),
        "a deleted reactor must not be gettable"
    );
}

/// `events_set: true` with an empty list is REFUSED (§'s NoEvents rule),
/// distinct from `events_set: false` (leave alone) — the proto-level
/// presence flag this service adds specifically because proto3 `repeated`
/// cannot itself distinguish "unset" from "empty".
#[tokio::test]
async fn update_with_events_set_true_and_an_empty_list_is_refused() {
    let (db, tenant_id, user_id) = setup().await;
    grant_all_reactor_permissions(&db, tenant_id, user_id).await;
    let auth_config = test_auth_config();
    let token = mint_token(tenant_id, user_id, &auth_config);
    let engine = make_engine(&db);
    let (endpoint, _shutdown) = start_test_server(&db, engine, auth_config).await;
    let mut client = authed_client!(endpoint, token);

    let created = client
        .create_reactor(CreateReactorRequest {
            name: "veto-only".into(),
            description: String::new(),
            events: vec!["grant.pre_assign".into()],
            mode: "intercept".into(),
            priority: 0,
            timeout_ms: None,
            failure_policy: None,
            enabled: None,
        })
        .await
        .unwrap()
        .into_inner()
        .reactor
        .unwrap();

    let status = client
        .update_reactor(UpdateReactorRequest {
            id: created.id,
            name: None,
            description: None,
            events: vec![],
            events_set: true,
            mode: None,
            priority: None,
            timeout_ms: None,
            failure_policy: None,
            enabled: None,
        })
        .await
        .expect_err("replacing events with an empty, explicitly-set list must be refused");

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}
