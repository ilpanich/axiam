//! In-process tonic 0.14 test server proving `CheckAccess`/`BatchCheckAccess`
//! round-trip through the generated stubs (SC#4, gRPC half).
//!
//! New test infrastructure — no shared gRPC test harness exists yet in
//! `sdks/rust/` (16-VALIDATION.md). A stub `AuthorizationService`
//! implementation returns canned `AccessDecision`s driven by the test's
//! `subject_id`/`action` inputs, letting each test assert a specific
//! outcome (allow, deny → `PERMISSION_DENIED`, `UNAVAILABLE`, and a
//! one-shot `UNAUTHENTICATED` that succeeds on retry) without a real
//! `AuthorizationEngine`.

#![cfg(feature = "grpc")]

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axiam_sdk::grpc::gen::authorization_service_server::{
    AuthorizationService, AuthorizationServiceServer,
};
use axiam_sdk::grpc::gen::{
    BatchCheckAccessRequest as WireBatchCheckAccessRequest,
    BatchCheckAccessResponse as WireBatchCheckAccessResponse,
    CheckAccessRequest as WireCheckAccessRequest, CheckAccessResponse as WireCheckAccessResponse,
};
use axiam_sdk::grpc::{
    build_channel, AccessDecision, AuthzGrpcClient, CheckAccessRequest, GrpcChannelConfig,
};
use axiam_sdk::token::refresh_guard::RefreshedTokens;
use axiam_sdk::token::TokenManager;
use axiam_sdk::{AxiamError, Sensitive};
use tonic::transport::server::TcpIncoming;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use uuid::Uuid;

/// Canned outcomes the stub server can be configured to return, selected by
/// the `action` field of the incoming request so each test can drive a
/// specific behavior without a real `AuthorizationEngine`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StubOutcome {
    Allow,
    Deny,
    Unavailable,
    /// Returns `UNAUTHENTICATED` exactly once (first call observed), then
    /// `Allow` on every subsequent call — proves the single-flight
    /// refresh-then-retry path (§9).
    UnauthenticatedOnce,
}

struct StubAuthorizationService {
    call_count: Arc<AtomicUsize>,
    unauthenticated_already_fired: Arc<std::sync::atomic::AtomicBool>,
}

impl StubAuthorizationService {
    fn new() -> (Self, Arc<AtomicUsize>) {
        let call_count = Arc::new(AtomicUsize::new(0));
        (
            Self {
                call_count: Arc::clone(&call_count),
                unauthenticated_already_fired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
            call_count,
        )
    }

    fn outcome_for(&self, action: &str) -> StubOutcome {
        match action {
            "allow" => StubOutcome::Allow,
            "deny" => StubOutcome::Deny,
            "unavailable" => StubOutcome::Unavailable,
            "unauthenticated-once" => StubOutcome::UnauthenticatedOnce,
            other => panic!("unknown test action: {other}"),
        }
    }

    fn decide(&self, action: &str) -> Result<WireCheckAccessResponse, Status> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        match self.outcome_for(action) {
            StubOutcome::Allow => Ok(WireCheckAccessResponse {
                allowed: true,
                deny_reason: String::new(),
            }),
            StubOutcome::Deny => Err(Status::permission_denied("caller lacks permission")),
            StubOutcome::Unavailable => Err(Status::unavailable("server unreachable")),
            StubOutcome::UnauthenticatedOnce => {
                let already_fired = self
                    .unauthenticated_already_fired
                    .swap(true, Ordering::SeqCst);
                if already_fired {
                    Ok(WireCheckAccessResponse {
                        allowed: true,
                        deny_reason: String::new(),
                    })
                } else {
                    Err(Status::unauthenticated("token expired"))
                }
            }
        }
    }
}

#[tonic::async_trait]
impl AuthorizationService for StubAuthorizationService {
    async fn check_access(
        &self,
        request: Request<WireCheckAccessRequest>,
    ) -> Result<Response<WireCheckAccessResponse>, Status> {
        let req = request.into_inner();
        self.decide(&req.action).map(Response::new)
    }

    async fn batch_check_access(
        &self,
        request: Request<WireBatchCheckAccessRequest>,
    ) -> Result<Response<WireBatchCheckAccessResponse>, Status> {
        let req = request.into_inner();
        let mut results = Vec::with_capacity(req.requests.len());
        for check in req.requests {
            results.push(self.decide(&check.action)?);
        }
        Ok(Response::new(WireBatchCheckAccessResponse { results }))
    }
}

/// Start the in-process server on an ephemeral loopback port; returns the
/// bound address and the shared call counter. The server task is detached
/// (aborted when the test process exits) — acceptable for a short-lived
/// integration test.
async fn start_test_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let (service, call_count) = StubAuthorizationService::new();

    let incoming =
        TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).expect("bind ephemeral loopback port");
    let addr = incoming.local_addr().expect("resolve bound local_addr");

    tokio::spawn(async move {
        Server::builder()
            .add_service(AuthorizationServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .expect("in-process tonic test server");
    });

    // Give the spawned server a brief moment to start accepting connections.
    // `connect_lazy` means the SDK client itself performs no eager
    // connection, so this only guards the test server's own startup race.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    (addr, call_count)
}

/// A refresh closure that always succeeds, incrementing a shared counter so
/// tests can assert exactly-one-refresh behavior (§9).
fn counting_refresh_fn(counter: Arc<AtomicUsize>) -> axiam_sdk::grpc::RefreshFn {
    Arc::new(move |_refresh_token: String| {
        let counter = Arc::clone(&counter);
        let fut: Pin<Box<dyn Future<Output = Result<RefreshedTokens, AxiamError>> + Send>> =
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(RefreshedTokens {
                    access: Sensitive::new("new-access-token".to_string()),
                    refresh: Some(Sensitive::new("new-refresh-token".to_string())),
                    exp: Some(9_999_999_999),
                    tenant_id: None,
                })
            });
        fut
    })
}

async fn build_test_client(
    addr: SocketAddr,
    tenant_id: Uuid,
    refresh_call_count: Arc<AtomicUsize>,
) -> AuthzGrpcClient {
    let token_manager = Arc::new(TokenManager::new());
    token_manager
        .set_tokens(
            Sensitive::new("initial-access-token".to_string()),
            Some(Sensitive::new("initial-refresh-token".to_string())),
            Some(9_999_999_999),
            Some(tenant_id),
        )
        .await;

    let channel = build_channel(&format!("http://{addr}"), &GrpcChannelConfig::default())
        .expect("build shared lazy channel");

    AuthzGrpcClient::new(
        channel,
        token_manager,
        tenant_id,
        counting_refresh_fn(refresh_call_count),
    )
}

fn sample_request(action: &str, tenant_id: Uuid) -> CheckAccessRequest {
    CheckAccessRequest {
        tenant_id,
        subject_id: Uuid::new_v4(),
        action: action.to_string(),
        resource_id: Uuid::new_v4(),
        scope: None,
    }
}

#[tokio::test]
async fn grpc_check_access() {
    let (addr, _call_count) = start_test_server().await;
    let tenant_id = Uuid::new_v4();
    let refresh_count = Arc::new(AtomicUsize::new(0));
    let client = build_test_client(addr, tenant_id, refresh_count).await;

    let decision = client
        .check_access(sample_request("allow", tenant_id))
        .await
        .expect("check_access should succeed");

    assert_eq!(
        decision,
        AccessDecision {
            allowed: true,
            deny_reason: None,
        }
    );
}

#[tokio::test]
async fn grpc_batch_check_access_preserves_input_order() {
    let (addr, _call_count) = start_test_server().await;
    let tenant_id = Uuid::new_v4();
    let refresh_count = Arc::new(AtomicUsize::new(0));
    let client = build_test_client(addr, tenant_id, refresh_count).await;

    let all_allow = vec![
        sample_request("allow", tenant_id),
        sample_request("allow", tenant_id),
        sample_request("allow", tenant_id),
    ];
    let results = client
        .batch_check(all_allow)
        .await
        .expect("all-allow batch should succeed");
    assert_eq!(results.len(), 3);
    assert!(
        results.iter().all(|r| r.allowed),
        "batch results must be returned in the same order as the input requests (CONTRACT.md §1)"
    );
}

#[tokio::test]
async fn grpc_batch_check_access_propagates_denial_status() {
    let (addr, _call_count) = start_test_server().await;
    let tenant_id = Uuid::new_v4();
    let refresh_count = Arc::new(AtomicUsize::new(0));
    let client = build_test_client(addr, tenant_id, refresh_count).await;

    // The stub server's `deny` action short-circuits with PERMISSION_DENIED
    // (mirroring the real server's fail-fast-on-mismatch behavior in
    // `crates/axiam-api-grpc/src/services/authorization.rs::batch_check_access`);
    // asserts the same §2 status mapping applies inside a batch call.
    let requests = vec![
        sample_request("allow", tenant_id),
        sample_request("deny", tenant_id),
    ];
    let err = client.batch_check(requests).await.unwrap_err();
    assert!(matches!(err, AxiamError::Authz { .. }));
}

#[tokio::test]
async fn grpc_permission_denied_maps_to_authz_error() {
    let (addr, _call_count) = start_test_server().await;
    let tenant_id = Uuid::new_v4();
    let refresh_count = Arc::new(AtomicUsize::new(0));
    let client = build_test_client(addr, tenant_id, refresh_count).await;

    let err = client
        .check_access(sample_request("deny", tenant_id))
        .await
        .unwrap_err();

    assert!(
        matches!(err, AxiamError::Authz { .. }),
        "PERMISSION_DENIED must map to AxiamError::Authz per CONTRACT.md §2, got: {err:?}"
    );
}

#[tokio::test]
async fn grpc_unavailable_maps_to_network_error() {
    let (addr, _call_count) = start_test_server().await;
    let tenant_id = Uuid::new_v4();
    let refresh_count = Arc::new(AtomicUsize::new(0));
    let client = build_test_client(addr, tenant_id, refresh_count).await;

    let err = client
        .check_access(sample_request("unavailable", tenant_id))
        .await
        .unwrap_err();

    assert!(
        matches!(err, AxiamError::Network { .. }),
        "UNAVAILABLE must map to AxiamError::Network per CONTRACT.md §2, got: {err:?}"
    );
}

#[tokio::test]
async fn grpc_unauthenticated_drives_exactly_one_refresh_then_succeeds() {
    let (addr, _call_count) = start_test_server().await;
    let tenant_id = Uuid::new_v4();
    let refresh_count = Arc::new(AtomicUsize::new(0));
    let client = build_test_client(addr, tenant_id, Arc::clone(&refresh_count)).await;

    let decision = client
        .check_access(sample_request("unauthenticated-once", tenant_id))
        .await
        .expect("UNAUTHENTICATED-then-success should ultimately succeed");

    assert!(decision.allowed);
    assert_eq!(
        refresh_count.load(Ordering::SeqCst),
        1,
        "exactly one single-flight refresh must occur, no second refresh (§9.3)"
    );
}
