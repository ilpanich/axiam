//! gRPC `check_access`/`batch_check` client methods + the UNAUTHENTICATED
//! single-flight-retry wrapper (D-04, CONTRACT.md §1/§2/§9).
//!
//! **Feature-independence note:** unlike the REST transport's
//! `AxiamClient` (gated behind `feature = "rest"`, since it is built on
//! `reqwest`), this module depends only on [`crate::token::TokenManager`]
//! and [`crate::token::refresh_guard::RefreshedTokens`] (both always
//! compiled — see `src/token/manager.rs` / `src/token/refresh_guard.rs`), so
//! `cargo build --no-default-features --features grpc` builds a fully
//! working gRPC client with a fully working single-flight refresh
//! mechanism, with no REST transport pulled in at all. The actual
//! `POST /api/v1/auth/refresh` HTTP call is supplied by the caller as a
//! `do_refresh` closure at construction time (see [`AuthzGrpcClient::new`])
//! — exactly the same shared single-flight guard
//! ([`TokenManager::refresh_if_needed`]) that the REST transport's
//! `AxiamClient::refresh` (16-02) drives with its own `reqwest`-based
//! closure. A caller who has already constructed a `rest`-enabled
//! `AxiamClient` passes a closure that reuses it; a `grpc`-only consumer
//! supplies their own minimal HTTP call.
//!
//! The UNAUTHENTICATED-retry wrapper lives here, at the ASYNC call site —
//! never inside [`crate::grpc::interceptor::AuthInterceptor`], which is
//! synchronous (Pitfall 3).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::Code;
use uuid::Uuid;

use crate::grpc::gen::authorization_service_client::AuthorizationServiceClient;
use crate::grpc::gen::{
    BatchCheckAccessRequest as WireBatchCheckAccessRequest,
    CheckAccessRequest as WireCheckAccessRequest, CheckAccessResponse as WireCheckAccessResponse,
};
use crate::grpc::interceptor::AuthInterceptor;
use crate::token::refresh_guard::RefreshedTokens;
use crate::token::TokenManager;
use crate::AxiamError;

/// A single access check request (CONTRACT.md §1) — the gRPC-transport
/// equivalent of `crate::rest::authz::AccessCheckRequest`, matching the
/// `CheckAccessRequest` proto message shape
/// (`proto/axiam/v1/authorization.proto`).
#[derive(Debug, Clone)]
pub struct CheckAccessRequest {
    pub tenant_id: Uuid,
    pub subject_id: Uuid,
    pub action: String,
    pub resource_id: Uuid,
    pub scope: Option<String>,
}

/// The result of a single access check (mirrors `CheckAccessResponse`,
/// shared shape with `crate::rest::authz::AccessDecision`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDecision {
    pub allowed: bool,
    pub deny_reason: Option<String>,
}

impl From<WireCheckAccessResponse> for AccessDecision {
    fn from(wire: WireCheckAccessResponse) -> Self {
        AccessDecision {
            allowed: wire.allowed,
            deny_reason: if wire.deny_reason.is_empty() {
                None
            } else {
                Some(wire.deny_reason)
            },
        }
    }
}

impl From<&CheckAccessRequest> for WireCheckAccessRequest {
    fn from(req: &CheckAccessRequest) -> Self {
        WireCheckAccessRequest {
            tenant_id: req.tenant_id.to_string(),
            subject_id: req.subject_id.to_string(),
            action: req.action.clone(),
            resource_id: req.resource_id.to_string(),
            scope: req.scope.clone(),
        }
    }
}

type InnerClient = AuthorizationServiceClient<InterceptedService<Channel, AuthInterceptor>>;

/// Caller-supplied closure performing the actual `POST /api/v1/auth/refresh`
/// HTTP call. Receives the current refresh token (already unwrapped from
/// `Sensitive`, matching [`TokenManager::refresh_if_needed`]'s contract) and
/// returns the new token triple on success.
pub type RefreshFn = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<RefreshedTokens, AxiamError>> + Send>>
        + Send
        + Sync,
>;

/// gRPC transport client for `AuthorizationService` (`CheckAccess` /
/// `BatchCheckAccess`), reusing the single shared lazily-connected
/// [`Channel`] (Pitfall 5) and injecting auth + tenant metadata via
/// [`AuthInterceptor`] on every RPC.
#[derive(Clone)]
pub struct AuthzGrpcClient {
    inner: InnerClient,
    token_manager: Arc<TokenManager>,
    tenant_id: Uuid,
    refresh_fn: RefreshFn,
}

impl AuthzGrpcClient {
    /// Wrap an already-constructed shared [`Channel`] (see
    /// [`crate::grpc::channel::build_channel`]) with the auth/tenant
    /// interceptor.
    ///
    /// `token_manager` MUST be the same instance any REST transport (if
    /// present) uses, so a token obtained via `login()` is visible to gRPC
    /// calls and vice versa. `refresh_fn` performs the actual
    /// `POST /api/v1/auth/refresh` HTTP call driven by the shared
    /// single-flight guard on `UNAUTHENTICATED` (§9) — supply a closure that
    /// reuses an existing `rest`-enabled `AxiamClient::refresh` code path,
    /// or a caller-provided minimal HTTP client in a `grpc`-only build.
    pub fn new(
        channel: Channel,
        token_manager: Arc<TokenManager>,
        tenant_id: Uuid,
        refresh_fn: RefreshFn,
    ) -> Self {
        let interceptor = AuthInterceptor::new(Arc::clone(&token_manager), tenant_id);
        let inner = AuthorizationServiceClient::with_interceptor(channel, interceptor);
        Self {
            inner,
            token_manager,
            tenant_id,
            refresh_fn,
        }
    }

    /// The tenant UUID this client was constructed with (never the slug
    /// form — see [`AuthInterceptor`] doc comment).
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    /// `CheckAccess` — evaluate a single authorization check (CONTRACT.md
    /// §1). On `UNAUTHENTICATED`, drives the shared single-flight refresh
    /// (§9) and retries exactly once; never retries a second time (§9.3).
    pub async fn check_access(
        &self,
        request: CheckAccessRequest,
    ) -> Result<AccessDecision, AxiamError> {
        let wire_request = WireCheckAccessRequest::from(&request);

        match self.try_check_access(wire_request.clone()).await {
            Ok(resp) => Ok(resp.into()),
            Err(status) if status.code() == Code::Unauthenticated => self
                .refresh_and_retry(|| self.try_check_access(wire_request.clone()))
                .await
                .map(Into::into),
            Err(status) => Err(status_to_axiam_error(status)),
        }
    }

    /// `BatchCheckAccess` — evaluate an ordered list of checks; results are
    /// returned in the same order as `requests` (CONTRACT.md §1). Shares the
    /// same UNAUTHENTICATED single-flight-retry behavior as
    /// [`Self::check_access`].
    pub async fn batch_check(
        &self,
        requests: Vec<CheckAccessRequest>,
    ) -> Result<Vec<AccessDecision>, AxiamError> {
        let wire_requests: Vec<WireCheckAccessRequest> =
            requests.iter().map(WireCheckAccessRequest::from).collect();
        let wire_request = WireBatchCheckAccessRequest {
            requests: wire_requests,
        };

        match self.try_batch_check(wire_request.clone()).await {
            Ok(results) => Ok(results.into_iter().map(Into::into).collect()),
            Err(status) if status.code() == Code::Unauthenticated => self
                .refresh_and_retry(|| self.try_batch_check(wire_request.clone()))
                .await
                .map(|results| results.into_iter().map(Into::into).collect()),
            Err(status) => Err(status_to_axiam_error(status)),
        }
    }

    async fn try_check_access(
        &self,
        wire_request: WireCheckAccessRequest,
    ) -> Result<WireCheckAccessResponse, tonic::Status> {
        let mut client = self.inner.clone();
        client
            .check_access(wire_request)
            .await
            .map(|resp| resp.into_inner())
    }

    async fn try_batch_check(
        &self,
        wire_request: WireBatchCheckAccessRequest,
    ) -> Result<Vec<WireCheckAccessResponse>, tonic::Status> {
        let mut client = self.inner.clone();
        client
            .batch_check_access(wire_request)
            .await
            .map(|resp| resp.into_inner().results)
    }

    /// Drive the shared single-flight refresh (§9) then retry `attempt`
    /// exactly once. The interceptor itself never performs this — it is
    /// synchronous and must not touch the async refresh mutex (Pitfall 3).
    async fn refresh_and_retry<T, F, Fut>(&self, attempt: F) -> Result<T, AxiamError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, tonic::Status>>,
    {
        let observed = self
            .token_manager
            .cached_access_token()
            .map(|t| t.expose().clone())
            .unwrap_or_default();

        let refresh_fn = Arc::clone(&self.refresh_fn);
        self.token_manager
            .refresh_if_needed(&observed, move |refresh_token| refresh_fn(refresh_token))
            .await?;

        attempt().await.map_err(status_to_axiam_error)
    }
}

/// Map a terminal gRPC [`tonic::Status`] to an [`AxiamError`] per
/// CONTRACT.md §2's gRPC status table, via the shared `from_grpc_code`
/// helper (16-01).
fn status_to_axiam_error(status: tonic::Status) -> AxiamError {
    AxiamError::from_grpc_code(status.code() as i32, status.message().to_string())
}
