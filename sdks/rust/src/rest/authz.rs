//! REST authz methods: `check_access`/`can`/`batch_check` (CONTRACT.md §1).
//!
//! Mirrors `crates/axiam-api-rest/src/handlers/authz_check.rs` request/
//! response shapes exactly (mirror only, no server crate dependency).
//! `tenant_id` is never sent in the body — the server derives it from the
//! JWT (§5); the SDK only sends `X-Tenant-ID` as the CONTRACT.md §5 header.

use backon::{ExponentialBuilder, Retryable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::client::AxiamClient;
use crate::AxiamError;

const CHECK_PATH: &str = "/api/v1/authz/check";
const BATCH_CHECK_PATH: &str = "/api/v1/authz/check/batch";

/// A single access check request (CONTRACT.md §1).
#[derive(Debug, Clone, Serialize)]
pub struct AccessCheckRequest {
    pub action: String,
    pub resource_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<Uuid>,
}

impl AccessCheckRequest {
    pub fn new(action: impl Into<String>, resource_id: Uuid) -> Self {
        Self {
            action: action.into(),
            resource_id,
            scope: None,
            subject_id: None,
        }
    }

    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    pub fn with_subject(mut self, subject_id: Uuid) -> Self {
        self.subject_id = Some(subject_id);
        self
    }
}

/// The result of a single access check (mirrors `CheckAccessResponse`).
#[derive(Debug, Clone, Deserialize)]
pub struct AccessDecision {
    pub allowed: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct BatchCheckRequestBody {
    checks: Vec<AccessCheckRequest>,
}

#[derive(Debug, Deserialize)]
struct BatchCheckResponseWire {
    results: Vec<AccessDecision>,
}

impl AxiamClient {
    /// `POST /api/v1/authz/check` — evaluate a single authorization check
    /// for the given `action`/`resource_id`/`scope` (CONTRACT.md §1).
    ///
    /// This is a read-only, idempotent operation: transient
    /// network/429-with-Retry-After failures are retried a bounded number
    /// of times (D-12); `login`/`verify_mfa`/`refresh`/`logout` are
    /// state-changing and deliberately do NOT get this treatment.
    pub async fn check_access(
        &self,
        action: &str,
        resource_id: Uuid,
        scope: Option<&str>,
    ) -> Result<AccessDecision, AxiamError> {
        let request = AccessCheckRequest {
            action: action.to_string(),
            resource_id,
            scope: scope.map(str::to_string),
            subject_id: None,
        };
        self.check_access_request(&request).await
    }

    /// `can` — alias for [`Self::check_access`] targeting browser/UI
    /// scenarios (CONTRACT.md §1 note).
    pub async fn can(
        &self,
        action: &str,
        resource_id: Uuid,
        scope: Option<&str>,
    ) -> Result<bool, AxiamError> {
        self.check_access(action, resource_id, scope)
            .await
            .map(|decision| decision.allowed)
    }

    /// `POST /api/v1/authz/check/batch` — evaluate an ordered list of
    /// checks; results are returned in the same order as `requests`
    /// (CONTRACT.md §1).
    pub async fn batch_check(
        &self,
        requests: Vec<AccessCheckRequest>,
    ) -> Result<Vec<AccessDecision>, AxiamError> {
        let body = BatchCheckRequestBody { checks: requests };
        let client = self.clone();

        let wire: BatchCheckResponseWire = (|| {
            let client = client.clone();
            let body_ref = &body;
            async move { client.send_authz_post(BATCH_CHECK_PATH, body_ref).await }
        })
        .retry(retry_policy())
        .when(is_retryable)
        .await?;

        Ok(wire.results)
    }

    async fn check_access_request(
        &self,
        request: &AccessCheckRequest,
    ) -> Result<AccessDecision, AxiamError> {
        let client = self.clone();
        (|| {
            let client = client.clone();
            async move { client.send_authz_post(CHECK_PATH, request).await }
        })
        .retry(retry_policy())
        .when(is_retryable)
        .await
    }

    async fn send_authz_post<B, R>(&self, path: &str, body: &B) -> Result<R, AxiamError>
    where
        B: Serialize + ?Sized,
        R: for<'de> Deserialize<'de>,
    {
        let response = self
            .http()
            .post(self.authz_url(path))
            .header("X-Tenant-ID", self.tenant_header_value())
            .json(body)
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("authz request failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "no response body".to_string());
            return Err(AxiamError::from_http_status(status, message));
        }

        response.json().await.map_err(|e| AxiamError::Network {
            message: format!("failed to parse authz response body: {e}"),
            source: Some(Box::new(e)),
        })
    }

    fn authz_url(&self, path: &str) -> url::Url {
        self.base_url()
            .join(path)
            .expect("authz path is a well-formed relative URL literal")
    }
}

/// Bounded exponential backoff for read-only authz checks (D-12): max 3
/// attempts total (1 initial + 2 retries).
fn retry_policy() -> ExponentialBuilder {
    ExponentialBuilder::default().with_max_times(2)
}

/// Only retry `NetworkError` (transient/429/5xx) — never retry `Auth`/`Authz`
/// failures, which are decisive, not transient (§9/D-12).
fn is_retryable(err: &AxiamError) -> bool {
    matches!(err, AxiamError::Network { .. })
}
