//! REST auth flow: `login`/`verify_mfa`/`refresh`/`logout` (CONTRACT.md §1).
//!
//! Mirrors `crates/axiam-api-rest/src/handlers/auth.rs` request/response
//! shapes exactly (mirror only, no server crate dependency). Tokens are
//! delivered exclusively via `Set-Cookie` — `LoginResult` deliberately has
//! **no** `access_token` field (D-05).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::client::{AxiamClient, OrgIdentifier, TenantIdentifier};
use crate::token::jwks::Claims;
use crate::token::manager::{extract_access_token_from_jar, extract_refresh_token_from_jar};
use crate::token::refresh_guard::RefreshedTokens;
use crate::AxiamError;
use crate::Sensitive;

const LOGIN_PATH: &str = "/api/v1/auth/login";
const MFA_VERIFY_PATH: &str = "/api/v1/auth/mfa/verify";
const REFRESH_PATH: &str = "/api/v1/auth/refresh";
const LOGOUT_PATH: &str = "/api/v1/auth/logout";

// ---------------------------------------------------------------------------
// Request bodies (mirror crates/axiam-api-rest/src/handlers/auth.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct LoginRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_slug: Option<String>,
    username_or_email: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct MfaVerifyRequestBody {
    challenge_token: String,
    totp_code: String,
}

#[derive(Debug, Serialize)]
struct RefreshRequestBody {
    tenant_id: Uuid,
    org_id: Uuid,
}

#[derive(Debug, Serialize)]
struct LogoutRequestBody {
    session_id: Uuid,
}

// ---------------------------------------------------------------------------
// Response bodies (mirror server shapes; Deserialize only, no server dep)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct LoginUserInfoWire {
    #[allow(dead_code)]
    id: Uuid,
    #[allow(dead_code)]
    username: String,
    #[allow(dead_code)]
    email: String,
}

/// `200 OK` body from `/api/v1/auth/login`, `/api/v1/auth/mfa/verify`, and
/// (fields overlap) `/api/v1/auth/refresh`.
#[derive(Debug, Deserialize)]
struct LoginSuccessResponseWire {
    #[allow(dead_code)]
    user: LoginUserInfoWire,
    session_id: Uuid,
    expires_in: u64,
}

/// `202 Accepted` body from `/api/v1/auth/login` when MFA is required.
#[derive(Debug, Deserialize)]
struct MfaRequiredResponseWire {
    challenge_token: String,
    available_methods: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RefreshSuccessResponseWire {
    expires_in: u64,
}

// ---------------------------------------------------------------------------
// Public result type — CONTRACT.md §1, D-05 (no access_token field)
// ---------------------------------------------------------------------------

/// The outcome of [`AxiamClient::login`]/[`AxiamClient::verify_mfa`].
///
/// **No `access_token` field exists here or anywhere else in this SDK's
/// public API** — AXIAM delivers tokens exclusively via `Set-Cookie`
/// (D-05). After a successful (non-MFA) call, the access token is already
/// present in the client's cookie jar and its claims have been decoded into
/// the internal [`crate::token::TokenManager`].
#[derive(Debug)]
pub struct LoginResult {
    /// `true` if the server responded with an MFA challenge instead of a
    /// completed session; call [`AxiamClient::verify_mfa`] next.
    pub mfa_required: bool,
    /// Set when `mfa_required` is `true` — the opaque challenge token to
    /// pass to [`AxiamClient::verify_mfa`]. Treated as sensitive (short-lived
    /// bearer of "logging in as this user") even though it is not a full
    /// session token.
    pub challenge_token: Option<Sensitive<String>>,
    /// Authentication methods available to satisfy the MFA challenge (only
    /// populated when `mfa_required` is `true`).
    pub available_methods: Vec<String>,
    /// The server-issued session id (only populated on a completed,
    /// non-MFA-pending login/verify_mfa).
    pub session_id: Option<Uuid>,
    /// Access token lifetime in seconds, as reported by the server (only
    /// populated on a completed login/verify_mfa).
    pub expires_in: Option<u64>,
}

impl LoginResult {
    fn mfa_required(challenge_token: String, available_methods: Vec<String>) -> Self {
        Self {
            mfa_required: true,
            challenge_token: Some(Sensitive::new(challenge_token)),
            available_methods,
            session_id: None,
            expires_in: None,
        }
    }

    fn success(session_id: Uuid, expires_in: u64) -> Self {
        Self {
            mfa_required: false,
            challenge_token: None,
            available_methods: Vec::new(),
            session_id: Some(session_id),
            expires_in: Some(expires_in),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared post-success handling: extract cookies, verify, cache state
// ---------------------------------------------------------------------------

/// After any 200 response that sets `axiam_access`/`axiam_refresh`/
/// `axiam_csrf`, read them out of the jar (RESEARCH.md Pattern 1), decode
/// the access token's claims via the JWKS verifier to populate `exp` and
/// resolve `tenant_id`/`org_id`, and cache the CSRF token for §3 forwarding.
async fn absorb_session_cookies(client: &AxiamClient) -> Result<Claims, AxiamError> {
    let access = extract_access_token_from_jar(&client.inner.jar, &client.inner.base_url)
        .ok_or_else(|| AxiamError::Auth {
            message: "server response did not set the axiam_access cookie".into(),
        })?;
    let refresh = extract_refresh_token_from_jar(&client.inner.jar, &client.inner.base_url);

    let claims = client.jwks_verifier().verify(access.expose()).await?;

    let tenant_id = Uuid::parse_str(&claims.tenant_id).ok();
    let org_id = claims
        .org_id
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok());

    client
        .token_manager()
        .set_tokens(access, refresh, Some(claims.exp), tenant_id)
        .await;

    if let Some(org_id) = org_id {
        client.set_resolved_org_id(org_id);
    }

    client.capture_csrf_from_jar();

    Ok(claims)
}

// ---------------------------------------------------------------------------
// Public REST auth methods
// ---------------------------------------------------------------------------

impl AxiamClient {
    /// `POST /api/v1/auth/login` (CONTRACT.md §1).
    ///
    /// On success (no MFA), the access token is read from the cookie jar,
    /// verified, and cached — `LoginResult` itself never carries it (D-05).
    /// When the server signals MFA is required, returns
    /// `LoginResult { mfa_required: true, .. }` carrying the challenge
    /// token; call [`Self::verify_mfa`] next.
    pub async fn login(&self, email: &str, password: &str) -> Result<LoginResult, AxiamError> {
        let body = self.build_login_body(email, password);

        let response = self
            .http()
            .post(self.url(LOGIN_PATH))
            .json(&body)
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("login request failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        match response.status().as_u16() {
            200 => {
                let wire: LoginSuccessResponseWire = response.json().await.map_err(deser_err)?;
                absorb_session_cookies(self).await?;
                Ok(LoginResult::success(wire.session_id, wire.expires_in))
            }
            202 => {
                let wire: MfaRequiredResponseWire = response.json().await.map_err(deser_err)?;
                self.set_pending_mfa_challenge(Sensitive::new(wire.challenge_token.clone()));
                Ok(LoginResult::mfa_required(
                    wire.challenge_token,
                    wire.available_methods,
                ))
            }
            status => Err(map_error_response(status, response).await),
        }
    }

    /// `POST /api/v1/auth/mfa/verify` (CONTRACT.md §1).
    ///
    /// Completes the two-phase flow started by [`Self::login`] when
    /// `mfa_required` was `true`, using the challenge token captured
    /// internally from that prior `login()` call.
    pub async fn verify_mfa(&self, code: &str) -> Result<LoginResult, AxiamError> {
        let challenge = self
            .take_pending_mfa_challenge()
            .ok_or_else(|| AxiamError::Auth {
                message: "verify_mfa called with no pending MFA challenge — call login() first"
                    .into(),
            })?;

        let body = MfaVerifyRequestBody {
            challenge_token: challenge.expose().clone(),
            totp_code: code.to_string(),
        };

        let response = self
            .http()
            .post(self.url(MFA_VERIFY_PATH))
            .json(&body)
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("verify_mfa request failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        match response.status().as_u16() {
            200 => {
                let wire: LoginSuccessResponseWire = response.json().await.map_err(deser_err)?;
                absorb_session_cookies(self).await?;
                Ok(LoginResult::success(wire.session_id, wire.expires_in))
            }
            status => Err(map_error_response(status, response).await),
        }
    }

    /// `POST /api/v1/auth/refresh` (CONTRACT.md §1).
    ///
    /// Delegates to the single-flight guard
    /// ([`crate::token::TokenManager::refresh_if_needed`]) — this method
    /// contains no refresh HTTP logic of its own beyond driving that guard
    /// with the actual `reqwest` call as its closure.
    pub async fn refresh(&self) -> Result<(), AxiamError> {
        let observed =
            self.token_manager()
                .cached_access_token()
                .ok_or_else(|| AxiamError::Auth {
                    message: "no access token to refresh — call login() first".into(),
                })?;
        let observed_value = observed.expose().clone();

        let tenant_id = self
            .resolved_tenant_id()
            .await
            .ok_or_else(|| AxiamError::Auth {
                message: "tenant_id could not be resolved; login() must succeed before refresh()"
                    .into(),
            })?;
        let org_id = self.resolved_org_id().ok_or_else(|| AxiamError::Auth {
            message: "org_id could not be resolved; login() must succeed before refresh()".into(),
        })?;

        let client = self.clone();
        self.token_manager()
            .refresh_if_needed(&observed_value, move |_refresh_token_unused| {
                // The refresh token itself travels via the httpOnly
                // `axiam_refresh` cookie (already in the shared jar), not
                // the request body — mirroring
                // crates/axiam-api-rest/src/handlers/auth.rs::refresh.
                let client = client.clone();
                async move {
                    let body = RefreshRequestBody { tenant_id, org_id };
                    let response = client
                        .http()
                        .post(client.url(REFRESH_PATH))
                        .header("X-Tenant-ID", client.tenant_header_value())
                        .maybe_csrf_header(&client)
                        .json(&body)
                        .send()
                        .await
                        .map_err(|e| AxiamError::Network {
                            message: format!("refresh request failed: {e}"),
                            source: Some(Box::new(e)),
                        })?;

                    match response.status().as_u16() {
                        200 => {
                            let wire: RefreshSuccessResponseWire =
                                response.json().await.map_err(deser_err)?;
                            // §9.3 requires the refresh call to not retry on
                            // failure, but on SUCCESS we still must read the
                            // rotated cookies before reporting the new token.
                            let access = extract_access_token_from_jar(
                                &client.inner.jar,
                                &client.inner.base_url,
                            )
                            .ok_or_else(|| AxiamError::Auth {
                                message: "refresh response did not set axiam_access".into(),
                            })?;
                            let refresh_token = extract_refresh_token_from_jar(
                                &client.inner.jar,
                                &client.inner.base_url,
                            );
                            let claims = client.jwks_verifier().verify(access.expose()).await?;
                            client.capture_csrf_from_jar();
                            let _ = wire.expires_in; // exp is authoritative from claims, not this field
                            Ok(RefreshedTokens {
                                access,
                                refresh: refresh_token,
                                exp: Some(claims.exp),
                                tenant_id: Uuid::parse_str(&claims.tenant_id).ok(),
                            })
                        }
                        // §9.3: 401 on the refresh call itself is AuthError,
                        // no retry loop.
                        status => Err(map_error_response(status, response).await),
                    }
                }
            })
            .await?;

        Ok(())
    }

    /// `POST /api/v1/auth/logout` (CONTRACT.md §1).
    ///
    /// Clears in-memory token state and the jar's session cookies.
    pub async fn logout(&self) -> Result<(), AxiamError> {
        let session_id = {
            // The server keys logout off the session id embedded in the
            // caller's own JWT (`jti`), cross-validated server-side against
            // the authenticated user — the SDK must supply the same id it
            // received at login.
            let manager = self.token_manager();
            let access = manager.cached_access_token();
            match access {
                Some(token) => {
                    let claims = self.jwks_verifier().verify(token.expose()).await?;
                    claims
                        .jti
                        .as_deref()
                        .and_then(|s| Uuid::parse_str(s).ok())
                        .ok_or_else(|| AxiamError::Auth {
                            message: "access token has no session id (jti) to log out".into(),
                        })?
                }
                None => {
                    return Err(AxiamError::Auth {
                        message: "no active session to log out".into(),
                    });
                }
            }
        };

        let body = LogoutRequestBody { session_id };
        let response = self
            .http()
            .post(self.url(LOGOUT_PATH))
            .header("X-Tenant-ID", self.tenant_header_value())
            .maybe_csrf_header(self)
            .json(&body)
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("logout request failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        if !response.status().is_success() {
            return Err(map_error_response(response.status().as_u16(), response).await);
        }

        self.token_manager().clear().await;
        Ok(())
    }

    fn build_login_body(&self, email: &str, password: &str) -> LoginRequestBody {
        let (tenant_id, tenant_slug) = match &self.inner.tenant {
            TenantIdentifier::Id(id) => (Some(*id), None),
            TenantIdentifier::Slug(slug) => (None, Some(slug.clone())),
        };
        let (org_id, org_slug) = match self.org_identifier() {
            Some(OrgIdentifier::Id(id)) => (Some(*id), None),
            Some(OrgIdentifier::Slug(slug)) => (None, Some(slug.clone())),
            None => (None, None),
        };
        LoginRequestBody {
            tenant_id,
            org_id,
            tenant_slug,
            org_slug,
            username_or_email: email.to_string(),
            password: password.to_string(),
        }
    }

    fn url(&self, path: &str) -> url::Url {
        self.inner
            .base_url
            .join(path)
            .expect("path is a well-formed relative URL literal")
    }
}

/// Map a non-2xx REST response to an [`AxiamError`] per CONTRACT.md §2,
/// pulling a human-readable message out of the body if present (never a
/// raw token — these responses never carry one).
async fn map_error_response(status: u16, response: reqwest::Response) -> AxiamError {
    let message = response
        .text()
        .await
        .unwrap_or_else(|_| "no response body".to_string());
    AxiamError::from_http_status(status, message)
}

fn deser_err(e: reqwest::Error) -> AxiamError {
    AxiamError::Network {
        message: format!("failed to parse response body: {e}"),
        source: Some(Box::new(e)),
    }
}

/// Small extension trait so state-changing request builders can forward the
/// captured `X-CSRF-Token` (§3) in one line without repeating the
/// `if-let`/`header` boilerplate everywhere.
trait CsrfHeaderExt {
    fn maybe_csrf_header(self, client: &AxiamClient) -> Self;
}

impl CsrfHeaderExt for reqwest::RequestBuilder {
    fn maybe_csrf_header(self, client: &AxiamClient) -> Self {
        match client.csrf_token() {
            Some(token) => self.header("X-CSRF-Token", token),
            None => self,
        }
    }
}
