//! Device Authorization Grant service (RFC 8628) — B2.
//!
//! Deliberately a **separate service** from [`crate::token::TokenService`]
//! rather than a seventh generic parameter on it. The device flow needs one
//! repository nothing else needs, and threading it through a service that
//! already carries six would change every construction site in the codebase to
//! serve one grant. The REST layer dispatches
//! `grant_type=urn:ietf:params:oauth:grant-type:device_code` here and
//! everything else to `TokenService`, which keeps the seam at one `match` arm.
//!
//! # The polling contract (RFC 8628 §3.5)
//!
//! The device hits the token endpoint in a loop. Almost every one of those
//! requests is answered with an *error*, and that is normal:
//!
//! | State | Answer | Device should |
//! |---|---|---|
//! | pending | `authorization_pending` | keep polling at `interval` |
//! | pending, polled too fast | `slow_down` | raise its interval and keep polling |
//! | approved | tokens | stop |
//! | denied | `access_denied` | **stop** — the user said no |
//! | expired | `expired_token` | restart the flow |
//! | unknown / already redeemed | `invalid_grant` | stop |
//!
//! `denied` being distinct from `pending` is what lets a device stop
//! immediately instead of polling out the full ten minutes after a user has
//! already refused — which is both a better experience and less load.

use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::models::oauth2_client::{CreateDeviceGrant, CreateRefreshToken, DeviceGrantStatus};
use axiam_core::repository::{
    DeviceGrantRepository, OAuth2ClientRepository, RefreshTokenRepository, TenantRepository,
    UserRepository,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::device::{
    DEFAULT_EXPIRES_IN_SECS, DEFAULT_INTERVAL_SECS, generate_device_code, generate_user_code,
    hash_device_code, normalize_user_code,
};
use crate::error::OAuth2Error;
use crate::token::TokenResponse;

/// The grant type this service handles.
pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// `POST /oauth2/device_authorization` request (RFC 8628 §3.1).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct DeviceAuthorizationRequest {
    pub client_id: String,
    pub scope: Option<String>,
}

/// `POST /oauth2/device_authorization` response (RFC 8628 §3.2).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DeviceAuthorizationResponse {
    /// The secret the device polls with. Returned once; only its hash is kept.
    pub device_code: String,
    /// The short code the user reads off the device and types.
    pub user_code: String,
    /// Where the user should go to enter it.
    pub verification_uri: String,
    /// The same URI with the code pre-filled, for devices that can render a
    /// QR code. RFC 8628 §3.3.1 — optional, but it is the difference between
    /// a user typing eight characters and scanning.
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

/// Device-flow service.
///
/// `Clone` for the same reason `TokenService` is: the REST layer holds it in
/// `AppState`, which actix clones per worker thread. Every field is either a
/// cheap repository handle or configuration, so a clone is a handful of
/// `Arc` bumps rather than a copy of anything.
#[derive(Clone)]
pub struct DeviceAuthorizationService<DG, OC, TR, RT, UR> {
    device_repo: DG,
    client_repo: OC,
    tenant_repo: TR,
    refresh_token_repo: RT,
    user_repo: UR,
    auth_config: AuthConfig,
    refresh_token_lifetime_secs: i64,
    /// Base URI the user is sent to, e.g. `https://id.example.com/device`.
    verification_uri: String,
}

impl<DG, OC, TR, RT, UR> DeviceAuthorizationService<DG, OC, TR, RT, UR>
where
    DG: DeviceGrantRepository,
    OC: OAuth2ClientRepository,
    TR: TenantRepository,
    RT: RefreshTokenRepository,
    UR: UserRepository,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        device_repo: DG,
        client_repo: OC,
        tenant_repo: TR,
        refresh_token_repo: RT,
        user_repo: UR,
        auth_config: AuthConfig,
        refresh_token_lifetime_secs: i64,
        verification_uri: String,
    ) -> Self {
        Self {
            device_repo,
            client_repo,
            tenant_repo,
            refresh_token_repo,
            user_repo,
            auth_config,
            refresh_token_lifetime_secs,
            verification_uri,
        }
    }

    /// RFC 8628 §3.1–3.2 — issue a device code and a user code.
    ///
    /// The client is authenticated only by `client_id`: RFC 8628 is designed
    /// for public clients (a TV cannot keep a secret), so there is no secret
    /// to check. What *is* checked is that the client exists, belongs to this
    /// tenant, and is registered for this grant type — otherwise any string
    /// could mint a pending grant and consume the user-code space.
    pub async fn authorize(
        &self,
        tenant_id: Uuid,
        req: DeviceAuthorizationRequest,
    ) -> Result<DeviceAuthorizationResponse, OAuth2Error> {
        let client = self
            .client_repo
            .get_by_client_id(tenant_id, &req.client_id)
            .await
            .map_err(|_| OAuth2Error::InvalidClient("unknown client".into()))?;

        if !client
            .grant_types
            .iter()
            .any(|g| g == DEVICE_CODE_GRANT_TYPE || g == "device_code")
        {
            return Err(OAuth2Error::UnauthorizedClient(
                "client is not registered for the device authorization grant".into(),
            ));
        }

        // Scopes are narrowed to what the client is registered for. A device
        // asking for more than its registration allows gets the intersection,
        // not an error: the same posture the other grants take.
        let requested: Vec<String> = req
            .scope
            .as_deref()
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_else(|| client.scopes.clone());
        let scopes: Vec<String> = requested
            .into_iter()
            .filter(|s| client.scopes.iter().any(|c| c == s))
            .collect();

        let device_code = generate_device_code();
        let user_code_display = generate_user_code();
        // Stored normalised, because that is the form every lookup uses.
        let user_code = normalize_user_code(&user_code_display);

        self.device_repo
            .create(CreateDeviceGrant {
                tenant_id,
                client_id: req.client_id,
                device_code_hash: hash_device_code(&device_code),
                user_code: user_code.clone(),
                scopes,
                expires_at: Utc::now() + Duration::seconds(DEFAULT_EXPIRES_IN_SECS as i64),
                interval_secs: DEFAULT_INTERVAL_SECS,
            })
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        Ok(DeviceAuthorizationResponse {
            device_code,
            verification_uri: self.verification_uri.clone(),
            verification_uri_complete: format!(
                "{}?user_code={}",
                self.verification_uri, user_code_display
            ),
            user_code: user_code_display,
            expires_in: DEFAULT_EXPIRES_IN_SECS,
            interval: DEFAULT_INTERVAL_SECS,
        })
    }

    /// RFC 8628 §3.4–3.5 — the device polls with its `device_code`.
    ///
    /// Order matters here and is worth stating: the poll interval is enforced
    /// **before** the state is examined. A device hammering the endpoint gets
    /// `slow_down` whatever its grant's state, so the corrective signal is not
    /// something it can outrun by being in a lucky state.
    pub async fn poll(
        &self,
        tenant_id: Uuid,
        device_code: &str,
    ) -> Result<TokenResponse, OAuth2Error> {
        let hash = hash_device_code(device_code);

        let (_interval, too_fast) = self
            .device_repo
            .record_poll(tenant_id, &hash)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
        if too_fast {
            return Err(OAuth2Error::SlowDown);
        }

        let grant = self
            .device_repo
            .get_by_device_code_hash(tenant_id, &hash)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?
            // An unknown device code and an already-redeemed one are both
            // `invalid_grant`. They are genuinely the same answer: in both
            // cases this code will never produce a token, and distinguishing
            // them would tell a caller which codes have existed.
            .ok_or_else(|| OAuth2Error::InvalidGrant("unknown device code".into()))?;

        if grant.expires_at <= Utc::now() {
            return Err(OAuth2Error::ExpiredToken);
        }

        match grant.status {
            DeviceGrantStatus::Pending => return Err(OAuth2Error::AuthorizationPending),
            DeviceGrantStatus::Denied => {
                return Err(OAuth2Error::AccessDenied(
                    "the user denied the request".into(),
                ));
            }
            DeviceGrantStatus::Redeemed => {
                return Err(OAuth2Error::InvalidGrant(
                    "device code has already been used".into(),
                ));
            }
            DeviceGrantStatus::Approved => {}
        }

        // Atomically redeem. Between the read above and here, a concurrent
        // poll may have taken it — which is exactly why the check is not
        // "status was approved a moment ago" but "this statement redeemed it".
        let redeemed = self
            .device_repo
            .redeem(tenant_id, &hash)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?
            .ok_or_else(|| OAuth2Error::InvalidGrant("device code has already been used".into()))?;

        let user_id = redeemed.user_id.ok_or_else(|| {
            // An approved grant without a user is a datastore inconsistency,
            // not a caller error — refuse rather than mint a token for nobody.
            OAuth2Error::ServerError("approved device grant has no subject".into())
        })?;

        let tenant = self
            .tenant_repo
            .get_by_id(tenant_id)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
        let user = self
            .user_repo
            .get_by_id(tenant_id, user_id)
            .await
            .map_err(|_| OAuth2Error::InvalidGrant("user no longer exists".into()))?;

        let refresh_token = axiam_auth::token::generate_refresh_token();
        self.refresh_token_repo
            .create(CreateRefreshToken {
                tenant_id,
                client_id: redeemed.client_id.clone(),
                user_id: Some(user.id),
                token_hash: axiam_auth::token::hash_refresh_token(&refresh_token),
                scopes: redeemed.scopes.clone(),
                // RFC 8628 has no browser session behind it: the device polls
                // and the approval happened elsewhere, so there is no AXIAM
                // session for a back-channel logout to name.
                session_id: None,
                expires_at: Utc::now() + Duration::seconds(self.refresh_token_lifetime_secs),
            })
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        let access_token = issue_access_token(
            user.id,
            tenant_id,
            tenant.organization_id,
            &redeemed.scopes,
            &self.auth_config,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        let scope = if redeemed.scopes.is_empty() {
            None
        } else {
            Some(redeemed.scopes.join(" "))
        };

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in: self.auth_config.access_token_lifetime_secs,
            refresh_token: Some(refresh_token),
            scope,
            id_token: None,
        })
    }

    /// Look up a pending grant by the code a user typed, for the verification
    /// page. Returns `None` for unknown, expired, or already-decided codes —
    /// the page must not reveal which.
    pub async fn lookup_for_verification(
        &self,
        tenant_id: Uuid,
        typed_code: &str,
    ) -> Result<Option<(String, Vec<String>)>, OAuth2Error> {
        let normalized = normalize_user_code(typed_code);
        if normalized.is_empty() {
            return Ok(None);
        }
        let grant = self
            .device_repo
            .get_by_user_code(tenant_id, &normalized)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        Ok(grant
            .filter(|g| g.status == DeviceGrantStatus::Pending && g.expires_at > Utc::now())
            .map(|g| (g.client_id, g.scopes)))
    }

    /// Record the user's approval or refusal from the verification page.
    ///
    /// `false` means the code was unknown, expired, or already decided — the
    /// caller shows one message for all three, because distinguishing them
    /// would turn the verification page into an oracle for which codes are
    /// live.
    pub async fn decide(
        &self,
        tenant_id: Uuid,
        typed_code: &str,
        approved: bool,
        user_id: Uuid,
    ) -> Result<bool, OAuth2Error> {
        let normalized = normalize_user_code(typed_code);
        if normalized.is_empty() {
            return Ok(false);
        }
        self.device_repo
            .decide(tenant_id, &normalized, approved, user_id)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))
    }
}
