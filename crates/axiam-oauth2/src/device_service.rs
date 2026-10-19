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
//!
//! # Who may poll (#635, R101W3-01)
//!
//! The device code is a credential, but it is not the only one. RFC 8628 §3.4's
//! token request is an RFC 6749 token request, so it names its `client_id`, and
//! RFC 6749 §3.2.1 has a confidential client authenticate at the token endpoint
//! whatever the grant. Both endpoints of this grant therefore take a
//! [`DeviceClient`], which only `crate::token::TokenService` makes, after the
//! client authenticated by its **registered** method (a public client, by
//! presenting nothing), its tenant was found live, and — at the poll — the
//! profile's request-time rules passed and the token binding was decided. The
//! poll then answers a grant issued to another client exactly as it answers an
//! unknown device code, before it records the poll or looks at the grant's
//! state: a caller holding a leaked device code learns nothing about it, and
//! cannot spend it, slow it down or redeem it under a client it can
//! authenticate as.

use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, AccessTokenSpec, CnfClaim};
use axiam_core::error::AxiamError;
use axiam_core::models::oauth2_client::{
    CreateDeviceGrant, CreateRefreshToken, DeviceGrantStatus, OAuth2Client,
};
use axiam_core::repository::{DeviceGrantRepository, RefreshTokenRepository, UserRepository};
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

/// Both spellings of the device grant the admin API accepts in a client's
/// `grant_types`: the URN, and the bare `device_code`.
pub const DEVICE_CODE_GRANT_SPELLINGS: [&str; 2] = [DEVICE_CODE_GRANT_TYPE, "device_code"];

/// Whether a client's `grant_types` hold the device grant, in either spelling
/// the admin API accepts (the URN, or the bare `device_code`).
pub fn holds_device_grant(grant_types: &[String]) -> bool {
    grant_types
        .iter()
        .any(|g| DEVICE_CODE_GRANT_SPELLINGS.contains(&g.as_str()))
}

/// A client [`crate::token::TokenService`] authenticated for the device grant
/// (#635, R101W3-01).
///
/// Its fields are private and only the token service constructs one, so
/// neither [`DeviceAuthorizationService::authorize`] nor
/// [`DeviceAuthorizationService::poll_at`] can be reached with a client that
/// did not authenticate: the type is the proof that it did. What it carries is
/// what the two operations need from that authentication and nothing they
/// would otherwise have to read again — the registration (scopes, allowed
/// resources, provenance), the organization of the tenant found live, and, at
/// the poll, the `cnf` the token must carry.
pub struct DeviceClient {
    client: OAuth2Client,
    organization_id: Uuid,
    cnf: Option<CnfClaim>,
}

impl DeviceClient {
    /// Only the token service calls this, once the checks the type stands
    /// for have passed.
    pub(crate) fn new(client: OAuth2Client, organization_id: Uuid, cnf: Option<CnfClaim>) -> Self {
        Self {
            client,
            organization_id,
            cnf,
        }
    }

    /// The authenticated client's identifier.
    pub fn client_id(&self) -> &str {
        &self.client.client_id
    }
}

/// `POST /oauth2/device_authorization` request (RFC 8628 §3.1).
///
/// `Debug` is written by hand so that the credentials never reach a log line.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct DeviceAuthorizationRequest {
    /// Optional (#683): a `client_secret_basic` client names itself in the
    /// `Authorization` header and a `private_key_jwt` client in its
    /// assertion (RFC 6749 §2.3.1, RFC 7521 §4.2). The handler resolves it
    /// with `resolve_client_id`, as the token endpoint does.
    #[serde(default)]
    pub client_id: Option<String>,
    /// The client's secret, for a client registered for `client_secret_post`
    /// (#635, RFC 8628 §3.1 → RFC 6749 §2.3). A public client
    /// (`token_endpoint_auth_method: none`) sends none, and is refused if it
    /// does.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// RFC 7523 client assertion, for a client registered for
    /// `private_key_jwt` (#635).
    #[serde(default)]
    pub client_assertion: Option<String>,
    /// RFC 7521 §4.2 assertion type; must accompany `client_assertion`.
    #[serde(default)]
    pub client_assertion_type: Option<String>,
    pub scope: Option<String>,
    /// T21.3 / RFC 8707 §2 — the target service this device wants a token for.
    ///
    /// Named here, where the device makes its request, because a grant's
    /// audience is decided when the grant is made: the poll that redeems it
    /// may only repeat it. Validated against the client's `allowed_resources`
    /// and stored on the grant; absent leaves the flow exactly as it was (I2).
    #[serde(default)]
    pub resource: Option<String>,
}

impl std::fmt::Debug for DeviceAuthorizationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceAuthorizationRequest")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "client_assertion",
                &self.client_assertion.as_ref().map(|_| "<redacted>"),
            )
            .field("client_assertion_type", &self.client_assertion_type)
            .field("scope", &self.scope)
            .field("resource", &self.resource)
            .finish()
    }
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
pub struct DeviceAuthorizationService<DG, RT, UR> {
    device_repo: DG,
    refresh_token_repo: RT,
    user_repo: UR,
    auth_config: AuthConfig,
    refresh_token_lifetime_secs: i64,
    /// Base URI the user is sent to, e.g. `https://id.example.com/device`.
    verification_uri: String,
    /// #613 (T-289) — see [`crate::scope_ceiling`].
    scope_policy: crate::scope_ceiling::SharedScopePolicy,
}

impl<DG, RT, UR> DeviceAuthorizationService<DG, RT, UR>
where
    DG: DeviceGrantRepository,
    RT: RefreshTokenRepository,
    UR: UserRepository,
{
    /// The client and tenant repositories it once held are gone (#635): the
    /// client is read, authenticated and its tenant checked by
    /// `crate::token::TokenService`, which hands over a [`DeviceClient`].
    pub fn new(
        device_repo: DG,
        refresh_token_repo: RT,
        user_repo: UR,
        auth_config: AuthConfig,
        refresh_token_lifetime_secs: i64,
        verification_uri: String,
    ) -> Self {
        Self {
            device_repo,
            refresh_token_repo,
            user_repo,
            auth_config,
            refresh_token_lifetime_secs,
            verification_uri,
            scope_policy: crate::scope_ceiling::unwired(),
        }
    }

    /// Install the tenant scope policy (#613). Until one is installed an
    /// externally registered client's device authorization is refused with
    /// `server_error`; an administrator's client never reads it.
    #[must_use]
    pub fn with_scope_policy(mut self, policy: crate::scope_ceiling::SharedScopePolicy) -> Self {
        self.scope_policy = policy;
        self
    }

    /// RFC 8628 §3.1–3.2 — issue a device code and a user code.
    ///
    /// `client` is the client the token service authenticated at this
    /// endpoint (#635): by its registered method, so a public client — a TV
    /// cannot keep a secret — by presenting nothing, and a confidential one by
    /// its credential (RFC 8628 §3.1 applies RFC 6749 §3.2.1 here); in a
    /// tenant that is still live (#641 (a)); holding this grant. Without the
    /// last two any string could mint a pending grant and consume the
    /// user-code space.
    pub async fn authorize(
        &self,
        tenant_id: Uuid,
        client: DeviceClient,
        req: DeviceAuthorizationRequest,
    ) -> Result<DeviceAuthorizationResponse, OAuth2Error> {
        // #613 (T-289) — for an externally registered client, "what the client
        // is registered for" is bounded by the tenant's current
        // `dcr_allowed_scopes`. No read for an administrator's client.
        let mut client = client.client;
        crate::scope_ceiling::apply_to_client(self.scope_policy.as_ref(), &mut client).await?;

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

        // T21.3 / RFC 8707 §2 — validated before a grant exists, so a device
        // naming a resource this client may not address never receives a
        // user code to display or a device code to poll with.
        let resource =
            crate::resource::resolve_requested(&client.allowed_resources, req.resource.as_deref())?;

        let device_code = generate_device_code();
        let user_code_display = generate_user_code();
        // Stored normalised, because that is the form every lookup uses.
        let user_code = normalize_user_code(&user_code_display);

        self.device_repo
            .create(CreateDeviceGrant {
                tenant_id,
                client_id: client.client_id,
                device_code_hash: hash_device_code(&device_code),
                user_code: user_code.clone(),
                scopes,
                expires_at: Utc::now() + Duration::seconds(DEFAULT_EXPIRES_IN_SECS as i64),
                interval_secs: DEFAULT_INTERVAL_SECS,
                resource,
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

    /// The config the device grant's access token is signed under (T21.6).
    ///
    /// See `TokenService::minting_config`.
    fn minting_config<'a>(&'a self, issuer: Option<&str>) -> std::borrow::Cow<'a, AuthConfig> {
        match issuer {
            None => std::borrow::Cow::Borrowed(&self.auth_config),
            Some(issuer) => std::borrow::Cow::Owned(AuthConfig {
                request_issuer: Some(issuer.to_owned()),
                ..self.auth_config.clone()
            }),
        }
    }

    /// RFC 8628 §3.4–3.5 — the device polls with its `device_code`.
    ///
    /// `client` is the client the token service authenticated on this request
    /// (#635) — see the module documentation. `issuer` is `None` for
    /// `/oauth2/token` and `Some("{root}/t/{tenant}")` for the per-tenant path
    /// (T21.6); it decides the `iss` of the minted access token and nothing
    /// else.
    ///
    /// # Order, and what each step may write
    ///
    /// 1. The grant is read by the device code's hash, in this tenant. A grant
    ///    issued to **another client** is `invalid_grant`, the answer an
    ///    unknown code gets, and nothing has been written for it: a caller
    ///    that holds a leaked device code and authenticates as some client it
    ///    controls neither learns the grant's state nor records a poll that
    ///    would `slow_down` the real device. (A wrong credential for the
    ///    grant's own client never got this far.)
    /// 2. Only now is the poll recorded, and the interval enforced **before**
    ///    the state is examined: a device hammering the endpoint gets
    ///    `slow_down` whatever its grant's state, so the corrective signal is
    ///    not something it can outrun by being in a lucky state.
    /// 3. Expired → `expired_token`; a `resource` that does not repeat the
    ///    grant's → `invalid_target`; then pending, denied and redeemed.
    /// 4. Approved → redeemed atomically; the subject is re-read after the
    ///    approval is spent; tokens are minted bound by the `cnf` the client's
    ///    registration asked for.
    ///
    /// `resource` is RFC 8707's parameter on the token request (T21.3). The
    /// device already named its target when it started the flow, so the only
    /// thing a poll may do with the parameter is **repeat it**: a poll that
    /// names a different resource — or names one at all when the grant is
    /// bound to none — is `invalid_target`. See
    /// [`crate::resource::resolve_bound`] for why a grant's audience is
    /// decided when the grant is made and never at redemption.
    pub async fn poll_at(
        &self,
        tenant_id: Uuid,
        client: &DeviceClient,
        device_code: &str,
        resource: Option<&str>,
        issuer: Option<&str>,
    ) -> Result<TokenResponse, OAuth2Error> {
        let hash = hash_device_code(device_code);

        let grant = self
            .device_repo
            .get_by_device_code_hash(tenant_id, &hash)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?
            // An unknown device code, an already-redeemed one and another
            // client's are all `invalid_grant`. They are genuinely the same
            // answer: in each case this code will never produce a token for
            // this caller, and distinguishing them would tell a caller which
            // codes have existed.
            .filter(|g| g.client_id == client.client_id())
            .ok_or_else(|| OAuth2Error::InvalidGrant("unknown device code".into()))?;

        let (_interval, too_fast) = self
            .device_repo
            .record_poll(tenant_id, &hash)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
        if too_fast {
            return Err(OAuth2Error::SlowDown);
        }

        if grant.expires_at <= Utc::now() {
            return Err(OAuth2Error::ExpiredToken);
        }

        // RFC 8707 §2 — checked here, before the status is examined and long
        // before the code is redeemed. A device that mis-sends the parameter
        // gets the actionable answer on its first poll instead of an hour of
        // `authorization_pending` followed by a refusal that has already spent
        // the user's approval. There is no oracle in answering early: the
        // caller holds the device code and authenticated as its client, so it
        // is the device, and the value it is being told about is the one it
        // sent itself at `/oauth2/device_authorization`.
        let _ = crate::resource::resolve_bound(grant.resource.as_deref(), resource)?;

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

        // The tenant is not read here any more (#635, #641 (b)): the client's
        // authentication read it, found it live, and handed over its
        // organization. A tombstoned tenant is therefore the `invalid_client`
        // every other grant answers, decided before the grant is touched,
        // where this read used to answer `server_error` after the approval was
        // spent.
        //
        // The subject is re-read after the approval is spent, and asked the
        // same question every other grant asks (R1W1-06 / #604): may this
        // account act, and is it free of brute-force lockout? A user
        // suspended, deleted or locked out between the approval and the
        // device's next poll gets `invalid_grant` and nothing is minted; the
        // grant is already `Redeemed`, so the next poll is refused too. The
        // predicate is CIBA's (`crate::ciba::user_may_be_subject`), shared
        // rather than copied so the two backchannel-style grants cannot drift.
        let refused = || {
            OAuth2Error::InvalidGrant(
                "the account this grant was issued for can no longer sign in".into(),
            )
        };
        let user = match self.user_repo.get_by_id(tenant_id, user_id).await {
            Ok(user) => user,
            Err(AxiamError::NotFound { .. }) => return Err(refused()),
            Err(e) => return Err(OAuth2Error::ServerError(e.to_string())),
        };
        if !crate::ciba::user_may_be_subject(&user) {
            tracing::info!(
                %tenant_id,
                %user_id,
                "refusing a device-grant redemption: the account may no longer sign in or is locked out"
            );
            return Err(refused());
        }

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
                requested_userinfo_claims: Vec::new(),
                // RFC 8707 — the grant's target travels onto the refresh
                // token, so a device that refreshes keeps the same audience
                // and cannot acquire a different one (see
                // `crate::resource::resolve_bound`).
                resource: redeemed.resource.clone(),
                // X7.2 / D-9 — no browser authentication happened here, so
                // there is no evidence to snapshot (and a device-grant ID
                // token has never carried any).
                auth_time: None,
                acr: None,
                amr: Vec::new(),
                // #681 / RFC 9449 §5 — a public DPoP-bound device's refresh
                // token is bound to the key its poll proved; `None` for every
                // other client.
                dpop_jkt: crate::dpop::refresh_token_binding(&client.client, client.cnf.as_ref()),
                expires_at: Utc::now() + Duration::seconds(self.refresh_token_lifetime_secs),
            })
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        // RFC 8707 §2 — the audience is the resource the device named when it
        // started the flow, or `axiam:user` when it named none. `AUD_USER` is
        // what every device grant minted before T21.3 and what every grant
        // that sends no `resource` still mints, byte for byte (I2).
        let audience = redeemed.resource.as_deref().unwrap_or(AUD_USER);
        // #635 — the binding the client's registration asks for, decided by
        // the token service from this request's certificate and DPoP proof
        // (`TokenService::certificate_binding_for`, as for every other grant).
        // `None` for a client that asked for none, which mints exactly the
        // token this grant always minted. Read before `cnf` is moved: RFC 9449
        // §5 announces a DPoP-bound token as such.
        let token_type = crate::dpop::token_type_for(client.cnf.as_ref());
        // #681 (R110W3-08) — RFC 9068 §2.2's `client_id`, as the CIBA grant
        // names its client: the device the user approved is the party this
        // token was granted to. It is what the approval surfaces read to
        // refuse a client's token (T-447, `minted_for_client`), so a device
        // token is refused there for what it is, not for the session it
        // lacks. And no `sid`: the approval happened in another browser, and
        // there is no session of the device's for the claim to name.
        let access_token = AccessTokenSpec::user(
            user.id,
            tenant_id,
            client.organization_id,
            Uuid::new_v4().to_string(),
        )
        .aud(audience)
        .scopes(&redeemed.scopes)
        .cnf(client.cnf.clone())
        .client_id(Some(client.client_id()))
        .issue(&self.minting_config(issuer))
        .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        let scope = if redeemed.scopes.is_empty() {
            None
        } else {
            Some(redeemed.scopes.join(" "))
        };

        Ok(TokenResponse {
            access_token,
            token_type,
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
