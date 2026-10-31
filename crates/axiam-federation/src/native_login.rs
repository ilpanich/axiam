//! G-A — a provider-issued **ID token**, presented by a native app, verified
//! as a sign-in.
//!
//! Design: `claude_dev/social-login-gap-plan-2026-10-30.md` §3.1. The rule
//! every function here applies:
//!
//! > **An ID token is accepted as a sign-in only when it was issued to us.**
//!
//! "Us" is one of the client IDs an operator listed in the provider's
//! `native_login.client_ids` for exactly this purpose — not the provider's web
//! `client_id` unless it is listed, and never "any audience". The party a
//! token was issued to is its `azp` when it carries one, otherwise its single
//! `aud` (D-N17, see [`issued_to`]).
//!
//! This module answers one question: *which AXIAM user does this ID token
//! prove signed in, through which provider?* The grant that turns the answer
//! into a token set lives in `axiam-oauth2` (W2.3).
//!
//! # The order is the design
//!
//! [`OidcFederationService::verify_native_id_token`] runs these steps in this
//! order, each before the next (step 1, client authentication and the grant
//! gate, is the token endpoint's):
//!
//! 2. **Provider**: the request's `provider` (UUID or `provider_slug`) names
//!    an *effective* provider of the requesting tenant — its own, or inherited
//!    from its organization, exactly as the browser login's provider listing
//!    resolves it ([`crate::provider_resolution`]) — that is enabled, speaks
//!    OIDC and has `native_login.enabled`. A provider of another tenant is not
//!    found.
//! 3. **Header**: `alg=none` refused on the raw header, `alg` within the
//!    provider's `allowed_algorithms`, `kid` resolved through the JWKS cache
//!    with its rate-limited rollover refetch — no new fetch surface.
//! 4. **Signature and claims**, through the browser login's own verification
//!    core: `iss` exactly the discovered issuer; the token issued to a listed
//!    client ID, **azp-first** (D-N17): a listed `azp`, with `aud` (string or
//!    array) containing a listed ID or the provider's web `client_id` — the
//!    shape of Google's Android tokens — or, with no `azp`, a single listed
//!    `aud` (several audiences need an `azp`, OIDC Core §3.1.3.7); `exp` in
//!    the future within the 60 s leeway (D-05); `iat` neither older than
//!    `max_token_age_secs` nor in the future beyond the leeway.
//! 5. **Shape**: an ID token and nothing else — `nonce` present and equal, in
//!    constant time, to the lower-case SHA-256 hex of the request's nonce
//!    (D-N16; the app gives the provider SDK the hash and AXIAM the raw
//!    value); an access-token `typ` (`at+jwt`) refused. The marker list is
//!    [`crate::token_shape`]'s, the same one X4 refuses by.
//! 6. **Replay**: the token's SHA-256 recorded in the replay store, until `exp`
//!    plus the leeway; a second presentation is refused, and a store that
//!    cannot record refuses too.
//! 7. **Subject**: the browser login's resolution, unchanged —
//!    `map_identity(provider_kind, attribute_map, claims)` and then
//!    `provision_or_link_identity`, provisioning on first sign-in, adopting no
//!    email as verified; then `account_may_act`.
//!
//! # Why the replay guard sits where it does
//!
//! The store is keyed on the SHA-256 of the token's exact bytes, and a row is
//! written only once steps 2–5 have all passed:
//!
//! * **Not before the signature (step 4).** Then anyone could write rows: a
//!   stream of garbage tokens would fill the table. A forged token can never
//!   take a genuine token's slot either way — its bytes, and so its hash,
//!   differ — but only a verified token, one the provider really issued to a
//!   listed client ID, is ever recorded.
//! * **Not before the nonce (step 5).** Then someone who obtained a victim's
//!   genuine token without the nonce it is bound to (from a log, a proxy, a
//!   crash report) could present it, fail the nonce check *after* burning its
//!   hash, and turn the victim's own sign-in into a "replay". Recorded after
//!   step 5, only a presenter holding both the token and its raw nonce — the
//!   app that started the sign-in — can spend it. That holds because the
//!   token carries only the nonce's SHA-256 (D-N16): the claim a token holder
//!   can read from the payload is not the value the request must carry. When
//!   the claim itself was accepted too, copying it passed (F4-W2-02).
//! * **Not after subject resolution (step 7).** Then two concurrent
//!   presentations would both resolve, and both sign in, before either
//!   recorded. The insert is the one atomic decision (a UNIQUE index), placed
//!   after everything that proves the presentation genuine and before anything
//!   that acts on it.
//!
//! # What the caller learns
//!
//! Every refusal past step 2 is one generic answer on the wire (the X4 rule:
//! a wrong token and a wrong configuration are told apart only in the server
//! log); [`NativeLoginError`] keeps the distinctions for logs, audit and tests.
//! The raw token is never logged, never stored, never returned.

use axiam_core::error::AxiamError;
use axiam_core::models::federation::{FederationConfig, FederationProtocol, ProviderKind};
use axiam_core::models::federation_claims::map_identity;
use axiam_core::repository::{
    FederationConfigRepository, FederationLinkRepository, ProviderIdTokenReplayRepository,
    TenantRepository, UserRepository,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::error::FederationError;
use crate::oidc::{
    CLOCK_SKEW_LEEWAY_SECS, IdTokenCheckError, OidcFederationService, upstream_instant,
};
use crate::provider_resolution::effective_providers;
use crate::token_exchange::flatten_audience;
use crate::token_shape;

/// The one description a client is given for any refusal (OAuth2
/// `invalid_grant`). Deliberately says nothing about which check failed.
pub const PUBLIC_REFUSAL_DESCRIPTION: &str = "the provider ID token is not acceptable";

/// The ID-token marker this path requires. It is the first of the shared
/// list X4 refuses by; [`tests::native_requires_a_marker_x4_refuses`] holds
/// the two together.
const REQUIRED_MARKER: &str = "nonce";

/// A native sign-in request, as the token endpoint received it.
///
/// Holds the token by reference only; nothing here is retained.
#[derive(Clone, Copy)]
pub struct NativeIdTokenRequest<'a> {
    /// The provider: its UUID, or its `provider_slug`.
    pub provider: &'a str,
    /// The ID token the provider issued to the app.
    pub id_token: &'a str,
    /// The raw nonce the app generated. The provider's SDK was given its
    /// lower-case SHA-256 hex, which is what the token's `nonce` claim holds.
    pub nonce: &'a str,
}

impl std::fmt::Debug for NativeIdTokenRequest<'_> {
    // Never the token, never the nonce.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeIdTokenRequest")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

/// What a verified native sign-in established. Sibling of
/// [`crate::token_exchange::ExternalSubject`]. Carries no token.
#[derive(Debug, Clone)]
pub struct NativeSubject {
    /// The AXIAM user signed in, in the requesting tenant.
    pub user_id: Uuid,
    /// The requesting tenant — where the user lives.
    pub tenant_id: Uuid,
    /// The federation provider that issued the ID token.
    pub provider_id: Uuid,
    /// The tenant that owns the provider: the requesting tenant, or its
    /// organization tenant when the provider is inherited.
    pub provider_tenant_id: Uuid,
    /// Whether the provider is inherited from the organization.
    pub inherited: bool,
    /// The provider's display name, for the audit record.
    pub provider_name: String,
    /// The provider's kind, for the audit record.
    pub provider_kind: ProviderKind,
    /// The verified issuer, exactly as the token spelled it.
    pub issuer: String,
    /// The provider-local subject the user was resolved from (after the
    /// provider's `attribute_map`). Audit only.
    pub external_subject: String,
    /// The listed client ID the token was issued to: its `azp` when it carries
    /// one, otherwise its single `aud`.
    pub audience: String,
    /// True when this sign-in created the AXIAM user.
    pub newly_provisioned: bool,
    /// When the provider says the user authenticated (`auth_time`), if it did
    /// and the value is a date (X7.2). `None` means: use the moment of
    /// verification.
    pub upstream_auth_time: Option<chrono::DateTime<chrono::Utc>>,
    /// The ID token's `exp`, as a NumericDate.
    pub id_token_exp: i64,
}

/// What the token endpoint answers for a [`NativeLoginError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeLoginRefusal {
    /// `invalid_grant` with [`PUBLIC_REFUSAL_DESCRIPTION`] — every refusal
    /// about the token or the configuration.
    InvalidGrant,
    /// `server_error` — the datastore failed, including a replay store that
    /// could not record (which must not accept).
    ServerError,
}

/// Why a native sign-in was refused.
///
/// The variants are for the server log, the audit record and the tests; the
/// wire sees only [`NativeLoginError::refusal`]. No variant carries the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeLoginError {
    /// Step 2: no effective, enabled, OIDC, native-login-enabled provider of
    /// this tenant is named by the request (unknown, another tenant's,
    /// disabled, SAML, OAuth2, native login off, or an unusable block).
    ProviderNotFound,
    /// Step 2: the provider's discovery document could not be read.
    ProviderUnavailable(String),
    /// Step 3: `alg` is `none` or not in the provider's `allowed_algorithms`.
    AlgorithmRefused,
    /// Step 3: no JWKS key matches the `kid`, after one rollover refetch.
    UnknownKey,
    /// Step 3: the provider's JWKS could not be fetched.
    KeysUnavailable(String),
    /// Step 4: the signature does not verify, or the token is not a JWS.
    BadSignature,
    /// Step 4: `iss` is not the provider's discovered issuer.
    WrongIssuer,
    /// Step 4: with no `azp`, the single `aud` is not listed; with a listed
    /// `azp`, `aud` names neither a listed ID nor the provider's web
    /// `client_id`.
    WrongAudience,
    /// Step 4: the `azp` is present and not listed (or not a string), or `aud`
    /// has several members and there is no `azp`.
    AuthorizedPartyRefused,
    /// Step 4: `exp` has passed, beyond the leeway.
    Expired,
    /// Step 4: `iat` is older than the provider's `max_token_age_secs`.
    TooOld,
    /// Step 4: `iat` is in the future beyond the leeway.
    IssuedInFuture,
    /// Step 4: another claim was refused (missing, malformed, empty `sub`).
    ClaimRejected(String),
    /// Step 5: the token has an access-token or refresh/logout `typ`.
    WrongTokenShape(String),
    /// Step 5: the token has no `nonce` — it is not an ID token from a flow
    /// the app bound to a nonce.
    NonceMissing,
    /// Step 5: the `nonce` is not the SHA-256 hex of the request's nonce
    /// (a claim equal to the request's value unhashed included), or the
    /// request carried none.
    NonceMismatch,
    /// Step 6: this token was presented before.
    Replayed,
    /// Step 6: the replay store could not record the token, so it is refused.
    ReplayGuardUnavailable(String),
    /// Step 7: the provider's attribute map yields no external subject.
    SubjectUnmapped,
    /// Step 7: the account may not act (locked, inactive, anonymized,
    /// deleted); the text is `account_may_act`'s.
    AccountRefused(String),
    /// A datastore failure outside the replay store.
    Server(String),
}

impl std::fmt::Display for NativeLoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProviderNotFound => write!(
                f,
                "no enabled OIDC provider with native sign-in is named by the request in this tenant"
            ),
            Self::ProviderUnavailable(m) => write!(f, "provider discovery failed: {m}"),
            Self::AlgorithmRefused => write!(f, "the token's algorithm is not accepted"),
            Self::UnknownKey => write!(f, "no provider key matches the token's kid"),
            Self::KeysUnavailable(m) => write!(f, "the provider's JWKS is unavailable: {m}"),
            Self::BadSignature => write!(f, "the token's signature does not verify"),
            Self::WrongIssuer => write!(f, "the token's issuer is not the provider's"),
            Self::WrongAudience => {
                write!(
                    f,
                    "the token was not issued to a native client ID of the provider"
                )
            }
            Self::AuthorizedPartyRefused => write!(
                f,
                "the token's azp is not a native client ID, or it has several audiences and no azp"
            ),
            Self::Expired => write!(f, "the token has expired"),
            Self::TooOld => write!(
                f,
                "the token was issued longer ago than the provider allows"
            ),
            Self::IssuedInFuture => write!(f, "the token is issued in the future beyond the skew"),
            Self::ClaimRejected(m) => write!(f, "a claim was refused: {m}"),
            Self::WrongTokenShape(t) => {
                write!(f, "the token's type '{t}' is not an ID token")
            }
            Self::NonceMissing => write!(f, "the token carries no nonce"),
            Self::NonceMismatch => write!(f, "the token's nonce does not match the request"),
            Self::Replayed => write!(f, "the token was presented before"),
            Self::ReplayGuardUnavailable(m) => {
                write!(f, "the replay store could not record the token: {m}")
            }
            Self::SubjectUnmapped => {
                write!(f, "no external subject could be mapped from the token")
            }
            Self::AccountRefused(m) => write!(f, "the account may not sign in: {m}"),
            Self::Server(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for NativeLoginError {}

impl NativeLoginError {
    /// What the wire sees. Everything about the token or the configuration
    /// is one `invalid_grant`; only a datastore failure is `server_error`.
    pub const fn refusal(&self) -> NativeLoginRefusal {
        match self {
            Self::ReplayGuardUnavailable(_) | Self::Server(_) => NativeLoginRefusal::ServerError,
            _ => NativeLoginRefusal::InvalidGrant,
        }
    }

    /// A stable, low-cardinality label for the audit record and metrics.
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::ProviderNotFound => "provider_not_found",
            Self::ProviderUnavailable(_) => "provider_unavailable",
            Self::AlgorithmRefused => "algorithm_refused",
            Self::UnknownKey => "unknown_key",
            Self::KeysUnavailable(_) => "keys_unavailable",
            Self::BadSignature => "bad_signature",
            Self::WrongIssuer => "wrong_issuer",
            Self::WrongAudience => "wrong_audience",
            Self::AuthorizedPartyRefused => "azp_refused",
            Self::Expired => "expired",
            Self::TooOld => "too_old",
            Self::IssuedInFuture => "issued_in_future",
            Self::ClaimRejected(_) => "claim_rejected",
            Self::WrongTokenShape(_) => "wrong_token_shape",
            Self::NonceMissing => "nonce_missing",
            Self::NonceMismatch => "nonce_mismatch",
            Self::Replayed => "replayed",
            Self::ReplayGuardUnavailable(_) => "replay_guard_unavailable",
            Self::SubjectUnmapped => "subject_unmapped",
            Self::AccountRefused(_) => "account_refused",
            Self::Server(_) => "server_error",
        }
    }

    /// Map a refusal of the shared verification core (steps 3 and 4).
    fn from_check(e: IdTokenCheckError) -> Self {
        use jsonwebtoken::errors::ErrorKind;
        match e {
            IdTokenCheckError::Federation(f) => match f {
                FederationError::AlgorithmNotAllowed(_) => Self::AlgorithmRefused,
                FederationError::JwtSignatureInvalid => Self::BadSignature,
                FederationError::JwksKidUnknown => Self::UnknownKey,
                FederationError::JwksFetchFailed(m) => Self::KeysUnavailable(m),
                other => Self::ClaimRejected(other.to_string()),
            },
            IdTokenCheckError::Claims(e) => match e.kind() {
                ErrorKind::InvalidIssuer => Self::WrongIssuer,
                ErrorKind::InvalidAudience => Self::WrongAudience,
                ErrorKind::ExpiredSignature => Self::Expired,
                other => Self::ClaimRejected(format!("{other:?}")),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Lowercase hex SHA-256 — the replay key of a token, and the nonce form the
/// token must carry (D-N16).
fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// Step 2's provider filter: what a provider must be to accept native sign-in
/// at all, independent of how the request named it.
fn accepts_native_login(config: &FederationConfig) -> bool {
    config.enabled
        && config.protocol == FederationProtocol::OidcConnect
        && config.native_login.enabled
        && config
            .native_login
            .validate_for_protocol(config.protocol)
            .is_ok()
}

/// Step 2's name match: the provider's UUID, or its `provider_slug`.
fn names(config: &FederationConfig, provider: &str) -> bool {
    match Uuid::parse_str(provider) {
        Ok(id) => config.id == id,
        Err(_) => config.provider_slug.as_deref() == Some(provider),
    }
}

/// Step 4's audience rule beyond the decoder's: which listed client ID the
/// token was issued to — **azp-first** (D-N17, F4-W2-03).
///
/// * With an `azp`, the `azp` is the party the token was issued to (OIDC Core
///   §2), so it must be listed. `aud` must then contain a listed ID or the
///   provider's own web `client_id`: Google issues an Android app's token
///   for the *server* client it asks for, so `aud` is the web client and
///   `azp` the Android client. A token for some third party that merely
///   carries one of our IDs in `aud` has a foreign `azp`, and is refused.
/// * Without an `azp`, `aud` must be one listed value (an iOS token without a
///   server client). Several audiences need an `azp` (OIDC Core §3.1.3.7).
///
/// So a browser-flow token — `aud` the web client, `azp` the web client or
/// absent — is refused unless the operator lists the web client, which
/// admits exactly those tokens and which the docs advise against.
///
/// `web_client_id` is the provider's configured `client_id`; empty means
/// none, and matches nothing.
fn issued_to(
    client_ids: &[String],
    web_client_id: &str,
    aud: Option<&serde_json::Value>,
    azp: Option<&serde_json::Value>,
) -> Result<String, NativeLoginError> {
    let audiences = flatten_audience(aud);
    let listed = |v: &str| client_ids.iter().any(|c| c == v);
    if audiences.is_empty() {
        return Err(NativeLoginError::WrongAudience);
    }
    match azp {
        Some(azp) => {
            let azp = azp
                .as_str()
                .filter(|azp| listed(azp))
                .ok_or(NativeLoginError::AuthorizedPartyRefused)?;
            let addressed = audiences
                .iter()
                .any(|a| listed(a) || (!web_client_id.is_empty() && a == web_client_id));
            if addressed {
                Ok(azp.to_owned())
            } else {
                Err(NativeLoginError::WrongAudience)
            }
        }
        None => match audiences.as_slice() {
            [one] if listed(one) => Ok(one.clone()),
            [_] => Err(NativeLoginError::WrongAudience),
            _ => Err(NativeLoginError::AuthorizedPartyRefused),
        },
    }
}

/// Step 4's age rule: `iat` neither in the future beyond the leeway nor older
/// than the provider allows. The bound is inclusive.
fn check_iat(iat: Option<u64>, now: i64, max_age_secs: i64) -> Result<(), NativeLoginError> {
    let iat = iat
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(|| NativeLoginError::ClaimRejected("no usable 'iat'".into()))?;
    if iat > now + CLOCK_SKEW_LEEWAY_SECS as i64 {
        return Err(NativeLoginError::IssuedInFuture);
    }
    if now - iat > max_age_secs {
        return Err(NativeLoginError::TooOld);
    }
    Ok(())
}

/// Step 5: the token is an ID token bound to this request's nonce.
///
/// `typ` (header or claim) must not name an access, refresh or logout token;
/// `nonce` must be present and equal, in constant time, to the lower-case
/// SHA-256 hex of the request nonce (D-N16, F4-W2-02). The raw form — a claim
/// equal to the request's value — is **not** accepted: a JWT payload is
/// readable by whoever holds the token, so accepting the claim itself would
/// let a token's holder copy it into the request. With the hashed form the
/// value to present is a SHA-256 preimage of what the token carries.
fn check_shape(
    header_typ: Option<&str>,
    raw: &serde_json::Value,
    request_nonce: &str,
) -> Result<(), NativeLoginError> {
    let claim_typ = raw.get("typ").and_then(serde_json::Value::as_str);
    for typ in [header_typ, claim_typ].into_iter().flatten() {
        let normalized = token_shape::normalize_typ(typ);
        if token_shape::refused_as_native_id_token(&normalized) {
            return Err(NativeLoginError::WrongTokenShape(normalized));
        }
    }

    let Some(token_nonce) = raw.get(REQUIRED_MARKER).and_then(serde_json::Value::as_str) else {
        return Err(NativeLoginError::NonceMissing);
    };
    if request_nonce.is_empty() || token_nonce.is_empty() {
        return Err(NativeLoginError::NonceMismatch);
    }
    let hashed = sha256_hex(request_nonce);
    if bool::from(token_nonce.as_bytes().ct_eq(hashed.as_bytes())) {
        Ok(())
    } else {
        Err(NativeLoginError::NonceMismatch)
    }
}

// ---------------------------------------------------------------------------
// The service method
// ---------------------------------------------------------------------------

impl<FC, FL, UR> OidcFederationService<FC, FL, UR>
where
    FC: FederationConfigRepository,
    FL: FederationLinkRepository,
    UR: UserRepository,
{
    /// Verify a provider-issued ID token presented for native sign-in into
    /// `tenant_id`, and resolve the AXIAM user it signs in.
    ///
    /// Runs §3.1 steps 2–7 in order (see the module documentation). `now` is
    /// the caller's clock in seconds since the epoch, used for the `iat`
    /// rules; `exp` is checked by the decoder against the system clock with
    /// the same 60 s leeway the browser login uses.
    ///
    /// The caller (W2.3) has authenticated the client and checked that it may
    /// use the grant; it maps every error through
    /// [`NativeLoginError::refusal`] and records
    /// [`NativeLoginError::reason_code`] in the audit trail.
    ///
    /// # Errors
    ///
    /// [`NativeLoginError`], one variant per refused check.
    pub async fn verify_native_id_token<TR, RR>(
        &self,
        tenants: &TR,
        replay: &RR,
        tenant_id: Uuid,
        request: &NativeIdTokenRequest<'_>,
        now: i64,
    ) -> Result<NativeSubject, NativeLoginError>
    where
        TR: TenantRepository,
        RR: ProviderIdTokenReplayRepository,
    {
        let result = self
            .verify_native_id_token_inner(tenants, replay, tenant_id, request, now)
            .await;
        if let Err(ref e) = result {
            // The reason, never the token. Configuration problems at warn so an
            // operator sees them; token problems at debug, because a stream of
            // bad tokens is a client's bug or an attack and not actionable here.
            match e {
                NativeLoginError::ProviderUnavailable(_)
                | NativeLoginError::KeysUnavailable(_)
                | NativeLoginError::ReplayGuardUnavailable(_)
                | NativeLoginError::Server(_) => warn!(
                    tenant_id = %tenant_id,
                    reason = e.reason_code(),
                    detail = %e,
                    "native sign-in refused"
                ),
                _ => debug!(
                    tenant_id = %tenant_id,
                    reason = e.reason_code(),
                    detail = %e,
                    "native sign-in refused"
                ),
            }
        }
        result
    }

    async fn verify_native_id_token_inner<TR, RR>(
        &self,
        tenants: &TR,
        replay: &RR,
        tenant_id: Uuid,
        request: &NativeIdTokenRequest<'_>,
        now: i64,
    ) -> Result<NativeSubject, NativeLoginError>
    where
        TR: TenantRepository,
        RR: ProviderIdTokenReplayRepository,
    {
        // --- 2. Which provider? ---------------------------------------------
        let (config, inherited) = self
            .resolve_native_provider(tenants, tenant_id, request.provider)
            .await?;
        let trust = &config.native_login;
        let metadata_url = config.metadata_url.as_deref().ok_or_else(|| {
            NativeLoginError::ProviderUnavailable("no metadata URL configured".into())
        })?;
        let discovery = self
            .discover(metadata_url)
            .await
            .map_err(|e| NativeLoginError::ProviderUnavailable(e.to_string()))?;

        // --- 3 and 4. Header, key, signature, iss, aud, exp ------------------
        // The browser login's verification core, with the native client IDs
        // and the provider's web `client_id` as the audiences the decoder
        // admits, and the same JWKS cache key, so the two share one rollover
        // state for this provider. The web client is admitted here only so a
        // token addressed to it can reach `issued_to`, which accepts it solely
        // as the `aud` of a token whose `azp` is listed (D-N17).
        let mut audiences: Vec<&str> = trust.client_ids.iter().map(String::as_str).collect();
        if !config.client_id.is_empty() && !audiences.contains(&config.client_id.as_str()) {
            audiences.push(config.client_id.as_str());
        }
        let checked = self
            .verify_id_token_core(
                request.id_token,
                &discovery,
                &audiences,
                &config.allowed_algorithms,
                &config.allowed_issuer_tenants,
                (config.tenant_id, config.id),
            )
            .await
            .map_err(NativeLoginError::from_check)?;
        let claims = &checked.verified.claims;
        let raw = &checked.verified.raw;

        let audience = issued_to(
            &trust.client_ids,
            &config.client_id,
            claims.aud.as_ref(),
            raw.get("azp"),
        )?;
        check_iat(claims.iat, now, trust.max_token_age_secs)?;
        let id_token_exp = claims
            .exp
            .and_then(|v| i64::try_from(v).ok())
            .ok_or_else(|| NativeLoginError::ClaimRejected("no usable 'exp'".into()))?;
        if claims.sub.trim().is_empty() {
            return Err(NativeLoginError::ClaimRejected("empty 'sub'".into()));
        }
        let issuer = claims
            .iss
            .clone()
            .ok_or_else(|| NativeLoginError::ClaimRejected("no 'iss'".into()))?;

        // --- 5. Shape: an ID token, bound to this request's nonce ------------
        check_shape(checked.header.typ.as_deref(), raw, request.nonce)?;

        // --- 6. Replay: spend the token, once --------------------------------
        // After the signature (a forged token records nothing) and before the
        // subject (two concurrent presentations cannot both resolve). Keyed on
        // the provider's own tenant, so an inherited provider's token is spent
        // once across the organization rather than once per tenant.
        let expires_at = chrono::DateTime::<chrono::Utc>::from_timestamp(
            id_token_exp.saturating_add(CLOCK_SKEW_LEEWAY_SECS as i64),
            0,
        )
        .ok_or_else(|| NativeLoginError::ClaimRejected("'exp' is not a date".into()))?;
        match replay
            .insert_id_token(
                config.tenant_id,
                config.id,
                &sha256_hex(request.id_token),
                expires_at,
            )
            .await
        {
            Ok(()) => {}
            Err(AxiamError::ReplayDetected) => return Err(NativeLoginError::Replayed),
            // A guard that cannot record must not accept: the token would be
            // single-use only while the datastore is up (the CIBA rule).
            Err(e) => return Err(NativeLoginError::ReplayGuardUnavailable(e.to_string())),
        }

        // --- 7. Which AXIAM user? --------------------------------------------
        // Exactly the browser login's resolution (D-N11): the provider's
        // attribute map over the verified claims, then the same link-or-
        // provision function. A native sign-in and a browser login with the
        // same claims are the same user.
        let identity = map_identity(config.provider_kind, &config.attribute_map, raw)
            .ok_or(NativeLoginError::SubjectUnmapped)?;
        let resolved = self
            .provision_or_link_identity(tenant_id, config.id, &identity)
            .await
            .map_err(|e| NativeLoginError::Server(e.to_string()))?;
        axiam_auth::service::account_may_act(&resolved.user)
            .map_err(|e| NativeLoginError::AccountRefused(e.to_string()))?;

        if resolved.newly_provisioned {
            info!(
                target: "axiam::audit",
                event = "federation.jit_provision",
                tenant_id = %tenant_id,
                provider = %config.provider,
                user_id = %resolved.user.id,
                source = "native_login",
                "JIT-provisioned an AXIAM user from a native sign-in"
            );
        }

        Ok(NativeSubject {
            user_id: resolved.user.id,
            tenant_id,
            provider_id: config.id,
            provider_tenant_id: config.tenant_id,
            inherited,
            provider_name: config.provider.clone(),
            provider_kind: config.provider_kind,
            issuer,
            external_subject: identity.external_subject,
            audience,
            newly_provisioned: resolved.newly_provisioned,
            upstream_auth_time: upstream_instant(claims.auth_time),
            id_token_exp,
        })
    }

    /// Step 2: the effective provider the request names, re-read in full from
    /// the tenant that owns it, as the browser login does.
    async fn resolve_native_provider<TR: TenantRepository>(
        &self,
        tenants: &TR,
        tenant_id: Uuid,
        provider: &str,
    ) -> Result<(FederationConfig, bool), NativeLoginError> {
        let provider = provider.trim();
        if provider.is_empty() {
            return Err(NativeLoginError::ProviderNotFound);
        }
        let tenant = tenants.get_by_id(tenant_id).await.map_err(|e| match e {
            AxiamError::NotFound { .. } => NativeLoginError::ProviderNotFound,
            other => NativeLoginError::Server(other.to_string()),
        })?;
        let effective = effective_providers(
            self.federation_config_repo_ref(),
            tenants,
            tenant.organization_id,
            tenant_id,
        )
        .await
        .map_err(|e| NativeLoginError::Server(e.to_string()))?;

        let mut matching = effective
            .into_iter()
            .filter(|p| accepts_native_login(&p.config) && names(&p.config, provider));
        let found = matching.next().ok_or(NativeLoginError::ProviderNotFound)?;
        // Two effective providers sharing a slug (an OIDC and an OAuth2
        // generic one, say, of which only one could match here — or a
        // misconfiguration) must not be resolved by list order.
        if matching.next().is_some() {
            return Err(NativeLoginError::ProviderNotFound);
        }

        let full = self
            .federation_config_repo_ref()
            .get_by_id(found.config.tenant_id, found.config.id)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { .. } => NativeLoginError::ProviderNotFound,
                other => NativeLoginError::Server(other.to_string()),
            })?;
        // The listing and the row are read apart; the row decides.
        if !accepts_native_login(&full) {
            return Err(NativeLoginError::ProviderNotFound);
        }
        Ok((full, found.inherited))
    }
}

#[cfg(test)]
mod tests;
