//! JWT access token issuance/verification and opaque refresh token
//! generation.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use axiam_core::models::uma::RptPermission;

use crate::config::AuthConfig;
use crate::error::AuthError;

/// Audience value for user-facing access tokens (issued by the login/refresh
/// flow — `sub` is a user UUID).
pub const AUD_USER: &str = "axiam:user";

/// Audience value for M2M / service-account access tokens (issued by the
/// OAuth2 Client Credentials grant — `sub` is a `client_id` string).
pub const AUD_M2M: &str = "axiam:m2m";

/// Self-describing subject kind carried by an access token (FUNC-04).
///
/// Informational only (D-10) — no validator or authz path branches on this
/// claim; it exists so SDK modeling and audit attribution can distinguish
/// which kind of subject minted the token. Tokens issued before this claim
/// existed have no `sub_kind` key and deserialize to [`SubjectKind::User`]
/// via `#[serde(default)]` on [`AccessTokenClaims::sub_kind`] (D-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// A human user authenticated via password/social login/MFA.
    #[default]
    User,
    /// A service account authenticated via mTLS client certificate
    /// (device-auth cert-auth path).
    ServiceAccount,
    /// An OAuth2 client authenticated via the Client Credentials grant.
    OAuth2Client,
}

/// JWT claims embedded in every access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject — user ID (UUID string).
    pub sub: String,
    /// Tenant ID (UUID string).
    pub tenant_id: String,
    /// Organization ID (UUID string).
    pub org_id: String,
    /// Issuer.
    pub iss: String,
    /// Issued-at (Unix timestamp).
    pub iat: i64,
    /// Expiration (Unix timestamp).
    pub exp: i64,
    /// Unique token ID.
    ///
    /// For tokens issued from Phase 4 onward this equals the `session.id` of
    /// the issuing session (user flow) or a random UUIDv4 (M2M / no session
    /// row). Pre-Phase-4 tokens carry a random UUID here — D-15 session
    /// revocation tolerates this by treating the jti-to-session relationship
    /// as advisory.
    pub jti: String,
    /// Token audience — `"axiam:user"` or `"axiam:m2m"`.
    ///
    /// `None` means the token was issued before Phase 4 and should be treated
    /// as `axiam:user` when `AuthConfig.allow_missing_aud_as_user` is `true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// OAuth2 scopes (space-separated string). Present when non-empty
    /// scopes are granted — both Client Credentials and Authorization
    /// Code flows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Self-describing subject kind (FUNC-04, D-09/D-10/D-11).
    ///
    /// Always serialized when a token is issued. Missing on decode (a
    /// pre-phase token) defaults to [`SubjectKind::User`]. Informational
    /// only — does not affect validation or authorization decisions.
    #[serde(default)]
    pub sub_kind: SubjectKind,
    /// RFC 8693 §4.1 actor claim — B3 token exchange, **delegation only**.
    ///
    /// Present when this token was minted by an exchange that carried an
    /// `actor_token`: `sub` remains the user, and this names the party acting
    /// for them. Absent on every ordinary token, and — deliberately — absent
    /// on an *impersonation* exchange too, because impersonation's whole
    /// definition is that the resulting token is indistinguishable from one
    /// the subject obtained directly. That is exactly why impersonation is
    /// off by default, gated behind a per-client grant, and audited: the
    /// audit record is the only place it is visible.
    ///
    /// Nested for chained delegation (`act.act`), capped at
    /// [`MAX_ACT_CHAIN_DEPTH`] — an uncapped chain is an unbounded field
    /// inside a signed token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<ActClaim>,
    /// UMA 2.0 `permissions` claim (X2) — present **only** on an RPT.
    ///
    /// Its presence is what makes a token an RPT; there is no separate token
    /// type, because an RPT is an ordinary AXIAM access token that additionally
    /// says which `(resource, scopes)` pairs were allowed when it was issued.
    ///
    /// These are a **record of a decision already made**, not an input to a
    /// future one. Nothing in the authorization path reads this claim to grant
    /// anything: a live check re-evaluates against the engine. That matters
    /// because a grant revoked after issuance does not retroactively empty a
    /// live RPT — which is why RPT lifetime is bounded to the minimum of the
    /// subject token's remaining life, the configured maximum, and 300 s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<RptPermission>>,
    /// Provenance of a cross-domain exchange (X4) — present **only** on a
    /// token minted from an *external* IdP's subject token.
    ///
    /// Two jobs, and the second is the reason it is inside the signed token
    /// rather than only in the audit log:
    ///
    /// 1. A resource server can tell a cross-domain token from a
    ///    locally-issued one without asking us anything.
    /// 2. **It makes the exchange non-transitive.** Both exchange paths refuse
    ///    a subject token carrying this claim, so a token minted from a
    ///    partner's token can never be exchanged again — ours or theirs.
    ///    Without it, trust composes silently: A trusts B, B trusts C,
    ///    therefore A trusts C, which nobody configured and nobody can see.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext_exchange: Option<ExtExchangeClaim>,
    /// RFC 7800 / RFC 8705 §3.1 confirmation claim (X5.1) — present **only**
    /// on a sender-constrained token.
    ///
    /// Its presence changes what the token *is*. An ordinary AXIAM access
    /// token is a bearer credential: whoever holds it may use it. A token
    /// carrying `cnf` is not — it names a key, and a resource server that
    /// accepts it without checking that the caller holds that key has silently
    /// converted it back into a bearer token. That is why the SDK contract
    /// (§10.1, contract 1.15) makes the check mandatory rather than optional,
    /// and why it is phrased as "reject when you cannot verify" rather than
    /// "verify when you can": a middleware that does not understand `cnf` must
    /// refuse the token, not ignore the claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<CnfClaim>,
}

/// RFC 7800 confirmation claim, carrying either or both of the two
/// sender-constraining methods AXIAM implements.
///
/// Deliberately a struct of optional fields rather than an enum: RFC 7800
/// permits several confirmation methods in one claim, and a token that arrived
/// carrying a method AXIAM does not implement must still round-trip through
/// `serde` intact rather than fail to decode. What it must *not* do is
/// validate — see [`CnfClaim::names_only_known_methods`], which answers `false`
/// for exactly that case, and [`verify_token_binding`], which treats it as a
/// refusal.
///
/// # Both at once is a conjunction, never a disjunction
///
/// A `cnf` carrying both `x5t#S256` and `jkt` means the holder must satisfy
/// **both**. Reading it as "either will do" would let a client that had asked
/// for two constraints be used with one — which is strictly weaker than what it
/// asked for, and is the failure mode of every "check whichever we can" binding
/// validator.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CnfClaim {
    /// RFC 8705 §3.1 `x5t#S256` — the base64url-encoded (unpadded) SHA-256
    /// digest of the DER-encoded client certificate the token was issued to.
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
    /// RFC 9449 §6.1 `jkt` — the base64url-encoded (unpadded) SHA-256 RFC 7638
    /// thumbprint of the public key whose DPoP proof was presented at the token
    /// endpoint.
    ///
    /// A token carrying this is usable only by a caller that can sign a fresh
    /// DPoP proof with the corresponding private key, on every request. That is
    /// a different cost class from `x5t#S256` — an asymmetric verification per
    /// request rather than one SHA-256 — and `axiam_oauth2::dpop`'s module docs
    /// say so with a measured number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
}

impl CnfClaim {
    /// Build a certificate-thumbprint confirmation (RFC 8705 §3.1).
    pub fn from_certificate_thumbprint(thumbprint: impl Into<String>) -> Self {
        Self {
            x5t_s256: Some(thumbprint.into()),
            jkt: None,
        }
    }

    /// Build a DPoP key-thumbprint confirmation (RFC 9449 §6).
    pub fn from_dpop_thumbprint(jkt: impl Into<String>) -> Self {
        Self {
            x5t_s256: None,
            jkt: Some(jkt.into()),
        }
    }

    /// Add a DPoP confirmation to an existing one, producing a `cnf` that
    /// demands both.
    #[must_use]
    pub fn with_dpop_thumbprint(mut self, jkt: impl Into<String>) -> Self {
        self.jkt = Some(jkt.into());
        self
    }

    /// The certificate thumbprint this token is bound to, if it names one.
    pub fn certificate_thumbprint(&self) -> Option<&str> {
        self.x5t_s256.as_deref()
    }

    /// The DPoP key thumbprint this token is bound to, if it names one.
    pub fn dpop_thumbprint(&self) -> Option<&str> {
        self.jkt.as_deref()
    }

    /// Whether this confirmation names at least one method this build can
    /// check, and no method it cannot.
    ///
    /// The second half is what makes the invariant hold. A `cnf` that names
    /// *some* method a validator understands alongside one it does not is still
    /// a constraint the validator cannot fully enforce — but AXIAM's
    /// [`CnfClaim`] can only represent the two it implements, so anything
    /// unknown deserializes into neither field and this answers `false`. A
    /// `cnf` naming no method at all — `{}` — also answers `false`, because an
    /// empty confirmation is not the same as an absent one and reading it as
    /// "unbound" would let a stripped claim downgrade a token.
    pub fn names_only_known_methods(&self) -> bool {
        self.x5t_s256.is_some() || self.jkt.is_some()
    }
}

/// X4 provenance claim: which foreign issuer's token this one came from.
///
/// Deliberately just the issuer. The external `sub` is in the audit record,
/// not here — a downstream service has no use for a partner-local identifier
/// and every reason not to key anything on it, whereas the issuer is what a
/// policy would actually branch on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtExchangeClaim {
    /// The external IdP's `iss`, exactly as it appeared in the subject token.
    pub iss: String,
}

/// RFC 8693 §4.1 `act` claim: who is acting on the subject's behalf.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActClaim {
    /// The actor's identifier — a `client_id` for a service actor.
    pub sub: String,
    /// The previous actor in a delegation chain, innermost last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActClaim>>,
}

impl ActClaim {
    /// Number of actors in this chain, counting `self`.
    pub fn depth(&self) -> usize {
        1 + self.act.as_ref().map_or(0, |inner| inner.depth())
    }
}

/// How many actors an `act` chain may name before an exchange is refused.
///
/// Three is not a round number chosen for tidiness: beyond a
/// user → gateway → service → service hop nobody reads the chain, and the
/// claim is carried in every request the token authenticates. A cap makes the
/// token size bounded; no cap makes it a function of how many times an
/// attacker can re-exchange.
pub const MAX_ACT_CHAIN_DEPTH: usize = 3;

/// Issue a signed EdDSA (Ed25519) JWT access token.
///
/// `jti` should be the `session.id` of the issuing session (pass
/// `session.id.to_string()`). This enables stateless session revocation
/// checks in D-15 without a DB lookup.
///
/// `aud` should be [`AUD_USER`] for user-facing tokens.
///
/// When `scopes` is non-empty a space-separated `scope` claim is
/// included in the token; otherwise the claim is omitted.
pub fn issue_access_token(
    user_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
    scopes: &[String],
    config: &AuthConfig,
    jti: String,
    aud: &str,
) -> Result<String, AuthError> {
    issue_access_token_bound(user_id, tenant_id, org_id, scopes, config, jti, aud, None)
}

/// [`issue_access_token`], optionally **sender-constrained** to a client
/// certificate (X5.1, RFC 8705 §3).
///
/// Passing `Some(cnf)` adds the confirmation claim; passing `None` produces a
/// byte-identical token to [`issue_access_token`], which is why that function
/// is a one-line delegation rather than a copy. Every existing caller keeps
/// issuing unbound tokens without knowing this parameter exists — the FAPI
/// posture stays one switch on one client, not a change to token issuance
/// everywhere.
///
/// # Cost
///
/// One `Option<CnfClaim>` move and, when bound, ~60 extra bytes inside the
/// signed payload. No extra cryptography: the certificate was verified during
/// the TLS handshake and its thumbprint is a SHA-256 over bytes already in
/// memory. This is the basis of X5.1's "certificate-bound tokens at IoT
/// prices" claim — see `benchmarks/` `bench-quick` for the measurement, and
/// the X5.1 table for the measured figure rather than the predicted one.
#[allow(clippy::too_many_arguments)]
pub fn issue_access_token_bound(
    user_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
    scopes: &[String],
    config: &AuthConfig,
    jti: String,
    aud: &str,
    cnf: Option<CnfClaim>,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let scope = if scopes.is_empty() {
        None
    } else {
        Some(scopes.join(" "))
    };

    let claims = AccessTokenClaims {
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: config.effective_issuer().to_owned(),
        iat: now,
        exp: now + config.access_token_lifetime_secs as i64,
        jti,
        aud: Some(aud.to_string()),
        scope,
        sub_kind: SubjectKind::User,
        act: None,
        permissions: None,
        ext_exchange: None,
        cnf,
    };

    // CQ-B14: Use pre-parsed key cache when available; fall back to PEM parsing.
    let owned;
    let key: &EncodingKey = if let Some(ref cached) = config.jwt_encoding_key {
        cached.as_ref()
    } else {
        owned = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        &owned
    };

    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, &claims, key)
        .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
}

/// Read the `iss` claim of a JWT **without verifying anything** (X4).
///
/// This is a routing primitive, not a validation one. It answers "which key
/// should this token be checked against" — never "is this token good". Both
/// destinations verify: a token claiming AXIAM's issuer is checked against
/// AXIAM's signing key, and a token claiming a partner's issuer is checked
/// against that partner's JWKS. A forged `iss` therefore selects the branch in
/// which it fails, which is why reading it unverified is safe here and would
/// not be anywhere that acts on the answer.
///
/// Returns `None` for anything that is not a three-part JWT with a
/// base64url-decodable JSON payload carrying a string `iss`.
pub fn unverified_issuer_of(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let (_header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    // A two-part token is an unsigned JWT; there is no branch that would
    // accept one, so refuse to route it at all rather than let it reach a
    // signature check that reports a less specific failure.
    if signature.is_empty() || parts.next().is_some() {
        return None;
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    json.get("iss")?.as_str().map(str::to_owned)
}

/// Issue an access token for an RFC 8693 token exchange (B3).
///
/// Distinct from [`issue_access_token`] in exactly the two ways the exchange
/// needs, and no others:
///
/// * **`expires_at` is supplied by the caller, not derived from the config.**
///   An exchanged token must never outlive the subject token it came from, or
///   an exchange becomes a lifetime-laundering step: hold a token for thirty
///   seconds, exchange it, hold the result for fifteen minutes. The caller
///   computes `min(subject remaining, configured max)` and passes it here.
/// * **`act` may be set**, naming the delegating party (§4.1).
/// * **`ext_exchange` may be set** (X4), naming the foreign issuer whose token
///   bought this one. Both exchange paths refuse a subject token that carries
///   it, which is what makes the exchange non-transitive.
///
/// Everything else — issuer, algorithm, key handling — is identical, so an
/// exchanged token validates through exactly the same path as any other.
#[allow(clippy::too_many_arguments)]
pub fn issue_exchanged_token(
    subject: &str,
    sub_kind: SubjectKind,
    tenant_id: Uuid,
    org_id: Uuid,
    scopes: &[String],
    config: &AuthConfig,
    jti: String,
    aud: &str,
    expires_at: i64,
    act: Option<ActClaim>,
    ext_exchange: Option<ExtExchangeClaim>,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    if expires_at <= now {
        return Err(AuthError::Crypto(
            "exchanged token would already be expired".into(),
        ));
    }
    let scope = if scopes.is_empty() {
        None
    } else {
        Some(scopes.join(" "))
    };

    let claims = AccessTokenClaims {
        sub: subject.to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: config.effective_issuer().to_owned(),
        iat: now,
        exp: expires_at,
        jti,
        aud: Some(aud.to_string()),
        scope,
        sub_kind,
        act,
        // An exchanged token is not an RPT. A UMA permission set is minted by
        // the uma-ticket grant against a consumed ticket, and re-stamping it
        // through an exchange would carry a decision past the ticket that
        // authorised it.
        permissions: None,
        ext_exchange,
        // An exchange does not inherit the subject token's sender constraint,
        // and must not invent one. RFC 8705 §3 binds a token to the
        // certificate presented *at the token endpoint by the party the token
        // is for*; the exchanging client is a different party from the subject,
        // so copying the subject's `cnf` would bind the new token to a
        // certificate its holder does not have — breaking every request — and
        // minting a fresh one would assert a constraint the exchange never
        // verified. Sender-constrained exchange is a distinct piece of work,
        // deliberately not smuggled in here.
        cnf: None,
    };

    let owned;
    let key: &EncodingKey = if let Some(ref cached) = config.jwt_encoding_key {
        cached.as_ref()
    } else {
        owned = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        &owned
    };

    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, &claims, key)
        .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
}

/// Issue a JWT access token for OAuth2 Client Credentials grant (M2M).
///
/// The `sub` claim is the OAuth2 `client_id` (not a user UUID).
/// `jti` is a random UUID — service accounts have no session row.
/// `aud` is set to [`AUD_M2M`].
/// If `scopes` is non-empty, a space-separated `scope` claim is
/// included in the token.
pub fn issue_client_credentials_token(
    client_id: &str,
    tenant_id: Uuid,
    org_id: Uuid,
    scopes: &[String],
    config: &AuthConfig,
) -> Result<String, AuthError> {
    issue_client_credentials_token_bound(client_id, tenant_id, org_id, scopes, config, None)
}

/// [`issue_client_credentials_token`], optionally sender-constrained to a
/// client certificate (X5.1, RFC 8705 §3).
///
/// This is the grant where certificate binding matters most: a
/// client-credentials token has no user behind it and typically a long tail of
/// machine callers, so a leaked one is usable by anything that can reach the
/// resource server. Binding it to the certificate the client already presents
/// on every connection removes that.
pub fn issue_client_credentials_token_bound(
    client_id: &str,
    tenant_id: Uuid,
    org_id: Uuid,
    scopes: &[String],
    config: &AuthConfig,
    cnf: Option<CnfClaim>,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let scope = if scopes.is_empty() {
        None
    } else {
        Some(scopes.join(" "))
    };

    let claims = AccessTokenClaims {
        sub: client_id.to_owned(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: config.effective_issuer().to_owned(),
        iat: now,
        exp: now + config.access_token_lifetime_secs as i64,
        // Not `new_id()`: a jti is a uniqueness marker inside an already-signed
        // JWT, not a record id, so key locality is irrelevant here.
        jti: Uuid::new_v4().to_string(),
        aud: Some(AUD_M2M.to_string()),
        scope,
        sub_kind: SubjectKind::OAuth2Client,
        act: None,
        permissions: None,
        ext_exchange: None,
        cnf,
    };

    // CQ-B14: Use pre-parsed key cache when available; fall back to PEM parsing.
    let owned;
    let key: &EncodingKey = if let Some(ref cached) = config.jwt_encoding_key {
        cached.as_ref()
    } else {
        owned = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        &owned
    };

    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, &claims, key)
        .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
}

/// Issue an RPT — the requesting party token of the UMA 2.0 grant (X2).
///
/// An RPT is an ordinary AXIAM access token for `subject_id` that additionally
/// carries the [`AccessTokenClaims::permissions`] claim. It is deliberately not
/// a distinct token type: every existing validator, audience check and
/// revocation path applies to it unchanged, which is what stops the RPT from
/// becoming a second credential format with its own gaps.
///
/// `lifetime_secs` is decided by the caller — `axiam_oauth2::uma` computes it
/// as the minimum of the subject token's remaining life, the deployment
/// ceiling, and the protocol default. It is **not** re-derived from
/// `config.access_token_lifetime_secs`, because an RPT must never outlive the
/// token that authorised it.
///
/// `aud` is [`AUD_USER`]: the subject is the requesting party, a user, and the
/// RPT authenticates as that user.
pub fn issue_rpt(
    subject_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
    permissions: Vec<RptPermission>,
    lifetime_secs: i64,
    config: &AuthConfig,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();

    let claims = AccessTokenClaims {
        sub: subject_id.to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: config.effective_issuer().to_owned(),
        iat: now,
        exp: now + lifetime_secs,
        // No session row backs an RPT — it is minted from a ticket, not a
        // login — so `jti` is a plain uniqueness marker, as it is for M2M.
        jti: Uuid::new_v4().to_string(),
        aud: Some(AUD_USER.to_string()),
        // The `permissions` claim carries the authority. Stamping an OAuth2
        // `scope` too would give a resource server two disagreeing places to
        // read authority from, and only one of them was evaluated.
        scope: None,
        sub_kind: SubjectKind::User,
        act: None,
        permissions: Some(permissions),
        // An RPT is minted from a ticket, never from an exchange. If the
        // subject token that bought the ticket was itself cross-domain, that
        // fact belongs to *that* token and its audit record; re-stamping it
        // here would attribute this decision to a provenance it does not have.
        ext_exchange: None,
        cnf: None,
    };

    let owned;
    let key: &EncodingKey = if let Some(ref cached) = config.jwt_encoding_key {
        cached.as_ref()
    } else {
        owned = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        &owned
    };

    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, &claims, key)
        .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
}

/// Issue a JWT access token for a service account authenticated via mTLS
/// client certificate (device-auth cert-auth path, resolving `TODO(T15)`).
///
/// The `sub` claim is the service account's `user_id` (mirrors the shape
/// the device-auth handler previously passed to [`issue_access_token`]).
/// `jti` is caller-supplied — service-account/device auth has no session
/// row, so callers pass a random UUID. `scope` is empty: a device's
/// authorization comes from the roles assigned to its service account.
///
/// # ⚠ Breaking change — `aud` is now [`AUD_M2M`]
///
/// This function used to stamp [`AUD_USER`], so a certificate-authenticated
/// device received a **user**-audience token and passed every user-facing
/// route guard. That was a documented back-compat decision, but it meant the
/// same principal got a user token by certificate and a machine token by
/// secret, leaving the SEC-006 / §4.3 audience narrowing only half applied
/// (§17.2 residual 1).
///
/// Both service-account authentication paths — mTLS here, and
/// [`issue_service_account_client_credentials_token`] — now mint
/// [`AUD_M2M`]. The audience finally describes *what kind of principal
/// holds the token* rather than which endpoint happened to issue it.
///
/// **Operator impact:** a device can no longer call user-facing routes. The
/// authorization-check endpoints accept machine tokens via
/// `AuthenticatedPrincipal`; any other route a fleet depends on must be
/// migrated deliberately, which is the point — those grants were previously
/// implicit.
pub fn issue_service_account_token(
    user_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
    jti: String,
    config: &AuthConfig,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();

    let claims = AccessTokenClaims {
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: config.effective_issuer().to_owned(),
        iat: now,
        exp: now + config.access_token_lifetime_secs as i64,
        jti,
        // §17.2 residual 1: was AUD_USER. See the breaking-change note above.
        aud: Some(AUD_M2M.to_string()),
        scope: None,
        sub_kind: SubjectKind::ServiceAccount,
        act: None,
        permissions: None,
        ext_exchange: None,
        cnf: None,
    };

    // CQ-B14: Use pre-parsed key cache when available; fall back to PEM parsing.
    let owned;
    let key: &EncodingKey = if let Some(ref cached) = config.jwt_encoding_key {
        cached.as_ref()
    } else {
        owned = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        &owned
    };

    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, &claims, key)
        .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
}

/// Mint a service-account access token for the **OAuth2 client-credentials**
/// grant.
///
/// The sibling of [`issue_service_account_token`], which the mTLS device-auth
/// path uses. The two now agree on **`aud`, `sub` and `sub_kind`** — this is a
/// service account either way, and since the residual-1 narrowing both paths
/// stamp [`AUD_M2M`], so §4.3 / `SEC-006` route narrowing keeps both off user
/// routes.
///
/// *(This comment previously said the device path stamps [`AUD_USER`] for
/// backwards compatibility and that the two were "deliberately distinct" in
/// audience. That has been the inverse of the code since the residual-1 flip.)*
///
/// **`sub` is the service-account id**, not the `client_id`, on both paths. The
/// authorization engine resolves roles by subject id, so a token whose `sub`
/// were the opaque `sa_…` client id would authenticate but carry no resolvable
/// grants. This is what makes a service account the *same principal* whether it
/// authenticated by certificate or by secret.
///
/// Two claims still differ, both because of how each path is reached:
///
/// * **`jti` is generated here**, whereas the mTLS path takes it from the
///   caller. Neither path has a session row to derive one from.
/// * **`scope` may be populated here.** The device path has no way to request
///   scopes; this grant does, though a service account registers none, so in
///   practice `scopes` is empty and this collapses to `None` (§12.1).
pub fn issue_service_account_client_credentials_token(
    service_account_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
    scopes: &[String],
    config: &AuthConfig,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let scope = if scopes.is_empty() {
        None
    } else {
        Some(scopes.join(" "))
    };

    let claims = AccessTokenClaims {
        sub: service_account_id.to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: config.effective_issuer().to_owned(),
        iat: now,
        exp: now + config.access_token_lifetime_secs as i64,
        jti: Uuid::new_v4().to_string(),
        aud: Some(AUD_M2M.to_string()),
        scope,
        sub_kind: SubjectKind::ServiceAccount,
        act: None,
        permissions: None,
        ext_exchange: None,
        cnf: None,
    };

    let owned;
    let key: &EncodingKey = if let Some(ref cached) = config.jwt_encoding_key {
        cached.as_ref()
    } else {
        owned = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        &owned
    };

    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, &claims, key)
        .map_err(|e| AuthError::Crypto(format!("failed to encode token: {e}")))
}

/// OIDC ID Token claims per OpenID Connect Core 1.0 section 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer identifier.
    pub iss: String,
    /// Subject — user ID (UUID string).
    pub sub: String,
    /// Audience — the OAuth2 `client_id`.
    pub aud: String,
    /// Expiration (Unix timestamp).
    pub exp: i64,
    /// Issued-at (Unix timestamp).
    pub iat: i64,
    /// Nonce echoed from the authorization request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Session identifier (B5).
    ///
    /// Carried so that RP-initiated logout can end *one* session rather than
    /// every session the subject holds, and so that a back-channel logout
    /// token can name the session precisely. An ID token that identifies only
    /// the user forces both to be all-or-nothing, which is not what a user
    /// logging out on their laptop asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// Tenant ID (UUID string).
    pub tenant_id: String,
    /// Organization ID (UUID string).
    pub org_id: String,
    /// User email — included only when `email` scope is requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Preferred username — included only when `profile` scope is requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
}

/// Issue a signed OIDC ID token (EdDSA / Ed25519).
///
/// The token includes standard OIDC claims plus AXIAM-specific
/// `tenant_id` and `org_id`. Profile/email claims are gated behind
/// the corresponding scopes.
#[allow(clippy::too_many_arguments)]
pub fn issue_id_token(
    user_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
    client_id: &str,
    nonce: Option<&str>,
    email: Option<&str>,
    username: Option<&str>,
    scopes: &[String],
    config: &AuthConfig,
    session_id: Option<Uuid>,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let has_scope = |s: &str| scopes.iter().any(|sc| sc == s);

    let claims = IdTokenClaims {
        iss: config.effective_issuer().to_owned(),
        sub: user_id.to_string(),
        aud: client_id.to_owned(),
        exp: now + config.access_token_lifetime_secs as i64,
        iat: now,
        nonce: nonce.map(str::to_owned),
        sid: session_id.map(|s| s.to_string()),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        email: if has_scope("email") {
            email.map(str::to_owned)
        } else {
            None
        },
        preferred_username: if has_scope("profile") {
            username.map(str::to_owned)
        } else {
            None
        },
    };

    // CQ-B14: Use pre-parsed key cache when available; fall back to PEM parsing.
    let owned;
    let key: &EncodingKey = if let Some(ref cached) = config.jwt_encoding_key {
        cached.as_ref()
    } else {
        owned = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        &owned
    };

    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, &claims, key)
        .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
}

/// Decode and verify an EdDSA JWT access token.
///
/// Audience validation: when `aud` is present it must be either
/// [`AUD_USER`] or [`AUD_M2M`]. When `aud` is absent (pre-Phase-4 token)
/// the library skips the audience check, preserving backward compatibility
/// during the rollout window. Per-route narrowing to a specific audience
/// happens in plan 04-04.
pub fn decode_access_token(
    token: &str,
    config: &AuthConfig,
) -> Result<AccessTokenClaims, AuthError> {
    // CQ-B14: Use pre-parsed key cache when available; fall back to PEM parsing.
    let owned;
    let key: &DecodingKey = if let Some(ref cached) = config.jwt_decoding_key {
        cached.as_ref()
    } else {
        owned = DecodingKey::from_ed_pem(config.jwt_public_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad public key: {e}")))?;
        &owned
    };

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[config.effective_issuer()]);
    // Do NOT require `aud` — pre-Phase-4 tokens omit it (D-20 back-compat).
    validation.set_required_spec_claims(&["sub", "exp", "iat", "iss"]);
    // Accept both user and M2M audiences; presence is checked for membership
    // only when the claim exists (jsonwebtoken skips aud check when token has
    // no `aud` claim and validate_aud=true with a configured audience set).
    validation.set_audience(&[AUD_USER, AUD_M2M]);
    validation.leeway = 60;

    jsonwebtoken::decode::<AccessTokenClaims>(token, key, &validation)
        .map(|data| data.claims)
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            _ => AuthError::TokenInvalid(e.to_string()),
        })
}

/// Validated JWT claims — a newtype proving the token was verified.
///
/// Used by the API layer to extract authenticated context from
/// incoming requests.
#[derive(Debug, Clone)]
pub struct ValidatedClaims(pub AccessTokenClaims);

/// Pre-validated user identity that can be cached in request extensions.
///
/// When the audit middleware (or any other middleware) validates a JWT,
/// it stores a `CachedUserIdentity` so downstream extractors can skip
/// re-verification.
#[derive(Debug, Clone)]
pub struct CachedUserIdentity {
    pub user_id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub org_id: uuid::Uuid,
    pub claims: ValidatedClaims,
}

/// Validate a JWT access token (signature, expiry, issuer) and return
/// the verified claims.
///
/// This is the entry point for request-level authentication
/// middleware. It is purely stateless — no database lookup is
/// performed.
pub fn validate_access_token(
    token: &str,
    config: &AuthConfig,
) -> Result<ValidatedClaims, AuthError> {
    decode_access_token(token, config).map(ValidatedClaims)
}

/// What a caller can actually prove about itself on *this* request (X5.1).
///
/// A struct rather than two `Option<&str>` parameters because both are
/// base64url-unpadded SHA-256 digests of the same length: swapping them would
/// compile, and would mean checking a certificate binding against a DPoP key.
///
/// [`Default`] is "proves nothing", which is what an ordinary bearer request
/// legitimately carries. That default is deliberately the *weakest* value, so a
/// caller that forgets to populate it fails closed on bound tokens rather than
/// passing.
#[derive(Debug, Clone, Copy, Default)]
pub struct PresentedProofs<'a> {
    /// `x5t#S256` of the client certificate rustls verified during the
    /// handshake — `axiam_oauth2::mtls::thumbprint_s256` produces it.
    ///
    /// Only ever derived from a verified peer chain. A value taken from a
    /// header or a request body would make the whole mechanism decorative,
    /// which is why `axiam_oauth2::mtls`'s module docs refuse the
    /// `X-Client-Certificate` proxy header by construction.
    pub certificate_thumbprint: Option<&'a str>,
    /// `jkt` of the key that signed a DPoP proof **which has already been
    /// verified** for this request — `axiam_oauth2::dpop::verify_dpop_proof`
    /// produces it.
    ///
    /// This is the field it is easiest to get catastrophically wrong. It must
    /// come from a *verified* proof: a `jkt` lifted out of an unverified proof
    /// header is attacker-controlled, and passing one here turns DPoP into a
    /// self-signed permission slip.
    pub dpop_thumbprint: Option<&'a str>,
}

impl<'a> PresentedProofs<'a> {
    /// Only a client certificate.
    pub fn certificate(thumbprint: &'a str) -> Self {
        Self {
            certificate_thumbprint: Some(thumbprint),
            dpop_thumbprint: None,
        }
    }

    /// Only a verified DPoP proof.
    pub fn dpop(jkt: &'a str) -> Self {
        Self {
            certificate_thumbprint: None,
            dpop_thumbprint: Some(jkt),
        }
    }
}

/// Enforce a token's sender constraint against what the caller actually proved
/// on *this* request (X5.1; RFC 8705 §3.2 and RFC 9449 §7.1).
///
/// This is the half of sender-constraining that makes the other half worth
/// anything. Issuing a `cnf` claim costs an attacker nothing if every resource
/// server ignores it; the constraint only exists at the point of use.
///
/// # The decision table
///
/// | token `cnf` | `x5t#S256` evidence | `jkt` evidence | result | why |
/// |---|---|---|---|---|
/// | absent | — | — | `Ok` | an ordinary bearer token; binding was never claimed, and a resource server must not start demanding proofs from callers holding perfectly valid unbound tokens |
/// | `x5t#S256` only | matching | — | `Ok` | the caller holds the private key for the certificate the token was issued to |
/// | `x5t#S256` only | absent, different, or unparseable | — | `Err` | a bound token in the hands of something that cannot prove it is the intended holder |
/// | `jkt` only | — | matching | `Ok` | the caller signed a fresh DPoP proof with the key the token names |
/// | `jkt` only | — | absent or different | `Err` | as above, for the DPoP half |
/// | **both** | matching | matching | `Ok` | a token that named two constraints is honoured only when **both** hold |
/// | **both** | either one missing or wrong | | `Err` | "whichever we can check" is not a conjunction, and reading it as one would use a token under weaker terms than it was issued under |
/// | present, naming neither | anything | anything | `Err` | the token names a confirmation method this build cannot check, so it cannot be honoured |
///
/// The last row is the one that is easy to get wrong, and it is the invariant
/// the SDK contract's §10.1 rule 9 makes mandatory across all eleven SDKs: **a
/// `cnf` naming a confirmation method the validator cannot check is refused,
/// never read as unbound.** Treating an unrecognised confirmation as "no
/// constraint" downgrades a sender-constrained token to a bearer token exactly
/// when a newer authorization server has started issuing a constraint this
/// validator predates — the moment at which failing open is most expensive.
///
/// An **empty** `cnf` (`{}`) takes that same last row rather than the first. An
/// absent claim means "never bound"; an empty object means "bound by something
/// that did not survive the trip", and the difference matters because the
/// second is what a claim-stripping intermediary produces.
///
/// # Ordinary clients
///
/// Row one is load-bearing and is asserted by a dedicated regression test. Every
/// token AXIAM issued before X5.1, and every token it issues to a client that
/// has never heard of DPoP, carries no `cnf` and therefore returns `Ok` without
/// any evidence at all. Nothing in this function can make a resource server
/// start demanding a proof from such a caller.
pub fn verify_token_binding(
    claims: &AccessTokenClaims,
    presented: PresentedProofs<'_>,
) -> Result<(), AuthError> {
    let Some(cnf) = claims.cnf.as_ref() else {
        return Ok(());
    };

    if !cnf.names_only_known_methods() {
        return Err(AuthError::TokenInvalid(
            "token carries a confirmation claim naming a method this server cannot verify".into(),
        ));
    }

    if let Some(expected) = cnf.certificate_thumbprint() {
        let Some(got) = presented.certificate_thumbprint else {
            return Err(AuthError::TokenInvalid(
                "token is certificate-bound but no client certificate was presented".into(),
            ));
        };
        if !thumbprints_match(expected, got) {
            return Err(AuthError::TokenInvalid(
                "token is bound to a different client certificate than the one presented".into(),
            ));
        }
    }

    if let Some(expected) = cnf.dpop_thumbprint() {
        let Some(got) = presented.dpop_thumbprint else {
            return Err(AuthError::TokenInvalid(
                "token is DPoP-bound but no verified DPoP proof accompanied the request".into(),
            ));
        };
        if !thumbprints_match(expected, got) {
            return Err(AuthError::TokenInvalid(
                "token is bound to a different DPoP key than the one that signed the proof".into(),
            ));
        }
    }

    Ok(())
}

/// Constant-time for the same reason `axiam_oauth2::mtls` is: the value is
/// usually public, but the one case where it is not — an attacker probing which
/// certificate or key a stolen token is bound to — should not be a
/// character-at-a-time oracle.
fn thumbprints_match(expected: &str, presented: &str) -> bool {
    use subtle::ConstantTimeEq;
    expected.as_bytes().ct_eq(presented.as_bytes()).into()
}

/// [`verify_token_binding`] for a validator that can check a client certificate
/// and nothing else (X5.1, RFC 8705 §3.2).
///
/// Retained because it is a genuinely different capability, not merely an older
/// spelling: a resource server behind an mTLS listener with no DPoP support can
/// check `x5t#S256` and cannot check `jkt`. Calling this expresses exactly that,
/// and — crucially — a `jkt`-bound token reaching it is **refused**, because a
/// validator that cannot check a constraint must not honour a token that
/// carries it. That refusal is the whole point of keeping the narrower entry
/// point rather than quietly widening every caller to the new one.
pub fn verify_certificate_binding(
    claims: &AccessTokenClaims,
    presented_thumbprint: Option<&str>,
) -> Result<(), AuthError> {
    if claims
        .cnf
        .as_ref()
        .is_some_and(|c| c.dpop_thumbprint().is_some())
    {
        return Err(AuthError::TokenInvalid(
            "token is DPoP-bound and this validator can only check certificate binding".into(),
        ));
    }
    verify_token_binding(
        claims,
        PresentedProofs {
            certificate_thumbprint: presented_thumbprint,
            dpop_thumbprint: None,
        },
    )
}

/// Generate a cryptographically random opaque refresh token
/// (32 bytes → base64url-encoded, no padding).
pub fn generate_refresh_token() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 hash of a raw refresh token, hex-encoded.
///
/// This is the value stored in the database as `session.token_hash`.
pub fn hash_refresh_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate an Ed25519 key pair in PEM format for testing.
    fn test_keypair() -> (String, String) {
        // Use a pre-generated Ed25519 test key pair (PEM).
        // Generated with: openssl genpkey -algorithm Ed25519
        let private_key = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----"; // nosemgrep: generic.secrets.security.detected-private-key

        let public_key = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";

        (private_key.into(), public_key.into())
    }

    fn test_config() -> AuthConfig {
        let (priv_pem, pub_pem) = test_keypair();
        AuthConfig {
            jwt_private_key_pem: priv_pem,
            jwt_public_key_pem: pub_pem,
            access_token_lifetime_secs: 900,
            refresh_token_lifetime_secs: 2_592_000,
            jwt_issuer: "axiam-test".into(),
            pepper: None,
            pepper_previous: None,
            min_password_length: 12,
            mfa_encryption_key: None,
            federation_encryption_key: None,
            allow_missing_aud_as_user: true,
            cookie_secure: true,
            mfa_challenge_lifetime_secs: 300,
            totp_issuer: "AXIAM-Test".into(),
            max_failed_login_attempts: 5,
            lockout_duration_secs: 300,
            lockout_backoff_multiplier: 2.0,
            max_lockout_duration_secs: 3600,
            auth_code_lifetime_secs: 600,
            oauth2_issuer_url: String::new(),
            email_verification_grace_period_hours: 24,
            password_reset_token_expiry_hours: 1,
            webauthn_rp_id: "localhost".into(),
            webauthn_rp_origin: "http://localhost:8090".into(),
            webauthn_rp_name: "AXIAM-Test".into(),
            jwt_encoding_key: None,
            jwt_decoding_key: None,
            hibp_breaker_threshold: 5,
            hibp_breaker_cooldown_secs: 30,
            max_concurrent_hashes: 0,
            hash_acquire_timeout_secs: 5,
            session_validation_cache_ttl_secs: 0,
        }
    }

    #[test]
    fn jwt_roundtrip() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let jti = Uuid::new_v4().to_string();

        let token = issue_access_token(
            user_id,
            tenant_id,
            org_id,
            &[],
            &config,
            jti.clone(),
            AUD_USER,
        )
        .unwrap();
        let claims = decode_access_token(&token, &config).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.tenant_id, tenant_id.to_string());
        assert_eq!(claims.org_id, org_id.to_string());
        assert_eq!(claims.iss, "axiam-test");
        assert_eq!(claims.jti, jti);
        assert_eq!(claims.aud, Some(AUD_USER.to_string()));
    }

    #[test]
    fn jti_equals_session_id() {
        // D-15: jti must equal the issuing session.id so revocation can be
        // performed statlessly without a DB lookup.
        let config = test_config();
        let session_id = "00000000-0000-0000-0000-000000000001".to_string();
        let token = issue_access_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            &[],
            &config,
            session_id.clone(),
            AUD_USER,
        )
        .unwrap();
        let claims = decode_access_token(&token, &config).unwrap();
        assert_eq!(claims.jti, session_id);
        assert_eq!(claims.aud, Some("axiam:user".to_string()));
    }

    #[test]
    fn jti_is_unique() {
        let config = test_config();
        let uid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let oid = Uuid::new_v4();

        let t1 = issue_access_token(
            uid,
            tid,
            oid,
            &[],
            &config,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .unwrap();
        let t2 = issue_access_token(
            uid,
            tid,
            oid,
            &[],
            &config,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .unwrap();

        let c1 = decode_access_token(&t1, &config).unwrap();
        let c2 = decode_access_token(&t2, &config).unwrap();
        assert_ne!(c1.jti, c2.jti);
    }

    #[test]
    fn refresh_token_is_url_safe() {
        let token = generate_refresh_token();
        // base64url characters only (A-Z a-z 0-9 - _), no padding.
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        // 32 bytes → 43 base64url chars.
        assert_eq!(token.len(), 43);
    }

    #[test]
    fn refresh_token_hash_is_deterministic() {
        let raw = "some-refresh-token";
        assert_eq!(hash_refresh_token(raw), hash_refresh_token(raw));
    }

    #[test]
    fn different_tokens_different_hashes() {
        let h1 = hash_refresh_token("token-a");
        let h2 = hash_refresh_token("token-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn client_credentials_token_roundtrip() {
        let config = test_config();
        let client_id = "my-service-client";
        let tenant_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let scopes = vec!["read:data".to_owned(), "write:data".to_owned()];

        let token =
            issue_client_credentials_token(client_id, tenant_id, org_id, &scopes, &config).unwrap();

        let claims = decode_access_token(&token, &config).unwrap();
        assert_eq!(claims.sub, client_id);
        assert_eq!(claims.tenant_id, tenant_id.to_string());
        assert_eq!(claims.org_id, org_id.to_string());
        assert_eq!(claims.iss, "axiam-test");
        assert_eq!(claims.scope.as_deref(), Some("read:data write:data"));
    }

    #[test]
    fn client_credentials_token_no_scopes() {
        let config = test_config();
        let token = issue_client_credentials_token(
            "svc-client",
            Uuid::new_v4(),
            Uuid::new_v4(),
            &[],
            &config,
        )
        .unwrap();

        let claims = decode_access_token(&token, &config).unwrap();
        assert_eq!(claims.sub, "svc-client");
        assert!(claims.scope.is_none());
    }

    #[test]
    fn user_token_has_no_scope_claim() {
        let config = test_config();
        let token = issue_access_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            &[],
            &config,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .unwrap();

        let claims = decode_access_token(&token, &config).unwrap();
        assert!(claims.scope.is_none());
    }

    #[test]
    fn user_token_includes_scopes() {
        let config = test_config();
        let scopes = vec!["openid".to_owned(), "email".to_owned()];
        let token = issue_access_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            &scopes,
            &config,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .unwrap();

        let claims = decode_access_token(&token, &config).unwrap();
        assert_eq!(claims.scope.as_deref(), Some("openid email"),);
    }

    // ------------------------------------------------------------------
    // ID token tests
    // ------------------------------------------------------------------

    /// Helper to decode an ID token with the test public key.
    fn decode_id_token(token: &str, config: &AuthConfig) -> IdTokenClaims {
        let key = DecodingKey::from_ed_pem(config.jwt_public_key_pem.as_bytes()).unwrap();
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[config.effective_issuer()]);
        validation.set_required_spec_claims(&["sub", "exp", "iat", "iss"]);
        // ID token `aud` is the client_id, not the issuer.
        validation.set_audience(&["test-client"]);
        jsonwebtoken::decode::<IdTokenClaims>(token, &key, &validation)
            .unwrap()
            .claims
    }

    #[test]
    fn id_token_roundtrip() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let scopes = vec![
            "openid".to_owned(),
            "email".to_owned(),
            "profile".to_owned(),
        ];

        let token = issue_id_token(
            user_id,
            tenant_id,
            org_id,
            "test-client",
            Some("abc123"),
            Some("user@example.com"),
            Some("jdoe"),
            &scopes,
            &config,
            None,
        )
        .unwrap();

        let claims = decode_id_token(&token, &config);

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.aud, "test-client");
        assert_eq!(claims.iss, "axiam-test");
        assert_eq!(claims.tenant_id, tenant_id.to_string());
        assert_eq!(claims.org_id, org_id.to_string());
        assert_eq!(claims.nonce.as_deref(), Some("abc123"));
        assert_eq!(claims.email.as_deref(), Some("user@example.com"),);
        assert_eq!(claims.preferred_username.as_deref(), Some("jdoe"),);
    }

    #[test]
    fn id_token_includes_nonce() {
        let config = test_config();
        let scopes = vec!["openid".to_owned()];

        let with_nonce = issue_id_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "test-client",
            Some("my-nonce"),
            None,
            None,
            &scopes,
            &config,
            None,
        )
        .unwrap();

        let without_nonce = issue_id_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "test-client",
            None,
            None,
            None,
            &scopes,
            &config,
            None,
        )
        .unwrap();

        let c1 = decode_id_token(&with_nonce, &config);
        assert_eq!(c1.nonce.as_deref(), Some("my-nonce"));

        let c2 = decode_id_token(&without_nonce, &config);
        assert!(c2.nonce.is_none());
    }

    #[test]
    fn id_token_email_scope() {
        let config = test_config();
        let uid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let oid = Uuid::new_v4();

        // With email scope
        let token_with = issue_id_token(
            uid,
            tid,
            oid,
            "test-client",
            None,
            Some("user@example.com"),
            None,
            &["openid".to_owned(), "email".to_owned()],
            &config,
            None,
        )
        .unwrap();
        let c = decode_id_token(&token_with, &config);
        assert_eq!(c.email.as_deref(), Some("user@example.com"),);

        // Without email scope
        let token_without = issue_id_token(
            uid,
            tid,
            oid,
            "test-client",
            None,
            Some("user@example.com"),
            None,
            &["openid".to_owned()],
            &config,
            None,
        )
        .unwrap();
        let c = decode_id_token(&token_without, &config);
        assert!(c.email.is_none());
    }

    #[test]
    fn id_token_profile_scope() {
        let config = test_config();
        let uid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let oid = Uuid::new_v4();

        // With profile scope
        let token_with = issue_id_token(
            uid,
            tid,
            oid,
            "test-client",
            None,
            None,
            Some("jdoe"),
            &["openid".to_owned(), "profile".to_owned()],
            &config,
            None,
        )
        .unwrap();
        let c = decode_id_token(&token_with, &config);
        assert_eq!(c.preferred_username.as_deref(), Some("jdoe"),);

        // Without profile scope
        let token_without = issue_id_token(
            uid,
            tid,
            oid,
            "test-client",
            None,
            None,
            Some("jdoe"),
            &["openid".to_owned()],
            &config,
            None,
        )
        .unwrap();
        let c = decode_id_token(&token_without, &config);
        assert!(c.preferred_username.is_none());
    }

    // ------------------------------------------------------------------
    // sub_kind tests (FUNC-04, D-09/D-10/D-11)
    // ------------------------------------------------------------------

    #[test]
    fn missing_sub_kind_defaults_to_user() {
        // D-11: a pre-phase token payload with no `sub_kind` key must still
        // deserialize successfully, defaulting to `SubjectKind::User`.
        let json = r#"{
            "sub": "some-subject",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "org_id": "00000000-0000-0000-0000-000000000002",
            "iss": "axiam-test",
            "iat": 0,
            "exp": 9999999999,
            "jti": "00000000-0000-0000-0000-000000000003"
        }"#;
        let claims: AccessTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub_kind, SubjectKind::User);
    }

    #[test]
    fn issue_access_token_stamps_user_sub_kind() {
        let config = test_config();
        let token = issue_access_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            &[],
            &config,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .unwrap();
        let claims = decode_access_token(&token, &config).unwrap();
        assert_eq!(claims.sub_kind, SubjectKind::User);
    }

    #[test]
    fn issue_client_credentials_token_stamps_oauth2_client_sub_kind() {
        let config = test_config();
        let token = issue_client_credentials_token(
            "svc-client",
            Uuid::new_v4(),
            Uuid::new_v4(),
            &[],
            &config,
        )
        .unwrap();
        let claims = decode_access_token(&token, &config).unwrap();
        assert_eq!(claims.sub_kind, SubjectKind::OAuth2Client);
    }

    #[test]
    fn issue_service_account_token_stamps_service_account_sub_kind() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let jti = Uuid::new_v4().to_string();

        let token =
            issue_service_account_token(user_id, tenant_id, org_id, jti.clone(), &config).unwrap();
        let claims = decode_access_token(&token, &config).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.tenant_id, tenant_id.to_string());
        assert_eq!(claims.org_id, org_id.to_string());
        assert_eq!(claims.jti, jti);
        assert_eq!(claims.sub_kind, SubjectKind::ServiceAccount);
    }

    #[test]
    fn validate_access_token_accepts_service_account_token() {
        // D-10: sub_kind is informational only — validation must not reject
        // (or otherwise treat differently) a ServiceAccount-kinded token.
        let config = test_config();
        let token = issue_service_account_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4().to_string(),
            &config,
        )
        .unwrap();

        let validated = validate_access_token(&token, &config).unwrap();
        assert_eq!(validated.0.sub_kind, SubjectKind::ServiceAccount);
    }

    // -----------------------------------------------------------------
    // X4 — the ext_exchange provenance claim
    // -----------------------------------------------------------------

    #[test]
    fn an_ordinary_exchanged_token_carries_no_provenance_claim() {
        let config = test_config();
        let token = issue_exchanged_token(
            &Uuid::new_v4().to_string(),
            SubjectKind::User,
            Uuid::new_v4(),
            Uuid::new_v4(),
            &["read".to_string()],
            &config,
            Uuid::new_v4().to_string(),
            AUD_USER,
            Utc::now().timestamp() + 60,
            None,
            None,
        )
        .unwrap();

        let claims = decode_access_token(&token, &config).unwrap();
        assert!(
            claims.ext_exchange.is_none(),
            "a same-domain B3 exchange must not claim a foreign provenance"
        );
        // And the key must be absent from the wire, not present-and-null: a
        // resource server testing `\"ext_exchange\" in claims` is doing the
        // documented thing.
        let payload = token.split('.').nth(1).unwrap();
        let json = String::from_utf8(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .unwrap(),
        )
        .unwrap();
        assert!(!json.contains("ext_exchange"), "wire payload: {json}");
    }

    #[test]
    fn a_cross_domain_exchange_stamps_the_foreign_issuer_and_it_survives_a_round_trip() {
        let config = test_config();
        let token = issue_exchanged_token(
            &Uuid::new_v4().to_string(),
            SubjectKind::User,
            Uuid::new_v4(),
            Uuid::new_v4(),
            &["read".to_string()],
            &config,
            Uuid::new_v4().to_string(),
            AUD_USER,
            Utc::now().timestamp() + 60,
            None,
            Some(ExtExchangeClaim {
                iss: "https://partner.example/".into(),
            }),
        )
        .unwrap();

        let claims = decode_access_token(&token, &config).unwrap();
        assert_eq!(
            claims.ext_exchange,
            Some(ExtExchangeClaim {
                iss: "https://partner.example/".into()
            }),
            "the provenance claim is what makes the exchange non-transitive; \
             a decode that loses it silently restores transitivity"
        );
    }

    // -----------------------------------------------------------------------
    // X5.1 — RFC 8705 §3 certificate binding
    // -----------------------------------------------------------------------

    /// A thumbprint of the right shape. The value itself is arbitrary; what
    /// matters is that it is the same string on both sides of the comparison.
    const TP: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const OTHER_TP: &str = "bWluZS1ub3QteW91cnMtdGhpcy1pcy00My1jaGFyc18";

    fn claims_with_cnf(cnf: Option<CnfClaim>) -> AccessTokenClaims {
        AccessTokenClaims {
            sub: Uuid::new_v4().to_string(),
            tenant_id: Uuid::new_v4().to_string(),
            org_id: Uuid::new_v4().to_string(),
            iss: "axiam-test".into(),
            iat: 0,
            exp: i64::MAX,
            jti: Uuid::new_v4().to_string(),
            aud: Some(AUD_M2M.into()),
            scope: None,
            sub_kind: SubjectKind::OAuth2Client,
            act: None,
            permissions: None,
            ext_exchange: None,
            cnf,
        }
    }

    /// An unbound token is a bearer token, and must not start demanding
    /// certificates. This is the regression test for "X5.1 broke every
    /// existing deployment".
    #[test]
    fn an_unbound_token_is_accepted_with_or_without_a_certificate() {
        let claims = claims_with_cnf(None);
        assert!(verify_certificate_binding(&claims, None).is_ok());
        assert!(verify_certificate_binding(&claims, Some(TP)).is_ok());
    }

    #[test]
    fn a_bound_token_is_accepted_only_with_its_own_certificate() {
        let claims = claims_with_cnf(Some(CnfClaim::from_certificate_thumbprint(TP)));
        assert!(verify_certificate_binding(&claims, Some(TP)).is_ok());
        assert!(verify_certificate_binding(&claims, Some(OTHER_TP)).is_err());
        assert!(verify_certificate_binding(&claims, None).is_err());
    }

    /// The row that is easiest to get wrong: a confirmation naming a method
    /// this build cannot check must be REFUSED, never read as "unbound". Read
    /// as unbound, a sender-constrained token silently degrades to a bearer
    /// token the moment a newer AS issues a constraint this validator
    /// predates.
    #[test]
    fn an_unrecognised_confirmation_method_is_refused_not_ignored() {
        // A `cnf` naming a method AXIAM does not implement — RFC 7800's `jwe`
        // encrypted-key confirmation — decodes to a `CnfClaim` with neither
        // field set. (Until X5.1's second half, `jkt` was the example here;
        // it is now a method this build *can* check, which is the point of
        // this change.)
        for raw in [
            r#"{"jwe":"eyJhbGciOiJSU0Et...opaque"}"#,
            // An empty confirmation is not an absent one. It is what a
            // claim-stripping intermediary leaves behind.
            r#"{}"#,
        ] {
            let cnf: CnfClaim =
                serde_json::from_str(raw).expect("a cnf naming another method must still decode");
            assert!(!cnf.names_only_known_methods(), "{raw}");

            let claims = claims_with_cnf(Some(cnf));
            assert!(verify_token_binding(&claims, PresentedProofs::default()).is_err());
            assert!(verify_token_binding(&claims, PresentedProofs::certificate(TP)).is_err());
            assert!(verify_token_binding(&claims, PresentedProofs::dpop(JKT)).is_err());
        }
    }

    /// The claim must serialize under RFC 8705's exact key. `x5t#S256` is not
    /// a legal Rust identifier, so it can only be right by way of the serde
    /// rename — which is exactly the kind of thing that gets dropped in a
    /// refactor and produces a claim no conforming resource server reads.
    #[test]
    fn cnf_serializes_under_the_rfc_8705_key() {
        let json = serde_json::to_string(&CnfClaim::from_certificate_thumbprint(TP)).unwrap();
        assert_eq!(json, format!(r#"{{"x5t#S256":"{TP}"}}"#));
    }

    // -----------------------------------------------------------------------
    // X5.1 second half — RFC 9449 DPoP binding
    // -----------------------------------------------------------------------

    /// A JWK thumbprint of the right shape.
    const JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    const OTHER_JKT: &str = "YW5vdGhlci1rZXktdGh1bWJwcmludC00My1jaGFycw";

    /// The positive regression test the contract requires of every SDK, and
    /// which the server owes too: **a client that has never heard of DPoP must
    /// get exactly the token behaviour it got before.** The likeliest way to
    /// break DPoP support is a resource-server path that starts demanding a
    /// proof from every caller, and this is what catches it.
    #[test]
    fn an_unbound_token_never_demands_a_dpop_proof() {
        let claims = claims_with_cnf(None);
        assert!(verify_token_binding(&claims, PresentedProofs::default()).is_ok());
        assert!(verify_token_binding(&claims, PresentedProofs::dpop(JKT)).is_ok());
        assert!(verify_token_binding(&claims, PresentedProofs::certificate(TP)).is_ok());
        // ...and the narrower entry point agrees, since an unbound token is
        // within any validator's competence.
        assert!(verify_certificate_binding(&claims, None).is_ok());
    }

    #[test]
    fn a_dpop_bound_token_is_accepted_only_with_its_own_key() {
        let claims = claims_with_cnf(Some(CnfClaim::from_dpop_thumbprint(JKT)));
        assert!(verify_token_binding(&claims, PresentedProofs::dpop(JKT)).is_ok());
        assert!(verify_token_binding(&claims, PresentedProofs::dpop(OTHER_JKT)).is_err());
        assert!(verify_token_binding(&claims, PresentedProofs::default()).is_err());
        // A certificate is not a substitute for a proof.
        assert!(verify_token_binding(&claims, PresentedProofs::certificate(TP)).is_err());
    }

    /// Both confirmations present is a conjunction. Honouring the token on one
    /// of the two would use it under weaker terms than it was issued under.
    #[test]
    fn a_doubly_bound_token_demands_both_proofs() {
        let claims = claims_with_cnf(Some(
            CnfClaim::from_certificate_thumbprint(TP).with_dpop_thumbprint(JKT),
        ));

        assert!(
            verify_token_binding(
                &claims,
                PresentedProofs {
                    certificate_thumbprint: Some(TP),
                    dpop_thumbprint: Some(JKT),
                }
            )
            .is_ok()
        );

        for weaker in [
            PresentedProofs::certificate(TP),
            PresentedProofs::dpop(JKT),
            PresentedProofs::default(),
            PresentedProofs {
                certificate_thumbprint: Some(TP),
                dpop_thumbprint: Some(OTHER_JKT),
            },
            PresentedProofs {
                certificate_thumbprint: Some(OTHER_TP),
                dpop_thumbprint: Some(JKT),
            },
        ] {
            assert!(
                verify_token_binding(&claims, weaker).is_err(),
                "a doubly-bound token must not be honoured on partial evidence: {weaker:?}"
            );
        }
    }

    /// A validator that can only check certificates must **refuse** a
    /// DPoP-bound token rather than pass it as unbound. This is rule 9's
    /// invariant applied to AXIAM's own narrower entry point, and it is the
    /// behaviour every SDK that cannot verify a proof must copy.
    #[test]
    fn a_certificate_only_validator_refuses_a_dpop_bound_token() {
        let claims = claims_with_cnf(Some(CnfClaim::from_dpop_thumbprint(JKT)));
        assert!(verify_certificate_binding(&claims, None).is_err());
        assert!(verify_certificate_binding(&claims, Some(TP)).is_err());

        // ...including when the token also carries a certificate binding it
        // *could* have checked. Half a conjunction is not the conjunction.
        let both = claims_with_cnf(Some(
            CnfClaim::from_certificate_thumbprint(TP).with_dpop_thumbprint(JKT),
        ));
        assert!(verify_certificate_binding(&both, Some(TP)).is_err());
    }

    #[test]
    fn the_dpop_confirmation_serializes_under_rfc_9449s_key() {
        let json = serde_json::to_string(&CnfClaim::from_dpop_thumbprint(JKT)).unwrap();
        assert_eq!(json, format!(r#"{{"jkt":"{JKT}"}}"#));

        let both = serde_json::to_string(
            &CnfClaim::from_certificate_thumbprint(TP).with_dpop_thumbprint(JKT),
        )
        .unwrap();
        assert_eq!(both, format!(r#"{{"x5t#S256":"{TP}","jkt":"{JKT}"}}"#));
    }

    #[test]
    fn a_dpop_bound_token_round_trips_through_a_real_jwt() {
        let config = test_config();
        let token = issue_client_credentials_token_bound(
            "oa_test",
            Uuid::new_v4(),
            Uuid::new_v4(),
            &[],
            &config,
            Some(CnfClaim::from_dpop_thumbprint(JKT)),
        )
        .expect("issue DPoP-bound token");

        let claims = validate_access_token(&token, &config).expect("validate").0;
        assert_eq!(
            claims.cnf.as_ref().and_then(CnfClaim::dpop_thumbprint),
            Some(JKT)
        );
        assert!(verify_token_binding(&claims, PresentedProofs::dpop(JKT)).is_ok());
        assert!(verify_token_binding(&claims, PresentedProofs::dpop(OTHER_JKT)).is_err());
    }

    /// A bound token must survive a real encode/decode round trip with the
    /// claim intact — the unit tests above operate on in-memory claims, which
    /// would not catch a `skip_serializing_if` that dropped the field.
    #[test]
    fn a_bound_token_round_trips_through_a_real_jwt() {
        let config = test_config();
        let token = issue_client_credentials_token_bound(
            "oa_test",
            Uuid::new_v4(),
            Uuid::new_v4(),
            &[],
            &config,
            Some(CnfClaim::from_certificate_thumbprint(TP)),
        )
        .expect("issue bound token");

        let claims = validate_access_token(&token, &config).expect("validate").0;
        assert_eq!(
            claims
                .cnf
                .as_ref()
                .and_then(CnfClaim::certificate_thumbprint),
            Some(TP)
        );
        assert!(verify_certificate_binding(&claims, Some(TP)).is_ok());
        assert!(verify_certificate_binding(&claims, Some(OTHER_TP)).is_err());
    }

    /// An unbound token must carry NO `cnf` key at all, not `"cnf":null`.
    /// A null would still be an unknown key to a strict resource server, and
    /// it would grow every token AXIAM has ever issued by six bytes for no
    /// reason.
    #[test]
    fn an_unbound_token_carries_no_cnf_key() {
        let config = test_config();
        let token = issue_access_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            &[],
            &config,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .expect("issue");
        let payload = token.split('.').nth(1).expect("payload");
        let decoded = URL_SAFE_NO_PAD.decode(payload).expect("b64");
        let json: serde_json::Value = serde_json::from_slice(&decoded).expect("json");
        assert!(
            json.get("cnf").is_none(),
            "an unbound token must not carry a cnf key at all, got {json}"
        );
    }
}
