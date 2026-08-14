//! OAuth2 client domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Which security posture a client is registered under (X5.1).
///
/// This is the FAPI "one switch". FAPI 2.0 is not a single feature but a
/// bundle of constraints — mandatory PAR, mandatory PKCE with `S256`,
/// mandatory strong client authentication, mandatory sender-constrained
/// tokens, and a refusal of every relaxation the base specs permit. Encoding
/// them as one profile rather than a dozen independent booleans means an
/// operator cannot register a client that is *nearly* FAPI, and a reviewer
/// can answer "is this client financial-grade?" by reading one field.
///
/// The same philosophy as the rate-limit postures: ordinary clients see no
/// behaviour change at all, because [`Standard`](Self::Standard) is the serde
/// default and every row written before schema v38 decodes to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ClientProfile {
    /// Everything AXIAM did before X5. No added requirements.
    #[default]
    Standard,
    /// FAPI 2.0 Security Profile (Final). See [`ClientProfile`] for what the
    /// switch turns on, and `axiam_oauth2::fapi` for where each constraint is
    /// enforced.
    Fapi2,
}

impl ClientProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Fapi2 => "fapi2",
        }
    }

    /// Parse a stored/wire value. `None` for anything unrecognised — a caller
    /// must fail closed rather than silently degrade an unknown profile to
    /// `Standard`, which would turn a typo into a downgrade.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "standard" => Some(Self::Standard),
            "fapi2" => Some(Self::Fapi2),
            _ => None,
        }
    }

    /// Whether this profile demands FAPI 2.0's constraint bundle.
    pub const fn is_fapi2(self) -> bool {
        matches!(self, Self::Fapi2)
    }
}

/// How a client proves its identity at the token endpoint (RFC 8705 §2,
/// OIDC Core §9 naming).
///
/// Only the methods AXIAM actually implements are representable. There is
/// deliberately no `none` variant: every AXIAM client is confidential today
/// (see `handle_authorization_code`), and adding a public-client value here
/// before the rest of the server understands one would let an operator
/// register a client whose authentication is silently skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    /// The shared secret in the request body (RFC 6749 §2.3.1). AXIAM's
    /// historical and default method.
    #[default]
    ClientSecretPost,
    /// PKI-based mutual TLS (RFC 8705 §2.1): the client presents a
    /// certificate issued by a CA the deployment's mTLS listener trusts, and
    /// AXIAM matches the *registered* expected subject DN or SAN against the
    /// certificate rustls already verified during the handshake.
    TlsClientAuth,
    /// Self-signed mutual TLS (RFC 8705 §2.2): the certificate chains to
    /// nothing, so the *certificate itself* is the registered credential —
    /// matched by its SHA-256 thumbprint.
    SelfSignedTlsClientAuth,
    /// Asymmetric client assertion (RFC 7523 §2.2, OIDC Core §9) — X5.1's
    /// second client-authentication family.
    ///
    /// The client signs a short-lived JWT with a private key whose public half
    /// AXIAM holds, either inline in [`OAuth2Client::jwks`] or published at
    /// [`OAuth2Client::jwks_uri`], and posts it as `client_assertion`. Unlike
    /// the mTLS methods this needs no transport-level cooperation at all,
    /// which is the whole reason FAPI 2.0 permits it: a client behind a
    /// TLS-terminating load balancer it does not control can still
    /// authenticate strongly.
    PrivateKeyJwt,
}

impl ClientAuthMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientSecretPost => "client_secret_post",
            Self::TlsClientAuth => "tls_client_auth",
            Self::SelfSignedTlsClientAuth => "self_signed_tls_client_auth",
            Self::PrivateKeyJwt => "private_key_jwt",
        }
    }

    /// Parse a stored/wire value. `None` for anything unrecognised — see
    /// [`ClientProfile::from_wire`] for why this does not default.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "client_secret_post" => Some(Self::ClientSecretPost),
            "tls_client_auth" => Some(Self::TlsClientAuth),
            "self_signed_tls_client_auth" => Some(Self::SelfSignedTlsClientAuth),
            "private_key_jwt" => Some(Self::PrivateKeyJwt),
            _ => None,
        }
    }

    /// Whether this method authenticates with a client certificate rather
    /// than a shared secret.
    pub const fn is_mtls(self) -> bool {
        matches!(self, Self::TlsClientAuth | Self::SelfSignedTlsClientAuth)
    }

    /// Whether this method authenticates with a signed client assertion
    /// (RFC 7523 §2.2).
    pub const fn is_private_key_jwt(self) -> bool {
        matches!(self, Self::PrivateKeyJwt)
    }

    /// Whether this method is one of the two client-authentication *families*
    /// FAPI 2.0 §5.3.1.1 permits.
    ///
    /// The distinction the profile actually draws is "proof of possession of a
    /// private key" versus "presentation of a shared secret", not
    /// method-by-method. Expressing it once here is what lets
    /// `axiam_oauth2::fapi` accept either family without enumerating methods at
    /// each call site — the mistake that would let a fourth method be added and
    /// silently fail the gate.
    pub const fn is_strong(self) -> bool {
        self.is_mtls() || self.is_private_key_jwt()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Client {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    /// HMAC-SHA256 hashed client secret.
    pub client_secret_hash: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    /// B5 — allow-list for RP-initiated logout's `post_logout_redirect_uri`.
    ///
    /// Deliberately separate from [`Self::redirect_uris`] rather than a reuse
    /// of it: one list receives an authorization code, the other receives a
    /// browser after a session has ended, and a deployment routinely wants the
    /// second to be a marketing page that must never be a code destination.
    ///
    /// `serde(default)` because rows written before schema v27 have no such
    /// field, and an empty allow-list is the correct reading of a client that
    /// never registered one — it means "no post-logout redirect is permitted",
    /// which is what the endpoint already does for an unrecognised URI.
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    /// B5 — where OIDC Back-Channel Logout tokens are POSTed for this client.
    /// `None` means the client does not participate; it is skipped rather than
    /// retried.
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    /// B5 — refuse a direct authorization request from this client, requiring
    /// it to push its parameters to `/oauth2/par` first (RFC 9126 §5). This is
    /// the per-client switch the FAPI profile turns on.
    #[serde(default)]
    pub require_par: bool,
    /// X5.1 — the FAPI switch. See [`ClientProfile`].
    #[serde(default)]
    pub profile: ClientProfile,
    /// X5.1 — how this client authenticates at the token endpoint.
    ///
    /// `serde(default)` resolves rows written before schema v38 to
    /// `client_secret_post`, which is exactly what they were doing.
    #[serde(default)]
    pub token_endpoint_auth_method: ClientAuthMethod,
    /// RFC 8705 §2.1.2 `tls_client_auth_subject_dn` — the expected subject
    /// distinguished name, in RFC 4514 string form, of the certificate a
    /// `tls_client_auth` client presents.
    ///
    /// RFC 8705 requires that **exactly one** of the `tls_client_auth_*`
    /// metadata parameters be registered, because two would create an
    /// ambiguity about which one authenticates. [`Self::mtls_binding_count`]
    /// is how that invariant is checked at registration time.
    #[serde(default)]
    pub tls_client_auth_subject_dn: Option<String>,
    /// RFC 8705 §2.1.2 `tls_client_auth_san_dns` — the expected dNSName SAN.
    #[serde(default)]
    pub tls_client_auth_san_dns: Option<String>,
    /// RFC 8705 §2.1.2 `tls_client_auth_san_uri` — the expected
    /// uniformResourceIdentifier SAN.
    #[serde(default)]
    pub tls_client_auth_san_uri: Option<String>,
    /// Certificate thumbprints accepted for `self_signed_tls_client_auth`,
    /// as base64url-encoded SHA-256 digests of the DER certificate — the same
    /// `x5t#S256` encoding RFC 8705 §3.1 uses for token binding.
    ///
    /// RFC 8705 §2.2 registers these as certificates inside the client's
    /// `jwks`/`jwks_uri`. AXIAM stores the thumbprint instead: the comparison
    /// the spec ultimately performs on a self-signed certificate is an
    /// equality check against a registered key, and a thumbprint is that
    /// check with no JWKS parser on the authentication path. The trade-off is
    /// recorded in the operator guide — it means AXIAM cannot rotate a
    /// self-signed client's certificate by having the client republish a
    /// `jwks_uri`; the new thumbprint must be registered. A list rather than a
    /// single value so a rotation can overlap.
    #[serde(default)]
    pub self_signed_tls_client_auth_thumbprints: Vec<String>,
    /// RFC 8705 §3.4 `tls_client_certificate_bound_access_tokens` — when set,
    /// tokens issued to this client carry a `cnf.x5t#S256` confirmation claim
    /// naming the certificate presented at the token endpoint, and are
    /// therefore usable only by the holder of that certificate's private key.
    ///
    /// Independent of [`Self::token_endpoint_auth_method`] on purpose: a
    /// client may authenticate with a secret over an mTLS connection and
    /// still want its tokens bound to the certificate it presented. The FAPI
    /// profile requires this to be true; nothing else does.
    #[serde(default)]
    pub tls_client_certificate_bound_access_tokens: bool,
    /// RFC 7591 `jwks` — the client's public key set, inline, as the raw JSON
    /// document.
    ///
    /// Stored as a string rather than a parsed structure so that a key type
    /// AXIAM does not implement round-trips through the database intact
    /// instead of failing to decode the whole client row. Parsing happens on
    /// the authentication path, where a failure is an authentication failure
    /// and nothing worse.
    ///
    /// Mutually exclusive with [`Self::jwks_uri`] (RFC 7591 §2): two key
    /// sources are two answers to "which keys authenticate this client", and
    /// the union of them is a credential nobody registered. The exclusivity is
    /// enforced by [`count_jwks_sources`] at registration, exactly as
    /// [`count_mtls_bindings`] enforces RFC 8705 §2.1.2's.
    #[serde(default)]
    pub jwks: Option<String>,
    /// RFC 7591 `jwks_uri` — where the client publishes its public key set.
    ///
    /// Fetched through `axiam_federation::jwks_cache::JwksCache`, which is the
    /// same TTL + stale-while-revalidate + SSRF-guarded path a federated IdP's
    /// JWKS goes through. A client-supplied URL AXIAM will fetch on demand is
    /// the same threat surface whichever feature asked for it, so it gets the
    /// same guard rather than a second one.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// RFC 9449 §5.2 `dpop_bound_access_tokens` — when set, tokens issued to
    /// this client carry a `cnf.jkt` confirmation naming the key that signed
    /// the DPoP proof presented at the token endpoint.
    ///
    /// The DPoP half of the sender-constraining row, and independent of
    /// [`Self::tls_client_certificate_bound_access_tokens`] for the same reason
    /// that flag is independent of the authentication method: RFC 9449 binds a
    /// token to a *key*, and which key that is has nothing to do with how the
    /// client proved its identity. A client may legitimately want both, and a
    /// token that carries both confirmations must satisfy both.
    #[serde(default)]
    pub dpop_bound_access_tokens: bool,
    /// Whether this client's DPoP proofs must carry a server-issued `nonce`
    /// (RFC 9449 §8).
    ///
    /// Server policy rather than client metadata in the RFC, but per-client
    /// here because the cost is per-client: a nonce turns every first request
    /// into two round trips, which a high-frequency IoT client feels and a
    /// browser-driven one does not. `false` — no nonce required — is the
    /// pre-v39 behaviour and the default, so turning DPoP on does not silently
    /// double anybody's request count.
    #[serde(default)]
    pub dpop_require_nonce: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// How many of the mutually exclusive `tls_client_auth_*` metadata parameters
/// are registered (RFC 8705 §2.1.2 permits exactly one).
///
/// A free function so that the registered client, a pending registration and a
/// merged update all count the same way. Three copies of this rule would be
/// three chances for the counter and the matcher to disagree about whether
/// `Some("")` is registered — and they must not, because the matcher's `else`
/// branch is reached exactly when the counter said one.
pub fn count_mtls_bindings(
    subject_dn: Option<&str>,
    san_dns: Option<&str>,
    san_uri: Option<&str>,
) -> usize {
    [subject_dn, san_dns, san_uri]
        .iter()
        .filter(|v| v.is_some_and(|s| !s.trim().is_empty()))
        .count()
}

/// How many of the mutually exclusive key sources a `private_key_jwt` client
/// registered (RFC 7591 §2 permits at most one).
///
/// A free function for the same reason [`count_mtls_bindings`] is: the pending
/// registration, the merged update and the stored row must agree on what counts
/// as registered, and a blank string must not count. If they disagreed, a
/// registration could pass validation with one source and then store zero,
/// leaving a client that can authenticate nothing — or two, leaving a client
/// whose credentials are the union of a document it controls and one it
/// publishes.
pub fn count_jwks_sources(jwks: Option<&str>, jwks_uri: Option<&str>) -> usize {
    [jwks, jwks_uri]
        .iter()
        .filter(|v| v.is_some_and(|s| !s.trim().is_empty()))
        .count()
}

impl OAuth2Client {
    /// See [`count_mtls_bindings`].
    pub fn mtls_binding_count(&self) -> usize {
        count_mtls_bindings(
            self.tls_client_auth_subject_dn.as_deref(),
            self.tls_client_auth_san_dns.as_deref(),
            self.tls_client_auth_san_uri.as_deref(),
        )
    }

    /// See [`count_jwks_sources`].
    pub fn jwks_source_count(&self) -> usize {
        count_jwks_sources(self.jwks.as_deref(), self.jwks_uri.as_deref())
    }

    /// Whether tokens issued to this client must carry a confirmation claim of
    /// *some* kind (X5.1).
    ///
    /// The FAPI profile requires sender-constrained tokens without caring which
    /// mechanism supplies the constraint, so the gate asks this rather than
    /// enumerating the two flags — which is what keeps a third mechanism from
    /// having to be added in two places.
    pub const fn is_sender_constrained(&self) -> bool {
        self.tls_client_certificate_bound_access_tokens || self.dpop_bound_access_tokens
    }
}

impl CreateOAuth2Client {
    /// See [`count_mtls_bindings`]. Used to validate a registration *before*
    /// it is written, so an impossible client is never created.
    pub fn mtls_binding_count(&self) -> usize {
        count_mtls_bindings(
            self.tls_client_auth_subject_dn.as_deref(),
            self.tls_client_auth_san_dns.as_deref(),
            self.tls_client_auth_san_uri.as_deref(),
        )
    }

    /// See [`count_jwks_sources`].
    pub fn jwks_source_count(&self) -> usize {
        count_jwks_sources(self.jwks.as_deref(), self.jwks_uri.as_deref())
    }
}

impl UpdateOAuth2Client {
    /// Whether this patch touches any field the security-profile rules read.
    ///
    /// The caller uses it to decide whether validating the update needs the
    /// stored row merged in. A patch that only renames a client cannot change
    /// whether the client satisfies its profile, so it should not pay for a
    /// read.
    pub fn touches_security_profile(&self) -> bool {
        self.profile.is_some()
            || self.token_endpoint_auth_method.is_some()
            || self.require_par.is_some()
            || self.tls_client_certificate_bound_access_tokens.is_some()
            || self.tls_client_auth_subject_dn.is_some()
            || self.tls_client_auth_san_dns.is_some()
            || self.tls_client_auth_san_uri.is_some()
            || self.self_signed_tls_client_auth_thumbprints.is_some()
            || self.jwks.is_some()
            || self.jwks_uri.is_some()
            || self.dpop_bound_access_tokens.is_some()
            || self.dpop_require_nonce.is_some()
    }
}

impl OAuth2Client {
    /// A copy of this client with `update`'s security-profile fields applied,
    /// for validating a patch against the row it will produce.
    ///
    /// Only the profile-relevant fields are merged — the result exists to be
    /// handed to `axiam_oauth2::fapi::validate_registration`, which reads
    /// nothing else, and merging the rest would invite the copy to be mistaken
    /// for the row that is about to be written.
    ///
    /// The empty-string "clear it" sentinel is honoured here exactly as the
    /// repository honours it, so validation sees the same DN/SAN the write
    /// will store. If these two disagreed, an update that clears the last
    /// `tls_client_auth_*` parameter would validate against the old value and
    /// then store a client that can authenticate nothing.
    pub fn with_update_applied(mut self, update: &UpdateOAuth2Client) -> Self {
        fn merge(current: Option<String>, patch: Option<&String>) -> Option<String> {
            match patch {
                None => current,
                Some(v) if v.trim().is_empty() => None,
                Some(v) => Some(v.clone()),
            }
        }

        if let Some(p) = update.profile {
            self.profile = p;
        }
        if let Some(m) = update.token_endpoint_auth_method {
            self.token_endpoint_auth_method = m;
        }
        if let Some(v) = update.require_par {
            self.require_par = v;
        }
        if let Some(v) = update.tls_client_certificate_bound_access_tokens {
            self.tls_client_certificate_bound_access_tokens = v;
        }
        self.tls_client_auth_subject_dn = merge(
            self.tls_client_auth_subject_dn,
            update.tls_client_auth_subject_dn.as_ref(),
        );
        self.tls_client_auth_san_dns = merge(
            self.tls_client_auth_san_dns,
            update.tls_client_auth_san_dns.as_ref(),
        );
        self.tls_client_auth_san_uri = merge(
            self.tls_client_auth_san_uri,
            update.tls_client_auth_san_uri.as_ref(),
        );
        if let Some(ref t) = update.self_signed_tls_client_auth_thumbprints {
            self.self_signed_tls_client_auth_thumbprints = t.clone();
        }
        self.jwks = merge(self.jwks, update.jwks.as_ref());
        self.jwks_uri = merge(self.jwks_uri, update.jwks_uri.as_ref());
        if let Some(v) = update.dpop_bound_access_tokens {
            self.dpop_bound_access_tokens = v;
        }
        if let Some(v) = update.dpop_require_nonce {
            self.dpop_require_nonce = v;
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOAuth2Client {
    pub tenant_id: Uuid,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub require_par: bool,
    /// X5.1 — see [`OAuth2Client::profile`].
    #[serde(default)]
    pub profile: ClientProfile,
    #[serde(default)]
    pub token_endpoint_auth_method: ClientAuthMethod,
    #[serde(default)]
    pub tls_client_auth_subject_dn: Option<String>,
    #[serde(default)]
    pub tls_client_auth_san_dns: Option<String>,
    #[serde(default)]
    pub tls_client_auth_san_uri: Option<String>,
    #[serde(default)]
    pub self_signed_tls_client_auth_thumbprints: Vec<String>,
    #[serde(default)]
    pub tls_client_certificate_bound_access_tokens: bool,
    /// X5.1 — see [`OAuth2Client::jwks`].
    #[serde(default)]
    pub jwks: Option<String>,
    /// X5.1 — see [`OAuth2Client::jwks_uri`].
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// X5.1 — see [`OAuth2Client::dpop_bound_access_tokens`].
    #[serde(default)]
    pub dpop_bound_access_tokens: bool,
    /// X5.1 — see [`OAuth2Client::dpop_require_nonce`].
    #[serde(default)]
    pub dpop_require_nonce: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateOAuth2Client {
    pub name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// `None` leaves the URI unchanged; `Some("")` clears it.
    ///
    /// The empty string is the sentinel rather than a nested `Option` because
    /// the latter needs a `double_option` serde helper (a new dependency) to
    /// survive a JSON round-trip, and an empty string is not a valid URI so it
    /// cannot collide with a real value. Without *some* way to say "clear it",
    /// a client could be given a back-channel logout URI and never have it
    /// removed — which is the one edit an operator makes when an RP is
    /// decommissioned.
    pub backchannel_logout_uri: Option<String>,
    pub require_par: Option<bool>,
    /// X5.1 — see [`OAuth2Client::profile`].
    pub profile: Option<ClientProfile>,
    pub token_endpoint_auth_method: Option<ClientAuthMethod>,
    /// `Some("")` clears, for the same reason
    /// [`Self::backchannel_logout_uri`] does — an empty DN/SAN is not a legal
    /// value, so it cannot collide with a real one, and without a way to say
    /// "clear it" a client migrated off mTLS would keep a stale expectation.
    pub tls_client_auth_subject_dn: Option<String>,
    pub tls_client_auth_san_dns: Option<String>,
    pub tls_client_auth_san_uri: Option<String>,
    pub self_signed_tls_client_auth_thumbprints: Option<Vec<String>>,
    pub tls_client_certificate_bound_access_tokens: Option<bool>,
    /// X5.1 — see [`OAuth2Client::jwks`]. `Some("")` clears, for the same
    /// reason [`Self::tls_client_auth_subject_dn`] does: without a way to say
    /// "clear it", a client migrated from an inline key set to a `jwks_uri`
    /// would keep both, and RFC 7591 permits at most one.
    pub jwks: Option<String>,
    /// X5.1 — see [`OAuth2Client::jwks_uri`]. `Some("")` clears.
    pub jwks_uri: Option<String>,
    /// X5.1 — see [`OAuth2Client::dpop_bound_access_tokens`].
    pub dpop_bound_access_tokens: Option<bool>,
    /// X5.1 — see [`OAuth2Client::dpop_require_nonce`].
    pub dpop_require_nonce: Option<bool>,
}

/// Represents a stored OAuth2 authorization code (short-lived, single-use).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    pub user_id: Uuid,
    pub code_hash: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// OIDC nonce — echoed back in the ID token.
    pub nonce: Option<String>,
    /// B5 — the AXIAM session this code was issued from, carried through to
    /// the token endpoint so the ID token can assert `sid`.
    ///
    /// `Option` because codes predating schema v28 have none, and because the
    /// value is genuinely absent on paths with no browser session behind them.
    #[serde(default)]
    pub session_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new authorization code.
#[derive(Debug, Clone)]
pub struct CreateAuthorizationCode {
    pub tenant_id: Uuid,
    pub client_id: String,
    pub user_id: Uuid,
    pub code_hash: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// OIDC nonce — stored with the code so it can be echoed in the ID token.
    pub nonce: Option<String>,
    /// B5 — the AXIAM session this code was issued from.
    pub session_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
}

/// Persisted refresh token (OAuth2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub token_hash: String,
    pub client_id: String,
    pub user_id: Option<Uuid>,
    pub scopes: Vec<String>,
    /// B5 — the AXIAM session this token descends from.
    ///
    /// Carried so that an ID token minted on refresh asserts the *same* `sid`
    /// the RP stored at login. Dropping it on refresh would leave an RP that
    /// only ever sees refreshed ID tokens unable to match a back-channel
    /// logout token to the session it holds.
    #[serde(default)]
    pub session_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new refresh token.
#[derive(Debug, Clone)]
pub struct CreateRefreshToken {
    pub tenant_id: Uuid,
    pub token_hash: String,
    pub client_id: String,
    pub user_id: Option<Uuid>,
    pub scopes: Vec<String>,
    /// B5 — see [`RefreshToken::session_id`].
    pub session_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Device Authorization Grant (RFC 8628) — B2
// ---------------------------------------------------------------------------

/// Where a device-authorization request has got to.
///
/// The transitions are `Pending → Approved | Denied → Redeemed`, and they are
/// one-way. `Redeemed` exists as a distinct state rather than being modelled by
/// deleting the row, because the difference between "this code was already
/// used" and "this code never existed" is what lets the token endpoint answer
/// a replay with `invalid_grant` instead of silently issuing a second token
/// set for one approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DeviceGrantStatus {
    /// Issued; the user has not acted yet. The token endpoint answers
    /// `authorization_pending`.
    Pending,
    /// The user approved. The next token poll redeems it.
    Approved,
    /// The user explicitly refused. Distinct from `Pending` so the device can
    /// stop polling immediately (`access_denied`) rather than waiting out the
    /// expiry.
    Denied,
    /// Already exchanged for tokens. Terminal.
    Redeemed,
}

impl DeviceGrantStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Redeemed => "redeemed",
        }
    }

    /// Parse a stored value. `None` for anything unrecognised — the caller
    /// must fail closed rather than default to a state that grants access.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            "redeemed" => Some(Self::Redeemed),
            _ => None,
        }
    }
}

/// A pending device authorization (RFC 8628 §3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceGrant {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    /// SHA-256 of the device code. The raw code is returned once and never
    /// stored — same posture as refresh tokens and authorization codes.
    pub device_code_hash: String,
    /// The short code the human types. Stored in normalised form (see
    /// `axiam_oauth2::device`), because a user typing `WXYZ-1234` and
    /// `wxyz1234` means the same thing and must not be a lookup miss.
    pub user_code: String,
    pub scopes: Vec<String>,
    pub status: DeviceGrantStatus,
    /// The user who approved. `None` while pending or denied.
    pub user_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    /// Minimum seconds the device must wait between polls (RFC 8628 §3.5).
    /// Raised by `slow_down`.
    pub interval_secs: u64,
    /// When the device last polled, for interval enforcement.
    pub last_polled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a device grant.
#[derive(Debug, Clone)]
pub struct CreateDeviceGrant {
    pub tenant_id: Uuid,
    pub client_id: String,
    pub device_code_hash: String,
    pub user_code: String,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub interval_secs: u64,
}

/// A pushed authorization request (RFC 9126, B5).
///
/// The client POSTs its authorization parameters to `/oauth2/par` — where it
/// authenticates — and receives an opaque `request_uri` to hand to the
/// browser in place of them. The parameters never travel through the user
/// agent, so they cannot be tampered with in transit or logged by anything
/// between the browser and AXIAM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushedAuthRequest {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    /// SHA-256 of the `request_uri`'s random component. The plaintext is a
    /// bearer credential for the 60 s it lives, so it is never stored — the
    /// same posture as device codes and refresh tokens.
    pub request_uri_hash: String,
    /// The pushed authorization parameters, verbatim.
    pub params: PushedAuthParams,
    /// Set on first use. The row is marked rather than deleted so that
    /// "already used" and "never existed" stay distinguishable in an audit
    /// trail, even though both answer `invalid_request` on the wire.
    pub consumed: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// The authorization parameters carried by a pushed request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PushedAuthParams {
    pub response_type: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

/// Input for creating a pushed authorization request.
#[derive(Debug, Clone)]
pub struct CreatePushedAuthRequest {
    pub tenant_id: Uuid,
    pub client_id: String,
    pub request_uri_hash: String,
    pub params: PushedAuthParams,
    pub expires_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Session/client participation — back-channel logout (B5)
// ---------------------------------------------------------------------------

/// A record that `client_id` participated in `session_id`.
///
/// Written when an authorization code is issued, which is the moment a client
/// actually joins the session. Back-channel logout iterates these rather than
/// every client in the tenant: broadcasting to clients that were never part of
/// the session would tell them a session they had no involvement in just
/// ended.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClient {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub client_id: String,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// Input for recording participation.
#[derive(Debug, Clone)]
pub struct CreateSessionClient {
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub client_id: String,
    pub user_id: Uuid,
}
