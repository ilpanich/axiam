//! Authentication configuration.

use std::sync::Arc;

use jsonwebtoken::{DecodingKey, EncodingKey};
use secrecy::SecretString;
use serde::Deserialize;

fn default_true() -> bool {
    true
}

/// What is wrong with `AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID`, in terms that
/// name no part of the value (T-244).
///
/// Rendered into one boot-time `WARN` by the composition root. It describes
/// the value's **shape** — how long it is, and whether its characters could
/// belong to a UUID at all — because those two facts distinguish the mistakes
/// an operator actually makes (a truncated paste, a tenant *slug* where an id
/// belongs, a different identifier entirely) without echoing anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultTenantProblem {
    /// Character count of the trimmed value. A UUID is 36.
    pub length: usize,
    /// A short phrase describing the character class.
    pub shape: &'static str,
}

impl std::fmt::Display for DefaultTenantProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} characters, {}", self.length, self.shape)
    }
}

/// The path segment that separates a deployment's root issuer from a tenant
/// identifier under the T21.6 per-tenant issuer form: `{root}/t/{tenant_id}`.
///
/// One constant rather than three string literals, because the value appears
/// in an issuer this module builds, in the routes `axiam-api-rest` mounts and
/// in the `PUBLIC_PATHS` entries that must agree with them. A deployment that
/// built issuers with one spelling and routed the other would publish a
/// discovery document naming endpoints it does not serve.
///
/// `/t/` rather than `/tenants/` or `/realms/`: it is short enough that the
/// three RFC 8414 §3 discovery forms stay readable, and it collides with no
/// path AXIAM already serves.
pub const TENANT_PATH_PREFIX: &str = "/t/";

/// Configuration for the authentication service.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// PEM-encoded Ed25519 private key for JWT signing.
    pub jwt_private_key_pem: String,
    /// PEM-encoded Ed25519 public key for JWT verification.
    pub jwt_public_key_pem: String,
    /// Trust an `X-Client-Certificate` request header as proof of device
    /// identity when the connection carries no TLS-verified client
    /// certificate. Default **`false`**.
    ///
    /// # Why this is off by default
    ///
    /// The header carries a PEM certificate, and a certificate is public data.
    /// `DeviceAuthService::authenticate` checks the fingerprint, the status,
    /// the expiry and the chain up to the tenant or organization CA — every one
    /// of which a *copy* of an enrolled device's certificate also satisfies.
    /// Nothing in that path proves the sender holds the private key, because
    /// nothing can: possession is proven by the TLS handshake, and on this path
    /// there was no handshake to prove it in.
    ///
    /// That is sound only while the header cannot originate with the client —
    /// i.e. a reverse proxy performs the mTLS handshake itself and
    /// unconditionally overwrites the header on every request it forwards.
    /// It stops being sound the moment the server is reachable by anything but
    /// that proxy, where anyone holding a copy of a device certificate
    /// authenticates as that device.
    ///
    /// Native mTLS is unaffected and always preferred: when rustls verified a
    /// client certificate on the connection, that certificate is authoritative
    /// and this setting is not consulted.
    ///
    /// Set it to `true` only if all of the following hold, and say so in your
    /// runbook:
    ///
    /// 1. TLS (and the client-certificate handshake) terminates at a proxy you
    ///    operate;
    /// 2. that proxy sets `X-Client-Certificate` from the certificate **it**
    ///    verified, on every request, overwriting anything the client sent;
    /// 3. nothing else can reach this server's listener.
    pub trust_forwarded_client_cert: bool,
    /// Access token lifetime in seconds (default: 900 = 15 minutes).
    pub access_token_lifetime_secs: u64,
    /// Refresh token lifetime in seconds (default: 2_592_000 = 30 days).
    pub refresh_token_lifetime_secs: u64,
    /// Authorization code lifetime in seconds (default: 600 = 10 minutes).
    pub auth_code_lifetime_secs: u64,
    /// JWT issuer (`iss` claim).
    pub jwt_issuer: String,
    /// OIDC issuer base URL (e.g. "https://auth.example.com"). Used for
    /// OIDC discovery endpoint URLs. Falls back to `jwt_issuer` if unset.
    pub oauth2_issuer_url: String,
    /// Base URL of the listener that performs the mutual-TLS handshake, when
    /// that is a different host or port from
    /// [`effective_issuer`](Self::effective_issuer)
    /// (`AXIAM__AUTH__OAUTH2_MTLS_BASE_URL`). Empty by default.
    ///
    /// Setting it makes the discovery document carry RFC 8705 §5
    /// `mtls_endpoint_aliases`; leaving it empty omits the member entirely,
    /// which is what the RFC asks of a server with nothing to alias.
    ///
    /// # Why a separate URL is needed at all
    ///
    /// A TLS listener decides whether to request a client certificate during
    /// the handshake, before it has seen a single byte of HTTP. So "ask for a
    /// certificate on `/oauth2/token` but not on `/oauth2/authorize`" is not a
    /// thing a listener can do — the choice is per-listener, and a deployment
    /// that wants both a browser-facing authorization endpoint and a
    /// certificate-authenticated token endpoint has to run two of them.
    ///
    /// Which leaves the client with a question metadata alone could not answer
    /// before RFC 8705 §5: the discovery document names one `token_endpoint`,
    /// and a client doing mTLS needs the *other* one. The aliases are that
    /// answer — the same endpoints, re-based on the host that will ask for a
    /// certificate.
    ///
    /// # When to leave it empty
    ///
    /// Two deployments should, and neither is unusual:
    ///
    /// - **`client_auth = optional` on a single listener.** rustls requests a
    ///   certificate and accepts a connection without one, so the conventional
    ///   endpoints already serve both populations and there is no second URL
    ///   to point at. This is the shape `scripts/e2e-mtls-native-check.sh`
    ///   exercises.
    /// - **`client_auth = required` on a single listener.** Every endpoint is
    ///   already behind the handshake; an alias would name the URL the client
    ///   is using.
    ///
    /// Set it only when mTLS genuinely terminates somewhere else — typically a
    /// second proxy hostname such as `https://mtls.iam.example.com` in front of
    /// the same server.
    ///
    /// # What it must be
    ///
    /// An absolute URL, validated where the document is built. A value that is
    /// not parseable fails the discovery request rather than being dropped:
    /// silently omitting the aliases would send an mTLS client to the
    /// conventional endpoints, which is the one outcome this setting exists to
    /// prevent.
    pub oauth2_mtls_base_url: String,
    /// The tenant a discovery document describes when the caller named none
    /// (`AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID`). Empty by default.
    ///
    /// # What it fixes
    ///
    /// Every OAuth2 endpoint that authenticates a *client* — token, PAR,
    /// introspection, revocation, device authorization, end-session — takes a
    /// **required** `tenant_id` query parameter, and `/oauth2/authorize` needs
    /// one for any request without a principal, which is every browser. The
    /// discovery document published none of them, so a relying party that did
    /// exactly what OIDC Discovery tells it to do — read the document, use the
    /// URLs — got `400 missing field tenant_id` at the token endpoint. The
    /// first OpenID Foundation conformance run could not complete a single
    /// authorization for this reason.
    ///
    /// Setting this makes the **bare** document publish endpoint URLs carrying
    /// the tenant, which is the deployment shape an OP is certified as: one
    /// issuer, one tenant. A document fetched with an explicit `?tenant_id=`
    /// carries that tenant instead, and this value is not consulted.
    ///
    /// # What it does NOT do
    ///
    /// It changes no endpoint's behaviour. A request that arrives without
    /// `tenant_id` is refused exactly as it is today — this is a statement in a
    /// document, not a fallback in a handler. That distinction is deliberate:
    /// a default applied at the endpoint would silently give an
    /// unparameterised request a tenant, and on a multi-tenant authorization
    /// server the tenant is the isolation boundary. Leaving it empty is
    /// therefore safe and is the correct setting for a deployment that serves
    /// many tenants from one issuer.
    pub oauth2_default_tenant_id: String,
    /// T21.6 — whether this deployment serves the per-tenant **path** issuer
    /// form `{root}/t/{tenant_id}` (`AXIAM__AUTH__TENANT_ISSUER_PATHS`).
    ///
    /// `false` by default, and with it false nothing about this deployment
    /// changes: the `/t/{tenant_id}` scope and the three tenant discovery
    /// routes are not mounted, no token can carry a tenant issuer, and
    /// [`Self::accepts_issuer`] answers exactly what the pinned-issuer check
    /// answered before this field existed.
    ///
    /// # What it is for
    ///
    /// RFC 8414 §2 forbids a query component in an issuer identifier, so the
    /// deployment-wide issuer plus `?tenant_id=` cannot be published as the
    /// issuer of one tenant. An MCP server naming AXIAM in its RFC 9728
    /// `authorization_servers` therefore has no way to point a client at
    /// anything but the default tenant. The path form is an issuer a client
    /// can turn into a discovery URL by the RFC 8414 §3 rule with no query at
    /// all.
    ///
    /// The tenant path is **derived, never configured**: a deployment sets a
    /// root issuer, and `{root}/t/{tenant_id}` follows from it.
    pub tenant_issuer_paths: bool,
    /// T21.6 — the issuer the **current request** arrived under, when it
    /// arrived on a per-tenant path.
    ///
    /// `None` on every request that is not on a `/t/{tenant_id}` path, which
    /// is every request on a deployment with [`Self::tenant_issuer_paths`]
    /// off. It is set only by cloning a deployment config through
    /// [`Self::for_tenant_path`], never by configuration — hence `serde(skip)`:
    /// an operator cannot set a per-request value from the environment, and an
    /// environment that appeared to offer one would be offering a way to
    /// forge `iss`.
    ///
    /// [`Self::effective_issuer`] answers this when it is set, which is what
    /// makes every `iss` a request mints — access token, ID token, logout
    /// token, the RFC 9207 response parameter — the tenant issuer without any
    /// of the four minting sites learning that tenant paths exist.
    /// [`Self::root_issuer`] answers the deployment's issuer regardless, and
    /// is what every **validation** decision reads.
    #[serde(skip)]
    pub request_issuer: Option<String>,
    /// T-39/T-143 — whether this deployment publishes
    /// `GET /oauth2/revocations`.
    ///
    /// `AXIAM__AUTH__REVOCATION_FEED_ENABLED`, default `false`. With it off the
    /// route is not mounted and no `revoked_session` row is written, so the
    /// deployment is byte-identical to one built before the feed existed.
    ///
    /// The feed narrows the window in which a revoked session's access token
    /// still verifies — from one token lifetime to one poll interval — for an
    /// SDK guard that opts into polling it. It is never a control: a guard
    /// that cannot fetch it behaves exactly as it does today, and the token
    /// itself still decides.
    #[serde(default)]
    pub revocation_feed_enabled: bool,
    /// Extra browser origins this deployment will hand a **federation SSO
    /// handoff code** to (`AXIAM__AUTH__SSO_SPA_ORIGINS`; a list, set the same
    /// way as `AXIAM__SERVER__CORS_ALLOWED_ORIGINS`).
    ///
    /// # Why this exists
    ///
    /// SAML and Apple return by cross-site form POST, so the session cookies
    /// cannot be set on that response. AXIAM instead mints a single-use handoff
    /// code and redirects the browser to the SPA with it — and that code is a
    /// bearer credential for a session. The redirect target therefore may not
    /// be whatever the caller of the *unauthenticated* login-start endpoint
    /// asked for: on those two protocols the identity provider never sees the
    /// SPA `redirect_uri`, so its own registered-redirect allowlist is not
    /// there to reject an attacker's host.
    ///
    /// The default is empty, which means **the origin of
    /// [`effective_issuer`](Self::effective_issuer) only**. That is the right
    /// default rather than a restrictive one: the endpoint a SAML IdP or Apple
    /// posts to is itself built from `effective_issuer`, so a deployment whose
    /// SPA is served from that origin — the shape `docker/nginx.conf` and the
    /// deployment guides describe, and the only shape in which
    /// `SameSite=Strict` session cookies work same-origin — needs no entry
    /// here at all.
    ///
    /// Set it when the SPA is served from a different host than the API (for
    /// example `https://app.example.com` against `https://api.example.com`).
    /// Values are compared as **origins**: scheme, host and port, with the path
    /// ignored — so `https://app.example.com` does not admit
    /// `https://app.example.com:8443`.
    ///
    /// # Since R-3: all four flows, not two
    ///
    /// This used to have no effect on the OIDC and OAuth2 flows, whose
    /// `redirect_uri` is registered at the provider and checked there. It now
    /// governs those two as well. The provider's check is a real control, but
    /// only as strict as each provider's registration hygiene — several accept
    /// wildcard or prefix registrations — and it is not a control AXIAM owns or
    /// can inspect; it stays as a second, independent layer behind this one.
    ///
    /// **This is the one thing R-3 can break.** A deployment whose SPA lives on
    /// an origin other than the issuer's, signing in through OIDC or OAuth2
    /// providers, worked without this variable and now needs it — the same
    /// requirement the SAML and Apple flows have imposed since beta08. The
    /// shipped same-origin topology needs nothing. The `400` names this
    /// variable, so the failure says what to set.
    pub sso_spa_origins: Vec<String>,
    /// Optional pepper prepended to passwords before Argon2id verification.
    /// Wrapped in `SecretString` so `Debug`/logging never leaks it by
    /// accident (SECHRD-12) — exposed only via `.expose_secret()` at the
    /// `&str` boundary where a pepper value is consumed.
    pub pepper: Option<SecretString>,
    /// Previous pepper, kept **verify-only** while a pepper rotation drains
    /// (`AXIAM__AUTH__PEPPER_PREVIOUS`, §13.4 observation 3).
    ///
    /// Client-secret hashes are keyed by the pepper, and the `v2.hs256$` tag
    /// versions the *algorithm*, not the *key* — so without this, rotating
    /// `AXIAM__AUTH__PEPPER` permanently invalidates **every** client secret and
    /// every service account and OAuth2 client has to be re-issued in lockstep
    /// with the restart.
    ///
    /// Set this to the outgoing value for the duration of a rotation. Secrets
    /// hashed under it still verify, and each one is transparently rewritten
    /// under the new pepper the first time its owner authenticates, so the
    /// rotation drains itself. Unset it once the fleet has drained; nothing is
    /// ever *written* under this key.
    ///
    /// It does **not** apply to Argon2id password peppering, which has its own
    /// migration story — only to client-secret hashing.
    pub pepper_previous: Option<SecretString>,
    /// Minimum password length for policy enforcement.
    pub min_password_length: usize,
    /// 256-bit AES-GCM key for encrypting TOTP secrets at rest.
    /// `None` disables MFA enrollment. Set programmatically (not from config files).
    #[serde(skip)]
    pub mfa_encryption_key: Option<[u8; 32]>,
    /// 256-bit AES-GCM key for encrypting federation client secrets at rest.
    /// `None` means federation config create/update will fail at runtime.
    /// Set programmatically from `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` (not from
    /// config files). Federation is optional — absence is warned, not fatal.
    #[serde(skip)]
    pub federation_encryption_key: Option<[u8; 32]>,
    /// 256-bit AES-GCM key that seals an OPAQUE exchange's server state
    /// between its two messages, on both the login and the registration path.
    ///
    /// `None` means the OPAQUE endpoints answer `503`, whatever the org or
    /// tenant policy says. That is deliberate: silently falling back to
    /// password login when the key is missing would turn a misconfiguration
    /// into an undetectable downgrade of a security control an operator
    /// believes is on.
    ///
    /// Deliberately its own key rather than a reuse of
    /// [`Self::mfa_encryption_key`]: the two rotate on different schedules, and
    /// sharing one would couple an OPAQUE outage to an unrelated TOTP
    /// rotation. Set from `AXIAM__AUTH__OPAQUE_SESSION_KEY` (not from config
    /// files).
    ///
    /// Rotating this is cheap — it invalidates exchanges in flight and nothing
    /// else. Contrast [`Self::opaque_setup_key`], which is the expensive one.
    #[serde(skip)]
    pub opaque_session_key: Option<[u8; 32]>,
    /// 256-bit AES-GCM key that encrypts each tenant's OPAQUE server key
    /// material — the OPRF seed and the long-term AKE key pair — at rest.
    ///
    /// `None` means the OPAQUE endpoints answer `503`, for the same reason as
    /// above.
    ///
    /// This is a **separate key from [`Self::opaque_session_key`] on purpose**,
    /// and the reason is what rotating each one costs. The session key seals
    /// 120 seconds of in-flight state and can be rotated on any schedule.
    /// This key protects data at rest: rotating it means re-encrypting every
    /// `opaque_server_setup` row, and **losing** it means every registration
    /// record in every tenant becomes unopenable and the whole estate needs a
    /// password reset. Sharing one key would put the cheap rotation and the
    /// catastrophic one on the same schedule, which is how an operator ends up
    /// doing neither. Set from `AXIAM__AUTH__OPAQUE_SETUP_KEY`.
    #[serde(skip)]
    pub opaque_setup_key: Option<[u8; 32]>,
    /// When `true`, access tokens decoded without an `aud` claim are treated as
    /// `axiam:user`. Enables a back-compat window during the Phase 4 rollout
    /// while pre-Phase-4 tokens are still circulating. Default: `true`.
    #[serde(default = "default_true")]
    pub allow_missing_aud_as_user: bool,
    /// When `true` (default), all auth cookies are marked `Secure` and are
    /// therefore sent only over HTTPS. Set `AXIAM__AUTH__COOKIE_SECURE=false`
    /// **only** in local HTTP development (e.g. http://localhost) — **never**
    /// in production or staging (D-18).
    #[serde(default = "default_true")]
    pub cookie_secure: bool,
    /// MFA challenge token lifetime in seconds (default: 300 = 5 minutes).
    pub mfa_challenge_lifetime_secs: u64,
    /// Issuer name shown in authenticator apps.
    pub totp_issuer: String,
    /// Max consecutive failed login attempts before lockout (default: 5).
    pub max_failed_login_attempts: u32,
    /// Initial lockout duration in seconds (default: 900 = 15 min).
    pub lockout_duration_secs: u64,
    /// Exponential backoff multiplier for repeated lockouts (default: 2.0).
    pub lockout_backoff_multiplier: f64,
    /// Maximum lockout duration in seconds (default: 3600 = 1 hour).
    pub max_lockout_duration_secs: u64,
    /// Grace period in hours during which PendingVerification users
    /// can still log in (default: 24). Set to 0 to disable.
    pub email_verification_grace_period_hours: u32,
    /// Password reset token expiry in hours (default: 1).
    pub password_reset_token_expiry_hours: u32,
    /// WebAuthn Relying Party ID (typically the domain name,
    /// e.g. "auth.example.com").
    pub webauthn_rp_id: String,
    /// WebAuthn Relying Party origin
    /// (e.g. "https://auth.example.com").
    pub webauthn_rp_origin: String,
    /// WebAuthn Relying Party display name.
    pub webauthn_rp_name: String,
    /// CQ-B14: Pre-parsed Ed25519 signing key. Populated once at startup via
    /// `resolve_keys()`. When `Some`, token-issue functions skip PEM re-parsing.
    /// When `None`, they fall back to parsing from `jwt_private_key_pem`.
    #[serde(skip)]
    pub jwt_encoding_key: Option<Arc<EncodingKey>>,
    /// CQ-B14: Pre-parsed Ed25519 verification key. Populated once at startup via
    /// `resolve_keys()`. When `Some`, token-verify functions skip PEM re-parsing.
    /// When `None`, they fall back to parsing from `jwt_public_key_pem`.
    #[serde(skip)]
    pub jwt_decoding_key: Option<Arc<DecodingKey>>,
    /// PERF-01: Consecutive HIBP failures/timeouts before the process-wide
    /// `HibpBreaker` trips open (default: 5). Overridable via
    /// `AXIAM__AUTH__HIBP_BREAKER_THRESHOLD`.
    pub hibp_breaker_threshold: u32,
    /// PERF-01: Cooldown in seconds the `HibpBreaker` stays open before
    /// allowing a half-open probe request (default: 30). Overridable via
    /// `AXIAM__AUTH__HIBP_BREAKER_COOLDOWN_SECS`.
    pub hibp_breaker_cooldown_secs: u64,
    /// B1: Maximum number of Argon2id hash/verify operations allowed to run
    /// concurrently, enforced by the process-wide `crypto_semaphore` shared
    /// across the login, password-change, password-reset and PKI crypto paths.
    ///
    /// Each in-flight Argon2id operation allocates a ~19 MiB memory arena
    /// (OWASP params m=19456), so unbounded concurrency is an unauthenticated
    /// memory-DoS vector: the login benchmark pegged 2 cores and reached
    /// ~970 MiB RSS ≈ 50 concurrent × 19 MiB arenas, against a 1024 MiB
    /// container cap. This permit count bounds peak concurrent arenas.
    ///
    /// `0` means "auto" and resolves to `min(available_parallelism, 4)` at
    /// semaphore-construction time (see [`AuthConfig::resolved_max_concurrent_hashes`]).
    /// Override via `AXIAM__AUTH__MAX_CONCURRENT_HASHES`.
    pub max_concurrent_hashes: usize,
    /// B1: How long (in seconds) a request waits to acquire a crypto-hash
    /// permit before giving up and returning a `ServiceUnavailable` (HTTP 503)
    /// backpressure error, instead of queueing unboundedly and adding to
    /// tail latency. Default: 5. Override via
    /// `AXIAM__AUTH__HASH_ACQUIRE_TIMEOUT_SECS`.
    pub hash_acquire_timeout_secs: u64,
    /// I6: TTL, in seconds, of the process-local **session-validation cache**.
    ///
    /// `0` (the default) disables the cache entirely — every authenticated
    /// request performs its own SurrealDB read to confirm the session behind the
    /// access token's `jti` still exists (D-15 / REQ-7). A non-zero value lets
    /// repeated requests inside the window reuse the last positive answer.
    ///
    /// Override via `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS`.
    ///
    /// # What it buys and what it costs
    ///
    /// The read it removes is the reason the D7 decision cache helped gRPC
    /// authorization checks 13.1× but REST checks only 5% in benchmark run 4:
    /// the decision cache elides the *authorization* round-trips, this one
    /// elides the *authentication* round-trip, and the gRPC surface never had
    /// the latter.
    ///
    /// The cost is a bounded revocation window. Every session-deleting path in
    /// `SurrealSessionRepository` invalidates the cache in the same call, so on
    /// a **single replica** a logout takes effect immediately. Across **two or
    /// more replicas** there is no invalidation channel, so a session revoked on
    /// replica A stays acceptable on replicas B…N for at most this many
    /// seconds — the same trade-off, and the same reasoning, as
    /// `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS`. Session *expiry* is not
    /// affected: cached entries carry the row's own `expires_at` and are
    /// rejected exactly on time regardless of the TTL.
    ///
    /// Suggested starting point when enabling: `5`, matching the decision
    /// cache's default.
    pub session_validation_cache_ttl_secs: u64,
}

impl AuthConfig {
    /// Effective issuer for JWT `iss` claims and OIDC discovery.
    ///
    /// Returns `oauth2_issuer_url` when set, falling back to
    /// `jwt_issuer`. Trailing slashes are stripped so that the
    /// OIDC discovery `issuer` exactly matches token `iss` claims
    /// (OIDC Core §2 requires an exact string match).
    pub fn effective_issuer(&self) -> &str {
        // T21.6 — the per-request tenant issuer wins when there is one, and
        // there is one only on a `/t/{tenant_id}` request. Every caller that
        // *stamps* an `iss` reads this and is therefore correct on both path
        // forms without knowing either exists; every caller that *checks* one
        // reads `root_issuer` instead.
        if let Some(ref issuer) = self.request_issuer {
            return issuer.trim_end_matches('/');
        }
        self.root_issuer()
    }

    /// The deployment's own issuer, ignoring any per-request tenant issuer
    /// (T21.6).
    ///
    /// Identical to [`Self::effective_issuer`] on every request that is not on
    /// a `/t/{tenant_id}` path, which is every request on a deployment with
    /// [`Self::tenant_issuer_paths`] off.
    ///
    /// This is the value every **validation** decision is derived from. The
    /// distinction matters exactly once and it is load-bearing: the set of
    /// issuers AXIAM accepts must be a property of the deployment, so a
    /// request that arrived under tenant `A` cannot narrow — or widen — what
    /// counts as a valid `iss`.
    #[must_use]
    pub fn root_issuer(&self) -> &str {
        if self.oauth2_issuer_url.is_empty() {
            self.jwt_issuer.trim_end_matches('/')
        } else {
            self.oauth2_issuer_url.trim_end_matches('/')
        }
    }

    /// The issuer identifier of one tenant under the T21.6 path form, or
    /// `None` when this deployment does not serve it.
    ///
    /// `{root}/t/{tenant_id}`, with no query and no fragment — which is what
    /// RFC 8414 §2 requires of an issuer and what the `?tenant_id=` form could
    /// never be.
    #[must_use]
    pub fn tenant_issuer(&self, tenant_id: uuid::Uuid) -> Option<String> {
        if !self.tenant_issuer_paths {
            return None;
        }
        Some(format!(
            "{}{}{}",
            self.root_issuer(),
            TENANT_PATH_PREFIX,
            tenant_id
        ))
    }

    /// This config, as seen by a request that arrived under tenant
    /// `tenant_id`'s path (T21.6).
    ///
    /// A clone rather than a mutation, and a clone rather than a borrow of a
    /// shared cell: the deployment config is shared by every concurrent
    /// request, and the one thing that must never happen is a request on the
    /// root path minting an `iss` a neighbouring tenant-path request put
    /// there. The cost is a handful of small allocations on a path that is
    /// about to sign a token.
    ///
    /// `None` when this deployment does not serve tenant paths, so a caller
    /// cannot manufacture a tenant issuer on a deployment that has not opted
    /// in.
    #[must_use]
    pub fn for_tenant_path(&self, tenant_id: uuid::Uuid) -> Option<Self> {
        let issuer = self.tenant_issuer(tenant_id)?;
        Some(Self {
            request_issuer: Some(issuer),
            ..self.clone()
        })
    }

    /// Is `iss` an issuer identifier this deployment mints under?
    ///
    /// With [`Self::tenant_issuer_paths`] off this is `iss == root_issuer()`,
    /// which is exactly the set `jsonwebtoken`'s pinned-issuer check accepted
    /// before T21.6 — so the default deployment's answer is unchanged.
    ///
    /// With it on the set is the root issuer **and** every `{root}/t/{uuid}`.
    /// Three properties of that widening are worth stating, because each one
    /// is a way it could have gone wrong:
    ///
    /// * the tenant segment must parse as a UUID, so `{root}/t/../admin`,
    ///   `{root}/t/` and `{root}/t/a%2Fb` are all refused rather than
    ///   normalised;
    /// * nothing is accepted **after** the tenant segment, so
    ///   `{root}/t/{uuid}/anything` is not an issuer;
    /// * the comparison is on the exact string, with no trailing-slash or
    ///   case folding — OIDC Core §2 requires `iss` to match the discovery
    ///   document's `issuer` exactly, and a comparison that is more forgiving
    ///   than the specification is one an attacker gets to choose the input to.
    ///
    /// Widening the accepted `iss` set does **not** widen the accepted `aud`
    /// set (I3): the audience check is a separate decision in
    /// [`crate::token::decode_access_token`] and stays pinned to the two
    /// built-in audiences.
    #[must_use]
    pub fn accepts_issuer(&self, iss: &str) -> bool {
        let root = self.root_issuer();
        if iss == root {
            return true;
        }
        if !self.tenant_issuer_paths {
            return false;
        }
        self.tenant_of_issuer(iss).is_some()
    }

    /// The tenant a `{root}/t/{uuid}` issuer names, or `None` when `iss` is
    /// not one (T21.6).
    ///
    /// `None` for the root issuer too: the root issuer names no tenant, which
    /// is the whole reason the path form exists.
    #[must_use]
    pub fn tenant_of_issuer(&self, iss: &str) -> Option<uuid::Uuid> {
        if !self.tenant_issuer_paths {
            return None;
        }
        let rest = iss.strip_prefix(self.root_issuer())?;
        let tenant = rest.strip_prefix(TENANT_PATH_PREFIX)?;
        uuid::Uuid::parse_str(tenant).ok()
    }

    /// The mTLS listener's base URL, or `None` when this deployment has no
    /// separate one (RFC 8705 §5).
    ///
    /// Trailing slashes are stripped for the same reason
    /// [`effective_issuer`](Self::effective_issuer) strips them: the value is
    /// concatenated with endpoint paths, and `https://host//oauth2/token` is a
    /// different URL from the one the operator meant.
    ///
    /// A value that is entirely whitespace answers `None` rather than `Some("")`
    /// — an empty alias base would produce relative alias URLs, which RFC 8705
    /// §5 does not permit and no client would resolve the way the operator
    /// intended.
    /// The configured default tenant, when one is set and parses as a UUID.
    ///
    /// An unparseable value is treated as unset rather than as an error: this
    /// is consulted while building a *public, unauthenticated* document, and a
    /// deployment whose operator fat-fingered the UUID should serve the
    /// document it served before the setting existed rather than 500 for every
    /// relying party. The mis-set value is visible in the document by its
    /// absence, and `mtls_base_url` takes the opposite view for the opposite
    /// reason — a bad alias actively misdirects a client, a missing tenant only
    /// fails to help one.
    #[must_use]
    pub fn default_tenant_id(&self) -> Option<uuid::Uuid> {
        let trimmed = self.oauth2_default_tenant_id.trim();
        if trimmed.is_empty() {
            return None;
        }
        uuid::Uuid::parse_str(trimmed).ok()
    }

    /// Whether [`Self::default_tenant_id`] is silently discarding a value the
    /// operator set (T-244, R-1…R-8).
    ///
    /// Treating an unparseable value as unset is right and stays — a public,
    /// unauthenticated document should not `500` for every relying party
    /// because somebody fat-fingered a UUID — but the operator was never told,
    /// so the deployment concluded the setting does not work. This answers
    /// `Some` exactly when a non-empty value failed to parse, and the caller
    /// logs it **once at boot**.
    ///
    /// # Why not on the request path
    ///
    /// [`Self::default_tenant_id`] is called per discovery request. A warning
    /// there is a log flood any anonymous caller can drive by requesting the
    /// document in a loop.
    ///
    /// # Why the shape and never the value
    ///
    /// A tenant id is not a secret, but a variable this code cannot prove *is*
    /// a tenant id may hold anything an operator pasted — including the
    /// contents of the wrong clipboard. The diagnostic therefore carries the
    /// length and a character class and nothing else.
    #[must_use]
    pub fn default_tenant_id_diagnostic(&self) -> Option<DefaultTenantProblem> {
        let trimmed = self.oauth2_default_tenant_id.trim();
        // Empty and whitespace-only are "unset", which is the default and
        // needs no warning.
        if trimmed.is_empty() || uuid::Uuid::parse_str(trimmed).is_ok() {
            return None;
        }
        Some(DefaultTenantProblem {
            length: trimmed.chars().count(),
            shape: if trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
                "hexadecimal, but not a 36-character UUID"
            } else {
                "contains characters a UUID cannot"
            },
        })
    }

    pub fn mtls_base_url(&self) -> Option<&str> {
        let trimmed = self.oauth2_mtls_base_url.trim().trim_end_matches('/');
        (!trimmed.is_empty()).then_some(trimmed)
    }

    /// CQ-B14: Parse Ed25519 keys from PEM once and cache in `Arc`.
    ///
    /// Call this once at startup after loading config from environment.
    /// After this returns `Ok(())`, all token functions skip per-call PEM
    /// parsing and use the cached keys instead.
    pub fn resolve_keys(&mut self) -> Result<(), String> {
        let enc = EncodingKey::from_ed_pem(self.jwt_private_key_pem.as_bytes())
            .map_err(|e| format!("invalid JWT private key PEM: {e}"))?;
        let dec = DecodingKey::from_ed_pem(self.jwt_public_key_pem.as_bytes())
            .map_err(|e| format!("invalid JWT public key PEM: {e}"))?;
        self.jwt_encoding_key = Some(Arc::new(enc));
        self.jwt_decoding_key = Some(Arc::new(dec));
        Ok(())
    }

    /// B1: Resolve `max_concurrent_hashes` (0 = auto) to a concrete permit
    /// count for the crypto semaphore.
    ///
    /// Auto (`0`) resolves to `min(available_parallelism, 4)`: bound by the
    /// core count so Argon2id (a CPU-bound operation) does not oversubscribe
    /// cores, and capped at 4 so peak concurrent ~19 MiB arenas stay well
    /// under typical container memory caps. A non-zero value is used verbatim
    /// (a `0` after resolution is impossible — it would be a zero-permit
    /// semaphore that deadlocks all hashing, so it is clamped to 1).
    pub fn resolved_max_concurrent_hashes(&self) -> usize {
        match self.max_concurrent_hashes {
            0 => std::thread::available_parallelism()
                .map(|n| n.get().min(4))
                .unwrap_or(4),
            n => n.max(1),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_private_key_pem: String::new(),
            jwt_public_key_pem: String::new(),
            // Fail closed: a forwarded certificate is trusted only where an
            // operator has asserted a proxy terminates mTLS and overwrites the
            // header. See the field docs for what that assertion costs if wrong.
            trust_forwarded_client_cert: false,
            access_token_lifetime_secs: 900,
            refresh_token_lifetime_secs: 2_592_000,
            auth_code_lifetime_secs: 600,
            jwt_issuer: "axiam".into(),
            oauth2_issuer_url: String::new(),
            // Empty means "no separate mTLS host", which omits
            // `mtls_endpoint_aliases` from discovery. The correct default:
            // most deployments run one listener.
            oauth2_mtls_base_url: String::new(),
            // Empty means "the bare document names no tenant", which is
            // today's behaviour and the right default for a multi-tenant
            // deployment. A single-tenant issuer sets it.
            oauth2_default_tenant_id: String::new(),
            // T21.6 — off. The whole feature is opt-in (I1): with this false
            // no route, no claim and no accepted issuer differs from a build
            // that predates it.
            tenant_issuer_paths: false,
            // Never a configured value; see the field docs.
            request_issuer: None,
            revocation_feed_enabled: false,
            sso_spa_origins: Vec::new(),
            pepper: None,
            pepper_previous: None,
            min_password_length: 12,
            mfa_encryption_key: None,
            opaque_session_key: None,
            opaque_setup_key: None,
            federation_encryption_key: None,
            allow_missing_aud_as_user: true,
            cookie_secure: true,
            mfa_challenge_lifetime_secs: 300,
            totp_issuer: "AXIAM".into(),
            max_failed_login_attempts: 5,
            lockout_duration_secs: 900,
            lockout_backoff_multiplier: 2.0,
            max_lockout_duration_secs: 3600,
            email_verification_grace_period_hours: 24,
            password_reset_token_expiry_hours: 1,
            webauthn_rp_id: "localhost".into(),
            webauthn_rp_origin: "http://localhost:8090".into(),
            webauthn_rp_name: "AXIAM".into(),
            jwt_encoding_key: None,
            jwt_decoding_key: None,
            hibp_breaker_threshold: 5,
            hibp_breaker_cooldown_secs: 30,
            // B1: 0 = auto → min(available_parallelism, 4) at construction.
            max_concurrent_hashes: 0,
            hash_acquire_timeout_secs: 5,
            // I6: opt-in. 0 = no session-validation cache (today's behaviour).
            session_validation_cache_ttl_secs: 0,
        }
    }
}

#[cfg(test)]
mod default_tenant_tests {
    use super::*;

    fn config_with(value: &str) -> AuthConfig {
        AuthConfig {
            oauth2_default_tenant_id: value.to_owned(),
            ..AuthConfig::default()
        }
    }

    /// Unset, whitespace-only and valid all mean "nothing to say". A warning
    /// in any of these is a warning an operator learns to scroll past.
    #[test]
    fn a_valid_or_absent_default_tenant_says_nothing() {
        for quiet in [
            "",
            "   ",
            "\n",
            "6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b",
            "  6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b  ",
        ] {
            assert_eq!(
                config_with(quiet).default_tenant_id_diagnostic(),
                None,
                "{quiet:?} must produce no diagnostic"
            );
        }
    }

    /// A value that is set and unusable is exactly the case the operator
    /// never heard about.
    #[test]
    fn an_unparseable_default_tenant_is_reported() {
        let problem = config_with("not-a-uuid")
            .default_tenant_id_diagnostic()
            .expect("an unparseable value must be reported");
        assert_eq!(problem.length, 10);
        assert_eq!(problem.shape, "contains characters a UUID cannot");
    }

    /// A truncated paste is the commonest way to get here, and it is worth
    /// distinguishing from a value that was never a UUID at all: the first is
    /// "you lost some characters", the second is "that is a different thing".
    #[test]
    fn a_truncated_uuid_is_reported_as_the_right_shape() {
        let problem = config_with("6f3e0a5c-1b2d-4e8f")
            .default_tenant_id_diagnostic()
            .expect("a truncated UUID must be reported");
        assert_eq!(problem.length, 18);
        assert_eq!(problem.shape, "hexadecimal, but not a 36-character UUID");
    }

    /// The rendered line carries the length and the class, and **no substring
    /// of the value**. The check is deliberately crude — every three-character
    /// window of the value — because the failure mode is somebody adding the
    /// value to the message to make it easier to debug.
    #[test]
    fn the_rendered_diagnostic_never_echoes_the_value() {
        let value = "tenant-acme-production";
        let rendered = config_with(value)
            .default_tenant_id_diagnostic()
            .unwrap()
            .to_string();
        for window in value
            .as_bytes()
            .windows(3)
            .map(|w| std::str::from_utf8(w).unwrap())
        {
            assert!(
                !rendered.contains(window),
                "the diagnostic must not echo any part of the value; \
                 found {window:?} in {rendered:?}"
            );
        }
        assert!(rendered.contains("22 characters"));
    }

    /// **I4 twin, and the proof this item changed nothing.** The accessor the
    /// discovery builder actually reads answers `None` for an unparseable
    /// value exactly as it did before the diagnostic existed — so the document
    /// a misconfigured deployment serves is the document an unconfigured one
    /// serves, which is what `oidc.rs::a_document_that_names_no_tenant_carries_no_query_string`
    /// pins on the other side.
    #[test]
    fn an_unparseable_default_tenant_is_still_treated_as_unset() {
        assert_eq!(config_with("not-a-uuid").default_tenant_id(), None);
        assert_eq!(config_with("").default_tenant_id(), None);
        assert_eq!(
            config_with("not-a-uuid").default_tenant_id(),
            config_with("").default_tenant_id(),
            "a bad value and no value must be indistinguishable to the builder"
        );
    }

    // -----------------------------------------------------------------------
    // T21.6 — per-tenant path issuers
    // -----------------------------------------------------------------------

    fn issuer_config(tenant_issuer_paths: bool) -> AuthConfig {
        AuthConfig {
            oauth2_issuer_url: "https://id.example.com".into(),
            jwt_issuer: "axiam".into(),
            tenant_issuer_paths,
            ..AuthConfig::default()
        }
    }

    const TENANT: &str = "11111111-2222-3333-4444-555555555555";

    /// The flag's off-state is the whole of I1 for this feature: no tenant
    /// issuer can be built, none is accepted, and the accepted set is exactly
    /// the one string `jsonwebtoken`'s pinned check accepted before T21.6.
    #[test]
    fn with_the_flag_off_no_tenant_issuer_exists_and_none_is_accepted() {
        let c = issuer_config(false);
        let tenant = uuid::Uuid::parse_str(TENANT).unwrap();
        assert_eq!(c.tenant_issuer(tenant), None);
        assert_eq!(c.for_tenant_path(tenant).map(|_| ()), None);
        assert_eq!(
            c.tenant_of_issuer(&format!("https://id.example.com/t/{TENANT}")),
            None
        );
        assert!(c.accepts_issuer("https://id.example.com"));
        assert!(!c.accepts_issuer(&format!("https://id.example.com/t/{TENANT}")));
        assert_eq!(c.effective_issuer(), c.root_issuer());
    }

    #[test]
    fn a_tenant_issuer_is_the_root_plus_the_derived_path() {
        let c = issuer_config(true);
        let tenant = uuid::Uuid::parse_str(TENANT).unwrap();
        assert_eq!(
            c.tenant_issuer(tenant).unwrap(),
            format!("https://id.example.com/t/{TENANT}")
        );
        let scoped = c.for_tenant_path(tenant).unwrap();
        assert_eq!(
            scoped.effective_issuer(),
            format!("https://id.example.com/t/{TENANT}")
        );
        // The deployment's own issuer is unmoved, and every VALIDATION decision
        // reads it — a request cannot narrow or widen what counts as valid by
        // choosing a path.
        assert_eq!(scoped.root_issuer(), "https://id.example.com");
    }

    /// The widening is a set of two shapes and no more. Each of these is a way
    /// a looser comparison — a prefix match, a trailing-slash tolerance, a
    /// normalising parse — would have admitted something it must not.
    #[test]
    fn only_the_root_and_a_well_formed_tenant_issuer_are_accepted() {
        let c = issuer_config(true);
        assert!(c.accepts_issuer("https://id.example.com"));
        assert!(c.accepts_issuer(&format!("https://id.example.com/t/{TENANT}")));

        for rejected in [
            // A tenant segment that is not a UUID.
            "https://id.example.com/t/admin",
            "https://id.example.com/t/..",
            "https://id.example.com/t/",
            "https://id.example.com/t",
            // Anything AFTER the tenant segment.
            &format!("https://id.example.com/t/{TENANT}/extra"),
            &format!("https://id.example.com/t/{TENANT}/"),
            // A trailing slash on the root, which OIDC Core §2 makes a
            // different identifier.
            "https://id.example.com/",
            // Another host that merely starts the same way.
            &format!("https://id.example.com.evil.test/t/{TENANT}"),
            "https://evil.test",
            // The right shape at the wrong scheme.
            &format!("http://id.example.com/t/{TENANT}"),
        ] {
            assert!(
                !c.accepts_issuer(rejected),
                "{rejected} must not be accepted as an issuer"
            );
        }
    }

    #[test]
    fn the_tenant_of_an_issuer_is_only_read_from_the_tenant_form() {
        let c = issuer_config(true);
        assert_eq!(
            c.tenant_of_issuer(&format!("https://id.example.com/t/{TENANT}")),
            Some(uuid::Uuid::parse_str(TENANT).unwrap())
        );
        // The root issuer names no tenant — which is the reason the path form
        // exists, so answering `Some` here would be answering the wrong
        // question.
        assert_eq!(c.tenant_of_issuer("https://id.example.com"), None);
        assert_eq!(c.tenant_of_issuer("https://id.example.com/t/nope"), None);
    }
}
