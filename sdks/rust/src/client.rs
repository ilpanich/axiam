//! `AxiamClient` + builder (owned by 16-02): tenant-scoped client
//! construction, base URL, timeouts, custom CA.
//!
//! CONTRACT.md §5: `tenant_slug` or `tenant_id` is a **non-optional**
//! constructor parameter — there is no default tenant. This builder
//! enforces that at `build()` time with a dedicated construction error
//! (never a silent default).
//!
//! CONTRACT.md §4: the client owns a per-instance
//! [`reqwest::cookie::Jar`] (not a process-global store) so multiple
//! clients can hold independent sessions.
//!
//! CONTRACT.md §6: TLS verification is always strict; the only escape
//! hatch is [`AxiamClientBuilder::with_custom_ca`]. There is no method on
//! this type that weakens or bypasses certificate verification.
//!
//! **Feature gating note:** `AxiamClient` is a REST-transport client (its
//! fields are all `reqwest`-based), so this entire module body is gated
//! behind `feature = "rest"` to preserve 16-01's `cargo build
//! --no-default-features` invariant (`client.rs`/`token` are declared
//! unconditionally in `lib.rs`, unlike `rest`/`grpc`/`amqp`).

#![cfg(feature = "rest")]

use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use crate::token::jwks::JwksVerifier;
use crate::token::TokenManager;
use crate::AxiamError;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The tenant identifier a client was built with — either form is accepted
/// per CONTRACT.md §5; the SDK resolves `Slug` to a UUID after the first
/// successful login by decoding the `tenant_id` claim from the verified
/// access token (RESEARCH.md Open Question #1).
#[derive(Debug, Clone)]
pub(crate) enum TenantIdentifier {
    Slug(String),
    Id(Uuid),
}

impl TenantIdentifier {
    /// The value to send in the `X-Tenant-ID` header before resolution.
    pub(crate) fn header_value(&self) -> String {
        match self {
            TenantIdentifier::Slug(s) => s.clone(),
            TenantIdentifier::Id(id) => id.to_string(),
        }
    }
}

/// The organization identifier a client was built with (see
/// [`AxiamClientBuilder::org_slug`]/[`AxiamClientBuilder::org_id`]).
///
/// **Deviation from CONTRACT.md §5 (Rule 2 — missing critical
/// functionality):** the contract specifies only `tenant_slug`/`tenant_id`
/// as constructor parameters. AXIAM's actual `POST /api/v1/auth/login` and
/// `POST /api/v1/auth/refresh` endpoints additionally require an
/// organization identifier (`org_id`/`org_slug` on login; `org_id: Uuid`,
/// non-optional, on refresh) — organizations are the top-level multi-tenant
/// entity above tenants (CLAUDE.md domain model). Without this, `login()`
/// cannot succeed against the real server at all, so an optional
/// `org_slug`/`org_id` builder parameter is added: if supplied it is
/// forwarded on login; either way, the resolved organization UUID is
/// decoded from the verified access token's `org_id` claim after the first
/// successful login and cached for `refresh()` to reuse, so the caller only
/// ever needs to supply it once (at construction, if known) or not at all
/// (if it can be inferred from the JWT after login).
#[derive(Debug, Clone)]
pub(crate) enum OrgIdentifier {
    Slug(String),
    Id(Uuid),
}

/// Builder for [`AxiamClient`]. Construct via [`AxiamClient::builder`].
///
/// `base_url` and one of `tenant_slug`/`tenant_id` are required; omitting
/// the tenant identifier is a `build()`-time [`AxiamError`], never a silent
/// default (§5). `org_slug`/`org_id` are optional (see [`OrgIdentifier`]
/// doc comment for why they exist beyond the CONTRACT.md §5 baseline).
#[derive(Default)]
pub struct AxiamClientBuilder {
    base_url: Option<url::Url>,
    tenant: Option<TenantIdentifier>,
    org: Option<OrgIdentifier>,
    connect_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    custom_ca_pem: Option<Vec<u8>>,
}

impl AxiamClientBuilder {
    /// The AXIAM server's base URL (required, no default per §14).
    pub fn base_url(mut self, url: impl AsRef<str>) -> Result<Self, AxiamError> {
        let parsed = url::Url::parse(url.as_ref()).map_err(|e| AxiamError::Network {
            message: format!("invalid base_url: {e}"),
            source: None,
        })?;
        self.base_url = Some(parsed);
        Ok(self)
    }

    /// Human-readable tenant slug form (§5). Mutually exclusive with
    /// [`Self::tenant_id`] — the last one called wins.
    pub fn tenant_slug(mut self, slug: impl Into<String>) -> Self {
        self.tenant = Some(TenantIdentifier::Slug(slug.into()));
        self
    }

    /// UUID tenant identifier form (§5). Mutually exclusive with
    /// [`Self::tenant_slug`] — the last one called wins.
    pub fn tenant_id(mut self, id: Uuid) -> Self {
        self.tenant = Some(TenantIdentifier::Id(id));
        self
    }

    /// Organization slug — optional; see [`OrgIdentifier`] doc comment.
    /// Mutually exclusive with [`Self::org_id`] — the last one called wins.
    pub fn org_slug(mut self, slug: impl Into<String>) -> Self {
        self.org = Some(OrgIdentifier::Slug(slug.into()));
        self
    }

    /// Organization UUID — optional; see [`OrgIdentifier`] doc comment.
    /// Mutually exclusive with [`Self::org_slug`] — the last one called wins.
    pub fn org_id(mut self, id: Uuid) -> Self {
        self.org = Some(OrgIdentifier::Id(id));
        self
    }

    /// Override the TCP connect timeout (default 10s, D-14).
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Override the overall request timeout (default 30s, D-14).
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }

    /// Add a custom CA certificate (PEM-encoded bytes) to the TLS
    /// verification chain, for development environments using self-signed
    /// certificates (§6). This is the **only** TLS-related escape hatch;
    /// there is deliberately no way to disable or weaken verification.
    ///
    /// Returns a construction-time error if `pem` is not valid PEM.
    pub fn with_custom_ca(mut self, pem: &[u8]) -> Result<Self, AxiamError> {
        // Validate eagerly so a malformed CA is caught here rather than at
        // first request time.
        reqwest::Certificate::from_pem(pem).map_err(|e| AxiamError::Network {
            message: format!("invalid custom CA PEM: {e}"),
            source: None,
        })?;
        self.custom_ca_pem = Some(pem.to_vec());
        Ok(self)
    }

    /// Finalize the client. Fails if `base_url` or a tenant identifier is
    /// missing (§5 — never a silent default).
    pub fn build(self) -> Result<AxiamClient, AxiamError> {
        let base_url = self.base_url.ok_or_else(|| AxiamError::Network {
            message: "base_url is required to build an AxiamClient".into(),
            source: None,
        })?;
        let tenant = self.tenant.ok_or_else(|| AxiamError::Auth {
            message:
                "a tenant identifier (tenant_slug or tenant_id) is required to build an AxiamClient \
                 — AXIAM is multi-tenant and there is no default tenant (CONTRACT.md §5)"
                    .into(),
        })?;

        let jar = Arc::new(reqwest::cookie::Jar::default());

        // Host-isolation (3A, defense in depth): never follow a redirect that
        // leaves our own origin. reqwest strips Authorization/Cookie on a
        // cross-host redirect but forwards custom headers (X-Tenant-ID /
        // X-CSRF-Token) — so a redirect to a third-party host would leak the
        // tenant identifier and CSRF token. Same-host redirects are followed
        // (capped at 10, matching reqwest's default); cross-host redirects are
        // not followed (the 3xx is returned as-is).
        let redirect_base_host = base_url.host_str().map(str::to_owned);
        let redirect_policy = reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= 10 {
                return attempt.error("too many redirects");
            }
            match (attempt.url().host_str(), redirect_base_host.as_deref()) {
                (Some(next), Some(base)) if !next.eq_ignore_ascii_case(base) => attempt.stop(),
                _ => attempt.follow(),
            }
        });

        let mut client_builder = reqwest::Client::builder()
            .cookie_provider(Arc::clone(&jar))
            .redirect(redirect_policy)
            .connect_timeout(self.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT))
            .timeout(self.request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT));

        if let Some(pem) = &self.custom_ca_pem {
            let cert = reqwest::Certificate::from_pem(pem).map_err(|e| AxiamError::Network {
                message: format!("invalid custom CA PEM: {e}"),
                source: None,
            })?;
            client_builder = client_builder.add_root_certificate(cert);
        }

        let http = client_builder.build().map_err(|e| AxiamError::Network {
            message: format!("failed to construct HTTP client: {e}"),
            source: Some(Box::new(e)),
        })?;

        let jwks_verifier = JwksVerifier::new(http.clone(), &base_url)?;

        Ok(AxiamClient {
            inner: Arc::new(AxiamClientInner {
                http,
                jar,
                base_url,
                tenant,
                org: self.org,
                token_manager: TokenManager::new(),
                jwks_verifier,
                csrf_token: std::sync::RwLock::new(None),
                resolved_org_id: std::sync::RwLock::new(None),
                pending_mfa_challenge: std::sync::RwLock::new(None),
            }),
        })
    }
}

pub(crate) struct AxiamClientInner {
    pub(crate) http: reqwest::Client,
    pub(crate) jar: Arc<reqwest::cookie::Jar>,
    pub(crate) base_url: url::Url,
    pub(crate) tenant: TenantIdentifier,
    pub(crate) org: Option<OrgIdentifier>,
    pub(crate) token_manager: TokenManager,
    pub(crate) jwks_verifier: JwksVerifier,
    /// Latest captured `X-CSRF-Token` value, forwarded on state-changing
    /// verbs (§3). `None` until the first response carrying the cookie.
    pub(crate) csrf_token: std::sync::RwLock<Option<String>>,
    /// Organization UUID resolved from the `org_id` claim of the verified
    /// access token after the first successful login/verify_mfa. See
    /// [`OrgIdentifier`] doc comment.
    pub(crate) resolved_org_id: std::sync::RwLock<Option<Uuid>>,
    /// The challenge token from the most recent `login()` call that
    /// returned `mfa_required: true`, so `verify_mfa(code)` can complete
    /// the two-phase flow with only a `code` argument, matching
    /// CONTRACT.md §1's exact `verify_mfa(code)` signature.
    pub(crate) pending_mfa_challenge: std::sync::RwLock<Option<crate::Sensitive<String>>>,
}

/// The AXIAM SDK's REST/gRPC/AMQP client entry point.
///
/// Cheaply cloneable (`Arc`-backed); every clone shares the same cookie
/// jar, token state, and JWKS cache.
#[derive(Clone)]
pub struct AxiamClient {
    pub(crate) inner: Arc<AxiamClientInner>,
}

impl AxiamClient {
    /// Start building a client. See [`AxiamClientBuilder`].
    pub fn builder() -> AxiamClientBuilder {
        AxiamClientBuilder::default()
    }

    /// The base URL this client was constructed with.
    pub fn base_url(&self) -> &url::Url {
        &self.inner.base_url
    }

    /// The `X-Tenant-ID` header value to send on every request — the raw
    /// slug/UUID string the client was built with (CONTRACT.md §5).
    pub(crate) fn tenant_header_value(&self) -> String {
        self.inner.tenant.header_value()
    }

    /// The resolved tenant UUID, if a login/verify_mfa has already
    /// decoded it from the access token's `tenant_id` claim; otherwise the
    /// UUID form the client was constructed with, if any.
    pub async fn resolved_tenant_id(&self) -> Option<Uuid> {
        if let Some(id) = self.inner.token_manager.tenant_id().await {
            return Some(id);
        }
        match &self.inner.tenant {
            TenantIdentifier::Id(id) => Some(*id),
            TenantIdentifier::Slug(_) => None,
        }
    }

    /// Access the underlying `reqwest::Client` (crate-internal use by the
    /// `rest`/`token` modules).
    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.inner.http
    }

    /// Access the token manager (crate-internal use by `rest`/`grpc`).
    pub(crate) fn token_manager(&self) -> &TokenManager {
        &self.inner.token_manager
    }

    /// Access the JWKS verifier (crate-internal use by `rest`/`middleware`).
    pub(crate) fn jwks_verifier(&self) -> &JwksVerifier {
        &self.inner.jwks_verifier
    }

    /// Read the latest captured CSRF token, if any (§3).
    pub(crate) fn csrf_token(&self) -> Option<String> {
        self.inner.csrf_token.read().ok().and_then(|g| g.clone())
    }

    /// Store a freshly-observed CSRF token (§3).
    pub(crate) fn set_csrf_token(&self, token: String) {
        if let Ok(mut guard) = self.inner.csrf_token.write() {
            *guard = Some(token);
        }
    }

    /// Read the `axiam_csrf` cookie directly out of the jar and cache it
    /// (used right after login/verify_mfa/refresh, mirroring how the
    /// `axiam_access` cookie is read — RESEARCH.md Pattern 1).
    pub(crate) fn capture_csrf_from_jar(&self) {
        if let Some(csrf) = crate::token::manager::extract_csrf_token_from_jar(
            &self.inner.jar,
            &self.inner.base_url,
        ) {
            self.set_csrf_token(csrf);
        }
    }

    /// The `org_slug`/`org_id` the client was constructed with, if any
    /// (see [`OrgIdentifier`] doc comment for why this exists).
    pub(crate) fn org_identifier(&self) -> Option<&OrgIdentifier> {
        self.inner.org.as_ref()
    }

    /// The organization UUID resolved from the access token's `org_id`
    /// claim after the first successful login/verify_mfa, if any yet.
    pub(crate) fn resolved_org_id(&self) -> Option<Uuid> {
        self.inner.resolved_org_id.read().ok().and_then(|g| *g)
    }

    /// Cache the resolved organization UUID (called after decoding the
    /// access token post-login/verify_mfa/refresh).
    pub(crate) fn set_resolved_org_id(&self, org_id: Uuid) {
        if let Ok(mut guard) = self.inner.resolved_org_id.write() {
            *guard = Some(org_id);
        }
    }

    /// Store the challenge token from a `login()` call that returned
    /// `mfa_required: true`, so a subsequent `verify_mfa(code)` can
    /// complete the flow without the caller re-supplying it.
    pub(crate) fn set_pending_mfa_challenge(&self, challenge: crate::Sensitive<String>) {
        if let Ok(mut guard) = self.inner.pending_mfa_challenge.write() {
            *guard = Some(challenge);
        }
    }

    /// Take (consume) the pending MFA challenge token, if any.
    pub(crate) fn take_pending_mfa_challenge(&self) -> Option<crate::Sensitive<String>> {
        self.inner
            .pending_mfa_challenge
            .write()
            .ok()
            .and_then(|mut guard| guard.take())
    }
}
