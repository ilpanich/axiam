//! Rate-limit key extractor using X-Forwarded-For header (per D-02, SEC-048).
//!
//! SEC-048: The extractor selects the *rightmost untrusted* hop from the
//! X-Forwarded-For header to prevent IP-spoofing based rate-limit evasion.
//!
//! # Deriving `trusted_hops`
//!
//! The value follows from one fact about how proxies write the header: a proxy
//! appends **the address it received the request from**, not its own. nginx's
//! `proxy_add_x_forwarded_for` is `$http_x_forwarded_for, $remote_addr`; Caddy's
//! `reverse_proxy` and ingress-nginx do the same. So the *nearest* proxy never
//! appears in the header the server reads — it is the socket peer. Therefore:
//!
//! > **`trusted_hops` = (number of reverse proxies between the client and this
//! > server) − 1** — equivalently, the number of *proxy* addresses that appear
//! > in the X-Forwarded-For header this server receives.
//!
//! | Proxies in front | Header the server sees | `trusted_hops` |
//! | --- | --- | --- |
//! | 1 (Caddy, or an ingress) | `<client>` | **0** |
//! | 2 (Caddy → nginx) | `<client>, <caddy>` | **1** |
//! | 3 (LB → ingress → mesh) | `<client>, <lb>, <ingress>` | **2** |
//!
//! Example, with a client that spoofs a header of its own behind two proxies:
//!   X-Forwarded-For: <attacker-ip>, <real-client-ip>, <trusted-proxy-ip>
//!   trusted_hops = 1 → selects <real-client-ip> (skip 1 from right)
//!
//! Behind a *single* appending proxy, `0` selects the real client whether or not
//! the client lies: with no spoof the header is `<client>` and index 0 is the
//! client; with a spoof it is `<attacker>, <client>` and index 1 is the client.
//!
//! **This corrected an off-by-one in the previous text**, which said the value
//! "should equal the number of trusted reverse-proxy hops (e.g. 1 for a single
//! nginx/ingress in front of the server)". Setting 1 behind one proxy makes
//! `trusted_hops >= hops.len()`, so the header is discarded and the key becomes
//! `peer_addr()` — the proxy's own address — collapsing every client on the
//! internet into a single bucket. The advice produced exactly the failure this
//! extractor exists to prevent. See `claude_dev/public-backend-tls-design.md` §4.
//!
//! Falls back to the direct peer address when the header is absent, unparseable,
//! or has fewer hops than `trusted_hops` (a client cannot manufacture extra
//! trusted hops to force a fallback to an attacker-controlled entry: when there
//! are not enough hops to trust, the XFF header is ignored entirely and the key
//! is derived from `peer_addr()`).
//!
//! **nginx/ingress requirement**: The upstream proxy MUST append the real client
//! IP to the RIGHT of X-Forwarded-For (not inject it at position 0) for this to
//! be effective. With `proxy_add_x_forwarded_for` in nginx this is the default
//! behaviour — the real client is the RIGHTMOST trusted entry, not the leftmost.
//!
//! # Which peers may write the header (`TRUSTED_PROXIES`, #711)
//!
//! No value of `trusted_hops` helps a connection with no appending proxy in
//! front: the rightmost entry is then the caller's own. When
//! `AXIAM__RATE_LIMIT__TRUSTED_PROXIES` names the proxies (CIDR blocks), the
//! header is read only on a request whose transport peer is inside one of
//! them; every other request is keyed on its peer, whatever it wrote. With the
//! list empty (the default) every peer's header is read, as before the list
//! existed. The rule is [`axiam_core::forwarded_for::TrustedProxies`], shared
//! with the gRPC extractor.

use actix_governor::governor::NotUntil;
use actix_governor::governor::clock::{Clock, DefaultClock, QuantaInstant};
use actix_governor::{KeyExtractor, SimpleKeyExtractionError};
use actix_web::HttpMessage;
use actix_web::HttpResponse;
use actix_web::dev::ServiceRequest;
use actix_web::http::header::{ContentType, HeaderMap, RETRY_AFTER};
use actix_web::web;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axiam_auth::config::AuthConfig;
use axiam_auth::token::CachedUserIdentity;
use axiam_core::forwarded_for::{TrustedProxies, select_client_ip};
use uuid::Uuid;

use crate::config::rate_limit::RateLimitKeyMode;
use crate::extractors::auth::{SessionValidator, admissible_session};
use crate::middleware::tenant_path::TenantPathBinding;

/// Extracts client IP from X-Forwarded-For header, falls back to peer address.
///
/// `trusted_hops` controls how many rightmost entries in the XFF header to skip
/// (they come from trusted proxies). The selected entry is the **rightmost
/// untrusted** hop — `idx = len - 1 - trusted_hops` — which is correct for a
/// chain of proxies that right-append the address they received from (nginx
/// `proxy_add_x_forwarded_for`, Caddy, ingress-nginx). `trusted_hops = 0`
/// selects the rightmost entry, which is the real client behind exactly one
/// such proxy; `trusted_hops = 1` skips one appended proxy address, which is
/// what two proxies produce — see the module docs for the derivation. (SEC-070: earlier doc text wrongly described this as using the
/// *leftmost* entry — the leftmost is the most attacker-controllable position
/// and is never used.)
#[derive(Debug, Clone, Default)]
pub struct XForwardedForKeyExtractor {
    /// Number of trusted reverse-proxy hops to skip from the right of
    /// the X-Forwarded-For list. Set to the number of load-balancers/
    /// ingress proxies between the client and this server.
    ///
    /// Default: 0 (rightmost entry), which is **correct** behind exactly one
    /// appending proxy — the shape of both shipped topologies
    /// (`k8s/ingress.yml` and the Compose/Pi deployment). NOTE: when the server
    /// is exposed with no proxy at all, a client can set XFF freely and no
    /// value of this field helps: that is what [`Self::trusted_proxies`] is
    /// for. *(Corrected 2026-10-19, #686: this note said the `peer_addr()`
    /// fallback kept that case safe, which holds only for a caller that sends
    /// no header.)*
    pub trusted_hops: usize,
    /// The peers whose X-Forwarded-For is read at all
    /// (`AXIAM__RATE_LIMIT__TRUSTED_PROXIES`, #711). A request from any other
    /// peer is keyed on the peer. Empty (the default): every peer's.
    pub trusted_proxies: TrustedProxies,
}

impl XForwardedForKeyExtractor {
    /// Create an extractor that uses the rightmost-untrusted hop.
    /// `trusted_hops` = number of trusted proxy entries from the right.
    /// The proxy list is empty: every peer's header is read.
    pub fn with_trusted_hops(trusted_hops: usize) -> Self {
        Self {
            trusted_hops,
            trusted_proxies: TrustedProxies::default(),
        }
    }

    /// This extractor, reading the header only from a peer in `trusted_proxies`.
    #[must_use]
    pub fn with_trusted_proxies(mut self, trusted_proxies: TrustedProxies) -> Self {
        self.trusted_proxies = trusted_proxies;
        self
    }

    /// The extractor the deployment configures: `AXIAM__RATE_LIMIT__TRUSTED_HOPS`
    /// ([`configured_trusted_hops`]) and `AXIAM__RATE_LIMIT__TRUSTED_PROXIES`
    /// ([`TrustedProxies::configured`]). Every REST limiter keyed on the
    /// client's address is built from this, so they cannot disagree about
    /// which address a request is.
    pub fn configured() -> Self {
        Self::with_trusted_hops(configured_trusted_hops())
            .with_trusted_proxies(TrustedProxies::configured())
    }
}

pub use axiam_core::forwarded_for::configured_trusted_hops;

/// The address a per-address rate limit keys a request on (SEC-048, T-212).
///
/// `peer`, the transport peer, when `trusted_proxies` does not honour its
/// header (#711). Otherwise the **rightmost untrusted** `X-Forwarded-For`
/// hop — `hops[len - 1 - trusted_hops]` — when the header has more hops than
/// `trusted_hops` and that entry parses as an address; otherwise `peer`.
/// Behind `trusted_hops + 1` appending proxies a client cannot choose the
/// result by writing the header: the entries it writes sit to the LEFT of the
/// ones the proxies append, and the index counts from the right; and a header
/// too short to reach past the trusted hops is ignored entirely rather than
/// indexed from the left (SECHRD-03). A server exposed with no proxy at all
/// reads whatever the caller wrote unless `trusted_proxies` names the proxies
/// — the deployment guide's T-212 caveat, shared by every limiter that calls
/// this.
///
/// The second value is `Some(hops seen)` when the header was discarded
/// because `trusted_hops >= hops` — the R-4 misconfiguration signal, which
/// only [`XForwardedForKeyExtractor`] records, once per request.
fn select_rate_limit_ip(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trusted_hops: usize,
    trusted_proxies: &TrustedProxies,
) -> (Option<IpAddr>, Option<usize>) {
    // The rule lives in `axiam_core::forwarded_for`, shared with the audit rows
    // and the log fields (#752), so they cannot disagree about the address.
    let selected = select_client_ip(
        headers.get("X-Forwarded-For").and_then(|v| v.to_str().ok()),
        peer.map(|addr| addr.ip()),
        trusted_hops,
        trusted_proxies,
    );
    (selected.ip, selected.discarded_hops)
}

impl KeyExtractor for XForwardedForKeyExtractor {
    type Key = IpAddr;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        let (ip, discarded_hops) = select_rate_limit_ip(
            req.headers(),
            req.peer_addr(),
            self.trusted_hops,
            &self.trusted_proxies,
        );
        // R-4: a header with fewer hops than `trusted_hops` requires is no
        // longer discarded silently. Under a `trusted_hops` one too high this
        // fires on every request and every client shares one bucket keyed on
        // the proxy — the failure T-212 describes, which went unnoticed
        // precisely because nothing said so. One WARN per process plus a
        // counter; see `super::xff_metrics`.
        if let Some(hops_seen) = discarded_hops {
            super::xff_metrics::record_discarded_xff(hops_seen, self.trusted_hops);
        }
        ip.ok_or_else(|| SimpleKeyExtractionError::new("no peer address"))
    }

    /// Returns a JSON 429 response with Retry-After header per D-03.
    ///
    /// Body: `{"error":"rate_limit_exceeded","retry_after":<seconds>}`
    fn exceed_rate_limit_response(
        &self,
        negative: &NotUntil<QuantaInstant>,
        mut response: actix_web::HttpResponseBuilder,
    ) -> HttpResponse {
        let wait_secs = negative
            .wait_time_from(DefaultClock::default().now())
            .as_secs();
        response
            .content_type(ContentType::json())
            .insert_header((RETRY_AFTER, wait_secs.to_string()))
            .body(format!(
                r#"{{"error":"rate_limit_exceeded","retry_after":{}}}"#,
                wait_secs
            ))
    }
}

// ---------------------------------------------------------------------------
// D8 — client-identity-aware keying (token/introspect/revoke only)
// ---------------------------------------------------------------------------

/// Request-extension carrying the `client_id` (if any) parsed from the
/// request body by
/// [`crate::middleware::rate_limit_shared::RateLimitShared`]'s
/// client-identity-aware constructor, so [`ClientAwareKeyExtractor`] (used
/// by the in-memory `Governor` on the SAME resource) doesn't need to peek
/// the body a second time.
///
/// Ordering guarantee this relies on: in `server.rs`, `RateLimitShared` is
/// always the OUTER `.wrap()` (last one added — see the module docs on
/// `RateLimitShared`), so it always runs BEFORE the `Governor` middleware
/// and always inserts this extension (`None` when no `client_id` could be
/// parsed, or when the configured key mode is `ip`) before delegating.
/// `Governor`'s [`ClientAwareKeyExtractor`] treats a *missing* extension
/// (e.g. if the two middlewares were ever mis-ordered) identically to
/// `None` — it falls back to the IP key, never panics.
#[derive(Debug, Clone, Default)]
pub struct RateLimitClientId(pub Option<String>);

/// Parses the `client_id` field out of an `application/x-www-form-urlencoded`
/// body — where a `client_secret_post` client (RFC 6749 §2.3.1, see
/// `handlers::oauth2` and `axiam_oauth2::token::{TokenRequest, RevokeRequest,
/// IntrospectRequest}`, all form-decoded via `web::Form<..>`) names itself.
/// A `client_secret_basic` client may name itself in the `Authorization`
/// header alone; see [`extract_basic_client_id`] and [`extract_client_id`].
///
/// Returns `None` for a missing/empty/unparseable `client_id` — the caller
/// (the rate limiter) must fail SAFE by falling back to the IP key rather
/// than reject the request outright; rejecting a malformed body is the
/// handler's job (it returns a proper RFC 6749 `invalid_request` error),
/// not the rate limiter's.
pub fn extract_form_client_id(body: &[u8]) -> Option<String> {
    url::form_urlencoded::parse(body)
        .find(|(k, _)| k == "client_id")
        .map(|(_, v)| v.into_owned())
        .filter(|v| !v.is_empty())
}

/// The `client_id` an `Authorization: Basic` header names (RFC 6749 §2.3.1,
/// decoded by `axiam_oauth2::client_secret_basic` exactly as the handlers
/// decode it), or `None` for no header, another scheme, or a header that does
/// not decode.
///
/// T23.1.5. RFC 6749 §2.3.1 makes the body's `client_id` optional for a client
/// authenticating through the header, and 37 of the Basic OP suite's 38
/// modules send it there alone. A rate limiter that read the form only keyed
/// such a request on the source address whatever `AXIAM__RATE_LIMIT__KEY` said,
/// so a `client_secret_basic` client had no per-client bucket and its secret
/// could be guessed from as many addresses as the guesser owned. The secret
/// half of the credential is dropped on the floor here: only the id selects a
/// bucket, and the header is never logged.
pub fn extract_basic_client_id(authorization: &str) -> Option<String> {
    axiam_oauth2::client_secret_basic::parse_authorization_header(authorization)?
        .ok()
        .map(|credentials| credentials.client_id().to_owned())
}

/// The `client_id` a request names itself by: the form body's when present,
/// otherwise the `Authorization: Basic` header's.
///
/// The body wins because that is the order the handlers resolve it in
/// (`resolve_client_id`), and a request naming two different ids is refused
/// there before any secret is checked, so a caller cannot use the disagreement
/// to guess a secret under a bucket other than the one it is charged to.
pub fn extract_client_id(body: &[u8], authorization: Option<&str>) -> Option<String> {
    extract_form_client_id(body).or_else(|| authorization.and_then(extract_basic_client_id))
}

// ---------------------------------------------------------------------------
// #633 — principal keying (the authenticated federation flow routes only)
// ---------------------------------------------------------------------------

/// The principal a [`RateLimitKeyMode::Principal`] bucket is keyed on: the
/// `(tenant, sub)` of an access token whose signature, expiry and issuer were
/// **verified** for this request.
///
/// Built only by [`verified_principal`], from the
/// [`CachedUserIdentity`] that `axiam_audit::middleware::AuditMiddleware`
/// leaves on every request whose token verifies. That middleware wraps the
/// whole application (`axiam-server`'s `boot.rs`), so it has run before any
/// limiter here, and reusing its result is what keeps the principal key free:
/// no limiter verifies a signature, so a refused credential still costs the
/// verifications it cost before (§10, "one verify per refusal").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitPrincipal {
    /// The tenant the token was issued in (its `tenant_id` claim).
    pub tenant_id: Uuid,
    /// The token's subject (its `sub` claim).
    pub subject: Uuid,
    /// Whether the token is sender-constrained (`cnf`, RFC 8705 / RFC 9449).
    /// Its proof of possession is checked by the extractor, after the limiter,
    /// so here the token alone does not yet show its holder is the principal.
    pub sender_constrained: bool,
}

/// Left in a request's extensions by [`confirm_principal_session`] when the
/// session the request's token names is live (#786, R112W2-01) — the one fact
/// about admission [`verified_principal`] cannot read from the token itself.
///
/// It is a rate-limit key input and nothing else: the session extractor never
/// reads it and makes its own check, so the limiter's verdict cannot admit
/// anybody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrincipalSessionLive;

/// The principal and session of a verified token the session extractor could
/// admit, as far as that is decidable without the datastore.
fn admissible_principal(req: &ServiceRequest) -> Option<(RateLimitPrincipal, Uuid)> {
    let config = req.app_data::<web::Data<AuthConfig>>()?;
    let extensions = req.extensions();
    let cached = extensions.get::<Arc<CachedUserIdentity>>()?;
    let path_tenant = extensions
        .get::<TenantPathBinding>()
        .map(|binding| binding.tenant_id);
    let session = admissible_session(cached, config, path_tenant)?;
    let principal = RateLimitPrincipal {
        tenant_id: cached.tenant_id,
        subject: cached.user_id,
        sender_constrained: cached.claims.0.cnf.is_some(),
    };
    Some((principal, session))
}

/// Ask the session store whether the session behind this request's token is
/// live, and record [`PrincipalSessionLive`] when it is — the asynchronous
/// half of [`verified_principal`], run by the principal-keyed shared layer
/// (`RateLimitShared::keyed_on_principal`) before either limiter charges
/// (#786, R112W2-01).
///
/// The same [`SessionValidator`], with the same `(tenant, session)`, that
/// [`AuthenticatedUser`](crate::extractors::auth::AuthenticatedUser) asks after
/// the limiters. With no validator registered the extractor checks no session,
/// so neither does this: the session counts as live. A token
/// [`admissible_principal`] already declines costs no read.
///
/// The shared layer runs whether `AXIAM__RATE_LIMIT__SHARED` is on or off (off,
/// its counter allows everything), and sits outside the in-process governor on
/// each of the five routes, so the governor never charges a principal whose
/// session this has not confirmed.
pub async fn confirm_principal_session(req: &ServiceRequest) {
    let Some((principal, session)) = admissible_principal(req) else {
        return;
    };
    let validator = req
        .app_data::<web::Data<Arc<dyn SessionValidator>>>()
        .map(|d| d.get_ref().clone());
    let live = match validator {
        Some(validator) => {
            validator
                .is_session_active(principal.tenant_id, session)
                .await
        }
        None => true,
    };
    if live {
        req.extensions_mut().insert(PrincipalSessionLive);
    }
}

/// The verified principal of this request, or `None` when no token verified
/// or the token is one the session extractor would refuse.
///
/// **Reads, never verifies.** `None` covers "no token", "a token that did not
/// verify" (forged, expired, another issuer's) and "no audit middleware in this
/// composition" alike, and every one of them keys on the address — the
/// pre-authentication fallback, which is what every route keyed on before
/// #633. A caller cannot reach this with a claim it wrote itself: request
/// extensions are written by server code only, and the one writer of this
/// extension inserts it after `validate_access_token` succeeded.
///
/// #754 (R111-04): a verified signature is not enough. A token
/// [`AuthenticatedUser`](crate::extractors::auth::AuthenticatedUser) refuses —
/// a device-grant token, a resource-audience token a relying party holds —
/// must not spend the principal's allowance, or whoever holds one can drain
/// it from many addresses. So the principal is returned only for a token
/// [`admissible_session`] passes (no `AuthConfig` in scope: the extractor
/// would refuse every token, and so the address).
///
/// #786 (R112W2-01): nor for a token whose session is revoked or expired. That
/// needs the datastore, so [`confirm_principal_session`] asks it first and this
/// returns the principal only when it found the session live
/// ([`PrincipalSessionLive`]). The in-process governor beneath has no refund,
/// so the key has to be right before it charges: a stale token is keyed on its
/// address, in both layers. Without that check in the composition (a governor
/// with no principal-keyed shared layer outside it) every request is keyed on
/// its address.
pub fn verified_principal(req: &ServiceRequest) -> Option<RateLimitPrincipal> {
    if !req.extensions().contains::<PrincipalSessionLive>() {
        return None;
    }
    admissible_principal(req).map(|(principal, _)| principal)
}

/// The identity part of a bucket key — `{endpoint}:{this}` in the shared
/// counter, the whole key in the in-memory governor — for every key mode.
///
/// One function for both layers, so the shared counter
/// ([`crate::middleware::rate_limit_shared::RateLimitShared`]) and the
/// in-process governor ([`ClientAwareKeyExtractor`]) can never disagree about
/// which bucket a request belongs to: with `AXIAM__RATE_LIMIT__SHARED` on or
/// off, a route keys the same way.
///
/// `None` only when the key needs the address and there is none; the caller
/// then fails open (shared layer) or refuses the key (governor), as before.
pub fn bucket_key_part(
    key_mode: RateLimitKeyMode,
    ip: Option<IpAddr>,
    client_id: Option<&str>,
    principal: Option<&RateLimitPrincipal>,
) -> Option<String> {
    match (key_mode, client_id, principal) {
        // #633. A verified bearer token: the principal alone, from whichever
        // address it comes — one token used from many addresses is one
        // bucket, and one address relaying many users is many.
        (RateLimitKeyMode::Principal, _, Some(p)) if !p.sender_constrained => {
            Some(format!("principal:{}:{}", p.tenant_id, p.subject))
        }
        // A sender-constrained token, whose possession is not yet proved: the
        // address and the principal together, so a copy replayed from
        // elsewhere spends a bucket of its own and never its principal's.
        (RateLimitKeyMode::Principal, _, Some(p)) => {
            ip.map(|ip| format!("{ip}:principal:{}:{}", p.tenant_id, p.subject))
        }
        // No verified token (pre-authentication fallback), `ip` mode, or no
        // client_id available (fail-safe fallback): the address alone.
        (RateLimitKeyMode::Principal, _, None)
        | (RateLimitKeyMode::Ip, _, _)
        | (RateLimitKeyMode::ClientId | RateLimitKeyMode::IpClientId, None, _) => {
            ip.map(|ip| ip.to_string())
        }
        (RateLimitKeyMode::ClientId, Some(cid), _) => Some(format!("client:{cid}")),
        (RateLimitKeyMode::IpClientId, Some(cid), _) => ip.map(|ip| format!("{ip}:client:{cid}")),
    }
}

/// D8 key extractor for the token/introspect/revoke endpoints: honors
/// `AXIAM__RATE_LIMIT__KEY` (`ip` | `client_id` | `ip_client_id`) to key the
/// in-memory `Governor` bucket on the OAuth2 `client_id`, the `(ip,
/// client_id)` pair, or (default, unchanged behavior) IP alone.
///
/// **Never wire this onto `/auth/login` or any other endpoint without a
/// client identity** — see [`crate::config::rate_limit::RateLimitKeyMode`]
/// for why login is structurally excluded (it authenticates a user, not an
/// OAuth2 client; there is no `client_id` to key on at that point).
///
/// The same extractor in [`RateLimitKeyMode::Principal`] keys the five
/// authenticated federation flow routes on their verified principal (#633);
/// see [`verified_principal`]. It never reads a body in that mode.
#[derive(Debug, Clone)]
pub struct ClientAwareKeyExtractor {
    /// Always computed alongside the client_id — used verbatim in `Ip`
    /// mode, and as a namespace-safety prefix in `IpClientId` mode.
    pub ip_extractor: XForwardedForKeyExtractor,
    pub key_mode: RateLimitKeyMode,
}

impl ClientAwareKeyExtractor {
    pub fn new(ip_extractor: XForwardedForKeyExtractor, key_mode: RateLimitKeyMode) -> Self {
        Self {
            ip_extractor,
            key_mode,
        }
    }
}

impl KeyExtractor for ClientAwareKeyExtractor {
    type Key = String;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        let ip = self.ip_extractor.extract(req)?;

        let client_id = req
            .extensions()
            .get::<RateLimitClientId>()
            .and_then(|c| c.0.clone());
        let principal = match self.key_mode {
            RateLimitKeyMode::Principal => verified_principal(req),
            _ => None,
        };

        // With an address in hand every mode yields a key; `ok_or` is for the
        // type, not a reachable branch.
        bucket_key_part(
            self.key_mode,
            Some(ip),
            client_id.as_deref(),
            principal.as_ref(),
        )
        .ok_or_else(|| SimpleKeyExtractionError::new("no bucket key"))
    }

    /// Same 429 contract as [`XForwardedForKeyExtractor`] — clients must
    /// see one consistent rate-limit response shape regardless of which key
    /// mode rejected the request.
    fn exceed_rate_limit_response(
        &self,
        negative: &NotUntil<QuantaInstant>,
        mut response: actix_web::HttpResponseBuilder,
    ) -> HttpResponse {
        let wait_secs = negative
            .wait_time_from(DefaultClock::default().now())
            .as_secs();
        response
            .content_type(ContentType::json())
            .insert_header((RETRY_AFTER, wait_secs.to_string()))
            .body(format!(
                r#"{{"error":"rate_limit_exceeded","retry_after":{}}}"#,
                wait_secs
            ))
    }
}

#[cfg(test)]
mod client_aware_tests {
    use super::*;
    use actix_web::test::TestRequest;
    use std::net::SocketAddr;

    const PEER_A: &str = "203.0.113.9:1";

    fn basic(raw: &str) -> String {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    }

    /// T23.1.5. The Basic header names a client exactly as the handlers decode
    /// it, so the bucket a request is charged to is the one its credential
    /// would authenticate under.
    #[test]
    fn a_basic_header_names_the_client_the_handlers_would_authenticate() {
        assert_eq!(
            extract_basic_client_id(&basic("oa%5Fabc:secret")).as_deref(),
            Some("oa_abc"),
            "the id half is form-urldecoded"
        );
        assert_eq!(
            extract_basic_client_id(&basic("oa_abc:a:b")).as_deref(),
            Some("oa_abc")
        );
        for (raw, case) in [
            ("Bearer abc".to_owned(), "another scheme"),
            ("Basic !!!".to_owned(), "not base64"),
            (basic("no-colon"), "no separator"),
            (basic("oa_abc:"), "empty secret"),
            (basic(":secret"), "empty id"),
        ] {
            assert_eq!(extract_basic_client_id(&raw), None, "case: {case}");
        }
    }

    #[test]
    fn the_form_client_id_wins_over_the_header_and_the_header_fills_in_for_its_absence() {
        let header = basic("from_header:secret");
        assert_eq!(
            extract_client_id(b"client_id=from_form", Some(&header)).as_deref(),
            Some("from_form")
        );
        assert_eq!(
            extract_client_id(b"grant_type=client_credentials", Some(&header)).as_deref(),
            Some("from_header")
        );
        assert_eq!(
            extract_client_id(b"client_id=", Some(&header)).as_deref(),
            Some("from_header"),
            "an empty form value is no value"
        );
        assert_eq!(extract_client_id(b"grant_type=x", None), None);
    }
    const PEER_B: &str = "203.0.113.10:2";

    fn req_with_client_id(peer: &str, client_id: Option<&str>) -> ServiceRequest {
        let req = TestRequest::get()
            .peer_addr(peer.parse::<SocketAddr>().unwrap())
            .to_srv_request();
        req.extensions_mut()
            .insert(RateLimitClientId(client_id.map(str::to_owned)));
        req
    }

    #[test]
    fn ip_mode_ignores_client_id_and_matches_plain_ip_extractor() {
        let extractor = ClientAwareKeyExtractor::new(
            XForwardedForKeyExtractor::default(),
            RateLimitKeyMode::Ip,
        );
        let req = req_with_client_id(PEER_A, Some("client-a"));

        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, "203.0.113.9");
    }

    #[test]
    fn client_id_mode_gives_independent_buckets_per_client_under_one_ip() {
        let extractor = ClientAwareKeyExtractor::new(
            XForwardedForKeyExtractor::default(),
            RateLimitKeyMode::ClientId,
        );

        let req_a = req_with_client_id(PEER_A, Some("client-a"));
        let req_b = req_with_client_id(PEER_A, Some("client-b"));

        let key_a = extractor.extract(&req_a).unwrap();
        let key_b = extractor.extract(&req_b).unwrap();

        assert_ne!(
            key_a, key_b,
            "distinct client_ids behind the SAME IP must get distinct buckets (D8 NAT fix)"
        );
        assert!(!key_a.contains("203.0.113.9"));
    }

    #[test]
    fn client_id_mode_gives_same_bucket_for_same_client_from_different_ips() {
        let extractor = ClientAwareKeyExtractor::new(
            XForwardedForKeyExtractor::default(),
            RateLimitKeyMode::ClientId,
        );

        let req_a = req_with_client_id(PEER_A, Some("client-a"));
        let req_b = req_with_client_id(PEER_B, Some("client-a"));

        assert_eq!(
            extractor.extract(&req_a).unwrap(),
            extractor.extract(&req_b).unwrap()
        );
    }

    #[test]
    fn ip_client_id_mode_distinguishes_both_dimensions() {
        let extractor = ClientAwareKeyExtractor::new(
            XForwardedForKeyExtractor::default(),
            RateLimitKeyMode::IpClientId,
        );

        let same_client_diff_ip_a = req_with_client_id(PEER_A, Some("client-a"));
        let same_client_diff_ip_b = req_with_client_id(PEER_B, Some("client-a"));
        let diff_client_same_ip = req_with_client_id(PEER_A, Some("client-b"));

        let key1 = extractor.extract(&same_client_diff_ip_a).unwrap();
        let key2 = extractor.extract(&same_client_diff_ip_b).unwrap();
        let key3 = extractor.extract(&diff_client_same_ip).unwrap();

        assert_ne!(
            key1, key2,
            "same client_id from different IPs must differ in ip_client_id mode"
        );
        assert_ne!(
            key1, key3,
            "different client_id from same IP must differ in ip_client_id mode"
        );
    }

    #[test]
    fn missing_client_id_falls_back_to_ip_even_in_client_id_mode() {
        // Fail-SAFE: malformed/no client_id must not disable rate limiting —
        // it must still be limited, just by the coarser IP key.
        let extractor = ClientAwareKeyExtractor::new(
            XForwardedForKeyExtractor::default(),
            RateLimitKeyMode::ClientId,
        );
        let req = req_with_client_id(PEER_A, None);

        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, "203.0.113.9");
    }

    #[test]
    fn missing_extension_entirely_falls_back_to_ip() {
        // Defense in depth: if RateLimitShared never ran (mis-ordering bug),
        // the extractor must not panic — it degrades to IP-only, matching
        // pre-D8 behavior rather than failing open or crashing.
        let extractor = ClientAwareKeyExtractor::new(
            XForwardedForKeyExtractor::default(),
            RateLimitKeyMode::ClientId,
        );
        let req = TestRequest::get()
            .peer_addr(PEER_A.parse::<SocketAddr>().unwrap())
            .to_srv_request();

        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, "203.0.113.9");
    }

    /// Builds a `NotUntil` "rate limited" outcome directly from a real
    /// `governor::RateLimiter`, without going through a full `actix_governor`
    /// `Governor` middleware/request cycle: consume a 1-per-hour direct quota
    /// once (succeeds), then again (fails) — the failure is exactly the
    /// `NotUntil<QuantaInstant>` both `exceed_rate_limit_response` impls
    /// take. Neither impl is reached by any HTTP-round-trip test in this
    /// crate: those exercise `RateLimitShared`'s own 429 body
    /// (`middleware::rate_limit_shared::too_many_requests_response`), never
    /// the in-memory `Governor`'s per-`KeyExtractor` override.
    fn rate_limited_not_until() -> NotUntil<QuantaInstant> {
        use actix_governor::governor::{Quota, RateLimiter};
        use std::num::NonZeroU32;

        let quota = Quota::per_hour(NonZeroU32::new(1).unwrap());
        let limiter = RateLimiter::direct(quota);
        limiter.check().expect("first request must be allowed");
        limiter
            .check()
            .expect_err("second request within the same window must be rate-limited")
    }

    #[test]
    fn xff_extractor_exceed_rate_limit_response_shape() {
        let negative = rate_limited_not_until();
        let extractor = XForwardedForKeyExtractor::default();
        let resp = extractor.exceed_rate_limit_response(&negative, HttpResponse::TooManyRequests());

        assert_eq!(
            resp.status(),
            actix_web::http::StatusCode::TOO_MANY_REQUESTS
        );
        assert!(
            resp.headers().contains_key(RETRY_AFTER),
            "429 response must carry a Retry-After header (D-03)"
        );
        assert_eq!(
            resp.headers().get(actix_web::http::header::CONTENT_TYPE),
            Some(&actix_web::http::header::HeaderValue::from_static(
                "application/json"
            ))
        );
    }

    #[test]
    fn client_aware_extractor_exceed_rate_limit_response_shape() {
        let negative = rate_limited_not_until();
        let extractor = ClientAwareKeyExtractor::new(
            XForwardedForKeyExtractor::default(),
            RateLimitKeyMode::Ip,
        );
        let resp = extractor.exceed_rate_limit_response(&negative, HttpResponse::TooManyRequests());

        assert_eq!(
            resp.status(),
            actix_web::http::StatusCode::TOO_MANY_REQUESTS
        );
        assert!(resp.headers().contains_key(RETRY_AFTER));
    }

    fn principal(tenant: u128, subject: u128, sender_constrained: bool) -> RateLimitPrincipal {
        RateLimitPrincipal {
            tenant_id: Uuid::from_u128(tenant),
            subject: Uuid::from_u128(subject),
            sender_constrained,
        }
    }

    /// #633: a verified bearer principal is one bucket from any address, and
    /// two principals behind one address are two buckets.
    #[test]
    fn principal_mode_keys_on_the_principal_alone() {
        let ip_a: IpAddr = "203.0.113.9".parse().unwrap();
        let ip_b: IpAddr = "203.0.113.10".parse().unwrap();
        let alice = principal(1, 10, false);
        let bob = principal(1, 11, false);
        let key = |ip, p| bucket_key_part(RateLimitKeyMode::Principal, Some(ip), None, Some(p));

        assert_eq!(
            key(ip_a, &alice),
            key(ip_b, &alice),
            "one token, two addresses"
        );
        assert_ne!(key(ip_a, &alice), key(ip_a, &bob), "one address, two users");
        assert!(!key(ip_a, &alice).unwrap().contains("203.0.113.9"));
        assert_ne!(
            key(ip_a, &principal(1, 10, false)),
            key(ip_a, &principal(2, 10, false)),
            "the tenant is part of the key"
        );
    }

    /// #633: without a verified token the key is the address — byte for byte
    /// the key `build_governor` gives — and a sender-constrained token keys on
    /// the address and the principal together.
    #[test]
    fn principal_mode_falls_back_to_the_address_and_pairs_a_bound_token_with_it() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(
            bucket_key_part(RateLimitKeyMode::Principal, Some(ip), None, None).as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(
            bucket_key_part(RateLimitKeyMode::Principal, None, None, None),
            None
        );

        let bound = principal(1, 10, true);
        let unbound = principal(1, 10, false);
        let other_ip: IpAddr = "203.0.113.10".parse().unwrap();
        let bound_here = bucket_key_part(RateLimitKeyMode::Principal, Some(ip), None, Some(&bound));
        let bound_there = bucket_key_part(
            RateLimitKeyMode::Principal,
            Some(other_ip),
            None,
            Some(&bound),
        );
        let unbound_here =
            bucket_key_part(RateLimitKeyMode::Principal, Some(ip), None, Some(&unbound));
        assert_ne!(
            bound_here, bound_there,
            "a bound token's key carries the address"
        );
        assert_ne!(
            bound_here, unbound_here,
            "and is never the bearer principal's key"
        );
        assert_ne!(bound_here.as_deref(), Some("203.0.113.9"));
    }

    /// The principal mode ignores a client_id, and the other modes ignore a
    /// principal: each key is what it was before #633.
    #[test]
    fn the_modes_do_not_read_each_others_identity() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let p = principal(1, 10, false);
        assert_eq!(
            bucket_key_part(RateLimitKeyMode::Principal, Some(ip), Some("c"), None).as_deref(),
            Some("203.0.113.9")
        );
        for (mode, expected) in [
            (RateLimitKeyMode::Ip, "203.0.113.9"),
            (RateLimitKeyMode::ClientId, "client:c"),
            (RateLimitKeyMode::IpClientId, "203.0.113.9:client:c"),
        ] {
            assert_eq!(
                bucket_key_part(mode, Some(ip), Some("c"), Some(&p)).as_deref(),
                Some(expected),
                "{mode:?}"
            );
        }
    }

    #[test]
    fn extract_form_client_id_parses_and_rejects_empty() {
        assert_eq!(
            extract_form_client_id(
                b"grant_type=client_credentials&client_id=abc123&client_secret=s"
            ),
            Some("abc123".to_string())
        );
        assert_eq!(extract_form_client_id(b"client_id=&grant_type=x"), None);
        assert_eq!(extract_form_client_id(b"grant_type=x"), None);
        assert_eq!(extract_form_client_id(b""), None);
    }
}

/// R110W3-01: the one selection the route limiters make of the caller's address.
#[cfg(test)]
mod address_selection_tests {
    use super::*;
    use actix_web::test::TestRequest;

    /// The reverse proxy: the transport peer of every request below.
    const PROXY: &str = "10.0.0.2:443";
    const A: &str = "198.51.100.9";
    const B: &str = "203.0.113.7";

    fn headers(xff: Option<&str>) -> HeaderMap {
        let mut req = TestRequest::get();
        if let Some(value) = xff {
            req = req.insert_header(("X-Forwarded-For", value));
        }
        req.to_http_request().headers().clone()
    }

    fn select(xff: Option<&str>, trusted_hops: usize) -> (Option<IpAddr>, Option<usize>) {
        select_rate_limit_ip(
            &headers(xff),
            Some(PROXY.parse().unwrap()),
            trusted_hops,
            &TrustedProxies::default(),
        )
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    fn proxy() -> Option<IpAddr> {
        Some(PROXY.parse::<SocketAddr>().unwrap().ip())
    }

    #[test]
    fn behind_one_proxy_the_key_is_the_address_the_proxy_appended() {
        assert_eq!(select(Some(A), 0), (ip(A), None));
        // An untrusted entry the client wrote itself sits to the LEFT of the
        // one the proxy appends, so it does not change the key: a caller at A
        // cannot charge its requests to B's bucket.
        assert_eq!(select(Some(&format!("{B}, {A}")), 0), (ip(A), None));
        assert_eq!(select(Some(&format!("{B},{B}, {A}")), 0), (ip(A), None));
    }

    #[test]
    fn trusted_hops_at_or_above_the_hop_count_falls_back_to_the_peer() {
        // The T-212 off-by-one (`1` behind one proxy): the header cannot be
        // trusted, so the key is the peer, and the discard is reported for
        // R-4's signal.
        assert_eq!(select(Some(A), 1), (proxy(), Some(1)));
        assert_eq!(select(Some(&format!("{B}, {A}")), 2), (proxy(), Some(2)));
        assert_eq!(select(Some(&format!("{B}, {A}")), 5), (proxy(), Some(2)));
        // One hop more than trusted reaches the client again.
        assert_eq!(select(Some(&format!("{B}, {A}")), 1), (ip(B), None));
    }

    #[test]
    fn no_header_or_an_unparseable_entry_falls_back_to_the_peer() {
        assert_eq!(select(None, 0), (proxy(), None));
        assert_eq!(select(Some("not-an-address"), 0), (proxy(), None));
        assert_eq!(
            select_rate_limit_ip(&headers(Some(A)), None, 1, &TrustedProxies::default()),
            (None, Some(1)),
            "no peer and nothing trusted is no key"
        );
    }

    #[test]
    fn a_peer_outside_the_proxy_list_is_keyed_on_itself() {
        let listed = TrustedProxies::parse("10.0.0.0/24").unwrap();
        let elsewhere = TrustedProxies::parse("192.0.2.0/24").unwrap();
        let peer = Some(PROXY.parse().unwrap());
        // The peer is a listed proxy: its header is read under `trusted_hops`.
        assert_eq!(
            select_rate_limit_ip(&headers(Some(A)), peer, 0, &listed),
            (ip(A), None)
        );
        // It is not: the header is the caller's, and is not read at all, at
        // any `trusted_hops`, and is not an R-4 discard.
        for hops in [0, 1, 5] {
            assert_eq!(
                select_rate_limit_ip(&headers(Some(A)), peer, hops, &elsewhere),
                (proxy(), None),
                "trusted_hops {hops}"
            );
        }
        // No peer under a list: nothing to check, no key.
        assert_eq!(
            select_rate_limit_ip(&headers(Some(A)), None, 0, &listed),
            (None, None)
        );
    }
}
