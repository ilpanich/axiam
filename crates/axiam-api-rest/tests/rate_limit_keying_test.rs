//! Negative tests for the rate-limit key extractor (SECHRD-03 / SEC-048+060, D-01d).
//!
//! Proves that `XForwardedForKeyExtractor` no longer keys off the
//! client-controlled leftmost `X-Forwarded-For` hop when there are not
//! enough trusted hops to derive a real client IP — it must fall through to
//! `peer_addr()` instead. Before the fix, an attacker could rotate the XFF
//! header on every request to get a fresh rate-limit bucket per request,
//! completely evading brute-force protection.

use actix_governor::KeyExtractor;
use actix_web::HttpMessage;
use actix_web::test::TestRequest;
use axiam_api_rest::config::rate_limit::RateLimitKeyMode;
use axiam_api_rest::extractors::rate_limit::{
    ClientAwareKeyExtractor, RateLimitClientId, XForwardedForKeyExtractor,
};
use axiam_api_rest::extractors::xff_metrics;
use std::net::{IpAddr, SocketAddr};

/// Fixed loopback peer address representing the real (trusted) TCP peer —
/// e.g. the connection accepted from a reverse proxy or, in the
/// insufficient-hops case, directly from the client.
const TEST_PEER: &str = "203.0.113.9:54321";

fn peer_ip() -> IpAddr {
    TEST_PEER.parse::<SocketAddr>().unwrap().ip()
}

/// Core regression test (must be named exactly this — referenced by the plan's
/// verify command): rotating X-Forwarded-For per request no longer yields a
/// fresh rate-limit bucket when trusted_hops >= hops.len().
#[actix_web::test]
async fn rate_limit_xff_rotation_rejected() {
    // Single-hop XFF header (as an attacker directly hitting the server would
    // send, with no real trusted proxy in front of it) but trusted_hops is
    // configured for a proxy chain that never materializes — the classic
    // misconfiguration/attack surface this fix closes.
    let extractor = XForwardedForKeyExtractor::with_trusted_hops(1);

    let rotating_xff_values = [
        "1.2.3.4",
        "5.6.7.8",
        "9.10.11.12",
        "255.255.255.255",
        "8.8.8.8",
    ];

    let mut resolved_keys = Vec::new();
    for xff in rotating_xff_values {
        let req = TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .insert_header(("X-Forwarded-For", xff))
            .to_srv_request();

        let key = extractor.extract(&req).expect("key extraction succeeds");
        resolved_keys.push(key);
    }

    // Every rotated XFF value must resolve to the SAME bucket (peer_addr),
    // never to the client-controlled hop that changed on every request.
    assert!(
        resolved_keys.iter().all(|k| *k == peer_ip()),
        "expected every request to key off peer_addr() ({peer_ip}), got: {resolved_keys:?}",
        peer_ip = peer_ip(),
    );

    let unique_keys: std::collections::HashSet<_> = resolved_keys.iter().collect();
    assert_eq!(
        unique_keys.len(),
        1,
        "rotating X-Forwarded-For must not produce distinct rate-limit buckets"
    );
}

/// Explicit assertion that the insufficient-hops branch never indexes
/// `hops[0]` (the old buggy fallback) — it must equal peer_addr(), not the
/// attacker-controlled leftmost hop.
#[actix_web::test]
async fn insufficient_hops_falls_through_to_peer_addr_not_leftmost_hop() {
    let extractor = XForwardedForKeyExtractor::with_trusted_hops(5);

    let req = TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .insert_header(("X-Forwarded-For", "198.51.100.7, 198.51.100.8"))
        .to_srv_request();

    let key = extractor.extract(&req).expect("key extraction succeeds");

    assert_eq!(
        key,
        peer_ip(),
        "insufficient trusted_hops must key off peer_addr(), not any XFF hop"
    );
    assert_ne!(
        key,
        "198.51.100.7".parse::<IpAddr>().unwrap(),
        "must never key off the leftmost (client-controlled) hop"
    );
}

/// Regression guard: the sufficient-hops right-indexed selection path must
/// remain unchanged by this fix.
#[actix_web::test]
async fn sufficient_hops_still_selects_right_indexed_hop() {
    // hops = [attacker, real-client, trusted-proxy]; trusted_hops = 1 →
    // idx = 3 - 1 - 1 = 1 → "real-client".
    let extractor = XForwardedForKeyExtractor::with_trusted_hops(1);

    let req = TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .insert_header((
            "X-Forwarded-For",
            "203.0.113.50, 203.0.113.51, 203.0.113.52",
        ))
        .to_srv_request();

    let key = extractor.extract(&req).expect("key extraction succeeds");

    assert_eq!(
        key,
        "203.0.113.51".parse::<IpAddr>().unwrap(),
        "sufficient-hops path must still select the rightmost-untrusted hop"
    );
}

// ---------------------------------------------------------------------------
// D8 — client-identity-aware keying (`ClientAwareKeyExtractor`)
//
// `ClientAwareKeyExtractor` is what the in-memory `Governor` uses on
// `/oauth2/token`, `/oauth2/revoke`, and `/oauth2/introspect` (see
// `server.rs::build_client_aware_governor`). It reads the `client_id`
// stashed into request extensions by
// `middleware::rate_limit_shared::RateLimitShared::new_client_identity_aware`
// (which always runs first — it is wired as the OUTER `.wrap()`). These
// tests exercise the extractor directly via that same extension contract.
// End-to-end (real middleware + real 429 responses) coverage lives in
// `rate_limit_client_identity_test.rs`.
// ---------------------------------------------------------------------------

fn req_with_stashed_client_id(
    peer: &str,
    client_id: Option<&str>,
) -> actix_web::dev::ServiceRequest {
    let req = TestRequest::get()
        .peer_addr(peer.parse::<SocketAddr>().unwrap())
        .to_srv_request();
    req.extensions_mut()
        .insert(RateLimitClientId(client_id.map(str::to_owned)));
    req
}

#[test]
fn client_aware_extractor_ip_mode_matches_plain_ip_extractor() {
    // D8 acceptance: `ip` mode (the default) must be indistinguishable from
    // the plain `XForwardedForKeyExtractor` used everywhere else.
    let plain = XForwardedForKeyExtractor::default();
    let client_aware = ClientAwareKeyExtractor::new(plain.clone(), RateLimitKeyMode::Ip);

    let req = req_with_stashed_client_id(TEST_PEER, Some("some-client"));

    let plain_key = plain.extract(&req).unwrap().to_string();
    let aware_key = client_aware.extract(&req).unwrap();

    assert_eq!(
        aware_key, plain_key,
        "ip mode must ignore any stashed client_id and match plain IP keying exactly"
    );
}

#[test]
fn client_aware_extractor_distinguishes_clients_under_one_ip_in_client_id_mode() {
    let extractor = ClientAwareKeyExtractor::new(
        XForwardedForKeyExtractor::default(),
        RateLimitKeyMode::ClientId,
    );

    let req_a = req_with_stashed_client_id(TEST_PEER, Some("client-a"));
    let req_b = req_with_stashed_client_id(TEST_PEER, Some("client-b"));

    let key_a = extractor.extract(&req_a).unwrap();
    let key_b = extractor.extract(&req_b).unwrap();

    assert_ne!(
        key_a, key_b,
        "distinct client_ids behind the SAME peer IP must get distinct buckets"
    );
}

#[test]
fn client_aware_extractor_ip_client_id_mode_distinguishes_both() {
    let extractor = ClientAwareKeyExtractor::new(
        XForwardedForKeyExtractor::default(),
        RateLimitKeyMode::IpClientId,
    );

    const OTHER_PEER: &str = "198.51.100.20:1";

    let same_client_diff_ip_1 = req_with_stashed_client_id(TEST_PEER, Some("client-a"));
    let same_client_diff_ip_2 = req_with_stashed_client_id(OTHER_PEER, Some("client-a"));
    let diff_client_same_ip = req_with_stashed_client_id(TEST_PEER, Some("client-b"));

    let k1 = extractor.extract(&same_client_diff_ip_1).unwrap();
    let k2 = extractor.extract(&same_client_diff_ip_2).unwrap();
    let k3 = extractor.extract(&diff_client_same_ip).unwrap();

    assert_ne!(k1, k2, "same client_id from a different IP must differ");
    assert_ne!(k1, k3, "different client_id from the same IP must differ");
}

#[test]
fn client_aware_extractor_falls_back_to_ip_when_no_client_id_present() {
    // Fail-SAFE: `client_id` mode with no resolvable client_id (malformed
    // body, or the extension was never stashed) must still rate-limit — by
    // falling back to the IP key, not by disabling the limiter.
    let extractor = ClientAwareKeyExtractor::new(
        XForwardedForKeyExtractor::default(),
        RateLimitKeyMode::ClientId,
    );

    let with_no_client_id = req_with_stashed_client_id(TEST_PEER, None);
    let key = extractor.extract(&with_no_client_id).unwrap();
    assert_eq!(key, peer_ip().to_string());
}

// ---------------------------------------------------------------------------
// Topology derivation (public-backend-TLS design §4)
// ---------------------------------------------------------------------------
//
// These pin the rule that decides what an operator sets:
//
//   trusted_hops = (reverse proxies between the client and this server) - 1
//
// because a proxy appends the address it received FROM, so the nearest proxy is
// the socket peer and never appears in the header. The rule used to be
// documented as "= the proxy count", which is off by one and, at one proxy,
// discards the header and keys every client on the internet to the proxy's own
// address. That is not a hypothetical: it was the live behaviour of the only
// deployment the repository documented end to end.

/// The Compose/Pi topology and `k8s/ingress.yml`: exactly one appending proxy
/// (Caddy, or ingress-nginx) in front of the server. The proxy sets
/// `X-Forwarded-For: <client>` and is itself the peer, so the default 0 is
/// correct and selects the real client.
#[actix_web::test]
async fn one_proxy_with_default_zero_selects_the_real_client() {
    let extractor = XForwardedForKeyExtractor::with_trusted_hops(0);

    let req = TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .insert_header(("X-Forwarded-For", "198.51.100.23"))
        .to_srv_request();

    assert_eq!(
        extractor.extract(&req).expect("key extraction succeeds"),
        "198.51.100.23".parse::<IpAddr>().unwrap(),
        "behind one appending proxy, trusted_hops=0 must key off the client"
    );
}

/// The same single-proxy topology, with a client that sends its own
/// `X-Forwarded-For` to try to mint a fresh bucket. The proxy appends the real
/// peer to the right of the spoof, so 0 still selects the real client and the
/// spoof is inert. This is the property that makes 0 the right default rather
/// than merely the convenient one.
#[actix_web::test]
async fn one_proxy_ignores_a_client_supplied_xff_prefix() {
    let extractor = XForwardedForKeyExtractor::with_trusted_hops(0);

    let req = TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        // "<attacker's invention>, <what the proxy appended>"
        .insert_header(("X-Forwarded-For", "10.0.0.1, 198.51.100.23"))
        .to_srv_request();

    assert_eq!(
        extractor.extract(&req).expect("key extraction succeeds"),
        "198.51.100.23".parse::<IpAddr>().unwrap(),
        "a client-supplied XFF prefix must not shift the selected hop"
    );
}

/// The topology this change removes: Caddy → nginx → server. nginx appends
/// Caddy's address, so the header carries one proxy entry and the correct value
/// is 1. Kept as a test because the shape is still legal — an operator who
/// keeps the old routing needs it — and because it is the case the old default
/// of 0 got wrong.
#[actix_web::test]
async fn two_proxies_need_one_trusted_hop() {
    let header = "198.51.100.23, 192.0.2.10"; // <client>, <caddy>

    let correct = XForwardedForKeyExtractor::with_trusted_hops(1);
    let req = TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .insert_header(("X-Forwarded-For", header))
        .to_srv_request();
    assert_eq!(
        correct.extract(&req).expect("key extraction succeeds"),
        "198.51.100.23".parse::<IpAddr>().unwrap(),
        "two appending proxies must be configured as trusted_hops=1"
    );

    // What the shipped default did to that topology: it selected the middle
    // proxy's address, so every client on the internet shared one bucket.
    let wrong = XForwardedForKeyExtractor::with_trusted_hops(0);
    let req = TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .insert_header(("X-Forwarded-For", header))
        .to_srv_request();
    assert_eq!(
        wrong.extract(&req).expect("key extraction succeeds"),
        "192.0.2.10".parse::<IpAddr>().unwrap(),
        "regression witness: trusted_hops=0 behind TWO proxies keys off the \
         inner proxy, collapsing every client into a single bucket"
    );
}

/// Three proxies (cloud L7 load balancer → ingress → mesh sidecar) carry two
/// proxy entries, so the value is 2. Completes the table in the extractor's
/// module docs.
#[actix_web::test]
async fn three_proxies_need_two_trusted_hops() {
    let extractor = XForwardedForKeyExtractor::with_trusted_hops(2);

    let req = TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        // <client>, <lb>, <ingress>
        .insert_header(("X-Forwarded-For", "198.51.100.23, 192.0.2.10, 192.0.2.11"))
        .to_srv_request();

    assert_eq!(
        extractor.extract(&req).expect("key extraction succeeds"),
        "198.51.100.23".parse::<IpAddr>().unwrap(),
        "three appending proxies must be configured as trusted_hops=2"
    );
}

/// Setting the value to the *proxy count* rather than the count minus one —
/// the advice the docs used to give — makes `trusted_hops >= hops.len()`, so
/// the header is discarded and the key becomes the proxy's own address. Every
/// client collapses into one bucket, including on `/auth/login`, which is
/// deliberately always keyed per-IP.
///
/// This is the exact failure the corrected documentation exists to prevent, so
/// it is asserted rather than described.
#[actix_web::test]
async fn the_old_off_by_one_advice_collapses_every_client_into_one_bucket() {
    // One proxy in front, told (wrongly) that there is one *entry* to skip.
    let extractor = XForwardedForKeyExtractor::with_trusted_hops(1);

    let first = TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .insert_header(("X-Forwarded-For", "198.51.100.23"))
        .to_srv_request();
    let second = TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .insert_header(("X-Forwarded-For", "203.0.113.77"))
        .to_srv_request();

    let a = extractor.extract(&first).expect("key extraction succeeds");
    let b = extractor.extract(&second).expect("key extraction succeeds");

    assert_eq!(a, peer_ip());
    assert_eq!(
        a, b,
        "two different clients must NOT share a key — they do here, which is \
         why trusted_hops = proxies - 1 rather than proxies"
    );
}

// ---------------------------------------------------------------------------
// R-4 — a discarded X-Forwarded-For is observable (narrows T-212/T-233)
// ---------------------------------------------------------------------------

/// Serializes the three counter tests below.
///
/// `axiam_rate_limit_xff_discarded_total` is one process-wide atomic, and
/// these tests measure a delta across one extraction. Without this, a test
/// reading `before`, extracting, and reading `after` can have another test's
/// increment land in between — which is not hypothetical: it is what turned
/// this suite red on CI while it passed locally, four runs in six once the
/// interleaving was forced.
///
/// A `std::sync::Mutex` rather than a `tokio` one on purpose: `#[actix_web::test]`
/// bodies are futures driven to completion on one thread, and the guard is held
/// across no await point that could yield to another test.
fn counter_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The fallback above is correct and stays. What R-4 adds is that it is no
/// longer *silent*.
///
/// T-212 is an off-by-one in `trusted_hops` that nobody noticed: with it one
/// too high, every client keyed to the proxy's address, the whole deployment
/// shared one bucket, and nothing in any log said so. The symptom is "the rate
/// limit is mysteriously strict", which an operator fixes by raising the limit.
///
/// These assert on **deltas**, not absolute values, and they take
/// [`counter_lock`] first: the counter is process-global, `cargo test` runs
/// these on threads of one process, and a read-modify-read across another
/// test's increment is exactly the interleaving that made this suite fail on
/// CI and pass locally. A test guarding an observability signal must not have
/// an intermittent failure of its own.
#[actix_web::test]
async fn a_discarded_xff_is_counted() {
    let _guard = counter_lock();
    let extractor = XForwardedForKeyExtractor::with_trusted_hops(3);
    let before = xff_metrics::xff_discarded();

    let req = TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .insert_header(("X-Forwarded-For", "198.51.100.7"))
        .to_srv_request();
    let key = extractor.extract(&req).expect("key extraction succeeds");

    assert_eq!(key, peer_ip(), "the key must still be the verified peer");
    assert_eq!(
        xff_metrics::xff_discarded() - before,
        1,
        "a header discarded by trusted_hops must be counted, or the one-bucket \
         failure is visible only in an incident"
    );
}

/// A header with enough hops is *used*, so nothing is discarded and nothing is
/// counted. Without this, a counter that incremented on every request would
/// look identical to a misconfiguration and mean nothing.
#[actix_web::test]
async fn a_trusted_xff_is_not_counted() {
    let _guard = counter_lock();
    let extractor = XForwardedForKeyExtractor::with_trusted_hops(1);
    let before = xff_metrics::xff_discarded();

    let req = TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .insert_header(("X-Forwarded-For", "198.51.100.7, 198.51.100.8"))
        .to_srv_request();
    let key = extractor.extract(&req).expect("key extraction succeeds");

    assert_eq!(key, "198.51.100.7".parse::<IpAddr>().unwrap());
    assert_eq!(
        xff_metrics::xff_discarded(),
        before,
        "a header that was trusted and used is not a discard"
    );
}

/// No header at all is **not** a misconfiguration: it is a client with no proxy
/// in front of it, reaching a server that correctly keys on the peer. Counting
/// it would bury the signal under every direct request the deployment serves.
#[actix_web::test]
async fn a_request_with_no_xff_is_not_counted() {
    let _guard = counter_lock();
    let extractor = XForwardedForKeyExtractor::with_trusted_hops(3);
    let before = xff_metrics::xff_discarded();

    let req = TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .to_srv_request();
    let key = extractor.extract(&req).expect("key extraction succeeds");

    assert_eq!(key, peer_ip());
    assert_eq!(
        xff_metrics::xff_discarded(),
        before,
        "a client with no proxy is not a misconfiguration"
    );
}
