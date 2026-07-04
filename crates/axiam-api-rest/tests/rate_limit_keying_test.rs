//! Negative tests for the rate-limit key extractor (SECHRD-03 / SEC-048+060, D-01d).
//!
//! Proves that `XForwardedForKeyExtractor` no longer keys off the
//! client-controlled leftmost `X-Forwarded-For` hop when there are not
//! enough trusted hops to derive a real client IP — it must fall through to
//! `peer_addr()` instead. Before the fix, an attacker could rotate the XFF
//! header on every request to get a fresh rate-limit bucket per request,
//! completely evading brute-force protection.

use actix_governor::KeyExtractor;
use actix_web::test::TestRequest;
use axiam_api_rest::extractors::rate_limit::XForwardedForKeyExtractor;
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
