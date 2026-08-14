//! Criterion micro-benchmarks for the auth hot paths (PERF-05).
//!
//! Benches ONLY measure around the existing, already-correct crypto/token
//! functions in `axiam_auth::password` and `axiam_auth::token` — no
//! crypto/verification source is modified (V6, T-27-40).
//!
//! Run locally with: `cargo bench -p axiam-auth`
//! Not wired into CI (D-15) — manual/local only, documentation-only report.

use std::hint::black_box;

use axiam_auth::config::AuthConfig;
use axiam_auth::password::{hash_password, verify_password};
use axiam_auth::token::{
    AUD_USER, CnfClaim, issue_access_token, issue_access_token_bound, verify_certificate_binding,
};
use criterion::{Criterion, criterion_group, criterion_main};
use uuid::Uuid;

/// Pre-generated Ed25519 test key pair (PEM), same fixture used by
/// `axiam-auth`'s own unit tests (`token.rs::tests::test_keypair`).
/// Generated with: openssl genpkey -algorithm Ed25519
fn test_keypair() -> (String, String) {
    let private_key = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----"; // nosemgrep: generic.secrets.security.detected-private-key
    let public_key = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
    (private_key.into(), public_key.into())
}

/// Build a bench `AuthConfig` with the Ed25519 test key pair pre-resolved
/// (`resolve_keys()` called ONCE here, outside every timed closure below) so
/// `issue_access_token` measures steady-state EdDSA signing cost, not
/// per-call PEM parsing.
fn bench_config() -> AuthConfig {
    let (priv_pem, pub_pem) = test_keypair();
    let mut config = AuthConfig {
        jwt_private_key_pem: priv_pem,
        jwt_public_key_pem: pub_pem,
        ..Default::default()
    };
    config
        .resolve_keys()
        .expect("test Ed25519 key pair must parse");
    config
}

fn bench_hash_password(c: &mut Criterion) {
    c.bench_function("hash_password (Argon2id, OWASP params)", |b| {
        b.iter(|| {
            hash_password(black_box("Sup3r-Secret-Passw0rd!"), black_box(None)).unwrap();
        })
    });
}

fn bench_verify_password(c: &mut Criterion) {
    // Hash ONCE outside the timed closure — the bench measures steady-state
    // verify cost, matching how a login request only ever verifies (never
    // re-hashes) an existing stored hash.
    let hash = hash_password("Sup3r-Secret-Passw0rd!", None).unwrap();

    c.bench_function("verify_password (Argon2id, steady state)", |b| {
        b.iter(|| {
            verify_password(
                black_box("Sup3r-Secret-Passw0rd!"),
                black_box(&hash),
                black_box(None),
            )
            .unwrap();
        })
    });
}

fn bench_issue_access_token(c: &mut Criterion) {
    let config = bench_config();
    let user_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let scopes = vec!["read".to_string(), "write".to_string()];

    c.bench_function("issue_access_token (EdDSA mint, steady state)", |b| {
        b.iter(|| {
            issue_access_token(
                black_box(user_id),
                black_box(tenant_id),
                black_box(org_id),
                black_box(&scopes),
                black_box(&config),
                black_box(Uuid::new_v4().to_string()),
                black_box(AUD_USER),
            )
            .unwrap();
        })
    });
}

/// X5.1 — the cost of certificate binding, isolated.
///
/// X5.1's gap table claims certificate-bound tokens are near-free "because the
/// cert is already verified in-process". This bench measures the part of that
/// claim that lives inside AXIAM: minting a token WITH a `cnf.x5t#S256`
/// confirmation versus minting the identical token without one, plus the
/// SHA-256 thumbprint that produces the claim's value.
///
/// # What this does and does not establish
///
/// It establishes the **mint-path delta**: the extra work `issue_access_token`
/// does per bound token, with no I/O, no network, no TLS and no datastore in
/// the picture. That is the right measurement for the mechanism, because the
/// mechanism's whole argument is that the expensive part (verifying the
/// certificate) already happened during the handshake.
///
/// It does **not** establish the end-to-end request-level overhead a
/// deployment sees — that is a function of everything else on the token path
/// (two database round-trips, TLS record handling, serialization) and of how
/// much of the request budget the mint occupies. A delta that is large in
/// relative terms here can be invisible end-to-end, and a claim about
/// req/s belongs to `benchmarks/`'s `bench-quick`, not here.
fn bench_certificate_binding(c: &mut Criterion) {
    let config = bench_config();
    let user_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let scopes = vec!["read".to_string(), "write".to_string()];
    // A real 43-character base64url SHA-256 thumbprint.
    let thumbprint = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    // The A of the A/B: identical call, no confirmation claim.
    c.bench_function(
        "issue_access_token_bound (unbound — the A of the A/B)",
        |b| {
            b.iter(|| {
                issue_access_token_bound(
                    black_box(user_id),
                    black_box(tenant_id),
                    black_box(org_id),
                    black_box(&scopes),
                    black_box(&config),
                    black_box(Uuid::new_v4().to_string()),
                    black_box(AUD_USER),
                    black_box(None),
                )
                .unwrap();
            })
        },
    );

    // The B: same call, plus the cnf claim. The delta between these two IS the
    // per-token cost of certificate binding at the mint.
    c.bench_function(
        "issue_access_token_bound (certificate-bound — the B of the A/B)",
        |b| {
            b.iter(|| {
                issue_access_token_bound(
                    black_box(user_id),
                    black_box(tenant_id),
                    black_box(org_id),
                    black_box(&scopes),
                    black_box(&config),
                    black_box(Uuid::new_v4().to_string()),
                    black_box(AUD_USER),
                    black_box(Some(CnfClaim::from_certificate_thumbprint(thumbprint))),
                )
                .unwrap();
            })
        },
    );

    // The other half of the per-request cost: deriving the thumbprint from the
    // DER certificate the handshake already verified. Sized at 1 KiB, a
    // realistic RSA-2048 leaf.
    let der = vec![0x42u8; 1024];
    c.bench_function("thumbprint_s256 (SHA-256 over a 1 KiB DER leaf)", |b| {
        b.iter(|| {
            // Inlined rather than calling axiam_oauth2 — axiam-auth must not
            // depend on the crate above it, and the operation is exactly a
            // SHA-256 plus a base64url encode either way.
            use base64::Engine as _;
            use sha2::{Digest, Sha256};
            black_box(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(Sha256::digest(black_box(&der))),
            );
        })
    });

    // And the resource-server side, which every request to a protected
    // endpoint pays once the binding is in use.
    let bound_claims = {
        let token = issue_access_token_bound(
            user_id,
            tenant_id,
            org_id,
            &scopes,
            &config,
            Uuid::new_v4().to_string(),
            AUD_USER,
            Some(CnfClaim::from_certificate_thumbprint(thumbprint)),
        )
        .unwrap();
        axiam_auth::token::validate_access_token(&token, &config)
            .unwrap()
            .0
    };
    c.bench_function("verify_certificate_binding (resource-server check)", |b| {
        b.iter(|| {
            verify_certificate_binding(black_box(&bound_claims), black_box(Some(thumbprint)))
                .unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_hash_password,
    bench_verify_password,
    bench_issue_access_token,
    bench_certificate_binding
);
criterion_main!(benches);
