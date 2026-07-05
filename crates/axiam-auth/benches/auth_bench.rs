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
use axiam_auth::token::{AUD_USER, issue_access_token};
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

criterion_group!(
    benches,
    bench_hash_password,
    bench_verify_password,
    bench_issue_access_token
);
criterion_main!(benches);
