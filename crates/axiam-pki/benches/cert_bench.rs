//! Criterion micro-benchmark for the X.509 chain-verify hot path (PERF-05).
//!
//! Benches ONLY the isolated `verify_signature` step used by
//! `DeviceAuthService::authenticate` (crates/axiam-pki/src/mtls.rs) — NOT the
//! full `authenticate()` flow, which requires DB repositories. No
//! crypto/verification source is modified (V6, T-27-40).
//!
//! Fixtures (a self-signed CA + one leaf cert signed by it) are built ONCE
//! via `rcgen` outside the timed closure, mirroring how `axiam-pki`'s own
//! `cert.rs`/`ca.rs` construct certificates.
//!
//! Run locally with: `cargo bench -p axiam-pki`
//! Not wired into CI (D-15) — manual/local only, documentation-only report.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair};
use x509_parser::prelude::parse_x509_certificate;

/// Generate a self-signed CA cert + one leaf cert signed by it, returning
/// their DER bytes. Built ONCE — outside every timed closure.
fn build_fixtures() -> (Vec<u8>, Vec<u8>) {
    let ca_key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("CA keygen must succeed");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params must build");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Bench Test CA");
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params
        .self_signed(&ca_key_pair)
        .expect("CA self-sign must succeed");

    let leaf_key_pair =
        KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("leaf keygen must succeed");
    let mut leaf_params =
        CertificateParams::new(Vec::<String>::new()).expect("leaf params must build");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "bench-test-device-001");
    leaf_params.is_ca = IsCa::NoCa;
    // rcgen 0.14: sign via an `Issuer` (CA params + signing key) rather than the
    // old `signed_by(key, &cert, &issuer_key)` 3-arg form. Same CA DN + key, so
    // the resulting chain is unchanged.
    let ca_issuer = Issuer::from_params(&ca_params, ca_key_pair);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key_pair, &ca_issuer)
        .expect("leaf signing must succeed");

    (ca_cert.der().to_vec(), leaf_cert.der().to_vec())
}

fn bench_parse_and_verify_signature(c: &mut Criterion) {
    let (ca_der, leaf_der) = build_fixtures();

    c.bench_function("cert_verify_signature (X.509 chain verify)", |b| {
        b.iter(|| {
            // Parse both certs from DER on every iteration — matches
            // `DeviceAuthService::authenticate`'s actual per-request work
            // (parse_x509_pem + parse_x509_certificate happen per call, only
            // the DB round-trips are excluded here).
            let (_, ca_x509) =
                parse_x509_certificate(black_box(&ca_der)).expect("CA cert must parse");
            let (_, client_x509) =
                parse_x509_certificate(black_box(&leaf_der)).expect("leaf cert must parse");

            client_x509
                .verify_signature(Some(ca_x509.public_key()))
                .expect("leaf must verify against CA public key");
        })
    });
}

criterion_group!(benches, bench_parse_and_verify_signature);
criterion_main!(benches);
