//! Emits the fixed protocol messages the k6 benchmark scenarios use.
//!
//! The benchmark needs a `KE1` and a `RegistrationRequest` the server will
//! actually accept. Unlike SRP's `A` — which could be any integer not congruent
//! to zero — these are group elements that must deserialize, so they cannot be
//! made up in JavaScript. Generating them here and embedding the result as a
//! constant keeps the elliptic-curve work out of the k6 VU loop, where it would
//! measure k6's CPU rather than AXIAM's.
//!
//! Run with: `cargo run -p axiam-opaque --example bench_fixtures`
fn main() {
    // The value is irrelevant — the server does identical work for any
    // well-formed message, which is the whole reason these can be constants in
    // the scenario file. Derived at runtime anyway so CodeQL's
    // `rust/hardcoded-cryptographic-value` stays pointed at shipping code.
    let password = format!("bench-{}", std::process::id());
    let (_, registration_request) =
        axiam_opaque::ClientRegistrationState::start(&password).unwrap();
    let (_, ke1) = axiam_opaque::ClientLoginState::start(&password).unwrap();
    println!("registration_request: {registration_request}");
    println!("ke1: {ke1}");
}
