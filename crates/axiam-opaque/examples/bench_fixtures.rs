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
    let (_, registration_request) =
        axiam_opaque::ClientRegistrationState::start("benchmark").unwrap();
    let (_, ke1) = axiam_opaque::ClientLoginState::start("benchmark").unwrap();
    println!("registration_request: {registration_request}");
    println!("ke1: {ke1}");
}
