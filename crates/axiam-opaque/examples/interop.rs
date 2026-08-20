//! Server half of the cross-implementation interoperability harness.
//!
//! # Why this exists
//!
//! `sdks/CONTRACT.md` §23.1 forbids an SDK from implementing OPAQUE, with
//! exactly one exception: the Go SDK uses `github.com/bytemare/opaque`, because
//! a vetted RFC 9807 implementation exists for Go and binding this crate's C
//! ABI would force cgo on every consumer, breaking `CGO_ENABLED=0` builds.
//!
//! That exception is only safe if the two implementations actually agree, and
//! "both say RFC 9807" is not evidence — they must agree on the OPRF, the key
//! schedule, the envelope construction, the AKE transcript *and* the KSF
//! parameters, of which only the first four are in the RFC. This harness is how
//! that claim is checked rather than assumed.
//!
//! # Running it
//!
//! ```bash
//! cargo build -p axiam-opaque --example interop
//! # then, from a checkout of the Go SDK:
//! go test -tags interop ./...
//! ```
//!
//! The Go side drives the client half and shells out to this binary for the
//! server half. A failure means one of the two moved; the right response is to
//! find out which, not to loosen the test.
//!
//! # What it is not
//!
//! Not the AXIAM server. It has no key material at rest, no sealed sessions, no
//! credential identifiers and no decoy path — see `axiam-auth`'s `opaque`
//! module for those. It is the bare protocol, which is all an interoperability
//! check needs.

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let usage = "usage: interop reg-start <registration_request_hex>\n       \
                 interop login-start <setup_hex> <record_hex> <ke1_hex>";

    match args.get(1).map(String::as_str) {
        // Prints `<setup_hex> <registration_response_hex>`.
        Some("reg-start") => {
            let request = args.get(2).expect(usage);
            let (setup, response) = axiam_opaque::testing::server_registration_start(request);
            println!("{setup} {response}");
        }
        // Prints `<ke2_hex>`.
        Some("login-start") => {
            let (setup, record, ke1) = (
                args.get(2).expect(usage),
                args.get(3).expect(usage),
                args.get(4).expect(usage),
            );
            println!(
                "{}",
                axiam_opaque::testing::server_login_start(setup, record, ke1)
            );
        }
        _ => panic!("{usage}"),
    }
}
