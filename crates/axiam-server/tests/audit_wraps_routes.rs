//! The audit middleware must wrap the `App` outside the routes (#674 (e)).
//!
//! The five authenticated federation routes key their rate-limit bucket on the
//! principal the audit middleware verified. Actix runs the *last* `.wrap` first,
//! so the middleware sees a request before the routes' limiters only when its
//! `.wrap(...)` is written before `.configure(... register_api_v1_routes_with ...)`.
//! Moving it inside would silently revert those routes to address keying while
//! every behavioural test passes; this scan fails instead.

use std::fs;
use std::path::Path;

fn boot_source() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/boot.rs");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn the_audit_middleware_wraps_the_app_outside_the_routes() {
    let src = boot_source();
    let wrap = src
        .find(".wrap(audit_middleware")
        .expect("boot.rs no longer wraps the App in `.wrap(audit_middleware…)`");
    let routes = src.find("register_api_v1_routes_with::<C>(cfg").expect(
        "boot.rs no longer registers the routes with `register_api_v1_routes_with::<C>(cfg…)`",
    );
    assert!(
        wrap < routes,
        "the audit middleware's `.wrap(` must precede the route registration in boot.rs: \
         inside the routes it never verifies the principal before the limiters, and the five \
         federation routes fall back to address keying (R110W2-06 (e))"
    );
}
