//! QR2-4 (#889): `axiam_audit::middleware::BEARER_ROUTE_PATTERNS` is the list
//! the audit action and the tracing span redact from. It is not derived from
//! the router, so a route added later with a bearer path parameter would leak
//! on a `//` or trailing-slash spelling unless someone also listed it.
//!
//! This test ties the two. It walks the paths of `sdks/openapi.json` rather
//! than the actix router: the spec is generated from the very route
//! registrations by utoipa, CI's OpenAPI drift check keeps the committed file
//! equal to them, and walking the router would need the whole application
//! (database, state) built just to enumerate patterns. A path parameter is a
//! bearer value when its name says so (`token`, `handle`, `secret`, `ticket`).

use axiam_audit::middleware::BEARER_ROUTE_PATTERNS;

const BEARER_WORDS: &[&str] = &["token", "handle", "secret", "ticket"];

fn placeholders(path: &str) -> Vec<&str> {
    path.split('/')
        .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
        .collect()
}

#[test]
fn every_bearer_path_parameter_in_the_api_is_listed_for_redaction() {
    let spec = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sdks/openapi.json"
    ))
    .expect("sdks/openapi.json");
    let spec: serde_json::Value = serde_json::from_str(&spec).expect("valid OpenAPI JSON");
    let paths = spec["paths"].as_object().expect("paths object");

    let mut bearer_paths = 0;
    for path in paths.keys() {
        let bearer = placeholders(path).into_iter().any(|name| {
            BEARER_WORDS
                .iter()
                .any(|w| name.to_ascii_lowercase().contains(w))
        });
        if !bearer {
            continue;
        }
        bearer_paths += 1;
        // The list holds patterns relative to the API scope (`/api/v1`).
        let relative = path.strip_prefix("/api/v1").unwrap_or(path);
        assert!(
            BEARER_ROUTE_PATTERNS.contains(&relative),
            "{path} carries a bearer path parameter but is not in \
             axiam_audit::middleware::BEARER_ROUTE_PATTERNS; its token would be \
             written to the audit action on an unmatched spelling"
        );
    }
    assert!(bearer_paths > 0, "the walk found no bearer path at all");

    // And the list names no route that does not exist.
    for pattern in BEARER_ROUTE_PATTERNS {
        let full = format!("/api/v1{pattern}");
        assert!(
            paths.contains_key(&full),
            "{full} is not in the OpenAPI spec"
        );
    }
}
