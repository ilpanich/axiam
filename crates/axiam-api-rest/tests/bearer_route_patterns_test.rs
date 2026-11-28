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
//! bearer value when one of its `_`-separated words says so (see
//! [`BEARER_WORDS`]); matching is on whole words, so `client_id` does not trip
//! `key` and `stream_id` does not trip `state`.
//!
//! The committed spec is generated with `--no-default-features`, so
//! feature-gated (SAML) routes are not walked. None of them has a bearer
//! placeholder today (checked 2026-11-27 against the `#[cfg(feature = "saml")]`
//! routes under `/tenants/{tenant_id}/saml/…`: only `tenant_id`, `sp_id` and
//! `credential_id`); one added later must be listed by hand.

use axiam_audit::middleware::BEARER_ROUTE_PATTERNS;

/// Words that make a path parameter a bearer value when they are a whole
/// `_`-separated component of its name.
const BEARER_WORDS: &[&str] = &[
    "token",
    "handle",
    "secret",
    "ticket",
    "code",
    "key",
    "nonce",
    "otp",
    "invite",
    "state",
    "assertion",
];

/// Path parameters that contain a bearer word but are not bearer values. Each
/// entry is a full `path` (as in the spec) plus the parameter name, with the
/// reason. Empty today: every parameter in the committed spec was checked
/// (`ca_id`, `client_id`, `credential_id`, `group_id`, `id`, `method_id`,
/// `org_id`, `permission_id`, `request_id`, `resource_id`, `role_id`, `sa_id`,
/// `scope_id`, `segment_id`, `service_account_id`, `sp_id`, `stream_id`,
/// `tenant_id`, `user_id`, and `token` for the export route); none has a
/// bearer word as a component other than `token`.
const NOT_BEARER: &[(&str, &str)] = &[];

fn is_bearer_parameter(path: &str, name: &str) -> bool {
    !NOT_BEARER.contains(&(path, name))
        && name
            .to_ascii_lowercase()
            .split('_')
            .any(|word| BEARER_WORDS.contains(&word))
}

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
        let bearer = placeholders(path)
            .into_iter()
            .any(|name| is_bearer_parameter(path, name));
        if !bearer {
            continue;
        }
        bearer_paths += 1;
        // The list holds patterns relative to the API scope (`/api/v1`), or
        // the full path for a route outside it (`/oauth2`, `/ssf`).
        let relative = path.strip_prefix("/api/v1").unwrap_or(path);
        assert!(
            BEARER_ROUTE_PATTERNS.contains(&relative)
                || BEARER_ROUTE_PATTERNS.contains(&path.as_str()),
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
            paths.contains_key(&full) || paths.contains_key(*pattern),
            "neither {full} nor {pattern} is in the OpenAPI spec"
        );
    }
}
