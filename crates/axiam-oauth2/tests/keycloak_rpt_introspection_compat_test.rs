//! R5.3 (X2 test gap) — RPT introspection shape vs. a recorded Keycloak
//! fixture.
//!
//! # What this test is, and is not
//!
//! `RptPermission`'s doc comment (`axiam_core::models::uma`) claims: "Field
//! names are Keycloak's (`rsid`/`rsname` aliases aside) so that a resource
//! server migrating from Keycloak can read an AXIAM RPT without a translation
//! layer — the compatibility the §X2 introspection test pins." This is that
//! test — and it exists to keep that claim honest, not merely to restate it.
//!
//! **This environment has no network access and no Keycloak instance**
//! (`docker/docker-compose.e2e.yml`'s new `keycloak` service, added in R5.4,
//! is never started here — see that PR/task for the cross-vendor proof that
//! *does* run against a real server). The fixture at
//! `tests/fixtures/keycloak_rpt_introspection.json` is therefore
//! **hand-constructed from Keycloak's published Authorization Services
//! Guide** ("Obtaining Information about an RPT" — RPT introspection via
//! `POST /realms/{realm}/protocol/openid-connect/token/introspect` with
//! `token_type_hint=requesting_party_token`), **not captured traffic from a
//! live server.** The fixture file repeats this in its own `_provenance`
//! field so the claim travels with the data; this module asserts that field
//! is present and says so, precisely to stop a future edit from quietly
//! turning "hand-transcribed" into an unlabelled claim of "real capture".
//!
//! # What "compatible" means here
//!
//! Two things, checked separately:
//!
//! 1. **Envelope compatibility** — a resource server that introspects a
//!    token and looks for `active` and `permissions` at the top level (the
//!    two keys UMA middleware actually branches on) finds them under the
//!    same names in both Keycloak's documented response and AXIAM's
//!    [`IntrospectionResponse`]. This is what "read an AXIAM RPT without a
//!    translation layer" can honestly mean for the *envelope*.
//! 2. **Content compatibility, with a named exception** — Keycloak calls the
//!    resource id `rsid` and the scope list `scopes`; AXIAM calls the same
//!    two things `resource_id` and `resource_scopes` (see
//!    [`axiam_core::models::uma::RptPermission`]). That is a field-*name*
//!    difference, not an information loss: this test builds the explicit
//!    rename Keycloak's own migration docs would need (`rsid ↔ resource_id`,
//!    `scopes ↔ resource_scopes`) and proves it is lossless and round-trips —
//!    which is the actual, checkable content of "aliases aside" rather than
//!    an assertion resting on the doc comment's word alone.

use axiam_core::models::uma::RptPermission;
use axiam_oauth2::token::IntrospectionResponse;
use serde_json::Value;
use uuid::Uuid;

const FIXTURE: &str = include_str!("fixtures/keycloak_rpt_introspection.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture must be valid JSON")
}

/// The fixture must keep disclosing what it is. If this ever fails, either
/// the disclosure was edited away (fix it) or the fixture was replaced by a
/// real capture (update this test's doc comment and this assertion to say
/// so, deliberately, rather than let the claim go stale silently).
#[test]
fn fixture_discloses_it_is_hand_constructed_not_captured() {
    let f = fixture();
    let provenance = f["_provenance"]
        .as_str()
        .expect("fixture must carry a _provenance string");
    assert!(
        provenance.contains("HAND-CONSTRUCTED"),
        "fixture provenance note must say plainly that this is not captured traffic, got: {provenance}"
    );
    assert!(
        provenance.to_ascii_lowercase().contains("not captured"),
        "fixture provenance note must say plainly that this is not captured traffic, got: {provenance}"
    );
}

/// The fixture itself must actually look like what Keycloak's docs describe
/// — a sanity check on the fixture, independent of anything AXIAM does. If
/// this fails, the fixture stopped representing the documented shape and the
/// rest of this file is testing against a fiction.
#[test]
fn fixture_matches_keycloaks_documented_rpt_introspection_shape() {
    let f = fixture();

    assert_eq!(f["active"], Value::Bool(true));
    assert!(
        f["exp"].is_i64(),
        "Keycloak's response carries a top-level exp"
    );
    assert!(
        f["iat"].is_i64(),
        "Keycloak's response carries a top-level iat"
    );

    let perms = f["permissions"]
        .as_array()
        .expect("Keycloak's RPT introspection response carries a permissions array");
    assert!(!perms.is_empty());

    for perm in perms {
        let rsid = perm["rsid"].as_str().expect("each permission has rsid");
        Uuid::parse_str(rsid).expect("rsid is a UUID — AXIAM resource ids are UUIDs too");
        let scopes = perm["scopes"]
            .as_array()
            .expect("each permission has a scopes array");
        assert!(scopes.iter().all(|s| s.is_string()), "scopes are strings");
    }
}

// ---------------------------------------------------------------------------
// Envelope compatibility: same top-level keys, same meaning.
// ---------------------------------------------------------------------------

/// Build an AXIAM RPT introspection response equivalent to the fixture: same
/// resource ids (parsed from the fixture's `rsid`s) and scopes, so the two
/// can be compared permission-by-permission.
fn axiam_response_for_fixture() -> IntrospectionResponse {
    let f = fixture();
    let permissions = f["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|perm| RptPermission {
            resource_id: Uuid::parse_str(perm["rsid"].as_str().unwrap()).unwrap(),
            resource_scopes: perm["scopes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect(),
            exp: f["exp"].as_i64().unwrap(),
        })
        .collect();

    IntrospectionResponse {
        active: true,
        sub: f["sub"].as_str().map(str::to_string),
        exp: f["exp"].as_i64(),
        iat: f["iat"].as_i64(),
        permissions: Some(permissions),
        ..IntrospectionResponse::default()
    }
}

#[test]
fn axiam_introspection_uses_the_same_envelope_keys_as_keycloak() {
    let kc = fixture();
    let axiam = serde_json::to_value(axiam_response_for_fixture()).unwrap();

    // The two keys a UMA-aware resource server actually branches on:
    // "is this token active" and "what permissions does it carry".
    assert_eq!(kc["active"], axiam["active"]);
    assert!(
        axiam.get("permissions").is_some(),
        "AXIAM's introspection response must expose the array under the key \
         `permissions`, same as Keycloak's — that shared key is what lets a \
         resource server find the array at all without a translation layer"
    );
    assert_eq!(
        kc["permissions"].as_array().unwrap().len(),
        axiam["permissions"].as_array().unwrap().len(),
        "same number of permission entries"
    );
}

/// Keycloak omits the UMA `permissions` block entirely for an ordinary
/// (non-RPT) token introspection — it is not present as `null` or `[]`, it is
/// simply absent. `IntrospectionResponse` must match that, not merely leave
/// it empty, or a resource server that checks `"permissions" in response`
/// (rather than truthiness) would misclassify an ordinary access token as an
/// RPT with zero permissions.
#[test]
fn a_non_rpt_introspection_omits_the_permissions_key_entirely_like_keycloak_does() {
    let ordinary = IntrospectionResponse {
        active: true,
        sub: Some("some-user".into()),
        exp: Some(1_700_000_000),
        permissions: None,
        ..IntrospectionResponse::default()
    };
    let v = serde_json::to_value(ordinary).unwrap();
    assert!(
        v.get("permissions").is_none(),
        "an ordinary access-token introspection must not carry a permissions \
         key at all (present-but-null or present-but-empty are both wrong: \
         Keycloak's plain-token introspection response has no such key)"
    );
}

/// Keycloak's documented answer for an inactive/unknown token is the single
/// field `{"active": false}` — everything else omitted (RFC 7662 §2.2
/// explicitly permits this: "other fields... SHOULD be omitted when the
/// token is invalid"). `IntrospectionResponse::default()` with `active:
/// false` must serialize the same way.
#[test]
fn an_inactive_token_introspection_is_minimal_like_keycloaks() {
    let inactive = IntrospectionResponse {
        active: false,
        ..IntrospectionResponse::default()
    };
    let v = serde_json::to_value(inactive).unwrap();
    assert_eq!(
        v.as_object().unwrap().len(),
        1,
        "only `active` should be present: {v}"
    );
    assert_eq!(v["active"], Value::Bool(false));
}

// ---------------------------------------------------------------------------
// Content compatibility: the rsid/resource_id, scopes/resource_scopes
// rename is lossless.
// ---------------------------------------------------------------------------

/// Keycloak's `(rsid, scopes)` shape for one permission, extracted from a
/// fixture entry.
fn keycloak_shape(perm: &Value) -> (Uuid, Vec<String>) {
    let rsid = Uuid::parse_str(perm["rsid"].as_str().unwrap()).unwrap();
    let mut scopes: Vec<String> = perm["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    scopes.sort();
    (rsid, scopes)
}

/// AXIAM's `(resource_id, resource_scopes)` shape for one permission,
/// extracted from a serialized [`IntrospectionResponse`] permission entry —
/// the explicit rename Keycloak's own naming would need, applied to AXIAM's
/// wire shape rather than assumed.
fn axiam_shape_renamed_to_keycloak(perm: &Value) -> (Uuid, Vec<String>) {
    let resource_id = Uuid::parse_str(perm["resource_id"].as_str().unwrap()).unwrap();
    let mut scopes: Vec<String> = perm["resource_scopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    scopes.sort();
    (resource_id, scopes)
}

#[test]
fn every_fixture_permission_round_trips_losslessly_through_axiams_field_names() {
    let kc = fixture();
    let kc_perms = kc["permissions"].as_array().unwrap();

    let axiam = serde_json::to_value(axiam_response_for_fixture()).unwrap();
    let axiam_perms = axiam["permissions"].as_array().unwrap();

    assert_eq!(kc_perms.len(), axiam_perms.len());

    // Order is preserved by construction (`axiam_response_for_fixture` maps
    // the fixture array 1:1), so this is a paired, not a set, comparison —
    // deliberately: an RPT changing the *order* of a resource server's
    // requested permissions would itself be worth noticing.
    for (kc_perm, axiam_perm) in kc_perms.iter().zip(axiam_perms.iter()) {
        let expected = keycloak_shape(kc_perm);
        let actual = axiam_shape_renamed_to_keycloak(axiam_perm);
        assert_eq!(
            expected, actual,
            "renaming AXIAM's resource_id/resource_scopes to rsid/scopes must \
             reproduce Keycloak's (rsid, scopes) content exactly — a resource \
             server applying that one documented rename should see identical \
             information to what Keycloak would have told it"
        );
    }
}

/// `rsname` is the one Keycloak field AXIAM's `RptPermission` has no
/// analogue for at all (AXIAM resources have no separate display name in the
/// RPT — the resource id is the only identifier). Documented here as a test,
/// not just prose: a resource server relying on `rsname` from an RPT
/// (uncommon — `rsid` is the identifier that matters for an authorization
/// decision) is the one part of "read it without a translation layer" that
/// does not hold, and this asserts that gap stays exactly that size and does
/// not silently grow to cover `rsid`/`scopes` too.
#[test]
fn rsname_is_the_one_documented_gap_not_covered_by_the_rename() {
    let kc = fixture();
    for perm in kc["permissions"].as_array().unwrap() {
        assert!(
            perm.get("rsname").is_some(),
            "fixture sanity: Keycloak's documented shape includes rsname"
        );
    }

    // AXIAM's wire shape has no `rsname`-equivalent key at all — constructed
    // directly here (not via `axiam_response_for_fixture`, which only ever
    // sets fields `RptPermission` actually has) so the absence is checked
    // against the real serialized struct, not merely asserted in prose.
    let one = RptPermission {
        resource_id: Uuid::new_v4(),
        resource_scopes: vec!["read".into()],
        exp: 1_700_000_000,
    };
    let v = serde_json::to_value(one).unwrap();
    assert!(
        v.get("rsname").is_none(),
        "RptPermission has no rsname-equivalent field — this is the one part \
         of Keycloak's shape the documented rename does not cover, and a \
         resource server keying off rsname (rather than rsid) would find AXIAM \
         RPTs incompatible on this one field"
    );
}
