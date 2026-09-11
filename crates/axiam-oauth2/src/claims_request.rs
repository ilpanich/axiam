//! OIDC Core §5.5 — the `claims` authorization request parameter.
//!
//! §5.5 lets a client ask for individual claims by name instead of, or as well
//! as, asking for a scope that bundles them:
//!
//! ```json
//! { "userinfo": { "name": { "essential": true } }, "id_token": { "acr": null } }
//! ```
//!
//! This module answers one question: **which UserInfo claims did the client
//! ask for by name, that AXIAM is willing to release on that basis alone?**
//! It is deliberately not a full §5.5 implementation — see [`RELEASABLE`].

use std::collections::BTreeSet;

/// The claims a `claims` parameter can unlock on its own.
///
/// # Why this is a list and not "anything AXIAM holds"
///
/// §5.5 is a *request* mechanism, not an authorization one. It says how a
/// client asks; it does not say the server must comply, and §5.5.1 is explicit
/// that even an `essential` claim is only a request. So the question of which
/// claims a client may obtain without the scope that bundles them stays
/// AXIAM's to answer, and the answer is: the ones whose release is governed by
/// scope alone.
///
/// That excludes `phone_number`, `phone_number_verified` and `address`. Those
/// are GDPR-sensitive and their release runs a consent ceremony (W7 / X7 G8,
/// `crate::sensitive`) — an end user is asked, and a record is kept. A request
/// parameter that skipped it would let any client obtain, by spelling a claim
/// name, exactly what the ceremony exists to stop it obtaining silently.
///
/// `sub` is absent because it is unconditional, and `updated_at` because it
/// travels with the profile claims it describes.
pub const RELEASABLE: &[&str] = &[
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "email",
    "email_verified",
];

/// The UserInfo claims a `claims` parameter asks for, filtered to
/// [`RELEASABLE`] and de-duplicated.
///
/// Returns empty for anything that is not a JSON object with a `userinfo`
/// member — including malformed JSON. A `claims` parameter AXIAM cannot parse
/// is a request it cannot honour, and the specification's own answer to a
/// claim the OP will not assert is to omit it (§5.3.2), not to fail the
/// authorization. Refusing here would break a client whose *other* parameters
/// are perfectly good.
///
/// The `id_token` member is ignored. AXIAM's ID token carries what OIDC Core
/// §5.4 says it should and no more — see the §5.4 work that removed
/// `tenant_id`, `org_id` and `email` from it — and honouring §5.5 there would
/// put claims back that were deliberately taken out.
#[must_use]
pub fn userinfo_claims(raw: &str) -> Vec<String> {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    let Some(members) = parsed.get("userinfo").and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    // `BTreeSet` for de-duplication *and* a stable order: the list is stored on
    // an authorization code and put in an access token, and a set that
    // reordered itself between two equal requests would produce two different
    // tokens for one authorization.
    members
        .keys()
        .filter(|name| RELEASABLE.contains(&name.as_str()))
        .map(|name| name.to_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_userinfo_member_is_read_and_the_id_token_member_is_not() {
        let raw = r#"{"userinfo":{"name":{"essential":true},"nickname":null},
                      "id_token":{"email":{"essential":true}}}"#;
        assert_eq!(userinfo_claims(raw), vec!["name", "nickname"]);
    }

    /// The module this exists for: `oidcc-claims-essential` asks for exactly
    /// this and nothing else, with `scope=openid`.
    #[test]
    fn an_essential_name_is_requested() {
        assert_eq!(
            userinfo_claims(r#"{"userinfo":{"name":{"essential":true}}}"#),
            vec!["name"]
        );
    }

    /// A `claims` parameter cannot reach past the consent ceremony.
    #[test]
    fn the_sensitive_claims_can_never_be_unlocked_by_naming_them() {
        let raw = r#"{"userinfo":{"phone_number":null,"phone_number_verified":null,
                       "address":null,"name":null}}"#;
        assert_eq!(
            userinfo_claims(raw),
            vec!["name"],
            "only the scope-governed claim survives"
        );
        for sensitive in ["phone_number", "phone_number_verified", "address"] {
            assert!(
                !RELEASABLE.contains(&sensitive),
                "{sensitive} is consent-gated and must not be releasable by request"
            );
        }
    }

    #[test]
    fn an_unknown_claim_is_dropped_rather_than_echoed() {
        assert!(userinfo_claims(r#"{"userinfo":{"favourite_colour":null}}"#).is_empty());
    }

    /// Unparseable, wrong shape and absent all mean "asked for nothing" — none
    /// of them may fail the authorization.
    #[test]
    fn anything_unusable_asks_for_nothing_and_does_not_error() {
        for raw in [
            "not json at all",
            "[]",
            "null",
            r#"{"id_token":{"name":null}}"#,
            r#"{"userinfo":"name"}"#,
            "{}",
        ] {
            assert!(userinfo_claims(raw).is_empty(), "{raw}");
        }
    }

    /// Stable and de-duplicated, because the result is put in a token.
    #[test]
    fn the_order_is_stable_regardless_of_how_the_parameter_was_written() {
        let a = userinfo_claims(r#"{"userinfo":{"nickname":null,"name":null,"email":null}}"#);
        let b = userinfo_claims(r#"{"userinfo":{"email":null,"name":null,"nickname":null}}"#);
        assert_eq!(a, b);
        assert_eq!(a, vec!["email", "name", "nickname"]);
    }
}
