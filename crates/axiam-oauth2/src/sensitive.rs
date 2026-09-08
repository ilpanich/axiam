//! X7 G8 — the GDPR-sensitive OIDC scopes `address` and `phone` (plan §4.8).
//!
//! # Four gates, and none of them is enough on its own
//!
//! A postal address or a telephone number reaches a relying party only when
//! **all four** of these hold, and each is closed by a different party:
//!
//! 1. The **organization** turned `sensitive_scopes_enabled` on
//!    (`axiam_core::models::settings::OidcPolicy`). Off by default; a tenant
//!    may turn it off again but never on.
//! 2. The **operator** registered the scope on the client. Nothing could
//!    register it before this wave, so no client that exists today has it, and
//!    `crate::authorize`'s step 5 refuses an unregistered scope as it always
//!    has (invariant I1).
//! 3. The **end user** consented, per client and per scope set, and the record
//!    is still there. Withdrawal takes effect on the next UserInfo call — not
//!    on the next token.
//! 4. The client is **not** on the `fapi2` profile, checked at registration
//!    (`crate::fapi::validate_registration`), again at the authorization
//!    endpoint (`crate::fapi::enforce_authorization_request`), and a third
//!    time at UserInfo, where no authorization request is in hand.
//!
//! # What this module is
//!
//! The pure half: which scopes are sensitive, what a consent record for them is
//! called, and what an authorization request has earned given the answers the
//! caller resolved. Every database read lives in the caller — the REST handler
//! owns the settings and consent repositories — for the same reason
//! `crate::authorize` takes `session_evidence` rather than a session
//! repository: this crate decides, it does not fetch.

use axiam_core::repository::OIDC_SCOPE_RELEASE_CONSENT_PREFIX;

pub use crate::fapi::SENSITIVE_SCOPES;

/// The sensitive scopes present in a requested set, in the canonical order
/// [`SENSITIVE_SCOPES`] declares.
///
/// Canonical rather than request order because the result names a consent
/// record, and `address phone` and `phone address` are the same consent. A
/// relying party that reorders its `scope` parameter between two requests must
/// not be asked to collect consent twice.
///
/// Duplicates in the request collapse: `scope=openid phone phone` asks for one
/// telephone number.
pub fn requested(scopes: &[String]) -> Vec<&'static str> {
    SENSITIVE_SCOPES
        .into_iter()
        .filter(|sensitive| scopes.iter().any(|s| s == sensitive))
        .collect()
}

/// The `consent_type` of the record covering releases to one relying party.
///
/// Per client, because consenting to give a postal address to one relying
/// party says nothing about any other — that is the whole content of "informed"
/// in Art. 4(11). The `client_id` is used verbatim: it is a registered
/// identifier this deployment issued, not request input.
pub fn consent_type(client_id: &str) -> String {
    format!("{OIDC_SCOPE_RELEASE_CONSENT_PREFIX}{client_id}")
}

/// The `version` of that record: the consented scopes, canonically ordered and
/// space-joined.
///
/// Putting the scope set in the version is what makes a client that later adds
/// a scope re-prompt rather than inherit. `phone` consented to yesterday does
/// not answer for `address phone` today, and the comparison that decides is
/// string equality on a canonical form rather than a subset test somebody
/// could get backwards.
pub fn consent_version(scopes: &[&str]) -> String {
    let mut canonical: Vec<&str> = SENSITIVE_SCOPES
        .into_iter()
        .filter(|s| scopes.contains(s))
        .collect();
    canonical.dedup();
    canonical.join(" ")
}

/// What the caller resolved about this request's sensitive scopes.
///
/// Resolved by the REST handler, which owns the settings and consent
/// repositories, and consumed by [`decide`]. The default is the state of every
/// authorization request in every deployment today.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Requested {
    /// No sensitive scope was asked for. Nothing in this module applies.
    #[default]
    None,
    /// Asked for, and the tenant's effective settings say the scopes are off.
    Disabled,
    /// Asked for, allowed, and a consent record covers exactly this set.
    Consented,
    /// Asked for, allowed, and no consent record covers this set.
    ConsentMissing,
}

/// What an authorization request carrying sensitive scopes has earned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Carry on. Either nothing sensitive was asked for, or it was consented.
    Proceed,
    /// Send the end user to the consent screen.
    AskForConsent,
    /// Answer the relying party with a terminal error.
    Refuse(Refusal),
}

/// Why a request carrying sensitive scopes was refused.
///
/// A typed reason rather than a built `OAuth2Error` so that this module stays
/// free of the error type's redirect semantics, and so a test can assert
/// *which* refusal happened rather than matching prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The tenant's effective settings have the scopes off. Answered
    /// `invalid_scope`, which is what an unregistrable scope has always
    /// earned — the switch being off and the scope never having been
    /// registrable are the same fact from the relying party's side.
    Disabled,
    /// `prompt=none` forbade the interaction that consent needs
    /// (OIDC Core §3.1.2.6).
    ConsentRequired,
    /// The end user has already been through the consent screen for this
    /// request and consent still is not recorded, so they declined.
    Declined,
}

/// Decide what a request carrying sensitive scopes earns.
///
/// The three inputs beyond the resolved state are all facts about *this*
/// request, and the order they are consulted in is the argument:
///
/// * `switch_is_off` is answered first because it is the operator's decision
///   and it outranks anything the end user or the relying party wants.
/// * `return_leg` — the request has already been through the consent screen
///   once — is answered before `prompt_none` because it is the stronger
///   statement: the user was asked, in person, and did not grant. Redirecting
///   again is the non-terminating case, so the chain is bounded at one hop
///   exactly as `crate::honour`'s is.
/// * `prompt_none` last, because it only applies to a first attempt.
///
/// `prompt_none` must be passed as `true` **only** when the relying party sent
/// it *and* the client is on the honour lane. A client registered `ignore` has
/// its `prompt` dropped everywhere else, and this is not the place to start
/// reading it — that would be invariant 4 broken by a wave that promised not
/// to.
pub fn decide(
    requested: Requested,
    switch_is_off: bool,
    return_leg: bool,
    prompt_none: bool,
) -> Decision {
    match requested {
        Requested::None => Decision::Proceed,
        Requested::Disabled => Decision::Refuse(Refusal::Disabled),
        Requested::Consented => {
            // A resolved `Consented` cannot coexist with the switch being off:
            // the caller only looks for a consent record once the switch has
            // said yes. Asserted rather than assumed, because the two facts
            // arrive from two different reads and a caller that transposed
            // them would otherwise release data on a tenant that forbade it.
            if switch_is_off {
                Decision::Refuse(Refusal::Disabled)
            } else {
                Decision::Proceed
            }
        }
        Requested::ConsentMissing => {
            if switch_is_off {
                Decision::Refuse(Refusal::Disabled)
            } else if return_leg {
                Decision::Refuse(Refusal::Declined)
            } else if prompt_none {
                Decision::Refuse(Refusal::ConsentRequired)
            } else {
                Decision::AskForConsent
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn only_the_two_scopes_are_sensitive() {
        assert_eq!(SENSITIVE_SCOPES, ["address", "phone"]);
        assert!(requested(&scopes(&["openid", "profile", "email"])).is_empty());
    }

    /// The result is in the canonical order, whatever order the relying party
    /// sent — otherwise the same consent would have two names.
    #[test]
    fn the_requested_set_is_canonically_ordered() {
        assert_eq!(
            requested(&scopes(&["phone", "openid", "address"])),
            vec!["address", "phone"]
        );
        assert_eq!(
            consent_version(&requested(&scopes(&["phone", "address"]))),
            consent_version(&requested(&scopes(&["address", "phone"]))),
        );
    }

    /// A repeated scope is one scope. A relying party sending `phone phone`
    /// must not be asked to consent to something with a different name.
    #[test]
    fn duplicates_collapse() {
        assert_eq!(requested(&scopes(&["phone", "phone"])), vec!["phone"]);
        assert_eq!(consent_version(&["phone", "phone"]), "phone");
    }

    /// Adding a scope changes the version, which is what makes a client that
    /// widens its request re-prompt instead of inheriting.
    #[test]
    fn widening_the_scope_set_changes_the_consent_version() {
        assert_ne!(
            consent_version(&["phone"]),
            consent_version(&["address", "phone"])
        );
        assert_eq!(consent_version(&["address", "phone"]), "address phone");
    }

    /// Consent is per relying party.
    #[test]
    fn the_consent_type_names_the_client() {
        assert_eq!(consent_type("shop"), "oidc_scope_release:shop");
        assert_ne!(consent_type("shop"), consent_type("shop2"));
    }

    /// The ordinary request — every request in every deployment today.
    #[test]
    fn a_request_asking_for_nothing_sensitive_proceeds() {
        assert_eq!(
            decide(Requested::None, false, false, false),
            Decision::Proceed
        );
        // Including under `prompt=none`, and on a return leg: neither means
        // anything when nothing sensitive was asked for.
        assert_eq!(decide(Requested::None, true, true, true), Decision::Proceed);
    }

    /// T8.1 — the switch outranks everything, consent included.
    #[test]
    fn the_switch_outranks_a_recorded_consent() {
        assert_eq!(
            decide(Requested::Disabled, true, false, false),
            Decision::Refuse(Refusal::Disabled)
        );
        assert_eq!(
            decide(Requested::Consented, true, false, false),
            Decision::Refuse(Refusal::Disabled),
            "a consent record must not survive the operator turning the capability off"
        );
    }

    /// T8.2 — a first authorization asks; `prompt=none` cannot.
    #[test]
    fn a_first_authorization_asks_and_prompt_none_is_refused() {
        assert_eq!(
            decide(Requested::ConsentMissing, false, false, false),
            Decision::AskForConsent
        );
        assert_eq!(
            decide(Requested::ConsentMissing, false, false, true),
            Decision::Refuse(Refusal::ConsentRequired)
        );
    }

    /// The chain is bounded at one hop: a request that has already been to the
    /// consent screen and come back without consent is answered, not sent
    /// again.
    #[test]
    fn a_return_leg_without_consent_is_a_decline_not_a_second_redirect() {
        assert_eq!(
            decide(Requested::ConsentMissing, false, true, false),
            Decision::Refuse(Refusal::Declined)
        );
        // And the decline outranks `prompt=none`: the stronger statement is
        // that the user was asked and said no.
        assert_eq!(
            decide(Requested::ConsentMissing, false, true, true),
            Decision::Refuse(Refusal::Declined)
        );
    }

    /// Consent recorded, switch on: the request proceeds and nothing has been
    /// released yet — release is UserInfo's decision, taken again there.
    #[test]
    fn a_consented_request_proceeds() {
        assert_eq!(
            decide(Requested::Consented, false, false, false),
            Decision::Proceed
        );
    }
}
