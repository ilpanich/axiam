//! D4 — the consent hop a client an administrator did not create must pass
//! (T21.4).
//!
//! # The rule
//!
//! *A client whose `managed_by` is not `admin` gets a consent screen on its
//! first authorization per end user, whatever scopes it asked for.*
//!
//! W7 already forces a consent screen for `address` and `phone`, on the
//! argument that releasing a postal address needs the subject's agreement.
//! This is a different argument for a different gate: the client itself is an
//! unrelated party. Nobody at the deployment decided this application should
//! exist — it registered itself over an open endpoint — so the only person who
//! can decide whether it may act as somebody is that somebody.
//!
//! # Why it reuses W7's consent record rather than inventing one
//!
//! The record lives in the same `oidc_scope_release:<client_id>` namespace, so
//! `DELETE /api/v1/account/consents/oidc-scopes/{client_id}` — which withdraws
//! **every** version recorded for a relying party — revokes it with no new
//! code and no new page. A separate namespace would have meant a second
//! withdrawal control, and an Art. 7(3) control that is as easy to give as to
//! withdraw is not one a subject should have to find twice.
//!
//! What distinguishes the two is the record's `version`:
//!
//! | Gate | `version` | Example |
//! | --- | --- | --- |
//! | W7 sensitive scopes | the sensitive scopes, canonically ordered | `address phone` |
//! | D4 external client | [`VERSION_PREFIX`] + the whole requested scope set | `client:openid profile` |
//!
//! The prefix cannot collide: W7's versions are drawn from a fixed two-element
//! list. Putting the **whole** scope set in the version is what makes a client
//! that later asks for more re-prompt rather than inherit — the same property
//! W7's version buys, for the same reason.
//!
//! # The two never overlap in practice
//!
//! A self-registered client cannot hold `address` or `phone` at all:
//! `axiam_core::models::settings::validate_dcr_policy` refuses those scopes in
//! `dcr_allowed_scopes` (the T21.4 amendment). So a request never needs both
//! records, and an end user never answers two consent screens for one
//! authorization.

use axiam_core::models::oauth2_client::ManagedBy;
use axiam_core::repository::OIDC_SCOPE_RELEASE_CONSENT_PREFIX;

/// What a D4 consent record's `version` starts with.
///
/// `client:` rather than something longer because the string is stored, read
/// back on every authorization, and shown to nobody. It exists to make the two
/// kinds of record in one namespace distinguishable, and W7's versions are
/// drawn from a closed two-element vocabulary that contains no colon.
pub const VERSION_PREFIX: &str = "client:";

/// The `consent_type` covering releases to one relying party.
///
/// Identical to `crate::sensitive::consent_type`, and deliberately a
/// re-export-by-delegation rather than a second `format!`: the two gates must
/// name the same record, or withdrawal would clear one and leave the other.
pub fn consent_type(client_id: &str) -> String {
    format!("{OIDC_SCOPE_RELEASE_CONSENT_PREFIX}{client_id}")
}

/// The `version` of a D4 record for a given requested scope set.
///
/// Sorted and de-duplicated, so `openid profile` and `profile openid openid`
/// are one consent rather than three. Sorting rather than preserving request
/// order for the reason `sensitive::consent_version` gives: a relying party
/// that reorders its `scope` parameter between two requests must not be asked
/// to collect consent twice.
///
/// An empty scope set yields `"client:"`, which is a perfectly good version —
/// a client that asked for nothing still asked to act as the user, and that is
/// the thing being consented to.
pub fn version(scopes: &[String]) -> String {
    let mut canonical: Vec<&str> = scopes.iter().map(String::as_str).collect();
    canonical.sort_unstable();
    canonical.dedup();
    format!("{VERSION_PREFIX}{}", canonical.join(" "))
}

/// What the caller resolved about this request's D4 consent.
///
/// Resolved by the REST handler, which owns the consent repository, and
/// consumed by [`decide`] — the same division `crate::sensitive` draws, for
/// the same reason: this crate decides, it does not fetch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Requested {
    /// The client is an administrator's, so D4 does not apply. The state of
    /// every authorization request in every deployment today.
    #[default]
    NotApplicable,
    /// External client, and a record covers exactly this scope set.
    Consented,
    /// External client, and no record covers this scope set.
    ConsentMissing,
}

/// What a D4 request has earned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Carry on.
    Proceed,
    /// Send the end user to the consent screen.
    AskForConsent,
    /// Answer the relying party with a terminal error.
    Refuse(Refusal),
}

/// Why a D4 request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `prompt=none` forbade the interaction consent needs
    /// (OIDC Core §3.1.2.6).
    ConsentRequired,
    /// The end user has already been through the consent screen for this
    /// request and consent still is not recorded, so they declined.
    Declined,
}

/// Decide what a request from an externally registered client earns.
///
/// The argument order mirrors `crate::sensitive::decide`, and so does the
/// order the inputs are consulted in: `consent_leg` — the request has already
/// been through the consent screen once — before `prompt_none`, because it is
/// the stronger statement. The user was asked, in person, and did not grant;
/// redirecting again is the non-terminating case, so the chain is bounded at
/// one consent hop.
///
/// `prompt_none` must be passed as `true` **only** when the relying party sent
/// it *and* the client is on the honour lane, exactly as W7's gate requires. A
/// client registered `ignore` has its `prompt` dropped everywhere else in this
/// server, and a `dcr` client is always `ignore` — the registration endpoint
/// forces it — so in T21.4 this argument is always `false`. It is a parameter
/// rather than a constant because T5's CIMD clients will reach the same gate
/// and the decision must not have to be rewritten then.
pub const fn decide(requested: Requested, consent_leg: bool, prompt_none: bool) -> Decision {
    match requested {
        Requested::NotApplicable | Requested::Consented => Decision::Proceed,
        Requested::ConsentMissing => {
            if consent_leg {
                Decision::Refuse(Refusal::Declined)
            } else if prompt_none {
                Decision::Refuse(Refusal::ConsentRequired)
            } else {
                Decision::AskForConsent
            }
        }
    }
}

/// Whether D4 applies to a client at all.
///
/// One question asked in one place, so the authorization endpoint, the consent
/// recorder and the account page cannot come to disagree about which clients
/// are covered.
pub const fn applies_to(managed_by: ManagedBy) -> bool {
    managed_by.is_external()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The property the whole record rests on: one consent, whatever order the
    /// relying party sends its scopes in, and a **different** consent as soon
    /// as it asks for more.
    #[test]
    fn the_version_is_the_scope_set_and_not_its_spelling() {
        assert_eq!(
            version(&scopes(&["profile", "openid"])),
            version(&scopes(&["openid", "profile", "openid"]))
        );
        assert_ne!(
            version(&scopes(&["openid"])),
            version(&scopes(&["openid", "profile"])),
            "a client that later asks for more must re-prompt rather than inherit"
        );
        assert_eq!(version(&scopes(&["openid"])), "client:openid");
        assert_eq!(version(&[]), "client:");
    }

    /// The two gates share a namespace and must stay distinguishable inside
    /// it. W7's versions are drawn from a closed vocabulary, so this is a
    /// property rather than a sample.
    #[test]
    fn a_d4_version_can_never_be_mistaken_for_a_w7_one() {
        for a in [None, Some("address")] {
            for b in [None, Some("phone")] {
                let set: Vec<&str> = [a, b].into_iter().flatten().collect();
                let w7 = crate::sensitive::consent_version(&set);
                assert!(
                    !w7.starts_with(VERSION_PREFIX),
                    "W7 version {w7:?} must not look like a D4 one"
                );
            }
        }
    }

    /// Both gates must name the same record, or withdrawing one would leave
    /// the other standing.
    #[test]
    fn both_gates_name_the_same_consent_record() {
        assert_eq!(
            consent_type("client-abc"),
            crate::sensitive::consent_type("client-abc")
        );
    }

    /// I1 — an administrator's client reaches none of this.
    #[test]
    fn an_administrators_client_is_never_asked() {
        assert!(!applies_to(ManagedBy::Admin));
        assert!(applies_to(ManagedBy::Dcr));
        assert!(applies_to(ManagedBy::Cimd));
        assert_eq!(
            decide(Requested::NotApplicable, false, false),
            Decision::Proceed
        );
        // Even on a consent return leg with prompt=none, which is the shape
        // that refuses for every other input.
        assert_eq!(
            decide(Requested::NotApplicable, true, true),
            Decision::Proceed
        );
    }

    #[test]
    fn a_missing_consent_asks_once_and_then_refuses() {
        assert_eq!(
            decide(Requested::ConsentMissing, false, false),
            Decision::AskForConsent
        );
        // Back from the screen without a record: the user declined.
        assert_eq!(
            decide(Requested::ConsentMissing, true, false),
            Decision::Refuse(Refusal::Declined)
        );
        // `prompt=none` forbids the question, and the answer names that
        // rather than pretending the user declined.
        assert_eq!(
            decide(Requested::ConsentMissing, false, true),
            Decision::Refuse(Refusal::ConsentRequired)
        );
        // The consent leg outranks `prompt=none`: the user *was* asked.
        assert_eq!(
            decide(Requested::ConsentMissing, true, true),
            Decision::Refuse(Refusal::Declined)
        );
    }

    #[test]
    fn a_recorded_consent_proceeds() {
        assert_eq!(
            decide(Requested::Consented, false, false),
            Decision::Proceed
        );
        assert_eq!(decide(Requested::Consented, true, true), Decision::Proceed);
    }
}
