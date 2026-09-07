//! Authentication context class references (W4, plan §4.4 — G3/G4).
//!
//! An `acr` claim is a statement about **how** the end user authenticated. A
//! relying party that requires a second factor reads it and decides whether to
//! release money, or medical records, or the ability to change a password. It
//! is therefore one of the few claims whose falsehood is directly exploitable,
//! and it has one famous way of becoming false.
//!
//! # The echo bug, and why it cannot be written here
//!
//! The classic implementation of `acr` is: read `acr_values` from the
//! authorization request, copy the first entry into the ID token, ship it.
//! Every conformance suite passes, every relying party is satisfied, and the
//! claim means nothing at all — the RP asked for MFA and was told "MFA"
//! because it asked, not because anything happened.
//!
//! [`acr_for`] is the whole defence, and it is a defence of shape rather than
//! of discipline: **it takes the session's evidence and nothing else.** There
//! is no parameter it could be handed the request through, so there is no
//! review that has to notice the request being handed to it. A future edit
//! that reintroduced the bug would have to widen the signature first, which is
//! a change a reader can see without knowing this story.
//!
//! The request is not ignored — it decides two things — but neither of them is
//! what the claim *says*:
//!
//! | The request's `acr_values` decide | The session's `amr` decides |
//! |---|---|
//! | whether a step-up is offered ([`Acr::satisfies`]) | which class was achieved ([`acr_for`]) |
//! | which *satisfied* value is reported ([`report_acr`]) | which values are satisfiable at all |
//!
//! [`report_acr`] is the second half of the same argument. It can only return
//! a requested value that the achieved class already satisfies; anything else
//! falls back to the achieved class itself. So the strongest thing an RP can
//! do by asking is change *which true statement* it is told.
//!
//! # The vocabulary is closed (plan §11, D6)
//!
//! Two values, defined by AXIAM, published in `acr_values_supported`
//! ([`crate::oidc::ACR_SINGLE_FACTOR`], [`crate::oidc::ACR_MULTI_FACTOR`]).
//! Not operator-configurable strings: an operator who can configure the string
//! can configure it to say `mfa` for a password login, which is the echo bug
//! arriving through the configuration file instead of through the code.
//!
//! # Federated sessions
//!
//! A federated login records `amr = ["fed"]` and nothing else
//! (`handlers/federation.rs`), because what the upstream provider did to
//! produce its assertion is the provider's claim and not AXIAM's evidence.
//! `fed` alone maps to [`Acr::SingleFactor`] here — the plan's "unmapped
//! upstream evidence yields `1fa`, strict by default". Mapping an upstream
//! `acr`/`amr` into the local vocabulary would need an operator-configured
//! attribute mapping, which does not exist (`federation_claims.rs` has no such
//! field) and which W4 deliberately does not add: it is exactly the
//! configuration surface D6 refuses.

use axiam_core::models::session::Amr;

use crate::oidc::{ACR_MULTI_FACTOR, ACR_SINGLE_FACTOR};

/// An authentication context class AXIAM can assert.
///
/// Ordered so that a stronger class compares greater than a weaker one, which
/// is what makes [`Acr::satisfies`] one comparison rather than a table that
/// could disagree with itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Acr {
    /// [`ACR_SINGLE_FACTOR`] — the floor. Any authentication AXIAM performed
    /// satisfies it, including one whose evidence a newer binary recorded and
    /// this one cannot read.
    SingleFactor,
    /// [`ACR_MULTI_FACTOR`] — two distinct factors, or one factor that is
    /// itself a possession proof with user verification.
    MultiFactor,
}

impl Acr {
    /// The published URN.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleFactor => ACR_SINGLE_FACTOR,
            Self::MultiFactor => ACR_MULTI_FACTOR,
        }
    }

    /// Parse a requested value. `None` for anything outside the vocabulary.
    ///
    /// An unrecognised `acr_values` entry is **not** an error: OIDC Core
    /// §3.1.2.1 makes `acr_values` a voluntary preference, and a relying party
    /// that lists three registries' worth of URNs is asking AXIAM to pick the
    /// one it knows. What an unknown value can never do is be *satisfied* —
    /// [`report_acr`] can only return what parses here — so a client that asks
    /// exclusively for values AXIAM does not implement is answered with the
    /// class its session actually achieved, never with its own string.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim() {
            ACR_SINGLE_FACTOR => Some(Self::SingleFactor),
            ACR_MULTI_FACTOR => Some(Self::MultiFactor),
            _ => None,
        }
    }

    /// Does an authentication of *this* class satisfy a request for `required`?
    ///
    /// Monotone: a session that completed MFA satisfies a request for the
    /// single-factor class too. OIDC Core §3.1.2.1 is explicit that what an ID
    /// token reports is the class the authentication *satisfied*, and refusing
    /// to let a stronger authentication satisfy a weaker request would force
    /// relying parties to enumerate every class they would accept.
    pub const fn satisfies(self, required: Self) -> bool {
        (self as u8) >= (required as u8)
    }
}

/// The class an authentication achieved, from its evidence and nothing else.
///
/// **This function must never be able to see the authorization request.** See
/// the module docs for why that is a property of the signature rather than of
/// a comment. If a future change needs the request here, the change that is
/// actually wanted is somewhere else.
///
/// [`Acr::MultiFactor`] is answered for evidence that proves two distinct
/// factors, or one possession factor the authenticator itself verified a human
/// for:
///
/// | Evidence | Why it is multi-factor |
/// |---|---|
/// | `mfa` | RFC 8176 §2's own marker, recorded by AXIAM's TOTP and MFA paths |
/// | `hwk` + `user` | a hardware authenticator that performed user verification — possession *and* a PIN or biometric |
/// | `swk` + `user` | the same for a platform (software-secured) passkey |
/// | `x509` | a client certificate: possession of a key the user cannot type, bound to a certificate AXIAM issued |
///
/// Everything else — a password, an unverified presence-only passkey, a
/// federated assertion, no evidence at all — is [`Acr::SingleFactor`]. That
/// includes the empty list a pre-v55 session row decodes to, and it includes a
/// value written by a newer binary that [`Amr::from_wire`] dropped: less
/// evidence lowers assurance, which is the only direction an unreadable row
/// may move the answer.
pub fn acr_for(amr: &[Amr]) -> Acr {
    let has = |needle: Amr| amr.contains(&needle);
    let verified_key = (has(Amr::Hwk) || has(Amr::Swk)) && has(Amr::User);
    if has(Amr::Mfa) || verified_key || has(Amr::X509) {
        Acr::MultiFactor
    } else {
        Acr::SingleFactor
    }
}

/// Which value to put in the `acr` claim, given what was achieved and what the
/// relying party asked for.
///
/// The rule is **most-preferred satisfied, in the relying party's order**, and
/// it is deliberately not "the highest class achieved": OIDC Core §3.1.2.1
/// says an ID token reports the class the authentication satisfied, and when
/// an RP lists `[1fa, mfa]` it has said which satisfied class it would rather
/// hear about. An RP that only wants the strongest lists only the strongest.
///
/// `requested` may contain anything, including values from other registries
/// and outright nonsense. Nothing that fails [`Acr::from_wire`] can be
/// returned, and nothing `achieved` does not [`satisfy`](Acr::satisfies) can
/// be returned — so the worst an RP achieves by asking is to select among true
/// statements. When nothing it asked for is satisfied (or it asked for
/// nothing), the achieved class is reported: truthfully, and knowing it will
/// disappoint.
pub fn report_acr(achieved: Acr, requested: &[String]) -> &'static str {
    requested
        .iter()
        .filter_map(|value| Acr::from_wire(value))
        .find(|wanted| achieved.satisfies(*wanted))
        .unwrap_or(achieved)
        .as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **T3.1, the type-level half.** `acr_for` is called with evidence and
    /// nothing else, and the strongest request in the vocabulary does not move
    /// the answer — because there is no parameter to move it with.
    #[test]
    fn the_claim_is_derived_from_evidence_the_request_cannot_reach() {
        // A password-only session. The RP may ask for whatever it likes; this
        // call site is the only producer of the claim, and it has nowhere to
        // put the request.
        assert_eq!(acr_for(&[Amr::Pwd]), Acr::SingleFactor);
        assert_eq!(
            report_acr(acr_for(&[Amr::Pwd]), &[ACR_MULTI_FACTOR.to_owned()]),
            ACR_SINGLE_FACTOR,
            "asking for mfa over a password session must be answered 1fa"
        );
    }

    #[test]
    fn multi_factor_is_answered_only_for_evidence_that_proves_two_factors() {
        for evidence in [
            vec![Amr::Pwd, Amr::Otp, Amr::Mfa],
            vec![Amr::Mfa],
            vec![Amr::Hwk, Amr::User],
            vec![Amr::Swk, Amr::User],
            vec![Amr::X509],
            vec![Amr::Pwd, Amr::Hwk, Amr::User],
        ] {
            assert_eq!(
                acr_for(&evidence),
                Acr::MultiFactor,
                "{evidence:?} proves two factors"
            );
        }
    }

    #[test]
    fn single_factor_is_the_answer_for_everything_else() {
        for evidence in [
            vec![],
            vec![Amr::Pwd],
            vec![Amr::Otp],
            // Presence without verification: the authenticator proved
            // possession and did not prove a human was asked for anything.
            vec![Amr::Hwk],
            vec![Amr::Swk],
            // A bare `user` with no key is not a factor AXIAM can name.
            vec![Amr::User],
            // The federated floor: `fed` alone is one upstream assertion.
            vec![Amr::Fed],
        ] {
            assert_eq!(
                acr_for(&evidence),
                Acr::SingleFactor,
                "{evidence:?} does not prove two factors"
            );
        }
    }

    /// The empty list a pre-v55 session row decodes to satisfies the floor and
    /// nothing above it — the strict direction, and no backfill.
    #[test]
    fn a_session_with_no_recorded_evidence_satisfies_only_the_floor() {
        let achieved = acr_for(&[]);
        assert!(achieved.satisfies(Acr::SingleFactor));
        assert!(!achieved.satisfies(Acr::MultiFactor));
    }

    #[test]
    fn a_stronger_authentication_satisfies_a_weaker_request() {
        assert!(Acr::MultiFactor.satisfies(Acr::SingleFactor));
        assert!(Acr::MultiFactor.satisfies(Acr::MultiFactor));
        assert!(Acr::SingleFactor.satisfies(Acr::SingleFactor));
        assert!(!Acr::SingleFactor.satisfies(Acr::MultiFactor));
    }

    /// **T3.4.** Most-preferred *satisfied* in the RP's order, not highest
    /// achieved. Pinned so the rule stays explicit rather than incidental.
    #[test]
    fn the_reported_value_is_the_most_preferred_one_the_session_satisfies() {
        let mfa_session = acr_for(&[Amr::Pwd, Amr::Otp, Amr::Mfa]);
        assert_eq!(
            report_acr(
                mfa_session,
                &[ACR_SINGLE_FACTOR.to_owned(), ACR_MULTI_FACTOR.to_owned()]
            ),
            ACR_SINGLE_FACTOR,
            "the RP put 1fa first and the session satisfies it"
        );
        assert_eq!(
            report_acr(
                mfa_session,
                &[ACR_MULTI_FACTOR.to_owned(), ACR_SINGLE_FACTOR.to_owned()]
            ),
            ACR_MULTI_FACTOR,
            "…and the other order selects the other satisfied value"
        );
    }

    #[test]
    fn nothing_requested_reports_what_was_achieved() {
        assert_eq!(report_acr(Acr::SingleFactor, &[]), ACR_SINGLE_FACTOR);
        assert_eq!(report_acr(Acr::MultiFactor, &[]), ACR_MULTI_FACTOR);
    }

    /// A value outside the vocabulary can never be returned — not even one an
    /// RP invented that looks like AXIAM's own.
    #[test]
    fn an_unknown_requested_value_is_never_echoed() {
        for invented in [
            "urn:axiam:acr:god-mode",
            "urn:axiam:acr:MFA",
            " urn:axiam:acr:mfa ",
            "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
            "1",
            "",
        ] {
            let reported = report_acr(Acr::MultiFactor, &[invented.to_owned()]);
            assert!(
                reported == ACR_SINGLE_FACTOR || reported == ACR_MULTI_FACTOR,
                "{invented:?} was echoed as {reported:?}"
            );
            assert_ne!(reported, invented, "{invented:?} was echoed verbatim");
        }
    }

    /// Whitespace is not trimmed by the parser used for *reporting*, but is by
    /// [`Acr::from_wire`] — the two must not disagree about what a value is.
    #[test]
    fn from_wire_trims_and_is_exact_otherwise() {
        assert_eq!(
            Acr::from_wire("  urn:axiam:acr:mfa "),
            Some(Acr::MultiFactor)
        );
        assert_eq!(Acr::from_wire("urn:axiam:acr:1fa"), Some(Acr::SingleFactor));
        assert_eq!(Acr::from_wire("urn:axiam:acr:1FA"), None);
    }

    /// The published vocabulary and the type must be the same two values: a
    /// class the discovery document does not advertise is one no RP can ask
    /// for, and a value it advertises that nothing satisfies is a lie.
    #[test]
    fn the_type_and_the_discovery_vocabulary_agree() {
        for value in [ACR_SINGLE_FACTOR, ACR_MULTI_FACTOR] {
            let parsed = Acr::from_wire(value).expect("advertised values must parse");
            assert_eq!(parsed.as_str(), value);
        }
    }
}
