//! The honour lane: what a security-bearing authentication-request parameter
//! actually does (W4, plan §4.2/§4.3/§4.4).
//!
//! W1 parsed `prompt`, `max_age`, `acr_values`, `claims.id_token.acr` and
//! `id_token_hint` and honoured none of them. W2 recorded, on every session,
//! the evidence that would be needed to answer them. W3 built the browser
//! login hop, so that "the answer is: authenticate the user again" became a
//! thing the authorization endpoint could actually *do*. This module is where
//! those three become one decision, **for a client registered
//! `authn_request_params = honour` and for nobody else**.
//!
//! It is a pure function over four things — what was asked, what the session
//! proves, who the request is acting for, and whether this request has already
//! been through the login hop once — so that every hard case in the plan is a
//! unit test rather than an HTTP round trip.
//!
//! # The shape of the answer
//!
//! [`evaluate`] returns one of three things, and the caller cannot confuse
//! them:
//!
//! - [`Outcome::Proceed`] — issue a code, and record this `acr` on it.
//! - [`Outcome::Interact`] — send the browser through the login hop, demanding
//!   at most the one factor named. This is the only arm that produces a login
//!   redirect, and it is unreachable when the request carries `prompt=none`.
//! - [`Outcome::Refuse`] — a terminal OIDC error, redirected to the relying
//!   party's registered `redirect_uri` by the caller.
//!
//! # Why the return leg matters so much
//!
//! `authorize → /login → authorize` terminates because the second leg carries
//! [`crate::login_hop::LOGIN_HOP_MARKER`] and this module never asks for a
//! second interaction when it sees one. That turns every requirement into two
//! questions rather than one: *can this session satisfy it?* and, if not,
//! *have we already tried?* A requirement that survives one interaction is
//! answered — with a token when what was asked was voluntary (an `acr_values`
//! preference, a `prompt=login` whose ceremony has now happened), and with an
//! error when it was not (`max_age`, an essential `acr`, an `id_token_hint`
//! naming somebody else).
//!
//! `prompt=none` reads the marker too, and reads it as a *refusal condition*:
//! a request that has been through the login page has, by definition, had the
//! interaction it asked not to have, so it is answered `login_required` rather
//! than with a code. That is what closes the one gap the carrier split would
//! otherwise leave — a pushed request whose `prompt=none` cannot be read until
//! after the handle is consumed, i.e. after the hop has already happened.
//!
//! The marker travels in a URL and a relying party could send one itself. It
//! never selects a principal and it never adds a claim: the strongest thing a
//! forged marker does is make the server skip an interaction *the forger asked
//! for*, and every claim the resulting token carries — `auth_time`, `acr`,
//! `amr` — still describes the authentication that really happened.
//!
//! # `max_age = 0`
//!
//! `elapsed = floor(now − authenticated_at)`, reauthenticate iff
//! `elapsed >= max_age`, per plan §4.3 — no special case and no leeway in the
//! relying party's disfavour. One consequence is worth stating out loud
//! because the plan's prose does not: **`max_age=0` can never be satisfied by
//! any code.** It always demands a reauthentication, and the reauthentication
//! it produces is itself zero seconds old, so `0 >= 0` holds again on the
//! return leg and the answer is `login_required`. An RP that sends `max_age=0`
//! is asking for an authentication of age zero, which no clock can report; the
//! honest answer is the refusal, not a code minted under a rounder comparison.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use axiam_core::models::session::Amr;

use crate::acr::{Acr, acr_for, report_acr};
use crate::authn_params::{AuthnRequestParams, Prompt};
use crate::error::OAuth2Error;
use crate::logout::IdTokenHint;

/// Everything [`evaluate`] is allowed to see.
///
/// A struct rather than eight positional arguments because two of them are
/// `Option<DateTime>`-shaped and one is a bare `bool`; a call site that
/// transposed them would still compile.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The parsed bundle, from whichever carrier delivered it.
    pub params: &'a AuthnRequestParams,
    /// When the end user authenticated, from the session behind this request.
    /// `None` when no session row could be read at all — which is the strict
    /// state, not an error: nothing can be asserted about an authentication
    /// that cannot be found.
    pub auth_time: Option<DateTime<Utc>>,
    /// What that authentication proved.
    pub amr: &'a [Amr],
    /// The subject this request is acting for.
    pub subject: Uuid,
    /// The client the request is for — the `aud` an `id_token_hint` must name.
    pub client_id: &'a str,
    /// The decoded `id_token_hint`, when there was one and it verified.
    ///
    /// `None` covers both "no hint was sent" and "a hint was sent and did not
    /// verify"; [`AuthnRequestParams::id_token_hint`] distinguishes them, and
    /// a hint that was sent and did not verify is treated as naming somebody
    /// else (OIDC Core §3.1.2.1 asks for an error, preferably `login_required`,
    /// rather than for the hint to be dropped).
    pub id_token_hint: Option<&'a IdTokenHint>,
    /// Whether this request carries [`crate::login_hop::LOGIN_HOP_MARKER`],
    /// i.e. has already been through the login page once.
    pub return_leg: bool,
    /// The clock. A parameter so that freshness is testable without sleeping.
    pub now: DateTime<Utc>,
}

/// Why an interaction is being asked for. Logged, never sent to the RP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// `prompt=login`, `prompt=select_account` or `prompt=consent`.
    PromptAsked,
    /// The session is older than `max_age` — or there is no session.
    MaxAgeExceeded,
    /// `id_token_hint` names a different subject, a different client, or did
    /// not verify.
    HintMismatch,
    /// The requested authentication context class is not satisfied.
    AcrUnsatisfied,
}

/// A login hop this evaluation is asking the caller to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interaction {
    /// The single factor the sign-in page must demand, when the reason for the
    /// hop is an unsatisfied ACR.
    ///
    /// At most one value, and it is a member of the closed vocabulary — the
    /// page never chooses an authentication context class, it only learns
    /// which factor to insist on.
    pub required_acr: Option<Acr>,
    /// What produced the hop.
    pub reason: Reason,
}

/// What the honour lane decided.
#[derive(Debug)]
pub enum Outcome {
    /// Issue a code. `acr` is the value to record on it, `None` when there is
    /// no session evidence to speak for.
    Proceed {
        /// The `acr` claim this authorization earns, already filtered through
        /// [`report_acr`] so it can only name a class the session satisfies.
        acr: Option<&'static str>,
    },
    /// Send the browser through the login hop.
    Interact(Interaction),
    /// Answer the relying party with a terminal error.
    Refuse(OAuth2Error),
}

/// Decide what an authorization request on the honour lane earns.
///
/// Callers must have refused a malformed bundle
/// ([`AuthnRequestParams::parse_error`]) before reaching here: this function
/// reads meanings, and a value that has no meaning is `invalid_request` at the
/// gate rather than a decision here.
///
/// # `prompt=consent` (a W4 decision that W7 supersedes)
///
/// Plan §4.2 sends `prompt=consent` to a first-party consent screen that G8
/// (wave W7) renders. That screen does not exist yet, and the two available
/// answers were *ignore it* — the silent downgrade this whole lane exists to
/// prevent, so not an option — or refuse with `interaction_required`.
///
/// W4 treats it as `login` instead, and the argument is that refusing buys no
/// security property while costing the lane its adopters. OIDC Core §3.1.2.1
/// says of `consent` that the server "SHOULD prompt the End-User for consent",
/// leaving the OP to choose the ceremony; a fresh credential check *is* an
/// interaction, performed by the user, in front of a page naming this
/// deployment, before any code is issued. Nothing is asserted about it — there
/// is no consent claim to be false, and no consent-gated data exists to be
/// released without one until W7 defines the sensitive scopes. Meanwhile
/// `interaction_required` would make the honour lane unusable for every
/// relying party whose library sends `prompt=consent` by reflex, and an
/// operator who cannot adopt `honour` keeps `ignore` — where `max_age` and
/// `prompt=none` are dropped silently too. W7 replaces the ceremony behind the
/// same redirect and no relying party has to change.
pub fn evaluate(req: Request<'_>) -> Outcome {
    let params = req.params;
    let has_session = req.auth_time.is_some();
    let achieved = acr_for(req.amr);

    // What the relying party asked about the authentication context class.
    // `claims.id_token.acr` wins over `acr_values` when it names values, per
    // OIDC Core §5.5.1.1 — it is the form that can be *essential*, and an RP
    // that sent both said the specific thing in the specific place.
    let acr_essential = params.claims_acr.as_ref().is_some_and(|c| c.essential);
    let wanted: &[String] = match params.claims_acr.as_ref() {
        Some(c) if !c.values.is_empty() => &c.values,
        _ => &params.acr_values,
    };
    let acr_requested = params.claims_acr.is_some() || !params.acr_values.is_empty();

    // Satisfied when nothing was asked; when something was asked with no
    // constraint, satisfied by having any evidence at all to report; otherwise
    // by the achieved class covering one of the values named.
    let acr_satisfied = if !acr_requested {
        true
    } else if wanted.is_empty() {
        has_session
    } else {
        has_session
            && wanted
                .iter()
                .filter_map(|v| Acr::from_wire(v))
                .any(|required| achieved.satisfies(required))
    };

    // `max_age`: whole seconds, floored, never in the relying party's favour.
    // No session is "infinitely old" rather than "unconstrained".
    let max_age_unmet = match params.max_age {
        None => false,
        Some(limit) => match req.auth_time {
            None => true,
            Some(at) => elapsed_secs(req.now, at) >= limit,
        },
    };

    // `id_token_hint`: present means it must name *this* subject and *this*
    // client. A hint that failed to verify arrives as `None` and is a mismatch
    // — never a hint that is quietly dropped.
    let hint_mismatch = params.id_token_hint.is_some()
        && !req.id_token_hint.is_some_and(|hint| {
            hint.subject_id == Some(req.subject) && hint.client_id == req.client_id
        });

    let asked_for_interaction = params
        .prompt
        .iter()
        .any(|p| matches!(p, Prompt::Login | Prompt::Consent | Prompt::SelectAccount));
    let select_account = params.prompt.contains(&Prompt::SelectAccount);

    // The value the code would carry, if a code is issued. Computed once so
    // that every `Proceed` below reports the same thing, and only ever from
    // `achieved` — see `crate::acr` for why that is the whole defence.
    let reported = has_session.then(|| report_acr(achieved, wanted));

    if params.prompt.contains(&Prompt::None) {
        // `prompt=none` is exclusive (the parser refuses it combined with
        // anything else), so no interaction was also asked for. Nothing below
        // may interact, and a request that already has is refused.
        if req.return_leg {
            return Outcome::Refuse(OAuth2Error::LoginRequired(
                "prompt=none was requested, but this authorization request has already been \
                 through the sign-in page; a silent authorization cannot follow an interactive \
                 one"
                .into(),
            ));
        }
        if hint_mismatch {
            return Outcome::Refuse(OAuth2Error::LoginRequired(
                "the id_token_hint names a different end user or a different client than the \
                 session this request arrives with"
                    .into(),
            ));
        }
        if max_age_unmet {
            return Outcome::Refuse(OAuth2Error::LoginRequired(
                "the authentication behind this session is older than the requested max_age, \
                 and prompt=none forbids asking the end user to authenticate again"
                    .into(),
            ));
        }
        if !acr_satisfied && acr_essential {
            return Outcome::Refuse(OAuth2Error::UnmetAuthenticationRequirements(
                "the requested authentication context class is essential and this session does \
                 not satisfy it, and prompt=none forbids a step-up"
                    .into(),
            ));
        }
        // A voluntary ACR that is not satisfied cannot be stepped up under
        // `prompt=none`, so the class actually achieved is reported. That is
        // the disappointing answer and the true one.
        return Outcome::Proceed { acr: reported };
    }

    let unmet = hint_mismatch || max_age_unmet || !acr_satisfied || asked_for_interaction;
    if !unmet {
        return Outcome::Proceed { acr: reported };
    }

    if !req.return_leg {
        let reason = if hint_mismatch {
            Reason::HintMismatch
        } else if max_age_unmet {
            Reason::MaxAgeExceeded
        } else if !acr_satisfied {
            Reason::AcrUnsatisfied
        } else {
            Reason::PromptAsked
        };
        // The page is told which factor to demand, and only when an ACR is
        // what is missing. It is the strongest class the RP named that AXIAM
        // implements — asking for less would not satisfy the request, and
        // there is nothing to ask for beyond the vocabulary.
        let required_acr = (!acr_satisfied)
            .then(|| wanted.iter().filter_map(|v| Acr::from_wire(v)).max())
            .flatten();
        return Outcome::Interact(Interaction {
            required_acr,
            reason,
        });
    }

    // The return leg: one interaction has happened and did not produce what
    // was asked for. Whatever is still unmet is answered rather than retried.
    if hint_mismatch {
        return Outcome::Refuse(if select_account {
            OAuth2Error::AccountSelectionRequired(
                "the end user who signed in is not the one the id_token_hint names".into(),
            )
        } else {
            OAuth2Error::LoginRequired(
                "the end user who signed in is not the one the id_token_hint names".into(),
            )
        });
    }
    if max_age_unmet {
        return Outcome::Refuse(OAuth2Error::LoginRequired(
            "the sign-in did not produce an authentication newer than the requested max_age; \
             a max_age of 0 cannot be satisfied by any authentication, since one is never \
             zero seconds old"
                .into(),
        ));
    }
    if !acr_satisfied && acr_essential {
        return Outcome::Refuse(OAuth2Error::UnmetAuthenticationRequirements(
            "the end user did not complete an authentication satisfying the essential \
             authentication context class this request requires"
                .into(),
        ));
    }
    // What is left is voluntary: an `acr_values` preference the step-up did
    // not meet (the end user declined the second factor, or has none), or a
    // `prompt` whose interaction has now happened. A token is issued, carrying
    // the class that was actually achieved.
    Outcome::Proceed { acr: reported }
}

/// Whole seconds between an authentication and now, never negative.
///
/// A clock that ran backwards (or an upstream provider asserting an
/// authentication instant slightly in the future) yields `0` rather than a
/// wrapped value: the session then reads as brand new, which is the *only*
/// direction that cannot manufacture a refusal out of a clock error — and
/// `max_age = 0` still refuses it, because `0 >= 0`.
fn elapsed_secs(now: DateTime<Utc>, authenticated_at: DateTime<Utc>) -> u64 {
    let secs = (now - authenticated_at).num_seconds();
    u64::try_from(secs).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authn_params::RawAuthnParams;
    use crate::oidc::{ACR_MULTI_FACTOR, ACR_SINGLE_FACTOR};

    const CLIENT: &str = "oa_honour";

    fn params(raw: RawAuthnParams<'_>) -> AuthnRequestParams {
        AuthnRequestParams::parse(&raw)
    }

    struct Fixture {
        subject: Uuid,
        now: DateTime<Utc>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                subject: Uuid::new_v4(),
                now: Utc::now(),
            }
        }

        fn request<'a>(
            &'a self,
            params: &'a AuthnRequestParams,
            age_secs: i64,
            amr: &'a [Amr],
        ) -> Request<'a> {
            Request {
                params,
                auth_time: Some(self.now - chrono::Duration::seconds(age_secs)),
                amr,
                subject: self.subject,
                client_id: CLIENT,
                id_token_hint: None,
                return_leg: false,
                now: self.now,
            }
        }
    }

    fn proceeds(outcome: &Outcome) -> Option<Option<&'static str>> {
        match outcome {
            Outcome::Proceed { acr } => Some(*acr),
            _ => None,
        }
    }

    fn refusal_code(outcome: &Outcome) -> &'static str {
        match outcome {
            Outcome::Refuse(e) => e.error_code(),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn interaction(outcome: &Outcome) -> Interaction {
        match outcome {
            Outcome::Interact(i) => *i,
            other => panic!("expected an interaction, got {other:?}"),
        }
    }

    /// A request that asks for nothing gets a code, and the `acr` it earns is
    /// the class its session achieved.
    #[test]
    fn an_empty_bundle_proceeds_and_still_reports_what_happened() {
        let f = Fixture::new();
        let p = params(RawAuthnParams::default());
        let out = evaluate(f.request(&p, 60, &[Amr::Pwd]));
        assert_eq!(proceeds(&out), Some(Some(ACR_SINGLE_FACTOR)));
    }

    /// With no session row behind the request there is nothing to report, and
    /// no `acr` is invented for it.
    #[test]
    fn a_request_with_no_session_evidence_reports_no_acr() {
        let f = Fixture::new();
        let p = params(RawAuthnParams::default());
        let mut req = f.request(&p, 0, &[]);
        req.auth_time = None;
        assert_eq!(proceeds(&evaluate(req)), Some(None));
    }

    // ---- T2.1 / T2.2 / T2.3 — max_age ------------------------------------

    /// **T2.1.** `max_age=0` against a one-second-old session reauthenticates.
    /// The comparison is `>=`, so this holds for a session of *any* age.
    #[test]
    fn t2_1_max_age_zero_always_reauthenticates() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            max_age: Some("0"),
            ..Default::default()
        });
        for age in [0, 1, 3600] {
            let out = evaluate(f.request(&p, age, &[Amr::Pwd]));
            assert_eq!(
                interaction(&out).reason,
                Reason::MaxAgeExceeded,
                "a {age}s-old session cannot satisfy max_age=0"
            );
        }
    }

    /// …and it is still unsatisfiable on the return leg, where the answer is a
    /// refusal rather than a second hop. Stated as a test because it is the
    /// consequence of `>=` the plan's prose does not spell out.
    #[test]
    fn max_age_zero_is_refused_rather_than_looped_after_a_reauthentication() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            max_age: Some("0"),
            ..Default::default()
        });
        let mut req = f.request(&p, 0, &[Amr::Pwd]);
        req.return_leg = true;
        assert_eq!(refusal_code(&evaluate(req)), "login_required");
    }

    /// **T2.2.** A session older than `max_age` is stepped through the login
    /// hop; the reauthenticated return leg proceeds.
    #[test]
    fn t2_2_an_expired_max_age_reauthenticates_and_then_proceeds() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            max_age: Some("1"),
            ..Default::default()
        });
        assert_eq!(
            interaction(&evaluate(f.request(&p, 2, &[Amr::Pwd]))).reason,
            Reason::MaxAgeExceeded
        );

        // The reauthentication produced a fresh session; the return leg is
        // satisfied by it.
        let mut fresh = f.request(&p, 0, &[Amr::Pwd]);
        fresh.return_leg = true;
        assert!(proceeds(&evaluate(fresh)).is_some());
    }

    /// **T2.3.** A `max_age` the session already satisfies asks for nothing.
    #[test]
    fn t2_3_a_satisfied_max_age_is_invisible() {
        let f = Fixture::new();
        for limit in ["10000", "15000"] {
            let p = params(RawAuthnParams {
                max_age: Some(limit),
                ..Default::default()
            });
            assert!(
                proceeds(&evaluate(f.request(&p, 30, &[Amr::Pwd]))).is_some(),
                "max_age={limit} over a 30s-old session"
            );
        }
    }

    /// A session that cannot be read is infinitely old, not unconstrained.
    #[test]
    fn max_age_against_no_session_at_all_is_unmet() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            max_age: Some("3600"),
            ..Default::default()
        });
        let mut req = f.request(&p, 0, &[]);
        req.auth_time = None;
        assert_eq!(
            interaction(&evaluate(req)).reason,
            Reason::MaxAgeExceeded,
            "no evidence of an authentication cannot satisfy a freshness bound"
        );
    }

    /// A clock that ran backwards must not manufacture a refusal.
    #[test]
    fn an_authentication_instant_in_the_future_reads_as_zero_seconds_old() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            max_age: Some("60"),
            ..Default::default()
        });
        let mut req = f.request(&p, 0, &[Amr::Pwd]);
        req.auth_time = Some(f.now + chrono::Duration::seconds(30));
        assert!(proceeds(&evaluate(req)).is_some());
    }

    // ---- T1.* — prompt ----------------------------------------------------

    /// **T1.1 / T1.7.** `prompt=none` with nothing to go on is refused, never
    /// redirected to a sign-in page.
    #[test]
    fn t1_1_prompt_none_without_a_usable_session_is_login_required() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            prompt: Some("none"),
            max_age: Some("60"),
            ..Default::default()
        });
        let mut req = f.request(&p, 0, &[]);
        req.auth_time = None;
        assert_eq!(refusal_code(&evaluate(req)), "login_required");
    }

    /// **T1.2.** `prompt=none` with a session that satisfies the request is a
    /// code, and no interaction of any kind.
    #[test]
    fn t1_2_prompt_none_with_a_satisfying_session_proceeds() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            prompt: Some("none"),
            max_age: Some("3600"),
            ..Default::default()
        });
        assert!(proceeds(&evaluate(f.request(&p, 5, &[Amr::Pwd]))).is_some());
    }

    /// `prompt=none` on a request that has already been through the login page
    /// is refused: the interaction it forbade has happened.
    ///
    /// This is what makes the pushed-request carrier safe. A `prompt=none`
    /// inside a PAR handle cannot be read until the handle is consumed, which
    /// is after the hop — so the marker, not the parameter, is what stops a
    /// code being issued behind an interaction the RP forbade.
    #[test]
    fn prompt_none_on_a_return_leg_is_refused_however_good_the_session_is() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            prompt: Some("none"),
            ..Default::default()
        });
        let mut req = f.request(&p, 0, &[Amr::Pwd, Amr::Mfa]);
        req.return_leg = true;
        assert_eq!(refusal_code(&evaluate(req)), "login_required");
    }

    /// **T1.5.** `prompt=login` always interacts, however fresh the session.
    #[test]
    fn t1_5_prompt_login_always_interacts() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            prompt: Some("login"),
            ..Default::default()
        });
        let out = evaluate(f.request(&p, 0, &[Amr::Pwd]));
        assert_eq!(interaction(&out).reason, Reason::PromptAsked);
        assert_eq!(
            interaction(&out).required_acr,
            None,
            "a prompt=login hop demands no particular factor"
        );

        // …and the interaction it produced satisfies it.
        let mut back = f.request(&p, 0, &[Amr::Pwd]);
        back.return_leg = true;
        assert!(proceeds(&evaluate(back)).is_some());
    }

    /// `select_account` is handled as `login` (plan §4.2): in a
    /// single-account SPA a fresh sign-in *is* the account picker.
    #[test]
    fn select_account_is_handled_as_login() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            prompt: Some("select_account"),
            ..Default::default()
        });
        assert_eq!(
            interaction(&evaluate(f.request(&p, 0, &[Amr::Pwd]))).reason,
            Reason::PromptAsked
        );
    }

    /// …and it is what turns a surviving hint mismatch into
    /// `account_selection_required` rather than `login_required`: the user did
    /// sign in, just not as the account the relying party named.
    #[test]
    fn select_account_names_the_account_when_a_hint_still_does_not_match() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            prompt: Some("select_account"),
            id_token_hint: Some("ey.a.b"),
            ..Default::default()
        });
        let mut req = f.request(&p, 0, &[Amr::Pwd]);
        req.return_leg = true;
        assert_eq!(refusal_code(&evaluate(req)), "account_selection_required");

        // Without `select_account` the same state is `login_required`.
        let p = params(RawAuthnParams {
            id_token_hint: Some("ey.a.b"),
            ..Default::default()
        });
        let mut req = f.request(&p, 0, &[Amr::Pwd]);
        req.return_leg = true;
        assert_eq!(refusal_code(&evaluate(req)), "login_required");
    }

    /// The W4 seam: `prompt=consent` is an interaction, not a no-op, until W7
    /// has a screen to render. See this function's docs for the argument.
    #[test]
    fn prompt_consent_interacts_rather_than_being_ignored() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            prompt: Some("consent"),
            ..Default::default()
        });
        assert_eq!(
            interaction(&evaluate(f.request(&p, 0, &[Amr::Pwd]))).reason,
            Reason::PromptAsked
        );
        let mut back = f.request(&p, 0, &[Amr::Pwd]);
        back.return_leg = true;
        assert!(
            proceeds(&evaluate(back)).is_some(),
            "the ceremony has happened; a second one would be a loop"
        );
    }

    // ---- T1.* / M4 — id_token_hint ---------------------------------------

    fn hint(subject: Option<Uuid>, client_id: &str) -> IdTokenHint {
        IdTokenHint {
            session_id: None,
            client_id: client_id.to_owned(),
            subject_id: subject,
        }
    }

    #[test]
    fn a_matching_hint_asks_for_nothing() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            id_token_hint: Some("ey.a.b"),
            ..Default::default()
        });
        let matching = hint(Some(f.subject), CLIENT);
        let mut req = f.request(&p, 0, &[Amr::Pwd]);
        req.id_token_hint = Some(&matching);
        assert!(proceeds(&evaluate(req)).is_some());
    }

    #[test]
    fn a_hint_for_another_subject_or_another_client_is_a_mismatch() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            id_token_hint: Some("ey.a.b"),
            ..Default::default()
        });
        for wrong in [
            hint(Some(Uuid::new_v4()), CLIENT),
            hint(Some(f.subject), "oa_someone_else"),
            hint(None, CLIENT),
        ] {
            let mut req = f.request(&p, 0, &[Amr::Pwd]);
            req.id_token_hint = Some(&wrong);
            assert_eq!(
                interaction(&evaluate(req)).reason,
                Reason::HintMismatch,
                "{wrong:?}"
            );
        }
    }

    /// A hint that did not verify is a mismatch, not an absent hint. Dropping
    /// it would let an unsigned string turn a `prompt=none` refusal into a
    /// code.
    #[test]
    fn an_unverifiable_hint_is_treated_as_naming_somebody_else() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            prompt: Some("none"),
            id_token_hint: Some("not-a-jwt"),
            ..Default::default()
        });
        let mut req = f.request(&p, 0, &[Amr::Pwd]);
        req.id_token_hint = None; // decoding failed
        assert_eq!(refusal_code(&evaluate(req)), "login_required");
    }

    // ---- T3.* — acr -------------------------------------------------------

    /// **T3.1.** A request for MFA over a password session never produces an
    /// `acr` of MFA. It produces a step-up; and when the step-up does not
    /// happen (**T3.3**, the return leg), the token says what is true.
    #[test]
    fn t3_1_and_t3_3_an_unsatisfied_voluntary_acr_steps_up_then_tells_the_truth() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            acr_values: Some(ACR_MULTI_FACTOR),
            ..Default::default()
        });
        let out = evaluate(f.request(&p, 0, &[Amr::Pwd]));
        assert_eq!(interaction(&out).reason, Reason::AcrUnsatisfied);
        assert_eq!(interaction(&out).required_acr, Some(Acr::MultiFactor));

        let mut declined = f.request(&p, 0, &[Amr::Pwd]);
        declined.return_leg = true;
        assert_eq!(
            proceeds(&evaluate(declined)),
            Some(Some(ACR_SINGLE_FACTOR)),
            "a declined step-up yields a token that says 1fa, never the mfa that was asked for"
        );
    }

    /// **T3.2.** An *essential* ACR that survives the step-up is refused, and
    /// never with a token.
    #[test]
    fn t3_2_an_unmet_essential_acr_is_refused() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            claims: Some(
                r#"{"id_token":{"acr":{"essential":true,"values":["urn:axiam:acr:mfa"]}}}"#,
            ),
            ..Default::default()
        });
        assert_eq!(
            interaction(&evaluate(f.request(&p, 0, &[Amr::Pwd]))).reason,
            Reason::AcrUnsatisfied
        );

        let mut back = f.request(&p, 0, &[Amr::Pwd]);
        back.return_leg = true;
        assert_eq!(
            refusal_code(&evaluate(back)),
            "unmet_authentication_requirements"
        );
    }

    /// …and under `prompt=none`, where no step-up is possible, immediately.
    #[test]
    fn an_essential_acr_under_prompt_none_is_refused_without_a_hop() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            prompt: Some("none"),
            claims: Some(
                r#"{"id_token":{"acr":{"essential":true,"values":["urn:axiam:acr:mfa"]}}}"#,
            ),
            ..Default::default()
        });
        assert_eq!(
            refusal_code(&evaluate(f.request(&p, 0, &[Amr::Pwd]))),
            "unmet_authentication_requirements"
        );
    }

    /// A voluntary ACR under `prompt=none` cannot be stepped up, so the
    /// request succeeds with the truthful class.
    #[test]
    fn a_voluntary_acr_under_prompt_none_proceeds_with_the_achieved_class() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            prompt: Some("none"),
            acr_values: Some(ACR_MULTI_FACTOR),
            ..Default::default()
        });
        assert_eq!(
            proceeds(&evaluate(f.request(&p, 0, &[Amr::Pwd]))),
            Some(Some(ACR_SINGLE_FACTOR))
        );
    }

    /// **T3.4.** Most-preferred satisfied, in the relying party's order.
    #[test]
    fn t3_4_the_reported_class_follows_the_relying_partys_order() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            acr_values: Some("urn:axiam:acr:1fa urn:axiam:acr:mfa"),
            ..Default::default()
        });
        assert_eq!(
            proceeds(&evaluate(f.request(&p, 0, &[Amr::Pwd, Amr::Otp, Amr::Mfa]))),
            Some(Some(ACR_SINGLE_FACTOR))
        );
    }

    /// A satisfied MFA request asks for no interaction and reports MFA.
    #[test]
    fn a_satisfied_acr_request_proceeds() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            acr_values: Some(ACR_MULTI_FACTOR),
            ..Default::default()
        });
        assert_eq!(
            proceeds(&evaluate(f.request(&p, 0, &[Amr::Hwk, Amr::User]))),
            Some(Some(ACR_MULTI_FACTOR))
        );
    }

    /// `claims.id_token.acr` with no values is a request for the claim, not
    /// for a class: any session satisfies it, no session does not.
    #[test]
    fn an_unconstrained_acr_claim_request_needs_only_a_session() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            claims: Some(r#"{"id_token":{"acr":{"essential":true}}}"#),
            ..Default::default()
        });
        assert!(proceeds(&evaluate(f.request(&p, 0, &[Amr::Pwd]))).is_some());

        let mut none = f.request(&p, 0, &[]);
        none.auth_time = None;
        assert_eq!(
            interaction(&evaluate(none)).reason,
            Reason::AcrUnsatisfied,
            "an essential acr claim cannot be produced without a session to produce it from"
        );
    }

    /// `claims.id_token.acr` outranks `acr_values` when it names values: it is
    /// the form that can be essential, and an RP that sent both said the
    /// specific thing in the specific place.
    #[test]
    fn the_claims_document_wins_over_acr_values_when_it_names_any() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            acr_values: Some(ACR_SINGLE_FACTOR),
            claims: Some(r#"{"id_token":{"acr":{"value":"urn:axiam:acr:mfa"}}}"#),
            ..Default::default()
        });
        assert_eq!(
            interaction(&evaluate(f.request(&p, 0, &[Amr::Pwd]))).reason,
            Reason::AcrUnsatisfied,
            "the acr_values entry the session does satisfy must not mask the claims request"
        );
    }

    /// An RP asking only for classes AXIAM does not implement is answered with
    /// what it has, never with its own string — and is not stepped up for a
    /// class nobody could ever reach.
    #[test]
    fn a_request_for_an_unimplemented_class_cannot_produce_an_endless_step_up() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            acr_values: Some("urn:example:acr:retina"),
            ..Default::default()
        });
        let out = evaluate(f.request(&p, 0, &[Amr::Pwd]));
        // One step-up is offered (the RP asked for something), with no factor
        // named — there is none to name.
        assert_eq!(interaction(&out).required_acr, None);

        let mut back = f.request(&p, 0, &[Amr::Pwd]);
        back.return_leg = true;
        assert_eq!(
            proceeds(&evaluate(back)),
            Some(Some(ACR_SINGLE_FACTOR)),
            "and it terminates with the truth rather than looping"
        );
    }

    /// Several unmet requirements at once are reported in a fixed order, so a
    /// log line names one cause rather than whichever branch ran first.
    #[test]
    fn the_reason_reported_is_the_most_specific_one() {
        let f = Fixture::new();
        let p = params(RawAuthnParams {
            prompt: Some("login"),
            max_age: Some("0"),
            acr_values: Some(ACR_MULTI_FACTOR),
            id_token_hint: Some("ey.a.b"),
            ..Default::default()
        });
        assert_eq!(
            interaction(&evaluate(f.request(&p, 0, &[Amr::Pwd]))).reason,
            Reason::HintMismatch
        );
    }
}
