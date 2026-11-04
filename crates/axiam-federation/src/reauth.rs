//! Forwarding a re-authentication requirement to the upstream identity
//! provider (#838, D-N26).
//!
//! When a relying party asks AXIAM for a fresh authentication — `prompt=login`,
//! a `max_age` the current session cannot meet, a step-up — the sign-in page
//! may answer it with "Sign in with X". Until #838 the upstream request said
//! nothing about freshness, so a provider holding an SSO session of its own
//! answered at once, with no credential, and the "re-authentication" proved
//! only that the browser still had a cookie at the provider.
//!
//! Two halves, kept apart because they fail differently:
//!
//! 1. **Ask** ([`oidc_params`], [`oauth2_params`], and `ForceAuthn="true"` on
//!    the SAML `AuthnRequest`). What a provider accepts is the provider's
//!    business, so the parameters are chosen per [`ProviderKind`] rather than
//!    sent uniformly: Google answers `prompt=login` with an error page rather
//!    than ignoring it, which would turn a re-authentication into a dead end.
//! 2. **Verify** ([`check_fresh`]). Asking is not proof. Where the provider
//!    states when it authenticated the user — OIDC `auth_time`, SAML
//!    `AuthnInstant` — the callback refuses an instant that predates the start
//!    of the sign-in. Where it states nothing (every plain-OAuth2 provider,
//!    and an OIDC provider that omits `auth_time`) there is nothing to compare,
//!    and the sign-in is accepted on the strength of the request alone; the
//!    session is then dated at AXIAM's verification moment, as before. That
//!    residual is recorded in the threat model (T-493) rather than closed by
//!    refusing every such provider, which would make a `prompt=login` relying
//!    party unusable for a GitHub user.

use chrono::{DateTime, Duration, Utc};

use axiam_core::models::federation::ProviderKind;

/// The extra authorization-request parameters that ask an OpenID Connect
/// provider to authenticate the user again.
///
/// - `max_age=0` for every OIDC kind. OIDC Core §3.1.2.1: a provider that
///   honours it must re-authenticate, and **must** then return `auth_time`
///   (§2), which is what [`check_fresh`] compares. A provider that does not
///   support it ignores an unknown parameter (RFC 6749 §3.1).
/// - `prompt=login` as well, except for Google and Apple. Google documents
///   `none`, `consent` and `select_account` and refuses any other value; Apple
///   documents no `prompt` at all. For both, `max_age=0` is the request and
///   `auth_time` the evidence.
pub fn oidc_params(kind: ProviderKind) -> &'static [(&'static str, &'static str)] {
    match kind {
        ProviderKind::Google | ProviderKind::Apple => &[("max_age", "0")],
        _ => &[("prompt", "login"), ("max_age", "0")],
    }
}

/// The extra authorization-request parameters that ask a plain-OAuth2
/// provider to authenticate the user again — where the provider has one.
///
/// OAuth 2.0 defines no such parameter, so this is a table of provider
/// extensions, and short on purpose:
///
/// - Facebook: `auth_type=reauthenticate`, its documented re-authentication
///   request.
/// - GitHub and a generic OAuth2 provider: nothing. GitHub's only `prompt`
///   value selects an account and re-authenticates nobody; a generic
///   provider's extensions are unknown. Sending a guess would either be
///   ignored or break the sign-in.
///
/// None of these providers returns an authentication instant, so the request
/// is the whole of the measure on this path (see the module docs).
pub fn oauth2_params(kind: ProviderKind) -> &'static [(&'static str, &'static str)] {
    match kind {
        ProviderKind::Facebook => &[("auth_type", "reauthenticate")],
        _ => &[],
    }
}

/// Why a re-authentication sign-in was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaleUpstreamAuthentication {
    /// The instant the provider said it authenticated the user.
    pub upstream_auth_time: DateTime<Utc>,
    /// The earliest instant this sign-in accepts.
    pub not_before: DateTime<Utc>,
}

/// Verify that a provider asked to re-authenticate actually did.
///
/// `not_before` is the login state row's `reauthenticate_after` — the moment
/// the sign-in started, or `None` for an ordinary sign-in, which checks
/// nothing. `upstream_auth_time` is the provider's `auth_time`/`AuthnInstant`
/// **as asserted**, before it is bounded by the verification moment.
///
/// The comparison allows the federation path's existing clock-skew leeway
/// ([`crate::oidc::CLOCK_SKEW_LEEWAY_SECS`]): the instant was stamped by the
/// provider's clock and `not_before` by ours. A provider that re-authenticated
/// the user lands after `not_before`; one that answered from an SSO session it
/// established earlier lands before it by however long ago that was, which is
/// minutes or hours in practice, not the seconds the leeway forgives.
///
/// An absent instant passes — see the module docs for why that is the
/// residual and not a refusal.
pub fn check_fresh(
    not_before: Option<DateTime<Utc>>,
    upstream_auth_time: Option<DateTime<Utc>>,
) -> Result<(), StaleUpstreamAuthentication> {
    let (Some(not_before), Some(upstream_auth_time)) = (not_before, upstream_auth_time) else {
        return Ok(());
    };
    let leeway = Duration::seconds(crate::oidc::CLOCK_SKEW_LEEWAY_SECS as i64);
    if upstream_auth_time + leeway < not_before {
        return Err(StaleUpstreamAuthentication {
            upstream_auth_time,
            not_before,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OIDC_KINDS: [ProviderKind; 4] = [
        ProviderKind::Google,
        ProviderKind::Apple,
        ProviderKind::Microsoft,
        ProviderKind::GenericOidc,
    ];

    #[test]
    fn every_oidc_kind_asks_for_max_age_zero() {
        for kind in OIDC_KINDS {
            assert!(
                oidc_params(kind).contains(&("max_age", "0")),
                "{kind:?} must send max_age=0"
            );
        }
    }

    #[test]
    fn prompt_login_is_withheld_from_the_providers_that_refuse_it() {
        for kind in [ProviderKind::Google, ProviderKind::Apple] {
            assert!(
                !oidc_params(kind).iter().any(|(k, _)| *k == "prompt"),
                "{kind:?} must not be sent a prompt value it rejects"
            );
        }
        for kind in [ProviderKind::Microsoft, ProviderKind::GenericOidc] {
            assert!(oidc_params(kind).contains(&("prompt", "login")), "{kind:?}");
        }
    }

    #[test]
    fn only_facebook_has_an_oauth2_reauthentication_parameter() {
        assert_eq!(
            oauth2_params(ProviderKind::Facebook),
            &[("auth_type", "reauthenticate")]
        );
        for kind in [ProviderKind::Github, ProviderKind::GenericOauth2] {
            assert!(oauth2_params(kind).is_empty(), "{kind:?}");
        }
    }

    #[test]
    fn an_ordinary_sign_in_checks_nothing() {
        let long_ago = Utc::now() - Duration::days(30);
        assert_eq!(check_fresh(None, Some(long_ago)), Ok(()));
        assert_eq!(check_fresh(None, None), Ok(()));
    }

    #[test]
    fn an_absent_upstream_instant_is_the_residual_and_passes() {
        assert_eq!(check_fresh(Some(Utc::now()), None), Ok(()));
    }

    #[test]
    fn an_authentication_after_the_start_passes() {
        let start = Utc::now();
        assert_eq!(
            check_fresh(Some(start), Some(start + Duration::seconds(20))),
            Ok(())
        );
    }

    #[test]
    fn a_reused_upstream_session_is_refused() {
        let start = Utc::now();
        let earlier = start - Duration::hours(3);
        assert_eq!(
            check_fresh(Some(start), Some(earlier)),
            Err(StaleUpstreamAuthentication {
                upstream_auth_time: earlier,
                not_before: start,
            })
        );
    }

    /// The provider's clock is not ours: up to the leeway behind is forgiven,
    /// one second more is not.
    #[test]
    fn the_clock_skew_leeway_is_forgiven_and_no_more() {
        let start = Utc::now();
        let leeway = crate::oidc::CLOCK_SKEW_LEEWAY_SECS as i64;
        assert_eq!(
            check_fresh(Some(start), Some(start - Duration::seconds(leeway))),
            Ok(())
        );
        assert!(check_fresh(Some(start), Some(start - Duration::seconds(leeway + 1))).is_err());
    }
}
