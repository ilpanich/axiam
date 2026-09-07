//! OpenID Connect authentication-request parameters (X7.1, plan §4.1).
//!
//! OIDC Core §3.1.2.1 adds nine parameters to the authorization request that
//! plain OAuth 2.0 does not have. AXIAM has never read any of them: they are
//! not fields on `AuthorizeQuery`, so serde drops them, and the request
//! proceeds as though they were never sent. That is a *conformant* answer for
//! the cosmetic four and a **silent downgrade** for the five that carry
//! security — a relying party that sends `max_age=0` and receives a code
//! minted from a week-old session has been told a freshness guarantee it did
//! not get.
//!
//! This module is the first half of closing that: one typed, total parse of
//! all nine, shared by both carriers. Acting on them is a later wave; nothing
//! here decides anything.
//!
//! # Why the parse is total
//!
//! Invariant 4 of the plan is that no client registered today changes
//! behaviour. A client on the `ignore` lane that sends `max_age=tomorrow`
//! gets a code today, and must keep getting one — so a malformed value
//! cannot be an error the parse *returns*, or the caller would have to
//! remember to swallow it, on every path, forever.
//!
//! Instead [`AuthnRequestParams::parse`] always succeeds and records the first
//! malformed value in [`AuthnRequestParams::parse_error`]. The honour lane
//! asks for it and refuses; the ignore lane never asks, and a parameter it
//! could not understand is simply one more parameter it was going to drop.
//! The presence of a parameter, which is what the FAPI gate reads, survives
//! either way — [`AuthnRequestParams::security_bearing_present`] counts a
//! malformed `max_age` as present, because a `fapi2` client that sent one
//! must be refused whether or not it spelled it correctly.
//!
//! # Which parameters are "security-bearing"
//!
//! | Parameter | Security-bearing | What it asserts |
//! |---|---|---|
//! | `prompt` | yes | that the OP did, or did not, interact with the user |
//! | `max_age` | yes | an upper bound on the age of the authentication |
//! | `acr_values` | yes | which authentication method was used |
//! | `claims` | yes | (its `id_token.acr` member) the same |
//! | `id_token_hint` | yes | which subject the RP believes is present |
//! | `login_hint` | no | a prefill for a form |
//! | `display` | no | a layout request |
//! | `ui_locales` | no | a language preference |
//! | `claims_locales` | no | a language preference |
//!
//! The split is not stylistic. The first five change what a token *means*, so
//! ignoring one is a lie; a `fapi2` client is refused them outright (see
//! `crate::fapi::enforce_authorization_request`). The last four change what a
//! page *looks like*, so ignoring one costs a relying party nothing it can
//! detect, and refusing `login_hint` — which client libraries send by reflex —
//! would break working clients for no security gain.

use axiam_core::models::oauth2_client::PushedAuthParams;

/// Longest accepted value for a free-text parameter, in bytes.
///
/// The four cosmetic parameters are data AXIAM stores and hands to a template;
/// none of them has a legitimate long form (`ui_locales` is a space-separated
/// BCP 47 list, `login_hint` an identifier). The cap exists so that a value
/// arriving from a browser query string cannot be used to push kilobytes
/// through whatever eventually renders it.
pub const MAX_HINT_LEN: usize = 256;

/// The values `prompt` may take (OIDC Core §3.1.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Prompt {
    /// No interactive prompt of any kind; fail with `login_required` (etc.)
    /// rather than showing a page.
    None,
    /// Reauthenticate even if a session exists.
    Login,
    /// Ask for consent even if it was given before.
    Consent,
    /// Offer an account chooser.
    SelectAccount,
}

impl Prompt {
    /// The wire spelling, as OIDC Core §3.1.2.1 writes it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Login => "login",
            Self::Consent => "consent",
            Self::SelectAccount => "select_account",
        }
    }

    fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "none" => Some(Self::None),
            "login" => Some(Self::Login),
            "consent" => Some(Self::Consent),
            "select_account" => Some(Self::SelectAccount),
            _ => None,
        }
    }
}

/// What an RP asked for in `claims.id_token.acr` (OIDC Core §5.5.1).
///
/// Only this one member of the `claims` document is modelled, and discovery
/// says so with `claims_parameter_supported: false`: a partially-honoured
/// `claims` document is worse than an unsupported one, because an RP cannot
/// tell which members were read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AcrRequest {
    /// `essential: true` — the RP wants the request to *fail* rather than
    /// return a token that does not satisfy it.
    pub essential: bool,
    /// The acceptable values, from `value` (one) or `values` (several), in the
    /// order the RP wrote them.
    pub values: Vec<String>,
}

/// The nine parameters as they arrived, before any interpretation.
///
/// A borrowed view rather than an owned struct so that the inline query string
/// and a consumed pushed request produce the *same* input to the *same* parse.
/// Two carriers with two parsers is how a parameter comes to mean one thing
/// over PAR and another inline, which is the confusion PAR exists to prevent.
#[derive(Debug, Clone, Copy, Default)]
pub struct RawAuthnParams<'a> {
    pub prompt: Option<&'a str>,
    pub max_age: Option<&'a str>,
    pub acr_values: Option<&'a str>,
    pub claims: Option<&'a str>,
    pub id_token_hint: Option<&'a str>,
    pub login_hint: Option<&'a str>,
    pub display: Option<&'a str>,
    pub ui_locales: Option<&'a str>,
    pub claims_locales: Option<&'a str>,
}

impl<'a> From<&'a PushedAuthParams> for RawAuthnParams<'a> {
    fn from(p: &'a PushedAuthParams) -> Self {
        Self {
            prompt: p.prompt.as_deref(),
            max_age: p.max_age.as_deref(),
            acr_values: p.acr_values.as_deref(),
            claims: p.claims.as_deref(),
            id_token_hint: p.id_token_hint.as_deref(),
            login_hint: p.login_hint.as_deref(),
            display: p.display.as_deref(),
            ui_locales: p.ui_locales.as_deref(),
            claims_locales: p.claims_locales.as_deref(),
        }
    }
}

/// The five parameters that change what a token means, in the order the gate
/// reports them.
const SECURITY_BEARING: [&str; 5] = ["prompt", "max_age", "acr_values", "claims", "id_token_hint"];

/// The parsed bundle.
///
/// Every field is `None`/empty when the parameter was absent **or** malformed;
/// [`Self::parse_error`] distinguishes the two, and [`Self::present`] records
/// what arrived regardless. See the module docs for why the parse cannot fail.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthnRequestParams {
    /// OIDC Core §3.1.2.1 — deduplicated and sorted, so `"login consent"` and
    /// `"consent login"` are one request rather than two.
    pub prompt: Vec<Prompt>,
    /// Seconds. `Some(0)` is a real value meaning "always reauthenticate" and
    /// is deliberately distinct from `None`; conflating them is the bug this
    /// type exists to make unrepresentable.
    pub max_age: Option<u64>,
    /// Space-separated, kept in the RP's preference order.
    pub acr_values: Vec<String>,
    /// The `id_token.acr` member of `claims`, if any.
    pub claims_acr: Option<AcrRequest>,
    /// Opaque here; decoded only on the honour lane, where a signature check
    /// is affordable and meaningful.
    pub id_token_hint: Option<String>,
    /// A prefill for the login form. Never used to look a user up.
    pub login_hint: Option<String>,
    /// A layout hint.
    pub display: Option<String>,
    /// A space-separated BCP 47 list.
    pub ui_locales: Option<String>,
    /// A space-separated BCP 47 list.
    pub claims_locales: Option<String>,

    /// Which of the nine arrived at all, malformed ones included.
    present: Vec<&'static str>,
    /// The first value that could not be understood.
    error: Option<String>,
}

impl AuthnRequestParams {
    /// Parse the nine parameters. Always succeeds — see the module docs.
    pub fn parse(raw: &RawAuthnParams<'_>) -> Self {
        let mut out = Self::default();
        let fail = |out: &mut Self, msg: String| {
            if out.error.is_none() {
                out.error = Some(msg);
            }
        };

        // `prompt` — a space-separated set. OIDC Core §3.1.2.1 makes `none`
        // exclusive: combined with anything else it is contradictory (the RP
        // asks both for no interaction and for a specific interaction), and
        // the spec says to answer `invalid_request` rather than pick one.
        if let Some(raw_prompt) = present(raw.prompt) {
            out.present.push("prompt");
            let mut set = Vec::new();
            for token in raw_prompt.split_ascii_whitespace() {
                match Prompt::from_wire(token) {
                    Some(p) => {
                        if !set.contains(&p) {
                            set.push(p);
                        }
                    }
                    None => fail(
                        &mut out,
                        format!(
                            "prompt value {token:?} is not one of none, login, consent, select_account"
                        ),
                    ),
                }
            }
            if set.contains(&Prompt::None) && set.len() > 1 {
                fail(
                    &mut out,
                    "prompt=none may not be combined with any other prompt value (OIDC Core \
                     §3.1.2.1)"
                        .to_owned(),
                );
            }
            set.sort_unstable();
            out.prompt = set;
        }

        // `max_age` — a non-negative integer count of seconds. `0` parses to
        // `Some(0)`, never `None`: it is the RP asking to always
        // reauthenticate, which is the strictest thing it can ask, and the
        // reading that drops it is the one that silently ignores the strongest
        // request in the specification.
        if let Some(raw_max_age) = present(raw.max_age) {
            out.present.push("max_age");
            match raw_max_age.parse::<u64>() {
                Ok(secs) => out.max_age = Some(secs),
                Err(_) => fail(
                    &mut out,
                    format!("max_age {raw_max_age:?} is not a non-negative integer of seconds"),
                ),
            }
        }

        if let Some(raw_acr) = present(raw.acr_values) {
            out.present.push("acr_values");
            out.acr_values = raw_acr
                .split_ascii_whitespace()
                .map(str::to_owned)
                .collect();
        }

        if let Some(raw_claims) = present(raw.claims) {
            out.present.push("claims");
            match serde_json::from_str::<serde_json::Value>(raw_claims) {
                Ok(doc) => match parse_claims_acr(&doc) {
                    Ok(acr) => out.claims_acr = acr,
                    Err(e) => fail(&mut out, e),
                },
                Err(e) => fail(&mut out, format!("claims is not a JSON object: {e}")),
            }
        }

        if let Some(hint) = present(raw.id_token_hint) {
            out.present.push("id_token_hint");
            // Deliberately not length-capped against MAX_HINT_LEN: this is a
            // JWT, not a hint in the cosmetic sense, and a legitimate one is
            // comfortably longer than 256 bytes. Its bound is the server's
            // request-line limit, and its validation is a signature check on
            // the honour lane.
            out.id_token_hint = Some(hint.to_owned());
        }

        // The cosmetic four. Bounded and taken as data; no lookup, no parsing,
        // no interpretation. A value that is too long is dropped rather than
        // truncated — a truncated locale or login hint is a *wrong* value,
        // and quietly substituting one is worse than having none.
        for (name, value, slot) in [
            ("login_hint", raw.login_hint, &mut out.login_hint),
            ("display", raw.display, &mut out.display),
            ("ui_locales", raw.ui_locales, &mut out.ui_locales),
            (
                "claims_locales",
                raw.claims_locales,
                &mut out.claims_locales,
            ),
        ] {
            if let Some(v) = present(value) {
                out.present.push(name);
                if v.len() > MAX_HINT_LEN {
                    if out.error.is_none() {
                        out.error = Some(format!(
                            "{name} exceeds the {MAX_HINT_LEN}-byte limit for a hint parameter"
                        ));
                    }
                } else {
                    *slot = Some(v.to_owned());
                }
            }
        }

        out
    }

    /// The first value that could not be understood, if any.
    ///
    /// Read **only** on the honour lane. On the ignore lane a malformed value
    /// is one more value that was going to be dropped, and surfacing it would
    /// break a client that works today (invariant 4).
    pub fn parse_error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// The names of the parameters that arrived, malformed ones included.
    pub fn present(&self) -> &[&'static str] {
        &self.present
    }

    /// Whether any of the nine arrived.
    pub fn is_empty(&self) -> bool {
        self.present.is_empty()
    }

    /// The security-bearing parameters that arrived — the five that change
    /// what a token means. See the module docs for why the other four are not
    /// on this list.
    pub fn security_bearing_present(&self) -> Vec<&'static str> {
        self.present
            .iter()
            .copied()
            .filter(|n| SECURITY_BEARING.contains(n))
            .collect()
    }
}

/// A parameter counts as present only when it is there and not blank.
///
/// `?prompt=` in a query string is a browser or a client library filling in a
/// template, not an RP asking for something. Treating it as present would make
/// an empty template refuse a `fapi2` request.
fn present(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

/// Read `claims.id_token.acr` (OIDC Core §5.5.1) out of a parsed document.
///
/// `Ok(None)` means the document parsed and asked for no ACR — which is the
/// common case, and not an error: `claims` is frequently sent asking for
/// `userinfo` members AXIAM does not implement, and discovery already says
/// `claims_parameter_supported: false`. Only a *malformed* `id_token.acr` is
/// an error, because that one member is the one AXIAM promises to read.
fn parse_claims_acr(doc: &serde_json::Value) -> Result<Option<AcrRequest>, String> {
    if !doc.is_object() {
        return Err("claims must be a JSON object (OIDC Core §5.5)".to_owned());
    }
    let Some(acr) = doc.get("id_token").and_then(|t| t.get("acr")) else {
        return Ok(None);
    };
    // `"acr": null` is the spec's own spelling of "requested with no
    // constraints" (§5.5), so it is a request with an empty value list rather
    // than a malformed one.
    if acr.is_null() {
        return Ok(Some(AcrRequest::default()));
    }
    let Some(obj) = acr.as_object() else {
        return Err(
            "claims.id_token.acr must be null or a JSON object (OIDC Core §5.5)".to_owned(),
        );
    };

    let essential = match obj.get("essential") {
        None => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(_) => return Err("claims.id_token.acr.essential must be a boolean".to_owned()),
    };

    let mut values = Vec::new();
    if let Some(v) = obj.get("value") {
        match v.as_str() {
            Some(s) => values.push(s.to_owned()),
            None => return Err("claims.id_token.acr.value must be a string".to_owned()),
        }
    }
    if let Some(vs) = obj.get("values") {
        match vs.as_array() {
            Some(arr) => {
                for v in arr {
                    match v.as_str() {
                        Some(s) => values.push(s.to_owned()),
                        None => {
                            return Err(
                                "claims.id_token.acr.values must be an array of strings".to_owned()
                            );
                        }
                    }
                }
            }
            None => return Err("claims.id_token.acr.values must be an array".to_owned()),
        }
    }

    Ok(Some(AcrRequest { essential, values }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: RawAuthnParams<'_>) -> AuthnRequestParams {
        AuthnRequestParams::parse(&raw)
    }

    /// The shape of every request that exists today: nine absent parameters,
    /// nothing present, nothing to report.
    #[test]
    fn an_empty_request_parses_to_an_empty_bundle() {
        let p = parse(RawAuthnParams::default());
        assert!(p.is_empty());
        assert!(p.parse_error().is_none());
        assert!(p.security_bearing_present().is_empty());
        assert_eq!(p, AuthnRequestParams::default());
    }

    /// A blank value is a template, not a request. It must not make a `fapi2`
    /// client's request refusable.
    #[test]
    fn blank_values_are_not_present() {
        let p = parse(RawAuthnParams {
            prompt: Some(""),
            max_age: Some("   "),
            login_hint: Some(""),
            ..Default::default()
        });
        assert!(p.is_empty(), "{:?}", p.present());
        assert!(p.parse_error().is_none());
    }

    #[test]
    fn prompt_is_a_deduplicated_set() {
        let p = parse(RawAuthnParams {
            prompt: Some("consent login consent"),
            ..Default::default()
        });
        assert_eq!(p.prompt, vec![Prompt::Login, Prompt::Consent]);
        assert!(p.parse_error().is_none());
    }

    /// OIDC Core §3.1.2.1: `none` is exclusive. The parse records the
    /// contradiction; only the honour lane reads it.
    #[test]
    fn prompt_none_may_not_be_combined() {
        let p = parse(RawAuthnParams {
            prompt: Some("none login"),
            ..Default::default()
        });
        assert!(p.parse_error().is_some_and(|e| e.contains("prompt=none")));
        assert_eq!(p.security_bearing_present(), vec!["prompt"]);
    }

    #[test]
    fn an_unknown_prompt_value_is_recorded_as_malformed() {
        let p = parse(RawAuthnParams {
            prompt: Some("teleport"),
            ..Default::default()
        });
        assert!(p.parse_error().is_some_and(|e| e.contains("teleport")));
    }

    /// T2.1's type-level half. `max_age=0` is the strongest freshness request
    /// an RP can make; a parse that turned it into `None` would drop exactly
    /// the request that matters most.
    #[test]
    fn max_age_zero_is_some_zero_and_never_none() {
        let p = parse(RawAuthnParams {
            max_age: Some("0"),
            ..Default::default()
        });
        assert_eq!(p.max_age, Some(0));
        assert!(p.parse_error().is_none());
    }

    #[test]
    fn max_age_must_be_a_non_negative_integer() {
        for bad in ["-1", "1.5", "tomorrow", "0x10", "9999999999999999999999"] {
            let p = parse(RawAuthnParams {
                max_age: Some(bad),
                ..Default::default()
            });
            assert!(
                p.parse_error().is_some(),
                "{bad:?} should be recorded as malformed"
            );
            assert_eq!(p.max_age, None);
            // ...and still counts as present, so a fapi2 client that sent it
            // is refused whether or not it spelled it correctly.
            assert_eq!(p.security_bearing_present(), vec!["max_age"]);
        }
    }

    #[test]
    fn acr_values_keeps_the_rps_preference_order() {
        let p = parse(RawAuthnParams {
            acr_values: Some("urn:axiam:acr:mfa urn:axiam:acr:1fa"),
            ..Default::default()
        });
        assert_eq!(p.acr_values, ["urn:axiam:acr:mfa", "urn:axiam:acr:1fa"]);
    }

    #[test]
    fn claims_id_token_acr_is_read_in_all_three_spellings() {
        let essential = parse(RawAuthnParams {
            claims: Some(r#"{"id_token":{"acr":{"essential":true}}}"#),
            ..Default::default()
        });
        assert_eq!(
            essential.claims_acr,
            Some(AcrRequest {
                essential: true,
                values: vec![]
            })
        );

        let single = parse(RawAuthnParams {
            claims: Some(r#"{"id_token":{"acr":{"value":"urn:axiam:acr:mfa"}}}"#),
            ..Default::default()
        });
        assert_eq!(
            single.claims_acr,
            Some(AcrRequest {
                essential: false,
                values: vec!["urn:axiam:acr:mfa".into()]
            })
        );

        let many = parse(RawAuthnParams {
            claims: Some(r#"{"id_token":{"acr":{"values":["a","b"],"essential":true}}}"#),
            ..Default::default()
        });
        assert_eq!(
            many.claims_acr,
            Some(AcrRequest {
                essential: true,
                values: vec!["a".into(), "b".into()]
            })
        );
    }

    /// `claims` asking only for members AXIAM does not implement is not an
    /// error — discovery already says `claims_parameter_supported: false`.
    #[test]
    fn a_claims_document_without_an_acr_member_is_not_malformed() {
        let p = parse(RawAuthnParams {
            claims: Some(r#"{"userinfo":{"email":{"essential":true}}}"#),
            ..Default::default()
        });
        assert!(p.parse_error().is_none());
        assert_eq!(p.claims_acr, None);
        assert_eq!(p.security_bearing_present(), vec!["claims"]);
    }

    #[test]
    fn a_malformed_claims_document_is_recorded() {
        for bad in [
            "{not json",
            r#"[]"#,
            r#"{"id_token":{"acr":42}}"#,
            r#"{"id_token":{"acr":{"essential":"yes"}}}"#,
            r#"{"id_token":{"acr":{"values":"a"}}}"#,
            r#"{"id_token":{"acr":{"value":7}}}"#,
        ] {
            let p = parse(RawAuthnParams {
                claims: Some(bad),
                ..Default::default()
            });
            assert!(p.parse_error().is_some(), "{bad:?} should be malformed");
        }
    }

    /// `"acr": null` is the specification's own way of asking for the claim
    /// with no constraint, not a broken document.
    #[test]
    fn a_null_acr_member_is_a_request_with_no_constraint() {
        let p = parse(RawAuthnParams {
            claims: Some(r#"{"id_token":{"acr":null}}"#),
            ..Default::default()
        });
        assert!(p.parse_error().is_none());
        assert_eq!(p.claims_acr, Some(AcrRequest::default()));
    }

    #[test]
    fn the_cosmetic_four_are_bounded_and_dropped_rather_than_truncated() {
        let long = "x".repeat(MAX_HINT_LEN + 1);
        let p = parse(RawAuthnParams {
            login_hint: Some(&long),
            ..Default::default()
        });
        assert_eq!(p.login_hint, None, "a too-long hint is dropped, not cut");
        assert!(p.parse_error().is_some());

        let ok = "x".repeat(MAX_HINT_LEN);
        let p = parse(RawAuthnParams {
            login_hint: Some(&ok),
            ..Default::default()
        });
        assert_eq!(p.login_hint.as_deref(), Some(ok.as_str()));
        assert!(p.parse_error().is_none());
    }

    /// The split the FAPI gate depends on: the cosmetic four are never
    /// security-bearing, however many of them arrive.
    #[test]
    fn the_cosmetic_four_are_not_security_bearing() {
        let p = parse(RawAuthnParams {
            login_hint: Some("ada@example.com"),
            display: Some("page"),
            ui_locales: Some("en-GB en"),
            claims_locales: Some("en"),
            ..Default::default()
        });
        assert!(!p.is_empty());
        assert!(
            p.security_bearing_present().is_empty(),
            "{:?}",
            p.security_bearing_present()
        );
    }

    #[test]
    fn all_five_security_bearing_parameters_are_reported() {
        let p = parse(RawAuthnParams {
            prompt: Some("login"),
            max_age: Some("60"),
            acr_values: Some("urn:axiam:acr:mfa"),
            claims: Some(r#"{"id_token":{"acr":{"essential":true}}}"#),
            id_token_hint: Some("ey.header.payload"),
            ..Default::default()
        });
        assert_eq!(
            p.security_bearing_present(),
            ["prompt", "max_age", "acr_values", "claims", "id_token_hint"]
        );
        assert!(p.parse_error().is_none());
    }

    /// The two carriers must produce the same bundle from the same values —
    /// the property that keeps a parameter from meaning one thing over PAR and
    /// another inline.
    #[test]
    fn the_par_carrier_parses_identically_to_the_inline_one() {
        let pushed = PushedAuthParams {
            response_type: "code".into(),
            redirect_uri: "https://rp.example/cb".into(),
            prompt: Some("login consent".into()),
            max_age: Some("0".into()),
            acr_values: Some("urn:axiam:acr:mfa".into()),
            claims: Some(r#"{"id_token":{"acr":{"essential":true}}}"#.into()),
            id_token_hint: Some("ey.hint".into()),
            login_hint: Some("ada@example.com".into()),
            display: Some("page".into()),
            ui_locales: Some("en-GB".into()),
            claims_locales: Some("en".into()),
            ..Default::default()
        };
        let from_par = AuthnRequestParams::parse(&RawAuthnParams::from(&pushed));
        let inline = parse(RawAuthnParams {
            prompt: Some("login consent"),
            max_age: Some("0"),
            acr_values: Some("urn:axiam:acr:mfa"),
            claims: Some(r#"{"id_token":{"acr":{"essential":true}}}"#),
            id_token_hint: Some("ey.hint"),
            login_hint: Some("ada@example.com"),
            display: Some("page"),
            ui_locales: Some("en-GB"),
            claims_locales: Some("en"),
        });
        assert_eq!(from_par, inline);
    }

    /// Only the *first* malformed value is reported, so an operator reading a
    /// log sees one cause rather than a cascade.
    #[test]
    fn only_the_first_parse_failure_is_recorded() {
        let p = parse(RawAuthnParams {
            prompt: Some("teleport"),
            max_age: Some("tomorrow"),
            ..Default::default()
        });
        assert!(p.parse_error().is_some_and(|e| e.contains("teleport")));
    }
}
