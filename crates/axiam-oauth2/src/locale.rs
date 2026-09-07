//! The presentation parameters of an authentication request (W5, plan §4.6 —
//! G6/G7), as types rather than as strings.
//!
//! `ui_locales` and `display` are the two cosmetic parameters that *do*
//! something. Neither changes what a token means — a relying party cannot
//! detect whether either was honoured by inspecting anything it receives —
//! which is why they are refused on no honest `fapi2` row and why the plan
//! files them away from the security-bearing five. What they do change is a
//! page a human is about to type a password into, and that is the whole reason
//! they are modelled here instead of being forwarded as the strings they
//! arrived as.
//!
//! # Why the raw value never leaves the server
//!
//! `ui_locales` is a space-separated list chosen by the relying party. The
//! obvious implementation forwards it to the sign-in page and lets the page
//! decide; the page then holds an attacker-chosen string, and every later edit
//! that renders it — a "language not available" notice, a `lang` attribute, a
//! debug banner — is a reflected-XSS bug waiting for someone to write it.
//!
//! So the match happens here, and what crosses to the SPA is a
//! [`Locale`] — one of five values this binary knows the names of. Test T6.2
//! (`ui_locales=<img onerror=…>` appears in no redirect the server builds) is
//! then true *by construction*: there is no code path along which the raw
//! value could be written into a URL, because the only thing the builder
//! accepts is this enum. It is not true because someone remembered to escape
//! it, and it does not become false when the next person forgets.
//!
//! [`Display`] is the same argument with four values instead of five.
//!
//! # `claims_locales` is not here, on purpose
//!
//! OIDC Core §3.1.2.1 defines `claims_locales` beside `ui_locales`, one letter
//! of prefix apart, with the same BCP 47 syntax. It selects the language of
//! **claim values** — a `name` in Japanese, an `address` in French — and AXIAM
//! has no localised claims at all, so it is accepted and ignored
//! (`OIDCCClaimsLocales` asks only that it not be an error).
//!
//! The thing to guard against is not that ignoring it is wrong; it is that the
//! two names are adjacent and the values are interchangeable-looking, so a
//! future edit reaching for "the locale the RP asked for" can reach for the
//! wrong one and be visibly correct in review. Nothing in this module reads
//! `claims_locales`, no caller passes it here, and
//! `crate::login_hop::build_login_redirect_for` has no parameter it could
//! arrive through. There is a test in `crate::honour`'s wave pinning that
//! `claims_locales=it` alone leaves the page in the deployment default.
//!
//! # The list is short on purpose
//!
//! Five languages, each translated completely in the SPA
//! (`frontend/src/i18n/`). A sixth added here without its bundle would make
//! `ui_locales=pt` *succeed* and then deliver English, which is worse than
//! answering "no match" and delivering English for a stated reason:
//! `scripts/check-locale-bundle-sync.py` fails the build when this enum and
//! the SPA's catalogue disagree, in either direction.

use std::fmt;

/// A language the sign-in page is fully translated into.
///
/// The variants are the allow-list. There is no constructor from an arbitrary
/// string that does not go through [`Locale::from_tag`], and nothing outside
/// this module can add a sixth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Locale {
    /// English — the deployment default, and what the absence of any selection
    /// means everywhere in this feature.
    English,
    /// Italian.
    Italian,
    /// French.
    French,
    /// German.
    German,
    /// Spanish.
    Spanish,
}

/// Every locale, in the order the documentation and the SPA list them.
///
/// Public because the sync gate and the discovery-adjacent documentation both
/// need to enumerate the list, and a second hand-written copy of it is the
/// thing this constant exists to prevent.
pub const ALL_LOCALES: [Locale; 5] = [
    Locale::English,
    Locale::Italian,
    Locale::French,
    Locale::German,
    Locale::Spanish,
];

/// What AXIAM falls back to when nothing else selects a language.
///
/// Named rather than spelled `Locale::English` at each call site: "the
/// deployment default" and "English" are the same value today and are not the
/// same *idea*, and a deployment that changed one should not silently change
/// the other.
pub const DEPLOYMENT_DEFAULT: Locale = Locale::English;

impl Locale {
    /// The BCP 47 language tag, lower-case, as it appears in a URL and in the
    /// SPA's catalogue key.
    pub const fn as_tag(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::Italian => "it",
            Self::French => "fr",
            Self::German => "de",
            Self::Spanish => "es",
        }
    }

    /// The language's own name for itself, for an operator-facing list.
    ///
    /// Endonyms rather than English names: a language picker that offers
    /// "German" to somebody who reads only German has picked the wrong
    /// audience for its own labels.
    pub const fn endonym(self) -> &'static str {
        match self {
            Self::English => "English",
            Self::Italian => "Italiano",
            Self::French => "Français",
            Self::German => "Deutsch",
            Self::Spanish => "Español",
        }
    }

    /// Parse one complete language tag. Case-insensitive; exact otherwise.
    ///
    /// BCP 47 tags are case-insensitive (RFC 5646 §2.1.1), so `EN`, `En` and
    /// `en` are one tag and answering differently would make the match depend
    /// on a relying party's house style. No truncation happens here — that is
    /// [`select_ui_locale`]'s job, and keeping the two apart is what lets this
    /// function also be the parser for a stored tenant default, where
    /// `fr-CA` in the column should mean "somebody wrote something this
    /// binary does not ship" rather than "French".
    pub fn from_tag(raw: &str) -> Option<Self> {
        let tag = raw.trim();
        ALL_LOCALES
            .into_iter()
            .find(|locale| locale.as_tag().eq_ignore_ascii_case(tag))
    }
}

impl fmt::Display for Locale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_tag())
    }
}

/// The `display` values OIDC Core §3.1.2.1 defines.
///
/// A closed set for the same reason [`Locale`] is one: the value reaches a
/// sign-in page, and the only safe thing to hand a page is a value the page
/// could have named itself. Anything outside the set is dropped — OIDC Core
/// makes `display` a hint, and an OP that refused an unknown hint would be
/// refusing a request it can answer perfectly well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Display {
    /// A full page. The default, and what every other value also gets.
    Page,
    /// A popup window: the one value that changes the layout.
    Popup,
    /// A touch device.
    Touch,
    /// A feature phone ("WAP"). Modelled because the specification defines it,
    /// and mapped to the default layout because AXIAM ships no WML.
    Wap,
}

impl Display {
    /// The wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Page => "page",
            Self::Popup => "popup",
            Self::Touch => "touch",
            Self::Wap => "wap",
        }
    }

    /// Parse a `display` value; `None` for anything outside the four.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim() {
            "page" => Some(Self::Page),
            "popup" => Some(Self::Popup),
            "touch" => Some(Self::Touch),
            "wap" => Some(Self::Wap),
            _ => None,
        }
    }

    /// Whether this asks for the compact layout.
    ///
    /// The plan's mapping in one place: `popup` is compact, everything else is
    /// the default. The SPA holds the CSS; this is the decision, so that "the
    /// allow-list" is one list and not two that could come to disagree.
    pub const fn is_compact(self) -> bool {
        matches!(self, Self::Popup)
    }
}

impl fmt::Display for Display {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Select the sign-in page's language for one authorization request.
///
/// `requested` is the raw `ui_locales` value — a space-separated list of BCP 47
/// tags in the relying party's **preference order** — and `tenant_default` is
/// the tenant's configured language, if it set one and if it names a locale
/// this binary ships.
///
/// Returns the locale to forward, or `None` when nothing was selected. `None`
/// and [`DEPLOYMENT_DEFAULT`] mean the same page: the SPA renders English when
/// it is told nothing, so a request that selects English is a request that
/// needs no parameter, and one fewer parameter in a URL is one fewer thing to
/// get wrong. That is also what makes T6.2 checkable by inspection — a value
/// that matches nothing produces no parameter at all.
///
/// # The matching rule
///
/// RFC 4647 §3.4 *lookup*, applied per requested tag, and the requested tags
/// are tried **in the order the relying party wrote them**. So
/// `ui_locales=zz it fr` selects Italian, not French: the first tag that
/// matches anything wins, rather than the best match found anywhere in the
/// list. That mirrors the "most-preferred satisfied, in RP order" rule W4
/// pinned for `acr_values` ([`crate::acr::report_acr`]) — one preference rule
/// for the whole authorization request rather than one per parameter.
///
/// Within a tag, lookup progressively truncates at `-`: `fr-CA` tries `fr-CA`
/// then `fr`; `de-AT-1996` tries `de-AT-1996`, `de-AT`, `de`. A trailing
/// single-character subtag is removed with the one before it, as §3.4 requires,
/// so a private-use tag cannot truncate to a bare `x`.
///
/// The input is bounded to [`crate::authn_params::MAX_HINT_LEN`] bytes by the
/// parser, so the two nested loops here are bounded by that and need no
/// separate limit.
pub fn select_ui_locale(requested: Option<&str>, tenant_default: Option<Locale>) -> Option<Locale> {
    requested
        .and_then(lookup)
        // No tag matched — or none was sent. The tenant's own default is the
        // next answer, and the deployment default (English, i.e. `None`) is
        // the last.
        .or(tenant_default)
}

/// RFC 4647 §3.4 lookup over the whole requested list. See
/// [`select_ui_locale`] for the rule this implements.
fn lookup(requested: &str) -> Option<Locale> {
    for tag in requested.split_ascii_whitespace() {
        let mut candidate = tag;
        loop {
            if let Some(locale) = Locale::from_tag(candidate) {
                return Some(locale);
            }
            let Some(cut) = candidate.rfind('-') else {
                break;
            };
            candidate = &candidate[..cut];
            // §3.4 step 3: a truncation that leaves a single-character subtag
            // at the end must remove that too, so `en-x-private` cannot become
            // the meaningless `en-x` and then `en` by a different route than
            // the one the specification describes.
            if let Some(cut) = candidate.rfind('-')
                && candidate.len() - cut == 2
            {
                candidate = &candidate[..cut];
            }
            if candidate.is_empty() {
                break;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **T6.1**, the exact-match half, plus the case-insensitivity BCP 47
    /// requires.
    #[test]
    fn an_exact_tag_selects_its_locale_whatever_its_case() {
        for (requested, expected) in [
            ("en", Locale::English),
            ("it", Locale::Italian),
            ("fr", Locale::French),
            ("de", Locale::German),
            ("es", Locale::Spanish),
            ("IT", Locale::Italian),
            ("De", Locale::German),
        ] {
            assert_eq!(
                select_ui_locale(Some(requested), None),
                Some(expected),
                "{requested:?} must select {expected:?}"
            );
        }
    }

    /// **T6.1**, the subtag-fallback half. RFC 4647 lookup truncates at `-`
    /// until something matches.
    #[test]
    fn a_region_or_variant_subtag_falls_back_to_the_language() {
        for (requested, expected) in [
            ("fr-CA", Locale::French),
            ("de-AT-1996", Locale::German),
            ("es-419", Locale::Spanish),
            ("it-IT", Locale::Italian),
            ("en-GB-oed", Locale::English),
        ] {
            assert_eq!(
                select_ui_locale(Some(requested), None),
                Some(expected),
                "{requested:?} must fall back to {expected:?}"
            );
        }
    }

    /// A private-use singleton must not survive truncation on its own.
    #[test]
    fn a_trailing_single_character_subtag_is_removed_with_the_one_before_it() {
        assert_eq!(
            select_ui_locale(Some("de-x-private"), None),
            Some(Locale::German)
        );
        // `x` alone matches nothing and must not loop forever either.
        assert_eq!(select_ui_locale(Some("x"), None), None);
        assert_eq!(select_ui_locale(Some("x-y-z"), None), None);
        assert_eq!(select_ui_locale(Some("-"), None), None);
        assert_eq!(select_ui_locale(Some("---"), None), None);
    }

    /// **T6.1**, the preference-order half — the rule that mirrors W4's
    /// `acr_values`: the first *requested* tag that matches wins, not the best
    /// match found in the list.
    #[test]
    fn the_first_requested_tag_that_matches_wins_in_the_rps_order() {
        assert_eq!(
            select_ui_locale(Some("zz it fr"), None),
            Some(Locale::Italian),
            "the RP put Italian before French"
        );
        assert_eq!(
            select_ui_locale(Some("zz fr it"), None),
            Some(Locale::French),
            "…and the other order selects the other language"
        );
        // A more specific tag later in the list does not outrank an exact
        // match earlier in it.
        assert_eq!(
            select_ui_locale(Some("de fr-CA"), None),
            Some(Locale::German)
        );
    }

    /// **T6.1**, the fallback chain: no match → tenant default → deployment
    /// default (which is `None`, i.e. "forward nothing").
    #[test]
    fn nothing_matched_falls_through_to_the_tenant_then_the_deployment_default() {
        assert_eq!(
            select_ui_locale(Some("zz qq"), Some(Locale::Italian)),
            Some(Locale::Italian)
        );
        assert_eq!(select_ui_locale(Some("zz qq"), None), None);
        assert_eq!(
            select_ui_locale(None, Some(Locale::Spanish)),
            Some(Locale::Spanish)
        );
        assert_eq!(select_ui_locale(None, None), None);
        // A tenant default never overrides a tag that did match.
        assert_eq!(
            select_ui_locale(Some("fr"), Some(Locale::Italian)),
            Some(Locale::French)
        );
    }

    /// **T6.2**, the server half. A hostile `ui_locales` selects nothing, so
    /// there is nothing for a redirect builder to carry — and the only thing
    /// it *could* carry is one of five known tags.
    #[test]
    fn a_hostile_ui_locales_selects_nothing() {
        for hostile in [
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "en\"><script>",
            "javascript:alert(1)",
            "../../etc/passwd",
            "en%20it",
            "",
            "   ",
        ] {
            assert_eq!(
                select_ui_locale(Some(hostile), None),
                None,
                "{hostile:?} must select nothing"
            );
        }
    }

    /// The one shape that *does* contain a valid tag inside something hostile:
    /// splitting on whitespace means `en` is a tag here and is selected. What
    /// matters is that the selection is the *enum value*, so what reaches a URL
    /// is `en` and never the rest of the string.
    #[test]
    fn a_valid_tag_beside_a_hostile_one_selects_only_the_valid_tag() {
        let selected = select_ui_locale(Some("<script> en"), None);
        assert_eq!(selected, Some(Locale::English));
        assert_eq!(selected.unwrap().as_tag(), "en");
    }

    /// Every tag this type can emit is URL-safe and lower-case, which is what
    /// lets the redirect builder write it without a second thought — and what
    /// the sync gate compares against the SPA's catalogue keys.
    #[test]
    fn every_tag_is_a_short_lowercase_ascii_identifier() {
        for locale in ALL_LOCALES {
            let tag = locale.as_tag();
            assert!(
                tag.chars().all(|c| c.is_ascii_lowercase()),
                "{tag:?} must be lower-case ASCII"
            );
            assert_eq!(tag.len(), 2, "{tag:?}");
            assert_eq!(
                Locale::from_tag(tag),
                Some(locale),
                "{tag:?} must round-trip"
            );
            assert!(!locale.endonym().is_empty());
        }
        // The list has no duplicates: a repeated tag would make the sync gate
        // and the SPA's exhaustive record disagree about how many there are.
        let mut tags: Vec<&str> = ALL_LOCALES.iter().map(|l| l.as_tag()).collect();
        tags.sort_unstable();
        let before = tags.len();
        tags.dedup();
        assert_eq!(tags.len(), before, "ALL_LOCALES must not repeat a tag");
    }

    /// English is the deployment default, and "no selection" means it.
    #[test]
    fn the_deployment_default_is_english() {
        assert_eq!(DEPLOYMENT_DEFAULT, Locale::English);
        assert_eq!(DEPLOYMENT_DEFAULT.as_tag(), "en");
        assert!(ALL_LOCALES.contains(&DEPLOYMENT_DEFAULT));
    }

    /// A stored tenant default is parsed with [`Locale::from_tag`] and not
    /// with the lookup: a column holding `fr-CA` names a locale this binary
    /// does not ship, and the honest answer is "no tenant default" rather than
    /// a guess.
    #[test]
    fn a_tenant_default_is_an_exact_tag_and_not_a_lookup() {
        assert_eq!(Locale::from_tag("fr"), Some(Locale::French));
        assert_eq!(Locale::from_tag("fr-CA"), None);
        assert_eq!(Locale::from_tag("klingon"), None);
        assert_eq!(Locale::from_tag(""), None);
    }

    /// **T6.1**, the `display` half: in-list values map, out-of-list values
    /// are dropped, and exactly one of them is compact.
    #[test]
    fn display_is_allow_listed_and_only_popup_is_compact() {
        for (raw, expected) in [
            ("page", Display::Page),
            ("popup", Display::Popup),
            ("touch", Display::Touch),
            ("wap", Display::Wap),
        ] {
            assert_eq!(Display::from_wire(raw), Some(expected));
            assert_eq!(expected.as_str(), raw);
            assert_eq!(expected.is_compact(), expected == Display::Popup);
        }
        for outside in [
            "PAGE",
            "Popup",
            "modal",
            "",
            "  ",
            "page popup",
            "<script>alert(1)</script>",
            "popup;--",
        ] {
            assert_eq!(
                Display::from_wire(outside),
                None,
                "{outside:?} is not one of the four values OIDC Core defines"
            );
        }
    }
}
