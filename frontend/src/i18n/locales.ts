/**
 * The languages the sign-in surface is translated into, and the two
 * allow-lists that decide what a URL is allowed to say about presentation
 * (W5, `claude_dev/basic-op-gap-plan.md` §4.6).
 *
 * # These lists are mirrors, and a script says so
 *
 * The authoritative allow-list is `axiam_oauth2::locale::Locale` on the
 * server: `/oauth2/authorize` matches the relying party's `ui_locales` against
 * it and forwards the *selected* tag, so a value this file has never heard of
 * cannot arrive here in the first place. This copy exists because the page has
 * to index a catalogue with it, not because the page is trusted to police it.
 *
 * Two mirrors of one list drift. `scripts/check-locale-bundle-sync.py` fails
 * the build when {@link LOCALES} and the Rust enum disagree in either
 * direction, which is the direction that matters: a tag the server can select
 * and this bundle cannot render would deliver an untranslated page, and a
 * language translated here that the server will never select is dead weight
 * nobody notices is dead.
 *
 * # Why the page still sanitises what it is given
 *
 * `?ui_locale=` is in a URL, and anyone can hand a victim a `/login` URL of
 * their own. The server's match is what keeps a relying party from choosing
 * the string; {@link sanitizeLocale} is what keeps *anybody* from choosing it,
 * and it is the same argument `sanitizeReturnTo` and `sanitizeRequiredAcr`
 * make for their own values. Everything outside the list reads as "no
 * selection", which renders the default language — never as an error, and
 * never as text on the page.
 */

/**
 * Every locale, in the order the documentation lists them.
 *
 * Must equal `axiam_oauth2::locale::ALL_LOCALES`, tag for tag; the sync gate
 * parses this array literal.
 */
export const LOCALES = ["en", "it", "fr", "de", "es"] as const;

/** A language the sign-in surface is fully translated into. */
export type Locale = (typeof LOCALES)[number];

/**
 * What renders when nothing selects a language.
 *
 * Mirrors `axiam_oauth2::locale::DEPLOYMENT_DEFAULT`. The server forwards no
 * `ui_locale` at all when its selection is "nothing", so this is also what
 * every client on the `ignore` lane gets — which is invariant 4 for this
 * wave: a page in English, with no locale parameter and no layout class,
 * exactly as before W5.
 */
export const DEFAULT_LOCALE: Locale = "en";

/**
 * The locale named by `?ui_locale=`, or `null`.
 *
 * `null` for an absent value, an unknown one, and a well-formed tag this build
 * does not ship — all three mean the same thing to a caller: render the
 * default language.
 *
 * Case-insensitive because BCP 47 tags are (RFC 5646 §2.1.1). No subtag
 * truncation: the server already did the RFC 4647 lookup and forwards a
 * complete tag from its own list, so a `fr-CA` arriving here did not come
 * from that lookup and should not be guessed at.
 */
export function sanitizeLocale(raw: string | null | undefined): Locale | null {
  if (typeof raw !== "string") return null;
  const tag = raw.trim().toLowerCase();
  return (LOCALES as readonly string[]).includes(tag) ? (tag as Locale) : null;
}

/**
 * The `display` values OIDC Core §3.1.2.1 defines.
 *
 * Mirrors `axiam_oauth2::locale::Display` for the same reason {@link LOCALES}
 * mirrors its enum. Unlike the locales this list needs no sync gate: it is
 * fixed by the specification rather than by how much translating anybody has
 * done, and a fifth value would be a specification change rather than a
 * project decision.
 */
export const DISPLAY_MODES = ["page", "popup", "touch", "wap"] as const;

/** A layout hint the relying party asked for. */
export type DisplayMode = (typeof DISPLAY_MODES)[number];

/**
 * The `login_hint` this page was handed, or `null`.
 *
 * The one presentation value with no closed set — it is whatever identifier
 * the relying party believes the end user types — so the checks here are
 * bounds rather than an allow-list, and they mirror the server's parser
 * (`axiam_oauth2::authn_params`) rather than inventing a second policy:
 *
 * * blank is absent, not a request to pre-fill an empty field;
 * * a value longer than 256 bytes is **dropped, not truncated** — a truncated
 *   identifier is a *wrong* identifier, and quietly substituting one is worse
 *   than having none;
 * * control characters are refused, because a value carrying one did not come
 *   from the server's builder, which percent-encodes them.
 *
 * What is deliberately *not* here is any escaping. The value is rendered as an
 * `<input>`'s `value` and nothing else, so React escapes it; a sanitiser that
 * also stripped `<` would make the field silently mangle a legitimate hint and
 * would suggest the escaping happens here, which is where the next person
 * would then stop looking.
 */
export function sanitizeLoginHint(raw: string | null | undefined): string | null {
  if (typeof raw !== "string") return null;
  const hint = raw.trim();
  if (hint === "") return null;
  if (new TextEncoder().encode(hint).length > 256) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(hint)) return null;
  return hint;
}

/**
 * The layout named by `?display=`, or `null`.
 *
 * Exact and case-sensitive, matching the server's `Display::from_wire`: OIDC
 * Core defines the four spellings in lower case and nothing else is one of
 * them.
 */
export function sanitizeDisplay(
  raw: string | null | undefined,
): DisplayMode | null {
  if (typeof raw !== "string") return null;
  return (DISPLAY_MODES as readonly string[]).includes(raw.trim())
    ? (raw.trim() as DisplayMode)
    : null;
}

/**
 * The class the sign-in card is rendered with.
 *
 * The plan's whole mapping: `popup` is compact, everything else — including
 * "nothing was asked for" — is the default. It returns a **class name from
 * this function**, never the parameter's value, so no relying-party string
 * reaches a `className` even if the allow-list above were ever widened.
 *
 * `""` rather than a "default" class so that a page which asked for nothing
 * renders markup byte-identical to the page before W5 existed.
 */
export function layoutClassFor(display: DisplayMode | null): string {
  return display === "popup" ? "mx-auto max-w-sm text-sm" : "";
}
