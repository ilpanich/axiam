/**
 * The SPA's internationalisation layer (W5,
 * `claude_dev/basic-op-gap-plan.md` §4.6).
 *
 * Three files and no dependency: {@link ./locales} holds the allow-lists,
 * {@link ./messages} holds the typed catalogue, and this one holds the two
 * hooks a page uses. See `./messages` for why the catalogue is hand-rolled and
 * why the admin console is deliberately out of scope.
 */

export {
  DEFAULT_LOCALE,
  DISPLAY_MODES,
  LOCALES,
  type DisplayMode,
  type Locale,
  layoutClassFor,
  sanitizeDisplay,
  sanitizeLocale,
  sanitizeLoginHint,
} from "./locales";
export {
  MESSAGES,
  type Bundle,
  type MessageKey,
  format,
  messagesFor,
} from "./messages";

import { useEffect, useMemo } from "react";

import { DEFAULT_LOCALE, type Locale, sanitizeLocale } from "./locales";
import { type Bundle, messagesFor } from "./messages";

/**
 * The locale a page was asked to render in, from a raw `?ui_locale=` value.
 *
 * The server has already matched the relying party's `ui_locales` list against
 * its own allow-list and forwarded one validated tag, so this is a second
 * check rather than the only one — {@link sanitizeLocale} says why it is still
 * worth making. Anything that does not name a shipped locale reads as
 * {@link DEFAULT_LOCALE}, which is also what an absent parameter means and
 * therefore what every client on the `ignore` lane gets.
 */
export function resolveLocale(raw: string | null | undefined): Locale {
  return sanitizeLocale(raw) ?? DEFAULT_LOCALE;
}

/**
 * The message bundle for `locale`, and the `<html lang>` that goes with it.
 *
 * Setting `lang` is the accessibility half of this feature and it is not
 * decoration: a screen reader chooses its pronunciation rules from it, so a
 * page rendered in German while claiming to be English is read aloud as
 * mispronounced English. It is restored on unmount because the admin console
 * this page navigates into is not translated, and leaving `lang="de"` on an
 * English console would be the same lie in the other direction.
 *
 * All five locales are left-to-right, so nothing here touches `dir`. Adding an
 * RTL language is the change that should add `dir` handling, together with the
 * layout work and the tests that make it real — writing untested RTL support
 * now would only make a future reviewer believe it had been thought about.
 */
export function useMessages(locale: Locale): Bundle {
  useEffect(() => {
    const root = document.documentElement;
    const previous = root.getAttribute("lang");
    root.setAttribute("lang", locale);
    return () => {
      if (previous === null) root.removeAttribute("lang");
      else root.setAttribute("lang", previous);
    };
  }, [locale]);

  // The bundle is a module-level constant, so this memo is about identity
  // rather than cost: a stable object keeps it out of the dependency arrays of
  // whatever effects a page hangs off its messages.
  return useMemo(() => messagesFor(locale), [locale]);
}
