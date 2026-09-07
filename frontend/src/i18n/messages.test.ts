import { describe, expect, it } from "vitest";

import { LOCALES, type Locale } from "./locales";
import { MESSAGES, TRANSLATED_LOCALES, format } from "./messages";

const KEYS = Object.keys(MESSAGES.en).sort();

describe("the catalogue", () => {
  /**
   * Belt-and-braces beside the compile-time guarantee.
   *
   * `Bundle = Record<MessageKey, string>` already makes a missing Italian
   * string a build failure, and that is the guarantee that matters. This test
   * earns its place by surviving the one thing the type system cannot: an
   * `as any`, an `as Bundle`, or a future refactor that widens `MessageKey` to
   * `string` — each of which switches the compile-time check off silently.
   */
  it("has every key in every locale, and no extras", () => {
    for (const locale of LOCALES) {
      expect(Object.keys(MESSAGES[locale]).sort(), `locale ${locale}`).toEqual(
        KEYS,
      );
    }
  });

  it("covers exactly the locales the allow-list ships", () => {
    expect([...TRANSLATED_LOCALES].sort()).toEqual([...LOCALES].sort());
  });

  /**
   * A blank or whitespace-only translation renders as a gap in the page, which
   * is the failure mode a runtime fallback would have hidden and this layer
   * deliberately does not have.
   */
  it("has no empty or whitespace-only string anywhere", () => {
    for (const locale of LOCALES) {
      for (const [key, value] of Object.entries(MESSAGES[locale])) {
        expect(value.trim(), `${locale}.${key}`).not.toBe("");
      }
    }
  });

  /**
   * The commonest way a translation goes subtly wrong: the English is copied
   * into the other bundle as a placeholder and nobody notices, because it
   * *renders*. Checked only for the messages long enough for a coincidence to
   * be implausible — short UI words legitimately coincide across languages
   * (`Password` in German, `or` in Spanish), so a blanket rule would be a rule
   * everybody learns to add exceptions to.
   */
  it("has no untranslated long string outside English", () => {
    const untranslated: string[] = [];
    for (const locale of LOCALES.filter((l) => l !== "en")) {
      for (const key of KEYS as (keyof typeof MESSAGES.en)[]) {
        const english = MESSAGES.en[key];
        if (english.length >= 25 && MESSAGES[locale as Locale][key] === english) {
          untranslated.push(`${locale}.${key}`);
        }
      }
    }
    expect(untranslated).toEqual([]);
  });

  /**
   * A placeholder that exists in one language and not another is a message
   * that renders with a name missing from it.
   */
  it("uses the same placeholders in every language", () => {
    const placeholders = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort();
    for (const key of KEYS as (keyof typeof MESSAGES.en)[]) {
      const expected = placeholders(MESSAGES.en[key]);
      for (const locale of LOCALES) {
        expect(placeholders(MESSAGES[locale][key]), `${locale}.${key}`).toEqual(
          expected,
        );
      }
    }
  });

  /**
   * **Invariant 4.** Every client on the `ignore` lane renders the English
   * bundle, so these strings must be the ones the page rendered before W5 —
   * three-period ellipses and all. Spot-checked on the strings a well-meaning
   * edit would most likely "improve".
   */
  it("keeps the English copy exactly as it was before this wave", () => {
    expect(MESSAGES.en.signingIn).toBe("Signing in...");
    expect(MESSAGES.en.verifying).toBe("Verifying...");
    expect(MESSAGES.en.waitingForDevice).toBe("Waiting for your device…");
    expect(MESSAGES.en.signInHeading).toBe("Sign in");
    expect(MESSAGES.en.signInAction).toBe("Sign in");
    expect(MESSAGES.en.usernameLabel).toBe("Username or email");
    expect(MESSAGES.en.mfaHeading).toBe("Two-factor authentication");
    expect(MESSAGES.en.bootstrapNotice).toBe(
      "Admin account created. Sign in to continue.",
    );
    expect(MESSAGES.en.webauthnUnknown).toBe(
      "Something went wrong setting up this device. Please try again.",
    );
  });
});

describe("format", () => {
  it("substitutes named placeholders", () => {
    expect(format("Could not start sign-in with {provider}.", {
      provider: "Okta",
    })).toBe("Could not start sign-in with Okta.");
  });

  /** A visible bug report beats a message reading "undefined". */
  it("leaves a placeholder with no value alone", () => {
    expect(format("hello {name}", {})).toBe("hello {name}");
  });

  /** It does no escaping: React escapes the text node this ends up in. */
  it("substitutes the value verbatim", () => {
    expect(format("{x}", { x: "<script>" })).toBe("<script>");
  });

  it("ignores inherited properties", () => {
    expect(format("{toString}", {})).toBe("{toString}");
  });
});
