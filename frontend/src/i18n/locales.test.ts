import { describe, expect, it } from "vitest";

import {
  DEFAULT_LOCALE,
  DISPLAY_MODES,
  LOCALES,
  layoutClassFor,
  sanitizeDisplay,
  sanitizeLocale,
  sanitizeLoginHint,
} from "./locales";

describe("sanitizeLocale", () => {
  it("accepts every shipped tag, in any case", () => {
    for (const tag of LOCALES) {
      expect(sanitizeLocale(tag)).toBe(tag);
      expect(sanitizeLocale(tag.toUpperCase())).toBe(tag);
      expect(sanitizeLocale(` ${tag} `)).toBe(tag);
    }
  });

  /**
   * Everything else reads as "no selection", which renders the default
   * language. Never an error, and never text on the page — the value arrives
   * in a URL anybody can write.
   */
  it("reads anything else as no selection", () => {
    for (const outside of [
      null,
      undefined,
      "",
      "   ",
      "zz",
      "klingon",
      // The server does the RFC 4647 lookup and forwards a complete tag, so a
      // subtag arriving here did not come from that lookup.
      "fr-CA",
      "en-GB",
      "<script>alert(1)</script>",
      "en it",
      "en,it",
    ]) {
      expect(sanitizeLocale(outside)).toBeNull();
    }
  });

  it("has English as the default", () => {
    expect(DEFAULT_LOCALE).toBe("en");
    expect(LOCALES).toContain(DEFAULT_LOCALE);
  });

  /** Mirrors `axiam_oauth2::locale::ALL_LOCALES`; the sync gate enforces it. */
  it("ships exactly five locales, with no duplicates", () => {
    expect(LOCALES).toEqual(["en", "it", "fr", "de", "es"]);
    expect(new Set(LOCALES).size).toBe(LOCALES.length);
  });
});

describe("sanitizeDisplay", () => {
  it("accepts the four values OIDC Core defines and nothing else", () => {
    for (const mode of DISPLAY_MODES) {
      expect(sanitizeDisplay(mode)).toBe(mode);
    }
    for (const outside of [
      null,
      undefined,
      "",
      "PAGE",
      "Popup",
      "modal",
      "page popup",
      "<script>",
    ]) {
      expect(sanitizeDisplay(outside)).toBeNull();
    }
  });

  /**
   * The plan's whole mapping. `""` for everything else matters: it is what
   * makes an `ignore`-lane page render the markup it rendered before W5.
   */
  it("maps only popup to the compact layout", () => {
    expect(layoutClassFor("popup")).not.toBe("");
    for (const other of ["page", "touch", "wap"] as const) {
      expect(layoutClassFor(other)).toBe("");
    }
    expect(layoutClassFor(null)).toBe("");
  });

  it("never returns the parameter's own value as a class", () => {
    for (const mode of DISPLAY_MODES) {
      expect(layoutClassFor(mode)).not.toContain(mode);
    }
  });
});

describe("sanitizeLoginHint", () => {
  it("passes an ordinary identifier through untouched", () => {
    expect(sanitizeLoginHint("ada@example.com")).toBe("ada@example.com");
    expect(sanitizeLoginHint("  ada  ")).toBe("ada");
    // Non-ASCII is a legitimate identifier, not something to strip.
    expect(sanitizeLoginHint("日本語@example.com")).toBe(
      "日本語@example.com",
    );
  });

  it("treats blank and missing alike", () => {
    for (const blank of [null, undefined, "", "   ", "\t"]) {
      expect(sanitizeLoginHint(blank)).toBeNull();
    }
  });

  /** Dropped rather than cut: a truncated identifier is a wrong identifier. */
  it("drops an over-long hint rather than truncating it", () => {
    expect(sanitizeLoginHint("x".repeat(256))).toHaveLength(256);
    expect(sanitizeLoginHint("x".repeat(257))).toBeNull();
    // Bounded in *bytes*, like the server's parser.
    expect(sanitizeLoginHint("é".repeat(129))).toBeNull();
  });

  it("refuses control characters", () => {
    expect(sanitizeLoginHint("a\u0000b")).toBeNull();
    expect(sanitizeLoginHint("a\nb")).toBeNull();
    expect(sanitizeLoginHint("a\rb")).toBeNull();
    expect(sanitizeLoginHint("a\u007fb")).toBeNull();
  });

  /**
   * It does **not** escape. The value is rendered as an input's `value` and
   * React escapes it; a sanitiser that stripped `<` here would mangle a
   * legitimate hint and would be where the next reader stopped looking for
   * the escaping that actually matters.
   */
  it("does not escape, because escaping is not its job", () => {
    expect(sanitizeLoginHint("<script>alert(1)</script>")).toBe(
      "<script>alert(1)</script>",
    );
  });
});
