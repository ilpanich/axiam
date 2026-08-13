import { describe, it, expect } from "vitest";
import {
  parseAudiences,
  parseScopeMap,
  stringifyAudiences,
  stringifyScopeMap,
} from "./TokenExchangeTrustEditor";
import {
  DEFAULT_TOKEN_EXCHANGE_TRUST,
  validateTokenExchangeTrust,
  type TokenExchangeTrust,
} from "@/services/federation";

describe("parseAudiences", () => {
  it("takes one audience per line and drops blanks", () => {
    expect(parseAudiences("https://a.example\n\n  https://b.example  \n")).toEqual([
      "https://a.example",
      "https://b.example",
    ]);
  });

  it("round-trips through stringifyAudiences", () => {
    const audiences = ["https://a.example", "https://b.example"];
    expect(parseAudiences(stringifyAudiences(audiences))).toEqual(audiences);
  });

  it("yields nothing for an empty box, which the validator then refuses", () => {
    expect(parseAudiences("   \n\n")).toEqual([]);
  });
});

describe("parseScopeMap", () => {
  it("reads one mapping per line", () => {
    const result = parseScopeMap(
      "partner.orders.read = read:orders\nOrders.ReadWrite.All = read:orders write:orders",
    );
    expect(result).toEqual({
      value: {
        "partner.orders.read": ["read:orders"],
        "Orders.ReadWrite.All": ["read:orders", "write:orders"],
      },
    });
  });

  it("accepts commas as well as spaces between scopes", () => {
    expect(parseScopeMap("a = x, y")).toEqual({ value: { a: ["x", "y"] } });
  });

  it("ignores blank lines and comments", () => {
    expect(parseScopeMap("# a comment\n\na = x\n")).toEqual({
      value: { a: ["x"] },
    });
  });

  it("names the line when a mapping has no equals sign", () => {
    const result = parseScopeMap("a = x\nthis is not a mapping");
    expect(result).toHaveProperty("error");
    expect((result as { error: string }).error).toContain("Line 2");
  });

  /**
   * An empty mapping is refused rather than accepted-as-nothing: it reads, to
   * the next person, as if it grants something.
   */
  it("refuses a key that maps to no scopes", () => {
    const result = parseScopeMap("partner.admin =");
    expect(result).toHaveProperty("error");
    expect((result as { error: string }).error).toContain("partner.admin");
  });

  it("refuses a blank key", () => {
    expect(parseScopeMap(" = read:orders")).toHaveProperty("error");
  });

  /**
   * Never a partial map: a half-parsed trust configuration submitted by
   * accident is the failure this form exists to avoid.
   */
  it("returns no map at all when any line is bad", () => {
    const result = parseScopeMap("good = x\nbad line\nalso.good = y");
    expect(result).not.toHaveProperty("value");
  });

  it("round-trips through stringifyScopeMap", () => {
    const map = { "partner.orders.read": ["read:orders", "write:orders"] };
    expect(parseScopeMap(stringifyScopeMap(map))).toEqual({ value: map });
  });
});

describe("validateTokenExchangeTrust", () => {
  const enabled = (over: Partial<TokenExchangeTrust> = {}): TokenExchangeTrust => ({
    ...DEFAULT_TOKEN_EXCHANGE_TRUST,
    enabled: true,
    accepted_audiences: ["https://api.example.com"],
    ...over,
  });

  it("accepts the server default", () => {
    expect(validateTokenExchangeTrust(DEFAULT_TOKEN_EXCHANGE_TRUST)).toBeNull();
  });

  it("refuses enabling with no accepted audience", () => {
    const msg = validateTokenExchangeTrust(enabled({ accepted_audiences: [] }));
    expect(msg).toContain("accept-all");
  });

  it("allows a disabled block with no audiences — that is the default", () => {
    expect(
      validateTokenExchangeTrust({
        ...DEFAULT_TOKEN_EXCHANGE_TRUST,
        enabled: false,
      }),
    ).toBeNull();
  });

  it("bounds the token age at both ends", () => {
    expect(validateTokenExchangeTrust(enabled({ max_token_age_secs: 0 }))).not.toBeNull();
    expect(
      validateTokenExchangeTrust(enabled({ max_token_age_secs: 3601 })),
    ).not.toBeNull();
    expect(validateTokenExchangeTrust(enabled({ max_token_age_secs: 3600 }))).toBeNull();
  });

  it("refuses a non-positive issued lifetime but allows it unset", () => {
    expect(validateTokenExchangeTrust(enabled({ max_lifetime_secs: 0 }))).not.toBeNull();
    expect(validateTokenExchangeTrust(enabled({ max_lifetime_secs: null }))).toBeNull();
  });

  it("refuses a scope-map entry that grants nothing", () => {
    const msg = validateTokenExchangeTrust(
      enabled({ scope_map: { "partner.admin": [] } }),
    );
    expect(msg).toContain("partner.admin");
  });

  it("refuses a blank audience entry", () => {
    expect(
      validateTokenExchangeTrust(
        enabled({ accepted_audiences: ["https://api.example.com", "  "] }),
      ),
    ).not.toBeNull();
  });
});
