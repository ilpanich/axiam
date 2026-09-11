import { describe, it, expect, vi } from "vitest";
import { useState } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { TokenExchangeTrustEditor } from "./TokenExchangeTrustEditor";
import {
  parseAudiences,
  parseScopeMap,
  stringifyAudiences,
  stringifyScopeMap,
} from "./tokenExchangeTrustFormat";
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

// ─── The editor itself ────────────────────────────────────────────────────────
//
// The parsers above are the easy half. The component is where a trust boundary
// is actually switched on, and its two textareas do something unusual: they
// keep raw text in the parent while *also* pushing a parsed value into the
// trust block on every keystroke — but only when the parse succeeds, so a
// half-typed scope map cannot blank out a saved one. That asymmetry is the
// thing worth pinning down.

describe("TokenExchangeTrustEditor", () => {
  /** A controlled host, so each assertion sees what a real parent would. */
  function Harness({
    initial = DEFAULT_TOKEN_EXCHANGE_TRUST,
    isOidc = true,
    onTrust,
  }: {
    initial?: TokenExchangeTrust;
    isOidc?: boolean;
    onTrust?: (t: TokenExchangeTrust) => void;
  }) {
    const [value, setValue] = useState<TokenExchangeTrust>(initial);
    const [audiencesText, setAudiencesText] = useState(
      stringifyAudiences(initial.accepted_audiences),
    );
    const [scopeMapText, setScopeMapText] = useState(
      stringifyScopeMap(initial.scope_map),
    );
    return (
      <TokenExchangeTrustEditor
        value={value}
        onChange={(next) => {
          setValue(next);
          onTrust?.(next);
        }}
        audiencesText={audiencesText}
        onAudiencesTextChange={setAudiencesText}
        scopeMapText={scopeMapText}
        onScopeMapTextChange={setScopeMapText}
        isOidc={isOidc}
        idPrefix="tx"
      />
    );
  }

  it("explains itself away on a non-OIDC provider instead of offering controls", () => {
    render(<Harness isOidc={false} />);
    expect(
      screen.getByText(/Available for OIDC providers only/),
    ).toBeInTheDocument();
    expect(
      screen.queryByLabelText("Accepted audiences (one per line)"),
    ).not.toBeInTheDocument();
  });

  it("turns the trust on without touching anything else", async () => {
    const onTrust = vi.fn();
    render(<Harness onTrust={onTrust} />);

    await userEvent.click(
      screen.getByLabelText("Accept this provider's tokens for exchange"),
    );

    expect(onTrust).toHaveBeenLastCalledWith({
      ...DEFAULT_TOKEN_EXCHANGE_TRUST,
      enabled: true,
    });
  });

  it("parses each typed audience into the trust block", async () => {
    const onTrust = vi.fn();
    render(<Harness onTrust={onTrust} />);

    await userEvent.type(
      screen.getByLabelText("Accepted audiences (one per line)"),
      "https://api.example.com",
    );

    expect(onTrust).toHaveBeenLastCalledWith(
      expect.objectContaining({
        accepted_audiences: ["https://api.example.com"],
      }),
    );
  });

  it("keeps the last good scope map while a new line is still half-typed", async () => {
    // The textarea's own text is the source of truth for what the operator
    // sees; the parsed map only advances on a line that parses. A keystroke
    // mid-word must not push an empty map into the trust block and quietly
    // widen what the partner is granted.
    const onTrust = vi.fn();
    render(
      <Harness
        initial={{
          ...DEFAULT_TOKEN_EXCHANGE_TRUST,
          enabled: true,
          accepted_audiences: ["https://api.example.com"],
          scope_map: { "partner.orders.read": ["read:orders"] },
        }}
        onTrust={onTrust}
      />,
    );

    const scopeMap = screen.getByLabelText("Scope map");
    expect(scopeMap).toHaveValue("partner.orders.read = read:orders");
    // "\npartner.admin" is not yet a mapping — no equals sign.
    await userEvent.type(scopeMap, "{Enter}partner.admin");

    expect(scopeMap).toHaveValue(
      "partner.orders.read = read:orders\npartner.admin",
    );
    expect(onTrust).toHaveBeenLastCalledWith(
      expect.objectContaining({
        scope_map: { "partner.orders.read": ["read:orders"] },
      }),
    );

    // Completing the line lands it.
    await userEvent.type(scopeMap, " = admin:all");
    expect(onTrust).toHaveBeenLastCalledWith(
      expect.objectContaining({
        scope_map: {
          "partner.orders.read": ["read:orders"],
          "partner.admin": ["admin:all"],
        },
      }),
    );
  });

  it("switches unknown subjects to just-in-time provisioning", async () => {
    const onTrust = vi.fn();
    render(<Harness onTrust={onTrust} />);

    await userEvent.selectOptions(
      screen.getByLabelText("Unknown subjects"),
      "jit_provision",
    );

    expect(onTrust).toHaveBeenLastCalledWith(
      expect.objectContaining({ subject_mapping: "jit_provision" }),
    );
  });

  it("falls back to the default max token age rather than storing zero", async () => {
    // An empty or zeroed box would otherwise mean "accept a token of any age",
    // which is the opposite of what clearing a ceiling should do.
    const onTrust = vi.fn();
    render(<Harness onTrust={onTrust} />);

    const maxAge = screen.getByLabelText("Max token age (seconds)");
    await userEvent.clear(maxAge);

    expect(onTrust).toHaveBeenLastCalledWith(
      expect.objectContaining({
        max_token_age_secs: DEFAULT_TOKEN_EXCHANGE_TRUST.max_token_age_secs,
      }),
    );

    // And the box snaps back to that default rather than staying empty, so a
    // real value has to replace it in one edit rather than be appended to it.
    expect(maxAge).toHaveValue(
      DEFAULT_TOKEN_EXCHANGE_TRUST.max_token_age_secs,
    );
    fireEvent.change(maxAge, { target: { value: "120" } });
    expect(onTrust).toHaveBeenLastCalledWith(
      expect.objectContaining({ max_token_age_secs: 120 }),
    );
  });

  it("treats a blank issued-lifetime as no extra ceiling, not as zero", async () => {
    const onTrust = vi.fn();
    render(
      <Harness
        initial={{ ...DEFAULT_TOKEN_EXCHANGE_TRUST, max_lifetime_secs: 900 }}
        onTrust={onTrust}
      />,
    );

    const maxLifetime = screen.getByLabelText(
      "Max issued lifetime (seconds, optional)",
    );
    expect(maxLifetime).toHaveValue(900);
    await userEvent.clear(maxLifetime);

    expect(onTrust).toHaveBeenLastCalledWith(
      expect.objectContaining({ max_lifetime_secs: null }),
    );

    await userEvent.type(maxLifetime, "600");
    expect(onTrust).toHaveBeenLastCalledWith(
      expect.objectContaining({ max_lifetime_secs: 600 }),
    );
  });
});
