import { describe, expect, it } from "vitest";

import { parseConsentRequest, SENSITIVE_SCOPES } from "@/lib/consentRequest";

const authorize = (query: string) => `/oauth2/authorize?${query}`;

describe("parseConsentRequest", () => {
  it("reads the client and the sensitive scopes out of the return_to", () => {
    const parsed = parseConsentRequest(
      authorize(
        "response_type=code&client_id=oa_shop&scope=openid+profile+address+phone",
      ),
    );
    expect(parsed).toEqual({
      clientId: "oa_shop",
      scopes: ["address", "phone"],
    });
  });

  /**
   * Canonical order, not request order. The server names its consent record by
   * the canonical ordering (`axiam_oauth2::sensitive::consent_version`), so a
   * page that posted the relying party's order would record a version the
   * release gate never matches — and the user would consent to something that
   * then released nothing.
   */
  it("returns the canonical order however the relying party sent it", () => {
    const reversed = parseConsentRequest(
      authorize("client_id=oa_shop&scope=phone+address"),
    );
    expect(reversed?.scopes).toEqual([...SENSITIVE_SCOPES]);
  });

  it("keeps only the sensitive scopes", () => {
    expect(
      parseConsentRequest(authorize("client_id=oa_shop&scope=openid+phone"))
        ?.scopes,
    ).toEqual(["phone"]);
  });

  /**
   * The three "nothing to decide" cases, which the page answers identically.
   * A form with no subject is worse than a sentence saying there is none.
   */
  it("returns null when there is nothing to decide", () => {
    expect(
      parseConsentRequest(authorize("client_id=oa_shop&scope=openid+profile")),
    ).toBeNull();
    expect(parseConsentRequest(authorize("scope=address"))).toBeNull();
    expect(parseConsentRequest(null)).toBeNull();
  });

  /**
   * The value is a `return_to` first and a consent request second: everything
   * `sanitizeReturnTo` refuses is refused here too, so an off-origin or
   * off-path URL cannot reach the page as a consent question — which is what
   * stops the page rendering somebody else's `client_id` beside AXIAM's own
   * branding.
   */
  it("refuses anything sanitizeReturnTo refuses", () => {
    expect(
      parseConsentRequest("https://evil.example/oauth2/authorize?client_id=x&scope=phone"),
    ).toBeNull();
    expect(
      parseConsentRequest("//evil.example/oauth2/authorize?client_id=x&scope=phone"),
    ).toBeNull();
    expect(
      parseConsentRequest("/other/path?client_id=x&scope=phone"),
    ).toBeNull();
    expect(parseConsentRequest("/oauth2/authorize")).toBeNull();
  });

  /**
   * A scope that merely contains a sensitive name is not one — the split is on
   * whitespace and the comparison is on whole tokens, matching
   * `axiam_oauth2::sensitive::requested`.
   */
  it("does not match a scope that only looks sensitive", () => {
    expect(
      parseConsentRequest(
        authorize("client_id=oa_shop&scope=openid+phonebook%3Aread"),
      ),
    ).toBeNull();
  });

  /** Duplicates collapse, so the consented version has one name. */
  it("collapses a repeated scope", () => {
    expect(
      parseConsentRequest(authorize("client_id=oa_shop&scope=phone+phone"))
        ?.scopes,
    ).toEqual(["phone"]);
  });
});
