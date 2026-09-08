/**
 * **W7 — the OpenID Connect consent screen** (`claude_dev/basic-op-gap-plan.md`
 * §4.8, the SPA half of T8.2).
 *
 * What this file asserts is the ceremony, not the release: whether a claim
 * actually reaches a relying party is decided four gates later, at UserInfo,
 * and is tested against a real server in
 * `crates/axiam-api-rest/tests/oauth2_sensitive_scopes_test.rs`. Here the
 * questions are narrower and all of them are about the person in front of the
 * page — is she told which relying party is asking, in her own language, what
 * it wants, and can she say no.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { apiMock } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { ConsentPage } from "./ConsentPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { LOCALES, MESSAGES, type Locale } from "@/i18n";

const RETURN_TO =
  "/oauth2/authorize?response_type=code&client_id=oa_shop&scope=openid+address+phone";

/** Where the page navigates. `window.location.assign` is stubbed per test. */
let assigned: string[] = [];

beforeEach(() => {
  vi.clearAllMocks();
  assigned = [];
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { assign: (url: string) => assigned.push(url) },
  });
  document.documentElement.removeAttribute("lang");
});

afterEach(() => {
  document.documentElement.removeAttribute("lang");
});

function renderConsent(query = `?return_to=${encodeURIComponent(RETURN_TO)}`) {
  return renderWithProviders(<ConsentPage />, { route: `/consent${query}` });
}

describe("the consent question", () => {
  /**
   * The relying party is named. Consent under Art. 4(11) is "specific" and
   * "informed", and a page that asked "share your details?" without saying
   * with whom would be neither.
   */
  it("names the relying party and both categories of data", () => {
    renderConsent();
    const m = MESSAGES.en;
    expect(
      screen.getByRole("heading", { name: m.consentHeading }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(m.consentIntro.replace("{client}", "oa_shop")),
    ).toBeInTheDocument();
    expect(screen.getByText(m.consentAddress)).toBeInTheDocument();
    expect(screen.getByText(m.consentPhone)).toBeInTheDocument();
  });

  /**
   * Only what was asked for is shown. A page listing both categories when the
   * request named one would be asking for consent to something nobody
   * requested, and recording it.
   */
  it("shows only the scopes the request asked for", () => {
    renderConsent(
      `?return_to=${encodeURIComponent(
        "/oauth2/authorize?client_id=oa_shop&scope=openid+phone",
      )}`,
    );
    expect(screen.getByText(MESSAGES.en.consentPhone)).toBeInTheDocument();
    expect(screen.queryByText(MESSAGES.en.consentAddress)).toBeNull();
  });

  /** Art. 7(3) has to be visible at the moment of consent, not only after. */
  it("says the consent can be withdrawn", () => {
    renderConsent();
    expect(
      screen.getByText(MESSAGES.en.consentWithdrawNote),
    ).toBeInTheDocument();
  });

  /**
   * The page renders in every shipped language, from the same catalogue the
   * sign-in page uses — a consent screen a person cannot read is not informed
   * consent.
   */
  it.each(LOCALES)("renders in %s", (locale: Locale) => {
    renderConsent(
      `?ui_locale=${locale}&return_to=${encodeURIComponent(RETURN_TO)}`,
    );
    const m = MESSAGES[locale];
    expect(
      screen.getByRole("heading", { name: m.consentHeading }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: m.consentAllowAction }),
    ).toBeInTheDocument();
    expect(document.documentElement.lang).toBe(locale);
  });
});

describe("answering", () => {
  /** Allow records the consent, then resumes the authorization request. */
  it("records the consent and returns to the authorization request", async () => {
    apiMock.post.mockResolvedValueOnce({ data: { consent_type: "x", version: "y" } });
    renderConsent();

    await userEvent.click(
      screen.getByRole("button", { name: MESSAGES.en.consentAllowAction }),
    );

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/account/consents/oidc-scopes",
        { client_id: "oa_shop", scopes: ["address", "phone"] },
      ),
    );
    await waitFor(() => expect(assigned).toEqual([RETURN_TO]));
  });

  /**
   * Declining is not a dead end and needs no knowledge of redirect URIs: the
   * browser goes back to the same authorization request, and the server's
   * return-leg rule turns "asked once, still no consent" into `access_denied`
   * for the relying party. So this button records nothing and navigates.
   */
  it("declining records nothing and still returns to the request", async () => {
    renderConsent();

    await userEvent.click(
      screen.getByRole("button", { name: MESSAGES.en.consentDenyAction }),
    );

    expect(apiMock.post).not.toHaveBeenCalled();
    expect(assigned).toEqual([RETURN_TO]);
  });

  /**
   * A failure to record must **not** resume. Returning now would produce
   * `access_denied` — the answer for somebody who declined — and this person
   * did not decline.
   */
  it("does not resume when the consent could not be recorded", async () => {
    apiMock.post.mockRejectedValueOnce(new Error("nope"));
    renderConsent();

    await userEvent.click(
      screen.getByRole("button", { name: MESSAGES.en.consentAllowAction }),
    );

    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        MESSAGES.en.consentFailed,
      ),
    );
    expect(assigned).toEqual([]);
  });
});

describe("nothing to decide", () => {
  /**
   * An off-origin `return_to` never becomes a consent question. Otherwise the
   * page would render an attacker's `client_id` beside this deployment's own
   * branding, and offer a button that navigates off-site.
   */
  it.each([
    ["no return_to", ""],
    [
      "an off-origin return_to",
      `?return_to=${encodeURIComponent("https://evil.example/oauth2/authorize?client_id=x&scope=phone")}`,
    ],
    [
      "a request asking for nothing sensitive",
      `?return_to=${encodeURIComponent("/oauth2/authorize?client_id=oa_shop&scope=openid")}`,
    ],
  ])("says so for %s", (_name, query) => {
    renderConsent(query);
    expect(screen.getByText(MESSAGES.en.consentNothingToDo)).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: MESSAGES.en.consentAllowAction }),
    ).toBeNull();
  });
});
