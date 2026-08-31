import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import {
  HANDOFF_QUERY_PARAM,
  SSO_CALLBACK_PATH,
  rememberPendingSso,
  ssoCallbackUrl,
  ssoLoginService,
  submitSamlAuthnRequest,
  takePendingSso,
} from "./ssoLogin";

beforeEach(() => {
  vi.clearAllMocks();
  sessionStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("ssoCallbackUrl", () => {
  /**
   * It has to match what is registered at the provider byte for byte — the
   * server passes it straight through and echoes it at the token exchange —
   * which is why it is built from one constant and the live origin rather than
   * configured in two places that can drift.
   */
  it("is the current origin plus the one callback path", () => {
    expect(ssoCallbackUrl()).toBe(
      `${window.location.origin}${SSO_CALLBACK_PATH}`,
    );
  });
});

describe("the pending record", () => {
  it("round-trips and is consumed by reading it", () => {
    rememberPendingSso({ protocol: "OAuth2", displayName: "GitHub" });
    expect(takePendingSso()).toEqual({
      protocol: "OAuth2",
      displayName: "GitHub",
    });
    expect(takePendingSso()).toBeNull();
  });

  /**
   * Private browsing, or storage disabled. A browser that refuses storage must
   * degrade to "the callback route guesses OIDC first", not to a thrown error
   * on the way to the identity provider.
   */
  it("survives storage that refuses to write", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("denied");
    });
    expect(() =>
      rememberPendingSso({ protocol: "OidcConnect", displayName: "Okta" }),
    ).not.toThrow();
  });

  it("survives storage that refuses to read", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("denied");
    });
    expect(takePendingSso()).toBeNull();
  });
});

describe("ssoLoginService", () => {
  it("asks for providers by slug, with the tenant only when there is one", async () => {
    apiMock.get.mockResolvedValue(res({ providers: [] }));

    await ssoLoginService.listProviders("acme", "eu");
    expect(apiMock.get).toHaveBeenCalledWith(
      "/api/v1/auth/federation/providers",
      { params: { org_slug: "acme", tenant_slug: "eu" } },
    );

    await ssoLoginService.listProviders("acme");
    expect(apiMock.get).toHaveBeenLastCalledWith(
      "/api/v1/auth/federation/providers",
      { params: { org_slug: "acme" } },
    );
  });

  /**
   * An unknown organization and a known one with nothing configured both answer
   * `200` with an empty list, deliberately — the endpoint must not be an
   * organization-slug oracle. A client that treated "empty" as an error would
   * put that property back.
   */
  it("treats a body with no providers array as an empty list", async () => {
    apiMock.get.mockResolvedValue(res({}));
    await expect(ssoLoginService.listProviders("acme")).resolves.toEqual([]);
  });

  it("starts a SAML login at the SAML endpoint", async () => {
    apiMock.post.mockResolvedValue(
      res({
        binding: "HTTP-POST",
        sso_url: "https://idp.example/sso",
        saml_request_b64: "PHNhbWw+",
        relay_state: "rs",
      }),
    );

    const body = {
      org_slug: "acme",
      federation_config_id: "c1",
      redirect_uri: "https://app.example/auth/sso/callback",
    };
    const out = await ssoLoginService.startSaml(body);

    expect(apiMock.post).toHaveBeenCalledWith(
      "/api/v1/auth/federation/saml/login",
      body,
    );
    expect(out.sso_url).toBe("https://idp.example/sso");
  });
});

describe("submitSamlAuthnRequest", () => {
  /**
   * The HTTP-POST binding *is* a form submission: the browser has to navigate
   * to the identity provider so the user can authenticate there, which is why
   * this cannot be a `fetch`. jsdom does not implement navigation, so `submit`
   * is stubbed and the form it was about to send is inspected instead.
   */
  it("posts SAMLRequest and RelayState to the IdP as a real form", () => {
    // The form is created, submitted and removed inside one call, so the only
    // moment it can be inspected is during `submit` — captured from the
    // document rather than from `this`, which the lint rules disallow aliasing.
    let submitted: HTMLFormElement | null = null;
    vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(() => {
      submitted = document.querySelector("form");
    });

    submitSamlAuthnRequest({
      sso_url: "https://idp.example/sso",
      saml_request_b64: "PHNhbWw+",
      relay_state: "rs-123",
    });

    const form = submitted as unknown as HTMLFormElement;
    expect(form).not.toBeNull();
    expect(form.method).toBe("post");
    expect(form.action).toBe("https://idp.example/sso");
    const fields = Object.fromEntries(
      Array.from(form.querySelectorAll("input")).map((i) => [i.name, i.value]),
    );
    expect(fields).toEqual({
      SAMLRequest: "PHNhbWw+",
      RelayState: "rs-123",
    });
  });

  /**
   * Removed after submission rather than left behind: the navigation makes it
   * mostly academic, but a back-button return to a page carrying a stale
   * AuthnRequest is not worth leaving lying around.
   */
  it("removes the form from the document afterwards", () => {
    vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(() => {});
    submitSamlAuthnRequest({
      sso_url: "https://idp.example/sso",
      saml_request_b64: "x",
      relay_state: "y",
    });
    expect(document.querySelectorAll("form")).toHaveLength(0);
  });
});

describe("the handoff query parameter", () => {
  it("is the name the server redirects with", () => {
    expect(HANDOFF_QUERY_PARAM).toBe("axiam_handoff");
  });
});
