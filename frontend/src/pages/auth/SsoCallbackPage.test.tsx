import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen } from "@testing-library/react";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

const navigate = vi.fn();
vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return { ...actual, useNavigate: () => navigate };
});

const fetchCurrentUserMock = vi.fn();
vi.mock("@/lib/fetchCurrentUser", () => ({
  fetchCurrentUser: () => fetchCurrentUserMock(),
  withReachableTenantSelected: (u: unknown) => Promise.resolve(u),
}));

import { SsoCallbackPage } from "./SsoCallbackPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { rememberPendingSso } from "@/services/ssoLogin";

const hydratedUser = {
  id: "u1",
  username: "ada",
  email: "ada@example.com",
  permissions: [],
  tenant_id: "t1",
};

beforeEach(() => {
  vi.clearAllMocks();
  sessionStorage.clear();
  fetchCurrentUserMock.mockResolvedValue(hydratedUser);
  apiMock.post.mockResolvedValue(
    res({
      user_id: "u1",
      session_id: "s1",
      expires_in: 900,
      redirect_uri: "https://spa.example/auth/sso/callback",
    }),
  );
});

describe("SsoCallbackPage", () => {
  it("completes an OIDC return by posting code and state same-origin", async () => {
    renderWithProviders(<SsoCallbackPage />, {
      route: "/auth/sso/callback?code=the-code&state=the-state",
    });

    await vi.waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/auth/federation/oidc/callback",
        { state: "the-state", code: "the-code" },
      ),
    );
    await vi.waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("/dashboard", { replace: true }),
    );
  });

  /**
   * The redirect itself says nothing about how AXIAM authenticated the
   * provider, so which completion endpoint verifies it is the one thing the SPA
   * has to remember across the navigation.
   */
  it("completes an OAuth2 return at the OAuth2 endpoint", async () => {
    rememberPendingSso({ protocol: "OAuth2", displayName: "GitHub" });
    renderWithProviders(<SsoCallbackPage />, {
      route: "/auth/sso/callback?code=c&state=s",
    });

    await vi.waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/auth/federation/oauth2/callback",
        { state: "s", code: "c" },
      ),
    );
  });

  /**
   * SAML and Apple return cross-site, so the server could not set the session
   * cookies and redirected here with a single-use code instead. Exchanging it
   * same-origin is the whole point of this route.
   */
  it("exchanges a handoff code for the session", async () => {
    renderWithProviders(<SsoCallbackPage />, {
      route: "/auth/sso/callback?axiam_handoff=one-time-code",
    });

    await vi.waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/auth/federation/handoff",
        { code: "one-time-code" },
      ),
    );
    await vi.waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("/dashboard", { replace: true }),
    );
  });

  it("strips the credential from the address bar before completing", async () => {
    const replaceState = vi.spyOn(window.history, "replaceState");
    renderWithProviders(<SsoCallbackPage />, {
      route: "/auth/sso/callback?axiam_handoff=one-time-code",
    });
    await vi.waitFor(() => expect(replaceState).toHaveBeenCalled());
    replaceState.mockRestore();
  });

  /**
   * A cancelled sign-in, an expired state and a misconfigured client need three
   * different next actions, so they get three different sentences. "Sign-in
   * failed" is the outcome this route exists to avoid.
   */
  it.each([
    ["access_denied", /cancelled/i],
    ["login_required", /sign in there first/i],
    ["temporarily_unavailable", /try again shortly/i],
    ["invalid_client", /not configured correctly/i],
  ])("explains the %s error rather than failing blankly", async (code, re) => {
    rememberPendingSso({ protocol: "OidcConnect", displayName: "Okta" });
    renderWithProviders(<SsoCallbackPage />, {
      route: `/auth/sso/callback?error=${code}`,
    });

    expect(await screen.findByRole("alert")).toHaveTextContent(re);
    // A provider that refused is not a completion to attempt.
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("names the provider in the error, when it knows it", async () => {
    rememberPendingSso({ protocol: "OidcConnect", displayName: "Okta" });
    renderWithProviders(<SsoCallbackPage />, {
      route: "/auth/sso/callback?error=access_denied",
    });
    expect(await screen.findByRole("alert")).toHaveTextContent("Okta");
  });

  it("reports an expired or reused sign-in as such", async () => {
    apiMock.post.mockRejectedValue({
      isAxiosError: true,
      response: { status: 401, data: {} },
    });
    renderWithProviders(<SsoCallbackPage />, {
      route: "/auth/sso/callback?code=c&state=s",
    });
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /expired or was already used/i,
    );
  });

  /**
   * The server's own reason wins on a 401 where it has one: "verify your email
   * at GitHub" and "start again" are not the same instruction.
   */
  it("prefers the server's reason over the generic expiry message", async () => {
    apiMock.post.mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 401,
        data: {
          message:
            "the identity provider returned no verified email address",
        },
      },
    });
    renderWithProviders(<SsoCallbackPage />, {
      route: "/auth/sso/callback?code=c&state=s",
    });
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /no verified email address/i,
    );
  });

  it("refuses an arrival carrying nothing usable", async () => {
    renderWithProviders(<SsoCallbackPage />, { route: "/auth/sso/callback" });
    expect(await screen.findByRole("alert")).toHaveTextContent(/incomplete/i);
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  /**
   * Every credential this route consumes is single-use, and React's
   * development StrictMode mounts effects twice — a second attempt would always
   * fail, and would report *that* failure to a user whose sign-in worked.
   */
  it("attempts the exchange exactly once", async () => {
    renderWithProviders(<SsoCallbackPage />, {
      route: "/auth/sso/callback?axiam_handoff=one-time-code",
    });
    await vi.waitFor(() => expect(apiMock.post).toHaveBeenCalledTimes(1));
    // Give a second effect run a chance to fire before asserting it did not.
    await new Promise((r) => setTimeout(r, 20));
    expect(apiMock.post).toHaveBeenCalledTimes(1);
  });
});

/**
 * #832 (F4-W3-01) — a federated sign-in started from a login hop returns to
 * the relying party, and a failed one leads back to that hop without `idp`.
 */
describe("SsoCallbackPage — the login hop", () => {
  const RETURN_TO = "/oauth2/authorize?client_id=rp&response_type=code&state=xyz";
  const IDP = "11111111-1111-4111-8111-111111111111";
  let assign: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    assign = vi.fn();
    vi.spyOn(window, "location", "get").mockReturnValue({
      ...window.location,
      pathname: "/auth/sso/callback",
      origin: "https://spa.example",
      assign,
    } as unknown as Location);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const rememberHop = (protocol: "OidcConnect" | "OAuth2" | "Saml" = "OidcConnect") =>
    rememberPendingSso({
      protocol,
      displayName: "Okta",
      hop: { returnTo: RETURN_TO, acr: "urn:axiam:acr:mfa", loginHint: "ada" },
    });

  it.each([
    ["an OIDC redirect", "OidcConnect", "?code=c&state=s", "/api/v1/auth/federation/oidc/callback"],
    ["an OAuth2 redirect", "OAuth2", "?code=c&state=s", "/api/v1/auth/federation/oauth2/callback"],
    ["a SAML/Apple handoff code", "Saml", "?axiam_handoff=one-time", "/api/v1/auth/federation/handoff"],
  ] as const)("resumes the hop after %s", async (_label, protocol, query, endpoint) => {
    rememberHop(protocol);
    renderWithProviders(<SsoCallbackPage />, { route: `/auth/sso/callback${query}` });

    await vi.waitFor(() => expect(assign).toHaveBeenCalledWith(RETURN_TO));
    expect(apiMock.post).toHaveBeenCalledWith(endpoint, expect.anything());
    expect(navigate).not.toHaveBeenCalled();
  });

  it("goes to the dashboard when the sign-in was not started from a hop", async () => {
    rememberPendingSso({ protocol: "OidcConnect", displayName: "Okta" });
    renderWithProviders(<SsoCallbackPage />, { route: "/auth/sso/callback?code=c&state=s" });
    await vi.waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("/dashboard", { replace: true }),
    );
    expect(assign).not.toHaveBeenCalled();
  });

  it("rejects a tampered stored return_to and goes to the dashboard", async () => {
    sessionStorage.setItem(
      "axiam.sso.pending",
      JSON.stringify({
        protocol: "OidcConnect",
        displayName: "Okta",
        hop: { returnTo: "https://evil.example/oauth2/authorize?x=1" },
      }),
    );
    renderWithProviders(<SsoCallbackPage />, { route: "/auth/sso/callback?code=c&state=s" });
    await vi.waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("/dashboard", { replace: true }),
    );
    expect(assign).not.toHaveBeenCalled();
  });

  it("goes to the dashboard when storage refuses to read", async () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("denied");
    });
    renderWithProviders(<SsoCallbackPage />, { route: "/auth/sso/callback?code=c&state=s" });
    await vi.waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("/dashboard", { replace: true }),
    );
    expect(assign).not.toHaveBeenCalled();
  });

  /**
   * F4-W3-04: this link is the real path back from a failed leg, and the
   * reason there is no loop — it never carries `idp`, so the page it opens has
   * nothing to start.
   */
  it.each([
    ["a provider error", "?error=access_denied", false],
    ["a failed completion", "?code=c&state=s", true],
  ])("after %s, Back to sign in keeps return_to and drops idp", async (_label, query, rejects) => {
    if (rejects) {
      apiMock.post.mockRejectedValue({ isAxiosError: true, response: { status: 401, data: {} } });
    }
    rememberHop();
    renderWithProviders(<SsoCallbackPage />, { route: `/auth/sso/callback${query}` });

    await screen.findByRole("alert");
    const link = screen.getByRole("link", { name: "Back to sign in" });
    const url = new URL(link.getAttribute("href") ?? "", "https://spa.example");
    expect(url.pathname).toBe("/login");
    expect(url.searchParams.get("return_to")).toBe(RETURN_TO);
    expect(url.searchParams.get("acr")).toBe("urn:axiam:acr:mfa");
    expect(url.searchParams.get("login_hint")).toBe("ada");
    expect(url.searchParams.has("idp")).toBe(false);
    expect(url.searchParams.has("reauth")).toBe(false);
    expect(link.getAttribute("href")).not.toContain(IDP);
    expect(assign).not.toHaveBeenCalled();
  });

  it("links to a bare /login after a failure with no hop", async () => {
    rememberPendingSso({ protocol: "OidcConnect", displayName: "Okta" });
    renderWithProviders(<SsoCallbackPage />, { route: "/auth/sso/callback?error=access_denied" });
    await screen.findByRole("alert");
    expect(screen.getByRole("link", { name: "Back to sign in" })).toHaveAttribute(
      "href",
      "/login",
    );
  });
});
