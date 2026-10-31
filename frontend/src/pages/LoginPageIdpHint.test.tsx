/**
 * **G-B (W3.2) — `/login?idp=<uuid>` starts that provider by itself.**
 *
 * The server resolves `axiam_idp_hint` / the client's `default_idp` to a
 * provider id and appends it to the login hop. This file tests the page's half:
 * the delayed start, the cancel, and — the part that matters — every way it
 * must *not* start (a failed SSO leg, an unknown id, a second visit).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { StrictMode } from "react";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

const navigate = vi.fn();
vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return { ...actual, useNavigate: () => navigate };
});

import { LoginPage } from "./LoginPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { markAutoRedirect } from "@/services/ssoLogin";

const IDP = "11111111-1111-4111-8111-111111111111";
const OTHER = "99999999-9999-4999-8999-999999999999";
const PROVIDERS_PATH = "/api/v1/auth/federation/providers";
const OIDC_START = "/api/v1/auth/federation/oidc/start";

const provider = (id: string, name: string, protocol = "OidcConnect") => ({
  id,
  provider_kind: "generic_oidc",
  display_name: name,
  protocol,
  has_bundled_mark: false,
  inherited: false,
});

let assign: ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.clearAllMocks();
  sessionStorage.clear();
  assign = vi.fn();
  vi.spyOn(window, "location", "get").mockReturnValue({
    ...window.location,
    origin: "https://spa.example",
    assign,
  } as unknown as Location);
  apiMock.get.mockImplementation((url: string) =>
    url === PROVIDERS_PATH
      ? Promise.resolve(
          res({ providers: [provider(IDP, "Acme SSO"), provider(OTHER, "Other")] }),
        )
      : Promise.reject(new Error(`unexpected get ${url}`)),
  );
  apiMock.post.mockImplementation((url: string) =>
    url === OIDC_START
      ? Promise.resolve(res({ authorize_url: "https://idp.example/auth", state: "s", expires_in_secs: 600 }))
      : Promise.reject(new Error(`unexpected post ${url}`)),
  );
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

/** Fill the workspace step so the provider list loads. */
async function submitWorkspace(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText("Organization slug"), "acme");
  await user.click(screen.getByRole("button", { name: /Continue/ }));
}

async function setup(query: string, strict = false) {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
  if (strict) {
    render(
      <StrictMode>
        <MemoryRouter initialEntries={[`/login${query}`]}>
          <LoginPage />
        </MemoryRouter>
      </StrictMode>,
    );
  } else {
    renderWithProviders(<LoginPage />, { route: `/login${query}` });
  }
  await submitWorkspace(user);
  return user;
}

const advance = (ms: number) => act(() => vi.advanceTimersByTimeAsync(ms));
const startCalls = () =>
  apiMock.post.mock.calls.filter(([url]) => url === OIDC_START);

describe("LoginPage — idp auto-redirect", () => {
  it("announces the redirect, then starts the matching provider once", async () => {
    await setup(`?return_to=${encodeURIComponent("/oauth2/authorize?x=1")}&idp=${IDP}`);

    const status = await screen.findByRole("status");
    expect(status).toHaveAttribute("aria-live", "polite");
    expect(status).toHaveTextContent("Redirecting to Acme SSO…");
    expect(
      screen.getByRole("button", { name: "Choose another way to sign in" }),
    ).toHaveFocus();
    // A visible moment to cancel: nothing has been started yet.
    expect(startCalls()).toHaveLength(0);

    await advance(1600);
    expect(startCalls()).toHaveLength(1);
    // The same protocol-generic start the manual button uses.
    expect(startCalls()[0][1]).toEqual({
      org_slug: "acme",
      federation_config_id: IDP,
      redirect_uri: "https://spa.example/auth/sso/callback",
    });
    expect(assign).toHaveBeenCalledWith("https://idp.example/auth");
    // return_to is untouched (the page never rewrites it for SSO).
    expect(navigate).not.toHaveBeenCalled();
  });

  it("starts a SAML provider through the SAML endpoint too", async () => {
    apiMock.get.mockImplementation(() =>
      Promise.resolve(res({ providers: [provider(IDP, "Acme SAML", "Saml")] })),
    );
    apiMock.post.mockResolvedValue(res({}));
    vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(() => {});
    await setup(`?idp=${IDP}`);
    await screen.findByRole("status");
    await advance(1600);
    expect(apiMock.post).toHaveBeenCalledWith(
      "/api/v1/auth/federation/saml/login",
      expect.objectContaining({ federation_config_id: IDP }),
    );
  });

  it("cancel stops the redirect and shows the ordinary page", async () => {
    const user = await setup(`?idp=${IDP}`);
    await screen.findByRole("status");
    await user.click(screen.getByRole("button", { name: "Choose another way to sign in" }));

    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in with Other" })).toBeInTheDocument();

    await advance(5000);
    expect(startCalls()).toHaveLength(0);
    expect(assign).not.toHaveBeenCalled();
  });

  it.each(["error", "error_description", "sso_error"])(
    "never redirects when the page carries %s (a failed SSO leg)",
    async (param) => {
      await setup(`?${param}=access_denied&idp=${IDP}`);
      expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
      await advance(5000);
      expect(screen.queryByRole("status")).not.toBeInTheDocument();
      expect(startCalls()).toHaveLength(0);
    },
  );

  it("does not repeat itself for a provider it already started (Back button, restarted request)", async () => {
    markAutoRedirect(IDP);
    await setup(`?idp=${IDP}`);
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    await advance(5000);
    expect(startCalls()).toHaveLength(0);
  });

  it("records the attempt before navigating, so a second visit is quiet", async () => {
    await setup(`?idp=${IDP}`);
    await screen.findByRole("status");
    await advance(1600);
    expect(startCalls()).toHaveLength(1);
    expect(sessionStorage.getItem("axiam.sso.auto")).toContain(IDP);
  });

  it.each([
    ["an id the tenant does not list", OTHER.replace("9", "8")],
    ["something that is not a UUID", "google"],
    ["a URL", encodeURIComponent("https://evil.example/")],
  ])("shows the ordinary page for %s", async (_label, value) => {
    await setup(`?idp=${value}`);
    expect(await screen.findByRole("button", { name: "Sign in with Acme SSO" })).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    await advance(5000);
    expect(startCalls()).toHaveLength(0);
  });

  it("matches the id case-insensitively", async () => {
    await setup(`?idp=${IDP.toUpperCase()}`);
    await screen.findByRole("status");
    await advance(1600);
    expect(startCalls()).toHaveLength(1);
  });

  it("starts exactly once under StrictMode's double effect", async () => {
    await setup(`?idp=${IDP}`, true);
    await screen.findByRole("status");
    await advance(5000);
    expect(startCalls()).toHaveLength(1);
  });

  it("falls back to the ordinary page, with the error, when the start fails", async () => {
    apiMock.post.mockRejectedValue(new Error("boom"));
    await setup(`?idp=${IDP}`);
    await screen.findByRole("status");
    await advance(1600);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not start sign-in with Acme SSO",
    );
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    await advance(5000);
    expect(startCalls()).toHaveLength(1);
  });

  it("waits twice as long when the person asked for reduced motion", async () => {
    vi.stubGlobal(
      "matchMedia",
      (q: string) =>
        ({ matches: q.includes("reduce"), media: q, addEventListener() {}, removeEventListener() {} }) as unknown as MediaQueryList,
    );
    await setup(`?idp=${IDP}`);
    await screen.findByRole("status");
    await advance(2000);
    expect(startCalls()).toHaveLength(0);
    await advance(1200);
    expect(startCalls()).toHaveLength(1);
  });
});
