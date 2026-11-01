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
import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

const navigate = vi.fn();
vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return { ...actual, useNavigate: () => navigate };
});

import { LoginPage } from "./LoginPage";
import { SsoCallbackPage } from "./auth/SsoCallbackPage";
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
    // #832: the hop travels with the sign-in, so the callback can resume it —
    // bound to the start's own `state` (#835, D-N29).
    const pending = JSON.parse(sessionStorage.getItem("axiam.sso.pending") ?? "{}");
    expect(pending.hop).toEqual({ returnTo: "/oauth2/authorize?x=1" });
    expect(pending.state).toBe("s");
  });

  it("records the hop's presentation with the pending sign-in, and never idp (#832)", async () => {
    await setup(
      `?return_to=${encodeURIComponent("/oauth2/authorize?x=1")}&ui_locale=en&display=popup&login_hint=ada&idp=${IDP}`,
    );
    await screen.findByRole("status");
    await advance(3200);
    expect(startCalls()).toHaveLength(1);
    const pending = JSON.parse(sessionStorage.getItem("axiam.sso.pending") ?? "{}");
    expect(pending.hop).toEqual({
      returnTo: "/oauth2/authorize?x=1",
      uiLocale: "en",
      display: "popup",
      loginHint: "ada",
    });
    expect(JSON.stringify(pending)).not.toContain(IDP);
  });

  it("records no hop when the page was not reached through one", async () => {
    await setup(`?idp=${IDP}`);
    await screen.findByRole("status");
    await advance(1600);
    expect(startCalls()).toHaveLength(1);
    expect(JSON.parse(sessionStorage.getItem("axiam.sso.pending") ?? "{}")).not.toHaveProperty("hop");
  });

  it("starts a SAML provider through the SAML endpoint too", async () => {
    apiMock.get.mockImplementation(() =>
      Promise.resolve(res({ providers: [provider(IDP, "Acme SAML", "Saml")] })),
    );
    apiMock.post.mockResolvedValue(
      res({ binding: "post", sso_url: "https://idp.example/sso", saml_request_b64: "x", relay_state: "rs" }),
    );
    vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(() => {});
    await setup(`?return_to=${encodeURIComponent("/oauth2/authorize?x=1")}&idp=${IDP}`);
    await screen.findByRole("status");
    await advance(1600);
    expect(apiMock.post).toHaveBeenCalledWith(
      "/api/v1/auth/federation/saml/login",
      expect.objectContaining({ federation_config_id: IDP }),
    );
    // #835 (D-N29): SAML's correlator is its relay_state, which the server
    // echoes beside the handoff code.
    const pending = JSON.parse(sessionStorage.getItem("axiam.sso.pending") ?? "{}");
    expect(pending.state).toBe("rs");
    expect(pending.hop).toEqual({ returnTo: "/oauth2/authorize?x=1" });
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

  // Defence in depth only (F4-W3-04): nothing AXIAM builds puts these on
  // `/login`. The guard that operates on a real failure is the next describe.
  it.each(["error", "error_description"])(
    "never redirects when the page carries %s (defence in depth)",
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
    // #835: a start that failed leaves no pending record behind.
    expect(sessionStorage.getItem("axiam.sso.pending")).toBeNull();
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

/**
 * #833 (F4-W3-03, D-N26) — a re-authentication is never started for the
 * person: the provider is highlighted and waits for a click.
 */
describe("LoginPage — idp on a re-authentication hop", () => {
  const authorize = (q: string) => encodeURIComponent(`/oauth2/authorize?client_id=rp&${q}`);

  it.each([
    ["reauth=1", `?return_to=${authorize("x=1")}&reauth=1&idp=${IDP}`],
    ["a step-up acr", `?return_to=${authorize("x=1")}&acr=urn:axiam:acr:mfa&idp=${IDP}`],
    // #835 (D-N28): the server's own marker, for a request that says
    // prompt=login or max_age=0 — inline or pushed, which this page cannot see.
    ["the server's fresh=1", `?return_to=${authorize("x=1")}&fresh=1&idp=${IDP}`],
    ["fresh=1 on a PAR hop", `?return_to=${authorize("request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc")}&fresh=1&idp=${IDP}`],
  ])("does not auto-start on %s, and highlights the provider", async (_label, query) => {
    const user = await setup(query);
    const suggested = await screen.findByRole("button", { name: "Sign in with Acme SSO" });
    await advance(5000);
    expect(screen.queryByTestId("idp-auto-redirect")).not.toBeInTheDocument();
    expect(startCalls()).toHaveLength(0);
    expect(suggested).toHaveAttribute("data-suggested", "true");
    expect(screen.getByRole("button", { name: "Sign in with Other" })).not.toHaveAttribute(
      "data-suggested",
    );

    // One click away: the person's click is what starts it.
    await user.click(suggested);
    expect(startCalls()).toHaveLength(1);
    expect(startCalls()[0][1]).toEqual(expect.objectContaining({ federation_config_id: IDP }));
  });

  /**
   * #835 (F4-W3-14) — the page no longer reads `prompt`/`max_age` out of
   * `return_to`: whether a hop is a re-authentication is the server's call,
   * made with its own parser and carried as `fresh=1`. Whatever `return_to`
   * holds, without a marker the page auto-starts.
   */
  it.each([
    ["prompt=login", "prompt=login"],
    ["prompt=consent login", "prompt=consent%20login"],
    ["max_age=0", "max_age=0"],
    ["max_age=00", "max_age=00"],
  ])("auto-starts when only return_to says %s", async (_label, q) => {
    await setup(`?return_to=${authorize(q)}&idp=${IDP}`);
    await screen.findByTestId("idp-auto-redirect");
    await advance(1600);
    expect(startCalls()).toHaveLength(1);
  });

  it("still auto-starts for an ordinary max_age", async () => {
    await setup(`?return_to=${authorize("max_age=3600")}&idp=${IDP}`);
    await screen.findByTestId("idp-auto-redirect");
    await advance(1600);
    expect(startCalls()).toHaveLength(1);
  });

  it.each([
    ["fresh=0", "&fresh=0"],
    ["fresh=true", "&fresh=true"],
    ["no marker", ""],
  ])("auto-starts on %s: only the server's fresh=1 marks the hop", async (_label, extra) => {
    await setup(`?return_to=${authorize("x=1")}${extra}&idp=${IDP}`);
    await screen.findByTestId("idp-auto-redirect");
    await advance(1600);
    expect(startCalls()).toHaveLength(1);
  });

  it("stays quiet on reload: the page strips reauth but keeps fresh=1", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    function LocationProbe() {
      return <output data-testid="search">{useLocation().search}</output>;
    }
    renderWithProviders(
      <>
        <LoginPage />
        <LocationProbe />
      </>,
      { route: `/login?return_to=${authorize("x=1")}&reauth=1&fresh=1&idp=${IDP}` },
    );
    await submitWorkspace(user);
    await screen.findByRole("button", { name: "Sign in with Acme SSO" });
    const search = screen.getByTestId("search").textContent ?? "";
    expect(new URLSearchParams(search).has("reauth")).toBe(false);
    expect(new URLSearchParams(search).get("fresh")).toBe("1");
    cleanup();

    // The reload: the URL as the page left it.
    vi.useRealTimers();
    await setup(search);
    await screen.findByRole("button", { name: "Sign in with Acme SSO" });
    await advance(5000);
    expect(screen.queryByTestId("idp-auto-redirect")).not.toBeInTheDocument();
    expect(startCalls()).toHaveLength(0);
  });

  /**
   * #836 (F4-W3-17) — an interaction hop carries `reauth=1` or a step-up `acr`
   * with `idp`, and never `fresh`. The page strips the mark from the address
   * bar, so it writes `fresh=1` in its place: the reload stays quiet and keeps
   * the provider highlighted. Returns the URL the page left behind, read once
   * `ready` has rendered and before any countdown could fire.
   */
  async function firstLoad(query: string, ready: () => Promise<unknown>): Promise<string> {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    function LocationProbe() {
      return <output data-testid="search">{useLocation().search}</output>;
    }
    renderWithProviders(
      <>
        <LoginPage />
        <LocationProbe />
      </>,
      { route: `/login${query}` },
    );
    await submitWorkspace(user);
    await ready();
    const search = screen.getByTestId("search").textContent ?? "";
    cleanup();
    vi.useRealTimers();
    return search;
  }

  it.each([
    ["reauth=1 alone", `?return_to=${authorize("x=1")}&reauth=1&idp=${IDP}`],
    ["a step-up acr alone", `?return_to=${authorize("x=1")}&acr=urn:axiam:acr:mfa&idp=${IDP}`],
  ])("stays quiet on reload of a hop marked by %s: the strip writes fresh=1", async (_label, query) => {
    const search = await firstLoad(query, () =>
      screen.findByRole("button", { name: "Sign in with Acme SSO" }),
    );
    const left = new URLSearchParams(search);
    expect(left.has("reauth")).toBe(false);
    expect(left.has("acr")).toBe(false);
    expect(left.get("fresh")).toBe("1");
    expect(left.get("idp")).toBe(IDP);
    expect(startCalls()).toHaveLength(0);

    // The reload: the URL as the page left it.
    await setup(search);
    const suggested = await screen.findByRole("button", { name: "Sign in with Acme SSO" });
    await advance(5000);
    expect(screen.queryByTestId("idp-auto-redirect")).not.toBeInTheDocument();
    expect(startCalls()).toHaveLength(0);
    expect(suggested).toHaveAttribute("data-suggested", "true");
  });

  it.each([
    ["reauth=0", `?return_to=${authorize("x=1")}&reauth=0&idp=${IDP}`],
    ["an unknown acr", `?return_to=${authorize("x=1")}&acr=urn%3Aother&idp=${IDP}`],
  ])("writes no fresh when the stripped %s was no mark: a hop with neither still auto-starts", async (_label, query) => {
    // The first load is itself unmarked: it counts down, and is left before
    // the start (unmounting clears the timer), so no attempt is recorded.
    const search = await firstLoad(query, () => screen.findByTestId("idp-auto-redirect"));
    const left = new URLSearchParams(search);
    expect(left.has("reauth")).toBe(false);
    expect(left.has("acr")).toBe(false);
    expect(left.has("fresh")).toBe(false);
    expect(startCalls()).toHaveLength(0);

    await setup(search);
    await screen.findByTestId("idp-auto-redirect");
    await advance(1600);
    expect(startCalls()).toHaveLength(1);
  });
});

/**
 * #833 (F4-W3-02) — providers load only after the person submits the
 * workspace step. A workspace taken from the URL never loads them, so it can
 * never start one: loading them from URL parameters would make `/login` a
 * redirector to any tenant operator's identity provider.
 */
describe("LoginPage — idp with a workspace in the URL", () => {
  it.each([
    ["org", `?org=acme&idp=${IDP}`],
    ["org and tenant", `?org=acme&tenant=eu&idp=${IDP}`],
    ["tenant", `?tenant=eu&idp=${IDP}`],
  ])("loads no providers and starts nothing from ?%s=", async (_label, query) => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderWithProviders(<LoginPage />, { route: `/login${query}` });
    expect(await screen.findByLabelText("Username or email")).toBeInTheDocument();
    await advance(5000);
    expect(apiMock.get.mock.calls.filter(([url]) => url === PROVIDERS_PATH)).toHaveLength(0);
    expect(screen.queryByTestId("idp-auto-redirect")).not.toBeInTheDocument();
    expect(startCalls()).toHaveLength(0);
    expect(assign).not.toHaveBeenCalled();
  });
});

/** #833 (F4-W3-11) — "choose another way" survives a reload. */
describe("LoginPage — cancel and reload", () => {
  it("records the cancel, so a reload does not restart the countdown", async () => {
    const query = `?return_to=${encodeURIComponent("/oauth2/authorize?x=1")}&idp=${IDP}`;
    const user = await setup(query);
    await screen.findByTestId("idp-auto-redirect");
    await user.click(screen.getByRole("button", { name: "Choose another way to sign in" }));
    expect(sessionStorage.getItem("axiam.sso.auto")).toContain(IDP);

    // The reload: a fresh page, the same tab's storage.
    cleanup();
    vi.useRealTimers();
    await setup(query);
    expect(await screen.findByRole("button", { name: "Sign in with Acme SSO" })).toBeInTheDocument();
    await advance(5000);
    expect(screen.queryByTestId("idp-auto-redirect")).not.toBeInTheDocument();
    expect(startCalls()).toHaveLength(0);
  });
});

/**
 * #833 (F4-W3-04) — the real failure path, end to end: the page starts the
 * provider, the provider fails, `SsoCallbackPage` renders its "Back to sign in"
 * link, and the page that link opens starts nothing — because the link carries
 * no `idp`, even with the ten-minute storage guard gone.
 */
describe("LoginPage — the return from a failed provider leg", () => {
  it("follows SsoCallbackPage's own failure link and does not start again", async () => {
    const returnTo = "/oauth2/authorize?client_id=rp&x=1";
    await setup(`?return_to=${encodeURIComponent(returnTo)}&idp=${IDP}`);
    await screen.findByTestId("idp-auto-redirect");
    await advance(1600);
    expect(startCalls()).toHaveLength(1);
    cleanup();

    // The provider's error redirect carries the start's `state` ("s" in the
    // mocked start): this is that sign-in's callback, so its hop is offered.
    renderWithProviders(<SsoCallbackPage />, {
      route: "/auth/sso/callback?error=access_denied&state=s",
    });
    await screen.findByRole("alert");
    const href = screen.getByRole("link", { name: "Back to sign in" }).getAttribute("href") ?? "";
    cleanup();

    const url = new URL(href, "https://spa.example");
    expect(url.pathname).toBe("/login");
    expect(url.searchParams.get("return_to")).toBe(returnTo);
    expect(url.searchParams.has("idp")).toBe(false);

    // Not the storage guard doing the work: remove it.
    sessionStorage.removeItem("axiam.sso.auto");
    vi.useRealTimers();
    await setup(url.search);
    expect(await screen.findByRole("button", { name: "Sign in with Acme SSO" })).toBeInTheDocument();
    await advance(5000);
    expect(screen.queryByTestId("idp-auto-redirect")).not.toBeInTheDocument();
    expect(startCalls()).toHaveLength(1);
  });
});
