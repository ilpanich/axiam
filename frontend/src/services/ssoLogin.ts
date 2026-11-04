import api from "@/lib/api";
import { sanitizeDisplay, sanitizeLocale, sanitizeLoginHint } from "@/i18n/locales";
import { sanitizeRequiredAcr } from "@/lib/reauth";
import { sanitizeReturnTo } from "@/lib/returnTo";
import type { FederationProtocol, ProviderKind } from "@/services/federation";

/**
 * The public "Sign in with X" surface.
 *
 * Deliberately separate from `services/federation.ts`, which is the
 * `federation:*`-gated admin CRUD. Everything here is called with **no
 * credential at all**, from the login page and the SSO callback route, and the
 * server treats it as such: the endpoints are in `PUBLIC_PATHS`, exempt from
 * CSRF (there is no session cookie to echo yet), and rate-limited on the login
 * budget.
 *
 * See `claude_dev/federation-sso-login-design.md` §5.
 */

/**
 * Paths are written out in full rather than composed from a shared prefix.
 *
 * `src/test/apiRoutes.test.ts` checks every path this app requests against the
 * server's OpenAPI document by scanning for string literals — a `${BASE}/…`
 * template hides the real path from it, and the prefix on its own is not a
 * route the server serves. Six literals cost nothing and stay checkable.
 */

/** Where the browser returns from an identity provider. */
export const SSO_CALLBACK_PATH = "/auth/sso/callback";

/**
 * The query parameter a cross-site return carries a handoff code in.
 *
 * SAML and Apple post their response to an AXIAM server endpoint rather than
 * redirecting the browser to the SPA, and `SameSite=Strict` cookies set on that
 * cross-site response would not be sent afterwards. The server therefore
 * redirects here with a 60-second single-use code, which the SPA exchanges
 * same-origin for the real session.
 */
export const HANDOFF_QUERY_PARAM = "axiam_handoff";

/**
 * The absolute callback URL sent to the provider.
 *
 * It must match what is registered at the provider byte for byte — the server
 * passes it straight through and echoes it at the token exchange — which is why
 * it is built from `window.location.origin` and one constant rather than being
 * configured in two places that can drift.
 */
export function ssoCallbackUrl(): string {
  return `${window.location.origin}${SSO_CALLBACK_PATH}`;
}

/** One sign-in button, as the server describes it. */
export interface PublicFederationProvider {
  id: string;
  provider_kind: ProviderKind;
  display_name: string;
  protocol: FederationProtocol;
  /** Whether AXIAM ships this provider's own mark. */
  has_bundled_mark: boolean;
  /** The operator's uploaded icon, for a generic provider that has one. */
  button_icon?: string | null;
  /** Whether the provider comes from the organization rather than the tenant. */
  inherited: boolean;
}

interface ProvidersResponse {
  providers: PublicFederationProvider[];
}

interface StartResponse {
  authorize_url: string;
  state: string;
  expires_in_secs: number;
}

/** What a completed SSO login returns, alongside the session cookies. */
export interface SsoLoginSuccess {
  user_id: string;
  session_id: string;
  expires_in: number;
  redirect_uri: string;
}

/**
 * What the SPA has to remember between navigating to a provider and coming
 * back.
 *
 * The protocol: `state` round-trips through the provider, and the nonce and
 * PKCE verifier never leave the server. What the callback route cannot
 * otherwise know is *which* completion endpoint to post to, because the
 * provider's redirect says nothing about how AXIAM authenticated it.
 *
 * And, when the sign-in was started from a login hop, the hop itself
 * (#832, F4-W3-01): the provider's redirect lands on `/auth/sso/callback`,
 * which has no `return_to` of its own, so without this record a federated
 * sign-in for a relying party ended in the AXIAM console and the relying
 * party's authorization request was abandoned.
 *
 * `sessionStorage` rather than `localStorage`: this is per-tab state with a
 * lifetime of one navigation, and a value that outlived the tab would only ever
 * be a stale one.
 */
const PENDING_KEY = "axiam.sso.pending";

/**
 * The login hop a federated sign-in was started from.
 *
 * Every field is stored as the page held it *after* its own sanitiser ran, and
 * is sanitised **again** by {@link takePendingSso} when it is read back:
 * `sessionStorage` is same-origin state, but "same origin" includes any script
 * that ever ran on it, so the check that matters is the one made before the
 * value is used — the T23.1.3 rule `resumeLoginHop` already follows.
 *
 * Deliberately absent: `idp` (a failed leg must not start the provider again —
 * F4-W3-04) and `reauth` (the session it asks the page to end was ended on the
 * first visit, and re-sending it would count a person's own retry against the
 * re-authentication loop guard in `@/lib/reauth`).
 */
export interface SsoLoginHop {
  /** The `/oauth2/authorize` request to resume, as `sanitizeReturnTo` accepted it. */
  returnTo: string;
  /** The one factor the sign-in must demand (`?acr=`), when the hop asked for one. */
  acr?: string;
  /** `?ui_locale=`, when the hop carried one. */
  uiLocale?: string;
  /** `?display=`, when the hop carried one. */
  display?: string;
  /** `?login_hint=`, when the hop carried one. */
  loginHint?: string;
}

export interface PendingSso {
  protocol: FederationProtocol;
  /** For the error UI: "Sign in with Okta failed", not "Sign in failed". */
  displayName: string;
  /**
   * The `state` the start endpoint returned (SAML: its `relay_state`) — the
   * one value the callback of *this* sign-in brings back, on every arrival
   * (#835, D-N29). See {@link hopForCallback}.
   */
  state?: string;
  /** The login hop this sign-in belongs to, if it was started from one. */
  hop?: SsoLoginHop;
}

/**
 * The longest stored `state` the callback will compare. The server's are
 * 43-character base64url strings; anything far longer is not one of them.
 */
const MAX_STATE_LEN = 512;

export function rememberPendingSso(pending: PendingSso): void {
  try {
    sessionStorage.setItem(PENDING_KEY, JSON.stringify(pending));
  } catch {
    // Private browsing, or storage disabled. The callback route falls back to
    // trying the OIDC completion first, which is the common case — so a browser
    // that refuses storage degrades to "OIDC works, OAuth2 needs a retry"
    // rather than to a blank page. A hop is lost the same way: the sign-in
    // completes and lands on the dashboard, which is where it landed before
    // #832, never somewhere the stored value would have had to be trusted.
  }
}

/**
 * Re-validate a stored hop, field by field. A `returnTo` that no longer passes
 * `sanitizeReturnTo` discards the whole hop — there is nothing to resume — and
 * any other field that fails its sanitiser is dropped on its own.
 */
function revalidateHop(raw: unknown): SsoLoginHop | undefined {
  if (typeof raw !== "object" || raw === null) return undefined;
  const r = raw as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === "string" ? v : null);
  const returnTo = sanitizeReturnTo(str(r.returnTo));
  if (!returnTo) return undefined;
  const acr = sanitizeRequiredAcr(str(r.acr));
  const uiLocale = sanitizeLocale(str(r.uiLocale));
  const display = sanitizeDisplay(str(r.display));
  const loginHint = sanitizeLoginHint(str(r.loginHint));
  return {
    returnTo,
    ...(acr ? { acr } : {}),
    ...(uiLocale ? { uiLocale } : {}),
    ...(display ? { display } : {}),
    ...(loginHint ? { loginHint } : {}),
  };
}

export function takePendingSso(): PendingSso | null {
  try {
    const raw = sessionStorage.getItem(PENDING_KEY);
    sessionStorage.removeItem(PENDING_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as PendingSso;
    const hop = revalidateHop(parsed.hop);
    const state =
      typeof parsed.state === "string" &&
      parsed.state.length > 0 &&
      parsed.state.length <= MAX_STATE_LEN
        ? parsed.state
        : undefined;
    return {
      protocol: parsed.protocol,
      displayName: parsed.displayName,
      ...(state ? { state } : {}),
      ...(hop ? { hop } : {}),
    };
  } catch {
    return null;
  }
}

/**
 * The stored hop, **only** when this callback belongs to the sign-in that
 * stored it (#835, D-N29, F4-W3-16).
 *
 * Every arrival on the callback route carries the start's `state`: an OIDC or
 * OAuth2 provider redirects with it, and the server echoes it (already spent)
 * beside a SAML or Apple handoff code and beside a form-post error. A callback
 * whose `state` is absent or differs is somebody else's sign-in — a login CSRF
 * landing in this tab — or a stale one, and must not resume a hop the person
 * left behind: the sign-in it completes then ends on the dashboard, and its
 * failure link is a bare `/login`. The record itself has already been removed
 * by {@link takePendingSso}, so it is cleared either way.
 */
export function hopForCallback(
  pending: PendingSso | null,
  callbackState: string | null,
): SsoLoginHop | undefined {
  if (!pending?.hop || !pending.state || !callbackState) return undefined;
  return pending.state === callbackState ? pending.hop : undefined;
}

/**
 * Where "Back to sign in" goes after a failed federated leg.
 *
 * A bare `/login` when the sign-in was not started from a hop. Otherwise the
 * hop again — `return_to` and the presentation it asked for, each re-validated
 * here because this is the moment the value is used — but **never** `idp`: the
 * person has just seen that provider fail, and a link that started it again by
 * itself is the loop the auto-redirect's guards exist to prevent (F4-W3-04).
 * Never `reauth` either, for the reason {@link SsoLoginHop} gives.
 */
export function loginHopRetryPath(hop: SsoLoginHop | undefined): string {
  const checked = revalidateHop(hop);
  if (!checked) return "/login";
  const q = new URLSearchParams({ return_to: checked.returnTo });
  if (checked.acr) q.set("acr", checked.acr);
  if (checked.loginHint) q.set("login_hint", checked.loginHint);
  if (checked.display) q.set("display", checked.display);
  if (checked.uiLocale) q.set("ui_locale", checked.uiLocale);
  return `/login?${q.toString()}`;
}

export const ssoLoginService = {
  /**
   * Which buttons to render for a workspace.
   *
   * Answers `200` with an empty list for an unknown organization as well as a
   * known one with nothing configured — deliberately indistinguishable, so the
   * endpoint is not an organization-slug oracle.
   */
  listProviders: (
    orgSlug: string,
    tenantSlug?: string,
  ): Promise<PublicFederationProvider[]> =>
    api
      .get<ProvidersResponse>("/api/v1/auth/federation/providers", {
        params: {
          org_slug: orgSlug,
          ...(tenantSlug ? { tenant_slug: tenantSlug } : {}),
        },
      })
      .then((r) => r.data.providers ?? []),

  /** Begin an OIDC login. Returns the URL to navigate to. */
  startOidc: (body: {
    org_slug: string;
    tenant_slug?: string;
    federation_config_id: string;
    redirect_uri: string;
    /** #838 — answer a re-authentication hop: ask the provider to authenticate again. */
    reauthenticate?: boolean;
  }): Promise<StartResponse> =>
    api.post<StartResponse>("/api/v1/auth/federation/oidc/start", body).then((r) => r.data),

  /** Begin a plain-OAuth2 login (GitHub, Facebook, generic). */
  startOauth2: (body: {
    org_slug: string;
    tenant_slug?: string;
    federation_config_id: string;
    redirect_uri: string;
    /** #838 — answer a re-authentication hop: ask the provider to authenticate again. */
    reauthenticate?: boolean;
  }): Promise<StartResponse> =>
    api.post<StartResponse>("/api/v1/auth/federation/oauth2/start", body).then((r) => r.data),

  /**
   * Begin a SAML login.
   *
   * Returns a POST-binding payload rather than a URL: SAML's HTTP-POST binding
   * requires the browser to submit a form to the IdP, which is what
   * `submitSamlAuthnRequest` does.
   */
  startSaml: (body: {
    org_slug: string;
    tenant_slug?: string;
    federation_config_id: string;
    redirect_uri: string;
    /** #838 — answer a re-authentication hop: ask the provider to authenticate again. */
    reauthenticate?: boolean;
  }): Promise<{
    binding: string;
    sso_url: string;
    saml_request_b64: string;
    relay_state: string;
  }> => api.post("/api/v1/auth/federation/saml/login", body).then((r) => r.data),

  /** Complete an OIDC login. Same-origin, so this response sets the cookies. */
  completeOidc: (state: string, code: string): Promise<SsoLoginSuccess> =>
    api
      .post<SsoLoginSuccess>("/api/v1/auth/federation/oidc/callback", { state, code })
      .then((r) => r.data),

  /** Complete a plain-OAuth2 login. */
  completeOauth2: (state: string, code: string): Promise<SsoLoginSuccess> =>
    api
      .post<SsoLoginSuccess>("/api/v1/auth/federation/oauth2/callback", { state, code })
      .then((r) => r.data),

  /**
   * Redeem a handoff code for the session.
   *
   * The same-origin half of the SameSite=Strict workaround: the cross-site
   * return could not set cookies, this request can.
   */
  completeHandoff: (code: string): Promise<SsoLoginSuccess> =>
    api
      .post<SsoLoginSuccess>("/api/v1/auth/federation/handoff", { code })
      .then((r) => r.data),
};

/**
 * Submit a SAML AuthnRequest to the IdP via the HTTP-POST binding.
 *
 * A real form submission, because that is what the binding is: a hidden form
 * with `SAMLRequest` and `RelayState`, auto-submitted. It cannot be a `fetch` —
 * the browser has to *navigate* to the IdP so the user can authenticate there.
 *
 * The form is removed after submission rather than left in the document; the
 * navigation makes that mostly academic, but a back-button return to a page
 * carrying a stale AuthnRequest is not a thing worth leaving lying around.
 */
export function submitSamlAuthnRequest(payload: {
  sso_url: string;
  saml_request_b64: string;
  relay_state: string;
}): void {
  const form = document.createElement("form");
  form.method = "POST";
  form.action = payload.sso_url;
  form.style.display = "none";

  const add = (name: string, value: string) => {
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    input.value = value;
    form.appendChild(input);
  };
  add("SAMLRequest", payload.saml_request_b64);
  add("RelayState", payload.relay_state);

  document.body.appendChild(form);
  form.submit();
  form.remove();
}

/**
 * **The auto-redirect loop guard** (G-B, W3.2).
 *
 * `/login?idp=<uuid>` starts that provider by itself. Without a memory of having
 * done so, a failed leg followed by the relying party restarting the
 * authorization request, or simply the browser's Back button from the provider,
 * would bounce the person to the provider forever. So the page records the
 * attempt in `sessionStorage` *before* it navigates away and refuses to repeat
 * it for the same provider within {@link AUTO_REDIRECT_TTL_MS}.
 *
 * Cleared on a completed sign-in (see `SsoCallbackPage`, `LoginPage`), so a
 * later, unrelated sign-in is not penalised. The TTL bounds the cost of a
 * sign-in that was abandoned at the provider: it is a convenience that expires,
 * never a lockout.
 *
 * It is one of the guards, not the only one (#833, F4-W3-04). The ones that
 * operate on a real failure are: the failure page (`SsoCallbackPage`) links back
 * to `/login` **without** `idp`, so there is nothing to start; this guard, for a
 * relying party that restarts the request; one start per page load (the
 * `autoStarted` ref); and the workspace step the person has to submit before
 * any provider is loaded, so nothing repeats unattended. Storage that refuses
 * writes degrades to "no guard" and leaves the other three. An error parameter
 * on `/login` also vetoes the start, as defence in depth only — nothing AXIAM
 * builds puts one there.
 *
 * Cancelling records the guard too (F4-W3-11): a person who said "choose
 * another way" once should not have the countdown restart on reload.
 */
const AUTO_KEY = "axiam.sso.auto";
export const AUTO_REDIRECT_TTL_MS = 10 * 60 * 1000;

export function markAutoRedirect(idp: string): void {
  try {
    sessionStorage.setItem(AUTO_KEY, JSON.stringify({ idp, at: Date.now() }));
  } catch {
    // See above: degrade to no guard.
  }
}

export function autoRedirectAttempted(idp: string): boolean {
  try {
    const raw = sessionStorage.getItem(AUTO_KEY);
    if (!raw) return false;
    const seen = JSON.parse(raw) as { idp?: unknown; at?: unknown };
    return (
      seen.idp === idp &&
      typeof seen.at === "number" &&
      Date.now() - seen.at < AUTO_REDIRECT_TTL_MS
    );
  } catch {
    return false;
  }
}

export function clearAutoRedirect(): void {
  try {
    sessionStorage.removeItem(AUTO_KEY);
  } catch {
    // Nothing to clear.
  }
}
