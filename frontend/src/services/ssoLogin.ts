import api from "@/lib/api";
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
 * Only the protocol: `state` round-trips through the provider, and the nonce
 * and PKCE verifier never leave the server. What the callback route cannot
 * otherwise know is *which* completion endpoint to post to, because the
 * provider's redirect says nothing about how AXIAM authenticated it.
 *
 * `sessionStorage` rather than `localStorage`: this is per-tab state with a
 * lifetime of one navigation, and a value that outlived the tab would only ever
 * be a stale one.
 */
const PENDING_KEY = "axiam.sso.pending";

interface PendingSso {
  protocol: FederationProtocol;
  /** For the error UI: "Sign in with Okta failed", not "Sign in failed". */
  displayName: string;
}

export function rememberPendingSso(pending: PendingSso): void {
  try {
    sessionStorage.setItem(PENDING_KEY, JSON.stringify(pending));
  } catch {
    // Private browsing, or storage disabled. The callback route falls back to
    // trying the OIDC completion first, which is the common case — so a browser
    // that refuses storage degrades to "OIDC works, OAuth2 needs a retry"
    // rather than to a blank page.
  }
}

export function takePendingSso(): PendingSso | null {
  try {
    const raw = sessionStorage.getItem(PENDING_KEY);
    sessionStorage.removeItem(PENDING_KEY);
    return raw ? (JSON.parse(raw) as PendingSso) : null;
  } catch {
    return null;
  }
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
  }): Promise<StartResponse> =>
    api.post<StartResponse>("/api/v1/auth/federation/oidc/start", body).then((r) => r.data),

  /** Begin a plain-OAuth2 login (GitHub, Facebook, generic). */
  startOauth2: (body: {
    org_slug: string;
    tenant_slug?: string;
    federation_config_id: string;
    redirect_uri: string;
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
