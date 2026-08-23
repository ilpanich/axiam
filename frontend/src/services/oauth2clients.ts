import api from "@/lib/api";
import { fetchAllPages } from "@/services/_pagination";

// ─── Domain Models ────────────────────────────────────────────────────────────

/**
 * X5.1 — the security posture a client is registered under.
 *
 * `fapi2` turns on the whole FAPI 2.0 constraint bundle at once; the backend
 * refuses the registration unless PAR, a strong auth method and at least one
 * sender-constraining mechanism come with it (see {@link validateClientPosture},
 * which mirrors `axiam_oauth2::fapi::validate_registration`).
 */
export const CLIENT_PROFILES = ["standard", "fapi2"] as const;
export type ClientProfile = (typeof CLIENT_PROFILES)[number];

/** X5.1 — how a client authenticates at the token endpoint (RFC 8705 §2). */
export const CLIENT_AUTH_METHODS = [
  "client_secret_post",
  "tls_client_auth",
  "self_signed_tls_client_auth",
  "private_key_jwt",
] as const;
export type ClientAuthMethod = (typeof CLIENT_AUTH_METHODS)[number];

/**
 * The two methods FAPI 2.0 §5.3.1.1 accepts, mirroring
 * `ClientAuthMethod::is_strong` on the backend. `client_secret_post` is the
 * only weak one, but this is written as an allow-list so a future strong
 * method joins by being listed rather than by not being excluded.
 */
export const STRONG_AUTH_METHODS: readonly ClientAuthMethod[] = [
  "tls_client_auth",
  "self_signed_tls_client_auth",
  "private_key_jwt",
];

export function isStrongAuthMethod(m: ClientAuthMethod): boolean {
  return STRONG_AUTH_METHODS.includes(m);
}

export interface OAuth2Client {
  id: string;
  client_id: string;
  name: string;
  redirect_uris: string[];
  grant_types: string[];
  scopes: string[];
  created_at: string;
  // ─── X5.1 security posture ─────────────────────────────────────────────────
  // All optional: a server that predates X5.1 (or the create response DTO,
  // which still omits them) simply leaves them undefined, and the page falls
  // back to the same defaults the backend applies.
  profile?: ClientProfile;
  token_endpoint_auth_method?: ClientAuthMethod;
  /** RFC 8705 §2.1.2 — expected certificate subject DN, RFC 4514 form. */
  tls_client_auth_subject_dn?: string;
  /** RFC 8705 §2.1.2 — expected `dNSName` SAN. */
  tls_client_auth_san_dns?: string;
  /** RFC 8705 §2.1.2 — expected `uniformResourceIdentifier` SAN. */
  tls_client_auth_san_uri?: string;
  /** base64url-unpadded SHA-256 digests of the DER certificate (`x5t#S256`). */
  self_signed_tls_client_auth_thumbprints?: string[];
  /** RFC 8705 §3.4 — issue certificate-bound access tokens. */
  tls_client_certificate_bound_access_tokens?: boolean;
  /** RFC 7591 §2 — inline public key set for `private_key_jwt`. */
  jwks?: string;
  /** RFC 7591 §2 — where the client publishes its public key set. */
  jwks_uri?: string;
  /** RFC 9449 §5.2 — issue DPoP-bound access tokens. */
  dpop_bound_access_tokens?: boolean;
  /**
   * RFC 9449 §8. **Not implemented in this build (SEC-097)** — the backend
   * refuses `true` with a 400 and nothing reads the stored value, so the admin
   * UI deliberately offers no control for it and only ever reads it back.
   */
  dpop_require_nonce?: boolean;
  /** RFC 9126 — require pushed authorization requests. */
  require_par?: boolean;
  /**
   * B5 — RP-initiated logout allow-list and back-channel logout delivery
   * URI. KNOWN BACKEND GAP (R4.2d residual): `OAuth2ClientResponse` in
   * `crates/axiam-api-rest/src/handlers/oauth2_clients.rs` does not
   * serialize these two fields today, even though `Create`/`UpdateOAuth2ClientRequest`
   * both accept and persist them — so a PUT that sets them succeeds, but
   * GET/list responses come back without them and this page cannot show the
   * currently-saved value until that response DTO is fixed server-side.
   * Optional here (rather than required) so that gap doesn't crash the page.
   */
  post_logout_redirect_uris?: string[];
  backchannel_logout_uri?: string | null;
}

// ─── Request payloads ─────────────────────────────────────────────────────────

/**
 * The X5.1 posture fields, shared by the create and update payloads.
 *
 * `dpop_require_nonce` is absent on purpose — see
 * {@link OAuth2Client.dpop_require_nonce}. Sending `false` would be accepted
 * but says nothing; sending `true` is refused.
 */
export interface ClientPosturePayload {
  profile?: ClientProfile;
  token_endpoint_auth_method?: ClientAuthMethod;
  tls_client_auth_subject_dn?: string;
  tls_client_auth_san_dns?: string;
  tls_client_auth_san_uri?: string;
  self_signed_tls_client_auth_thumbprints?: string[];
  tls_client_certificate_bound_access_tokens?: boolean;
  jwks?: string;
  jwks_uri?: string;
  dpop_bound_access_tokens?: boolean;
  require_par?: boolean;
}

export interface CreateOAuth2ClientPayload extends ClientPosturePayload {
  name: string;
  redirect_uris: string[];
  grant_types: string[];
  scopes?: string[];
  post_logout_redirect_uris?: string[];
  backchannel_logout_uri?: string;
}

export interface UpdateOAuth2ClientPayload extends ClientPosturePayload {
  name?: string;
  redirect_uris?: string[];
  grant_types?: string[];
  scopes?: string[];
  post_logout_redirect_uris?: string[];
  /** Pass "" to clear a previously registered URI (mirrors the backend). */
  backchannel_logout_uri?: string;
}

// ─── Response types ───────────────────────────────────────────────────────────

// Client creation returns the client fields plus the one-time plaintext secret.
export interface CreateOAuth2ClientResponse extends OAuth2Client {
  client_secret: string;
}

// ─── Available options ────────────────────────────────────────────────────────

export const GRANT_TYPES = [
  "authorization_code",
  "client_credentials",
  "refresh_token",
] as const;

export type GrantType = (typeof GRANT_TYPES)[number];

export const OAUTH2_SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access",
  // X2 — the scope that makes an access token a UMA Protection API Token.
  // Without it in this list a resource server cannot be onboarded to the UMA
  // Protection API from the admin UI at all: `/uma2/perm` and
  // `/uma2/rreg/resource_set` both refuse a token that does not carry it.
  "uma_protection",
] as const;

export type OAuth2Scope = (typeof OAUTH2_SCOPES)[number];

/** Scopes whose meaning is not obvious from the bare string. */
export const OAUTH2_SCOPE_HINTS: Record<string, string> = {
  uma_protection:
    "Marks this client as a UMA resource server — required to mint permission tickets and register resource sets.",
};

// ─── Registration validation ──────────────────────────────────────────────────

/** base64url-unpadded SHA-256, mirroring `THUMBPRINT_LEN` on the backend. */
const THUMBPRINT_LEN = 43;

function isWellformedThumbprint(value: string): boolean {
  return value.length === THUMBPRINT_LEN && /^[A-Za-z0-9_-]+$/.test(value);
}

function nonBlank(value: string | undefined): string | undefined {
  const t = value?.trim();
  return t ? t : undefined;
}

/**
 * Client-side mirror of `axiam_oauth2::fapi::validate_registration`.
 *
 * The backend runs the authoritative check and refuses a bad registration with
 * a 400 either way — this exists so an operator building a FAPI 2.0 client
 * sees *which* constraint is unmet while they are still filling the form,
 * rather than as one opaque server error after submitting. The rules are in
 * the same order as the backend's, so the two agree about which constraint
 * fails first.
 *
 * One check is deliberately weaker: the backend parses the inline JWKS as a
 * `jsonwebtoken::jwk::JwkSet`, which rejects well-formed JSON that is not a
 * key set; this only checks that it parses as JSON, because reimplementing JWK
 * validation in the browser would be a second, drifting opinion about key
 * material. A JWKS that is valid JSON but not a valid key set therefore passes
 * here and is refused by the server — a later error, never a missed one.
 *
 * Returns `null` when the posture is valid.
 */
export function validateClientPosture(p: ClientPosturePayload): string | null {
  const method = p.token_endpoint_auth_method ?? "client_secret_post";
  const thumbprints = p.self_signed_tls_client_auth_thumbprints ?? [];

  // RFC 8705 / RFC 7591 consistency — applies to any client using a strong
  // method, whatever profile it declares.
  if (method === "tls_client_auth") {
    const bindings = [
      p.tls_client_auth_subject_dn,
      p.tls_client_auth_san_dns,
      p.tls_client_auth_san_uri,
    ].filter((v) => nonBlank(v) !== undefined).length;
    if (bindings !== 1) {
      return `tls_client_auth requires exactly one of Subject DN, SAN dNSName or SAN URI — ${bindings} registered.`;
    }
  }

  if (method === "self_signed_tls_client_auth" && thumbprints.length === 0) {
    return "self_signed_tls_client_auth requires at least one certificate thumbprint.";
  }

  if (method === "private_key_jwt") {
    const sources = [p.jwks, p.jwks_uri].filter(
      (v) => nonBlank(v) !== undefined
    ).length;
    if (sources !== 1) {
      return `private_key_jwt requires exactly one of JWKS or JWKS URI — ${sources} registered.`;
    }
  }

  // Thumbprints are checked whenever any are registered, even under a method
  // that does not use them: a malformed value in the row is a landmine for the
  // day somebody switches the method.
  for (const t of thumbprints) {
    if (!isWellformedThumbprint(t)) {
      return `"${t}" is not a well-formed thumbprint (expected ${THUMBPRINT_LEN} base64url characters).`;
    }
  }

  const jwks = nonBlank(p.jwks);
  if (jwks !== undefined) {
    try {
      JSON.parse(jwks);
    } catch {
      return "JWKS must be a valid JSON document.";
    }
  }

  // Matches `is_https_absolute`: a case-insensitive prefix test that also
  // requires something after the scheme, deliberately not a URL parse — the
  // real fetch guard is the SSRF-checked JWKS cache, and a second, weaker URL
  // parser here would only be a second opinion about what counts as a URL.
  const jwksUri = nonBlank(p.jwks_uri);
  if (
    jwksUri !== undefined &&
    !(
      jwksUri.length > "https://".length &&
      jwksUri.slice(0, 8).toLowerCase() === "https://"
    )
  ) {
    return "JWKS URI must be an absolute https URL.";
  }

  // The profile bundle. A standard client stops here.
  if (p.profile !== "fapi2") return null;

  if (!p.require_par) {
    return "A fapi2 client must require pushed authorization requests (PAR).";
  }
  if (!isStrongAuthMethod(method)) {
    return `A fapi2 client cannot authenticate with ${method} — use an mTLS method or private_key_jwt.`;
  }
  if (
    !p.tls_client_certificate_bound_access_tokens &&
    !p.dpop_bound_access_tokens
  ) {
    return "A fapi2 client must sender-constrain its tokens — enable certificate-bound or DPoP-bound access tokens.";
  }

  return null;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const oauth2ClientService = {
  list: (): Promise<OAuth2Client[]> =>
    fetchAllPages<OAuth2Client>("/api/v1/oauth2-clients"),

  create: (payload: CreateOAuth2ClientPayload): Promise<CreateOAuth2ClientResponse> =>
    api
      .post<CreateOAuth2ClientResponse>("/api/v1/oauth2-clients", payload)
      .then((r) => r.data),

  get: (id: string): Promise<OAuth2Client> =>
    api.get<OAuth2Client>(`/api/v1/oauth2-clients/${id}`).then((r) => r.data),

  update: (id: string, payload: UpdateOAuth2ClientPayload): Promise<OAuth2Client> =>
    api
      .put<OAuth2Client>(`/api/v1/oauth2-clients/${id}`, payload)
      .then((r) => r.data),

  remove: (id: string): Promise<void> =>
    api.delete(`/api/v1/oauth2-clients/${id}`).then(() => undefined),
};
