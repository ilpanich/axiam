// oidc.ts — the AXIAM-facing half of this RP: discovery, authorization_code
// + PKCE, RP-Initiated Logout, and Back-Channel Logout token verification.
//
// This deliberately talks to the documented wire protocol directly (plain
// `fetch` + `jose`) rather than depending on the published `axiam-sdk` npm
// package, for the same reason examples/b1-deny-override and
// examples/b2-iot-device-quickstart use plain curl: it can never drift from
// what the wire actually does, and it doubles as a from-scratch reference
// for anyone integrating against AXIAM without that SDK. The function names
// and behavior below track `sdks/CONTRACT.md` §12 / §12.7's canonical
// operations (`oidc_discover`, `oidc_begin`, `oidc_exchange`, `logout_url`,
// `verify_logout_token`) even though this is TypeScript, not the SDK itself.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

export interface OidcDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
  pushed_authorization_request_endpoint?: string;
  backchannel_logout_supported?: boolean;
  [key: string]: unknown;
}

export interface AuthorizationRequest {
  url: string;
  state: string;
  nonce: string;
  codeVerifier: string;
}

export interface OidcTokenSet {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
  refresh_token?: string;
  id_token?: string;
}

export interface IdClaims extends JWTPayload {
  sid?: string;
}

export interface LogoutTokenResult {
  sid: string | undefined;
  sub: string | undefined;
  jti: string;
}

/** `oidc_discover` — `GET /.well-known/openid-configuration`. */
export async function discover(axiamUrl: string): Promise<OidcDiscoveryDocument> {
  const resp = await fetch(`${axiamUrl}/.well-known/openid-configuration`);
  if (!resp.ok) {
    throw new Error(`oidc_discover: ${resp.status} ${await resp.text()}`);
  }
  return (await resp.json()) as OidcDiscoveryDocument;
}

/**
 * `oidc_begin` — pure local computation, no network I/O
 * (`sdks/CONTRACT.md` §12.1). Builds the RFC 7636 §4.1 PKCE pair from a
 * CSPRNG (`node:crypto.randomBytes`), never `Math.random`.
 */
export function beginAuthorization(opts: {
  discovery: OidcDiscoveryDocument;
  clientId: string;
  redirectUri: string;
  scope: string;
}): AuthorizationRequest {
  const state = randomBytes(24).toString("base64url");
  const nonce = randomBytes(24).toString("base64url");
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
  const scope = opts.scope.split(/\s+/).includes("openid")
    ? opts.scope
    : `openid ${opts.scope}`;

  const url = new URL(opts.discovery.authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", opts.clientId);
  url.searchParams.set("redirect_uri", opts.redirectUri);
  url.searchParams.set("scope", scope);
  url.searchParams.set("state", state);
  url.searchParams.set("nonce", nonce);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");

  return { url: url.toString(), state, nonce, codeVerifier };
}

/**
 * `POST /oauth2/par` (RFC 9126, B5) — pushes the authorization request
 * server-side and returns an opaque `request_uri` for the browser redirect,
 * instead of the parameters themselves.
 */
export async function pushAuthorizationRequest(opts: {
  axiamUrl: string;
  tenantId: string;
  clientId: string;
  clientSecret: string;
  authReq: AuthorizationRequest;
  redirectUri: string;
  scope: string;
}): Promise<{ requestUri: string; expiresIn: number }> {
  const url = new URL(opts.authReq.url);
  const body = new URLSearchParams({
    client_id: opts.clientId,
    client_secret: opts.clientSecret,
    response_type: "code",
    redirect_uri: opts.redirectUri,
    scope: url.searchParams.get("scope") ?? opts.scope,
    state: opts.authReq.state,
    code_challenge: url.searchParams.get("code_challenge") ?? "",
    code_challenge_method: "S256",
    nonce: opts.authReq.nonce,
  });
  const resp = await fetch(
    `${opts.axiamUrl}/oauth2/par?tenant_id=${encodeURIComponent(opts.tenantId)}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    },
  );
  if (!resp.ok) {
    throw new Error(`PAR push failed: ${resp.status} ${await resp.text()}`);
  }
  const json = (await resp.json()) as { request_uri: string; expires_in: number };
  return { requestUri: json.request_uri, expiresIn: json.expires_in };
}

/** Builds the `/oauth2/authorize?request_uri=...` redirect for a pushed request. */
export function authorizeUrlFromRequestUri(opts: {
  discovery: OidcDiscoveryDocument;
  clientId: string;
  requestUri: string;
}): string {
  const url = new URL(opts.discovery.authorization_endpoint);
  url.searchParams.set("client_id", opts.clientId);
  url.searchParams.set("request_uri", opts.requestUri);
  return url.toString();
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function jwks(jwksUri: string): ReturnType<typeof createRemoteJWKSet> {
  let set = jwksCache.get(jwksUri);
  if (!set) {
    set = createRemoteJWKSet(new URL(jwksUri));
    jwksCache.set(jwksUri, set);
  }
  return set;
}

/**
 * `oidc_exchange` — `POST /oauth2/token` with `grant_type=authorization_code`,
 * followed by the full `sdks/CONTRACT.md` §12.4 ID-token validation
 * checklist. On any check failing, the WHOLE token set is discarded (§12.4
 * rule 7) — this function throws rather than returning a partially-trusted
 * result.
 */
export async function exchangeCode(opts: {
  axiamUrl: string;
  tenantId: string;
  discovery: OidcDiscoveryDocument;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  code: string;
  codeVerifier: string;
  expectedNonce: string;
}): Promise<{ tokens: OidcTokenSet; idClaims: IdClaims }> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: opts.code,
    code_verifier: opts.codeVerifier,
    redirect_uri: opts.redirectUri,
    client_id: opts.clientId,
    client_secret: opts.clientSecret,
  });
  const resp = await fetch(
    `${opts.axiamUrl}/oauth2/token?tenant_id=${encodeURIComponent(opts.tenantId)}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    },
  );
  const tokens = (await resp.json()) as OidcTokenSet & { error?: string };
  if (!resp.ok || tokens.error) {
    throw new Error(`oidc_exchange: ${resp.status} ${JSON.stringify(tokens)}`);
  }
  if (!tokens.id_token) {
    throw new Error("oidc_exchange: response carried no id_token (was 'openid' requested?)");
  }

  // §12.4 checklist, in order:
  const { payload } = await jwtVerify(tokens.id_token, jwks(opts.discovery.jwks_uri), {
    algorithms: ["EdDSA"], // rule 1 — EdDSA only, never "none", never negotiated from the token
    issuer: opts.discovery.issuer, // rule 3 — exact match
    audience: opts.clientId, // rule 4
    clockTolerance: 60, // rule 5 — at most 60s skew
  });
  // rule 5's exp/iat-required half: `jwtVerify` already rejects a missing/expired
  // `exp`, but `iat` is not enforced-required by the library, so check explicitly.
  if (typeof payload.iat !== "number") {
    throw new Error("oidc_exchange: id_token missing iat");
  }
  // rule 6 — nonce, constant-time compared.
  const nonceClaim = typeof payload["nonce"] === "string" ? payload["nonce"] : "";
  const a = Buffer.from(nonceClaim);
  const b = Buffer.from(opts.expectedNonce);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    throw new Error("oidc_exchange: nonce mismatch");
  }

  return { tokens, idClaims: payload as IdClaims };
}

/**
 * `logout_url` (§12.7.2) — pure local computation. `end_session_endpoint`
 * comes from discovery, never string concatenation; `state` is passed
 * through unmodified and never invented here.
 */
export function logoutUrl(opts: {
  discovery: OidcDiscoveryDocument;
  tenantId: string;
  idToken: string;
  postLogoutRedirectUri?: string;
  state?: string;
}): string {
  if (!opts.discovery.end_session_endpoint) {
    throw new Error("logout_url: discovery document has no end_session_endpoint");
  }
  const url = new URL(opts.discovery.end_session_endpoint);
  // AXIAM is multi-tenant and `tenant_id` is a REQUIRED query parameter on
  // /oauth2/end_session (EndSessionQuery.tenant_id is a non-optional Uuid),
  // exactly as it is on /oauth2/token and /oauth2/device_authorization.
  // OIDC RP-Initiated Logout 1.0 does not define it, so a generic RP library
  // will not send it and the request fails deserialization before the handler
  // runs. Set it first so it survives any later parameter juggling.
  url.searchParams.set("tenant_id", opts.tenantId);
  url.searchParams.set("id_token_hint", opts.idToken);
  if (opts.postLogoutRedirectUri) {
    url.searchParams.set("post_logout_redirect_uri", opts.postLogoutRedirectUri);
  }
  if (opts.state) {
    url.searchParams.set("state", opts.state);
  }
  return url.toString();
}

/**
 * `verify_logout_token` (§12.7.3) — every one of the eight required checks,
 * each because skipping it has a name (see the doc comment on each branch).
 * Returns `{sid, sub, jti}`, never a bare boolean (§12.7.3's "MUST NOT
 * collapse the result" rule): the caller needs to know *which* session to
 * end, and this function has already done every check that lets it be sure.
 */
export async function verifyBackchannelLogoutToken(opts: {
  discovery: OidcDiscoveryDocument;
  clientId: string;
  logoutToken: string;
}): Promise<LogoutTokenResult> {
  // 1/2. Signature, verified against the OP's JWKS (same verifier as
  //      oidc_exchange — no second key-fetching path).
  const { payload } = await jwtVerify(opts.logoutToken, jwks(opts.discovery.jwks_uri), {
    algorithms: ["EdDSA"],
    // 3. iss / 4. aud, exact match — jwtVerify enforces both when given.
    issuer: opts.discovery.issuer,
    audience: opts.clientId,
    clockTolerance: 60,
  });

  // 5. `events` must contain exactly the back-channel-logout key, as an object.
  const events = payload["events"];
  if (
    typeof events !== "object" ||
    events === null ||
    !("http://schemas.openid.net/event/backchannel-logout" in events) ||
    typeof (events as Record<string, unknown>)["http://schemas.openid.net/event/backchannel-logout"] !==
      "object"
  ) {
    throw new Error("verify_logout_token: missing/malformed backchannel-logout events claim");
  }

  // 6. `nonce` MUST be absent — its presence is the signature of a replayed ID token.
  if ("nonce" in payload) {
    throw new Error("verify_logout_token: logout token must not carry a nonce claim");
  }

  // 7. At least one of sid/sub must identify something.
  const sid = typeof payload["sid"] === "string" ? payload["sid"] : undefined;
  const sub = typeof payload.sub === "string" ? payload.sub : undefined;
  if (!sid && !sub) {
    throw new Error("verify_logout_token: neither sid nor sub present");
  }

  // 8. jti surfaced for the caller's own dedup (this function does not dedup —
  //    delivery is at-least-once, and a durable dedup store is the RP's job).
  const jti = typeof payload.jti === "string" ? payload.jti : undefined;
  if (!jti) {
    throw new Error("verify_logout_token: missing jti");
  }

  return { sid, sub, jti };
}
