// resource-server.ts — the resource-server half of the MCP authorization
// handshake: RFC 9728 protected-resource metadata, the RFC 6750
// `WWW-Authenticate` challenge, and the `aud`-checking guard that decides
// whether a request reaches an MCP tool.
//
// `sdks/CONTRACT.md` §28 ("MCP Resource-Server Helpers") is the normative
// specification this file implements. It is written by hand against `jose`
// rather than imported from the published `axiam-sdk` package, for the same
// reason `examples/b5-rp-logout-app/src/oidc.ts` hand-rolls CONTRACT §12
// against `jose` instead of depending on the SDK: it can never drift from
// what the wire actually does, and it is a from-scratch reference for anyone
// integrating against AXIAM in a language with no SDK yet.
//
// As of this writing `axiam-sdk`'s published npm package (`1.0.0-beta15`)
// does not yet export the §28 operations — the TypeScript reference
// implementation (T21.9b) had not been published when this example was
// written. Once it is, the three functions below should be deleted in favor
// of `import { protectedResourceMetadata, serveProtectedResourceMetadata,
// bearerChallenge } from "axiam-sdk/middleware"`, and `requireBearerAuth`
// below should build on `axiamMiddleware`'s `expectedAudience` option
// (already published) plus the `resource_metadata_url` option §28.5 adds.
// See this example's README for what is actually verified today.

import { createRemoteJWKSet, jwtVerify } from "jose";
import type { Express, NextFunction, Request, RequestHandler, Response } from "express";

/** RFC 9728 §2 — the document, exactly as §28.2 orders its members. */
export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  scopes_supported?: string[];
  bearer_methods_supported: string[];
  resource_documentation?: string;
}

export interface ProtectedResourceMetadataResult {
  document: ProtectedResourceMetadata;
  /** The path the document is served at (§28.3). */
  metadataPath: string;
  /** `metadataPath` resolved against `resource`'s scheme and authority. */
  metadataUrl: string;
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "localhost"]);

function requireHttpsOrLoopback(url: URL, label: string): void {
  if (url.protocol === "https:") return;
  if (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)) return;
  throw new Error(
    `${label}: scheme must be https, or http on a loopback host (127.0.0.1, [::1], localhost) — got ${url.toString()}`,
  );
}

/**
 * `protected_resource_metadata` (CONTRACT §28.1/§28.2) — pure local
 * computation, no network I/O. Validates and refuses; never repairs.
 */
export function protectedResourceMetadata(opts: {
  resource: string;
  authorizationServers: string[];
  scopesSupported?: string[];
  bearerMethodsSupported?: string[];
  resourceDocumentation?: string;
}): ProtectedResourceMetadataResult {
  const resourceUrl = new URL(opts.resource);
  if (resourceUrl.search || resourceUrl.hash) {
    throw new Error("protected_resource_metadata: resource must carry no query and no fragment");
  }
  requireHttpsOrLoopback(resourceUrl, "protected_resource_metadata: resource");

  if (opts.authorizationServers.length === 0) {
    throw new Error("protected_resource_metadata: authorization_servers must be non-empty");
  }
  const seenServers = new Set<string>();
  for (const entry of opts.authorizationServers) {
    const u = new URL(entry);
    if (u.search || u.hash) {
      throw new Error(`protected_resource_metadata: authorization_servers entry carries a query or fragment: ${entry}`);
    }
    if (seenServers.has(entry)) {
      throw new Error(`protected_resource_metadata: duplicate authorization_servers entry: ${entry}`);
    }
    seenServers.add(entry);
  }

  const bearerMethods = opts.bearerMethodsSupported ?? ["header"];
  if (bearerMethods.length !== 1 || bearerMethods[0] !== "header") {
    throw new Error('protected_resource_metadata: bearer_methods_supported must be exactly ["header"] in this contract version');
  }

  const scopes = opts.scopesSupported ?? [];
  if (new Set(scopes).size !== scopes.length) {
    throw new Error("protected_resource_metadata: scopes_supported contains a duplicate");
  }

  let resourceDocumentation: string | undefined;
  if (opts.resourceDocumentation !== undefined) {
    const u = new URL(opts.resourceDocumentation);
    requireHttpsOrLoopback(u, "protected_resource_metadata: resource_documentation");
    resourceDocumentation = opts.resourceDocumentation;
  }

  const path = resourceUrl.pathname === "/" ? "" : resourceUrl.pathname;
  const metadataPath = `/.well-known/oauth-protected-resource${path}`;
  const metadataUrl = `${resourceUrl.protocol}//${resourceUrl.host}${metadataPath}`;

  const document: ProtectedResourceMetadata = {
    resource: opts.resource,
    authorization_servers: opts.authorizationServers,
    bearer_methods_supported: bearerMethods,
    ...(scopes.length > 0 ? { scopes_supported: scopes } : {}),
    ...(resourceDocumentation !== undefined ? { resource_documentation: resourceDocumentation } : {}),
  };

  return { document, metadataPath, metadataUrl };
}

/**
 * `serve_protected_resource_metadata` (CONTRACT §28.3) — registers exactly
 * one unauthenticated `GET` route, identical for every caller.
 */
export function serveProtectedResourceMetadata(
  app: Express,
  metadata: ProtectedResourceMetadataResult,
): string {
  app.get(metadata.metadataPath, (_req, res) => {
    res.set("Cache-Control", "public, max-age=3600");
    res.set("Access-Control-Allow-Origin", "*");
    res.status(200).json(metadata.document);
  });
  return metadata.metadataUrl;
}

const NQCHAR = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
const NQSCHAR = /^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/;

function quote(value: string): string {
  if (/["\\]/.test(value)) {
    throw new Error(`bearer_challenge: value must not contain a quote or backslash: ${value}`);
  }
  return `"${value}"`;
}

/**
 * `bearer_challenge` (CONTRACT §28.4) — returns the `WWW-Authenticate`
 * VALUE only, never the whole header line. Parameter order is fixed:
 * error, error_description, scope, resource_metadata.
 */
export function bearerChallenge(opts: {
  resourceMetadataUrl: string;
  error?: "invalid_request" | "invalid_token" | "insufficient_scope";
  errorDescription?: string;
  scope?: string;
}): string {
  const parts = ["Bearer"];
  const params: string[] = [];
  if (opts.error !== undefined) {
    params.push(`error=${quote(opts.error)}`);
  }
  if (opts.errorDescription !== undefined) {
    if (!NQSCHAR.test(opts.errorDescription)) {
      throw new Error("bearer_challenge: error_description contains a disallowed character");
    }
    params.push(`error_description=${quote(opts.errorDescription)}`);
  }
  if (opts.scope !== undefined) {
    const tokens = opts.scope.split(" ");
    if (opts.scope === "" || tokens.some((t) => t === "" || !NQCHAR.test(t))) {
      throw new Error("bearer_challenge: scope is empty, has doubled/leading/trailing spaces, or an empty token");
    }
    params.push(`scope=${quote(opts.scope)}`);
  }
  const metaUrl = new URL(opts.resourceMetadataUrl);
  requireHttpsOrLoopback(metaUrl, "bearer_challenge: resource_metadata");
  if (/["\\\s]/.test(opts.resourceMetadataUrl)) {
    throw new Error("bearer_challenge: resource_metadata must carry no quote, backslash or space");
  }
  params.push(`resource_metadata=${quote(opts.resourceMetadataUrl)}`);

  return `${parts.join(" ")} ${params.join(", ")}`;
}

/** The identity the guard injects once a bearer token verifies (mirrors AxiamIdentity, CONTRACT §10). */
export interface AxiamIdentity {
  userId: string;
  tenantId: string;
  roles: string[];
}

export interface McpRequest extends Request {
  axiamUser?: AxiamIdentity;
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

export interface RequireBearerAuthOptions {
  /** AXIAM's `jwks_uri`, from its discovery document. */
  jwksUri: string;
  /** AXIAM's `issuer`, from its discovery document (CONTRACT §10.1 rule 5). */
  issuer: string;
  /**
   * CONTRACT §10.1 rule 6 / §28.5 rule 2 — the resource this server is. MUST
   * equal the `resource` published in the protected-resource metadata
   * document (§28.5 rule 3); this guard does not check that agreement itself
   * (server.ts constructs both from the same constant, which is what CONTRACT
   * §28.1's `metadata_url`/`metadata_path` accessors exist to make easy).
   */
  expectedAudience: string;
  /** §28.5 rule 1 — the URL every 401/403 this guard emits points at. */
  resourceMetadataUrl: string;
}

/**
 * `axiamMiddleware` + the §28.5 challenge, in one guard. §10.1's audience
 * check (rule 6) and §28's challenge are inseparable here on purpose: this
 * example has no route that is guarded without also being announced.
 */
export function requireBearerAuth(opts: RequireBearerAuthOptions): RequestHandler {
  return async (req: McpRequest, res: Response, next: NextFunction) => {
    const header = req.headers.authorization;
    const token = typeof header === "string" && header.startsWith("Bearer ") ? header.slice(7) : undefined;

    if (!token) {
      // RFC 6750 §3 — no credential presented, so `error` is absent (CONTRACT §28.4).
      res.setHeader("WWW-Authenticate", bearerChallenge({ resourceMetadataUrl: opts.resourceMetadataUrl }));
      res.status(401).json({ error: "authentication_failed", message: "no bearer credential presented" });
      return;
    }

    try {
      const { payload } = await jwtVerify(token, jwks(opts.jwksUri), {
        algorithms: ["EdDSA"],
        issuer: opts.issuer,
        audience: opts.expectedAudience,
        clockTolerance: 60,
      });
      const tenantId = typeof payload["tenant_id"] === "string" ? payload["tenant_id"] : "";
      const scope = typeof payload["scope"] === "string" ? payload["scope"] : "";
      req.axiamUser = {
        userId: typeof payload.sub === "string" ? payload.sub : "",
        tenantId,
        roles: scope.split(/\s+/).filter(Boolean),
      };
      next();
    } catch {
      // Expired, wrong tenant, wrong audience, bad signature: one answer,
      // deliberately (CONTRACT §28.4 — these are all `invalid_token`).
      res.setHeader(
        "WWW-Authenticate",
        bearerChallenge({ resourceMetadataUrl: opts.resourceMetadataUrl, error: "invalid_token" }),
      );
      res.status(401).json({ error: "authentication_failed", message: "invalid or expired token" });
    }
  };
}

/**
 * `require_access`'s §28.5-rule-5 sibling: a route that names a scope and
 * finds it missing answers 403 `insufficient_scope`, carrying the challenge.
 * A route with no scope requirement never calls this.
 */
export function requireScope(scope: string, resourceMetadataUrl: string): RequestHandler {
  return (req: McpRequest, res: Response, next: NextFunction) => {
    if (req.axiamUser?.roles.includes(scope)) {
      next();
      return;
    }
    res.setHeader(
      "WWW-Authenticate",
      bearerChallenge({ resourceMetadataUrl, error: "insufficient_scope", scope }),
    );
    res.status(403).json({ error: "authorization_denied", message: `missing scope: ${scope}` });
  };
}
