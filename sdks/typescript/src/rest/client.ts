// AxiamClient — the isomorphic REST + auth core (D-01/D-25).
//
// Constructor validates the required tenant (§5), builds the SharedSession
// (D-13), and installs the CSRF + reactive single-flight refresh
// interceptors (D-05/D-07). REST method implementations (login/verifyMfa/
// refresh/logout/checkAccess/can/batchCheck) are added by Task 2's
// auth.ts/authz.ts, which extend this class's prototype.

import type { AxiamClientOptions } from '../core/index.js';
import { createSession, SharedSession } from './session.js';
import { installInterceptors } from './interceptors.js';
import * as authMethods from './auth.js';
import * as authzMethods from './authz.js';
import type { AccessCheck, AccessDecision, LoginResult } from './types.js';

/**
 * The main entry point for the AXIAM TypeScript/JavaScript SDK — an
 * isomorphic (browser + Node) REST client for authentication and
 * authorization against an AXIAM server.
 *
 * @remarks
 * `AxiamClient` implements the SDK's cross-language behavioral contract
 * (see `CONTRACT.md` §1–§10): the canonical `login`/`verifyMfa`/`refresh`/
 * `logout`/`checkAccess`/`can`/`batchCheck` method vocabulary (§1), the
 * three-way `AuthError`/`AuthzError`/`NetworkError` taxonomy (§2), automatic
 * CSRF forwarding (§3), the required tenant context (§5), and a per-instance
 * single-flight refresh guard that de-duplicates concurrent token refreshes
 * (§9).
 *
 * A `tenantSlug` or `tenantId` is mandatory at construction — there is no
 * default tenant, and AXIAM is a multi-tenant system where every
 * authenticated call is scoped by the `X-Tenant-ID` header this client
 * injects on every request (§5). Session tokens never appear as a return
 * value or public property anywhere on this class: they arrive exclusively
 * via `httpOnly` cookies set by the server.
 *
 * @example
 * ```ts
 * const client = new AxiamClient({ baseUrl: 'https://iam.example.com', tenantSlug: 'acme' });
 *
 * const result = await client.login('user@example.com', 'hunter2');
 * if (result.status === 'mfa_required') {
 *   await client.verifyMfa(result.mfaToken, '123456');
 * }
 *
 * const decision = await client.checkAccess({ action: 'read', resourceId: 'document:42' });
 * if (!decision.allowed) {
 *   throw new Error(decision.reason ?? 'access denied');
 * }
 * ```
 */
export class AxiamClient {
  /** @internal — exposed for auth.ts/authz.ts method implementations and other transports (D-13). */
  readonly session: SharedSession;

  /**
   * @param options client configuration (§5/§6).
   * @param session optional pre-built session to adopt instead of the default
   *   browser `SharedSession`. This is the injection point for the Node
   *   persona (SDK-Q05): a Node REST consumer builds a `NodeSession` (cookie
   *   jar + CSRF/refresh token sync) via `createNodeClient`/`createNodeSession`
   *   from the Node-only `axiam-sdk/node` (or `axiam-sdk/grpc`) subpath and it
   *   is adopted here, so httpOnly login/refresh cookies persist. When omitted
   *   the browser `SharedSession` is built by default — the Node modules are
   *   NEVER statically imported from this browser-safe module, so a `/rest`
   *   browser bundle keeps pulling zero Node dependencies (SC#1).
   */
  constructor(options: AxiamClientOptions, session?: SharedSession) {
    this.session = session ?? createSession(options);
    installInterceptors(this.session.axios, this.session);
  }

  /** `POST /api/v1/auth/login` (§1, D-18). */
  login(email: string, password: string): Promise<LoginResult> {
    return authMethods.login(this, email, password);
  }

  /** `POST /api/v1/auth/mfa/verify` (§1, D-18). Completes the two-phase flow started by login(). */
  verifyMfa(mfaToken: string, code: string): Promise<LoginResult> {
    return authMethods.verifyMfa(this, mfaToken, code);
  }

  /** `POST /api/v1/auth/refresh` (§1). Usually driven reactively by the response interceptor (D-07). */
  refresh(): Promise<void> {
    return authMethods.refresh(this);
  }

  /** `POST /api/v1/auth/logout` (§1). Clears session csrf/auth state. */
  logout(): Promise<void> {
    return authMethods.logout(this);
  }

  /** `POST /api/v1/authz/check` (§1, FND-04). */
  checkAccess(check: AccessCheck): Promise<AccessDecision> {
    return authzMethods.checkAccess(this, check);
  }

  /** `can` — alias for checkAccess targeting browser/UI scenarios (§1 note). */
  can(action: string, resourceId: string, scope?: string): Promise<boolean> {
    return authzMethods.can(this, action, resourceId, scope);
  }

  /** `POST /api/v1/authz/check/batch` (§1). Results preserve input order. */
  batchCheck(checks: AccessCheck[]): Promise<AccessDecision[]> {
    return authzMethods.batchCheck(this, checks);
  }
}
