// Wire types + public result types for REST auth/authz (D-18, FND-04, §1).
//
// Wire* types mirror crates/axiam-api-rest/src/handlers/auth.rs and
// authz_check.rs exactly (snake_case, server response shapes). The public
// LoginResult discriminated union renames challenge_token -> mfaToken per
// §1's camelCase convention and deliberately carries no session token field
// anywhere — tokens arrive exclusively via Set-Cookie (D-05/T-17-07).

import type { AccessDecision } from '../core/index.js';

// ---------------------------------------------------------------------------
// Wire types (snake_case, mirror server handlers)
// ---------------------------------------------------------------------------

export interface LoginUserInfoWire {
  id: string;
  username: string;
  email: string;
}

/** 200 OK body from /api/v1/auth/login, /api/v1/auth/mfa/verify, and (subset) /api/v1/auth/refresh. */
export interface LoginSuccessResponseWire {
  user: LoginUserInfoWire;
  session_id: string;
  expires_in: number;
}

/** 202 Accepted body from /api/v1/auth/login when MFA is required. */
export interface MfaRequiredResponseWire {
  mfa_required: boolean;
  challenge_token: string;
  available_methods: string[];
}

/** 200 OK body from /api/v1/auth/refresh. */
export interface RefreshSuccessResponseWire {
  expires_in: number;
}

// ---------------------------------------------------------------------------
// Public API types (camelCase, D-18)
// ---------------------------------------------------------------------------

/** The authenticated user's identity, as returned by `login()`/`verifyMfa()` on success. */
export interface AxiamUserInfo {
  /** The user's unique identifier (UUID). */
  id: string;
  /** The user's login username. */
  username: string;
  /** The user's email address. */
  email: string;
}

/**
 * The outcome of AxiamClient.login()/verifyMfa() (D-18).
 *
 * No raw session-token field exists here or anywhere else in the public
 * REST API surface — AXIAM delivers tokens exclusively via `Set-Cookie`
 * (T-17-07).
 */
export type LoginResult =
  | {
      /** Discriminant: MFA is required to complete the login. */
      status: 'mfa_required';
      /** Opaque challenge token to pass to `verifyMfa(mfaToken, code)`. */
      mfaToken: string;
      /** The MFA methods the user has enrolled and may complete the challenge with. */
      availableMethods: string[];
    }
  | {
      /** Discriminant: login completed and a session was established. */
      status: 'authenticated';
      /** The authenticated user's identity. */
      user: AxiamUserInfo;
      /** Opaque session identifier for this authenticated session. */
      sessionId: string;
      /** Access token lifetime in seconds from the time of this response. */
      expiresIn: number;
    };

// ---------------------------------------------------------------------------
// Authz types (FND-04, D-08)
// ---------------------------------------------------------------------------

/** A single access check request, as passed to `checkAccess()`/`can()`/`batchCheck()`. */
export interface AccessCheck {
  /** The action being performed (e.g. `"read"`, `"write"`, `"delete"`). */
  action: string;
  /** The identifier of the resource the action targets. */
  resourceId: string;
  /** Optional sub-resource scope for finer-grained checks. */
  scope?: string;
  /** Optional subject (user/service account) identifier to check on behalf of; defaults to the caller's own identity when omitted. */
  subjectId?: string;
}

/**
 * The result of a REST access check (mirrors `CheckAccessResponseWire`).
 * Shared verbatim with the gRPC transport's `AuthzGrpcClient` result shape
 * (SDK-Q10, C2) — defined once in `core/authz.ts` and re-exported here so
 * both `axiam-sdk/rest` and `axiam-sdk/grpc` consumers see the identical
 * `AccessDecision` type.
 */
export type { AccessDecision };

/** Wire body for POST /api/v1/authz/check (mirrors CheckAccessBody). */
export interface CheckAccessBodyWire {
  action: string;
  resource_id: string;
  scope?: string;
  subject_id?: string;
}

/** Wire response for POST /api/v1/authz/check (mirrors CheckAccessResponse). */
export interface CheckAccessResponseWire {
  allowed: boolean;
  reason?: string;
}

/** Wire body for POST /api/v1/authz/check/batch. */
export interface BatchCheckAccessBodyWire {
  checks: CheckAccessBodyWire[];
}

/** Wire response for POST /api/v1/authz/check/batch — results in input order. */
export interface BatchCheckAccessResponseWire {
  results: CheckAccessResponseWire[];
}
