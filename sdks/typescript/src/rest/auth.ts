// login/verifyMfa/refresh/logout over REST (D-18, §1).
//
// Mirrors sdks/rust/src/rest/auth.rs's request/response shapes exactly
// (mirror only, no server crate dependency). Tokens are delivered
// exclusively via Set-Cookie — LoginResult deliberately carries no session
// token field anywhere in the public API (T-17-07).

import { mapHttpStatusToError, NetworkError, sanitizeAxiosError } from '../core/index.js';
import type { AxiamClient } from './client.js';
import type {
  LoginResult,
  LoginSuccessResponseWire,
  MfaRequiredResponseWire,
  RefreshSuccessResponseWire,
} from './types.js';

const LOGIN_PATH = '/api/v1/auth/login';
const MFA_VERIFY_PATH = '/api/v1/auth/mfa/verify';
const REFRESH_PATH = '/api/v1/auth/refresh';
const LOGOUT_PATH = '/api/v1/auth/logout';

interface LoginRequestBody {
  username_or_email: string;
  password: string;
}

interface MfaVerifyRequestBody {
  challenge_token: string;
  totp_code: string;
}

function loginSuccessToResult(wire: LoginSuccessResponseWire): LoginResult {
  return {
    status: 'authenticated',
    user: { id: wire.user.id, username: wire.user.username, email: wire.user.email },
    sessionId: wire.session_id,
    expiresIn: wire.expires_in,
  };
}

function mfaRequiredToResult(wire: MfaRequiredResponseWire): LoginResult {
  return {
    status: 'mfa_required',
    mfaToken: wire.challenge_token,
    availableMethods: wire.available_methods,
  };
}

function extractErrorMessage(err: unknown): string {
  if (err && typeof err === 'object' && 'message' in err && typeof (err as { message?: unknown }).message === 'string') {
    return (err as { message: string }).message;
  }
  return 'request failed';
}

/**
 * `POST /api/v1/auth/login` (§1).
 *
 * On a 200 response returns the authenticated branch of the LoginResult
 * discriminated union; on the MFA-required response (202) returns the
 * mfa_required branch (mfaToken sourced from the wire challenge_token).
 */
export async function login(client: AxiamClient, email: string, password: string): Promise<LoginResult> {
  const body: LoginRequestBody = { username_or_email: email, password };

  try {
    // axios treats any 2xx (including 202 MFA-required) as a resolved
    // response, not a thrown error — branch on the actual status here.
    const response = await client.session.axios.post<LoginSuccessResponseWire | MfaRequiredResponseWire>(
      LOGIN_PATH,
      body,
    );
    if (response.status === 202) {
      return mfaRequiredToResult(response.data as MfaRequiredResponseWire);
    }
    client.session.authenticated = true;
    // CR-01/D-05: sync the Node persona's csrfToken (and cached access token)
    // from the jar now that the session cookie(s) have landed. No-op for the
    // browser SharedSession, which has no onAuthenticated implementation.
    await client.session.onAuthenticated?.();
    return loginSuccessToResult(response.data as LoginSuccessResponseWire);
  } catch (err) {
    const status = extractAxiosStatus(err);
    if (status !== undefined) {
      throw mapHttpStatusToError(status, extractErrorMessage(extractAxiosData(err)) ?? 'login failed', {
        cause: err,
      });
    }
    throw new NetworkError('login request failed', sanitizeAxiosError(err));
  }
}

/**
 * `POST /api/v1/auth/mfa/verify` (§1).
 *
 * Completes the two-phase flow started by login() when status was
 * 'mfa_required', using the caller-supplied mfaToken (the challenge token
 * returned from that prior login() call).
 */
export async function verifyMfa(client: AxiamClient, mfaToken: string, code: string): Promise<LoginResult> {
  const body: MfaVerifyRequestBody = { challenge_token: mfaToken, totp_code: code };

  try {
    const response = await client.session.axios.post<LoginSuccessResponseWire>(MFA_VERIFY_PATH, body);
    client.session.authenticated = true;
    // CR-01/D-05: same post-authentication sync as login()'s 200 branch.
    await client.session.onAuthenticated?.();
    return loginSuccessToResult(response.data);
  } catch (err) {
    const status = extractAxiosStatus(err);
    if (status !== undefined) {
      throw mapHttpStatusToError(status, extractErrorMessage(extractAxiosData(err)) ?? 'verifyMfa failed', {
        cause: err,
      });
    }
    throw new NetworkError('verifyMfa request failed', sanitizeAxiosError(err));
  }
}

/**
 * `POST /api/v1/auth/refresh` (§1).
 *
 * Callers typically do not invoke this directly — the response interceptor
 * (interceptors.ts) drives it reactively via the single-flight guard on a
 * 401 (D-07). Exposed as a public method for explicit proactive refresh.
 */
export async function refresh(client: AxiamClient): Promise<void> {
  try {
    await client.session.axios.post<RefreshSuccessResponseWire>(REFRESH_PATH, {});
  } catch (err) {
    const status = extractAxiosStatus(err);
    if (status !== undefined) {
      // §9.3: 401 on the refresh call itself is AuthError, no retry loop.
      throw mapHttpStatusToError(status, extractErrorMessage(extractAxiosData(err)) ?? 'refresh failed', {
        cause: err,
      });
    }
    throw new NetworkError('refresh request failed', sanitizeAxiosError(err));
  }
}

/**
 * `POST /api/v1/auth/logout` (§1).
 *
 * Clears session csrf/auth state regardless of the response outcome once
 * the request has been sent successfully.
 */
export async function logout(client: AxiamClient): Promise<void> {
  try {
    await client.session.axios.post(LOGOUT_PATH, {});
  } catch (err) {
    const status = extractAxiosStatus(err);
    if (status !== undefined) {
      throw mapHttpStatusToError(status, extractErrorMessage(extractAxiosData(err)) ?? 'logout failed', {
        cause: err,
      });
    }
    throw new NetworkError('logout request failed', sanitizeAxiosError(err));
  } finally {
    client.session.authenticated = false;
    client.session.csrfToken = undefined;
  }
}

// ---------------------------------------------------------------------------
// axios error helpers (kept local — core stays dependency-free of axios)
// ---------------------------------------------------------------------------

function extractAxiosStatus(err: unknown): number | undefined {
  if (err && typeof err === 'object' && 'response' in err) {
    const response = (err as { response?: { status?: number } }).response;
    return response?.status;
  }
  return undefined;
}

function extractAxiosData<T>(err: unknown): T | undefined {
  if (err && typeof err === 'object' && 'response' in err) {
    const response = (err as { response?: { data?: T } }).response;
    return response?.data;
  }
  return undefined;
}
