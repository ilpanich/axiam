import api from "@/lib/api";
import type { OpaqueEnrollment } from "@/services/opaque";

// ─── Request payloads ─────────────────────────────────────────────────────────

/**
 * Backend `RequestResetBody` (crates/axiam-api-rest/src/handlers/password_reset.rs)
 * accepts an OPTIONAL org/tenant slug pair (the forgot-password page has no
 * tenant_id yet — Open Question 1 / D-04). No user-typed tenant field, no
 * email-domain inference: the slug must come from the URL the page was
 * loaded with.
 */
export interface RequestPasswordResetPayload {
  email: string;
  org_slug?: string;
  tenant_slug?: string;
}

export interface ConfirmPasswordResetPayload {
  tenant_id: string;
  token: string;
  new_password: string;
}

export interface ChangePasswordPayload {
  current_password: string;
  new_password: string;
}

export interface ConfirmMfaPayload {
  code: string;
}

// ─── Response types ───────────────────────────────────────────────────────────

export interface MfaEnrollResponse {
  /** Base32-encoded TOTP shared secret (backend field: `secret_base32`). */
  secret_base32: string;
  /** otpauth:// provisioning URI for QR generation (backend field: `totp_uri`). */
  totp_uri: string;
}

// ─── Auth service ─────────────────────────────────────────────────────────────

export const authService = {
  /**
   * Request a password-reset email.
   * POST /api/v1/auth/reset
   *
   * Backend `RequestResetBody` accepts an optional `org_slug`/`tenant_slug`
   * pair (D-04 / Open Question 1) — the forgot-password page carries the
   * tenant slug in its own URL (no user-typed tenant field, no
   * email-domain inference). Enumeration-safety (D-05) is preserved even
   * when the slug is unresolvable or omitted.
   */
  requestPasswordReset: (
    email: string,
    orgSlug?: string,
    tenantSlug?: string
  ): Promise<void> =>
    api
      .post<void>("/api/v1/auth/reset", {
        email,
        org_slug: orgSlug,
        tenant_slug: tenantSlug,
      })
      .then(() => undefined),

  /**
   * Confirm a password reset using the token from the email link.
   * POST /api/v1/auth/reset/confirm
   *
   * Backend `ConfirmResetBody` requires `tenant_id` (a UUID) — the emailed
   * reset link carries it directly (Open Question 2, mirroring the
   * already-shipped VerifyEmailPage `?token=…&tenant_id=…` pattern) — see
   * ResetPasswordPage.
   */
  confirmPasswordReset: (
    tenantId: string,
    token: string,
    new_password: string,
    /**
     * OPAQUE registration record for the new password, when the tenant uses it.
     *
     * Reset has to carry one or it becomes the hole in OPAQUE coverage: a
     * tenant could run `opaque_mode: required` while every "forgot password" put a
     * plaintext on the wire and left the account holding a verifier for a
     * password it no longer has.
     */
    opaque?: OpaqueEnrollment | null
  ): Promise<void> =>
    api
      .post<void>("/api/v1/auth/reset/confirm", {
        tenant_id: tenantId,
        token,
        new_password,
        ...(opaque ? { opaque } : {}),
      })
      .then(() => undefined),

  /**
   * Verify an email address via the token from the verification email.
   * POST /api/v1/auth/verify-email
   *
   * Backend `VerifyEmailRequest` requires BOTH `tenant_id` (a UUID) and
   * `token` (crates/axiam-api-rest/src/handlers/email_verification.rs).
   * The tenant id must therefore be carried by the verification link
   * (e.g. as a `tenant_id` query param) — see VerifyEmailPage.
   */
  verifyEmail: (tenantId: string, token: string): Promise<void> =>
    api
      .post<void>("/api/v1/auth/verify-email", { tenant_id: tenantId, token })
      .then(() => undefined),

  /**
   * Resend the email verification message.
   * POST /api/v1/auth/resend-verification
   *
   * Despite living behind an authenticated page (ProfilePage), this is a
   * PUBLIC/unauthenticated backend route — `ResendVerificationRequest`
   * requires BOTH `tenant_id` (a UUID) AND `email` in the body (23-RESEARCH
   * Pitfall 4). The caller must supply both from the current auth context.
   */
  /**
   * Resend the *signed-in* user's verification email, and report what happened.
   *
   * `resendVerification` below is the public, unauthenticated endpoint, and it
   * answers a constant 200 whatever the outcome — it has to, since a caller
   * supplies an arbitrary address and any variation would say which addresses
   * have accounts. That made the profile page's button report success while
   * doing nothing: already verified, account locked, daily limit reached and
   * "mail enqueued" all looked identical.
   *
   * Here the caller is authenticated and asking about its own record, so
   * nothing is disclosed by answering honestly. Rejects with a 409 when the
   * address is already verified or the account may not be sent one, and a 429
   * at the daily limit.
   */
  resendOwnVerification: (): Promise<void> =>
    api.post<void>("/api/v1/users/me/resend-verification").then(() => undefined),

  resendVerification: (tenantId: string, email: string): Promise<void> =>
    api
      .post<void>("/api/v1/auth/resend-verification", {
        tenant_id: tenantId,
        email,
      })
      .then(() => undefined),

  /**
   * Change the currently-authenticated user's password.
   * POST /api/v1/auth/password/change
   */
  changePassword: (
    current_password: string,
    new_password: string,
    /** OPAQUE registration record for the new password, when the tenant uses it. */
    opaque?: OpaqueEnrollment | null
  ): Promise<void> =>
    api
      .post<void>("/api/v1/auth/password/change", {
        current_password,
        new_password,
        ...(opaque ? { opaque } : {}),
      })
      .then(() => undefined),

  /**
   * Begin TOTP MFA enrollment for the authenticated user — returns the
   * shared secret + otpauth URI. Uses the self-service enroll endpoint
   * (the `/mfa/setup/*` variants require a login-issued setup_token and
   * are only for the partial-login MFA-setup flow).
   * POST /api/v1/auth/mfa/enroll
   */
  enrollMfa: (): Promise<MfaEnrollResponse> =>
    api
      .post<MfaEnrollResponse>("/api/v1/auth/mfa/enroll")
      .then((r) => r.data),

  /**
   * Confirm TOTP MFA enrollment with a 6-digit code.
   * POST /api/v1/auth/mfa/confirm  (body: { totp_code })
   */
  confirmMfa: (code: string): Promise<void> =>
    api
      .post<void>("/api/v1/auth/mfa/confirm", { totp_code: code })
      .then(() => undefined),

  /**
   * Begin TOTP MFA enrollment during the MFA-mandated login flow
   * (CORR-05b / D-16). Unlike `enrollMfa`, this variant carries a
   * login-issued `setup_token` instead of relying on an authenticated
   * session — it backs the public `/auth/mfa-setup` route.
   * POST /api/v1/auth/mfa/setup/enroll  (body: { setup_token })
   */
  setupEnrollMfa: (setupToken: string): Promise<MfaEnrollResponse> =>
    api
      .post<MfaEnrollResponse>("/api/v1/auth/mfa/setup/enroll", {
        setup_token: setupToken,
      })
      .then((r) => r.data),

  /**
   * Confirm TOTP MFA enrollment during the MFA-mandated login flow
   * (CORR-05b / D-16).
   * POST /api/v1/auth/mfa/setup/confirm  (body: { setup_token, totp_code })
   */
  setupConfirmMfa: (setupToken: string, totpCode: string): Promise<void> =>
    api
      .post<void>("/api/v1/auth/mfa/setup/confirm", {
        setup_token: setupToken,
        totp_code: totpCode,
      })
      .then(() => undefined),
};
