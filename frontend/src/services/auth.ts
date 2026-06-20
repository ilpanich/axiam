import api from "@/lib/api";

// ─── Request payloads ─────────────────────────────────────────────────────────

export interface RequestPasswordResetPayload {
  email: string;
}

export interface ConfirmPasswordResetPayload {
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
   */
  requestPasswordReset: (email: string): Promise<void> =>
    api
      .post<void>("/api/v1/auth/reset", { email })
      .then(() => undefined),

  /**
   * Confirm a password reset using the token from the email link.
   * POST /api/v1/auth/reset/confirm
   */
  confirmPasswordReset: (token: string, new_password: string): Promise<void> =>
    api
      .post<void>("/api/v1/auth/reset/confirm", { token, new_password })
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
   * Resend the email verification message (authenticated endpoint).
   * POST /api/v1/auth/resend-verification
   */
  resendVerification: (): Promise<void> =>
    api
      .post<void>("/api/v1/auth/resend-verification")
      .then(() => undefined),

  /**
   * Change the currently-authenticated user's password.
   * POST /api/v1/auth/password/change
   */
  changePassword: (current_password: string, new_password: string): Promise<void> =>
    api
      .post<void>("/api/v1/auth/password/change", { current_password, new_password })
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
};
