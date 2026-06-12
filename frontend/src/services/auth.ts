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
  secret: string;
  qr_code_uri: string;
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
   * GET /api/v1/auth/verify-email?token=<encoded>
   */
  verifyEmail: (token: string): Promise<void> =>
    api
      .get<void>(`/api/v1/auth/verify-email?token=${encodeURIComponent(token)}`)
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
   * Begin TOTP MFA enrollment — returns secret + QR code URI.
   * POST /api/v1/auth/mfa/setup/enroll
   */
  enrollMfa: (): Promise<MfaEnrollResponse> =>
    api
      .post<MfaEnrollResponse>("/api/v1/auth/mfa/setup/enroll")
      .then((r) => r.data),

  /**
   * Confirm TOTP MFA enrollment with a 6-digit code.
   * POST /api/v1/auth/mfa/setup/confirm
   */
  confirmMfa: (code: string): Promise<void> =>
    api
      .post<void>("/api/v1/auth/mfa/setup/confirm", { code })
      .then(() => undefined),
};
