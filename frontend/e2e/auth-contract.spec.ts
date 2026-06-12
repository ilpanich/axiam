/**
 * Auth endpoint contract tests (SEC-044/CQ-F27).
 *
 * These tests verify that each auth page calls the correct /api/v1/auth/* backend
 * endpoint. They use Playwright route interception to capture the outbound request URL
 * and assert it matches the canonical path — without requiring a live backend.
 *
 * Structure is intentionally append-friendly: each flow has its own test.describe
 * block so Phase 09-04 can add additional describe blocks without conflict.
 *
 * Run target: npx playwright test --grep "Auth endpoint contract"
 */

import { test, expect } from "@playwright/test";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

import type { Page } from "@playwright/test";

/**
 * Mock GET /api/v1/auth/me so the app's auth-init hook resolves as authenticated.
 * Required for protected pages (Profile, ChangePassword, MfaManagement) to render
 * instead of redirecting to /login.
 */
async function mockAuthMe(page: Page): Promise<void> {
  await page.route("**/api/v1/auth/me", (route) => {
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: "contract-test-user",
        username: "contract",
        email: "contract@test.example",
        permissions: [],
      }),
    });
  });
}

/**
 * Mock GET /api/v1/users/me (ProfilePage profile data).
 */
async function mockUserProfile(page: Page): Promise<void> {
  await page.route("**/api/v1/users/me", (route) => {
    if (route.request().method() === "GET") {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          id: "contract-test-user",
          username: "contract",
          email: "contract@test.example",
          display_name: null,
          email_verified: false,
        }),
      });
    } else {
      route.continue();
    }
  });
}

/**
 * Mock GET /api/v1/users/me/mfa-methods (ProfilePage + MfaManagementPage).
 */
async function mockMfaMethods(page: Page): Promise<void> {
  await page.route("**/api/v1/users/me/mfa-methods", (route) => {
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([]),
    });
  });
}

// ---------------------------------------------------------------------------
// Test suite — "Auth endpoint contract"
// ---------------------------------------------------------------------------

test.describe("Auth endpoint contract", () => {
  // ── Block A: Public auth flows ──────────────────────────────────────────

  test.describe("ForgotPasswordPage", () => {
    test("POST /api/v1/auth/reset — not /auth/forgot-password", async ({ page }) => {
      let capturedUrl: string | undefined;

      await page.route("**/auth/**", (route) => {
        if (route.request().method() === "POST") {
          capturedUrl = route.request().url();
          route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
        } else {
          route.continue();
        }
      });

      await page.goto("/auth/forgot-password");
      await page.getByLabel("Email address").fill("test@example.com");
      await page.getByRole("button", { name: /Send Reset Link/i }).click();

      // Wait for the success state to appear (the page always shows success after submit)
      await expect(page.getByText(/If an account with that email exists/i)).toBeVisible();

      expect(capturedUrl).toBeDefined();
      expect(capturedUrl).toContain("/api/v1/auth/reset");
      expect(capturedUrl).not.toContain("/auth/forgot-password");
    });
  });

  test.describe("ResetPasswordPage", () => {
    test("POST /api/v1/auth/reset/confirm — not /auth/reset-password", async ({ page }) => {
      let capturedUrl: string | undefined;

      await page.route("**/auth/**", (route) => {
        if (route.request().method() === "POST") {
          capturedUrl = route.request().url();
          route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
        } else {
          route.continue();
        }
      });

      // Provide a token in the query string so the form renders (not the "no token" state)
      await page.goto("/auth/reset-password?token=contract-test-token");

      // Fill a password that satisfies the policy checker (12+ chars, upper, lower, digit, special)
      const newPassword = "Contract@Test123!";
      await page.getByLabel("New Password").fill(newPassword);
      await page.getByLabel("Confirm Password").fill(newPassword);

      // Wait for the submit button to become enabled
      const submitBtn = page.getByRole("button", { name: /Reset Password/i });
      await expect(submitBtn).toBeEnabled({ timeout: 3_000 });
      await submitBtn.click();

      // Wait for any response (success or error state)
      await page.waitForTimeout(500);

      expect(capturedUrl).toBeDefined();
      expect(capturedUrl).toContain("/api/v1/auth/reset/confirm");
      expect(capturedUrl).not.toContain("/auth/reset-password");
    });
  });

  test.describe("VerifyEmailPage", () => {
    test("GET /api/v1/auth/verify-email — not /auth/verify-email", async ({ page }) => {
      let capturedUrl: string | undefined;

      await page.route("**/auth/**", (route) => {
        if (route.request().method() === "GET") {
          capturedUrl = route.request().url();
          route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
        } else {
          route.continue();
        }
      });

      // Token in query string triggers the on-mount verification call
      await page.goto("/auth/verify-email?token=contract-verify-token");

      // Wait for success state (email verified)
      await expect(page.getByText(/Email verified/i)).toBeVisible({ timeout: 5_000 });

      expect(capturedUrl).toBeDefined();
      expect(capturedUrl).toContain("/api/v1/auth/verify-email");
      expect(capturedUrl).toContain("token=contract-verify-token");
      expect(capturedUrl).not.toContain("/auth/verify-email?");
    });
  });

  // ── Block B: Authenticated profile flows ───────────────────────────────

  test.describe("ProfilePage", () => {
    test("resend-verification POST /api/v1/auth/resend-verification — not /auth/resend-verification", async ({ page }) => {
      let capturedUrl: string | undefined;

      // Mock auth init so the app treats us as authenticated
      await mockAuthMe(page);
      await mockUserProfile(page);
      await mockMfaMethods(page);

      await page.route("**/auth/**", (route) => {
        if (route.request().method() === "POST") {
          capturedUrl = route.request().url();
          route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
        } else {
          route.continue();
        }
      });

      await page.goto("/profile");

      // The profile shows the "Unverified" badge and "Resend verification email" button
      // because email_verified is false in our mock
      const resendBtn = page.getByText(/Resend verification email/i);
      await expect(resendBtn).toBeVisible({ timeout: 5_000 });
      await resendBtn.click();

      await page.waitForTimeout(500);

      expect(capturedUrl).toBeDefined();
      expect(capturedUrl).toContain("/api/v1/auth/resend-verification");
      expect(capturedUrl).not.toContain("/auth/resend-verification");
    });
  });

  test.describe("ChangePasswordPage", () => {
    test("POST /api/v1/auth/password/change — not /auth/change-password", async ({ page }) => {
      let capturedUrl: string | undefined;

      await mockAuthMe(page);

      await page.route("**/auth/**", (route) => {
        if (route.request().method() === "POST") {
          capturedUrl = route.request().url();
          route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
        } else {
          route.continue();
        }
      });

      await page.goto("/profile/change-password");

      const newPassword = "Contract@Test123!";
      await page.getByLabel("Current Password").fill("OldPassword@123!");
      await page.getByLabel("New Password").fill(newPassword);
      await page.getByLabel("Confirm New Password").fill(newPassword);

      const submitBtn = page.getByRole("button", { name: /Update Password/i });
      await expect(submitBtn).toBeEnabled({ timeout: 3_000 });
      await submitBtn.click();

      await page.waitForTimeout(500);

      expect(capturedUrl).toBeDefined();
      expect(capturedUrl).toContain("/api/v1/auth/password/change");
      expect(capturedUrl).not.toContain("/auth/change-password");
    });
  });

  test.describe("MfaManagementPage", () => {
    test("enroll POST /api/v1/auth/mfa/setup/enroll — not /auth/mfa/setup", async ({ page }) => {
      let capturedEnrollUrl: string | undefined;

      await mockAuthMe(page);
      await mockMfaMethods(page);

      await page.route("**/auth/**", (route) => {
        if (route.request().method() === "POST") {
          capturedEnrollUrl = route.request().url();
          // Return a mock TOTP enroll response so the dialog opens
          route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({
              secret: "CONTRACTTESTBASE32SECRET",
              qr_code_uri: "otpauth://totp/test:contract@test.example?secret=CONTRACTTESTBASE32SECRET",
            }),
          });
        } else {
          route.continue();
        }
      });

      await page.goto("/profile/mfa");

      const setupBtn = page.getByRole("button", { name: /Set up TOTP Authenticator/i });
      await expect(setupBtn).toBeVisible({ timeout: 5_000 });
      await setupBtn.click();

      await page.waitForTimeout(500);

      expect(capturedEnrollUrl).toBeDefined();
      expect(capturedEnrollUrl).toContain("/api/v1/auth/mfa/setup/enroll");
      expect(capturedEnrollUrl).not.toContain("/auth/mfa/setup");
    });

    test("confirm POST /api/v1/auth/mfa/setup/confirm — not /auth/mfa/confirm", async ({ page }) => {
      let capturedConfirmUrl: string | undefined;

      await mockAuthMe(page);
      await mockMfaMethods(page);

      // Route for both enroll (first POST) and confirm (second POST)
      let enrollDone = false;
      await page.route("**/auth/**", (route) => {
        if (route.request().method() === "POST") {
          if (!enrollDone) {
            // First POST = enroll
            enrollDone = true;
            route.fulfill({
              status: 200,
              contentType: "application/json",
              body: JSON.stringify({
                secret: "CONTRACTTESTBASE32SECRET",
                qr_code_uri: "otpauth://totp/test:contract@test.example?secret=CONTRACTTESTBASE32SECRET",
              }),
            });
          } else {
            // Second POST = confirm
            capturedConfirmUrl = route.request().url();
            route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
          }
        } else {
          route.continue();
        }
      });

      await page.goto("/profile/mfa");

      // Click "Set up TOTP" to trigger enroll
      const setupBtn = page.getByRole("button", { name: /Set up TOTP Authenticator/i });
      await expect(setupBtn).toBeVisible({ timeout: 5_000 });
      await setupBtn.click();

      // Wait for the TOTP dialog to appear
      await expect(page.getByRole("dialog", { name: /Set up TOTP/i })).toBeVisible({
        timeout: 3_000,
      });

      // Fill in a 6-digit code and submit
      const codeInput = page.getByLabel("Verification Code");
      await expect(codeInput).toBeVisible();
      await codeInput.fill("123456");

      await page.getByRole("button", { name: /Confirm/i }).click();

      await page.waitForTimeout(500);

      expect(capturedConfirmUrl).toBeDefined();
      expect(capturedConfirmUrl).toContain("/api/v1/auth/mfa/setup/confirm");
      expect(capturedConfirmUrl).not.toContain("/auth/mfa/confirm");
    });
  });
});

// ---------------------------------------------------------------------------
// Test suite — "Silent refresh CSRF contract" (CQ-F28 / T-09-07)
//
// Proves the app's boot/silent refresh POST goes through the `api` axios
// instance (whose request interceptor attaches X-CSRF-Token) rather than bare
// axios. Driving through the app boot is essential: a raw fetch would NOT
// attach CSRF and would falsely fail — the intercept must observe the app's
// own refresh so the api-instance interceptor runs.
// ---------------------------------------------------------------------------

test.describe("Silent refresh CSRF contract", () => {
  test("boot refresh POST /api/v1/auth/refresh carries X-CSRF-Token header", async ({
    page,
    context,
  }) => {
    // The request interceptor reads the axiam_csrf cookie and copies it into
    // the X-CSRF-Token header on state-changing requests. Seed it so the
    // interceptor has a value to attach.
    const csrfValue = "contract-csrf-token-value";
    await context.addCookies([
      {
        name: "axiam_csrf",
        value: csrfValue,
        url: "http://localhost:5173",
      },
    ]);

    // Make the first /auth/me return 401 so fetchCurrentUser() returns null,
    // which triggers the single boot refresh in useAuthInit.
    await page.route("**/api/v1/auth/me", (route) => {
      route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ error: "unauthorized" }),
      });
    });

    // Capture the refresh request's headers, then fulfill so the flow settles.
    let refreshHeaders: Record<string, string> | undefined;
    await page.route("**/api/v1/auth/refresh", (route) => {
      refreshHeaders = route.request().headers();
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({}),
      });
    });

    // Boot the app — useAuthInit runs on mount and drives the silent refresh.
    await page.goto("/");

    // Wait until the boot refresh has been observed.
    await expect.poll(() => refreshHeaders, { timeout: 5_000 }).toBeDefined();

    // The refresh POST must carry a non-empty x-csrf-token request header,
    // proving it went through the api instance (not bare axios).
    expect(refreshHeaders?.["x-csrf-token"]).toBeTruthy();
    expect(refreshHeaders?.["x-csrf-token"]).toBe(csrfValue);
  });
});
