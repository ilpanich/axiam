import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./helpers/auth";

// ---------------------------------------------------------------------------
// Identity / Profile page tests — live backend (D-13).
// Auth via httpOnly cookie (T-07-12 / ASVS V3.1). No sessionStorage.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test 1: Profile page redirects to login if not authenticated
// ---------------------------------------------------------------------------

// This test asserts the UNauthenticated redirect, so it must not inherit the
// shared admin session captured by the setup project — run it with an empty
// storageState. (Scoped to a describe so the authenticated tests below still
// use the shared session.)
test.describe("unauthenticated profile access", () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test("profile page redirects to login if not authenticated", async ({
    page,
  }) => {
    // No loginAsAdmin — no session cookie
    await page.goto("/profile");
    await expect(page).toHaveURL(/\/login/);
  });
});

// ---------------------------------------------------------------------------
// Test 2: Profile page shows user info when authenticated via real login
// ---------------------------------------------------------------------------

test("profile page shows user info when authenticated", async ({ page }) => {
  await loginAsAdmin(page);
  await page.goto("/profile");
  await expect(page).not.toHaveURL(/\/login/);
  // Admin email set by bootstrap
  const adminEmail = process.env["E2E_ADMIN_EMAIL"] ?? "admin@axiam.dev";
  await expect(page.getByText(adminEmail)).toBeVisible();
});

// ---------------------------------------------------------------------------
// Test 3: Profile page shows user detail section
// ---------------------------------------------------------------------------

test("profile page shows user info section", async ({ page }) => {
  await loginAsAdmin(page);
  await page.goto("/profile");
  await expect(page).not.toHaveURL(/\/login/);
  // Admin username shown in profile
  await expect(page.getByText("admin").first()).toBeVisible();
});

// ---------------------------------------------------------------------------
// Test 4: "Edit Profile" button reveals editable display name and email inputs
// ---------------------------------------------------------------------------

test("Edit Profile button reveals editable display name and email inputs", async ({ page }) => {
  await loginAsAdmin(page);
  await page.goto("/profile");
  await expect(page).not.toHaveURL(/\/login/);
  await page.getByRole("button", { name: /Edit Profile/i }).click();
  await expect(page.getByLabel("Display Name")).toBeVisible();
  await expect(page.getByLabel("Email")).toBeVisible();
});

// ---------------------------------------------------------------------------
// Test 5: Change Password page shows 5 policy requirement rows
// (UI-only — no live backend data needed after login)
// ---------------------------------------------------------------------------

test("Change Password page shows 5 policy requirement rows", async ({ page }) => {
  await loginAsAdmin(page);
  await page.goto("/profile/change-password");

  // Type at least one character so the policy checker becomes visible
  await page.locator("#new_password").fill("a");

  const list = page.getByRole("list", { name: "Password requirements" });
  await expect(list).toBeVisible();
  const items = list.getByRole("listitem");
  await expect(items).toHaveCount(5);
});

// ---------------------------------------------------------------------------
// Test 6: All policy requirements show red X for empty password
// ---------------------------------------------------------------------------

test("All policy requirements show red X for empty password", async ({ page }) => {
  await loginAsAdmin(page);
  await page.goto("/profile/change-password");

  await page.locator("#new_password").fill("a");

  const list = page.getByRole("list", { name: "Password requirements" });
  await expect(list).toBeVisible();
  const items = list.getByRole("listitem");
  await expect(items).toHaveCount(5);
  await expect(items.first()).toHaveClass(/text-destructive/);
});

// ---------------------------------------------------------------------------
// Test 7: Policy requirements update as password is typed — all green for valid
// ---------------------------------------------------------------------------

test("Policy requirements all turn green when valid password is typed", async ({ page }) => {
  await loginAsAdmin(page);
  await page.goto("/profile/change-password");

  await page.locator("#new_password").fill("Abc123!@#abc");

  const list = page.getByRole("list", { name: "Password requirements" });
  await expect(list).toBeVisible();
  const items = list.getByRole("listitem");
  const count = await items.count();
  expect(count).toBe(5);
  for (let i = 0; i < count; i++) {
    await expect(items.nth(i)).toHaveClass(/text-emerald-400/);
  }
});

// ---------------------------------------------------------------------------
// Test 8: Forgot Password page renders email input (no auth required — UI-only)
// ---------------------------------------------------------------------------

test("Forgot Password page renders email input", async ({ page }) => {
  await page.goto("/auth/forgot-password");
  await expect(page.getByLabel("Email address")).toBeVisible();
});

// ---------------------------------------------------------------------------
// Test 9: Forgot Password shows success message after submit (any email)
// ---------------------------------------------------------------------------

test("Forgot Password shows success message after submit (any email)", async ({ page }) => {
  await page.route("**/auth/forgot-password", (route) => {
    if (route.request().method() === "POST") {
      route.fulfill({ status: 200, json: {} });
    } else {
      route.continue();
    }
  });

  await page.goto("/auth/forgot-password");
  await page.getByLabel("Email address").fill("anyemail@test.com");
  await page.getByRole("button", { name: /Send Reset Link/i }).click();

  await expect(
    page.getByText(/If an account with that email exists/i)
  ).toBeVisible();
});

// ---------------------------------------------------------------------------
// Test 10: Reset Password page shows error when no token in URL
// ---------------------------------------------------------------------------

test("Reset Password page shows error when no token in URL", async ({ page }) => {
  await page.goto("/auth/reset-password");
  await expect(page.getByText(/Invalid reset link/i)).toBeVisible();
  await expect(page.getByRole("link", { name: /Request new reset link/i })).toBeVisible();
});

// ---------------------------------------------------------------------------
// Test 11: Reset Password page shows password form when token is present
// ---------------------------------------------------------------------------

test("Reset Password page shows password form when token is present in URL", async ({ page }) => {
  // The page requires BOTH token and tenant_id (the emailed link carries both);
  // with token alone it renders the "Invalid reset link" state instead of the form.
  await page.goto("/auth/reset-password?token=abc123&tenant_id=t_123");
  await expect(page.getByLabel("New Password")).toBeVisible();
  await expect(page.getByLabel("Confirm Password")).toBeVisible();
  await expect(page.getByRole("button", { name: /Reset Password/i })).toBeVisible();
});

// ---------------------------------------------------------------------------
// Test 12: Verify Email page shows loading state on mount when token is present
// ---------------------------------------------------------------------------

test("Verify Email page shows loading state on mount when token present", async ({ page }) => {
  await page.route("**/auth/verify-email**", async (route) => {
    const acceptHeader = route.request().headers()["accept"] ?? "";
    if (acceptHeader.includes("application/json")) {
      await new Promise((r) => setTimeout(r, 3000));
      route.fulfill({ status: 200, json: {} });
    } else {
      route.continue();
    }
  });

  // Loading state only renders when BOTH token and tenant_id are present;
  // the verification link carries both (token alone -> "Invalid verification link").
  await page.goto("/auth/verify-email?token=sometoken&tenant_id=t_123");
  await expect(page.getByText(/Verifying your email/i)).toBeVisible({ timeout: 5000 });
});

// ---------------------------------------------------------------------------
// Test 13: MFA Management page shows "Set up TOTP Authenticator" button
// ---------------------------------------------------------------------------

test("MFA Management page shows Set up TOTP Authenticator button", async ({ page }) => {
  await loginAsAdmin(page);
  await page.goto("/profile/mfa");
  await expect(page).not.toHaveURL(/\/login/);
  await expect(
    page.getByRole("button", { name: /Set up TOTP Authenticator/i })
  ).toBeVisible();
});

// ---------------------------------------------------------------------------
// Test 14: MFA Management page shows passkeys "Coming soon" section
// ---------------------------------------------------------------------------

test("MFA Management page shows passkeys Coming soon section", async ({ page }) => {
  await loginAsAdmin(page);
  await page.goto("/profile/mfa");
  await expect(page).not.toHaveURL(/\/login/);
  await expect(page.getByText(/WebAuthn \/ Passkeys/i)).toBeVisible();
  await expect(page.getByText("Coming soon")).toBeVisible();
  await expect(page.getByRole("button", { name: /Add Passkey/i })).toBeDisabled();
});
