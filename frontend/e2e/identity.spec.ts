import { test, expect } from "@playwright/test";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const mockProfile = {
  id: "u1",
  username: "testuser",
  email: "testuser@example.com",
  display_name: "Test User",
  email_verified: true,
};

const mockProfileUnverified = {
  ...mockProfile,
  email_verified: false,
};

const mockMfaMethods = [
  {
    id: "mfa-1",
    method_type: "totp",
    name: "Authenticator App",
    created_at: "2026-01-05T00:00:00Z",
  },
];

// ---------------------------------------------------------------------------
// Auth helper — injects a fake authenticated session into sessionStorage
// ---------------------------------------------------------------------------

async function mockAuth(page: import("@playwright/test").Page): Promise<void> {
  await page.addInitScript(() => {
    const fakeState = {
      state: {
        accessToken: "fake-jwt-token",
        isAuthenticated: true,
        user: { id: "u1", email: "testuser@example.com", username: "testuser" },
        orgSlug: "org-1",
        tenantSlug: "tenant-1",
      },
      version: 0,
    };
    sessionStorage.setItem("axiam-auth", JSON.stringify(fakeState));
  });
}

// ---------------------------------------------------------------------------
// Test 1: Profile page redirects to login if not authenticated
// ---------------------------------------------------------------------------

test("profile page redirects to login if not authenticated", async ({ page }) => {
  // No mockAuth — no session
  await page.goto("/profile");
  await expect(page).toHaveURL(/\/login/);
});

// ---------------------------------------------------------------------------
// Test 2: Profile page shows user info when authenticated
// ---------------------------------------------------------------------------

test("profile page shows user info when authenticated", async ({ page }) => {
  await mockAuth(page);

  await page.route("**/api/v1/users/me", (route) => {
    if (route.request().method() === "GET") {
      route.fulfill({ json: mockProfile });
    } else {
      route.continue();
    }
  });

  await page.route("**/api/v1/users/me/mfa-methods", (route) => {
    route.fulfill({ json: mockMfaMethods });
  });

  await page.goto("/profile");

  await expect(page.getByText("testuser@example.com")).toBeVisible();
  // Use first() to avoid strict-mode error — display name appears in both the large heading
  // and the display-name detail row
  await expect(page.getByText("Test User").first()).toBeVisible();
});

// ---------------------------------------------------------------------------
// Test 3: Profile page shows "Unverified" badge when email_verified is false
// ---------------------------------------------------------------------------

test("profile page shows Unverified badge when email is not verified", async ({ page }) => {
  await mockAuth(page);

  await page.route("**/api/v1/users/me", (route) => {
    if (route.request().method() === "GET") {
      route.fulfill({ json: mockProfileUnverified });
    } else {
      route.continue();
    }
  });

  await page.route("**/api/v1/users/me/mfa-methods", (route) => {
    route.fulfill({ json: [] });
  });

  await page.goto("/profile");

  await expect(page.getByText("Unverified")).toBeVisible();
});

// ---------------------------------------------------------------------------
// Test 4: "Edit Profile" button reveals editable display name and email inputs
// ---------------------------------------------------------------------------

test("Edit Profile button reveals editable display name and email inputs", async ({ page }) => {
  await mockAuth(page);

  await page.route("**/api/v1/users/me", (route) => {
    if (route.request().method() === "GET") {
      route.fulfill({ json: mockProfile });
    } else {
      route.continue();
    }
  });

  await page.route("**/api/v1/users/me/mfa-methods", (route) => {
    route.fulfill({ json: [] });
  });

  await page.goto("/profile");

  await page.getByRole("button", { name: /Edit Profile/i }).click();

  await expect(page.getByLabel("Display Name")).toBeVisible();
  await expect(page.getByLabel("Email")).toBeVisible();
});

// ---------------------------------------------------------------------------
// Test 5: Change Password page shows 5 policy requirement rows
// ---------------------------------------------------------------------------

test("Change Password page shows 5 policy requirement rows", async ({ page }) => {
  await mockAuth(page);
  await page.goto("/profile/change-password");

  // Type at least one character so the policy checker becomes visible
  await page.locator("#new_password").fill("a");

  // The policy checker renders an aria-label="Password requirements" list
  const list = page.getByRole("list", { name: "Password requirements" });
  await expect(list).toBeVisible();
  const items = list.getByRole("listitem");
  await expect(items).toHaveCount(5);
});

// ---------------------------------------------------------------------------
// Test 6: All policy requirements show red X for empty password
// ---------------------------------------------------------------------------

test("All policy requirements show red X for empty password", async ({ page }) => {
  await mockAuth(page);
  await page.goto("/profile/change-password");

  // Type "a" to show the policy checker (1 char, fails most rules)
  await page.locator("#new_password").fill("a");

  const list = page.getByRole("list", { name: "Password requirements" });
  await expect(list).toBeVisible();

  // "At least 12 characters" should show red X (fails)
  const items = list.getByRole("listitem");
  await expect(items).toHaveCount(5);
  // The first rule (12 chars) should show the red failure class
  await expect(items.first()).toHaveClass(/text-destructive/);
});

// ---------------------------------------------------------------------------
// Test 7: Policy requirements update as password is typed — all green for valid password
// ---------------------------------------------------------------------------

test('Policy requirements all turn green when valid password is typed', async ({ page }) => {
  await mockAuth(page);
  await page.goto("/profile/change-password");

  // "Abc123!@#abc" — 12+ chars, upper, lower, digit, special
  await page.locator("#new_password").fill("Abc123!@#abc");

  const list = page.getByRole("list", { name: "Password requirements" });
  await expect(list).toBeVisible();
  const items = list.getByRole("listitem");

  // All 5 items should have the emerald green color class (text-emerald-400)
  const count = await items.count();
  expect(count).toBe(5);
  for (let i = 0; i < count; i++) {
    await expect(items.nth(i)).toHaveClass(/text-emerald-400/);
  }
});

// ---------------------------------------------------------------------------
// Test 8: Forgot Password page renders email input
// ---------------------------------------------------------------------------

test("Forgot Password page renders email input", async ({ page }) => {
  await page.goto("/auth/forgot-password");
  await expect(page.getByLabel("Email address")).toBeVisible();
});

// ---------------------------------------------------------------------------
// Test 9: Forgot Password always shows success message after submit
// ---------------------------------------------------------------------------

test("Forgot Password shows success message after submit (any email)", async ({ page }) => {
  // Only intercept POST requests to avoid blocking the page navigation (GET)
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

  // Success message should always appear
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
// Test 11: Reset Password page shows password form when token is present in URL
// ---------------------------------------------------------------------------

test("Reset Password page shows password form when token is present in URL", async ({ page }) => {
  await page.goto("/auth/reset-password?token=abc123");

  await expect(page.getByLabel("New Password")).toBeVisible();
  await expect(page.getByLabel("Confirm Password")).toBeVisible();
  await expect(page.getByRole("button", { name: /Reset Password/i })).toBeVisible();
});

// ---------------------------------------------------------------------------
// Test 12: Verify Email page shows loading state on mount when token is present
// ---------------------------------------------------------------------------

test("Verify Email page shows loading state on mount when token present", async ({ page }) => {
  // Intercept only the API verification call (not the page navigation).
  // Distinguish by checking the Accept header: page navigation has text/html, API call has
  // application/json (Axios default).
  await page.route("**/auth/verify-email**", async (route) => {
    const acceptHeader = route.request().headers()["accept"] ?? "";
    if (acceptHeader.includes("application/json")) {
      // This is the Axios API call — delay it so we can see the loading state
      await new Promise((r) => setTimeout(r, 3000));
      route.fulfill({ status: 200, json: {} });
    } else {
      // This is the initial page navigation — let Vite serve index.html
      route.continue();
    }
  });

  await page.goto("/auth/verify-email?token=sometoken");

  // The loading text should be visible while the API call is still pending
  await expect(page.getByText(/Verifying your email/i)).toBeVisible({ timeout: 5000 });
});

// ---------------------------------------------------------------------------
// Test 13: MFA Management page shows "Set up TOTP Authenticator" button
// ---------------------------------------------------------------------------

test("MFA Management page shows Set up TOTP Authenticator button", async ({ page }) => {
  await mockAuth(page);

  await page.route("**/api/v1/users/me/mfa-methods", (route) => {
    route.fulfill({ json: [] });
  });

  await page.goto("/profile/mfa");

  await expect(
    page.getByRole("button", { name: /Set up TOTP Authenticator/i })
  ).toBeVisible();
});

// ---------------------------------------------------------------------------
// Test 14: MFA Management page shows passkeys "Coming soon" section
// ---------------------------------------------------------------------------

test("MFA Management page shows passkeys Coming soon section", async ({ page }) => {
  await mockAuth(page);

  await page.route("**/api/v1/users/me/mfa-methods", (route) => {
    route.fulfill({ json: [] });
  });

  await page.goto("/profile/mfa");

  await expect(page.getByText(/WebAuthn \/ Passkeys/i)).toBeVisible();
  await expect(page.getByText("Coming soon")).toBeVisible();
  // The "Add Passkey" button should be disabled
  await expect(page.getByRole("button", { name: /Add Passkey/i })).toBeDisabled();
});
