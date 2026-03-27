import { test, expect } from "@playwright/test";

const mockSettings = {
  password_min_length: 12,
  password_complexity_enabled: true,
  max_failed_login_attempts: 5,
  account_lockout_duration_minutes: 30,
  access_token_lifetime_minutes: 15,
  refresh_token_lifetime_days: 7,
  max_concurrent_sessions: 5,
  mfa_required: false,
  mfa_totp_enabled: true,
  mfa_webauthn_enabled: false,
  email_notifications_enabled: true,
  webhook_notifications_enabled: false,
};

async function mockAuth(
  page: import("@playwright/test").Page
): Promise<void> {
  await page.addInitScript(() => {
    const fakeState = {
      state: {
        accessToken: "fake-jwt-token",
        isAuthenticated: true,
        user: { id: "u1", email: "admin@axiam.dev", username: "admin" },
        orgId: "org-1",
        tenantId: "tenant-1",
      },
      version: 0,
    };
    sessionStorage.setItem("axiam-auth", JSON.stringify(fakeState));
  });
}

test.describe("Settings page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/settings", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockSettings });
      } else if (route.request().method() === "PUT") {
        route.fulfill({ json: { ...mockSettings, ...route.request().postDataJSON() } });
      } else {
        route.continue();
      }
    });
  });

  test("renders Settings page header", async ({ page }) => {
    await page.goto("/settings");
    await expect(
      page.getByRole("heading", { name: "Settings", exact: true })
    ).toBeVisible();
  });

  test("shows Security Policies card with password settings", async ({
    page,
  }) => {
    await page.goto("/settings");
    await expect(
      page.getByRole("heading", { name: "Security Policies", exact: true })
    ).toBeVisible();
    await expect(
      page.getByText("Password minimum length", { exact: true })
    ).toBeVisible();
  });

  test("shows Session Management card", async ({ page }) => {
    await page.goto("/settings");
    await expect(
      page.getByRole("heading", { name: "Session Management", exact: true })
    ).toBeVisible();
    await expect(
      page.getByText("Access token lifetime", { exact: true })
    ).toBeVisible();
  });

  test("shows MFA Settings card", async ({ page }) => {
    await page.goto("/settings");
    await expect(
      page.getByRole("heading", { name: "MFA Settings", exact: true })
    ).toBeVisible();
    await expect(page.getByText("MFA required")).toBeVisible();
  });

  test("shows Notification Preferences card", async ({ page }) => {
    await page.goto("/settings");
    await expect(
      page.getByRole("heading", {
        name: "Notification Preferences",
        exact: true,
      })
    ).toBeVisible();
  });

  test("displays current setting values in view mode", async ({ page }) => {
    await page.goto("/settings");
    // Should show the value 12 for password min length
    await expect(page.getByText("12").first()).toBeVisible();
  });

  test("Edit Settings button switches to edit mode", async ({ page }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: /Edit Settings/i }).click();
    // In edit mode, Save Settings button should appear
    await expect(
      page.getByRole("button", { name: /Save Settings/i })
    ).toBeVisible();
  });

  test("edit mode shows form inputs for password settings", async ({
    page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: /Edit Settings/i }).click();
    // Should see input fields now
    const inputs = page.locator("input[type='number']");
    await expect(inputs.first()).toBeVisible();
  });

  test("cancel edit returns to view mode", async ({ page }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: /Edit Settings/i }).click();
    await page.getByRole("button", { name: /Cancel/i }).click();
    await expect(
      page.getByRole("button", { name: /Edit Settings/i })
    ).toBeVisible();
  });
});
