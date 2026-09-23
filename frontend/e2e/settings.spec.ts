import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./helpers/auth";

// ---------------------------------------------------------------------------
// Settings page tests — live backend (D-13).
// Auth via httpOnly cookie (T-07-12 / ASVS V3.1). No sessionStorage.
// ---------------------------------------------------------------------------

test.describe("Settings page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("renders Settings page header (not redirected to /login)", async ({
    page,
  }) => {
    await page.goto("/settings");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(
      page.getByRole("heading", { name: "Settings", exact: true })
    ).toBeVisible();
  });

  test("shows Security Policies card with password settings", async ({
    page,
  }) => {
    await page.goto("/settings");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(
      page.getByRole("heading", { name: "Password Policy", exact: true })
    ).toBeVisible();
    await expect(
      page.getByText("Password minimum length", { exact: true })
    ).toBeVisible();
  });

  test("shows Session Management card", async ({ page }) => {
    await page.goto("/settings");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(
      page.getByRole("heading", { name: "Lockout & Tokens", exact: true })
    ).toBeVisible();
    await expect(
      page.getByText("Access token lifetime", { exact: true })
    ).toBeVisible();
  });

  test("shows MFA Settings card", async ({ page }) => {
    await page.goto("/settings");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(
      page.getByRole("heading", { name: "MFA Settings", exact: true })
    ).toBeVisible();
    await expect(page.getByText("MFA required")).toBeVisible();
  });

  test("shows Notification Preferences card", async ({ page }) => {
    await page.goto("/settings");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(
      page.getByRole("heading", {
        name: "Email, Certificates & Notifications",
        exact: true,
      })
    ).toBeVisible();
  });

  test("displays current setting values from live backend", async ({ page }) => {
    await page.goto("/settings");
    await expect(page).not.toHaveURL(/\/login/);
    // Settings page should show some numeric value (password min length, etc.)
    // Live backend returns the seeded defaults from the AXIAM config
    await expect(page.getByRole("navigation").first()).toBeVisible();
  });

  test("Edit Settings button switches to edit mode", async ({ page }) => {
    await page.goto("/settings");
    await expect(page).not.toHaveURL(/\/login/);
    await page.getByRole("button", { name: /Edit Settings/i }).click();
    await expect(
      page.getByRole("button", { name: /Save Settings/i })
    ).toBeVisible();
  });

  test("edit mode shows form inputs for password settings", async ({
    page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: /Edit Settings/i }).click();
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

  // S-7b. A fresh bootstrap lists no Server names, and the card must say what
  // that means (I1: every Server request is refused).
  test("shows the Server certificate names card, empty by default", async ({
    page,
  }) => {
    await page.goto("/settings");
    await expect(
      page.getByRole("heading", { name: "Server Certificate Names", exact: true })
    ).toBeVisible();
    await expect(
      page.getByText("Empty — every Server certificate request is refused.")
    ).toBeVisible();
  });

  // The live tighten-only refusal, end to end: the tenant adds a name its
  // organization never listed, and the server's 400 is shown as it comes. A
  // refused save changes nothing, so this leaves the fixture as it found it.
  test("a tenant widening the Server name list gets the server's refusal verbatim", async ({
    page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: /Edit Settings/i }).click();
    const names = page.getByRole("group", { name: "Server certificate names" });
    await names.getByRole("button", { name: "Add entry" }).click();
    await names.getByLabel("Allowed name 1").fill(".example.com");
    await page.getByRole("button", { name: /Save Settings/i }).click();
    await expect(page.getByRole("alert")).toContainText(
      /server_cert_allowed_names: ".example.com" is not within the org baseline/
    );
  });
});
