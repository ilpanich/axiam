import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./helpers/auth";

// Exercises the login flow itself — must run unauthenticated, so opt out of the
// shared admin session captured by the setup project.
test.use({ storageState: { cookies: [], origins: [] } });

test.describe("Login flow", () => {
  test("redirects unauthenticated users to /login", async ({ page }) => {
    await page.goto("/");
    await expect(page).toHaveURL(/\/login/);
  });

  test("renders login form with org slug field", async ({ page }) => {
    await page.goto("/login");
    const orgSlugInput = page.getByLabel("Organization slug");
    await expect(orgSlugInput).toBeVisible();
  });

  test("renders AXIAM logo", async ({ page }) => {
    await page.goto("/login");
    const logo = page.getByAltText("AXIAM");
    await expect(logo).toBeVisible();
  });

  test("shows tenant slug field on login page", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByLabel("Tenant slug")).toBeVisible();
  });

  test("advances to credentials step after org/tenant entry", async ({
    page,
  }) => {
    await page.goto("/login");
    await page.getByLabel("Organization slug").fill("my-org");
    await page.getByLabel("Tenant slug").fill("default");
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.getByLabel("Username or email")).toBeVisible();
  });

  test("shows validation error when org/tenant fields are empty", async ({
    page,
  }) => {
    await page.goto("/login");
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(
      page.getByText("Please enter both organization and tenant slug.")
    ).toBeVisible();
  });

  test("successful login lands off /login with navigation visible", async ({
    page,
  }) => {
    await loginAsAdmin(page);
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByRole("navigation").first()).toBeVisible();
  });

  test("wrong credentials stay on /login with error message", async ({
    page,
  }) => {
    await page.goto("/login");
    const orgSlug = process.env["E2E_ORG_SLUG"] ?? "test-org";
    const tenantSlug = process.env["E2E_TENANT_SLUG"] ?? "default";
    await page.getByLabel("Organization slug").fill(orgSlug);
    await page.getByLabel("Tenant slug").fill(tenantSlug);
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByLabel("Username or email").fill("wrong@example.com");
    await page.getByLabel("Password").fill("wrongpassword123");
    await page.getByRole("button", { name: "Sign in" }).click();
    // Should remain on /login and show an error. Allow extra time: a
    // wrong-credentials attempt still runs a full Argon2id verification on the
    // backend (constant-time by design), which under a loaded CI runner can
    // take several seconds before the error renders.
    await expect(page).toHaveURL(/\/login/);
    await expect(
      page.getByText(/Invalid credentials|error|incorrect/i),
    ).toBeVisible({ timeout: 15_000 });
  });
});
