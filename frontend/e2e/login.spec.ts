import { test, expect } from "@playwright/test";

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

  // NOTE: This test requires the backend to be running at http://localhost:8080.
  // Skip it in CI environments without a running backend.
  test.skip("shows error on wrong credentials", async ({ page }) => {
    // This test is skipped because it requires a running backend.
    // To run it manually: ensure the backend is available at http://localhost:8080,
    // then remove the test.skip wrapper.
    await page.goto("/login");
    await page.getByLabel("Organization slug").fill("test-org");
    await page.getByLabel("Tenant slug").fill("default");
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByLabel("Username or email").fill("wrong@example.com");
    await page.getByLabel("Password").fill("wrongpassword");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(
      page.getByText(/Invalid credentials|error/i)
    ).toBeVisible();
  });
});
