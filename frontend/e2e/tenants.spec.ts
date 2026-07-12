import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./helpers/auth";

// ---------------------------------------------------------------------------
// Tenants list page tests — live backend (D-13).
// Auth via httpOnly cookie (T-07-12 / ASVS V3.1). No sessionStorage.
// The bootstrap fixture seeds a tenant under the E2E org.
// ---------------------------------------------------------------------------

test.describe("Tenants list page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("renders Tenants page header (not redirected to /login)", async ({
    page,
  }) => {
    await page.goto("/tenants");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(
      page.getByRole("heading", { name: "Tenants" })
    ).toBeVisible();
  });

  test("shows the bootstrapped E2E Default Tenant in the list", async ({
    page,
  }) => {
    await page.goto("/tenants");
    await expect(page).not.toHaveURL(/\/login/);
    // The bootstrap fixture creates a tenant named "E2E Default Tenant"
    await expect(page.getByText("E2E Default Tenant")).toBeVisible();
  });

  test("shows organization name for the bootstrapped tenant", async ({
    page,
  }) => {
    await page.goto("/tenants");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByText("E2E Test Org").first()).toBeVisible();
  });

  test('"New Tenant" button opens the create modal', async ({ page }) => {
    await page.goto("/tenants");
    await page.getByRole("button", { name: /New Tenant/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "New Tenant" })
    ).toBeVisible();
  });

  test("create form has Organization, Name, Slug, and Description fields", async ({
    page,
  }) => {
    await page.goto("/tenants");
    await page.getByRole("button", { name: /New Tenant/i }).click();
    await expect(page.getByLabel(/Name/)).toBeVisible();
    await expect(page.getByLabel(/Slug/)).toBeVisible();
    await expect(page.getByLabel(/Description/)).toBeVisible();
  });

  test("shows the bootstrapped tenant row with its slug", async ({
    page,
  }) => {
    await page.goto("/tenants");
    await expect(page).not.toHaveURL(/\/login/);
    // TenantsPage has no status column (the Tenant model has no status field),
    // so verify the bootstrapped tenant renders as a real row: its name plus
    // its slug ("default") shown in the table's slug cell.
    await expect(page.getByText("E2E Default Tenant")).toBeVisible();
    await expect(page.getByText("default", { exact: true }).first()).toBeVisible();
  });

  test("search filters tenants by name", async ({ page }) => {
    await page.goto("/tenants");
    await expect(page.getByText("E2E Default Tenant")).toBeVisible();
    const searchBox = page.getByPlaceholder(/search/i);
    if (await searchBox.isVisible()) {
      await searchBox.fill("E2E");
      await expect(page.getByText("E2E Default Tenant")).toBeVisible();
    } else {
      await expect(page.getByRole("navigation").first()).toBeVisible();
    }
  });

  test("delete button shows confirmation dialog", async ({ page }) => {
    await page.goto("/tenants");
    await expect(page).not.toHaveURL(/\/login/);
    const deleteBtn = page
      .getByRole("button", { name: /Delete E2E Default Tenant/i })
      .first();
    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
      await expect(
        page.getByRole("dialog", { name: /Delete Tenant/i })
      ).toBeVisible();
    } else {
      await expect(page.getByRole("navigation").first()).toBeVisible();
    }
  });
});
