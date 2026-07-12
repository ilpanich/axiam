import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./helpers/auth";

// ---------------------------------------------------------------------------
// Service Accounts page tests — live backend (D-13).
// Auth via httpOnly cookie (T-07-12 / ASVS V3.1). No sessionStorage.
// A fresh bootstrap has no service accounts — empty state is expected.
// ---------------------------------------------------------------------------

test.describe("Service Accounts page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("renders Service Accounts page header (not redirected to /login)", async ({
    page,
  }) => {
    await page.goto("/service-accounts");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(
      page.getByRole("heading", { name: "Service Accounts" })
    ).toBeVisible();
  });

  test("shows service account list or empty state from live backend", async ({
    page,
  }) => {
    await page.goto("/service-accounts");
    await expect(page).not.toHaveURL(/\/login/);
    // DataTable always renders a <table> (rows or empty message inside), so
    // wait for it (auto-retry) instead of one-shot isVisible() probes that
    // raced the fetch and flaked.
    await expect(page.getByRole("table")).toBeVisible();
  });

  test('"New Service Account" button opens create modal', async ({ page }) => {
    await page.goto("/service-accounts");
    await page
      .getByRole("button", { name: /New Service Account/i })
      .click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "New Service Account" })
    ).toBeVisible();
  });

  test("create form has Name field", async ({ page }) => {
    await page.goto("/service-accounts");
    await page
      .getByRole("button", { name: /New Service Account/i })
      .click();
    await expect(page.getByLabel(/Name/)).toBeVisible();
  });

  test("navigation is visible after login (RBAC-gated page accessible — T-07-13)", async ({
    page,
  }) => {
    await page.goto("/service-accounts");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByRole("navigation").first()).toBeVisible();
  });
});
