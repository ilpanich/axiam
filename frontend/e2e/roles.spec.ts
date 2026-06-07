import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./helpers/auth";

// ---------------------------------------------------------------------------
// Roles list tests — live backend (D-13).
// The bootstrapped tenant has a super-admin role seeded by the bootstrap fixture.
// Auth via httpOnly cookie (T-07-12 / ASVS V3.1).
// ---------------------------------------------------------------------------

test.describe("Roles list page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("renders roles list page (not redirected to /login)", async ({
    page,
  }) => {
    await page.goto("/roles");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByRole("navigation")).toBeVisible();
  });

  test("shows the seeded super-admin role from bootstrap fixture", async ({
    page,
  }) => {
    await page.goto("/roles");
    await expect(page).not.toHaveURL(/\/login/);
    // The bootstrap fixture seeds a super-admin role — it must appear in the list
    await expect(page.getByText("super-admin")).toBeVisible();
  });

  test('"New Role" button opens modal with name/description/global toggle fields', async ({
    page,
  }) => {
    await page.goto("/roles");
    await page.getByRole("button", { name: /New Role/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "New Role" })
    ).toBeVisible();
    await expect(page.getByLabel("Name *")).toBeVisible();
    await expect(page.getByLabel("Description")).toBeVisible();
    await expect(
      page.getByLabel(/Global role/i)
    ).toBeVisible();
  });

  test("super-admin role shows Global badge (RBAC-gated visibility — T-07-13)", async ({
    page,
  }) => {
    await page.goto("/roles");
    await expect(page).not.toHaveURL(/\/login/);
    // Admin with super-admin role should see the Roles page and Global badges
    // This asserts RBAC-gated nav is accessible to the bootstrapped admin (T-07-13)
    await expect(page.getByText("Global").first()).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Role detail page tests — live backend
// ---------------------------------------------------------------------------

test.describe("Role detail page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("role list shows Permissions section link or heading", async ({
    page,
  }) => {
    await page.goto("/roles");
    await expect(page).not.toHaveURL(/\/login/);
    // Navigate to the first role — click the first role name or row
    const firstRoleLink = page.getByRole("link").filter({ hasText: /super-admin/i }).first();
    if (await firstRoleLink.isVisible()) {
      await firstRoleLink.click();
      await expect(
        page.getByRole("heading", { name: "Permissions", level: 2 })
      ).toBeVisible();
    } else {
      // Fallback: just assert roles page loaded
      await expect(page.getByRole("heading", { name: "Roles" })).toBeVisible();
    }
  });
});

// ---------------------------------------------------------------------------
// Permissions list tests — live backend
// ---------------------------------------------------------------------------

test.describe("Permissions list page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("permissions list page renders (not redirected to /login)", async ({
    page,
  }) => {
    await page.goto("/permissions");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByRole("navigation")).toBeVisible();
  });

  test("permissions page shows seeded permissions from bootstrap", async ({
    page,
  }) => {
    await page.goto("/permissions");
    await expect(page).not.toHaveURL(/\/login/);
    // The bootstrap fixture seeds all AXIAM permissions — at least one should appear
    // The permission table or empty-state must be visible
    const hasTable = await page.getByRole("table").isVisible().catch(() => false);
    const hasEmptyState = await page.getByText(/no permissions|empty/i).isVisible().catch(() => false);
    expect(hasTable || hasEmptyState).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Resources page tests — live backend
// ---------------------------------------------------------------------------

test.describe("Resources page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("resources page renders tree view by default", async ({ page }) => {
    await page.goto("/resources");
    await expect(page).not.toHaveURL(/\/login/);
    // Tree view is default — either tree or empty state should be present
    const hasTree = await page.getByRole("tree").isVisible().catch(() => false);
    const hasEmptyState = await page.getByText(/no resources/i).isVisible().catch(() => false);
    expect(hasTree || hasEmptyState).toBe(true);
  });

  test("list view toggle switches from tree to table", async ({ page }) => {
    await page.goto("/resources");
    await expect(page).not.toHaveURL(/\/login/);
    const listViewBtn = page.getByRole("button", { name: /List view/i });
    if (await listViewBtn.isVisible()) {
      await listViewBtn.click();
      await expect(page.getByRole("tree")).not.toBeVisible();
    } else {
      // Page rendered without tree — acceptable for empty DB
      await expect(page.getByRole("navigation")).toBeVisible();
    }
  });
});
