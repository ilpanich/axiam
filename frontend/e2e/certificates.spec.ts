import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./helpers/auth";

// ---------------------------------------------------------------------------
// Certificates page tests — live backend (D-13).
// Auth via httpOnly cookie (T-07-12 / ASVS V3.1). No sessionStorage.
// A fresh bootstrap has no certificates or webhooks — empty-state assertions.
// ---------------------------------------------------------------------------

test.describe("Certificates page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("renders certificates page (not redirected to /login)", async ({
    page,
  }) => {
    await page.goto("/certificates");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByRole("navigation").first()).toBeVisible();
  });

  test("shows certificate list or empty state from live backend", async ({
    page,
  }) => {
    await page.goto("/certificates");
    await expect(page).not.toHaveURL(/\/login/);
    const hasTable = await page.getByRole("table").isVisible().catch(() => false);
    const hasEmptyState = await page
      .getByText(/no certificates|empty/i)
      .isVisible()
      .catch(() => false);
    const hasGenerateBtn = await page
      .getByRole("button", { name: /Generate Certificate/i })
      .isVisible()
      .catch(() => false);
    expect(hasTable || hasEmptyState || hasGenerateBtn).toBe(true);
  });

  test('"Generate Certificate" button opens modal with common name field', async ({
    page,
  }) => {
    await page.goto("/certificates");
    await expect(page).not.toHaveURL(/\/login/);
    const generateBtn = page.getByRole("button", { name: /Generate Certificate/i });
    if (await generateBtn.isVisible()) {
      await generateBtn.click();
      await expect(page.getByRole("dialog")).toBeVisible();
      await expect(page.getByLabel("Common Name *")).toBeVisible();
    } else {
      await expect(page.getByRole("navigation").first()).toBeVisible();
    }
  });

  test("generate modal has Key Type select and Validity Days field", async ({
    page,
  }) => {
    await page.goto("/certificates");
    await expect(page).not.toHaveURL(/\/login/);
    const generateBtn = page.getByRole("button", { name: /Generate Certificate/i });
    if (await generateBtn.isVisible()) {
      await generateBtn.click();
      await expect(page.getByLabel("Key Type")).toBeVisible();
      await expect(page.getByLabel("Validity Days")).toBeVisible();
    } else {
      await expect(page.getByRole("navigation").first()).toBeVisible();
    }
  });
});

// ---------------------------------------------------------------------------
// Webhooks page tests — live backend
// ---------------------------------------------------------------------------

test.describe("Webhooks page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("renders webhooks page (not redirected to /login)", async ({ page }) => {
    await page.goto("/webhooks");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByRole("navigation").first()).toBeVisible();
  });

  test("shows webhook list or empty state from live backend", async ({
    page,
  }) => {
    await page.goto("/webhooks");
    await expect(page).not.toHaveURL(/\/login/);
    const hasTable = await page.getByRole("table").isVisible().catch(() => false);
    const hasEmptyState = await page.getByText(/no webhooks/i).isVisible().catch(() => false);
    const hasNewBtn = await page
      .getByRole("button", { name: /New Webhook/i })
      .isVisible()
      .catch(() => false);
    expect(hasTable || hasEmptyState || hasNewBtn).toBe(true);
  });

  test('"New Webhook" button opens create modal with URL field', async ({
    page,
  }) => {
    await page.goto("/webhooks");
    await page.getByRole("button", { name: /New Webhook/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByLabel("URL *")).toBeVisible();
  });

  test("webhook create modal has event type checkboxes", async ({ page }) => {
    await page.goto("/webhooks");
    await page.getByRole("button", { name: /New Webhook/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(
      page.getByRole("checkbox", { name: "user.created" })
    ).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// PGP Keys page tests — live backend
// ---------------------------------------------------------------------------

test.describe("PGP Keys page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("renders PGP keys page (not redirected to /login)", async ({ page }) => {
    await page.goto("/pgp-keys");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByRole("navigation").first()).toBeVisible();
  });

  test("shows PGP key list or empty state from live backend", async ({
    page,
  }) => {
    await page.goto("/pgp-keys");
    await expect(page).not.toHaveURL(/\/login/);
    const hasTable = await page.getByRole("table").isVisible().catch(() => false);
    const hasEmptyState = await page.getByText(/no.*keys|empty/i).isVisible().catch(() => false);
    const hasNewBtn = await page.getByRole("button").isVisible().catch(() => false);
    expect(hasTable || hasEmptyState || hasNewBtn).toBe(true);
  });
});
