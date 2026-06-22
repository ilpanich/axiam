import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./helpers/auth";

// ---------------------------------------------------------------------------
// Dashboard tests — runs against LIVE backend (D-13).
// Auth via httpOnly cookie set by loginAsAdmin (T-07-12 / ASVS V3.1).
// ---------------------------------------------------------------------------

test.describe("Dashboard page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('dashboard shows "Users" stat card', async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page).not.toHaveURL(/\/login/);
    // Use section label to scope to the stat card, avoiding the nav sidebar "Users" link
    await expect(
      page.getByLabel("Key metrics").getByText("Users")
    ).toBeVisible();
  });

  test("dashboard renders and navigation is visible after login", async ({
    page,
  }) => {
    await page.goto("/dashboard");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByRole("navigation")).toBeVisible();
  });

  test("dashboard shows recent activity section", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByText("Recent Activity")).toBeVisible();
  });

  test("dashboard shows quick actions section", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByText("Quick Actions")).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Audit Logs tests — live backend
// ---------------------------------------------------------------------------

test.describe("Audit Logs page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("audit logs page renders filter bar", async ({ page }) => {
    await page.goto("/audit-logs");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByRole("heading", { name: "Audit Logs" })).toBeVisible();
    await expect(page.getByLabel("Actor")).toBeVisible();
  });

  test("audit log filter bar has Actor, Action, Outcome fields", async ({
    page,
  }) => {
    await page.goto("/audit-logs");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByLabel("Actor")).toBeVisible();
    await expect(page.getByLabel("Action")).toBeVisible();
    await expect(page.getByLabel("Outcome")).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// OAuth2 Clients tests — live backend
// ---------------------------------------------------------------------------

test.describe("OAuth2 Clients page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("OAuth2 clients list renders with New Client button", async ({
    page,
  }) => {
    await page.goto("/oauth2-clients");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(
      page.getByRole("button", { name: /New Client/i })
    ).toBeVisible();
  });

  test("OAuth2 client create modal has Grant Types checkboxes", async ({
    page,
  }) => {
    await page.goto("/oauth2-clients");
    await page.getByRole("button", { name: /New Client/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByText("Grant Types *")).toBeVisible();
    await expect(
      page.getByRole("checkbox", { name: "authorization_code" })
    ).toBeVisible();
    await expect(
      page.getByRole("checkbox", { name: "client_credentials" })
    ).toBeVisible();
    await expect(
      page.getByRole("checkbox", { name: "refresh_token" })
    ).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Notification Rules tests — live backend
// ---------------------------------------------------------------------------

test.describe("Notification Rules page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("notification rules list renders with New Rule button", async ({
    page,
  }) => {
    await page.goto("/notification-rules");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(
      page.getByRole("button", { name: /New Rule/i })
    ).toBeVisible();
  });

  test("notification rule create modal has Event Type and Recipient Emails fields", async ({
    page,
  }) => {
    await page.goto("/notification-rules");
    await page.getByRole("button", { name: /New Rule/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByLabel(/Event Type/i)).toBeVisible();
    await expect(
      page.getByLabel("Recipient Emails (one per line)")
    ).toBeVisible();
  });
});
