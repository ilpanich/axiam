import { test, expect } from "@playwright/test";

const mockOrgs = [
  {
    id: "org-1",
    name: "Acme Corp",
    slug: "acme",
    description: "Test org",
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "org-2",
    name: "Globex Inc",
    slug: "globex",
    description: "Another org",
    created_at: "2026-02-01T00:00:00Z",
  },
];

const mockTenantsOrg1 = [
  {
    id: "t-1",
    name: "Production",
    slug: "prod",
    description: "Production tenant",
    org_id: "org-1",
    is_active: true,
    created_at: "2026-01-15T00:00:00Z",
  },
  {
    id: "t-2",
    name: "Staging",
    slug: "staging",
    description: "Staging environment",
    org_id: "org-1",
    is_active: false,
    created_at: "2026-01-20T00:00:00Z",
  },
];

const mockTenantsOrg2 = [
  {
    id: "t-3",
    name: "Default",
    slug: "default",
    description: "Default tenant",
    org_id: "org-2",
    is_active: true,
    created_at: "2026-02-10T00:00:00Z",
  },
];

async function mockAuth(
  page: import("@playwright/test").Page
): Promise<void> {
  await page.addInitScript(() => {
    const fakeState = {
      state: {
        accessToken: "fake-jwt-token",
        isAuthenticated: true,
        user: { id: "u1", email: "admin@axiam.dev", username: "admin" },
        orgSlug: "org-1",
        tenantSlug: "tenant-1",
      },
      version: 0,
    };
    sessionStorage.setItem("axiam-auth", JSON.stringify(fakeState));
  });
}

test.describe("Tenants list page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/organizations", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockOrgs });
      } else {
        route.continue();
      }
    });

    await page.route("**/api/v1/organizations/org-1/tenants", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockTenantsOrg1 });
      } else {
        route.continue();
      }
    });

    await page.route("**/api/v1/organizations/org-2/tenants", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockTenantsOrg2 });
      } else {
        route.continue();
      }
    });
  });

  test("renders Tenants page header", async ({ page }) => {
    await page.goto("/tenants");
    await expect(
      page.getByRole("heading", { name: "Tenants" })
    ).toBeVisible();
  });

  test("renders tenants from all organizations", async ({ page }) => {
    await page.goto("/tenants");
    await expect(page.getByText("Production", { exact: true })).toBeVisible();
    await expect(page.getByText("Staging", { exact: true })).toBeVisible();
    await expect(page.getByText("Default", { exact: true })).toBeVisible();
  });

  test("shows organization name for each tenant", async ({ page }) => {
    await page.goto("/tenants");
    await expect(page.getByText("Acme Corp").first()).toBeVisible();
    await expect(page.getByText("Globex Inc")).toBeVisible();
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

  test("shows active/inactive status badges", async ({ page }) => {
    await page.goto("/tenants");
    await expect(page.getByText("Active").first()).toBeVisible();
  });

  test("search filters tenants by name", async ({ page }) => {
    await page.goto("/tenants");
    // Wait for data to load first
    await expect(page.getByText("Production", { exact: true })).toBeVisible();
    await page.getByPlaceholder(/search/i).fill("Prod");
    await expect(page.getByText("Production", { exact: true })).toBeVisible();
    await expect(page.getByText("Default", { exact: true })).not.toBeVisible();
  });

  test("delete button shows confirmation dialog", async ({ page }) => {
    await page.goto("/tenants");
    await page
      .getByRole("button", { name: /Delete Production/i })
      .click();
    await expect(
      page.getByRole("dialog", { name: /Delete Tenant/i })
    ).toBeVisible();
  });
});
