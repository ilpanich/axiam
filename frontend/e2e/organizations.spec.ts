import { test, expect } from "@playwright/test";

// Shared mock data
const mockOrg = {
  id: "org-1",
  name: "Acme Corp",
  slug: "acme",
  description: "Test organization",
  created_at: "2026-01-01T00:00:00Z",
};

const mockTenant = {
  id: "tenant-1",
  name: "Default Tenant",
  slug: "default",
  description: "Primary tenant",
  org_id: "org-1",
  created_at: "2026-01-10T00:00:00Z",
};

const mockCert = {
  id: "cert-1",
  common_name: "Acme Root CA",
  key_type: "RSA4096",
  status: "active",
  expires_at: "2027-01-01T00:00:00Z",
  created_at: "2026-01-01T00:00:00Z",
};

const mockSettings = {
  password_min_length: 12,
  password_require_uppercase: true,
  password_require_lowercase: true,
  password_require_digit: true,
  password_require_symbol: false,
  password_history_count: 5,
  mfa_enforced: true,
  session_timeout_minutes: 60,
  certificate_validity_days: 365,
};

// Auth mock — bypass the auth redirect by mocking the auth store is handled via
// a seeded localStorage token (the app reads it on load).
async function mockAuth(
  page: import("@playwright/test").Page
): Promise<void> {
  // Seed a fake access token into sessionStorage so Zustand's persist
  // middleware rehydrates the auth store, allowing the auth guard to pass.
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

test.describe("Organizations list page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/organizations", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: [mockOrg] });
      } else {
        route.continue();
      }
    });
  });

  test("renders organization list with mocked data", async ({ page }) => {
    await page.goto("/organizations");
    await expect(page.getByText("Acme Corp")).toBeVisible();
  });

  test("shows Organizations page header", async ({ page }) => {
    await page.goto("/organizations");
    await expect(
      page.getByRole("heading", { name: "Organizations" })
    ).toBeVisible();
  });

  test('"New Organization" button opens the create modal', async ({ page }) => {
    await page.goto("/organizations");
    await page.getByRole("button", { name: /New Organization/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "New Organization" })
    ).toBeVisible();
  });

  test("create form has Name and Slug fields", async ({ page }) => {
    await page.goto("/organizations");
    await page.getByRole("button", { name: /New Organization/i }).click();
    await expect(page.getByLabel("Name *")).toBeVisible();
    await expect(page.getByLabel("Slug *")).toBeVisible();
  });

  test("delete button shows confirmation dialog", async ({ page }) => {
    await page.goto("/organizations");
    await page
      .getByRole("button", { name: /Delete Acme Corp/i })
      .click();
    await expect(
      page.getByRole("dialog", { name: /Delete Organization/i })
    ).toBeVisible();
    await expect(
      page.getByText(/Are you sure you want to delete/)
    ).toBeVisible();
  });
});

test.describe("Organization detail page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/organizations/org-1", (route) => {
      route.fulfill({ json: mockOrg });
    });

    await page.route("**/api/v1/organizations/org-1/tenants", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: [mockTenant] });
      } else {
        route.continue();
      }
    });

    await page.route(
      "**/api/v1/organizations/org-1/ca-certificates",
      (route) => {
        if (route.request().method() === "GET") {
          route.fulfill({ json: [mockCert] });
        } else {
          route.continue();
        }
      }
    );

    await page.route(
      "**/api/v1/organizations/org-1/settings",
      (route) => {
        route.fulfill({ json: mockSettings });
      }
    );
  });

  test("navigating to org detail shows tab bar with expected tabs", async ({
    page,
  }) => {
    await page.goto("/organizations/org-1");
    await expect(page.getByRole("tab", { name: "Tenants" })).toBeVisible();
    await expect(
      page.getByRole("tab", { name: "CA Certificates" })
    ).toBeVisible();
    await expect(page.getByRole("tab", { name: "Settings" })).toBeVisible();
  });

  test("Settings tab shows MFA enforced toggle", async ({ page }) => {
    await page.goto("/organizations/org-1");
    await page.getByRole("tab", { name: "Settings" }).click();
    await expect(
      page.getByRole("checkbox", { name: /enforce mfa/i })
    ).toBeVisible();
  });

  test("CA Certificates tab shows Generate Certificate button", async ({
    page,
  }) => {
    await page.goto("/organizations/org-1");
    await page.getByRole("tab", { name: "CA Certificates" }).click();
    await expect(
      page.getByRole("button", { name: /Generate Certificate/i })
    ).toBeVisible();
  });

  test("Tenants tab shows tenant name from mocked data", async ({ page }) => {
    await page.goto("/organizations/org-1");
    await expect(page.getByText("Default Tenant")).toBeVisible();
  });
});
