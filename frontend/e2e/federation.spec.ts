import { test, expect } from "@playwright/test";

const mockProviders = [
  {
    id: "fed-1",
    name: "Corporate SSO",
    type: "saml",
    status: "active",
    domain: "corp.example.com",
    last_sync_at: "2026-03-25T10:00:00Z",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-03-25T10:00:00Z",
    saml_config: {
      metadata_url: "https://idp.corp.example.com/metadata",
      entity_id: "urn:corp:idp",
      sso_url: "https://idp.corp.example.com/sso",
      certificate: "-----BEGIN CERTIFICATE-----\nMIIC...",
    },
  },
  {
    id: "fed-2",
    name: "Google Workspace",
    type: "oidc",
    status: "active",
    domain: "workspace.google.com",
    last_sync_at: "2026-03-26T08:00:00Z",
    created_at: "2026-02-01T00:00:00Z",
    updated_at: "2026-03-26T08:00:00Z",
    oidc_config: {
      issuer_url: "https://accounts.google.com",
      client_id: "google-client-id",
      client_secret: "***",
      scopes: ["openid", "email", "profile"],
    },
  },
  {
    id: "fed-3",
    name: "Legacy LDAP Bridge",
    type: "saml",
    status: "inactive",
    domain: "legacy.internal",
    created_at: "2025-06-01T00:00:00Z",
    updated_at: "2025-06-01T00:00:00Z",
    saml_config: {
      metadata_url: "https://ldap-bridge.internal/metadata",
      entity_id: "urn:legacy:ldap",
      sso_url: "https://ldap-bridge.internal/sso",
      certificate: "-----BEGIN CERTIFICATE-----\nMIIB...",
    },
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
        orgId: "org-1",
        tenantId: "tenant-1",
      },
      version: 0,
    };
    sessionStorage.setItem("axiam-auth", JSON.stringify(fakeState));
  });
}

test.describe("Federation page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/federation/providers**", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockProviders });
      } else {
        route.continue();
      }
    });
  });

  test("renders Federation page header", async ({ page }) => {
    await page.goto("/federation");
    await expect(
      page.getByRole("heading", { name: "Federation" })
    ).toBeVisible();
  });

  test("renders provider list with mocked data", async ({ page }) => {
    await page.goto("/federation");
    await expect(page.getByText("Corporate SSO")).toBeVisible();
    await expect(page.getByText("Google Workspace")).toBeVisible();
    await expect(page.getByText("Legacy LDAP Bridge")).toBeVisible();
  });

  test("shows SAML and OIDC type badges", async ({ page }) => {
    await page.goto("/federation");
    await expect(page.getByText("SAML").first()).toBeVisible();
    await expect(page.getByText("OIDC")).toBeVisible();
  });

  test("shows domain for each provider", async ({ page }) => {
    await page.goto("/federation");
    await expect(page.getByText("corp.example.com")).toBeVisible();
    await expect(page.getByText("workspace.google.com")).toBeVisible();
  });

  test('"New Provider" button opens create modal', async ({ page }) => {
    await page.goto("/federation");
    await page.getByRole("button", { name: /New Provider/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "New Federation Provider" })
    ).toBeVisible();
  });

  test("create form has Name, Type, and Domain fields", async ({ page }) => {
    await page.goto("/federation");
    await page.getByRole("button", { name: /New Provider/i }).click();
    await expect(page.getByLabel(/Name/)).toBeVisible();
    await expect(page.getByLabel(/Domain/)).toBeVisible();
  });

  test("test connection button exists for each provider", async ({
    page,
  }) => {
    await page.goto("/federation");
    await expect(
      page.getByRole("button", {
        name: /Test connection for Corporate SSO/i,
      })
    ).toBeVisible();
  });

  test("shows active/inactive status badges", async ({ page }) => {
    await page.goto("/federation");
    await expect(page.getByText("Active").first()).toBeVisible();
  });

  test("delete button shows confirmation dialog", async ({ page }) => {
    await page.goto("/federation");
    await page
      .getByRole("button", { name: /Delete Corporate SSO/i })
      .click();
    await expect(
      page.getByRole("dialog", { name: /Delete Federation Provider/i })
    ).toBeVisible();
  });

  test("search filters providers by name", async ({ page }) => {
    await page.goto("/federation");
    await page.getByPlaceholder(/search/i).fill("Google");
    await expect(page.getByText("Google Workspace")).toBeVisible();
    await expect(page.getByText("Corporate SSO")).not.toBeVisible();
  });
});
