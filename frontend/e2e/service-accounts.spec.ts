import { test, expect } from "@playwright/test";

const mockServiceAccounts = [
  {
    id: "sa-1",
    name: "CI/CD Pipeline",
    description: "Used for automated deployments",
    client_id: "sa-ci-cd-pipeline-abc123",
    status: "active",
    roles: ["admin", "deploy", "read"],
    last_used_at: "2026-03-20T14:30:00Z",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-03-20T14:30:00Z",
  },
  {
    id: "sa-2",
    name: "Monitoring Agent",
    description: "Read-only access for monitoring",
    client_id: "sa-monitoring-agent-def456",
    status: "disabled",
    roles: ["monitoring-read"],
    last_used_at: undefined,
    created_at: "2026-02-15T00:00:00Z",
    updated_at: "2026-02-15T00:00:00Z",
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

test.describe("Service Accounts page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/service-accounts**", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockServiceAccounts });
      } else {
        route.continue();
      }
    });
  });

  test("renders Service Accounts page header", async ({ page }) => {
    await page.goto("/service-accounts");
    await expect(
      page.getByRole("heading", { name: "Service Accounts" })
    ).toBeVisible();
  });

  test("renders service account list with mocked data", async ({ page }) => {
    await page.goto("/service-accounts");
    await expect(page.getByText("CI/CD Pipeline")).toBeVisible();
    await expect(page.getByText("Monitoring Agent")).toBeVisible();
  });

  test("shows client IDs in the table", async ({ page }) => {
    await page.goto("/service-accounts");
    await expect(
      page.getByText("sa-ci-cd-pipeline-abc123")
    ).toBeVisible();
  });

  test('"New Service Account" button opens create modal', async ({
    page,
  }) => {
    await page.goto("/service-accounts");
    await page
      .getByRole("button", { name: /New Service Account/i })
      .click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "New Service Account" })
    ).toBeVisible();
  });

  test("create form has Name and Description fields", async ({ page }) => {
    await page.goto("/service-accounts");
    await page
      .getByRole("button", { name: /New Service Account/i })
      .click();
    await expect(page.getByLabel(/Name/)).toBeVisible();
    await expect(page.getByLabel(/Description/)).toBeVisible();
  });

  test("shows active/disabled status badges", async ({ page }) => {
    await page.goto("/service-accounts");
    await expect(page.getByText("Active").first()).toBeVisible();
  });

  test("rotate secret button exists for each account", async ({ page }) => {
    await page.goto("/service-accounts");
    await expect(
      page
        .getByRole("button", { name: /Rotate secret for CI\/CD Pipeline/i })
    ).toBeVisible();
  });

  test("rotate secret shows confirmation dialog", async ({ page }) => {
    await page.goto("/service-accounts");
    await page
      .getByRole("button", { name: /Rotate secret for CI\/CD Pipeline/i })
      .click();
    await expect(
      page.getByRole("dialog", { name: /Rotate Client Secret/i })
    ).toBeVisible();
  });

  test("delete button shows confirmation dialog", async ({ page }) => {
    await page.goto("/service-accounts");
    await page
      .getByRole("button", { name: /Delete CI\/CD Pipeline/i })
      .click();
    await expect(
      page.getByRole("dialog", { name: /Delete Service Account/i })
    ).toBeVisible();
  });

  test("search filters service accounts", async ({ page }) => {
    await page.goto("/service-accounts");
    await page.getByPlaceholder(/search/i).fill("Monitor");
    await expect(page.getByText("Monitoring Agent")).toBeVisible();
    await expect(page.getByText("CI/CD Pipeline")).not.toBeVisible();
  });
});
