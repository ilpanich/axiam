import { test, expect } from "@playwright/test";

// ─── Mock data ────────────────────────────────────────────────────────────────

const mockRoles = [
  {
    id: "1",
    name: "Admin",
    description: "Full access",
    is_global: true,
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "2",
    name: "Viewer",
    description: "Read only",
    is_global: false,
    created_at: "2026-01-01T00:00:00Z",
  },
];

const mockPermissions = [
  {
    id: "1",
    name: "users:read",
    action: "read",
    description: "Read users",
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "2",
    name: "users:write",
    action: "write",
    description: "Write users",
    created_at: "2026-01-01T00:00:00Z",
  },
];

const mockResources = [
  {
    id: "1",
    name: "API Gateway",
    resource_type: "api",
    description: "Main API",
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "2",
    name: "Users endpoint",
    resource_type: "endpoint",
    parent_id: "1",
    description: "User API",
    created_at: "2026-01-01T00:00:00Z",
  },
];

// ─── Auth helper ──────────────────────────────────────────────────────────────

async function mockAuth(page: import("@playwright/test").Page): Promise<void> {
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

// ─── Roles list tests ─────────────────────────────────────────────────────────

test.describe("Roles list page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/roles", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockRoles });
      } else {
        route.continue();
      }
    });
  });

  test("1. renders roles list with mocked data — Admin role visible", async ({
    page,
  }) => {
    await page.goto("/roles");
    await expect(page.getByText("Admin", { exact: true })).toBeVisible();
  });

  test('2. "Global" badge appears on global role', async ({ page }) => {
    await page.goto("/roles");
    // The Admin role is_global: true — should show Global badge
    // Find the row containing "Admin" and check for Global badge
    const adminRow = page.getByRole("row", { name: /Admin/i });
    await expect(adminRow.getByText("Global")).toBeVisible();
  });

  test('3. "New Role" button opens modal with name/description/global toggle fields', async ({
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
});

// ─── Role detail page tests ───────────────────────────────────────────────────

test.describe("Role detail page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/roles/1", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockRoles[0] });
      } else {
        route.continue();
      }
    });

    await page.route("**/api/v1/roles/1/permissions", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: [mockPermissions[0]] });
      } else {
        route.continue();
      }
    });

    await page.route("**/api/v1/permissions", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockPermissions });
      } else {
        route.continue();
      }
    });

    await page.route("**/api/v1/groups", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: [] });
      } else {
        route.continue();
      }
    });
  });

  test("4. role detail page shows Permissions section", async ({ page }) => {
    await page.goto("/roles/1");
    await expect(
      page.getByRole("heading", { name: "Permissions", level: 2 })
    ).toBeVisible();
    // The granted permission should appear in the table
    await expect(page.getByText("users:read")).toBeVisible();
  });

  test('5. role detail page shows "Grant Permission" button', async ({
    page,
  }) => {
    await page.goto("/roles/1");
    await expect(
      page.getByRole("button", { name: /Grant Permission/i })
    ).toBeVisible();
  });
});

// ─── Permissions list tests ───────────────────────────────────────────────────

test.describe("Permissions list page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/permissions", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockPermissions });
      } else {
        route.continue();
      }
    });

    await page.route("**/api/v1/resources", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockResources });
      } else {
        route.continue();
      }
    });
  });

  test("6. permissions list renders with mocked data", async ({ page }) => {
    await page.goto("/permissions");
    await expect(page.getByText("users:read")).toBeVisible();
    await expect(page.getByText("users:write")).toBeVisible();
  });

  test("7. permission action badge shows correctly (read = blue badge)", async ({
    page,
  }) => {
    await page.goto("/permissions");
    // The read badge for users:read should be visible
    // We look for the span with text "read" that has the blue styling
    const readBadge = page.locator("span").filter({ hasText: /^read$/ }).first();
    await expect(readBadge).toBeVisible();
    // Verify it has the blue color class
    await expect(readBadge).toHaveClass(/text-blue-400/);
  });
});

// ─── Resources page tests ─────────────────────────────────────────────────────

test.describe("Resources page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/resources", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockResources });
      } else {
        route.continue();
      }
    });
  });

  test("8. resources page renders tree view by default", async ({ page }) => {
    await page.goto("/resources");
    // Tree view is default — ResourceTree renders a role="tree" element
    await expect(page.getByRole("tree")).toBeVisible();
    // The tree view toggle button should be pressed
    await expect(page.getByRole("button", { name: /Tree view/i })).toHaveAttribute(
      "aria-pressed",
      "true"
    );
  });

  test("9. resource tree shows parent-child hierarchy (API Gateway with Users endpoint child)", async ({
    page,
  }) => {
    await page.goto("/resources");
    await expect(page.getByText("API Gateway")).toBeVisible();
    await expect(page.getByText("Users endpoint")).toBeVisible();
  });

  test("10. list view toggle shows table", async ({ page }) => {
    await page.goto("/resources");
    // Click list view toggle
    await page.getByRole("button", { name: /List view/i }).click();
    // Should now see a table — wait for tree to disappear
    await expect(page.getByRole("tree")).not.toBeVisible();
    await expect(page.getByRole("table")).toBeVisible();
    // Verify both resources appear in the table (look for rows by resource name in name column)
    const nameCell = page
      .getByRole("row")
      .filter({ hasText: /^API Gateway/ })
      .first();
    await expect(nameCell).toBeVisible();
    const usersCell = page
      .getByRole("row")
      .filter({ hasText: /^Users endpoint/ })
      .first();
    await expect(usersCell).toBeVisible();
  });
});
