import { test, expect } from "@playwright/test";

// ─── Mock data ────────────────────────────────────────────────────────────────

const mockUsers = [
  {
    id: "1",
    username: "alice",
    email: "alice@example.com",
    display_name: "Alice Smith",
    is_active: true,
    mfa_enabled: true,
    email_verified: true,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "2",
    username: "bob",
    email: "bob@example.com",
    display_name: "Bob Jones",
    is_active: false,
    mfa_enabled: false,
    email_verified: false,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  },
];

const mockPaginatedUsers = {
  data: mockUsers,
  total: 2,
  page: 1,
  per_page: 20,
};

const mockMfaMethods = [
  {
    id: "mfa-1",
    method_type: "totp",
    name: "Authenticator App",
    created_at: "2026-01-05T00:00:00Z",
  },
];

const mockGroups = [
  {
    id: "grp-1",
    name: "Engineering",
    description: "Engineering team",
    created_at: "2026-01-10T00:00:00Z",
  },
  {
    id: "grp-2",
    name: "Admins",
    description: undefined,
    created_at: "2026-01-12T00:00:00Z",
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
        orgId: "org-1",
        tenantId: "tenant-1",
      },
      version: 0,
    };
    sessionStorage.setItem("axiam-auth", JSON.stringify(fakeState));
  });
}

// ─── Users list tests ─────────────────────────────────────────────────────────

test.describe("Users list page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/users**", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockPaginatedUsers });
      } else {
        route.continue();
      }
    });
  });

  test("renders users list with mocked data — alice visible", async ({
    page,
  }) => {
    await page.goto("/users");
    await expect(page.getByText("Alice Smith")).toBeVisible();
  });

  test('"New User" button opens create modal with username/email/password fields', async ({
    page,
  }) => {
    await page.goto("/users");
    await page.getByRole("button", { name: /New User/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "New User" })
    ).toBeVisible();
    // Use label text exact match to avoid collisions with aria-labels in table cells
    await expect(page.getByLabel("Username *")).toBeVisible();
    await expect(page.getByLabel("Email *")).toBeVisible();
    await expect(page.getByLabel("Password *")).toBeVisible();
  });

  test("inactive user shows inactive status badge", async ({ page }) => {
    await page.goto("/users");
    // Bob is inactive — find his row and check the badge
    const bobRow = page.getByRole("row", { name: /bob/i });
    await expect(bobRow.getByText("Inactive")).toBeVisible();
  });

  test("MFA enabled user shows Enabled badge", async ({ page }) => {
    await page.goto("/users");
    // Alice has MFA enabled
    const aliceRow = page.getByRole("row", { name: /alice/i });
    await expect(aliceRow.getByText("Enabled")).toBeVisible();
  });
});

// ─── User detail page tests ───────────────────────────────────────────────────

test.describe("User detail page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/users/1", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockUsers[0] });
      } else {
        route.continue();
      }
    });

    await page.route("**/api/v1/users/1/mfa-methods", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockMfaMethods });
      } else {
        route.continue();
      }
    });

    await page.route("**/api/v1/roles**", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: [] });
      } else {
        route.continue();
      }
    });
  });

  test("user detail page shows MFA Methods section", async ({ page }) => {
    await page.goto("/users/1");
    await expect(
      page.getByRole("heading", { name: "MFA Methods", level: 2 })
    ).toBeVisible();
    // The TOTP method name should appear in the table
    await expect(page.getByText("Authenticator App")).toBeVisible();
  });

  test("user detail page shows Reset MFA button", async ({ page }) => {
    await page.goto("/users/1");
    await expect(
      page.getByRole("button", { name: /Reset MFA/i })
    ).toBeVisible();
  });

  test("user detail page shows user info card", async ({ page }) => {
    await page.goto("/users/1");
    await expect(
      page.getByRole("heading", { name: "User Info", level: 2 })
    ).toBeVisible();
    // Use exact match to avoid ambiguity with alice@example.com and Alice Smith
    await expect(page.getByText("alice", { exact: true })).toBeVisible();
    await expect(page.getByText("alice@example.com", { exact: true })).toBeVisible();
  });
});

// ─── Groups list tests ────────────────────────────────────────────────────────

test.describe("Groups list page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/groups", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockGroups });
      } else {
        route.continue();
      }
    });
  });

  test("renders groups list with mocked data", async ({ page }) => {
    await page.goto("/groups");
    // Use the button role (group name is a nav link button) to avoid ambiguity with description
    await expect(
      page.getByRole("button", { name: "Engineering", exact: true })
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Admins", exact: true })
    ).toBeVisible();
  });

  test("shows Groups page heading", async ({ page }) => {
    await page.goto("/groups");
    await expect(
      page.getByRole("heading", { name: "Groups" })
    ).toBeVisible();
  });

  test('"New Group" button opens create modal', async ({ page }) => {
    await page.goto("/groups");
    await page.getByRole("button", { name: /New Group/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "New Group" })
    ).toBeVisible();
  });
});

// ─── Group detail page tests ──────────────────────────────────────────────────

test.describe("Group detail page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/groups/grp-1", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockGroups[0] });
      } else {
        route.continue();
      }
    });

    await page.route("**/api/v1/groups/grp-1/members", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: [mockUsers[0]] });
      } else {
        route.continue();
      }
    });
  });

  test("group detail shows Members section with Add Member button", async ({
    page,
  }) => {
    await page.goto("/groups/grp-1");
    await expect(
      page.getByRole("heading", { name: "Members", level: 2 })
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: /Add Member/i })
    ).toBeVisible();
  });

  test("group detail shows existing member in table", async ({ page }) => {
    await page.goto("/groups/grp-1");
    await expect(page.getByText("Alice Smith")).toBeVisible();
  });

  test("group detail shows group name in info card", async ({ page }) => {
    await page.goto("/groups/grp-1");
    // Exact match to avoid collision with "Engineering team" description
    await expect(page.getByText("Engineering", { exact: true })).toBeVisible();
  });
});
