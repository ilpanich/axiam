import { test, expect } from "@playwright/test";

// ─── Mock data ────────────────────────────────────────────────────────────────

const mockUsersResp = {
  data: [
    {
      id: "1",
      username: "alice",
      email: "a@b.com",
      display_name: "Alice",
      is_active: true,
      mfa_enabled: true,
      email_verified: true,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    },
  ],
  total: 42,
  page: 1,
  per_page: 1,
};

const mockAuditLogs = {
  data: [
    {
      id: "1",
      actor_id: "u1",
      actor_username: "alice",
      action: "user.created",
      resource_type: "user",
      resource_id: "u2",
      outcome: "success",
      ip_address: "10.0.0.1",
      created_at: "2026-03-27T10:00:00Z",
    },
  ],
  total: 1,
  page: 1,
  per_page: 8,
};

const mockCerts: unknown[] = [];
const mockGroups: unknown[] = [];
const mockRoles: unknown[] = [];

const mockOAuth2Clients = [
  {
    id: "c1",
    client_id: "abc-123-def",
    name: "My App",
    redirect_uris: ["https://app.example.com/callback"],
    grant_types: ["authorization_code"],
    scopes: ["openid", "profile"],
    is_public: false,
    created_at: "2026-01-15T00:00:00Z",
  },
];

const mockNotificationRules = [
  {
    id: "nr1",
    event_type: "user.created",
    recipient_emails: ["admin@example.com"],
    is_active: true,
    description: "Notify on new users",
    created_at: "2026-01-20T00:00:00Z",
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

// ─── Dashboard tests ──────────────────────────────────────────────────────────

test.describe("Dashboard page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    // Wire up all dashboard API calls
    await page.route("**/api/v1/users**", (route) => {
      route.fulfill({ json: mockUsersResp });
    });
    await page.route("**/api/v1/groups**", (route) => {
      route.fulfill({ json: mockGroups });
    });
    await page.route("**/api/v1/roles**", (route) => {
      route.fulfill({ json: mockRoles });
    });
    await page.route("**/api/v1/certificates**", (route) => {
      route.fulfill({ json: mockCerts });
    });
    await page.route("**/api/v1/audit-logs**", (route) => {
      route.fulfill({ json: mockAuditLogs });
    });
  });

  test('dashboard shows "Users" stat card', async ({ page }) => {
    await page.goto("/dashboard");
    // Use section label to scope to the stat card, avoiding the nav sidebar "Users" link
    await expect(
      page.getByLabel("Key metrics").getByText("Users")
    ).toBeVisible();
  });

  test("dashboard shows total user count 42 from mocked data", async ({
    page,
  }) => {
    await page.goto("/dashboard");
    await expect(page.getByText("42")).toBeVisible();
  });

  test("dashboard shows recent activity section", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page.getByText("Recent Activity")).toBeVisible();
  });

  test("dashboard shows quick actions section", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page.getByText("Quick Actions")).toBeVisible();
  });
});

// ─── Audit Logs tests ─────────────────────────────────────────────────────────

test.describe("Audit Logs page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/audit-logs**", (route) => {
      route.fulfill({ json: mockAuditLogs });
    });
  });

  test("audit logs page renders filter bar", async ({ page }) => {
    await page.goto("/audit-logs");
    // The filter bar is a section with labeled inputs
    await expect(page.getByRole("heading", { name: "Audit Logs" })).toBeVisible();
    await expect(page.getByLabel("Actor")).toBeVisible();
  });

  test("audit log filter bar has Actor, Action, Outcome fields", async ({
    page,
  }) => {
    await page.goto("/audit-logs");
    await expect(page.getByLabel("Actor")).toBeVisible();
    await expect(page.getByLabel("Action")).toBeVisible();
    await expect(page.getByLabel("Outcome")).toBeVisible();
  });

  test("audit log row shows actor username and action", async ({ page }) => {
    await page.goto("/audit-logs");
    await expect(page.getByText("alice")).toBeVisible();
    await expect(page.getByText("user.created")).toBeVisible();
  });

  test("audit log outcome shows success indicator", async ({ page }) => {
    await page.goto("/audit-logs");
    // Scope to the table to avoid matching the hidden <option> element in the Outcome filter select
    await expect(page.getByRole("table").getByText("Success")).toBeVisible();
  });
});

// ─── OAuth2 Clients tests ─────────────────────────────────────────────────────

test.describe("OAuth2 Clients page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/oauth2-clients**", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockOAuth2Clients });
      } else {
        route.continue();
      }
    });
  });

  test("OAuth2 clients list renders with New Client button", async ({
    page,
  }) => {
    await page.goto("/oauth2-clients");
    await expect(
      page.getByRole("button", { name: /New Client/i })
    ).toBeVisible();
    // The mocked client name should be visible in the table
    await expect(page.getByText("My App")).toBeVisible();
  });

  test("OAuth2 client create modal has Grant Types checkboxes", async ({
    page,
  }) => {
    await page.goto("/oauth2-clients");
    await page.getByRole("button", { name: /New Client/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    // Grant types group should be present
    await expect(page.getByText("Grant Types *")).toBeVisible();
    // Each grant type checkbox should be present
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

// ─── Notification Rules tests ─────────────────────────────────────────────────

test.describe("Notification Rules page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/notification-rules**", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockNotificationRules });
      } else {
        route.continue();
      }
    });
  });

  test("notification rules list renders with New Rule button", async ({
    page,
  }) => {
    await page.goto("/notification-rules");
    await expect(
      page.getByRole("button", { name: /New Rule/i })
    ).toBeVisible();
    // The mocked rule event type should be visible
    await expect(page.getByText("user.created")).toBeVisible();
  });

  test("notification rule create modal has Event Type and Recipient Emails fields", async ({
    page,
  }) => {
    await page.goto("/notification-rules");
    await page.getByRole("button", { name: /New Rule/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    // Use regex to match "Event Type *" label text (the * is part of the label)
    await expect(page.getByLabel(/Event Type/i)).toBeVisible();
    await expect(
      page.getByLabel("Recipient Emails (one per line)")
    ).toBeVisible();
  });
});
