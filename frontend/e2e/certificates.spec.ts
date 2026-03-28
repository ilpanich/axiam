import { test, expect } from "@playwright/test";

// ─── Mock data ────────────────────────────────────────────────────────────────

const mockCerts = [
  {
    id: "1",
    common_name: "api.acme.com",
    key_type: "RSA4096",
    status: "active",
    expires_at: "2027-01-01T00:00:00Z",
    serial_number: "AA:BB:CC:DD",
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "2",
    common_name: "old.acme.com",
    key_type: "Ed25519",
    status: "revoked",
    expires_at: "2025-01-01T00:00:00Z",
    serial_number: "11:22:33:44",
    created_at: "2025-01-01T00:00:00Z",
  },
];

const mockWebhooks = [
  {
    id: "1",
    url: "https://hooks.example.com/axiam",
    event_types: ["user.created", "user.deleted"],
    is_active: true,
    description: "Main hook",
    created_at: "2026-01-01T00:00:00Z",
  },
];

const mockPgpKeys = [
  {
    id: "1",
    user_id: "u1",
    key_type: "RSA4096",
    fingerprint: "AABB CCDD EEFF 0011",
    description: "Audit signing key",
    status: "active",
    public_key_armor:
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----",
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

// ─── Certificates tests ───────────────────────────────────────────────────────

test.describe("Certificates page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/certificates", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockCerts });
      } else {
        route.continue();
      }
    });
  });

  test("renders certificates list with mocked data — common name visible", async ({
    page,
  }) => {
    await page.goto("/certificates");
    await expect(page.getByText("api.acme.com")).toBeVisible();
  });

  test("revoked cert shows revoked status badge", async ({ page }) => {
    await page.goto("/certificates");
    const revokedRow = page.getByRole("row", { name: /old\.acme\.com/i });
    await expect(revokedRow.getByText("Revoked")).toBeVisible();
  });

  test('"Generate Certificate" button opens modal with common name field', async ({
    page,
  }) => {
    await page.goto("/certificates");
    await page.getByRole("button", { name: /Generate Certificate/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByLabel("Common Name *")).toBeVisible();
  });

  test("generate modal has Key Type select and Validity Days field", async ({
    page,
  }) => {
    await page.goto("/certificates");
    await page.getByRole("button", { name: /Generate Certificate/i }).click();
    await expect(page.getByLabel("Key Type")).toBeVisible();
    await expect(page.getByLabel("Validity Days")).toBeVisible();
  });
});

// ─── Webhooks tests ───────────────────────────────────────────────────────────

test.describe("Webhooks page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/webhooks", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockWebhooks });
      } else {
        route.continue();
      }
    });
  });

  test("renders webhooks list with mocked data — URL visible", async ({
    page,
  }) => {
    await page.goto("/webhooks");
    await expect(
      page.getByText("https://hooks.example.com/axiam")
    ).toBeVisible();
  });

  test("webhook shows event count badge", async ({ page }) => {
    await page.goto("/webhooks");
    await expect(page.getByText("2 events")).toBeVisible();
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
    // At least one event type checkbox should be visible (aria-label matches event name)
    await expect(
      page.getByRole("checkbox", { name: "user.created" })
    ).toBeVisible();
  });
});

// ─── PGP Keys tests ───────────────────────────────────────────────────────────

test.describe("PGP Keys page", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuth(page);

    await page.route("**/api/v1/pgp-keys", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({ json: mockPgpKeys });
      } else {
        route.continue();
      }
    });
  });

  test("renders PGP keys list with mocked data — fingerprint visible", async ({
    page,
  }) => {
    await page.goto("/pgp-keys");
    await expect(page.getByText("AABB CCDD EEFF 0011")).toBeVisible();
  });

  test("PGP key row shows View Public Key action button", async ({ page }) => {
    await page.goto("/pgp-keys");
    await expect(
      page.getByRole("button", { name: /View public key/i })
    ).toBeVisible();
  });
});
