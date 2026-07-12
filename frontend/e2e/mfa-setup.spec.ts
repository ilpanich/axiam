import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./helpers/auth";

// Drives login/MFA-setup flows (mocked and real) from an unauthenticated
// starting point, so it opts out of the shared admin session.
test.use({ storageState: { cookies: [], origins: [] } });

// ---------------------------------------------------------------------------
// mfa-setup.spec.ts — CORR-05b (D-16) no-dead-end + tenant-restore-after-reload
// ---------------------------------------------------------------------------
//
// Two contracts under test:
//
// 1. An MFA-mandated login (mfa_setup_required + setup_token) must land on
//    the public /auth/mfa-setup route carrying setup_token in the URL (not
//    router state), enroll, and never strand the user back on /login.
// 2. After a hard reload, the Topbar must restore the tenant from the
//    /auth/me tenant_slug/org_slug fields (26-05 backend half) with no
//    persisted "Select tenant" fallback.

test.describe("MFA-setup no-dead-end (CORR-05b / D-16)", () => {
  test("mfa_setup_required login routes to /auth/mfa-setup with setup_token and renders enroll UI", async ({
    page,
  }) => {
    // scripts/e2e-bootstrap.sh (the seeded E2E fixture) does not provision a
    // user in the mfa_setup_required state, so the /auth/login response is
    // mocked here to force it. This still exercises the REAL frontend
    // routing contract under test (LoginPage's mfa_setup_required branch and
    // the real MfaSetupPage component + its real enroll call) — only the
    // network responses are stubbed, not any client-side logic.
    const orgSlug = process.env["E2E_ORG_SLUG"] ?? "test-org";
    const tenantSlug = process.env["E2E_TENANT_SLUG"] ?? "default";
    const mockSetupToken = "e2e-mock-setup-token";

    await page.route("**/api/v1/auth/login", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          mfa_setup_required: true,
          setup_token: mockSetupToken,
        }),
      });
    });

    await page.route("**/api/v1/auth/mfa/setup/enroll", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          secret_base32: "JBSWY3DPEHPK3PXP",
          totp_uri:
            "otpauth://totp/AXIAM:e2e-mfa-setup@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AXIAM",
        }),
      });
    });

    await page.goto("/login");
    await page.getByLabel("Organization slug").fill(orgSlug);
    await page.getByLabel("Tenant slug").fill(tenantSlug);
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByLabel("Username or email").fill("mfa-setup-user@example.com");
    await page.getByLabel("Password").fill("SomePassword123!");
    await page.getByRole("button", { name: "Sign in" }).click();

    // No dead end: bookmark/refresh-safe query-param carrier, not router
    // state — reaches /auth/mfa-setup, never stranded back on /login.
    await expect(page).toHaveURL(
      new RegExp(`/auth/mfa-setup\\?setup_token=${mockSetupToken}`)
    );

    // Enroll UI (QR + manual secret + code input) rendered from the real
    // MfaSetupPage + shared TotpSetupPanel component.
    await expect(
      page.getByRole("heading", { name: "Set up your authenticator" })
    ).toBeVisible();
    await expect(page.getByText(/enter this key manually/i)).toBeVisible();
    await expect(page.getByLabel("Verification Code")).toBeVisible();
  });

  test.skip(
    "full enroll -> confirm -> dashboard flow completes without a dead end",
    async () => {
      // Tracking note: the seeded E2E fixture (scripts/e2e-bootstrap.sh) does
      // not provision a user in the mfa_setup_required state, and confirming
      // a mocked TOTP secret would not exercise the real backend's
      // /mfa/setup/confirm verification (computing a live TOTP code against
      // a stubbed secret defeats the purpose of testing against a real
      // backend). This leg requires a seed-fixture enhancement that
      // provisions a genuine mfa_setup_required user + a way to compute the
      // matching TOTP code — tracked as a follow-up, not a blocking gap in
      // this plan's scope (green means green, per D-12).
    }
  );
});

test.describe("Tenant context restore after hard reload (CORR-05a/b, D-14/D-15)", () => {
  test("Topbar restores the org/tenant slug after a hard reload — no persisted Select tenant flash", async ({
    page,
  }) => {
    const orgSlug = process.env["E2E_ORG_SLUG"] ?? "test-org";
    const tenantSlug = process.env["E2E_TENANT_SLUG"] ?? "default";

    await loginAsAdmin(page);
    await expect(page.getByRole("navigation").first()).toBeVisible();

    // Fresh login already shows the restored tenant label (ambient
    // login-form slugs) — confirm the baseline before reloading.
    const restoredPattern = new RegExp(
      `${orgSlug.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*/\\s*${tenantSlug.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`
    );
    await expect(page.getByRole("button", { name: restoredPattern })).toBeVisible();

    // Hard reload — the auth store is rebuilt from scratch via useAuthInit's
    // /auth/me call. Tenant context must be restored from the 26-05
    // tenant_slug/org_slug fields, not from any client-side login-form
    // state (which is gone after a reload).
    await page.reload();
    await page.waitForURL(/\/dashboard|\/$/, { timeout: 15_000 });

    await expect(page.getByRole("button", { name: restoredPattern })).toBeVisible();

    // Non-negotiable (UI-SPEC): the degraded fallback must not appear as a
    // stable post-restore state once /auth/me has resolved.
    await expect(page.getByRole("button", { name: "Select tenant" })).toHaveCount(0);
  });
});
