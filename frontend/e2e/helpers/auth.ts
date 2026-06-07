import { Page } from "@playwright/test";

/**
 * loginAsAdmin — drives the real AXIAM login UI to authenticate as admin.
 *
 * Uses E2E_ORG_SLUG / E2E_TENANT_SLUG / E2E_ADMIN_EMAIL / E2E_ADMIN_PASSWORD
 * env vars (with defaults matching scripts/e2e-bootstrap.sh).
 *
 * Auth state is maintained via an httpOnly cookie set by the backend — no
 * sessionStorage or localStorage is used (T-07-12 / ASVS V3.1).
 *
 * Field labels verified from frontend/e2e/login.spec.ts:8,22,28,33.
 */
export async function loginAsAdmin(page: Page): Promise<void> {
  const orgSlug = process.env["E2E_ORG_SLUG"] ?? "test-org";
  const tenantSlug = process.env["E2E_TENANT_SLUG"] ?? "default";
  const adminEmail = process.env["E2E_ADMIN_EMAIL"] ?? "admin@axiam.dev";
  const adminPassword = process.env["E2E_ADMIN_PASSWORD"] ?? "Test@Admin123!";

  await page.goto("/login");

  // Step 1: Enter org and tenant slugs
  await page.getByLabel("Organization slug").fill(orgSlug);
  await page.getByLabel("Tenant slug").fill(tenantSlug);
  await page.getByRole("button", { name: "Continue" }).click();

  // Step 2: Enter credentials
  await page.getByLabel("Username or email").fill(adminEmail);
  await page.getByLabel("Password").fill(adminPassword);
  await page.getByRole("button", { name: "Sign in" }).click();

  // Wait for successful redirect off /login (httpOnly cookie is now set)
  await page.waitForURL(/\/dashboard|\/$/, { timeout: 15_000 });
}
