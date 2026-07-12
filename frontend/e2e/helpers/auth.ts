import { Page } from "@playwright/test";

/**
 * Shared Playwright storageState file for the authenticated admin session.
 *
 * The `setup` project (e2e/auth.setup.ts) performs ONE real UI login and
 * writes the resulting httpOnly session + CSRF cookies here; every other
 * project loads it via `use.storageState`, so the suite pays the Argon2id
 * login cost once instead of ~60 times. Path is relative to the Playwright
 * cwd (the `frontend/` directory). Gitignored.
 */
export const STORAGE_STATE = "e2e/.auth/admin.json";

/**
 * loginAsAdmin — ensures the page has an authenticated admin session.
 *
 * With the shared storageState in place (the default for most projects), a
 * session cookie is already loaded, so this becomes a fast no-op: it navigates
 * home and returns as soon as it confirms we are not bounced to /login. Only
 * when there is no session (the auth-flow specs opt out of storageState with an
 * empty session, and the `setup` project itself starts clean) does it drive the
 * full two-step login UI.
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

  // Fast path: if a session already exists (shared storageState), navigating
  // home settles on an authenticated route rather than /login — nothing to do.
  //
  // The app's AuthGate renders ONLY a loading spinner (URL still "/") until
  // GET /auth/me resolves, then routes: authenticated -> /dashboard,
  // unauthenticated -> /dashboard -> /login. So we must wait for that init +
  // client-side redirect to fully settle before reading the URL — a bare
  // waitForURL matches the transient "/" during the spinner and would wrongly
  // report "authenticated". `networkidle` waits for /auth/me (and any boot
  // refresh) plus the settled route; the app does no background polling, so it
  // reliably goes idle.
  await page.goto("/", { waitUntil: "networkidle", timeout: 45_000 }).catch(() => {});
  if (!new URL(page.url()).pathname.startsWith("/login")) {
    return;
  }
  // Unauthenticated: make sure the login form has rendered before filling.
  await page
    .getByLabel("Organization slug")
    .waitFor({ state: "visible", timeout: 15_000 });

  // Step 1: Enter org and tenant slugs
  await page.getByLabel("Organization slug").fill(orgSlug);
  await page.getByLabel("Tenant slug").fill(tenantSlug);
  await page.getByRole("button", { name: "Continue" }).click();

  // Step 2: Enter credentials
  await page.getByLabel("Username or email").fill(adminEmail);
  await page.getByLabel("Password").fill(adminPassword);
  await page.getByRole("button", { name: "Sign in" }).click();

  // Wait for successful redirect off /login (httpOnly cookie is now set).
  // 45s (not 15s): every login runs an Argon2id verification on the backend,
  // and under a loaded CI runner sharing CPU with the server container the
  // post-login redirect can occasionally take >15s, which showed up as
  // intermittent `waitForURL` timeouts across the suite.
  await page.waitForURL(/\/dashboard|\/$/, { timeout: 45_000 });
}
