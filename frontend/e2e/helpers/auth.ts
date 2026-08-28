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
 * Uses E2E_ORG_SLUG / E2E_TENANT_SLUG / E2E_TENANT_ADMIN_USERNAME /
 * E2E_ADMIN_PASSWORD env vars (with defaults matching
 * scripts/e2e-bootstrap.sh, which seeds the tenant admin with the same
 * password as the super-admin so there is one fixture credential, not two).
 *
 * Signs in as the TENANT-level administrator, not the organization-level
 * super-admin bootstrap creates. Both exist in the seeded stack and the
 * difference matters here: an organization-level principal signs in naming no
 * tenant, and then acts on its own organization scope until the UI's tenant
 * selector points it somewhere else. Almost every spec in this suite asserts
 * on tenant-scoped data (users, roles, resources, certificates), so the
 * principal that owns that data is the one to be. The organization-level flow
 * has its own coverage: `lib/activeTenant` and `lib/grantReach` unit tests,
 * and `examples/b6-organization-scope` end to end.
 *
 * Auth state is maintained via an httpOnly cookie set by the backend — no
 * sessionStorage or localStorage is used (T-07-12 / ASVS V3.1).
 *
 * Field labels verified from frontend/e2e/login.spec.ts:8,22,28,33.
 */
export async function loginAsAdmin(page: Page): Promise<void> {
  const orgSlug = process.env["E2E_ORG_SLUG"] ?? "test-org";
  const tenantSlug = process.env["E2E_TENANT_SLUG"] ?? "default";
  // By username, not email: the login field takes either, and an email literal
  // next to a password literal is a credential pair to a secret scanner.
  const adminUsername =
    process.env["E2E_TENANT_ADMIN_USERNAME"] ?? "tenant-admin";
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
  await page.getByLabel("Username or email").fill(adminUsername);
  await page.getByLabel("Password").fill(adminPassword);
  // `exact` is load-bearing, not decoration: the page also carries a "Sign in
  // with a passkey" button (C2), whose accessible name contains this one. A
  // substring match resolves to both and Playwright fails the whole run on the
  // strict-mode violation — and because this helper backs the auth setup
  // project, that failure takes every other spec down with it.
  await page.getByRole("button", { name: "Sign in", exact: true }).click();

  // Wait for successful redirect off /login (httpOnly cookie is now set).
  // 45s (not 15s): every login runs an Argon2id verification on the backend,
  // and under a loaded CI runner sharing CPU with the server container the
  // post-login redirect can occasionally take >15s, which showed up as
  // intermittent `waitForURL` timeouts across the suite.
  await page.waitForURL(/\/dashboard|\/$/, { timeout: 45_000 });
}

/**
 * loginAsOrgAdmin — signs in as the ORGANIZATION-level super-admin.
 *
 * The principal `POST /api/v1/admin/bootstrap` creates, and the one every
 * organization-scope defect in this suite is about. It signs in naming **no
 * tenant**: the login form's tenant field is left blank, and the server resolves
 * the organization's own reserved scope. Almost everything else in the suite
 * signs in as the tenant administrator instead (see `loginAsAdmin`), because
 * that is the principal that owns tenant-scoped data.
 *
 * Always drives the full login UI rather than reusing `storageState`: the shared
 * session belongs to the tenant admin, and silently inheriting it would make
 * every assertion here about the wrong principal. Specs using this helper opt
 * out of the shared session with `test.use({ storageState: { cookies: [],
 * origins: [] } })`.
 */
export async function loginAsOrgAdmin(page: Page): Promise<void> {
  const orgSlug = process.env["E2E_ORG_SLUG"] ?? "test-org";
  const adminUsername = process.env["E2E_ADMIN_USERNAME"] ?? "admin";
  const adminPassword = process.env["E2E_ADMIN_PASSWORD"] ?? "Test@Admin123!";

  await page.goto("/login", { waitUntil: "networkidle", timeout: 45_000 });
  await page
    .getByLabel("Organization slug")
    .waitFor({ state: "visible", timeout: 15_000 });

  await page.getByLabel("Organization slug").fill(orgSlug);
  // Deliberately blank. An organization-level principal names no tenant, and
  // the empty string must be read as "none" rather than as a slug that cannot
  // match — the bug that once made this sign-in impossible whatever the OPAQUE
  // mode, because the tenant is resolved before the policy is ever read.
  await page.getByLabel("Tenant slug").fill("");
  await page.getByRole("button", { name: "Continue" }).click();

  await page.getByLabel("Username or email").fill(adminUsername);
  await page.getByLabel("Password").fill(adminPassword);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();

  await page.waitForURL(/\/dashboard|\/$/, { timeout: 45_000 });
}
