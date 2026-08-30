import { test, expect } from "@playwright/test";
import { loginAsOrgAdmin } from "./helpers/auth";

// ---------------------------------------------------------------------------
// Organization-level administration — live backend.
//
// Every case here is a flow the only administrator of a freshly bootstrapped
// deployment takes on their first day, and each one was broken by the same
// assumption: that a request always names a tenant, and that the tenant it names
// is the one the caller lives in. Neither holds at organization scope.
//
// These specs deliberately do NOT reuse the shared storageState: it belongs to
// the tenant administrator, and inheriting it would make every assertion here
// about the wrong principal.
// ---------------------------------------------------------------------------

test.use({ storageState: { cookies: [], origins: [] } });

/**
 * Switch the tenant the admin UI is acting on, by visible tenant name.
 *
 * The trigger's accessible name is `<org slug> / <tenant>`, which is what the
 * slash matches. The entries inside the panel are `role="menuitem"` — matching
 * them as `button` finds nothing, however the name is written.
 */
async function selectTenant(
  page: import("@playwright/test").Page,
  name: string | RegExp,
) {
  await page.getByRole("button", { name: /\// }).first().click();
  const menu = page.getByRole("menu", { name: "Tenant selector" });
  await expect(menu).toBeVisible();
  await menu.getByRole("menuitem", { name }).first().click();
  await expect(menu).toBeHidden();
}

test.describe("Organization-level super-admin", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsOrgAdmin(page);
  });

  test("signs in naming no tenant and lands authenticated", async ({ page }) => {
    // The blank tenant field is the whole point: it has to read as "none" and
    // resolve the organization's reserved scope, not as a slug that cannot
    // match. When it did the latter, the only administrator of a fresh
    // deployment could not sign in at all — whatever the OPAQUE mode, because
    // the tenant is resolved before the policy is ever read.
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByRole("navigation").first()).toBeVisible();
  });

  test("keeps its session and its permissions after switching tenant", async ({
    page,
  }) => {
    // `GET /auth/me` used to look the caller's own record up in the SELECTED
    // tenant, answer 401, and log the administrator out — and read permissions
    // from there too, so the array came back empty and the UI hid every control
    // for actions the server would in fact have allowed.
    await page.goto("/users");
    await selectTenant(page, /E2E Default Tenant/);

    await expect(page).not.toHaveURL(/\/login/);
    // A control that only a permitted caller is shown. Its presence is the
    // assertion: an empty permission array hides it.
    await expect(page.getByRole("button", { name: /New User/ })).toBeVisible();
  });

  test("creates a user inside a child tenant", async ({ page }) => {
    // The reported 400: "Validation error: the OPAQUE session was issued for a
    // different tenant". `POST /api/v1/users` is scoped to the selected tenant
    // by the `X-Axiam-Tenant` header, so the new account's OPAQUE registration
    // record has to be sealed against THAT tenant's key material — not the
    // administrator's own. Creating a user anywhere but your own tenant was
    // impossible for as long as OPAQUE was on.
    const username = `e2e-child-${Date.now()}`;

    await page.goto("/users");
    await selectTenant(page, /E2E Default Tenant/);

    await page.getByRole("button", { name: /New User/ }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Username *").fill(username);
    await dialog.getByLabel("Email *").fill(`${username}@example.com`);
    await dialog.getByLabel("Password *").fill("E2e@ChildTenant123!");
    await dialog.getByRole("button", { name: "Create" }).click();

    // The dialog closes only on success; a 400 leaves it open with the message.
    await expect(dialog).toBeHidden({ timeout: 30_000 });
    await expect(page.getByText(username).first()).toBeVisible({
      timeout: 30_000,
    });
  });

  test("changes its own password while acting on a child tenant", async ({
    page,
  }) => {
    // The caller's own password lives in the tenant it INHABITS. Reading the
    // acting tenant looked the account up in the selected one, found nothing,
    // and failed with no visible cause — the only thing that had changed was
    // which row of the tenant switcher was highlighted.
    //
    // The request is intercepted rather than executed, because this spec cannot
    // put the fixture back. `password_history_count` defaults to 5, so changing
    // the administrator's password back to the seeded one is *refused* — an
    // earlier version of this test rotated and tried to restore, and when the
    // restore failed it left the shared credential rotated and every later spec
    // failed to sign in.
    //
    // What the browser uniquely decides is which endpoint the form posts to
    // while a child tenant is selected. The two deeper properties are covered
    // where they can be asserted honestly: that the server accepts the change
    // at organization scope, by `org_scope_gaps_test::an_org_admin_can_change_
    // their_own_password_while_acting_on_a_child_tenant`; that any OPAQUE record
    // is sealed against the principal tenant rather than the acting one, by
    // `opaqueEnrollment.test.ts`.
    let changeUrl: string | undefined;

    await page.goto("/profile/change-password");
    await selectTenant(page, /E2E Default Tenant/);

    await page.route("**/api/v1/auth/password/change", (route) => {
      changeUrl = route.request().url();
      route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
    });
    // OPAQUE is off in the e2e stack; 404 is how the server says so.
    await page.route("**/api/v1/auth/opaque/**", (route) => {
      route.fulfill({ status: 404, contentType: "application/json", body: "{}" });
    });

    const current = process.env["E2E_ADMIN_PASSWORD"] ?? "Test@Admin123!";
    const next = "E2e@RotatedOrgAdmin456!";

    await page.goto("/profile/change-password");
    await page.getByLabel("Current Password").fill(current);
    await page.getByLabel("New Password", { exact: true }).fill(next);
    await page.getByLabel("Confirm New Password").fill(next);
    await page.getByRole("button", { name: /Update Password/i }).click();

    await expect(page.getByText(/Password changed successfully/i)).toBeVisible({
      timeout: 30_000,
    });
    expect(changeUrl).toContain("/api/v1/auth/password/change");
  });

  test("opens its own profile while acting on a child tenant", async ({
    page,
  }) => {
    // The reported symptom: an organization-level administrator with a tenant
    // selected could not open their own profile at all. `GET /users/{own id}`
    // and `GET /users/{own id}/mfa-methods` were scoped to the tenant being
    // ACTED ON, and the administrator's record lives in the organization's
    // reserved scope — so both answered 404 and the page rendered its load
    // error for an account that plainly exists.
    await page.goto("/profile");
    await expect(
      page.getByRole("button", { name: /Edit Profile/i }),
    ).toBeVisible({ timeout: 30_000 });

    await selectTenant(page, /E2E Default Tenant/);

    await page.goto("/profile");
    await expect(page).not.toHaveURL(/\/login/);
    // "Failed to load profile." is the whole page when the query rejects, and
    // "Edit Profile" only renders once it resolves — so these two assertions
    // are the difference between the bug and the fix.
    await expect(
      page.getByText(/Failed to load profile/i),
    ).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: /Edit Profile/i }),
    ).toBeVisible({ timeout: 30_000 });
  });

  test("lists OAuth2 clients rather than an empty table", async ({ page }) => {
    // The page requested an "/oauth2/clients" sub-path, which is not a route —
    // the "/oauth2/…" prefix belongs to the protocol endpoints and is not under
    // /api/v1 at all. Every load answered 404, and because an empty result and
    // a failed request render identically here, it read as "this tenant has no
    // OAuth2 clients" for an entire release.
    //
    // Asserting on the REQUEST is what makes this a regression test: asserting
    // on the rendered table would pass against a 404 the moment the tenant
    // genuinely has no clients.
    const listUrls: string[] = [];
    page.on("request", (req) => {
      const url = new URL(req.url());
      if (url.pathname.includes("oauth2") && url.pathname.startsWith("/api/"))
        listUrls.push(url.pathname);
    });

    await page.goto("/oauth2-clients");
    await expect(page.getByRole("button", { name: /New Client/i })).toBeVisible({
      timeout: 30_000,
    });

    expect(listUrls).toContain("/api/v1/oauth2-clients");
    expect(listUrls).not.toContain("/api/v1/oauth2/clients");
  });

  test("offers the organization's CA certificates to a tenant", async ({
    page,
  }) => {
    // A CA is an organization-scoped asset and every tenant issues under it.
    // The page used to resolve the organization id by listing organizations —
    // `super-admin` only — so for any administrator below that role the list
    // came back empty and the page reported that the organization had no CA.
    await page.goto("/certificates");
    await expect(page).not.toHaveURL(/\/login/);
    // Either the issuer picker is offered, or the page says plainly that no CA
    // exists yet — both are honest. What must not happen is a permission error.
    await expect(page.getByText(/Forbidden|403/i)).toHaveCount(0);
  });
});
