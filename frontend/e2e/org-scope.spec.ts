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

/** Switch the tenant the admin UI is acting on, by visible tenant name. */
async function selectTenant(page: import("@playwright/test").Page, name: string) {
  await page.getByRole("button", { name: /\// }).first().click();
  const menu = page.getByRole("menu", { name: "Tenant selector" });
  await expect(menu).toBeVisible();
  await menu.getByRole("button", { name }).first().click();
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
    await selectTenant(page, /default|E2E Default Tenant/.source);

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
    await selectTenant(page, /default|E2E Default Tenant/.source);

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
    // Rotated and rotated back, so the fixture credential still works for every
    // other spec in the suite whatever order they run in.
    const current = process.env["E2E_ADMIN_PASSWORD"] ?? "Test@Admin123!";
    const rotated = "E2e@RotatedOrgAdmin456!";

    await page.goto("/profile/password");
    await selectTenant(page, /default|E2E Default Tenant/.source);

    async function change(from: string, to: string) {
      await page.goto("/profile/password");
      await page.getByLabel("Current Password").fill(from);
      await page.getByLabel("New Password", { exact: true }).fill(to);
      await page.getByLabel("Confirm New Password").fill(to);
      await page.getByRole("button", { name: /Change Password/i }).click();
      await expect(
        page.getByText(/Password changed successfully/i)
      ).toBeVisible({ timeout: 30_000 });
    }

    await change(current, rotated);
    await change(rotated, current);
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
