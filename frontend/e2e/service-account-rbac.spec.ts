import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./helpers/auth";

// ---------------------------------------------------------------------------
// Service accounts hold roles and join groups — live backend.
//
// A service account could authenticate and then do nothing. `has_role` has
// always been declared `User/ServiceAccount/Group -> Role`, and the
// authorization engine has always applied RBAC identically to a machine and a
// person — but nothing could create the edge, so the only way to give a machine
// permissions was to hand it a human's account.
//
// Runs as the tenant administrator: service accounts, roles and groups are all
// tenant-scoped, and that is the principal that owns them.
// ---------------------------------------------------------------------------

const STAMP = Date.now();
const SA_NAME = `e2e-sa-${STAMP}`;
const ROLE_NAME = `e2e-role-${STAMP}`;
const GROUP_NAME = `e2e-group-${STAMP}`;

test.describe.configure({ mode: "serial" });

test.describe("Service-account RBAC", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("creates the fixtures this suite grants against", async ({ page }) => {
    await page.goto("/service-accounts");
    await page.getByRole("button", { name: /New Service Account/i }).click();
    let dialog = page.getByRole("dialog");
    await dialog.getByLabel(/Name/i).first().fill(SA_NAME);
    await dialog.getByRole("button", { name: /Create/i }).click();
    // The client secret is shown once, in a dialog that has to be dismissed.
    await expect(page.getByText(SA_NAME).first()).toBeVisible({
      timeout: 30_000,
    });

    await page.goto("/roles");
    await page.getByRole("button", { name: /New Role/i }).click();
    dialog = page.getByRole("dialog");
    await dialog.getByLabel(/Name/i).first().fill(ROLE_NAME);
    await dialog.getByRole("button", { name: /Create/i }).click();
    await expect(page.getByText(ROLE_NAME).first()).toBeVisible({
      timeout: 30_000,
    });

    await page.goto("/groups");
    await page.getByRole("button", { name: /New Group/i }).click();
    dialog = page.getByRole("dialog");
    await dialog.getByLabel(/Name/i).first().fill(GROUP_NAME);
    await dialog.getByRole("button", { name: /Create/i }).click();
    await expect(page.getByText(GROUP_NAME).first()).toBeVisible({
      timeout: 30_000,
    });
  });

  test("assigns a role directly to a service account", async ({ page }) => {
    await page.goto("/roles");
    await page.getByText(ROLE_NAME).first().click();

    await page.getByRole("button", { name: "service accounts" }).click();
    await page.getByRole("button", { name: /Assign Service Account/ }).click();

    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Service account").selectOption({ label: SA_NAME });
    await dialog.getByRole("button", { name: "Assign" }).click();

    await expect(dialog).toBeHidden({ timeout: 30_000 });
    await expect(page.getByText(SA_NAME).first()).toBeVisible({
      timeout: 30_000,
    });
  });

  test("adds a service account to a group, which is how a fleet is granted", async ({
    page,
  }) => {
    await page.goto("/groups");
    await page.getByText(GROUP_NAME).first().click();

    await page.getByRole("button", { name: /Add Service Account/ }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Service account").selectOption({ label: SA_NAME });
    await dialog.getByRole("button", { name: "Add" }).click();

    await expect(dialog).toBeHidden({ timeout: 30_000 });
    // The Service Accounts card, not the Members one — the two are listed
    // separately because a page saying "members" has to say which rows are
    // people.
    await expect(page.getByText(SA_NAME).first()).toBeVisible({
      timeout: 30_000,
    });
  });

  test("removes the service account from the group again", async ({ page }) => {
    await page.goto("/groups");
    await page.getByText(GROUP_NAME).first().click();

    await page
      .getByRole("button", { name: `Remove service account ${SA_NAME} from group` })
      .click();
    const confirm = page.getByRole("dialog");
    await confirm.getByRole("button", { name: "Delete" }).click();

    await expect(
      page.getByText(/No service accounts in this group/)
    ).toBeVisible({ timeout: 30_000 });
  });
});
