import { test, expect } from "@playwright/test";
import { readFixture } from "../helpers/matrix";
import { storageStateFor } from "../helpers/matrix-fixture";

/**
 * S-10b — the `inherit` flag in the console, against the live fixture.
 *
 * Read-only on purpose. `resource-hierarchy.spec.ts` asks the engine questions
 * whose answers depend on mx-editor's assignment on `mx-b` cascading; changing
 * that assignment here, even and back, would make those answers depend on the
 * order the two files run in. So this file asserts what the console renders
 * and offers for assignments the fixture made the way every client always has
 * (no `inherit` sent), and leaves every write to the unit tests, which drive
 * the unassign-then-assign sequence against a mock.
 */

const fx = readFixture();

test.describe("role-assignment inherit flag", () => {
  test.use({ storageState: storageStateFor("tenant-admin") });

  test("a scoped assignment made without the field reads as inheritable (I4)", async ({ page }) => {
    const roleId = fx.roles["mx-role-editor"];
    expect(roleId, "unverified — blocked: mx-role-editor was not built").toBeTruthy();
    if (!roleId) return;

    await page.goto(`/roles/${roleId}`);
    const action = page.getByRole("button", {
      name: /^Stop .+'s mx-role-editor assignment at mx-b$/,
    });
    await expect(action.first()).toBeVisible();
    await expect(action.first()).toHaveText("Stop here");
    // No row of this role was made non-inheritable, so nothing is marked.
    await expect(page.getByText("This resource only")).toHaveCount(0);
  });

  test("the assign dialog offers the flag only once a resource is chosen", async ({ page }) => {
    const roleId = fx.roles["mx-role-editor"];
    expect(roleId, "unverified — blocked: mx-role-editor was not built").toBeTruthy();
    if (!roleId) return;

    await page.goto(`/roles/${roleId}`);
    await page.getByRole("button", { name: /Assign User/ }).click();
    const dialog = page.getByRole("dialog");
    const inherit = dialog.getByLabel(/Also applies to the resource.s descendants/);
    await expect(dialog.getByLabel("Scope")).toBeVisible();
    await expect(inherit).toHaveCount(0);
    await dialog.getByLabel("Scope").selectOption({ label: "mx-b" });
    await expect(inherit).toBeChecked();
    // Leave without assigning anything.
    await page.keyboard.press("Escape");
  });

  test("a global role's rows offer no change", async ({ page }) => {
    const roleId = fx.roles["mx-role-viewer"];
    expect(roleId, "unverified — blocked: mx-role-viewer was not built").toBeTruthy();
    if (!roleId) return;

    await page.goto(`/roles/${roleId}`);
    // mx-role-viewer's assignments are tenant-wide: nothing to stop at.
    await expect(page.getByRole("heading", { name: "Assignments" })).toBeVisible();
    await expect(page.getByRole("button", { name: /assignment at/ })).toHaveCount(0);
  });
});
