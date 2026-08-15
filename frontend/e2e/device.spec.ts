import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./helpers/auth";

// ---------------------------------------------------------------------------
// Device verification page tests — live backend (B2 step 3 / R4.1).
// Auth via httpOnly cookie (T-07-12 / ASVS V3.1). No sessionStorage.
//
// What this file deliberately does NOT cover: a full approve/deny round trip
// against a real device grant. That would require an OAuth2 client
// registered for the `urn:ietf:params:oauth:grant-type:device_code` grant
// (see `crates/axiam-oauth2/src/device_service.rs::authorize`), and neither
// the admin client-creation UI nor the `POST /api/v1/oauth2-clients`
// endpoint's own `validate_grant_types` allow-list
// (`crates/axiam-api-rest/src/handlers/oauth2_clients.rs::KNOWN_GRANT_TYPES`)
// accepts that grant type today — there is no reachable path to create such
// a client through the API this suite is allowed to drive. That gap is
// server-side and outside this task's frontend-only scope; it's noted as a
// residual. Everything below instead exercises the page against the live
// backend the same way `reactors.spec.ts` does for state it must not create:
// rendering, client-side validation, and the endpoint's genuine "not found"
// response for a code nobody has ever issued.
// ---------------------------------------------------------------------------

test.describe("Device verification page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("renders the device page (not redirected to /login)", async ({ page }) => {
    await page.goto("/device");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByRole("heading", { name: "Connect a device" })).toBeVisible();
    await expect(page.getByLabel("Device code")).toBeVisible();
  });

  test("is reachable from the sidebar", async ({ page }) => {
    await page.goto("/dashboard");
    await page.getByRole("link", { name: "Connect a Device" }).click();
    await expect(page).toHaveURL(/\/device$/);
  });

  test("requires a non-blank code before continuing", async ({ page }) => {
    await page.goto("/device");
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(
      page.getByText("Enter the code shown on your device.")
    ).toBeVisible();
  });

  test("shows a generic not-found message for a code that was never issued", async ({
    page,
  }) => {
    await page.goto("/device");
    await page.getByLabel("Device code").fill("ZZZZ-0000");
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.getByText(/wasn't found/)).toBeVisible();
    // Still on the entry step — a rejected code must not advance to consent.
    await expect(page.getByRole("button", { name: "Approve" })).toHaveCount(0);
  });

  test("auto-verifies a ?user_code= query param and shows the same not-found message", async ({
    page,
  }) => {
    await page.goto("/device?user_code=ZZZZ-0000");
    await expect(page.getByText(/wasn't found/)).toBeVisible();
  });
});
