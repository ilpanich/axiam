import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./helpers/auth";

// ---------------------------------------------------------------------------
// Reactors page tests — live backend (X1).
// Auth via httpOnly cookie (T-07-12 / ASVS V3.1). No sessionStorage.
//
// A fresh bootstrap has no reactors, so every assertion here is either an
// empty-state assertion or is about the *registry*, which is seeded in the
// server binary rather than in the database and is therefore always present.
// Nothing below creates a reactor: a registration is tenant state that later
// specs would inherit, and an enabled fail_closed interceptor with no process
// answering it would deny logins for the rest of the suite.
// ---------------------------------------------------------------------------

test.describe("Reactors page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("renders reactors page (not redirected to /login)", async ({ page }) => {
    await page.goto("/reactors");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByRole("navigation").first()).toBeVisible();
  });

  test("shows reactor list or empty state from live backend", async ({
    page,
  }) => {
    await page.goto("/reactors");
    await expect(page).not.toHaveURL(/\/login/);
    // DataTable always renders a <table> (rows or the empty message inside),
    // so wait for it — auto-retries through the async fetch rather than
    // one-shot probes that race the load.
    await expect(page.getByRole("table")).toBeVisible();
  });

  // The point of GET /api/v1/reactors/events is that the console renders the
  // server's registry instead of a hard-coded copy. Asserting a known event
  // name reaches the DOM is what actually exercises that round trip — a
  // hard-coded list would pass a render test but fail this one the day the
  // server's registry changed.
  test("renders the hookable-event registry from the live server", async ({
    page,
  }) => {
    await page.goto("/reactors");
    await expect(page.getByText("Hookable events")).toBeVisible();
    await expect(
      page.getByText("token.pre_issue", { exact: true }).first()
    ).toBeVisible();
    await expect(
      page.getByText("login.post_auth", { exact: true }).first()
    ).toBeVisible();
  });

  test('"New Reactor" button opens create modal with a Name field', async ({
    page,
  }) => {
    await page.goto("/reactors");
    await page.getByRole("button", { name: /New Reactor/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByLabel("Name *")).toBeVisible();
  });

  test("create modal lists event checkboxes from the registry", async ({
    page,
  }) => {
    await page.goto("/reactors");
    await page.getByRole("button", { name: /New Reactor/i }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByLabel("token.pre_issue")).toBeVisible();
    await expect(dialog.getByLabel("user.pre_create")).toBeVisible();
  });

  // Deliberately the empty-events case rather than the empty-name one: `name`
  // carries the native `required` attribute, so a real browser blocks that
  // submit before React sees it and the app's own message never renders. The
  // event set has no native equivalent, so this is the pre-flight that is
  // actually reachable here. (The name path is covered in the jsdom suite,
  // where fireEvent.submit bypasses native validation.)
  test("refuses to submit without an event", async ({ page }) => {
    await page.goto("/reactors");
    await page.getByRole("button", { name: /New Reactor/i }).click();
    const dialog = page.getByRole("dialog");

    await dialog.getByLabel("Name *").fill("e2e-no-events");
    await dialog.getByRole("button", { name: "Create" }).click();

    await expect(dialog.getByText("Select at least one event.")).toBeVisible();
    // Still open: a rejected pre-flight must not look like a success.
    await expect(dialog).toBeVisible();
  });

  // A listener's reply is never read, so offering it a timeout or a failure
  // policy would imply a control the server does not honour for that mode.
  test("hides interceptor tuning when the mode is listen", async ({ page }) => {
    await page.goto("/reactors");
    await page.getByRole("button", { name: /New Reactor/i }).click();
    const dialog = page.getByRole("dialog");

    await expect(dialog.getByLabel("Timeout (ms)")).toBeVisible();
    await dialog.getByLabel("Mode *").selectOption("listen");
    await expect(dialog.getByLabel("Timeout (ms)")).toBeHidden();
    await expect(dialog.getByLabel("Failure policy")).toBeHidden();
  });
});
