import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./helpers/auth";

// SECFIX-05 / D-03: logout revokes the caller's own session from the
// authenticated JWT (no request body sent by the client) and must not 400.
// This spec drives the real Topbar "Sign out" control and asserts:
//   (a) the logout request itself succeeds (no 400 — the body-less handler
//       accepts the request), and
//   (b) the app returns to the unauthenticated state afterward.
//
// Execution is local-only here; CI wiring for the full Playwright suite is
// CORR-04 (Phase 26).
test.describe("Logout flow", () => {
  test("signing out succeeds with no 400 and returns to unauthenticated state", async ({
    page,
  }) => {
    await loginAsAdmin(page);
    await expect(page).not.toHaveURL(/\/login/);

    const logoutResponsePromise = page.waitForResponse((response) =>
      response.url().includes("/api/v1/auth/logout")
    );

    await page.getByRole("button", { name: "User menu" }).click();
    await page.getByRole("menuitem", { name: "Sign out" }).click();

    const logoutResponse = await logoutResponsePromise;
    expect(logoutResponse.status()).not.toBe(400);
    expect(logoutResponse.ok()).toBe(true);

    // App returns to the unauthenticated state (redirected to /login).
    await page.waitForURL(/\/login/, { timeout: 15_000 });
    await expect(page).toHaveURL(/\/login/);

    // Reloading must not silently re-authenticate — confirms client auth
    // state was actually cleared, not just navigated away transiently.
    await page.reload();
    await expect(page).toHaveURL(/\/login/);
  });
});
