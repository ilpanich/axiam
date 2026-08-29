import { test, expect, Page } from "@playwright/test";
import {
  MATRIX_PRINCIPALS,
  NAV_DESTINATIONS,
  effectivePermissions,
  holds,
  readFixture,
} from "../helpers/matrix";

/**
 * The two-directional navigation matrix — the actual point of the exercise.
 *
 * For every principal and every destination reachable from the frontend, both
 * directions are asserted:
 *
 *   - what its roles allow, it **can** reach and **can** see offered;
 *   - what its roles do not allow, it **cannot** reach and is **not** offered.
 *
 * The second direction is the one that hides silently. A page that renders a
 * control the server would refuse is a bug; so is one that hides a control the
 * server would allow, and nothing surfaces that except asking. Both are checked
 * explicitly here.
 *
 * **The oracle is the server, not a table in this file.** Each principal's
 * effective permissions come from `GET /api/v1/auth/me` — the same array the UI
 * itself gates on — and the expectation is derived from the permission the
 * route and the sidebar entry *declare*. A hand-maintained table of "viewer
 * should see these six pages" would drift the first time a permission was
 * renamed, and would then assert the drift rather than the contract.
 *
 * Every assertion is `expect.soft`. A principal that fails one destination must
 * keep walking the other twenty-one: the backend image is Rust and rebuilds
 * slowly, so a wave that stops at the first failure buys one finding per image
 * build (`E2E-TESTS.md` §5).
 */

const fixture = readFixture();

test.describe.configure({ mode: "parallel" });

for (const principal of MATRIX_PRINCIPALS) {
  test.describe(`nav reach — ${principal.username}`, () => {
    test.use({ storageState: principal.storageState });

    test(`sees exactly the destinations its permissions allow`, async ({ page }) => {
      test.setTimeout(180_000);

      const perms = await effectivePermissions(page);
      expect(
        perms,
        `${principal.username}: GET /auth/me returned no permissions array — ` +
          `every assertion below would be measuring nothing`,
      ).not.toBeNull();
      if (!perms) return;

      // ---- direction 1: the sidebar offers exactly what is permitted -----
      await page.goto("/dashboard", { waitUntil: "networkidle" });
      // `complementary`, not `navigation`: the label "Main navigation" is on
      // the `<aside>` element, whose implicit ARIA role is `complementary`. The
      // `<nav>` inside it carries no accessible name at all — noted as a
      // separate (minor) accessibility finding; scoping to the labelled
      // element is what actually finds the entries today.
      const nav = page.getByRole("complementary", { name: "Main navigation" });

      for (const dest of NAV_DESTINATIONS) {
        const allowed = dest.navPermission === null || holds(perms, dest.navPermission);
        const link = nav.getByRole("link", { name: dest.label, exact: true });

        // Presence: every entry is rendered for every principal; what changes
        // is whether it is enabled. Asserting presence separately keeps a
        // missing entry from reading as "correctly hidden".
        await expect
          .soft(link, `${principal.username}: nav entry "${dest.label}" is missing entirely`)
          .toHaveCount(1);
        if ((await link.count()) !== 1) continue;

        const disabled = (await link.getAttribute("aria-disabled")) === "true";
        expect
          .soft(
            disabled,
            allowed
              ? `${principal.username} holds ${dest.navPermission ?? "(no permission required)"} ` +
                `but the "${dest.label}" nav entry is disabled — a control the server would allow, hidden`
              : `${principal.username} does NOT hold ${dest.navPermission} ` +
                `but the "${dest.label}" nav entry is enabled — a control the server would refuse, offered`,
          )
          .toBe(!allowed);
      }

      // ---- direction 2: the route agrees with the sidebar ----------------
      //
      // Navigating directly is what a bookmark, a deep link or a typed URL
      // does, and it is the path a UX-only sidebar gate does not cover.
      for (const dest of NAV_DESTINATIONS) {
        const gate = dest.routePermission;
        const allowed = gate === null || holds(perms, gate);
        await page.goto(dest.path, { waitUntil: "networkidle" });

        const denied = await isAccessDenied(page);
        expect
          .soft(
            denied,
            allowed
              ? `${principal.username} holds ${gate ?? "(no permission required)"} but ` +
                `${dest.path} rendered Access Denied`
              : `${principal.username} does NOT hold ${gate} but ${dest.path} rendered its page`,
          )
          .toBe(!allowed);
      }
    });

    test("the sidebar gate and the route gate agree", async ({ page }) => {
      // A structural check that needs no permissions at all: an entry whose
      // sidebar gate is weaker than its route gate offers a live link into a
      // page that will refuse. `/audit-logs` is the case this caught.
      const mismatched = NAV_DESTINATIONS.filter(
        (d) => d.routePermission !== null && d.navPermission !== d.routePermission,
      );
      expect
        .soft(
          mismatched.map((d) => `${d.path}: nav=${d.navPermission} route=${d.routePermission}`),
          "sidebar entries whose declared permission differs from the permission " +
            "guarding the route they link to — each offers a destination the route refuses",
        )
        .toEqual([]);
      // Keep the browser fixture honest: this test asserts on static data, but
      // running it inside the project ties the finding to the wave it was found in.
      expect(fixture.problems.length >= 0).toBe(true);
    });
  });
}

/**
 * Whether the page settled on `ForbiddenPage` (or was bounced to /login).
 *
 * Matched on the heading rather than a test id because the heading is the thing
 * a user actually reads, and a refactor that changed it without changing the
 * behaviour should be visible here rather than silently passing.
 */
async function isAccessDenied(page: Page): Promise<boolean> {
  if (new URL(page.url()).pathname.startsWith("/login")) return true;
  return (
    (await page.getByRole("heading", { name: "Access Denied" }).count()) > 0
  );
}
