import { test, expect, Page } from "@playwright/test";
import { readFileSync } from "node:fs";
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
        // A destination the sidebar does not offer has nothing to assert here;
        // its route gate is still checked in direction 2 below.
        if (dest.inNav === false) continue;
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
        (d) =>
          d.inNav !== false &&
          d.routePermission !== null &&
          d.navPermission !== d.routePermission,
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

    test("every route the application declares is in the matrix", async () => {
      // `NAV_DESTINATIONS` is a hand-maintained table, and a hand-maintained
      // table of what to measure goes stale in the one direction that is
      // invisible: a route added to `router.tsx` and not added here is simply
      // never visited, and the matrix reports a clean wave over a surface it
      // never touched. `/settings/webauthn-attestation-policy` was exactly
      // that — gated by a permission no other destination uses, and unmeasured
      // in both directions for as long as the table has existed.
      //
      // Read as text rather than imported: `router.tsx` pulls in every page
      // component, and a Playwright worker is not a place to evaluate React
      // modules that expect a DOM. What is needed here is only the set of
      // declared paths, and that is a lexical fact about the file.
      const source = readFileSync(
        new URL("../../src/router.tsx", import.meta.url),
        "utf8",
      );
      const declared = [...source.matchAll(/^\s*path:\s*"([^"]+)",/gm)].map((m) => m[1]);
      expect(
        declared.length,
        "no `path:` entries were found in router.tsx — this guard is reading the wrong file " +
          "or the route table has changed shape, and it is measuring nothing",
      ).toBeGreaterThan(10);

      // Not matrix destinations, and why:
      //   - the public/auth routes are reached signed OUT, so a principal's
      //     permissions say nothing about them (`login.spec.ts` covers them);
      //   - a parameterised path has no single URL to visit;
      //   - `*` is the not-found fallback.
      const exempt = (path: string) =>
        path.includes(":") ||
        path === "*" ||
        path === "/" ||
        path.startsWith("/login") ||
        path.startsWith("/bootstrap") ||
        path.startsWith("/auth/");

      const known = new Set(NAV_DESTINATIONS.map((d) => d.path.replace(/^\//, "")));
      const missing = declared
        .filter((path) => !exempt(path))
        .filter((path) => !known.has(path.replace(/^\//, "")));

      expect
        .soft(
          missing,
          "routes declared in frontend/src/router.tsx that no matrix destination covers — " +
            "each is a page whose permission boundary this suite never measures, in either " +
            "direction. Add them to NAV_DESTINATIONS (or to the exemptions above, with a reason).",
        )
        .toEqual([]);
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
