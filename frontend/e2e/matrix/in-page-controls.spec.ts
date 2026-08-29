import { test, expect, Locator, Page } from "@playwright/test";
import {
  MATRIX_PRINCIPALS,
  effectivePermissions,
  holds,
  readFixture,
} from "../helpers/matrix";

/**
 * The half of `E2E-TESTS.md` §2 that page-level reach does not measure.
 *
 * `nav-reach.spec.ts` asserts which *pages* a principal may open. But a page a
 * principal may open still renders controls gated one level down, by
 * `usePermissions().can(...)` — twelve pages do this today — and §2 is explicit
 * that both directions of that gate are defects:
 *
 *   "a page that renders a control the server would refuse is a bug, and so is
 *    one that hides a control the server would allow. The second is the one
 *    that hides silently — check for it explicitly."
 *
 * Neither direction was being measured. A `can("scim_tokens:create")` that
 * inverted, or that named a permission the registry does not issue, would show
 * up as an operator who "just cannot find the button" — and every page-level
 * assertion would stay green while they could not.
 *
 * ---------------------------------------------------------------------------
 * Why these controls
 * ---------------------------------------------------------------------------
 *
 * Each entry below is a control whose visibility is decided by exactly one
 * permission, on a page reachable without first selecting a row. Gates that
 * only appear after a selection (`ScopesPanel`, `EffectiveAccessPanel`, the
 * per-row bind-certificate action on service accounts) are deliberately left
 * out: reaching them needs fixture data whose absence would read as "the
 * control is correctly hidden", which is the one answer this file must never
 * produce by accident. They are named in `claude_dev/e2e-findings.md` as still
 * unmeasured rather than quietly dropped.
 */

interface GatedControl {
  /** Where the control lives. */
  path: string;
  /** What it is, for the failure message. */
  label: string;
  /** The single permission its rendering is gated on. */
  permission: string;
  /** The permission guarding the page itself — no page, no control. */
  pagePermission: string;
  /** How to find it once the page has settled. */
  locate: (page: Page) => Locator;
}

const GATED_CONTROLS: GatedControl[] = [
  {
    path: "/scim-tokens",
    label: '"New Token" button',
    permission: "scim_tokens:create",
    pagePermission: "scim_tokens:list",
    locate: (page) => page.getByRole("button", { name: "New Token" }),
  },
  {
    path: "/audit-logs",
    label: "the tenant/system audit scope switch",
    permission: "audit_logs:list_system",
    pagePermission: "audit_logs:list",
    locate: (page) => page.getByRole("tablist", { name: "Audit log scope" }),
  },
  {
    path: "/privacy",
    label: 'the "act on behalf of" field on data export',
    permission: "gdpr:export",
    // /privacy needs only a session: it is where a user exercises their own
    // rights. The gated field is the part that acts on *someone else*.
    pagePermission: "",
    locate: (page) => page.locator("#export-target-id"),
  },
  {
    path: "/privacy",
    label: 'the "act on behalf of" field on erasure',
    permission: "users:erase",
    pagePermission: "",
    locate: (page) => page.locator("#erase-target-id"),
  },
];

const fixture = readFixture();

test.describe.configure({ mode: "parallel" });

test.skip(
  fixture === null,
  "the matrix fixture has not been built — run the matrix-setup project first",
);

for (const principal of MATRIX_PRINCIPALS) {
  test.describe(`in-page controls — ${principal.username}`, () => {
    test.use({ storageState: principal.storageState });

    test("every gated control is offered exactly when its permission allows it", async ({
      page,
    }) => {
      test.setTimeout(120_000);

      const perms = await effectivePermissions(page);
      expect(
        perms,
        `${principal.username}: GET /auth/me returned no permissions array — ` +
          `every assertion below would be measuring nothing`,
      ).not.toBeNull();
      if (!perms) return;

      for (const control of GATED_CONTROLS) {
        // A control on a page this principal cannot open is not a finding —
        // the page gate already refused, and `nav-reach.spec.ts` asserts that.
        if (control.pagePermission && !holds(perms, control.pagePermission)) continue;

        await page.goto(control.path, { waitUntil: "networkidle" });

        // Guard against measuring an error page. If the route did not render,
        // "the control is absent" is true and meaningless.
        const denied =
          new URL(page.url()).pathname.startsWith("/login") ||
          (await page.getByRole("heading", { name: "Access Denied" }).count()) > 0;
        expect
          .soft(
            denied,
            `${principal.username}: ${control.path} did not render, so ` +
              `${control.label} could not be measured there`,
          )
          .toBe(false);
        if (denied) continue;

        const allowed = holds(perms, control.permission);
        const count = await control.locate(page).count();

        expect
          .soft(
            count > 0,
            allowed
              ? `${principal.username} holds ${control.permission} but ${control.label} ` +
                `is not rendered on ${control.path} — a control the server would allow, hidden`
              : `${principal.username} does NOT hold ${control.permission} but ${control.label} ` +
                `is rendered on ${control.path} — a control the server would refuse, offered`,
          )
          .toBe(allowed);
      }
    });
  });
}

// The "is this permission string real?" guard is NOT here.
//
// It was, and it skipped every run: the only principal that could serve as the
// registry — the organization super-admin — holds `*`, which matches a typo as
// happily as a real permission. A test that can never execute is worse than no
// test, because it reads as coverage.
//
// The sound version needs no server at all and lives in
// `frontend/src/lib/permissionStrings.test.ts`: the backend's registry is a
// source file (`crates/axiam-api-rest/src/permissions.rs`), so the two lists
// can simply be compared.
