import { test, expect, Locator, Page } from "@playwright/test";
import {
  MATRIX_PRINCIPALS,
  effectivePermissions,
  holds,
  readFixture,
} from "../helpers/matrix";

/**
 * The half of `claude_dev/E2E-TESTS.md` §2 that page-level reach does not measure.
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
 * `GATED_CONTROLS` holds the controls whose visibility is decided by exactly
 * one permission on a page reachable without first selecting anything.
 * `SELECTION_GATED_CONTROLS`, below it, holds the three that only exist after
 * a row is selected — `ScopesPanel`, `EffectiveAccessPanel` and the per-row
 * bind-certificate action on service accounts.
 *
 * Those three were left out of the first version of this file for a real
 * reason, and it is the reason the second version is shaped the way it is:
 * "the control is absent" is also what you see when the fixture had no row to
 * select, when the selection did not take, or when the panel failed to render.
 * Three ways to accidentally report "correctly hidden" about something that
 * was never looked at. So every selection-gated entry carries a `landmark` —
 * an element the panel renders REGARDLESS of the permission — and the landmark
 * is asserted before the gate is. If the landmark is missing the test fails
 * saying the selection did not happen, which is a different sentence from the
 * one about the control.
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

/**
 * A control that does not exist until something is selected.
 *
 * The extra members over `GatedControl` all serve one purpose: making
 * "the control is hidden" impossible to confuse with "nothing was measured".
 */
interface SelectionGatedControl {
  path: string;
  label: string;
  permission: string;
  pagePermission: string;
  /**
   * Make the selection. Returns `false` when there was nothing to select,
   * which is a fixture problem and is reported as one — never as a hidden
   * control.
   */
  reveal: (page: Page) => Promise<boolean>;
  /**
   * Something the revealed panel renders whatever the principal holds. This is
   * the proof that the selection worked and the panel is on screen, and it is
   * asserted before the gate below it.
   */
  landmark: (page: Page) => Locator;
  /** The permission-gated control itself. */
  locate: (page: Page) => Locator;
  /**
   * What the panel shows INSTEAD when the permission is absent, where it shows
   * something. Asserting the substitute turns "the control is missing" into
   * "the panel deliberately said no", which is a stronger statement and one a
   * blank page cannot fake.
   */
  refusalMarker?: (page: Page) => Locator;
}

/** Select the first resource in the tree on `/resources`. */
async function selectFirstResource(page: Page): Promise<boolean> {
  const rows = page.getByRole("treeitem");
  if ((await rows.count()) === 0) return false;
  await rows.first().click();
  return true;
}

/**
 * Put an organization-level principal into a tenant before it looks for rows.
 *
 * An organization-level principal signs in naming no tenant, so it is looking
 * at the organization's own scope — which has no resources and no service
 * accounts, correctly. Every selection-gated control would then be
 * unmeasurable for the one principal that holds every permission, i.e. for the
 * entire "allowed" side of the gate.
 *
 * The selection is seeded in `sessionStorage` under the key the application
 * itself defines (`lib/activeTenant.ts`), in the shape it itself writes. This
 * is not a back door into the app's internals: it is precisely what the app
 * restores on a reload since F-03, so the page comes up in the same state an
 * operator who used the tenant switcher would be in. Driving the switcher
 * through the UI instead would work, and is what `tenancy.spec.ts` asserts —
 * which is why this file does not need to re-assert it, only to arrive.
 */
async function actOnTenantA(page: Page, tenantAId: string): Promise<void> {
  await page.addInitScript(
    ([id]) => {
      try {
        globalThis.sessionStorage?.setItem(
          "axiam.activeTenant",
          JSON.stringify({ id, name: "matrix tenant A" }),
        );
      } catch {
        // A sessionStorage that throws means the seed did not happen; the
        // "nothing to select" branch then reports it as the fixture problem it
        // has become, rather than this silently becoming a hidden control.
      }
    },
    [tenantAId],
  );
}

const SELECTION_GATED_CONTROLS: SelectionGatedControl[] = [
  {
    path: "/resources",
    label: 'the "New Scope" button on the selected resource\'s scopes panel',
    permission: "scopes:create",
    pagePermission: "resources:list",
    reveal: selectFirstResource,
    // `ScopesPanel` titles its card `Scopes — <resource name>`, outside the
    // `can("scopes:create")` branch, so it is present for a principal that
    // may not create one.
    landmark: (page) => page.getByText(/^Scopes — /),
    locate: (page) => page.getByRole("button", { name: "New Scope" }),
  },
  {
    path: "/resources",
    label: "the act-as subject picker on the effective-access preview",
    permission: "authz:check_as",
    pagePermission: "resources:list",
    reveal: selectFirstResource,
    // Rendered once a resource is selected, before the `canCheckAs` branch.
    landmark: (page) => page.getByText(/Previewing access to/),
    locate: (page) => page.getByRole("button", { name: "Choose user" }),
    // The panel explains the refusal rather than silently omitting the field.
    refusalMarker: (page) => page.getByRole("note"),
  },
  {
    path: "/service-accounts",
    label: "the per-row bind-certificate action",
    permission: "certificates:bind",
    pagePermission: "service_accounts:list",
    reveal: async (page) => {
      // A row, any row — the action is per-row and ungated actions sit beside
      // it, which is what the landmark below looks for. No click needed: the
      // action is in the row, not behind a selection.
      const rows = page.getByRole("button", { name: /^Rotate secret for / });
      return (await rows.count()) > 0;
    },
    // `Rotate secret for …` sits in the same actions cell and is ungated, so
    // its presence proves a row rendered with its action buttons.
    landmark: (page) => page.getByRole("button", { name: /^Rotate secret for / }).first(),
    locate: (page) => page.getByRole("button", { name: /^Bind certificate to / }),
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

    test("every selection-gated control is offered exactly when its permission allows it", async ({
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

      // An organization-level principal has no rows in its own scope; it needs
      // to be acting on a tenant before any of these controls exist at all.
      if (principal.tenantSlug === null) {
        expect(
          fixture.tenantA,
          `${principal.username} signs in at organization level and the fixture ` +
            `records no tenant A to act on, so no selection-gated control could ` +
            `be reached`,
        ).toBeTruthy();
        if (!fixture.tenantA) return;
        await actOnTenantA(page, fixture.tenantA);
      }

      for (const control of SELECTION_GATED_CONTROLS) {
        if (!holds(perms, control.pagePermission)) continue;

        await page.goto(control.path, { waitUntil: "networkidle" });

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

        // 1. There has to be something to select. Its absence is a fixture
        //    problem, and saying so is the whole point of this branch — the
        //    alternative reads identically to "the control is correctly
        //    hidden".
        const revealed = await control.reveal(page);
        expect
          .soft(
            revealed,
            `${principal.username}: nothing to select on ${control.path}, so ` +
              `${control.label} was not measured. This is a FIXTURE gap, not a ` +
              `hidden control — the matrix fixture must seed a row here.`,
          )
          .toBe(true);
        if (!revealed) continue;

        // 2. The selection must actually have produced the panel. The landmark
        //    is ungated, so a principal that may not use the control still
        //    sees it; if it is missing, nothing below is a measurement.
        const landmark = control.landmark(page);
        let panelShown = true;
        try {
          await landmark.first().waitFor({ state: "visible", timeout: 10_000 });
        } catch {
          panelShown = false;
        }
        expect
          .soft(
            panelShown,
            `${principal.username}: selected on ${control.path} but the panel ` +
              `holding ${control.label} never appeared — the selection did not ` +
              `take, so its absence proves nothing`,
          )
          .toBe(true);
        if (!panelShown) continue;

        // 3. Only now is the gate itself worth asserting.
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

        // 4. Where the panel substitutes an explanation, assert the
        //    substitution. "Absent" and "replaced by a refusal" are different
        //    claims, and only the second rules out the panel having rendered
        //    half of itself.
        if (!allowed && control.refusalMarker) {
          const marker = await control.refusalMarker(page).count();
          expect
            .soft(
              marker,
              `${principal.username} lacks ${control.permission} and ${control.label} ` +
                `is correctly absent, but the panel shows no explanation in its ` +
                `place — which is also what a half-rendered panel looks like`,
            )
            .toBeGreaterThan(0);
        }
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
