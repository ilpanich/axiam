import { test, expect } from "@playwright/test";
import { ensureOnApp, effectivePermissions, readFixture } from "../helpers/matrix";
import { storageStateFor } from "../helpers/matrix-fixture";

/**
 * An organization-level principal narrowed to some of its organization's
 * tenants.
 *
 * Organization scope is otherwise all-or-nothing: such a principal's global
 * grants reach every tenant of the organization. `mx-org-a-admin` holds the
 * organization's own `super-admin` role — the whole permission registry — with
 * a `tenant_scope` naming tenant A alone, so every assertion here is about the
 * *scope* and never about a missing permission. A gate that leaked would leak
 * to a principal holding everything.
 *
 * Three properties, in the order a defect would surface them:
 *
 *   1. it works normally inside tenant A;
 *   2. tenant B is refused — at the header, not one 403 per page;
 *   3. the organization itself is refused, which is the half `axiam_authz`
 *      structurally cannot enforce: creating a tenant names no tenant for a
 *      scope to be compared against.
 *
 * Plus what the admin UI does with that, which is the reported defect: a
 * principal shown controls the server refuses.
 */

const fx = readFixture();

/** Skip with a reason rather than fail when the fixture could not build it. */
function requireFixture(): boolean {
  if (fx.users["org-a-admin"] && fx.tenantA && fx.tenantB) return true;
  test.skip(
    true,
    `unverified — blocked: ${fx.problems.join("; ") || "mx-org-a-admin fixture missing"}`,
  );
  return false;
}

test.describe("a tenant-scoped organization principal", () => {
  test.use({ storageState: storageStateFor("org-a-admin") });

  test("is not handed the wildcard", async ({ page }) => {
    if (!requireFixture()) return;
    await ensureOnApp(page);

    const permissions = await effectivePermissions(page);
    expect(permissions, "/auth/me did not answer with a permission array").not.toBeNull();
    // B-09's rule, extended: `*` short-circuits every client-side `can()`, so
    // emitting it for a principal refused organization-level actions renders
    // exactly the controls this file is about.
    expect(
      permissions,
      "a restricted principal must not be told it can do everything",
    ).not.toContain("*");
    // ...and it is still a super-admin *somewhere*, so an empty list would mean
    // the filter went too far and this suite is measuring a broken account.
    expect(
      (permissions ?? []).length,
      "the account still holds every action that applies inside its reach",
    ).toBeGreaterThan(0);
  });

  test("reports the tenants it reaches, and only those", async ({ page }) => {
    if (!requireFixture()) return;
    await ensureOnApp(page);

    const reachable = await page.evaluate(async () => {
      const res = await fetch("/api/v1/auth/me", { credentials: "include" });
      if (!res.ok) return null;
      const body = (await res.json()) as {
        user?: { reachable_tenant_ids?: string[] };
      };
      return body.user?.reachable_tenant_ids ?? null;
    });

    expect(reachable, "/auth/me must report the restriction").not.toBeNull();
    expect(reachable).toEqual([fx.tenantA]);
  });

  test("is refused the organization's own lifecycle actions", async ({ page }) => {
    if (!requireFixture()) return;
    await ensureOnApp(page);

    // Creating a tenant names no tenant, so there is nothing for the
    // authorization engine to compare a scope against — this is the one place
    // the restriction can be enforced, and the one most likely to be forgotten.
    const status = await page.evaluate(async (orgId) => {
      const csrf = document.cookie
        .split("; ")
        .find((c) => c.startsWith("axiam_csrf="))
        ?.slice("axiam_csrf=".length);
      const res = await fetch(`/api/v1/organizations/${orgId}/tenants`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          ...(csrf ? { "X-CSRF-Token": csrf } : {}),
        },
        body: JSON.stringify({ name: "Should Not Exist", slug: "mx-should-not-exist" }),
      });
      return res.status;
    }, fx.orgId);

    expect(
      status,
      "an account confined to particular tenants is not an organization administrator",
    ).toBe(403);
  });

  test("sees only the tenants it reaches in the tenant list", async ({ page }) => {
    if (!requireFixture()) return;
    await page.goto("/tenants", { waitUntil: "networkidle" });

    // `Matrix Tenant B` is the control: it exists, the caller holds
    // `tenants:list`, and it must still not be listed. Whole-cell matching,
    // because a substring search for "Matrix" would find tenant A's row.
    const names = new Set(
      (await page.getByRole("cell").allInnerTexts()).map((t) => t.trim()),
    );
    expect
      .soft(
        names.has("Matrix Tenant B"),
        "the roster must be filtered to the tenants this principal can act on",
      )
      .toBe(false);
  });

  test("is refused a switch to a tenant outside its reach", async ({ page }) => {
    if (!requireFixture()) return;
    await ensureOnApp(page);

    const status = await page.evaluate(async (tenantB) => {
      const res = await fetch("/api/v1/auth/me", {
        credentials: "include",
        headers: { "X-Axiam-Tenant": tenantB },
      });
      return res.status;
    }, fx.tenantB);

    // Refused at the header rather than as a denial on every request that
    // follows — the difference between one clear answer and a session that
    // looks switched and fails everywhere.
    expect(status).toBe(403);
  });

  test("works normally inside the tenant it does reach", async ({ page }) => {
    if (!requireFixture()) return;
    await ensureOnApp(page);

    // The control for every assertion above. A restriction that also broke the
    // permitted tenant would satisfy all of them and be useless.
    const status = await page.evaluate(async (tenantA) => {
      const res = await fetch("/api/v1/users", {
        credentials: "include",
        headers: { "X-Axiam-Tenant": tenantA },
      });
      return res.status;
    }, fx.tenantA);

    expect(status).toBe(200);
  });

  test("is not offered the organization's controls in the UI", async ({ page }) => {
    if (!requireFixture()) return;
    await page.goto("/tenants", { waitUntil: "networkidle" });

    // The reported defect, from the operator's side: a control the server
    // refuses must not be drawn. `New Tenant` is the one on this page.
    await expect(
      page.getByRole("button", { name: /new tenant/i }),
      "the tenant roster belongs to the organization, and this principal is not its administrator",
    ).toHaveCount(0);

    // The Organizations section is a live link into a page whose every button
    // answers 403.
    const organizations = page.getByRole("link", { name: /organizations/i });
    if ((await organizations.count()) > 0) {
      await expect(organizations.first()).toHaveAttribute("aria-disabled", "true");
    }
  });
});

test.describe("a tenant administrator", () => {
  test.use({ storageState: storageStateFor("tenant-admin") });

  test("is not offered the organization's controls either", async ({ page }) => {
    // The other principal in the report. It holds the whole permission registry
    // of tenant A — `organizations:create` included, since a permission is a
    // registry value a seeded role carries — and is refused every
    // organization-level action on the basis of where it lives. A
    // permission-driven gate could not have hidden anything here.
    await page.goto("/tenants", { waitUntil: "networkidle" });

    await expect(page.getByRole("button", { name: /new tenant/i })).toHaveCount(0);

    const organizations = page.getByRole("link", { name: /organizations/i });
    if ((await organizations.count()) > 0) {
      await expect(organizations.first()).toHaveAttribute("aria-disabled", "true");
    }
  });

  test("sees only its own tenant in the tenant list", async ({ page }) => {
    if (!fx.tenantB) {
      test.skip(true, `unverified — blocked: ${fx.problems.join("; ") || "tenant B missing"}`);
      return;
    }
    await page.goto("/tenants", { waitUntil: "networkidle" });

    const names = new Set(
      (await page.getByRole("cell").allInnerTexts()).map((t) => t.trim()),
    );
    expect
      .soft(
        names.has("Matrix Tenant B"),
        "a tenant administrator has no business seeing the organization's other workspaces",
      )
      .toBe(false);
  });
});
