import { test, expect, Page } from "@playwright/test";
import { ensureOnApp, readFixture } from "../helpers/matrix";
import { ORG_SLUG, storageStateFor } from "../helpers/matrix-fixture";

/**
 * Cross-tenant isolation, and the organization-level reach that is its
 * deliberate exception.
 *
 * Two properties that only make sense stated together:
 *
 *   - a **tenant** principal of tenant A sees and reaches nothing of tenant B,
 *     by any route the UI offers — including the one route that looks like a
 *     way around it, the `X-Axiam-Tenant` header;
 *   - an **organization** principal reaches every tenant in its own
 *     organization through the tenant switcher, and its own scope keeps working
 *     while it is doing so.
 *
 * The second half is where the interesting bug lives. Selecting a child tenant
 * changes which tenant subsequent requests are *about*; it must not change
 * which principal is making them. `/auth/me` and the caller's own password
 * change are the two things that must still resolve in the organization scope
 * where the caller's record actually lives.
 */

const fx = readFixture();

test.describe("cross-tenant isolation", () => {
  test.use({ storageState: storageStateFor("b-admin") });

  test("a super-admin of tenant B sees nothing of tenant A", async ({ page }) => {
    if (!fx.tenantB || !fx.users["viewer"]) {
      test.skip(true, `unverified — blocked: ${fx.problems.join("; ") || "tenant B fixture missing"}`);
      return;
    }

    // Tenant B's administrator holds `*` — within tenant B. The wildcard is
    // what makes this worth asserting: if isolation were enforced by permission
    // rather than by scope, this principal would see everything.
    await page.goto("/users", { waitUntil: "networkidle" });
    const listed = new Set(
      (await page.getByRole("cell").allInnerTexts()).map((t) => t.trim()),
    );
    for (const username of ["mx-viewer", "mx-editor", "mx-denied", "tenant-admin"]) {
      expect
        .soft(
          listed.has(username),
          `mx-b-admin administers tenant B; ${username} lives in tenant A and must not ` +
            `appear in its user list`,
        )
        .toBe(false);
    }

    await page.goto("/resources", { waitUntil: "networkidle" });
    // Matched as whole cell values, not as substrings of the page text: tenant
    // B legitimately owns a resource called `mx-b-only`, and a substring search
    // for "mx-b" finds it and reports tenant A's node as leaked. The first
    // version of this assertion did exactly that.
    const shown = await page.getByRole("cell").allInnerTexts();
    const names = new Set(shown.map((t) => t.trim()));
    for (const name of ["mx-root", "mx-a", "mx-b", "mx-c", "mx-d", "mx-b-sibling"]) {
      expect
        .soft(
          names.has(name),
          `resource ${name} belongs to tenant A and must not be listed in tenant B`,
        )
        .toBe(false);
    }
  });

  test("a tenant principal cannot reach another tenant by naming it in a header", async ({
    page,
  }) => {
    // `X-Axiam-Tenant` is how an ORGANIZATION-level principal says which tenant
    // a request is about. A tenant principal sending the same header must not
    // be promoted by it — otherwise the header is an authorization bypass
    // available to anyone who reads the docs.
    if (!fx.tenantA) {
      test.skip(true, "unverified — blocked: tenant A id missing from the fixture");
      return;
    }
    await ensureOnApp(page);
    const res = await page.evaluate(async (tenantA) => {
      const r = await fetch("/api/v1/users", {
        credentials: "include",
        headers: { "X-Axiam-Tenant": tenantA },
      });
      return { status: r.status, body: (await r.text()).slice(0, 500) };
    }, fx.tenantA);

    // Either refused outright, or answered from the caller's OWN tenant. What
    // it must never be is tenant A's user list.
    if (res.status === 200) {
      for (const username of ["mx-viewer", "mx-editor", "tenant-admin"]) {
        expect
          .soft(
            res.body,
            `mx-b-admin sent X-Axiam-Tenant naming tenant A and got HTTP 200. The answer ` +
              `must still be tenant B's own data — finding ${username} in it means the ` +
              `header promoted a tenant principal across the isolation boundary`,
          )
          .not.toContain(username);
      }
    } else {
      expect
        .soft(
          [400, 401, 403, 404].includes(res.status),
          `a tenant principal naming a foreign tenant should be refused with a client ` +
            `error, not HTTP ${res.status}: ${res.body}`,
        )
        .toBe(true);
    }
  });
});

test.describe("organization-level reach", () => {
  test.use({ storageState: storageStateFor("org-admin") });
  // Serial: these share one browser session and one piece of mutable UI state
  // — which tenant is selected — and running them in parallel would have them
  // switching it under each other.
  test.describe.configure({ mode: "serial" });

  test("the tenant switcher offers the organization and every tenant in it", async ({ page }) => {
    await page.goto("/dashboard", { waitUntil: "networkidle" });
    await openTenantMenu(page);

    const menu = page.getByRole("menu", { name: "Tenant selector" });
    await expect
      .soft(menu, "the organization super-admin must be offered a tenant switcher")
      .toBeVisible();

    // "Organization" is the caller's own scope, offered by name because it is
    // where its record lives — not a tenant picked from a list of tenants.
    await expect
      .soft(
        menu.getByRole("menuitem", { name: "Organization" }),
        "an organization-level principal must be able to return to its own scope",
      )
      .toHaveCount(1);

    for (const name of ["E2E Default Tenant", "Matrix Tenant B"]) {
      await expect
        .soft(
          menu.getByRole("menuitem", { name }),
          `the switcher must offer "${name}" — the org super-admin administers every ` +
            `tenant in its organization`,
        )
        .toHaveCount(1);
    }
  });

  test("switching tenants changes which tenant's data is shown", async ({ page }) => {
    if (!fx.users["viewer"]) {
      test.skip(true, `unverified — blocked: ${fx.problems.join("; ") || "fixture users missing"}`);
      return;
    }

    await selectTenant(page, "E2E Default Tenant");
    await navigateInApp(page, "Users");
    await expect
      .soft(
        page.getByText("mx-viewer", { exact: false }).first(),
        "with tenant A selected, the org super-admin must see tenant A's users",
      )
      .toBeVisible({ timeout: 20_000 });

    await selectTenant(page, "Matrix Tenant B");
    await navigateInApp(page, "Users");
    const inB = new Set((await page.getByRole("cell").allInnerTexts()).map((t) => t.trim()));
    expect
      .soft(
        inB.has("mx-viewer"),
        "with tenant B selected, tenant A's users must be gone — the switcher changes " +
          "which tenant requests are about, and every list in the app is tenant-scoped",
      )
      .toBe(false);
    expect
      .soft(
        inB.has("mx-b-admin"),
        "with tenant B selected, tenant B's own administrator must be listed",
      )
      .toBe(true);
  });

  test("/auth/me keeps answering for the caller while a child tenant is selected", async ({
    page,
  }) => {
    // The reported shape: selecting a child tenant changes which tenant
    // requests are *about*. It must not change which principal is making them,
    // and the caller's own record lives in the organization scope, not in the
    // tenant it happens to be looking at.
    await selectTenant(page, "Matrix Tenant B");
    await ensureOnApp(page);
    const me = await page.evaluate(async () => {
      const r = await fetch("/api/v1/auth/me", { credentials: "include" });
      return { status: r.status, body: r.ok ? await r.json() : await r.text() };
    });

    expect
      .soft(
        me.status,
        `/auth/me must keep working with a child tenant selected; got ${me.status}: ` +
          JSON.stringify(me.body).slice(0, 300),
      )
      .toBe(200);
    // `/auth/me` answers `{ user: {...}, opaque: {...} }` — the username is
    // nested. Reading it off the top level yielded `undefined`, which compared
    // unequal to "admin" and looked exactly like the defect this asserts
    // against.
    expect
      .soft(
        (me.body as { user?: { username?: string } })?.user?.username,
        "the answer must still describe the organization super-admin, not a principal " +
          "resolved inside the selected tenant",
      )
      .toBe("admin");
  });

  test("the caller's own password change resolves in its own scope while a child tenant is selected", async ({
    page,
  }) => {
    // Deliberately submitted with a WRONG current password. What is under test
    // is which scope the caller was resolved in, and the server can only answer
    // "that is not your current password" if it found the caller at all. A
    // successful rotation would prove the same thing and would also invalidate
    // every other session in this run, so the refusal is the better probe.
    await selectTenant(page, "Matrix Tenant B");
    await ensureOnApp(page);

    const res = await page.evaluate(async () => {
      const csrf = document.cookie
        .split("; ")
        .find((c) => c.startsWith("axiam_csrf="))
        ?.split("=")[1];
      const r = await fetch("/api/v1/auth/password/change", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          ...(csrf ? { "X-CSRF-Token": decodeURIComponent(csrf) } : {}),
        },
        body: JSON.stringify({
          current_password: "definitely-not-the-current-password",
          new_password: "Unused@Password123!",
        }),
      });
      return { status: r.status, body: (await r.text()).slice(0, 400) };
    });

    // 400/401/422 = "found you, wrong password" — the caller was resolved.
    // 404 = "no such user" — resolved in the selected tenant instead, which is
    // the defect. 500 = the scope lookup fell over.
    expect
      .soft(
        [400, 401, 403, 422].includes(res.status),
        `changing its own password with a child tenant selected must fail on the PASSWORD, ` +
          `not on finding the caller. HTTP ${res.status}: ${res.body}`,
      )
      .toBe(true);
  });

  test.afterAll(async ({ browser }) => {
    // Leave the switcher on the organization scope: the selection is persisted
    // per principal, and a later wave that inherited "tenant B" would silently
    // assert about the wrong tenant.
    const context = await browser.newContext({ storageState: storageStateFor("org-admin") });
    const page = await context.newPage();
    await page.goto("/dashboard", { waitUntil: "networkidle" }).catch(() => {});
    await selectTenant(page, "Organization").catch(() => {});
    await context.close();
  });
});

/**
 * Opens the tenant switcher.
 *
 * Located by the organization slug it always renders rather than by an
 * accessible name, because the trigger has none — it is a `<button>` with
 * `aria-haspopup="menu"` whose only text is `<org> / <tenant>`. Recorded as a
 * minor accessibility observation rather than worked around silently.
 */
async function openTenantMenu(page: Page): Promise<void> {
  const trigger = page
    .locator('button[aria-haspopup="menu"]')
    .filter({ hasText: ORG_SLUG })
    .first();
  await trigger.click();
  await page.getByRole("menu", { name: "Tenant selector" }).waitFor({ timeout: 15_000 });
}

/**
 * Navigates by clicking the sidebar link, NOT with `page.goto`.
 *
 * The distinction is load-bearing here. The selected tenant lives in module
 * state (`lib/activeTenant`), so a full document load resets it to the
 * organization scope — see finding F-03. `page.goto` is a full load; clicking
 * a link is not. A spec that navigated with `goto` after switching would be
 * asserting about the organization scope while believing it was asserting about
 * the tenant, which is how the first version of this file mis-read the
 * switcher as cosmetic.
 */
async function navigateInApp(page: Page, label: string): Promise<void> {
  await page
    .getByRole("complementary", { name: "Main navigation" })
    .getByRole("link", { name: label, exact: true })
    .click();
  await page.waitForLoadState("networkidle");
}

async function selectTenant(page: Page, label: string): Promise<void> {
  if (new URL(page.url()).protocol === "about:") {
    await page.goto("/dashboard", { waitUntil: "networkidle" });
  }
  await openTenantMenu(page);
  await page.getByRole("menuitem", { name: label, exact: true }).click();
  // Selecting clears the query cache and refetches every list; waiting for the
  // network to settle is what makes the next assertion about the new tenant
  // rather than about the previous one's cached rows.
  await page.waitForLoadState("networkidle");
}
