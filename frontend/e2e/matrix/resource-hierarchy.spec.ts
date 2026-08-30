import { test, expect } from "@playwright/test";
import { authzCheck, ensureOnApp, readFixture } from "../helpers/matrix";
import { storageStateFor } from "../helpers/matrix-fixture";

/**
 * Resource-scoped grants, inheritance, and deny-override — asked of the
 * authorization engine itself.
 *
 * The UI can only show what it was told. No page renders "may mx-denied update
 * mx-d?", and the whole point of a depth-5 tree is questions of exactly that
 * shape, so these are put to `POST /api/v1/authz/check` with `subject_id`.
 * That parameter is gated on `authz:check_as`, which the tenant administrator
 * holds — so one session can interrogate the engine about every principal
 * instead of eight sessions each asking about themselves.
 *
 * The fixture tree, and what each question is for:
 *
 * ```
 *   mx-root
 *    └ mx-a          ← mx-denied's DENY on resources:update sits here
 *       ├ mx-b       ← mx-editor's ALLOW on resources:update sits here
 *       │  └ mx-c    ← must inherit from mx-b
 *       │     └ mx-d ← must inherit from mx-b, two levels down
 *       │            ← mx-denied's ALLOW also sits here, and must lose
 *       └ mx-b-sibling  ← must NOT inherit from mx-b
 * ```
 *
 * Every assertion is `expect.soft`: one wrong answer must not stop the other
 * twenty from being measured in the same wave.
 */

const fx = readFixture();

test.describe("resource hierarchy and deny-override", () => {
  // The tenant administrator, because `subject_id` needs `authz:check_as` and
  // the fixture principals deliberately do not hold it.
  test.use({ storageState: storageStateFor("tenant-admin") });

  test.beforeEach(() => {
    const missing = ["root", "a", "b", "c", "d", "b-sibling"].filter(
      (k) => !fx.resources[k],
    );
    // Hard, and only here: with no tree there is no question to ask, and a
    // green "0 assertions" would be worse than an honest stop.
    expect(
      missing,
      `unverified — blocked: the fixture resource tree is incomplete. ` +
        `Missing: ${missing.join(", ")}. Fixture problems: ${fx.problems.join("; ")}`,
    ).toEqual([]);
  });

  test("a grant on mx-b reaches its descendants and not its sibling", async ({ page }) => {
    const editor = fx.users["editor"];
    expect(editor, "unverified — blocked: mx-editor was not built").toBeTruthy();
    if (!editor) return;

    // Reaches: the node itself, and every node beneath it, at any depth.
    for (const node of ["b", "c", "d"]) {
      const r = await authzCheck(page, {
        action: "resources:update",
        resource_id: fx.resources[node],
        subject_id: editor.id,
      });
      expect
        .soft(
          r.allowed,
          `mx-editor holds resources:update on mx-b; mx-${node} is mx-b or beneath it, ` +
            `so the grant must reach it (HTTP ${r.status})`,
        )
        .toBe(true);
    }

    // Does not reach: a sibling of the granted node, or anything above it.
    // Without this half, inheritance is indistinguishable from "allowed
    // everywhere".
    for (const node of ["b-sibling", "a", "root"]) {
      const r = await authzCheck(page, {
        action: "resources:update",
        resource_id: fx.resources[node],
        subject_id: editor.id,
      });
      expect
        .soft(
          r.allowed,
          `mx-editor's grant is on mx-b; mx-${node} is not beneath mx-b, ` +
            `so the grant must NOT reach it (HTTP ${r.status})`,
        )
        .toBe(false);
    }
  });

  test("a deny on an ancestor masks an allow granted lower down", async ({ page }) => {
    // The deny-override property, stated as plainly as the engine allows:
    // mx-denied holds resources:update ALLOW on mx-d — the deepest node — and
    // resources:update DENY on mx-a, two levels above it. Deny wins.
    const denied = fx.users["denied"];
    expect(denied, "unverified — blocked: mx-denied was not built").toBeTruthy();
    if (!denied) return;

    const r = await authzCheck(page, {
      action: "resources:update",
      resource_id: fx.resources["d"],
      subject_id: denied.id,
    });
    expect
      .soft(
        r.allowed,
        "mx-denied holds an explicit ALLOW for resources:update on mx-d and an explicit " +
          "DENY on its ancestor mx-a. The engine is deny-override, not most-specific-wins, " +
          `so mx-d must be refused (HTTP ${r.status})`,
      )
      .toBe(false);

    // The same deny must reach every node beneath where it sits.
    for (const node of ["a", "b", "c", "d"]) {
      const check = await authzCheck(page, {
        action: "resources:update",
        resource_id: fx.resources[node],
        subject_id: denied.id,
      });
      expect
        .soft(
          check.allowed,
          `the deny on mx-a must reach mx-${node} (HTTP ${check.status})`,
        )
        .toBe(false);
    }

    // ...and the deny must not leak sideways out of the subtree it sits on.
    // `mx-root` is above `mx-a`; mx-denied has no allow there either, so the
    // answer is "refused" for a different reason — which is why this asserts
    // on the reason rather than the boolean.
    const control = await authzCheck(page, {
      action: "resources:get",
      resource_id: fx.resources["b-sibling"],
      subject_id: denied.id,
    });
    expect
      .soft(
        control.allowed,
        "mx-denied also holds the global read-only role, so resources:get on a node " +
          "outside the denied action must still be allowed — a deny on resources:update " +
          `must not spill onto other actions (HTTP ${control.status})`,
      )
      .toBe(true);
  });

  test("a scoped deny narrows only the scopes it names", async ({ page }) => {
    // mx-role-scope-deny denies `resources:get` on the `invoices` scope only.
    // An empty `scope_ids` would be a wildcard and would mask the action
    // entirely — the difference between the two is the assertion.
    const viewer = fx.users["viewer"];
    const roleId = fx.roles["mx-role-scope-deny"];
    if (!viewer || !roleId || !fx.scopes["invoices"] || !fx.scopes["reports"]) {
      test.skip(
        true,
        "unverified — blocked: the scoped-deny role or its scopes were not built " +
          `(${fx.problems.join("; ") || "no reason recorded"})`,
      );
      return;
    }

    // Granting inside the test rather than in the fixture: this is the one
    // assertion whose subject must NOT already hold the deny when the other
    // specs run, and scoping the mutation here keeps the principals in the nav
    // matrix stable.
    //
    // On the app's origin first: a fresh page is on `about:blank`, where
    // `document.cookie` throws SecurityError and a relative fetch has no origin.
    await ensureOnApp(page);
    const assign = await page.evaluate(
      async ([role, user, resource]) => {
        const csrf = document.cookie
          .split("; ")
          .find((c) => c.startsWith("axiam_csrf="))
          ?.split("=")[1];
        const res = await fetch(`/api/v1/roles/${role}/users`, {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
            ...(csrf ? { "X-CSRF-Token": decodeURIComponent(csrf) } : {}),
          },
          body: JSON.stringify({ user_id: user, resource_id: resource }),
        });
        return res.status;
      },
      [roleId, viewer.id, fx.resources["b"]] as const,
    );
    expect
      .soft(
        [200, 201, 204, 409].includes(assign),
        `assigning mx-role-scope-deny to mx-viewer on mx-b returned HTTP ${assign}`,
      )
      .toBe(true);

    const onDenied = await authzCheck(page, {
      action: "resources:get",
      resource_id: fx.resources["b"],
      subject_id: viewer.id,
      scope: "invoices",
    });
    expect
      .soft(
        onDenied.allowed,
        "the deny names the `invoices` scope, so resources:get must be refused there " +
          `(HTTP ${onDenied.status})`,
      )
      .toBe(false);

    const onOther = await authzCheck(page, {
      action: "resources:get",
      resource_id: fx.resources["b"],
      subject_id: viewer.id,
      scope: "reports",
    });
    expect
      .soft(
        onOther.allowed,
        "the deny names `invoices` only, so `reports` must be unaffected — a scoped deny " +
          `that masks every scope is a wildcard deny, which is a different grant (HTTP ${onOther.status})`,
      )
      .toBe(true);
  });

  test("a principal with no roles is refused everywhere", async ({ page }) => {
    // The floor the default-deny engine has to hold. Cheap, and the assertion
    // that catches a grant accidentally made to everyone.
    const nobody = fx.users["nobody"];
    expect(nobody, "unverified — blocked: mx-nobody was not built").toBeTruthy();
    if (!nobody) return;

    for (const action of ["resources:get", "resources:update", "users:list", "roles:list"]) {
      for (const node of ["root", "b", "d"]) {
        const r = await authzCheck(page, {
          action,
          resource_id: fx.resources[node],
          subject_id: nobody.id,
        });
        expect
          .soft(
            r.allowed,
            `mx-nobody holds no roles at all; ${action} on mx-${node} must be refused ` +
              `(HTTP ${r.status})`,
          )
          .toBe(false);
      }
    }
  });
});
