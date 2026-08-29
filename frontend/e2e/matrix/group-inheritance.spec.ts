import { test, expect } from "@playwright/test";
import { authzCheck, ensureOnApp, readFixture } from "../helpers/matrix";
import { storageStateFor } from "../helpers/matrix-fixture";

/**
 * Group membership grants immediately, and revokes immediately.
 *
 * Both halves matter, and the second is the one that goes wrong. Authorization
 * decisions are cached per subject; a grant that arrives late is a nuisance, but
 * a revoke that arrives late is a principal who keeps the access it was just
 * taken off — for as long as the cache holds. Asserting only the grant direction
 * would pass on a system with no invalidation at all.
 *
 * Run as the tenant administrator, which is the principal that owns the group,
 * and asked of `POST /api/v1/authz/check` with `subject_id`, so the answer is
 * the engine's rather than a page's rendering of it.
 *
 * Serial, and it puts the membership back: this mutates fixture state that
 * `nav-reach.spec.ts` also asserts on.
 */

const fx = readFixture();

test.describe("group inheritance", () => {
  test.use({ storageState: storageStateFor("tenant-admin") });
  test.describe.configure({ mode: "serial" });

  const groupId = () => fx.groups["mx-group-alpha"];

  test("a member holds the group's roles, and loses them the moment it leaves", async ({
    page,
  }) => {
    const user = fx.users["grouped"];
    const group = groupId();
    const root = fx.resources["root"];
    if (!user || !group || !root) {
      test.skip(
        true,
        `unverified — blocked: ${fx.problems.join("; ") || "group fixture incomplete"}`,
      );
      return;
    }

    // mx-grouped holds NO role directly. Everything it can do arrives through
    // mx-group-alpha, which carries the global read-only role — so this first
    // answer is entirely the group's doing.
    const before = await authzCheck(page, {
      action: "users:list",
      resource_id: root,
      subject_id: user.id,
    });
    expect
      .soft(
        before.allowed,
        "mx-grouped holds no role of its own; users:list must reach it through " +
          `mx-group-alpha (HTTP ${before.status})`,
      )
      .toBe(true);

    // --- revoke ----------------------------------------------------------
    const removed = await mutate(page, `/api/v1/groups/${group}/members/${user.id}`, "DELETE");
    expect
      .soft(
        [200, 204].includes(removed.status),
        `removing mx-grouped from mx-group-alpha returned HTTP ${removed.status}: ${removed.body}`,
      )
      .toBe(true);

    const afterRemove = await authzCheck(page, {
      action: "users:list",
      resource_id: root,
      subject_id: user.id,
    });
    expect
      .soft(
        afterRemove.allowed,
        "mx-grouped has just been removed from the only group that granted it anything. " +
          "The decision cache is flushed per subject on a membership change, so a surviving " +
          `allow here is a stale grant, not a delay (HTTP ${afterRemove.status})`,
      )
      .toBe(false);

    // --- grant ------------------------------------------------------------
    const added = await mutate(page, `/api/v1/groups/${group}/members`, "POST", {
      user_id: user.id,
    });
    expect
      .soft(
        [200, 201, 204, 409].includes(added.status),
        `adding mx-grouped back to mx-group-alpha returned HTTP ${added.status}: ${added.body}`,
      )
      .toBe(true);

    const afterAdd = await authzCheck(page, {
      action: "users:list",
      resource_id: root,
      subject_id: user.id,
    });
    expect
      .soft(
        afterAdd.allowed,
        "re-joining the group must restore the grant immediately, not on the next cache " +
          `expiry (HTTP ${afterAdd.status})`,
      )
      .toBe(true);
  });

  test("a service account inherits a group's roles exactly as a person does", async ({ page }) => {
    // Newly implemented, and the reason `has_role` was always declared
    // `User/ServiceAccount/Group -> Role`: a machine identity has to be able to
    // hold permissions without borrowing a person's account.
    const sa = fx.serviceAccounts["mx-sa-group"];
    const group = groupId();
    const root = fx.resources["root"];
    if (!sa || !group || !root) {
      test.skip(
        true,
        `unverified — blocked: ${fx.problems.join("; ") || "service-account fixture incomplete"}`,
      );
      return;
    }

    const before = await authzCheck(page, {
      action: "users:list",
      resource_id: root,
      subject_id: sa.id,
    });
    expect
      .soft(
        before.allowed,
        "mx-sa-group holds no role directly and is a member of mx-group-alpha; the " +
          `group's role must reach a machine identity as it reaches a person (HTTP ${before.status})`,
      )
      .toBe(true);

    const removed = await mutate(
      page,
      `/api/v1/groups/${group}/service-accounts/${sa.id}`,
      "DELETE",
    );
    expect
      .soft(
        [200, 204].includes(removed.status),
        `removing mx-sa-group from the group returned HTTP ${removed.status}: ${removed.body}`,
      )
      .toBe(true);

    const afterRemove = await authzCheck(page, {
      action: "users:list",
      resource_id: root,
      subject_id: sa.id,
    });
    expect
      .soft(
        afterRemove.allowed,
        "a machine identity's grant must be revoked on leaving a group just as a person's " +
          `is — a stale allow on a service account is a credential that outlives its authority ` +
          `(HTTP ${afterRemove.status})`,
      )
      .toBe(false);

    // Restore, so the rest of the matrix sees the fixture it expects.
    const added = await mutate(page, `/api/v1/groups/${group}/service-accounts`, "POST", {
      service_account_id: sa.id,
    });
    expect
      .soft(
        [200, 201, 204, 409].includes(added.status),
        `restoring mx-sa-group's membership returned HTTP ${added.status}: ${added.body}`,
      )
      .toBe(true);
  });
});

/** Issues a mutating request from the page's own origin, with CSRF attached. */
async function mutate(
  page: import("@playwright/test").Page,
  path: string,
  method: "POST" | "DELETE" | "PUT",
  body?: unknown,
): Promise<{ status: number; body: string }> {
  await ensureOnApp(page);
  return page.evaluate(
    async ([p, m, b]) => {
      const csrf = document.cookie
        .split("; ")
        .find((c) => c.startsWith("axiam_csrf="))
        ?.split("=")[1];
      const res = await fetch(p as string, {
        method: m as string,
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          ...(csrf ? { "X-CSRF-Token": decodeURIComponent(csrf) } : {}),
        },
        ...(b ? { body: JSON.stringify(b) } : {}),
      });
      return { status: res.status, body: (await res.text()).slice(0, 300) };
    },
    [path, method, body ?? null] as const,
  );
}
