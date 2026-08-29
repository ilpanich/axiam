import { test as setup, expect, Page } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { Api } from "./helpers/api";
import {
  buildMatrixFixture,
  FIXTURE_STATE,
  ORG_SLUG,
  PASSWORD,
  TENANT_A_SLUG,
  TENANT_B_SLUG,
  storageStateFor,
} from "./helpers/matrix-fixture";

/**
 * Builds the RBAC / PKI fixture once per run and captures one browser session
 * per principal.
 *
 * Why a setup project rather than a `beforeAll`: the matrix signs in as seven
 * different principals and asserts several dozen things per principal. Every
 * sign-in costs an Argon2id verification on the backend, so logging in per
 * test would dominate the runtime of every wave. Each principal logs in once,
 * here, and the specs load the resulting session with `storageState`.
 *
 * Nothing in this file uses a hard `expect` on a fixture step. A wave that
 * aborts because one CA failed to generate measures nothing behind it, and the
 * backend image is too slow to rebuild for that to be an acceptable trade — see
 * `E2E-TESTS.md` §5. Fixture failures are collected in `fixture.problems` and
 * the specs report the areas they block as *unverified*, never as green.
 */

setup("build the RBAC / PKI fixture", async () => {
  setup.setTimeout(300_000);

  const api = await Api.open();
  const login = await api.login(ORG_SLUG, "admin", PASSWORD);
  // This one IS hard: with no organization super-admin session there is no
  // fixture at all, and every downstream assertion would be measuring nothing.
  expect(
    login.status,
    `organization-level sign-in as admin@${ORG_SLUG} failed: ` +
      JSON.stringify(login.body).slice(0, 400),
  ).toBe(200);

  const fixture = await buildMatrixFixture(api);
  mkdirSync(dirname(FIXTURE_STATE), { recursive: true });
  writeFileSync(FIXTURE_STATE, JSON.stringify(fixture, null, 2));

  if (fixture.problems.length > 0) {
    // Printed, not thrown. These are findings for the log, and the wave still
    // has to measure everything they do not block.
    console.log(
      `\n[matrix-setup] ${fixture.problems.length} fixture step(s) did not complete:\n` +
        fixture.problems.map((p) => `  - ${p}`).join("\n") +
        "\n",
    );
  }
  await api.dispose();
});

/**
 * One browser session per principal, written to its own storageState file.
 *
 * A principal whose sign-in is broken loses only its own file: the specs that
 * load it fail at their first navigation with a clear reason, and every other
 * principal's block still runs.
 */
const PRINCIPALS: Array<{
  key: string;
  username: string;
  /** `null` signs in at organization level, naming no tenant. */
  tenantSlug: string | null;
}> = [
  { key: "org-admin", username: "admin", tenantSlug: null },
  { key: "tenant-admin", username: "tenant-admin", tenantSlug: TENANT_A_SLUG },
  { key: "viewer", username: "mx-viewer", tenantSlug: TENANT_A_SLUG },
  { key: "editor", username: "mx-editor", tenantSlug: TENANT_A_SLUG },
  { key: "denied", username: "mx-denied", tenantSlug: TENANT_A_SLUG },
  { key: "grouped", username: "mx-grouped", tenantSlug: TENANT_A_SLUG },
  { key: "nobody", username: "mx-nobody", tenantSlug: TENANT_A_SLUG },
  { key: "b-admin", username: "mx-b-admin", tenantSlug: TENANT_B_SLUG },
];

/**
 * All eight sign-ins, in ONE test and strictly sequentially.
 *
 * Not eight parallel tests, which is what this was first written as: the
 * shipped rate-limit posture allows `login_per_min: 10` per IP, every principal
 * here shares one IP, and a wave that re-runs setup a few times inside a minute
 * then loses most of its sessions to 429s that surface only as a `waitForURL`
 * timeout. Serial, with a wait when the limiter says so, is both honest and
 * faster than debugging the same timeout eight times.
 *
 * A principal whose sign-in genuinely fails still costs only its own session:
 * the failure is collected and reported at the end, and the other seven
 * storageState files are written regardless.
 */
setup("sign in as every principal", async ({ browser }) => {
  setup.setTimeout(600_000);

  const failures: string[] = [];

  for (const p of PRINCIPALS) {
    const context = await browser.newContext();
    const page = await context.newPage();
    try {
      await signIn(page, p);
      await context.storageState({ path: storageStateFor(p.key) });
    } catch (e) {
      // Whatever the login form actually said beats "timed out waiting for a
      // navigation", which is the same message for a wrong password, a locked
      // account and a rate limit.
      const shown = await page
        .getByRole("alert")
        .first()
        .textContent()
        .catch(() => null);
      failures.push(
        `${p.username}: ${e instanceof Error ? e.message.split("\n")[0] : String(e)}` +
          (shown ? ` — page said: ${shown.trim()}` : ""),
      );
    } finally {
      await context.close();
    }
  }

  if (failures.length > 0) {
    console.log(
      `\n[matrix-setup] ${failures.length} principal(s) could not sign in:\n` +
        failures.map((f) => `  - ${f}`).join("\n") +
        "\n",
    );
  }
  // Hard only if NO principal got a session: the matrix would then be measuring
  // nothing at all, and a green run would be a lie.
  expect(
    failures.length,
    `every principal failed to sign in:\n${failures.join("\n")}`,
  ).toBeLessThan(PRINCIPALS.length);
});

/**
 * Drives the two-step sign-in form, waiting out the login rate limiter.
 *
 * The limiter answers 429 and the form renders its message; retrying after the
 * window is the correct behaviour for a fixture, and distinguishing it from a
 * real credential failure is the reason this looks at the page rather than only
 * at the URL.
 */
async function signIn(
  page: Page,
  p: { username: string; tenantSlug: string | null },
): Promise<void> {
  for (let attempt = 0; attempt < LOGIN_ATTEMPTS; attempt++) {
    await page.goto("/login", { waitUntil: "networkidle", timeout: 45_000 });
    await page
      .getByLabel("Organization slug")
      .waitFor({ state: "visible", timeout: 15_000 });

    await page.getByLabel("Organization slug").fill(ORG_SLUG);
    // Blank for an organization-level principal. The empty string must be read
    // as "no tenant", not as a slug that cannot match.
    await page.getByLabel("Tenant slug").fill(p.tenantSlug ?? "");
    await page.getByRole("button", { name: "Continue" }).click();

    await page.getByLabel("Username or email").fill(p.username);
    await page.getByLabel("Password").fill(PASSWORD);
    // `exact` matters: the page also carries "Sign in with a passkey", whose
    // accessible name contains this one, and a substring match resolves to
    // both and fails the whole project on a strict-mode violation.
    await page.getByRole("button", { name: "Sign in", exact: true }).click();

    try {
      await page.waitForURL(/\/dashboard|\/$/, { timeout: 30_000 });
      return;
    } catch (e) {
      const alert = await page
        .getByRole("alert")
        .first()
        .textContent()
        .catch(() => null);
      const throttled = /too many|rate|try again/i.test(alert ?? "");
      if (!throttled || attempt === LOGIN_ATTEMPTS - 1) throw e;
      await page.waitForTimeout(RATE_LIMIT_WAIT_MS);
    }
  }
}

/** Sign-in attempts per principal before the failure is reported. */
const LOGIN_ATTEMPTS = 4;
/**
 * How long to wait out the login limiter. `login_per_min` is a per-minute
 * window, so a little over a minute clears it whatever phase it was in.
 */
const RATE_LIMIT_WAIT_MS = 65_000;
