import { defineConfig, devices } from "@playwright/test";
import { STORAGE_STATE } from "./e2e/helpers/auth";

/**
 * Where the suite points. Two shapes are supported, and they need different
 * setup:
 *   - `http://localhost:5173` (the default) — the Vite dev server, started by
 *     the `webServer` block below.
 *   - `https://localhost` — the production-like Compose stack behind Caddy,
 *     which is already running and must not be started here.
 */
const BASE_URL = process.env["E2E_BASE_URL"] ?? "http://localhost:5173";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env["CI"],
  // 2 retries on CI: the shared-session `setup` project (below) removes the
  // per-test Argon2id login that drove most flakiness; a small retry budget is
  // kept as a backstop for incidental network jitter against the live backend.
  retries: process.env["CI"] ? 2 : 0,
  workers: process.env["CI"] ? 1 : undefined,
  // `list` streams each test's pass/fail to stdout so the CI log shows
  // progress and failures even if the run is interrupted; `html` is still
  // produced for the uploaded artifact.
  reporter: [["list"], ["html"]],
  use: {
    baseURL: BASE_URL,
    trace: "on-first-retry",
    // The documented front door for the production-like stack is
    // `caddy reverse-proxy --from https://localhost`, whose certificate is
    // issued by Caddy's own local CA. That CA is trusted by the developer's
    // system store, not by a fresh Playwright browser profile, and the whole
    // reason for testing through HTTPS is cookie behaviour — `Secure` and
    // `SameSite` — not certificate validation.
    ignoreHTTPSErrors: true,
  },
  projects: [
    // Runs first: authenticates once and writes STORAGE_STATE (see
    // e2e/auth.setup.ts). No storageState of its own — it starts clean.
    {
      name: "setup",
      testMatch: /auth\.setup\.ts/,
    },
    {
      name: "chromium",
      testIgnore: [/matrix\//, /.*\.setup\.ts/],
      use: {
        ...devices["Desktop Chrome"],
        // Reuse the session captured by the setup project. Auth-flow specs
        // (login/logout/mfa-setup/auth-contract) override this with an empty
        // session via `test.use(...)` so they run unauthenticated.
        storageState: STORAGE_STATE,
      },
      dependencies: ["setup"],
    },
    // The RBAC / PKI permission matrix (claude_dev/E2E-TESTS.md). Split from `chromium`
    // because it needs its own fixture and its own eight sessions, and because
    // it must be runnable on its own while a wave is being iterated on:
    //   npx playwright test --project=matrix
    {
      name: "matrix-setup",
      testMatch: /matrix\.setup\.ts/,
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "matrix",
      testMatch: /matrix\/.*\.spec\.ts/,
      use: {
        ...devices["Desktop Chrome"],
        // Deliberately no default storageState: each matrix spec declares the
        // principal it is about with `test.use({ storageState })`. Inheriting a
        // session here would make a spec that forgot to declare one silently
        // assert about the wrong principal — the one failure mode a permission
        // matrix cannot afford.
      },
      dependencies: ["matrix-setup"],
    },
  ],
  // Only when the suite is pointed at a local dev server. Against the
  // production-like stack (E2E_BASE_URL=https://localhost, fronted by Caddy)
  // there is nothing for Playwright to start, and spawning `npm run dev`
  // would boot a second, unrelated frontend on :5173 that no test then uses.
  ...(BASE_URL.includes("localhost:5173")
    ? {
  webServer: {
    command: "npm run dev",
    url: "http://localhost:5173",
    // Reuse a server already listening on 5173 in BOTH environments:
    // - CI starts `vite preview` (serving the production `dist` build with the
    //   backend proxy) before running Playwright, so Playwright must reuse it
    //   rather than spawn a second `npm run dev` on the same port (which would
    //   error / shadow the prod build with the dev server — WR-03).
    // - Locally, Playwright starts `npm run dev` only if nothing is already up.
    reuseExistingServer: true,
  },
      }
    : {}),
});
