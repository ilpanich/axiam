import { defineConfig, devices } from "@playwright/test";
import { STORAGE_STATE } from "./e2e/helpers/auth";

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
    baseURL: process.env["E2E_BASE_URL"] ?? "http://localhost:5173",
    trace: "on-first-retry",
  },
  projects: [
    // Runs first: authenticates once and writes STORAGE_STATE (see
    // e2e/auth.setup.ts). No storageState of its own — it starts clean.
    {
      name: "setup",
      testMatch: /.*\.setup\.ts/,
    },
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        // Reuse the session captured by the setup project. Auth-flow specs
        // (login/logout/mfa-setup/auth-contract) override this with an empty
        // session via `test.use(...)` so they run unauthenticated.
        storageState: STORAGE_STATE,
      },
      dependencies: ["setup"],
    },
  ],
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
});
