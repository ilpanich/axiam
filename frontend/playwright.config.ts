import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env["CI"],
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
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: "npm run dev",
    url: "http://localhost:5173",
    // Reuse a server already listening on 5173 in BOTH environments:
    // - CI starts `npx serve dist -l 5173` (the production build) before
    //   running Playwright, so Playwright must reuse it rather than spawn a
    //   second `npm run dev` on the same port (which would error / shadow the
    //   prod build with the dev server — WR-03).
    // - Locally, Playwright starts `npm run dev` only if nothing is already up.
    reuseExistingServer: true,
  },
});
