import { test as setup } from "@playwright/test";
import { loginAsAdmin, STORAGE_STATE } from "./helpers/auth";

// One-time authentication for the whole E2E suite. This `setup` project runs
// before the test projects (they declare `dependencies: ["setup"]`), performs a
// single real UI login against the live backend, and persists the resulting
// httpOnly session + CSRF cookies to STORAGE_STATE. Every authenticated spec
// then loads that state instead of logging in per-test — removing ~60 Argon2id
// logins per run and the post-login redirect flakiness they caused.
setup("authenticate as admin", async ({ page }) => {
  await loginAsAdmin(page);
  await page.context().storageState({ path: STORAGE_STATE });
});
