#!/usr/bin/env node
/**
 * drive-browser.mjs — complete a conformance run's interactive hops in a real
 * browser.
 *
 * WHY THIS EXISTS
 *
 * The OpenID Foundation suite can drive a sign-in page itself, through a
 * `browser` block in the plan configuration. Its runner is HtmlUnit, and
 * pointed at AXIAM's `/login` it fetched the document and stopped: what it
 * recorded was the bare Vite `index.html` with a `<script type="module">` in
 * it, and every element the automation was told to fill belongs to a React tree
 * HtmlUnit never built. `wait id org-slug 15` timed out, and a failed browser
 * task INTERRUPTS the module — strictly worse than having no block, which
 * merely leaves it WAITING with a URL for somebody to visit.
 *
 * So nobody visits it by hand. This does, in Chromium, which is what the page
 * was written for. The suite is polled for the URLs it is waiting on
 * (`GET /api/runner/browser/<testId>` returns `{urls, visited}`), each is
 * driven through AXIAM's three-step sign-in and, when it appears, the consent
 * screen, and the browser is left to follow the redirect back to the suite's
 * callback — which is what tells the suite the hop is done.
 *
 * This is a statement about the SUITE, not about AXIAM. A JavaScript sign-in
 * page is what a modern OP has, and the OpenID Foundation expects the
 * interactive hops of a certification run to be completed in a browser.
 *
 * USAGE
 *
 *   node conformance/scripts/drive-browser.mjs            # until interrupted
 *   node conformance/scripts/drive-browser.mjs --once     # one sweep, then exit
 *
 * Reads the same suite.env / suite.local.env the rest of the harness does, via
 * the environment: SUITE_BASE_URL, AXIAM_ORG_SLUG, AXIAM_TENANT_SLUG,
 * CONFORMANCE_USER, CONFORMANCE_USER_PASSWORD. Run it beside `conformance-run`;
 * `just conformance-drive` does both.
 */

// The suite's own certificate is self-signed for CN=localhost — it is
// upstream's image and not ours to reissue — so Node's fetch refuses it with a
// bare `TypeError: fetch failed`. Turned off HERE, inside a throwaway process
// whose only two peers are containers on this host, rather than exported into
// the operator's environment where it would outlive the run.
//
// Note what this does NOT relax: the half under test is the SUITE verifying
// AXIAM's certificate, and that is a different process which still verifies
// against the CA this harness minted. `conformance-up` injects it into the
// suite's truststore precisely so it can.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

import { createRequire } from 'node:module';

// playwright-core lives in frontend/node_modules — the repository has one
// browser download and one pinned version, shared with the E2E suite. Resolved
// through NODE_PATH (set by `just conformance-drive`) rather than a second
// package.json at the root.
const require = createRequire(import.meta.url);
const { chromium } = require('playwright-core');

const SUITE = need('SUITE_BASE_URL');
const ORG = need('AXIAM_ORG_SLUG');
/**
 * The tenant slug the sign-in form wants — which is NOT always the slug of the
 * tenant the account lives in.
 *
 * AXIAM's organization-scope row has the slug `organization`, and the form says
 * so in as many words: "Organization-level accounts — including the
 * administrator created at setup — leave this blank." Typing `organization`
 * into the field asks for a tenant NAMED organization, the lookup 403s, and the
 * form never advances to the credentials step. The symptom is a timeout waiting
 * for `#username`, twenty seconds and one indirection away from the cause.
 *
 * So `organization` and the empty string both mean "leave it blank".
 */
const TENANT = (process.env.AXIAM_TENANT_SLUG ?? '').trim();
const TENANT_IS_ORG_SCOPE = TENANT === '' || TENANT === 'organization';
const USER = need('CONFORMANCE_USER');
const PASSWORD = need('CONFORMANCE_USER_PASSWORD');
const ONCE = process.argv.includes('--once');

function need(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`[drive] ${name} is not set — source conformance/suite.env and suite.local.env`);
    process.exit(1);
  }
  return v;
}

/**
 * The suite's own certificate is self-signed for CN=localhost (it is upstream's
 * image), so TLS verification is off for this browser. That is scoped to a
 * throwaway Chromium talking to two containers on this host, and the half that
 * is actually under test — the suite verifying AXIAM's certificate — is
 * unaffected and still verifies.
 */
async function suiteJson(path) {
  const res = await fetch(`${SUITE}${path}`);
  if (!res.ok) throw new Error(`GET ${path} -> ${res.status}`);
  return res.json();
}

/** Every test instance in the newest plan, newest plan first. */
async function currentInstances() {
  const plans = (await suiteJson('/api/plan?length=5')).data ?? [];
  plans.sort((a, b) => String(b.started ?? '').localeCompare(String(a.started ?? '')));
  if (plans.length === 0) return [];
  const plan = await suiteJson(`/api/plan/${plans[0]._id}`);
  return (plan.modules ?? []).flatMap((m) => m.instances ?? []);
}

/**
 * Drive one authorization URL to completion.
 *
 * Everything is addressed by `id`. The labels are localised — W5 shipped five
 * locales — so text matching would bind this to whichever locale the run picked.
 */
async function visit(context, url) {
  const page = await context.newPage();
  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30_000 });

    // Wait for whichever step the SPA settles on before asking which it is.
    //
    // `locator.isVisible()` does NOT auto-wait — it answers about the DOM as it
    // stands, right now. Asking it first meant that on any paint slower than
    // the navigation, `#org-slug` was "not visible", the workspace step was
    // skipped, and the wait for `#username` then timed out on a page still
    // showing the workspace form. Twenty seconds and one indirection away from
    // the cause.
    await page
      .locator('#org-slug, #username')
      .first()
      .waitFor({ state: 'visible', timeout: 20_000 });

    // Step 1, the workspace. Genuinely conditional: `/login` jumps straight to
    // the credentials step when the URL already carries `?org=` or `?tenant=`.
    if (await page.locator('#org-slug').isVisible()) {
      await page.locator('#org-slug').fill(ORG);
      if (!TENANT_IS_ORG_SCOPE) {
        await page.locator('#tenant-slug').fill(TENANT);
      }
      await page.locator('#login-workspace-submit').click();
    }

    // Step 2, the credentials.
    await page.locator('#username').waitFor({ state: 'visible', timeout: 20_000 });
    await page.locator('#username').fill(USER);
    await page.locator('#password').fill(PASSWORD);
    await page.locator('#login-credentials-submit').click();

    // Now one of two things happens, and which one is not knowable in advance:
    // the consent screen appears (a sensitive scope was requested), or the
    // browser is already on its way back to the suite (the FAPI plans ask for
    // `openid` alone and never see consent). Racing the two is what lets a
    // single driver serve both lanes without being told which it is in.
    const backAtSuite = () =>
      page.waitForURL((u) => u.href.startsWith(SUITE), { timeout: 45_000 });

    const outcome = await Promise.race([
      backAtSuite().then(() => 'suite', () => 'timeout'),
      page
        .locator('#consent-allow')
        .waitFor({ state: 'visible', timeout: 45_000 })
        .then(() => 'consent', () => 'timeout'),
    ]);

    if (outcome === 'consent') {
      await page.locator('#consent-allow').click();
      await backAtSuite();
    } else if (outcome === 'timeout') {
      throw new Error('neither the consent screen nor the suite callback appeared');
    }

    // Landing back on the suite's callback is what tells it the hop finished.
    // Waiting for that rather than returning early is the difference between
    // driving the flow and merely starting it.
    console.log(`[drive] completed ${new URL(url).pathname}`);
    return true;
  } catch (e) {
    console.error(`[drive] could not complete ${url}\n        ${e.message.split('\n')[0]}`);
    return false;
  } finally {
    await page.close();
  }
}

async function main() {
  // `host.docker.internal` is the name the SUITE uses, because the suite is in
  // a container; it does not resolve on the host, where this runs. suite.env
  // documents the same category error for AXIAM_ADMIN_BASE_URL.
  //
  // Resolved in the BROWSER rather than by rewriting the URL, and the
  // difference matters. The authorization URL's origin is the issuer: it is
  // where the `axiam_op_session` cookie is scoped, what the SPA's same-origin
  // `return_to` is relative to, and what the suite will compare against. Swap
  // `localhost` in and the login hop still works while testing a different
  // origin from the one under certification.
  const browser = await chromium.launch({
    headless: true,
    args: ['--host-resolver-rules=MAP host.docker.internal 127.0.0.1'],
  });
  // A fresh context per sweep is not an optimisation to skip: the OP session
  // cookie is the whole point of the login hop, and carrying one between
  // modules would silently turn "sign in" into "already signed in" and make
  // prompt/max_age modules test nothing.
  let seen = new Set();
  try {
    for (;;) {
      let drove = 0;
      for (const testId of await currentInstances()) {
        let info;
        try {
          info = await suiteJson(`/api/runner/browser/${testId}`);
        } catch {
          continue;
        }
        for (const url of info.urls ?? []) {
          if (seen.has(url)) continue;
          seen.add(url);
          const context = await browser.newContext({ ignoreHTTPSErrors: true });
          if (await visit(context, url)) drove += 1;
          await context.close();
        }
      }
      if (ONCE) {
        console.log(`[drive] one sweep, ${drove} authorization(s) completed`);
        return;
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
  } finally {
    await browser.close();
  }
}

main().catch((e) => {
  console.error(`[drive] ${e.stack ?? e}`);
  process.exit(1);
});
