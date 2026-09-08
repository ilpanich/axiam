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

/**
 * The suite's hostname, compared WITHOUT the port.
 *
 * The callback arrives on SUITE_BASE_URL's port (8442 here, the published one),
 * and the suite then redirects the browser to its own internal base — port 8443
 * — which nothing publishes, so the host browser gets `404 page not found`.
 * That 404 is not a failure: by the time it happens the callback has been
 * delivered and the module has moved on. Matching on the full base URL called
 * it one anyway, and every module then cost a 45-second timeout it had already
 * passed.
 */
const SUITE_HOST = new URL(SUITE).hostname;
const atSuite = (u) => u.hostname === SUITE_HOST;

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

/**
 * Every test instance in the newest plan.
 *
 * `length` has to be generous, and that is the whole point of this comment.
 * `/api/plan` returns plans in the suite's own order, which is OLDEST FIRST —
 * so `length=5` on a suite that has run a dozen plans returns the five oldest
 * and the newest is not in the window at all. Sorting them by `started`
 * afterwards then yields the newest of the WRONG five, and the driver polls a
 * long-dead plan forever, reporting "0 authorizations completed" with no error
 * to explain it. Fetch a wide window, then sort.
 */
async function currentInstances() {
  const plans = (await suiteJson('/api/plan?length=100')).data ?? [];
  if (plans.length === 0) return [];
  plans.sort((a, b) => String(b.started ?? '').localeCompare(String(a.started ?? '')));
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
      page.waitForURL((u) => atSuite(u), { timeout: 45_000 });

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
      // Where the browser actually stopped, and what it was shown. Without
      // this the driver reports "nothing appeared", which is true and useless:
      // the first time this fired, the page was AXIAM answering
      // `{"error":"invalid_request"}` as a BODY at the authorization endpoint
      // instead of redirecting the error to the registered `redirect_uri`
      // (RFC 6749 §4.1.2.1) — a real finding that the message hid.
      const body = await page
        .evaluate(() => document.body.innerText.slice(0, 300))
        .catch(() => '<unreadable>');
      throw new Error(
        `stopped at ${page.url().split('?')[0]} — neither the consent screen ` +
          `nor the suite callback appeared. Page said: ${body.replace(/\s+/g, ' ')}`,
      );
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
  // ONE BROWSER CONTEXT PER TEST — not per authorization, and not one for the
  // whole run. Both extremes are wrong, in opposite directions.
  //
  // A context per authorization was the first attempt, on the reasoning that
  // carrying an OP session between modules would turn "sign in" into "already
  // signed in". True between modules; false WITHIN one. A test may drive two
  // authorizations and compare them, and `oidcc-max-age-10000` does exactly
  // that:
  //
  //     CheckIdTokenAuthTimeClaimsSameIfPresent: the id_tokens contain
  //     different auth_time claims, but must contain the same auth_time
  //
  // Two fresh contexts meant two sign-ins, two sessions and two `auth_time`s,
  // so the module failed on a difference the harness had manufactured.
  // `oidcc-prompt-none-logged-in` failed the same way: it asks for `prompt=none`
  // expecting the session established a moment earlier, and met a browser that
  // had never signed in.
  //
  // One context for the whole run is the opposite error — then
  // `oidcc-prompt-none-not-logged-in` can never see a signed-out browser.
  //
  // Per test gives both: continuity inside a test, isolation between them.
  const contexts = new Map();
  const contextFor = async (testId) => {
    if (!contexts.has(testId)) {
      contexts.set(testId, await browser.newContext({ ignoreHTTPSErrors: true }));
    }
    return contexts.get(testId);
  };
  let seen = new Set();
  try {
    for (;;) {
      let drove = 0;
      for (const testId of await currentInstances()) {
        // Only a test that is still WAITING may be driven, and this check is
        // not defensive — it is a correctness requirement.
        //
        // The suite runs every module of a plan through ONE alias, and a
        // callback is delivered to whichever test holds that alias at the
        // moment it arrives ("Alias has now been claimed by another test" in
        // the log). Completing a URL whose test has already moved on therefore
        // delivers ITS result to somebody else's callback. That is not
        // hypothetical: an `invalid_request` from
        // `oidcc-response-type-missing` was driven late and landed on
        // `oidcc-server`, failing the plan's happy path with an error it never
        // asked for — and looking exactly like an AXIAM defect.
        let status;
        try {
          status = (await suiteJson(`/api/info/${testId}`)).status;
        } catch {
          continue;
        }
        if (status !== 'WAITING') {
          // The test is done with its browser. Closing it here — rather than
          // after each visit — is what bounds the number of live contexts
          // without breaking continuity inside a test.
          const finished = contexts.get(testId);
          if (finished) {
            contexts.delete(testId);
            await finished.close().catch(() => {});
          }
          continue;
        }

        let info;
        try {
          info = await suiteJson(`/api/runner/browser/${testId}`);
        } catch {
          continue;
        }
        for (const url of info.urls ?? []) {
          if (seen.has(url)) continue;
          seen.add(url);
          // Reused across every authorization this test performs, and closed
          // only when the test leaves WAITING for good — see `contextFor`.
          const context = await contextFor(testId);
          if (await visit(context, url)) drove += 1;
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
