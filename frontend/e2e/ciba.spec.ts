import { test, expect } from "@playwright/test";
import type { Api } from "./helpers/api";
import { loginAsAdmin } from "./helpers/auth";
import {
  CibaClientCalls,
  adminApi,
  approvalPath,
  claimsOf,
  registerCibaClient,
  requestIdFor,
  whoAmI,
} from "./helpers/ciba";

// ---------------------------------------------------------------------------
// CIBA (client-initiated backchannel authentication), poll mode — live backend
// (G-7, T23.7.3; contract §33).
//
// Three parties, played by three things in one process:
//   * the CLIENT is a registered confidential client that holds the CIBA grant,
//     talking to /oauth2/bc-authorize and /oauth2/token with its own
//     credential (helpers/ciba.ts, `CibaClientCalls`);
//   * the USER is the browser, which opens the approval page and decides, as
//     the person following the e-mailed link would;
//   * the ADMINISTRATOR registers clients and reads the audit log.
//
// The stack has no mailbox, so the approval link cannot be read from the
// message. Its record id is read where an operator would find it: the
// `oauth2.ciba_initiated` audit row every stored request leaves.
//
// What this file proves end to end, beyond the 21 + 15 HTTP tests the server
// crates carry:
//   - poll to tokens through the real approval page, the tokens carrying the
//     approval's evidence;
//   - denial is `access_denied`; a second redemption is `invalid_grant`;
//   - an expired request is `expired_token`, and its link is a "not found";
//   - `slow_down` grows the interval; a request for nobody looks like any other
//     and cannot be opened by anyone (D-63);
//   - a request that asks for a multi-factor class cannot be approved by a
//     password session;
//   - the limiter counts `bc-authorize` — a flood of FAILED client
//     authentications spends the budget — which is the class of defect Keycloak
//     26.7.x had, where a brute-force control did not cover CIBA.
//
// What it does NOT prove, and why: PING MODE. A ping is an HTTPS call from the
// server container to a receiver the client registered, through the outbound
// address guard (an `https` URL whose every address is publicly routable, with
// no redirect followed), over a TLS client that trusts only the Mozilla roots.
// There is no receiver a CI job can stand up that satisfies all three without
// either weakening that guard or adding a trust-anchor setting to production
// code, so ping end to end is covered at the Rust level instead
// (`crates/axiam-api-rest/tests/ciba_ping_flow_test.rs`: the approval route,
// the deliverer through its test seam, the receiver, then the client's
// redemption). See the T23.7.3 report in the plan for the decision.
//
// Budget: `AXIAM__RATE_LIMIT__BC_AUTHORIZE_PER_MIN` is 20 on this stack
// (docker/docker-compose.e2e.yml). This file makes ten `bc-authorize` calls
// before the limiter test spends the rest (the refusals count: the route's
// bucket counts every request, authenticated or not), so the limiter test must
// stay LAST and the describe must stay serial.
// ---------------------------------------------------------------------------

const USERNAME = process.env["E2E_TENANT_ADMIN_USERNAME"] ?? "tenant-admin";

test.describe.configure({ mode: "serial" });

test.describe("CIBA (poll mode)", () => {
  let api: Api;
  let tenantId: string;
  let userId: string;
  const open: CibaClientCalls[] = [];

  test.beforeAll(async () => {
    api = await adminApi();
    ({ tenantId, userId } = await whoAmI(api));
  });

  test.afterAll(async () => {
    for (const c of open) await c.dispose();
    await api.dispose();
  });

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  /** A fresh client of its own, so each test's requests are told apart. */
  async function newClient(label: string, extra: Record<string, unknown> = {}) {
    const client = await registerCibaClient(api, `e2e-ciba-${label}-${Date.now()}`, extra);
    const calls = await CibaClientCalls.open(tenantId, client);
    open.push(calls);
    return calls;
  }

  const authReqId = (body: Record<string, unknown>): string => {
    const id = body["auth_req_id"];
    if (typeof id !== "string" || id.length === 0) {
      throw new Error("bc-authorize answered without an auth_req_id");
    }
    return id;
  };

  test("the user approves on the approval page and the client collects its tokens", async ({
    page,
  }) => {
    test.setTimeout(120_000);
    const client = await newClient("poll");
    const started = Date.now();
    const initiated = await client.bcAuthorize({
      scope: "openid profile",
      login_hint: USERNAME,
      binding_message: "Confirm e2e 42 EUR",
      requested_expiry: "120",
    });
    expect(initiated.status).toBe(200);
    expect(initiated.body["expires_in"]).toBe(120);
    expect(initiated.body["interval"]).toBe(5);
    const id = authReqId(initiated.body);

    // Nobody has decided: the first poll is pending, never an error.
    const pending = await client.pollOnce(id);
    expect(pending.status).toBe(400);
    expect(pending.body["error"]).toBe("authorization_pending");

    // The user follows the link, sees what the CLIENT said, and approves.
    const requestId = await requestIdFor(api, client.client.clientId, started);
    await page.goto(approvalPath(requestId));
    await expect(page.getByRole("heading", { name: "Approve a sign-in" })).toBeVisible();
    await expect(page.getByTestId("binding-message")).toHaveText("Confirm e2e 42 EUR");
    await page.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(page.getByText("Sign-in approved")).toBeVisible();

    // The client polls as §33.7 says and gets the tokens.
    const tokens = await client.pollUntilDecided(id, Date.now() + 60_000);
    expect(tokens.status).toBe(200);
    expect(tokens.body["token_type"]).toBe("Bearer");
    expect(typeof tokens.body["access_token"]).toBe("string");
    expect(typeof tokens.body["refresh_token"]).toBe("string");

    // Tokens carry the approval's evidence (D-67).
    const idToken = claimsOf(tokens.body["id_token"]);
    expect(idToken["aud"]).toBe(client.client.clientId);
    expect(idToken["sub"]).toBe(userId);
    expect(typeof idToken["acr"]).toBe("string");
    expect(idToken["amr"]).toContain("pwd");
    expect(typeof idToken["auth_time"]).toBe("number");
    expect(typeof claimsOf(tokens.body["access_token"])["sid"]).toBe("string");

    // Already redeemed: the same request is refused, never served twice.
    await client.waitOutInterval();
    const again = await client.pollOnce(id);
    expect(again.status).toBe(400);
    expect(again.body["error"]).toBe("invalid_grant");
  });

  test("the user refuses and the client is told access_denied", async ({ page }) => {
    test.setTimeout(120_000);
    const client = await newClient("deny");
    const started = Date.now();
    const initiated = await client.bcAuthorize({
      scope: "openid",
      login_hint: USERNAME,
      binding_message: "Confirm e2e refusal",
    });
    expect(initiated.status).toBe(200);
    const id = authReqId(initiated.body);

    const requestId = await requestIdFor(api, client.client.clientId, started);
    await page.goto(approvalPath(requestId));
    await page.getByRole("button", { name: "Deny", exact: true }).click();
    await expect(page.getByText("Sign-in refused")).toBeVisible();

    const answer = await client.pollUntilDecided(id, Date.now() + 60_000);
    expect(answer.status).toBe(400);
    expect(answer.body["error"]).toBe("access_denied");
    expect(answer.body["access_token"]).toBeUndefined();

    // A decided request cannot be decided again: the link is now a "not found".
    await page.goto(approvalPath(requestId));
    await expect(page.getByText("Request not found")).toBeVisible();
  });

  test("a request that nobody answers expires, and its link is no longer found", async ({
    page,
  }) => {
    test.setTimeout(120_000);
    const client = await newClient("expiry");
    const started = Date.now();
    const initiated = await client.bcAuthorize({
      scope: "openid",
      login_hint: USERNAME,
      requested_expiry: "30",
    });
    expect(initiated.status).toBe(200);
    expect(initiated.body["expires_in"]).toBe(30);
    const id = authReqId(initiated.body);
    const requestId = await requestIdFor(api, client.client.clientId, started);

    const pending = await client.pollOnce(id);
    expect(pending.body["error"]).toBe("authorization_pending");

    // Wait out the request's lifetime, then the interval.
    const lifetimeEnds = started + 30_000 + 3_000;
    const wait = lifetimeEnds - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    await client.waitOutInterval();
    const late = await client.pollOnce(id);
    expect(late.status).toBe(400);
    expect(late.body["error"]).toBe("expired_token");

    // Nobody can approve it after the fact either.
    await page.goto(approvalPath(requestId));
    await expect(page.getByText("Request not found")).toBeVisible();
    await expect(page.getByRole("button", { name: "Approve", exact: true })).toHaveCount(0);
  });

  test("polling inside the interval is slow_down, and the interval grows", async () => {
    test.setTimeout(60_000);
    const client = await newClient("slowdown");
    const initiated = await client.bcAuthorize({
      scope: "openid",
      login_hint: USERNAME,
    });
    expect(initiated.status).toBe(200);
    const id = authReqId(initiated.body);

    const first = await client.pollOnce(id);
    expect(first.body["error"]).toBe("authorization_pending");
    const early = await client.pollOnce(id);
    expect(early.status).toBe(400);
    expect(early.body["error"]).toBe("slow_down");

    // Six seconds is longer than the original five-second interval but shorter
    // than the grown ten: the server must still say slow_down.
    await new Promise((r) => setTimeout(r, 6_000));
    const stillEarly = await client.pollOnce(id);
    expect(stillEarly.body["error"]).toBe("slow_down");
  });

  test("a request for nobody looks like any other and cannot be opened by anyone", async ({
    page,
  }) => {
    const real = await newClient("decoy-real");
    const ghost = await newClient("decoy");
    const realAnswer = await real.bcAuthorize({ scope: "openid", login_hint: USERNAME });
    const started = Date.now();
    const ghostAnswer = await ghost.bcAuthorize({
      scope: "openid",
      login_hint: `nobody-${Date.now()}`,
    });

    // The same shape and the same status: no `unknown_user_id`, no oracle.
    expect(ghostAnswer.status).toBe(realAnswer.status);
    expect(Object.keys(ghostAnswer.body).sort()).toEqual(
      Object.keys(realAnswer.body).sort(),
    );
    expect(ghostAnswer.body["expires_in"]).toBe(realAnswer.body["expires_in"]);

    // It is polled like a real one, and stays pending until it expires.
    const poll = await ghost.pollOnce(authReqId(ghostAnswer.body));
    expect(poll.body["error"]).toBe("authorization_pending");

    // And nobody, the administrator included, can open it.
    const requestId = await requestIdFor(api, ghost.client.clientId, started);
    await page.goto(approvalPath(requestId));
    await expect(page.getByText("Request not found")).toBeVisible();
  });

  test("a request for a multi-factor sign-in cannot be approved by a password session", async ({
    page,
  }) => {
    const client = await newClient("stepup");
    const started = Date.now();
    const initiated = await client.bcAuthorize({
      scope: "openid",
      login_hint: USERNAME,
      acr_values: "urn:axiam:acr:mfa",
      binding_message: "Confirm e2e step-up",
    });
    expect(initiated.status).toBe(200);
    const id = authReqId(initiated.body);
    const requestId = await requestIdFor(api, client.client.clientId, started);

    await page.goto(approvalPath(requestId));
    await expect(page.getByText(/needs a stronger sign-in/)).toBeVisible();
    await expect(page.getByRole("button", { name: "Sign in again" })).toBeVisible();
    // The way to approve is hidden until the session is stronger.
    await expect(page.getByRole("button", { name: "Approve", exact: true })).toHaveCount(0);

    // Nothing was decided.
    const poll = await client.pollOnce(id);
    expect(poll.body["error"]).toBe("authorization_pending");
  });

  test("parameters the server does not implement are refused as invalid_request", async () => {
    const client = await newClient("refusals");
    const unsupported: Record<string, string>[] = [
      { request_uri: "https://client.example/request" },
      { login_hint_token: "opaque-hint" },
      { user_code: "1234" },
    ];
    for (const extra of unsupported) {
      const answer = await client.bcAuthorize({
        scope: "openid",
        login_hint: USERNAME,
        ...extra,
      });
      expect(answer.status, `refused with ${Object.keys(extra)[0]}`).toBe(400);
      expect(answer.body["error"]).toBe("invalid_request");
    }
  });

  // MUST STAY LAST: it spends the rest of the endpoint's budget for the minute.
  test("the limiter counts bc-authorize, failed client authentications included", async () => {
    const client = await newClient("limiter");
    const statuses: number[] = [];
    let limited: { status: number; body: Record<string, unknown> } | null = null;
    for (let attempt = 0; attempt < 60 && !limited; attempt++) {
      const answer = await client.bcAuthorizeWithWrongCredential({
        scope: "openid",
        login_hint: USERNAME,
      });
      statuses.push(answer.status);
      if (answer.status === 429) limited = answer;
    }
    // A wrong credential is `invalid_client` (401) every time until the budget
    // is gone, and then it is the limiter that answers: the attempts counted.
    expect(limited, "the budget must run out within 60 attempts").not.toBeNull();
    expect(statuses.slice(0, -1).every((s) => s === 401)).toBe(true);
    expect(limited?.body["error"]).toBe("rate_limit_exceeded");

    // The budget is the endpoint's, not the credential's: a well-formed request
    // from the real client is refused too, until the window rolls.
    const valid = await client.bcAuthorize({ scope: "openid", login_hint: USERNAME });
    expect(valid.status).toBe(429);
  });
});
