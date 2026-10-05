import {
  APIRequestContext,
  request as playwrightRequest,
} from "@playwright/test";
import { randomBytes } from "node:crypto";
import { Api, items } from "./api";
import { STORAGE_STATE } from "./auth";

/**
 * Helpers for the CIBA end-to-end suite (`ciba.spec.ts`, G-7 / T23.7.3).
 *
 * Two roles are played from one test process, and keeping them apart is the
 * point of this file:
 *
 *  - the **administrator** (the shared tenant-admin session) registers CIBA
 *    clients through `POST /api/v1/oauth2-clients`, and reads the audit log;
 *  - the **client** (a registered confidential client) talks to
 *    `/oauth2/bc-authorize` and `/oauth2/token` with its own credential, and
 *    nothing else. It never holds a session.
 *
 * The *user* is the browser: it opens the approval page and decides, exactly as
 * the person following the mail link would.
 *
 * Nothing here logs a client credential, an `auth_req_id` or a token, and no
 * assertion message formats one.
 */

export const CIBA_GRANT = "urn:openid:params:grant-type:ciba";

/** The signed-in tenant administrator's API client, from the shared session. */
export async function adminApi(): Promise<Api> {
  return Api.fromStorageState(STORAGE_STATE);
}

/** The administrator's tenant and user ids, from `GET /api/v1/auth/me`. */
export async function whoAmI(
  api: Api,
): Promise<{ tenantId: string; userId: string }> {
  const me = await api.get<{ user?: { id?: string; tenant_id?: string } }>(
    "/api/v1/auth/me",
  );
  const tenantId = me.body?.user?.tenant_id;
  const userId = me.body?.user?.id;
  if (me.status !== 200 || !tenantId || !userId) {
    throw new Error(`GET /api/v1/auth/me answered ${me.status} without a user`);
  }
  return { tenantId, userId };
}

/** A registered CIBA client: its identifier and the one-time credential. */
export interface RegisteredClient {
  id: string;
  clientId: string;
  credential: string;
}

/**
 * Registers a confidential CIBA client (`client_secret_basic`, poll mode unless
 * `extra` says otherwise). A fresh client per test keeps each test's requests
 * apart in the audit log, which is how the approval link is found.
 */
export async function registerCibaClient(
  api: Api,
  name: string,
  extra: Record<string, unknown> = {},
): Promise<RegisteredClient> {
  const res = await api.post<{
    id?: string;
    client_id?: string;
    client_secret?: string;
  }>("/api/v1/oauth2-clients", {
    name,
    redirect_uris: [],
    grant_types: [CIBA_GRANT, "refresh_token"],
    scopes: ["openid", "profile"],
    token_endpoint_auth_method: "client_secret_basic",
    backchannel_token_delivery_mode: "poll",
    ...extra,
  });
  const body = res.body;
  if (
    res.status !== 201 ||
    !body?.id ||
    !body.client_id ||
    !body.client_secret
  ) {
    throw new Error(
      `registering a CIBA client answered ${res.status}: ${JSON.stringify(
        stripCredential(body),
      )}`,
    );
  }
  return { id: body.id, clientId: body.client_id, credential: body.client_secret };
}

function stripCredential(body: unknown): unknown {
  if (body && typeof body === "object") {
    const { client_secret: _omitted, ...rest } = body as Record<string, unknown>;
    return rest;
  }
  return body;
}

/** What the CIBA endpoints answered, parsed. */
export interface Answer {
  status: number;
  body: Record<string, unknown>;
}

function basicHeader(clientId: string, credential: string): string {
  // RFC 6749 §2.3.1: both halves are form-urlencoded before they are joined.
  const joined = `${encodeURIComponent(clientId)}:${encodeURIComponent(credential)}`;
  return `Basic ${Buffer.from(joined, "utf8").toString("base64")}`;
}

/**
 * One CIBA client's calls: `bc-authorize`, the token endpoint with the CIBA
 * grant, and a polling loop that obeys `interval` and `slow_down` the way
 * contract §33.7 says a client must.
 */
export class CibaClientCalls {
  /** Seconds the client must leave between polls (§33.7 rules 2 and 3). */
  intervalSecs = 5;
  private lastPollAt = 0;

  private constructor(
    private readonly ctx: APIRequestContext,
    private readonly tenantId: string,
    readonly client: RegisteredClient,
  ) {}

  static async open(
    tenantId: string,
    client: RegisteredClient,
  ): Promise<CibaClientCalls> {
    const base = process.env["E2E_BASE_URL"] ?? "http://localhost:5173";
    const ctx = await playwrightRequest.newContext({
      baseURL: base,
      ignoreHTTPSErrors: true,
    });
    return new CibaClientCalls(ctx, tenantId, client);
  }

  async dispose(): Promise<void> {
    await this.ctx.dispose();
  }

  private async form(
    path: string,
    fields: Record<string, string>,
    credential: string = this.client.credential,
  ): Promise<Answer> {
    const res = await this.ctx.post(`${path}?tenant_id=${this.tenantId}`, {
      headers: {
        Authorization: basicHeader(this.client.clientId, credential),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: new URLSearchParams(fields).toString(),
    });
    let body: Record<string, unknown> = {};
    try {
      body = (await res.json()) as Record<string, unknown>;
    } catch {
      // A non-JSON body (a proxy's error page) is reported by its status.
    }
    return { status: res.status(), body };
  }

  /** `POST /oauth2/bc-authorize`, with the client's own credential. */
  bcAuthorize(params: Record<string, string>): Promise<Answer> {
    return this.form("/oauth2/bc-authorize", params);
  }

  /**
   * `POST /oauth2/bc-authorize` with a credential that is **wrong**: the
   * attempt the Keycloak 26.7.x class forgot to count.
   */
  bcAuthorizeWithWrongCredential(params: Record<string, string>): Promise<Answer> {
    // Random at run time and unrelated to the real credential.
    const wrong = randomBytes(24).toString("hex");
    return this.form("/oauth2/bc-authorize", params, wrong);
  }

  /** One token request with the CIBA grant, recording when it was made. */
  async pollOnce(authReqId: string): Promise<Answer> {
    this.lastPollAt = Date.now();
    return this.form("/oauth2/token", {
      grant_type: CIBA_GRANT,
      auth_req_id: authReqId,
    });
  }

  /** Waits until the current interval has elapsed since the last poll. */
  async waitOutInterval(marginMs = 600): Promise<void> {
    const due = this.lastPollAt + this.intervalSecs * 1000 + marginMs;
    const wait = due - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  }

  /**
   * Polls as a conforming client does: wait out the interval, ask, add five
   * seconds permanently on `slow_down`, keep going on `authorization_pending`,
   * and stop at anything else or at the deadline. Returns the first answer that
   * is neither of the two non-terminal ones.
   */
  async pollUntilDecided(authReqId: string, deadlineMs: number): Promise<Answer> {
    for (;;) {
      await this.waitOutInterval();
      if (Date.now() > deadlineMs) {
        throw new Error("the request was not decided before the test's deadline");
      }
      const answer = await this.pollOnce(authReqId);
      const code = answer.body["error"];
      if (answer.status === 400 && code === "slow_down") {
        this.intervalSecs += 5;
        continue;
      }
      if (answer.status === 400 && code === "authorization_pending") continue;
      return answer;
    }
  }
}

/**
 * The record id of the request a client's `bc-authorize` stored, which is what
 * the e-mailed approval link carries.
 *
 * The e2e stack has no mailbox, so the link cannot be read from a message. The
 * administrator can read it where an operator would look: every stored request
 * is audited as `oauth2.ciba_initiated` with the request's record id as the
 * row's resource and the client's id in its metadata. (The row is written
 * detached from the `bc-authorize` response, so it is waited for.)
 */
export async function requestIdFor(
  api: Api,
  clientId: string,
  sinceMs: number,
): Promise<string> {
  const from = new Date(sinceMs - 60_000).toISOString();
  const deadline = Date.now() + 20_000;
  for (;;) {
    const res = await api.get<unknown>(
      `/api/v1/audit-logs?action=oauth2.ciba_initiated&limit=100&from=${encodeURIComponent(from)}`,
    );
    const rows = items<{
      resource_id?: string | null;
      metadata?: { client_id?: string };
    }>(res.body);
    const row = rows.find((r) => r.metadata?.client_id === clientId);
    if (row?.resource_id) return row.resource_id;
    if (Date.now() > deadline) {
      throw new Error(
        `no oauth2.ciba_initiated audit row for the client after 20 s (status ${res.status})`,
      );
    }
    await new Promise((r) => setTimeout(r, 500));
  }
}

/** The approval page's path, as the mail link carries it. */
export function approvalPath(requestId: string): string {
  return `/ciba/approve?request_id=${requestId}`;
}

/** The claims of a JWT's payload, without verifying anything. */
export function claimsOf(jwt: unknown): Record<string, unknown> {
  if (typeof jwt !== "string") throw new Error("expected a compact JWT string");
  const part = jwt.split(".")[1];
  if (!part) throw new Error("not a compact JWT");
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<
    string,
    unknown
  >;
}
