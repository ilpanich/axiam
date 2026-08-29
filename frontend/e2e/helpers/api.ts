import {
  APIRequestContext,
  APIResponse,
  request as playwrightRequest,
} from "@playwright/test";

/**
 * A thin REST client for the AXIAM API, used by the matrix fixture and by the
 * specs that need to assert what the *server* answers rather than what the UI
 * renders.
 *
 * Two things it exists to get right, both of which are easy to get wrong by
 * hand:
 *
 * 1. **CSRF.** The backend issues an `X-CSRF-Token` on the login response and
 *    requires it back on every mutating request (double-submit against the
 *    httpOnly session cookie). Playwright's request context carries the cookie
 *    automatically but knows nothing about the header, so it is captured at
 *    sign-in and replayed here.
 * 2. **Acting tenant.** An organization-level principal names the tenant it is
 *    acting on per request, in `X-Axiam-Tenant`. That header is honoured only
 *    for a principal whose own record lives in the organization scope — a
 *    tenant principal sending it is not thereby promoted, which is one of the
 *    isolation properties the matrix asserts.
 *
 * `baseURL` is the API origin. Behind the documented Caddy front door
 * (`https://localhost`) the frontend proxies `/api` to the backend, so the
 * same origin serves both and `E2E_BASE_URL` is the right default.
 */
export interface ApiResult<T = unknown> {
  status: number;
  body: T;
  headers: Record<string, string>;
}

export class Api {
  private csrf: string | null = null;
  private tenantId: string | null = null;

  private constructor(
    private readonly ctx: APIRequestContext,
    readonly baseURL: string,
  ) {}

  /**
   * Opens a request context against `baseURL`. `ignoreHTTPSErrors` because the
   * documented front door is Caddy's local CA, which the Node process has no
   * reason to trust — the browser contexts trust it via Playwright's own
   * `ignoreHTTPSErrors`, and this is the same concession for the API side.
   */
  static async open(baseURL?: string): Promise<Api> {
    const url =
      baseURL ?? process.env["E2E_BASE_URL"] ?? "http://localhost:5173";
    const ctx = await playwrightRequest.newContext({
      baseURL: url,
      ignoreHTTPSErrors: true,
    });
    return new Api(ctx, url);
  }

  async dispose(): Promise<void> {
    await this.ctx.dispose();
  }

  /** The tenant every subsequent request acts on, or `null` for none. */
  actingTenant(tenantId: string | null): this {
    this.tenantId = tenantId;
    return this;
  }

  /** True once {@link login} has captured a CSRF token. */
  get authenticated(): boolean {
    return this.csrf !== null;
  }

  /**
   * Signs in. `tenantSlug` omitted (or null) signs in at ORGANIZATION level —
   * naming no tenant is what selects the organization's own reserved scope,
   * where the principal `POST /admin/bootstrap` creates actually lives.
   */
  async login(
    orgSlug: string,
    usernameOrEmail: string,
    password: string,
    tenantSlug?: string | null,
  ): Promise<ApiResult> {
    const body: Record<string, string> = {
      org_slug: orgSlug,
      username_or_email: usernameOrEmail,
      password,
    };
    if (tenantSlug) body["tenant_slug"] = tenantSlug;

    const res = await this.ctx.post("/api/v1/auth/login", { data: body });
    const headers = res.headers();
    // Header name is compared lowercase: Node lowercases response header keys,
    // but relying on that silently is how this breaks behind a proxy that does
    // not.
    const token = headers["x-csrf-token"];
    if (res.ok() && token) this.csrf = token;
    return {
      status: res.status(),
      body: await safeJson(res),
      headers,
    };
  }

  async logout(): Promise<void> {
    await this.post("/api/v1/auth/logout", {});
    this.csrf = null;
  }

  private extraHeaders(): Record<string, string> {
    const h: Record<string, string> = {};
    if (this.csrf) h["X-CSRF-Token"] = this.csrf;
    if (this.tenantId) h["X-Axiam-Tenant"] = this.tenantId;
    return h;
  }

  async get<T = unknown>(path: string): Promise<ApiResult<T>> {
    return this.send<T>(() => this.ctx.get(path, { headers: this.extraHeaders() }));
  }

  async post<T = unknown>(path: string, data: unknown): Promise<ApiResult<T>> {
    return this.send<T>(() => this.ctx.post(path, { data, headers: this.extraHeaders() }));
  }

  async put<T = unknown>(path: string, data: unknown): Promise<ApiResult<T>> {
    return this.send<T>(() => this.ctx.put(path, { data, headers: this.extraHeaders() }));
  }

  async delete<T = unknown>(path: string): Promise<ApiResult<T>> {
    return this.send<T>(() => this.ctx.delete(path, { headers: this.extraHeaders() }));
  }

  /**
   * Issues a request, waiting out a 429 rather than treating it as a failure.
   *
   * `POST /api/v1/users` shares the `register_per_min` bucket — 5/min per IP in
   * the shipped "internet" posture — which is a deliberate choice, not a defect
   * (see the note above the two `/users` resources in
   * `crates/axiam-api-rest/src/server.rs`). A fixture that builds six users
   * therefore *will* be throttled, and a fixture that reported that as a broken
   * step would put a permanent phantom finding in every wave.
   *
   * The wait honours `Retry-After` when the server sends one and otherwise
   * backs off to the top of the next minute-ish window. Bounded: after
   * {@link RATE_LIMIT_RETRIES} attempts the 429 is returned to the caller, so a
   * genuinely stuck limiter still surfaces instead of hanging the run.
   */
  private async send<T>(
    issue: () => Promise<APIResponse>,
  ): Promise<ApiResult<T>> {
    let res = await issue();
    for (let attempt = 0; attempt < RATE_LIMIT_RETRIES && res.status() === 429; attempt++) {
      const retryAfter = Number(res.headers()["retry-after"]);
      const waitMs = Number.isFinite(retryAfter) && retryAfter > 0
        ? (retryAfter + 1) * 1000
        : 15_000;
      await new Promise((r) => setTimeout(r, waitMs));
      res = await issue();
    }
    return { status: res.status(), body: (await safeJson(res)) as T, headers: res.headers() };
  }
}

/** How many times a 429 is waited out before it is reported to the caller. */
const RATE_LIMIT_RETRIES = 6;

/**
 * List endpoints answer either a bare array or `{ items: [...] }` depending on
 * whether they paginate. Callers should not have to care which.
 */
export function items<T = Record<string, unknown>>(body: unknown): T[] {
  if (Array.isArray(body)) return body as T[];
  if (body && typeof body === "object" && Array.isArray((body as { items?: unknown }).items)) {
    return (body as { items: T[] }).items;
  }
  return [];
}

async function safeJson(res: { json(): Promise<unknown>; text(): Promise<string> }): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    // 204s and error pages are not JSON. Returning the text keeps a failure
    // message readable instead of collapsing it to "undefined".
    try {
      return await res.text();
    } catch {
      return null;
    }
  }
}
