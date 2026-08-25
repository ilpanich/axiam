import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { InternalAxiosRequestConfig, AxiosResponse } from "axios";
import api from "./api";
import { useAuthStore } from "@/stores/auth";
import { queryClient } from "@/lib/queryClient";

// Reach into the axios instance's registered interceptor handlers so we can
// drive them directly without issuing real HTTP requests.
type Handler = {
  fulfilled: (v: unknown) => unknown;
  rejected: (e: unknown) => unknown;
};
const reqHandler = (
  api.interceptors.request as unknown as { handlers: Handler[] }
).handlers[0];
const resHandler = (
  api.interceptors.response as unknown as { handlers: Handler[] }
).handlers[0];

function cfg(
  partial: Partial<InternalAxiosRequestConfig> & { method?: string }
): InternalAxiosRequestConfig {
  return { headers: {}, ...partial } as InternalAxiosRequestConfig;
}

/**
 * A request config whose replay answers 401 — i.e. the session really is dead.
 *
 * After a failed refresh the interceptor replays the original request once
 * before concluding anything, because a refresh can fail for a reason that has
 * nothing to do with the session being over (another tab consumed the
 * single-use token first). Only a replay that is ALSO unauthenticated proves
 * the session is gone, so every test of the logout path has to supply one.
 */
function deadSessionRequest(url = "/api/v1/users"): InternalAxiosRequestConfig {
  return cfg({
    url,
    adapter: () =>
      Promise.reject(
        Object.assign(new Error("unauthorized"), { response: { status: 401 } })
      ),
  });
}

beforeEach(() => {
  document.cookie = "axiam_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
  useAuthStore.setState({ isAuthenticated: false, user: null });
  vi.restoreAllMocks();
});

const TENANT_ID = "01a02475-00a5-7f01-ad53-4051a56222ae";

/**
 * A signed-in store. `user.tenant_id` matters as much as `isAuthenticated`
 * here: the refresh body carries it, and without it the interceptor declines
 * to refresh at all.
 */
function signedIn() {
  useAuthStore.setState({
    isAuthenticated: true,
    user: {
      id: "u1",
      username: "admin",
      email: "admin@axiam.dev",
      permissions: [],
      tenant_id: TENANT_ID,
    },
  });
}

describe("request interceptor — CSRF injection", () => {
  it("injects X-CSRF-Token on POST when the cookie is present", () => {
    document.cookie = "axiam_csrf=tok123";
    const out = reqHandler.fulfilled(cfg({ method: "post" })) as InternalAxiosRequestConfig;
    expect(out.headers["X-CSRF-Token"]).toBe("tok123");
  });

  it("URL-decodes the cookie value", () => {
    document.cookie = "axiam_csrf=a%2Bb";
    const out = reqHandler.fulfilled(cfg({ method: "put" })) as InternalAxiosRequestConfig;
    expect(out.headers["X-CSRF-Token"]).toBe("a+b");
  });

  it("does NOT inject on safe GET requests", () => {
    document.cookie = "axiam_csrf=tok123";
    const out = reqHandler.fulfilled(cfg({ method: "get" })) as InternalAxiosRequestConfig;
    expect(out.headers["X-CSRF-Token"]).toBeUndefined();
  });

  it("defaults to GET (no header) when method is omitted", () => {
    document.cookie = "axiam_csrf=tok123";
    const out = reqHandler.fulfilled(cfg({})) as InternalAxiosRequestConfig;
    expect(out.headers["X-CSRF-Token"]).toBeUndefined();
  });

  it("skips injection when no CSRF cookie is present", () => {
    const out = reqHandler.fulfilled(cfg({ method: "delete" })) as InternalAxiosRequestConfig;
    expect(out.headers["X-CSRF-Token"]).toBeUndefined();
  });

  it("rejected handler propagates the error", async () => {
    const err = new Error("boom");
    await expect(reqHandler.rejected(err)).rejects.toBe(err);
  });
});

describe("response interceptor — success + early rejections", () => {
  it("passes a successful response through unchanged", () => {
    const response = { status: 200, data: {} } as AxiosResponse;
    expect(resHandler.fulfilled(response)).toBe(response);
  });

  it("rejects immediately when there is no config on the error", async () => {
    await expect(resHandler.rejected({ response: { status: 401 } })).rejects.toBeTruthy();
  });

  it("rejects a non-401 error without attempting refresh", async () => {
    const err = { config: cfg({ url: "/api/v1/users" }), response: { status: 500 } };
    await expect(resHandler.rejected(err)).rejects.toBe(err);
  });

  it("does not refresh a 401 while unauthenticated", async () => {
    useAuthStore.setState({ isAuthenticated: false });
    const err = { config: cfg({ url: "/api/v1/users" }), response: { status: 401 } };
    await expect(resHandler.rejected(err)).rejects.toBe(err);
  });

  it("does not refresh a 401 on the login/refresh/logout endpoints", async () => {
    signedIn();
    const err = { config: cfg({ url: "/api/v1/auth/login" }), response: { status: 401 } };
    await expect(resHandler.rejected(err)).rejects.toBe(err);
  });

  it("does not refresh a request already marked _retry", async () => {
    signedIn();
    const config = { ...cfg({ url: "/api/v1/users" }), _retry: true };
    const err = { config, response: { status: 401 } };
    await expect(resHandler.rejected(err)).rejects.toBe(err);
  });

  // A 401 from a WebAuthn assertion means the assertion did not prove who you
  // are — not that a token aged out. Refreshing and replaying it is meaningless,
  // and on /login the failure path's full-page redirect resets the form to its
  // first step, which is what made passkey sign-in bounce.
  it.each([
    "/api/v1/auth/webauthn/authenticate/start",
    "/api/v1/auth/webauthn/authenticate/finish",
  ])("does not refresh a 401 from %s", async (url: string) => {
    signedIn();
    const postSpy = vi.spyOn(api, "post");
    const err = { config: cfg({ url }), response: { status: 401 } };
    await expect(resHandler.rejected(err)).rejects.toBe(err);
    expect(postSpy).not.toHaveBeenCalled();
  });
});

describe("response interceptor — silent refresh path", () => {
  afterEach(() => {
    useAuthStore.setState({ isAuthenticated: false });
  });

  it("on 401 while authenticated: refreshes then replays the original request", async () => {
    signedIn();
    const postSpy = vi.spyOn(api, "post").mockResolvedValue({ data: {} } as AxiosResponse);
    // A custom adapter lets api(originalRequest) resolve without real network.
    const replay = { data: "replayed", status: 200 };
    const originalRequest = cfg({
      url: "/api/v1/users",
      adapter: () => Promise.resolve(replay as unknown as AxiosResponse),
    });
    const err = { config: originalRequest, response: { status: 401 } };
    const result = (await resHandler.rejected(err)) as AxiosResponse;
    // tenant_id is mandatory server-side; org_id is deliberately NOT sent,
    // because `refresh` derives the org from the tenant and ignores the claim.
    expect(postSpy).toHaveBeenCalledWith("/api/v1/auth/refresh", {
      tenant_id: TENANT_ID,
    });
    expect(result.data).toBe("replayed");
  });

  it("does not refresh when the store has no tenant_id to send", async () => {
    // isAuthenticated without a hydrated user: refreshing would post a body the
    // server rejects with `missing field tenant_id`, and the 400 would then be
    // treated as a dead session and log the user out.
    useAuthStore.setState({ isAuthenticated: true, user: null });
    const postSpy = vi.spyOn(api, "post");
    const clearSpy = vi.spyOn(queryClient, "clear").mockImplementation(() => {});
    const err = { config: deadSessionRequest(), response: { status: 401 } };
    await expect(resHandler.rejected(err)).rejects.toBe(err);
    expect(postSpy).not.toHaveBeenCalled();
    expect(clearSpy).toHaveBeenCalled();
  });

  it("queues concurrent 401s behind a single in-flight refresh, then replays both", async () => {
    signedIn();
    // Deferred refresh so a second 401 arrives while the first is still refreshing.
    let resolveRefresh!: () => void;
    const refreshPromise = new Promise<AxiosResponse>((r) => {
      resolveRefresh = () => r({ data: {} } as AxiosResponse);
    });
    vi.spyOn(api, "post").mockReturnValue(refreshPromise as unknown as Promise<AxiosResponse>);

    const makeReq = (tag: string) =>
      cfg({
        url: `/api/v1/thing/${tag}`,
        adapter: () => Promise.resolve({ data: tag, status: 200 } as unknown as AxiosResponse),
      });

    const first = resHandler.rejected({ config: makeReq("a"), response: { status: 401 } }) as Promise<AxiosResponse>;
    // Second 401 while the refresh is still pending — must be queued, not a 2nd refresh.
    const second = resHandler.rejected({ config: makeReq("b"), response: { status: 401 } }) as Promise<AxiosResponse>;

    resolveRefresh();
    const [r1, r2] = await Promise.all([first, second]);
    expect(r1.data).toBe("a");
    expect(r2.data).toBe("b");
    // Exactly one refresh POST despite two 401s.
    expect(api.post).toHaveBeenCalledTimes(1);
  });

  it("on refresh failure: clears cache + auth and redirects to /login", async () => {
    signedIn();
    const refreshErr = new Error("refresh failed");
    vi.spyOn(api, "post").mockRejectedValue(refreshErr);
    const clearSpy = vi.spyOn(queryClient, "clear").mockImplementation(() => {});
    const clearAuthSpy = vi.spyOn(useAuthStore.getState(), "clearAuth");
    const hrefSetter = vi.fn();
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { set href(v: string) { hrefSetter(v); } },
    });

    const err = { config: deadSessionRequest(), response: { status: 401 } };
    await expect(resHandler.rejected(err)).rejects.toBe(refreshErr);
    expect(clearSpy).toHaveBeenCalled();
    expect(clearAuthSpy).toHaveBeenCalled();
    expect(hrefSetter).toHaveBeenCalledWith("/login");
  });

  it("on refresh failure while already on /login: clears auth but does not redirect", async () => {
    // Assigning location.href to the page you are already on triggers a full
    // reload, which re-runs whatever produced the 401 and reloads again.
    signedIn();
    const refreshErr = new Error("refresh failed");
    vi.spyOn(api, "post").mockRejectedValue(refreshErr);
    vi.spyOn(queryClient, "clear").mockImplementation(() => {});
    const clearAuthSpy = vi.spyOn(useAuthStore.getState(), "clearAuth");
    const hrefSetter = vi.fn();
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { pathname: "/login", set href(v: string) { hrefSetter(v); } },
    });

    const err = { config: deadSessionRequest(), response: { status: 401 } };
    await expect(resHandler.rejected(err)).rejects.toBe(refreshErr);
    expect(clearAuthSpy).toHaveBeenCalled();
    expect(hrefSetter).not.toHaveBeenCalled();
  });

  // ── A failed refresh is not proof the session is over ────────────────────
  //
  // The reported symptom was being "randomly disconnected" while working.
  // Refresh tokens are single-use with rotation and `isRefreshing` is module
  // state, so it serializes refreshes within one tab and knows nothing about
  // the others: two tabs both hit a 401 as the access token ages out, both
  // refresh, and the slower one presents a token the faster one consumed. The
  // session is alive and the cookies in this browser have already been rotated
  // — but the old code read that failure as "logged out" and redirected both
  // tabs to /login.

  it("recovers when another tab already rotated the cookies", async () => {
    signedIn();
    vi.spyOn(api, "post").mockRejectedValue(new Error("refresh token already used"));
    // `mockClear` because `restoreAllMocks` cannot reach these.
    // `useAuthStore.setState` builds a NEW state object that copies the
    // function references from the old one, so a spy installed on an earlier
    // test's state object is carried into this one; `restoreAllMocks` then
    // restores the *old* object, and `spyOn` here finds the surviving mock and
    // hands it back with its call history intact. Clearing is what makes
    // "not called" mean "not called during this test".
    const clearAuthSpy = vi.spyOn(useAuthStore.getState(), "clearAuth");
    clearAuthSpy.mockClear();
    const clearSpy = vi.spyOn(queryClient, "clear").mockImplementation(() => {});
    clearSpy.mockClear();
    const hrefSetter = vi.fn();
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { set href(v: string) { hrefSetter(v); } },
    });

    // The replay succeeds: the cookie jar is shared, so this request now
    // carries the access cookie the other tab's refresh installed.
    const originalRequest = cfg({
      url: "/api/v1/users",
      adapter: () =>
        Promise.resolve({ data: "recovered", status: 200 } as unknown as AxiosResponse),
    });

    const result = (await resHandler.rejected({
      config: originalRequest,
      response: { status: 401 },
    })) as AxiosResponse;

    expect(result.data).toBe("recovered");
    expect(clearAuthSpy).not.toHaveBeenCalled();
    expect(clearSpy).not.toHaveBeenCalled();
    expect(hrefSetter).not.toHaveBeenCalled();
  });

  it("does not log out when the replay fails for a reason other than auth", async () => {
    // A 500 or a dropped connection on the replay says nothing about the
    // credentials. Reporting it is right; ending the session over it is not.
    signedIn();
    vi.spyOn(api, "post").mockRejectedValue(new Error("refresh failed"));
    // See the note above on why this needs an explicit clear.
    const clearAuthSpy = vi.spyOn(useAuthStore.getState(), "clearAuth");
    clearAuthSpy.mockClear();
    const serverError = Object.assign(new Error("boom"), {
      response: { status: 500 },
    });

    const originalRequest = cfg({
      url: "/api/v1/users",
      adapter: () => Promise.reject(serverError),
    });

    await expect(
      resHandler.rejected({ config: originalRequest, response: { status: 401 } })
    ).rejects.toBe(serverError);
    expect(clearAuthSpy).not.toHaveBeenCalled();
  });

  it("still logs out when the replay is also unauthenticated", async () => {
    // The complement of the two above: the recovery attempt must not become a
    // way for a genuinely dead session to linger.
    signedIn();
    const refreshErr = new Error("refresh failed");
    vi.spyOn(api, "post").mockRejectedValue(refreshErr);
    vi.spyOn(queryClient, "clear").mockImplementation(() => {});
    const clearAuthSpy = vi.spyOn(useAuthStore.getState(), "clearAuth");
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { set href(_v: string) {} },
    });

    await expect(
      resHandler.rejected({
        config: deadSessionRequest(),
        response: { status: 401 },
      })
    ).rejects.toBe(refreshErr);
    expect(clearAuthSpy).toHaveBeenCalled();
  });
});
