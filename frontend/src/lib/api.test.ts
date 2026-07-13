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

beforeEach(() => {
  document.cookie = "axiam_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
  useAuthStore.setState({ isAuthenticated: false });
  vi.restoreAllMocks();
});

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
    useAuthStore.setState({ isAuthenticated: true });
    const err = { config: cfg({ url: "/api/v1/auth/login" }), response: { status: 401 } };
    await expect(resHandler.rejected(err)).rejects.toBe(err);
  });

  it("does not refresh a request already marked _retry", async () => {
    useAuthStore.setState({ isAuthenticated: true });
    const config = { ...cfg({ url: "/api/v1/users" }), _retry: true };
    const err = { config, response: { status: 401 } };
    await expect(resHandler.rejected(err)).rejects.toBe(err);
  });
});

describe("response interceptor — silent refresh path", () => {
  afterEach(() => {
    useAuthStore.setState({ isAuthenticated: false });
  });

  it("on 401 while authenticated: refreshes then replays the original request", async () => {
    useAuthStore.setState({ isAuthenticated: true });
    const postSpy = vi.spyOn(api, "post").mockResolvedValue({ data: {} } as AxiosResponse);
    // A custom adapter lets api(originalRequest) resolve without real network.
    const replay = { data: "replayed", status: 200 };
    const originalRequest = cfg({
      url: "/api/v1/users",
      adapter: () => Promise.resolve(replay as unknown as AxiosResponse),
    });
    const err = { config: originalRequest, response: { status: 401 } };
    const result = (await resHandler.rejected(err)) as AxiosResponse;
    expect(postSpy).toHaveBeenCalledWith("/api/v1/auth/refresh", {});
    expect(result.data).toBe("replayed");
  });

  it("queues concurrent 401s behind a single in-flight refresh, then replays both", async () => {
    useAuthStore.setState({ isAuthenticated: true });
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
    useAuthStore.setState({ isAuthenticated: true });
    const refreshErr = new Error("refresh failed");
    vi.spyOn(api, "post").mockRejectedValue(refreshErr);
    const clearSpy = vi.spyOn(queryClient, "clear").mockImplementation(() => {});
    const clearAuthSpy = vi.spyOn(useAuthStore.getState(), "clearAuth");
    const hrefSetter = vi.fn();
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { set href(v: string) { hrefSetter(v); } },
    });

    const err = { config: cfg({ url: "/api/v1/users" }), response: { status: 401 } };
    await expect(resHandler.rejected(err)).rejects.toBe(refreshErr);
    expect(clearSpy).toHaveBeenCalled();
    expect(clearAuthSpy).toHaveBeenCalled();
    expect(hrefSetter).toHaveBeenCalledWith("/login");
  });
});
