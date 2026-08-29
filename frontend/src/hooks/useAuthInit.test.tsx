import { describe, it, expect, beforeEach, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));
// `withReachableTenantSelected` is left REAL rather than stubbed. It is a
// no-op for every principal these tests describe (none is organization-level),
// so stubbing it would only hide the one case that matters — and the suite
// below asserts that case directly.
vi.mock("@/lib/fetchCurrentUser", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@/lib/fetchCurrentUser")>();
  return { ...actual, fetchCurrentUser: vi.fn() };
});

import { useAuthInit } from "./useAuthInit";
import { fetchCurrentUser } from "@/lib/fetchCurrentUser";
import { useAuthStore, type AuthUser } from "@/stores/auth";
import { getActiveTenant, setActiveTenant } from "@/lib/activeTenant";

const mockFetch = vi.mocked(fetchCurrentUser);

const user: AuthUser = {
  id: "u1",
  username: "a",
  email: "a@x.io",
  permissions: [],
  tenant_id: "t1",
};

beforeEach(() => {
  vi.clearAllMocks();
  // The selection is module state persisted per tab; without this reset one
  // test's chosen tenant is the next one's "already selected", and the
  // auto-selection below correctly declines to override it.
  setActiveTenant(null);
  useAuthStore.setState({
    user: null,
    tenantSlug: null,
    orgSlug: null,
    isAuthenticated: false,
    isInitializing: true,
  });
});

describe("useAuthInit", () => {
  it("hydrates the store when /auth/me returns a user (with slugs)", async () => {
    mockFetch.mockResolvedValue({ ...user, tenantSlug: "ten", orgSlug: "org" });
    renderHook(() => useAuthInit());
    await waitFor(() => expect(useAuthStore.getState().isAuthenticated).toBe(true));
    expect(useAuthStore.getState().tenantSlug).toBe("ten");
    expect(useAuthStore.getState().orgSlug).toBe("org");
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("sets the user but skips tenant context when slugs are missing", async () => {
    mockFetch.mockResolvedValue(user);
    renderHook(() => useAuthInit());
    await waitFor(() => expect(useAuthStore.getState().isAuthenticated).toBe(true));
    expect(useAuthStore.getState().tenantSlug).toBeNull();
  });

  it("attempts a single boot refresh, then re-fetches, on an initial null", async () => {
    mockFetch.mockResolvedValueOnce(null).mockResolvedValueOnce(user);
    apiMock.post.mockResolvedValue(res({}));
    renderHook(() => useAuthInit());
    await waitFor(() => expect(useAuthStore.getState().isAuthenticated).toBe(true));
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/refresh", {});
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("clears auth when refresh fails and the user stays null", async () => {
    mockFetch.mockResolvedValue(null);
    apiMock.post.mockRejectedValue(new Error("no refresh cookie"));
    renderHook(() => useAuthInit());
    await waitFor(() => expect(useAuthStore.getState().isInitializing).toBe(false));
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });

  it("lands a tenant-restricted organization principal in a tenant it reaches", async () => {
    // Such a principal's roles apply only inside the tenants they name, and
    // never in the organization's own scope — so signing in with no tenant
    // selected would show an empty dashboard with every list forbidden.
    //
    // The second resolution is the re-read from inside the selected tenant:
    // `/auth/me` computes the permission array for the tenant being acted on,
    // so keeping the first snapshot would gate the UI on the empty
    // organization-scope set while every request went to the tenant.
    const restricted: AuthUser = {
      ...user,
      organization_level: true,
      reachable_tenant_ids: ["tenant-a"],
    };
    // The boot read, through the mocked module export...
    mockFetch.mockResolvedValue(restricted);
    // ...and the re-read, which `withReachableTenantSelected` performs through
    // the module's OWN `fetchCurrentUser` — a direct call inside the module,
    // which no export-level mock intercepts. Stubbing the HTTP layer is what
    // actually stands in for it, and it exercises the real code path.
    apiMock.get.mockResolvedValue(
      res({
        user: { ...restricted, organization_level: true },
        permissions: ["users:list"],
      }),
    );

    renderHook(() => useAuthInit());

    await waitFor(() =>
      expect(useAuthStore.getState().isAuthenticated).toBe(true),
    );
    expect(getActiveTenant()).toBe("tenant-a");
    expect(useAuthStore.getState().user?.permissions).toEqual(["users:list"]);
  });

  it("leaves an unrestricted organization principal in the organization scope", async () => {
    // The organization scope is a real place for this one: its roles apply
    // there and everywhere else in the organization, so moving it would be an
    // unexplained jump into an arbitrary tenant.
    mockFetch.mockResolvedValue({ ...user, organization_level: true });

    renderHook(() => useAuthInit());

    await waitFor(() =>
      expect(useAuthStore.getState().isAuthenticated).toBe(true),
    );
    expect(getActiveTenant()).toBeNull();
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});
