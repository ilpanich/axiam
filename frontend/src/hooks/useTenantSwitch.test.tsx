import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { getActiveTenant, setActiveTenant } from "@/lib/activeTenant";
import { tenantScopedQueryKeyHash } from "@/lib/queryClient";
import { useAuthStore, type AuthUser } from "@/stores/auth";
import { useTenantSwitch } from "@/hooks/useTenantSwitch";

const { fetchCurrentUserMock } = vi.hoisted(() => ({
  fetchCurrentUserMock: vi.fn(),
}));

vi.mock("@/lib/fetchCurrentUser", () => ({
  fetchCurrentUser: fetchCurrentUserMock,
}));

const orgPrincipal: AuthUser = {
  id: "u1",
  username: "orgadmin",
  email: "orgadmin@x.io",
  permissions: ["organizations:list", "tenants:list"],
  tenant_id: "org-tenant",
  principal_tenant_id: "org-tenant",
  organization_level: true,
};

function makeHarness() {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, queryKeyHashFn: tenantScopedQueryKeyHash },
    },
  });
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  }
  const { result } = renderHook(() => useTenantSwitch(), { wrapper: Wrapper });
  return { client, result };
}

beforeEach(() => {
  vi.clearAllMocks();
  setActiveTenant(null);
  useAuthStore.setState({
    user: orgPrincipal,
    isAuthenticated: true,
    isInitializing: false,
    activeTenantId: null,
    activeTenantName: null,
    isSwitchingTenant: false,
  });
  fetchCurrentUserMock.mockResolvedValue(orgPrincipal);
});

afterEach(() => setActiveTenant(null));

describe("useTenantSwitch", () => {
  it("points subsequent requests at the selected tenant", async () => {
    const { result } = makeHarness();
    await result.current("t2", "Research & Development");

    expect(getActiveTenant()).toBe("t2");
    expect(useAuthStore.getState().activeTenantId).toBe("t2");
    expect(useAuthStore.getState().activeTenantName).toBe(
      "Research & Development"
    );
  });

  it("re-reads the caller in the scope it switched into", async () => {
    // The permission array `/auth/me` returns is computed for the tenant being
    // acted on. Keeping the copy taken at login meant the UI offered controls
    // the server would refuse and hid ones it would allow.
    const inTenant: AuthUser = {
      ...orgPrincipal,
      permissions: ["users:list"],
      tenantSlug: "rd",
    };
    fetchCurrentUserMock.mockResolvedValue(inTenant);

    const { result } = makeHarness();
    await result.current("t2", "R&D");

    expect(fetchCurrentUserMock).toHaveBeenCalledTimes(1);
    expect(useAuthStore.getState().user?.permissions).toEqual(["users:list"]);
  });

  it("leaves no cached row from the tenant it left", async () => {
    // The regression: `queryClient.clear()` removes a query from the cache but
    // does NOT detach a mounted observer, which goes on rendering the data it
    // already had. Whatever this hook does, nothing from the previous tenant
    // may still be readable afterwards.
    const { client, result } = makeHarness();
    client.setQueryData(["users", 1], [{ id: "a", username: "in-org" }]);
    expect(client.getQueryData(["users", 1])).toHaveLength(1);

    await result.current("t2", "R&D");

    expect(client.getQueryData(["users", 1])).toBeUndefined();
    expect(client.getQueryCache().getAll()).toHaveLength(0);
  });

  it("holds the switching flag up for the whole switch and lowers it after", async () => {
    let seenDuringFetch: boolean | undefined;
    fetchCurrentUserMock.mockImplementation(async () => {
      seenDuringFetch = useAuthStore.getState().isSwitchingTenant;
      return orgPrincipal;
    });

    const { result } = makeHarness();
    await result.current("t2", "R&D");

    // Up while `/auth/me` is in flight: pages rendered in that window would
    // gate on the previous tenant's permissions.
    expect(seenDuringFetch).toBe(true);
    await waitFor(() =>
      expect(useAuthStore.getState().isSwitchingTenant).toBe(false)
    );
  });

  it("lowers the flag even when the re-read fails", async () => {
    // A failed background refresh must not strand the app on a spinner. The
    // selection still stands; every request is authorized server-side anyway.
    fetchCurrentUserMock.mockRejectedValue(new Error("network"));

    const { result } = makeHarness();
    await expect(result.current("t2", "R&D")).rejects.toThrow("network");

    expect(useAuthStore.getState().isSwitchingTenant).toBe(false);
    expect(getActiveTenant()).toBe("t2");
  });

  it("keeps the previous snapshot when the re-read returns nothing", async () => {
    fetchCurrentUserMock.mockResolvedValue(null);

    const { result } = makeHarness();
    await result.current("t2", "R&D");

    expect(useAuthStore.getState().user).toEqual(orgPrincipal);
    expect(useAuthStore.getState().isSwitchingTenant).toBe(false);
  });

  it("switches back to the organization scope with a null tenant", async () => {
    setActiveTenant("t2", "R&D");
    useAuthStore.setState({ activeTenantId: "t2", activeTenantName: "R&D" });

    const { result } = makeHarness();
    await result.current(null, null);

    expect(getActiveTenant()).toBeNull();
    expect(useAuthStore.getState().activeTenantId).toBeNull();
  });
});
