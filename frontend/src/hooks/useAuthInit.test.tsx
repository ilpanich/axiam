import { describe, it, expect, beforeEach, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));
vi.mock("@/lib/fetchCurrentUser", () => ({ fetchCurrentUser: vi.fn() }));

import { useAuthInit } from "./useAuthInit";
import { fetchCurrentUser } from "@/lib/fetchCurrentUser";
import { useAuthStore, type AuthUser } from "@/stores/auth";

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
});
