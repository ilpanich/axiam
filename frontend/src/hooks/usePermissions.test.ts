import { describe, it, expect, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import { usePermissions } from "./usePermissions";
import { useAuthStore, type AuthUser } from "@/stores/auth";

const baseUser: AuthUser = {
  id: "u1",
  username: "a",
  email: "a@x.io",
  permissions: ["users:read", "roles:read"],
  tenant_id: "t1",
};

beforeEach(() => {
  useAuthStore.setState({
    user: null,
    isAuthenticated: false,
    isInitializing: false,
  });
});

describe("usePermissions", () => {
  it("returns false for every check when unauthenticated", () => {
    const { result } = renderHook(() => usePermissions());
    expect(result.current.can("users:read")).toBe(false);
    expect(result.current.permissions).toEqual([]);
  });

  it("grants only held permissions", () => {
    useAuthStore.setState({ user: baseUser, isAuthenticated: true });
    const { result } = renderHook(() => usePermissions());
    expect(result.current.can("users:read")).toBe(true);
    expect(result.current.can("users:write")).toBe(false);
  });

  it("wildcard '*' satisfies every check", () => {
    useAuthStore.setState({
      user: { ...baseUser, permissions: ["*"] },
      isAuthenticated: true,
    });
    const { result } = renderHook(() => usePermissions());
    expect(result.current.can("anything:at:all")).toBe(true);
  });

  it("reflects the initializing flag", () => {
    useAuthStore.setState({ isInitializing: true });
    const { result } = renderHook(() => usePermissions());
    expect(result.current.isLoading).toBe(true);
  });
});
