import { describe, it, expect, beforeEach } from "vitest";
import { useAuthStore, type AuthUser } from "./auth";

const user: AuthUser = {
  id: "u1",
  username: "alice",
  email: "a@x.io",
  permissions: ["users:read"],
  tenant_id: "t1",
};

describe("useAuthStore", () => {
  beforeEach(() => {
    // Reset to a known clean state between tests.
    useAuthStore.setState({
      user: null,
      tenantSlug: null,
      orgSlug: null,
      isAuthenticated: false,
      isInitializing: true,
    });
  });

  it("starts unauthenticated and initializing", () => {
    const s = useAuthStore.getState();
    expect(s.isAuthenticated).toBe(false);
    expect(s.isInitializing).toBe(true);
    expect(s.user).toBeNull();
  });

  it("setUser authenticates and stops initializing", () => {
    useAuthStore.getState().setUser(user);
    const s = useAuthStore.getState();
    expect(s.user).toEqual(user);
    expect(s.isAuthenticated).toBe(true);
    expect(s.isInitializing).toBe(false);
  });

  it("setTenantContext stores slugs without touching auth", () => {
    useAuthStore.getState().setUser(user);
    useAuthStore.getState().setTenantContext("ten", "org");
    const s = useAuthStore.getState();
    expect(s.tenantSlug).toBe("ten");
    expect(s.orgSlug).toBe("org");
    expect(s.isAuthenticated).toBe(true);
  });

  it("clearAuth resets to unauthenticated but ends initialization", () => {
    useAuthStore.getState().setUser(user);
    useAuthStore.getState().setTenantContext("ten", "org");
    useAuthStore.getState().clearAuth();
    const s = useAuthStore.getState();
    expect(s.user).toBeNull();
    expect(s.isAuthenticated).toBe(false);
    expect(s.tenantSlug).toBeNull();
    expect(s.orgSlug).toBeNull();
    expect(s.isInitializing).toBe(false);
  });

  it("setInitializing toggles the boot flag", () => {
    useAuthStore.getState().setInitializing(false);
    expect(useAuthStore.getState().isInitializing).toBe(false);
    useAuthStore.getState().setInitializing(true);
    expect(useAuthStore.getState().isInitializing).toBe(true);
  });
});
