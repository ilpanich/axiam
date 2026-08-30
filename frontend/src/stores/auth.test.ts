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
      isSwitchingTenant: false,
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

  it("setSwitchingTenant toggles the tenant-switch flag", () => {
    expect(useAuthStore.getState().isSwitchingTenant).toBe(false);
    useAuthStore.getState().setSwitchingTenant(true);
    expect(useAuthStore.getState().isSwitchingTenant).toBe(true);
    useAuthStore.getState().setSwitchingTenant(false);
    expect(useAuthStore.getState().isSwitchingTenant).toBe(false);
  });

  it("clearAuth lowers the tenant-switch flag", () => {
    // A sign-out mid-switch would otherwise leave the flag raised, and the
    // layout renders a spinner in place of the page while it is — so the next
    // sign-in would land on "Switching tenant…" and stay there.
    useAuthStore.getState().setUser(user);
    useAuthStore.getState().setSwitchingTenant(true);
    useAuthStore.getState().clearAuth();
    expect(useAuthStore.getState().isSwitchingTenant).toBe(false);
  });
});
