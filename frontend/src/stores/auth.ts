import { create } from "zustand";

import { setActiveTenant } from "@/lib/activeTenant";

export interface AuthUser {
  id: string;
  username: string;
  email: string;
  permissions: string[];
  /**
   * Raw tenant_id UUID from the backend (LoginUserInfo.tenant_id, 23-06).
   * Required by unauthenticated-but-tenant-scoped calls like
   * `resendVerification` (ResendVerificationRequest.tenant_id: Uuid).
   */
  tenant_id: string;
  /** Restored from /auth/me for slug-based tenant context (CQ-F29). */
  tenantSlug?: string;
  orgSlug?: string;
  /**
   * The caller's own tenant's effective OPAQUE policy, from /auth/me.
   *
   * Carried here because setting a password requires building a registration
   * record client-side, and the client needs to know whether to do that at all.
   * Absent means the tenant does not use OPAQUE (or settings could not be
   * resolved), in which case password-set requests simply omit the field.
   */
  opaque?: { opaque_mode: string; opaque_suite: string; opaque_ksf: string };
  /**
   * Whether this principal lives in the organization's own reserved tenant.
   *
   * An organization-level principal's global grants apply to every tenant in
   * the organization, so it can switch the tenant it acts on with a header on
   * the next request. An ordinary tenant principal cannot switch at all — it is
   * not a principal of any other tenant — and the selector has to say so rather
   * than offer a switch the server would refuse.
   */
  organization_level?: boolean;
}

interface AuthState {
  user: AuthUser | null;
  tenantSlug: string | null;
  orgSlug: string | null;
  /**
   * The tenant an organization-level principal is currently acting on, or
   * `null` for its own (the organization scope).
   *
   * Mirrored into the API client, which sends it as `X-Axiam-Tenant`. Kept here
   * as well so the UI can show which tenant is selected without reaching into
   * the request layer.
   */
  activeTenantId: string | null;
  activeTenantName: string | null;
  isAuthenticated: boolean;
  isInitializing: boolean;
}

interface AuthActions {
  setUser: (user: AuthUser) => void;
  clearAuth: () => void;
  setTenantContext: (tenantSlug: string, orgSlug: string) => void;
  setInitializing: (value: boolean) => void;
  /**
   * Act on `tenantId` from the next request onwards, or on the caller's own
   * tenant when `null`.
   *
   * Only meaningful for an organization-level principal; the server refuses the
   * header for anyone else, and refuses a tenant outside the caller's own
   * organization. Callers should clear cached query data after switching —
   * every list in the app is tenant-scoped, and showing one tenant's rows under
   * another tenant's name is worse than a blank page.
   */
  selectTenant: (tenantId: string | null, tenantName?: string | null) => void;
}

const initialState: AuthState = {
  user: null,
  tenantSlug: null,
  orgSlug: null,
  activeTenantId: null,
  activeTenantName: null,
  isAuthenticated: false,
  isInitializing: true,
};

export const useAuthStore = create<AuthState & AuthActions>()((set) => ({
  ...initialState,

  setUser: (user) =>
    set({
      user,
      isAuthenticated: true,
      isInitializing: false,
    }),

  clearAuth: () => {
    // Clear the header too. A stale active tenant surviving a logout would be
    // sent on the *next* principal's requests, which is the sort of leftover
    // that only shows up when two people share a browser.
    setActiveTenant(null);
    set({ ...initialState, isInitializing: false });
  },

  setTenantContext: (tenantSlug, orgSlug) => set({ tenantSlug, orgSlug }),

  setInitializing: (value) => set({ isInitializing: value }),

  selectTenant: (tenantId, tenantName = null) => {
    setActiveTenant(tenantId);
    set({ activeTenantId: tenantId, activeTenantName: tenantName });
  },
}));
