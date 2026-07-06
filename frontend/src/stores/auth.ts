import { create } from "zustand";

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
}

interface AuthState {
  user: AuthUser | null;
  tenantSlug: string | null;
  orgSlug: string | null;
  isAuthenticated: boolean;
  isInitializing: boolean;
}

interface AuthActions {
  setUser: (user: AuthUser) => void;
  clearAuth: () => void;
  setTenantContext: (tenantSlug: string, orgSlug: string) => void;
  setInitializing: (value: boolean) => void;
}

const initialState: AuthState = {
  user: null,
  tenantSlug: null,
  orgSlug: null,
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

  clearAuth: () => set({ ...initialState, isInitializing: false }),

  setTenantContext: (tenantSlug, orgSlug) => set({ tenantSlug, orgSlug }),

  setInitializing: (value) => set({ isInitializing: value }),
}));
