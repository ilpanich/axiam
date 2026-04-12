import { create } from "zustand";

export interface AuthUser {
  id: string;
  username: string;
  email: string;
  permissions: string[];
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
