import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";

export interface AuthUser {
  id: string;
  username: string;
  email: string;
}

interface AuthState {
  accessToken: string | null;
  user: AuthUser | null;
  tenantId: string | null;
  orgId: string | null;
  isAuthenticated: boolean;
}

interface AuthActions {
  setTokens: (accessToken: string, user: AuthUser) => void;
  clearAuth: () => void;
  setTenantContext: (tenantId: string, orgId: string) => void;
}

const initialState: AuthState = {
  accessToken: null,
  user: null,
  tenantId: null,
  orgId: null,
  isAuthenticated: false,
};

export const useAuthStore = create<AuthState & AuthActions>()(
  persist(
    (set) => ({
      ...initialState,

      setTokens: (accessToken, user) =>
        set({
          accessToken,
          user,
          isAuthenticated: true,
        }),

      clearAuth: () => set({ ...initialState }),

      setTenantContext: (tenantId, orgId) => set({ tenantId, orgId }),
    }),
    {
      name: "axiam-auth",
      storage: createJSONStorage(() => sessionStorage),
      // Do NOT persist isAuthenticated — derive it on rehydration
      partialize: (state) => ({
        accessToken: state.accessToken,
        user: state.user,
        tenantId: state.tenantId,
        orgId: state.orgId,
      }),
      onRehydrateStorage: () => (state) => {
        if (state) {
          state.isAuthenticated = state.accessToken !== null;
        }
      },
    }
  )
);
