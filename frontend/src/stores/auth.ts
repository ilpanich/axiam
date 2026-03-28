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
  tenantSlug: string | null;
  orgSlug: string | null;
  isAuthenticated: boolean;
}

interface AuthActions {
  setTokens: (accessToken: string, user: AuthUser) => void;
  updateAccessToken: (accessToken: string) => void;
  clearAuth: () => void;
  setTenantContext: (tenantSlug: string, orgSlug: string) => void;
}

const initialState: AuthState = {
  accessToken: null,
  user: null,
  tenantSlug: null,
  orgSlug: null,
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

      updateAccessToken: (accessToken) => set({ accessToken }),

      clearAuth: () => set({ ...initialState }),

      setTenantContext: (tenantSlug, orgSlug) =>
        set({ tenantSlug, orgSlug }),
    }),
    {
      name: "axiam-auth",
      storage: createJSONStorage(() => sessionStorage),
      // Do NOT persist isAuthenticated — derive it on rehydration
      partialize: (state) => ({
        accessToken: state.accessToken,
        user: state.user,
        tenantSlug: state.tenantSlug,
        orgSlug: state.orgSlug,
      }),
      onRehydrateStorage: () => (state, error) => {
        if (error) return;
        if (!state) return;
        const isAuthenticated = !!(state.accessToken && state.user);
        useAuthStore.setState({ isAuthenticated });
      },
    }
  )
);
