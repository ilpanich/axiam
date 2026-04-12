import { useEffect } from "react";
import { useAuthStore } from "@/stores/auth";
import { fetchCurrentUser } from "@/lib/fetchCurrentUser";

/**
 * Auth initialization hook — calls GET /api/v1/auth/me on mount to
 * rehydrate auth state from cookies. If 200, populates store.
 * If 401 or network error, treats as unauthenticated.
 */
export function useAuthInit() {
  const setUser = useAuthStore((s) => s.setUser);
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const setInitializing = useAuthStore((s) => s.setInitializing);

  useEffect(() => {
    let cancelled = false;

    async function init() {
      const user = await fetchCurrentUser();
      if (cancelled) return;
      if (user) {
        setUser(user);
      } else {
        clearAuth();
      }
    }

    init();
    return () => {
      cancelled = true;
    };
  }, [setUser, clearAuth, setInitializing]);
}
