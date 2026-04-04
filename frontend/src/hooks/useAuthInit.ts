import { useEffect } from "react";
import { useAuthStore } from "@/stores/auth";
import api from "@/lib/api";

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
      try {
        const res = await api.get("/api/v1/auth/me");
        if (!cancelled && res.data?.user) {
          setUser(res.data.user);
        } else if (!cancelled) {
          clearAuth();
        }
      } catch {
        // 401 or network error — unauthenticated (per UI-SPEC: no error shown)
        if (!cancelled) {
          clearAuth();
        }
      }
    }

    init();
    return () => {
      cancelled = true;
    };
  }, [setUser, clearAuth, setInitializing]);
}
