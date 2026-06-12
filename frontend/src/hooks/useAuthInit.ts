import { useEffect } from "react";
import { useAuthStore } from "@/stores/auth";
import { fetchCurrentUser } from "@/lib/fetchCurrentUser";
import api from "@/lib/api";

/**
 * Auth initialization hook — calls GET /api/v1/auth/me on mount to
 * rehydrate auth state from cookies. If 200, populates store.
 *
 * If the first /auth/me returns null (access cookie expired) the hook
 * attempts exactly ONE silent refresh through the api instance (which
 * attaches X-CSRF-Token) and re-fetches, so a valid refresh cookie keeps
 * the user logged in across a page reload (CQ-F28). On any failure it
 * treats the user as unauthenticated.
 */
export function useAuthInit() {
  const setUser = useAuthStore((s) => s.setUser);
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const setInitializing = useAuthStore((s) => s.setInitializing);

  useEffect(() => {
    let cancelled = false;

    async function init() {
      let user = await fetchCurrentUser();
      if (cancelled) return;

      // Access cookie expired but refresh cookie may still be valid:
      // attempt exactly one boot refresh before declaring unauthenticated.
      if (!user) {
        try {
          await api.post("/api/v1/auth/refresh", {});
          user = await fetchCurrentUser();
        } catch {
          // Genuinely unauthenticated — fall through to clearAuth.
        }
        if (cancelled) return;
      }

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
