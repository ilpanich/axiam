import { useEffect, useRef } from "react";
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
  const setTenantContext = useAuthStore((s) => s.setTenantContext);
  // CQ-F35: useRef once-guard prevents a second HTTP request under React 18
  // StrictMode (which mounts effects twice in development). The cancelled flag
  // still handles concurrent response handling from a single invocation.
  const initialized = useRef(false);

  useEffect(() => {
    // CQ-F35: fire boot fetch exactly once even under StrictMode double-mount.
    if (initialized.current) return;
    initialized.current = true;

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
        // CQ-F29: Restore tenantSlug/orgSlug from /auth/me response so the
        // tenant context survives a hard reload. Slugs come from the backend,
        // not fabricated client-side (ASVS V4 / T-11-05-CTX).
        if (user.tenantSlug && user.orgSlug) {
          setTenantContext(user.tenantSlug, user.orgSlug);
        }
      } else {
        clearAuth();
      }
    }

    init();
    return () => {
      cancelled = true;
    };
    // CQ-F35: setInitializing removed from dep array — it is never called inside
    // the effect body, so including it only caused StrictMode to re-run the effect.
  }, [setUser, clearAuth, setTenantContext]);
}
