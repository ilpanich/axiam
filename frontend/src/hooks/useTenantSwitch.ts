import { useCallback } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { fetchCurrentUser } from "@/lib/fetchCurrentUser";
import { useAuthStore } from "@/stores/auth";

/**
 * Change the tenant an organization-level principal acts on, and leave the UI
 * showing that tenant's data and nothing else.
 *
 * # Why this is a hook rather than four lines in the topbar
 *
 * It was four lines in the topbar, and each of them was subtly wrong in a way
 * that only showed up as "the page didn't refresh":
 *
 * 1. `queryClient.clear()` does not refetch what is on screen. It removes each
 *    query from the cache and destroys it, but a mounted observer keeps its
 *    reference to the orphaned query and goes on rendering the data it already
 *    had. The operator switched tenant and kept looking at the previous
 *    tenant's rows under the new tenant's name.
 * 2. The caller's permission array is recomputed for the tenant being acted on,
 *    so it is stale from the moment the header changes until `/auth/me` comes
 *    back. Pages rendered in that window gate on the old tenant's permissions
 *    while their requests go to the new one.
 * 3. Nothing dropped page-local state — a half-filled form, a selected row, an
 *    open dialog holding an id that does not exist in the tenant now being
 *    acted on.
 *
 * # What it does instead
 *
 * Raise `isSwitchingTenant`, which makes the layout swap the routed subtree for
 * a spinner — every page unmounts, taking its query observers and its local
 * state with it. Point the header at the new tenant, re-read `/auth/me` in the
 * new scope, then lower the flag. The pages remount against a cache namespaced
 * by the acting tenant (see `tenantScopedQueryKeyHash`), so every query is a
 * miss and fetches, and none of the previous tenant's entries are reachable
 * from the new one.
 *
 * `removeQueries()` still runs, and deliberately drops EVERY entry rather than
 * only the ones belonging to the tenant being left. The namespace already makes
 * cross-tenant bleed impossible, so this is not about correctness — it is about
 * not holding one tenant's users, roles and audit rows in memory while an
 * operator works in another. The cost is that switching back re-fetches; in an
 * IAM console that is the right trade.
 *
 * The `/auth/me` re-read is best-effort: if it fails the previous snapshot
 * stands, every request is authorized server-side regardless, and an error
 * toast for a background refresh is noise on an action that visibly succeeded.
 * The flag is lowered in either case — a failed refresh must not leave the app
 * stuck on a spinner.
 */
export function useTenantSwitch(): (
  tenantId: string | null,
  tenantName: string | null,
) => Promise<void> {
  const queryClient = useQueryClient();
  const selectTenant = useAuthStore((s) => s.selectTenant);
  const setSwitchingTenant = useAuthStore((s) => s.setSwitchingTenant);
  const setUser = useAuthStore((s) => s.setUser);

  return useCallback(
    async (tenantId: string | null, tenantName: string | null) => {
      setSwitchingTenant(true);
      try {
        // Before the header moves. Nothing is observing these by now — the
        // pages unmounted when the flag went up — so removal is a plain drop
        // rather than the orphaning `clear()` used to cause.
        queryClient.removeQueries();
        selectTenant(tenantId, tenantName);

        // Several fields of `/auth/me` describe the tenant being ACTED ON
        // rather than the principal — the effective OPAQUE policy, the tenant
        // slug, and the permission array, which across a tenant boundary
        // carries only the caller's *global* grants.
        const refreshed = await fetchCurrentUser();
        if (refreshed) setUser(refreshed);
      } finally {
        setSwitchingTenant(false);
      }
    },
    [queryClient, selectTenant, setSwitchingTenant, setUser],
  );
}
