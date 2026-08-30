import { QueryClient, hashKey } from "@tanstack/react-query";

import { getActiveTenant } from "@/lib/activeTenant";

// D-18: DashboardPage's user-count probe key. Defined here (not inline in
// DashboardPage.tsx) so it can be exported and imported by a regression test
// without tripping the react-refresh/only-export-components ESLint rule
// (array literals are not treated as "constant exports" by that rule).
//
// Distinct from UsersPage's ["users", page, search] key by construction:
// page is always a number there, never the string "dashboard-count", so
// this key can never structurally collide and cross-contaminate the shared
// react-query cache.
export const DASHBOARD_USER_COUNT_QUERY_KEY = ["users", "dashboard-count"] as const;

/**
 * The cache slot a query with no tenant selected belongs to.
 *
 * A sentinel rather than the empty string so it can never collide with a real
 * tenant id, and so a cache dump reads as "the caller's own scope" rather than
 * as a missing value.
 */
export const OWN_SCOPE_CACHE_SLOT = "__own__";

/**
 * Namespace every cache entry by the tenant it was fetched for.
 *
 * # Why this exists
 *
 * Every list in this app is tenant-scoped, but almost none of the ~40 query
 * keys say so: `["users", 1, ""]` means "page 1 of the users of whichever
 * tenant `X-Axiam-Tenant` named at the moment the request went out". When an
 * organization-level principal switches tenant, that meaning changes under
 * every key at once, and nothing in the key records it.
 *
 * The switch used to deal with that by calling `queryClient.clear()`. That is
 * not what `clear()` does: it removes each query from the cache map and calls
 * `query.destroy()`, but a *mounted* observer keeps its reference to the
 * orphaned `Query` and goes on rendering the data it already had, with no
 * refetch — so the page the operator was looking at when they switched kept
 * showing the previous tenant's rows under the new tenant's name, which is the
 * single worst thing a multi-tenant admin UI can do.
 *
 * Hashing the acting tenant into the cache key fixes that at the root rather
 * than at the call site: one tenant's `["users", 1, ""]` and another's are
 * simply different cache entries, so no amount of forgetting to invalidate can
 * show one under the other. `useTenantSwitch` empties the cache on a switch as
 * well, but that is a memory-hygiene choice; this is the structural guarantee
 * underneath it, and it holds even for a code path that forgets to clear.
 *
 * # Why it does not break invalidation
 *
 * `invalidateQueries`/`removeQueries` match on the key ARRAY
 * (`partialMatchKey`), not on this hash, so `invalidateQueries({ queryKey:
 * ["users"] })` still matches every page of every tenant, exactly as before.
 * Only cache *identity* changes.
 *
 * # What it does NOT do
 *
 * A mounted observer's key does not change when the tenant does, so this alone
 * does not make an on-screen page refetch — the observer stays bound to the
 * query it already resolved. Remounting the routed subtree is what turns the
 * new namespace into a new fetch; see `useTenantSwitch`.
 */
export function tenantScopedQueryKeyHash(queryKey: readonly unknown[]): string {
  return hashKey([getActiveTenant() ?? OWN_SCOPE_CACHE_SLOT, ...queryKey]);
}

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 60_000,
      queryKeyHashFn: tenantScopedQueryKeyHash,
      retry: (failureCount, error: unknown) => {
        const status = (error as { response?: { status?: number } })?.response
          ?.status;
        if (status === 401 || status === 403) return false;
        return failureCount < 2;
      },
    },
  },
});
