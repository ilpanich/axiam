// Single-flight refresh guard (CONTRACT.md §9, D-07/D-13).
//
// Module-level shared-Promise guard: concurrent callers awaiting an in-flight
// refresh all resolve/reject together off the same Promise. The guard clears
// on settle (success or failure) so a later expiry can trigger a fresh
// refresh — this is the exactly-one-in-flight-at-a-time semantics §9
// requires, not a permanent single-refresh-ever lock.

let refreshPromise: Promise<void> | null = null;

/**
 * Ensures at most one `doRefresh()` call is in flight at a time. Concurrent
 * callers share the same in-flight Promise; after it settles, a subsequent
 * call invokes `doRefresh` again.
 */
export function refreshOnce(doRefresh: () => Promise<void>): Promise<void> {
  if (!refreshPromise) {
    refreshPromise = doRefresh().finally(() => {
      refreshPromise = null;
    });
  }
  return refreshPromise;
}

/** Test-only helper to reset the module-level guard between test cases. @internal */
export function resetRefreshGuard(): void {
  refreshPromise = null;
}
