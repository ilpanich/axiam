// Single-flight refresh guard (CONTRACT.md §9, D-07/D-13).
//
// Per-session-scoped shared-Promise guard (CR-02 gap closure, 17-VERIFICATION.md):
// createRefreshGuard() returns a fresh, independent refreshOnce closure per
// call, each closing over its OWN private refreshPromise. Concurrent callers
// against the SAME guard instance share the same in-flight Promise; the
// guard clears on settle (success or failure) so a later expiry can trigger
// a fresh refresh — this is the exactly-one-in-flight-at-a-time semantics §9
// requires, not a permanent single-refresh-ever lock. Distinct guard
// instances (one per SharedSession/NodeSession, D-13) never share state, so
// a refresh on session A can never silently satisfy a concurrent refresh on
// session B.

/** A session-scoped single-flight guard closure, as returned by `createRefreshGuard()`. */
export type RefreshGuard = (doRefresh: () => Promise<void>) => Promise<void>;

/** Test-only reset hook type, attached to each guard closure via `Object.assign`. @internal */
interface ResettableRefreshGuard {
  (doRefresh: () => Promise<void>): Promise<void>;
  __reset(): void;
}

/**
 * Build a fresh, independent single-flight refresh guard. Each call returns
 * its own closure with a private `refreshPromise` — instantiate one per
 * `SharedSession`/`NodeSession` (D-13) so refresh guards never cross-wire
 * between independent client instances (CR-02).
 */
export function createRefreshGuard(): RefreshGuard {
  let refreshPromise: Promise<void> | null = null;

  const guard = ((doRefresh: () => Promise<void>): Promise<void> => {
    if (!refreshPromise) {
      refreshPromise = doRefresh().finally(() => {
        refreshPromise = null;
      });
    }
    return refreshPromise;
  }) as ResettableRefreshGuard;

  guard.__reset = () => {
    refreshPromise = null;
  };

  return guard;
}

// Backward-compatible module-level default guard instance, retained for
// test/core/singleFlightRefresh.test.ts and any caller still importing the
// bare `refreshOnce`/`resetRefreshGuard` module-level functions. New
// wiring (rest/interceptors.ts, grpc/callWithRefresh.ts) MUST use a
// per-session guard from `createRefreshGuard()` instead (see
// SharedSession.refreshGuard).
const defaultGuard = createRefreshGuard() as ResettableRefreshGuard;

/**
 * Ensures at most one `doRefresh()` call is in flight at a time, backed by
 * the single module-level default guard instance. Concurrent callers share
 * the same in-flight Promise; after it settles, a subsequent call invokes
 * `doRefresh` again.
 *
 * @deprecated for new wiring — use a per-instance guard from
 * `createRefreshGuard()` instead (D-13/CR-02). Retained for backward
 * compatibility.
 */
export function refreshOnce(doRefresh: () => Promise<void>): Promise<void> {
  return defaultGuard(doRefresh);
}

/** Test-only helper to reset the module-level default guard between test cases. @internal */
export function resetRefreshGuard(): void {
  defaultGuard.__reset();
}
