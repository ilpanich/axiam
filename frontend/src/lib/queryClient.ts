import { QueryClient } from "@tanstack/react-query";

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

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 60_000,
      retry: (failureCount, error: unknown) => {
        const status = (error as { response?: { status?: number } })?.response
          ?.status;
        if (status === 401 || status === 403) return false;
        return failureCount < 2;
      },
    },
  },
});
