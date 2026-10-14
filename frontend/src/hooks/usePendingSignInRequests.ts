import { useQuery } from "@tanstack/react-query";
import { cibaService, type CibaApprovalRequest } from "@/services/ciba";

/** How often the user menu's badge re-reads the list. */
export const PENDING_SIGN_INS_POLL_MS = 60_000;

/** What the user menu shows of the pending list. */
export interface PendingSignIns {
  /** Oldest first, at most fifty. */
  requests: CibaApprovalRequest[];
  /**
   * How many requests are waiting in all: `requests.length`, or more when the
   * server left some out (`truncated`, #599).
   */
  total: number;
  /** Whether `total` counts requests `requests` does not hold. */
  truncated: boolean;
}

const NONE: PendingSignIns = { requests: [], total: 0, truncated: false };

/**
 * The signed-in user's own pending CIBA sign-in requests (D-74, #566), for the
 * user menu's badge.
 *
 * An account with no vouched address is sent no approval mail, so this list is
 * the only way it finds a request. It is read once a minute while the tab is
 * visible -- the route's allowance (`ciba_approval_per_min`, 30 a minute) is
 * the signed-in user's own, not the address's (D-4, #599) -- and not retried:
 * a refusal (a token that is not a console sign-in's, an allowance spent) shows
 * no badge rather than an error on every page.
 */
export function usePendingSignInRequests(): PendingSignIns {
  const { data } = useQuery({
    queryKey: ["ciba-pending-requests"],
    queryFn: async (): Promise<PendingSignIns> => {
      const list = await cibaService.listPending();
      const requests = list.requests;
      // Never fewer than what is in hand, whatever the server said.
      const total = Math.max(list.total_pending ?? requests.length, requests.length);
      return { requests, total, truncated: total > requests.length };
    },
    refetchInterval: PENDING_SIGN_INS_POLL_MS,
    refetchIntervalInBackground: false,
    retry: false,
  });
  return data ?? NONE;
}
