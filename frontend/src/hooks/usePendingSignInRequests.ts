import { useQuery } from "@tanstack/react-query";
import { cibaService, type CibaApprovalRequest } from "@/services/ciba";

/** How often the user menu's badge re-reads the list. */
export const PENDING_SIGN_INS_POLL_MS = 60_000;

/**
 * The signed-in user's own pending CIBA sign-in requests (D-74, #566), for the
 * user menu's badge.
 *
 * An account with no vouched address is sent no approval mail, so this list is
 * the only way it finds a request. It is read once a minute while the tab is
 * visible -- the route's allowance (`ciba_approval_per_min`) is 30 -- and not
 * retried: a refusal (a token that is not a console sign-in's, an allowance
 * spent) shows no badge rather than an error on every page.
 */
export function usePendingSignInRequests(): CibaApprovalRequest[] {
  const { data } = useQuery({
    queryKey: ["ciba-pending-requests"],
    queryFn: async () => (await cibaService.listPending()).requests,
    refetchInterval: PENDING_SIGN_INS_POLL_MS,
    refetchIntervalInBackground: false,
    retry: false,
  });
  return data ?? [];
}
