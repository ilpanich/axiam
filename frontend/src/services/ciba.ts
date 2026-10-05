import api from "@/lib/api";
import { ACR_MULTI_FACTOR, sanitizeRequiredAcr } from "@/lib/reauth";

// ─── CIBA user approval (G-7, T23.7.2) ───────────────────────────────────────
//
// Mirrors `crates/axiam-api-rest/src/handlers/ciba_approval.rs`:
//  - GET  /api/v1/ciba/requests/{id}          -> CibaApprovalRequest
//  - POST /api/v1/ciba/requests/{id}/approve  -> { ok, decision }
//  - POST /api/v1/ciba/requests/{id}/deny     -> { ok, decision }
//
// Every reason a request cannot be decided by this user -- unknown id, another
// user's, expired, already decided, changed since it was read -- is the same
// `404`. The page must not try to tell them apart (D-68).

export interface CibaApprovalRequest {
  request_id: string;
  /** Send back with the decision: it is conditional on this value. */
  version: number;
  client_id: string;
  client_name: string;
  scopes: string[];
  /** Shown as text. Never interpreted as markup. */
  binding_message: string | null;
  requested_acr: string[];
  /** The class to step up to before approving, or null. */
  step_up_required: string | null;
  expires_at: string;
}

export interface CibaDecisionResponse {
  ok: boolean;
  decision: "approved" | "denied";
}

/** The body of the `403` that asks the page to step up. */
export interface CibaStepUpRequired {
  error: "step_up_required";
  message: string;
  required_acr: string;
}

export const cibaService = {
  get: (requestId: string): Promise<CibaApprovalRequest> =>
    api
      .get<CibaApprovalRequest>(`/api/v1/ciba/requests/${requestId}`)
      .then((r) => r.data),

  approve: (requestId: string, version: number): Promise<CibaDecisionResponse> =>
    api
      .post<CibaDecisionResponse>(`/api/v1/ciba/requests/${requestId}/approve`, {
        version,
      })
      .then((r) => r.data),

  deny: (requestId: string, version: number): Promise<CibaDecisionResponse> =>
    api
      .post<CibaDecisionResponse>(`/api/v1/ciba/requests/${requestId}/deny`, {
        version,
      })
      .then((r) => r.data),
};

/** A canonical UUID: the only shape a request id takes. */
const UUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** The request id in the page's URL, or `null` for anything that is not one. */
export function parseRequestId(raw: string | null | undefined): string | null {
  if (!raw) return null;
  return UUID_RE.test(raw) ? raw.toLowerCase() : null;
}

/** The path (with query) of the approval page for one request. */
export function approvalPath(requestId: string): string {
  return `/ciba/approve?request_id=${requestId}`;
}

/**
 * The step-up as a login URL: the existing login hop (`reauth=1`, the class the
 * sign-in must achieve) with this page as the place to come back to. The class
 * is held to the two-value vocabulary (`sanitizeRequiredAcr`), so nothing the
 * server or a URL says can put another string on the login page.
 */
export function stepUpLoginPath(requestId: string, requiredAcr: string): string {
  const acr = sanitizeRequiredAcr(requiredAcr) ?? ACR_MULTI_FACTOR;
  return (
    `/login?return_to=${encodeURIComponent(approvalPath(requestId))}` +
    `&reauth=1&acr=${encodeURIComponent(acr)}`
  );
}
