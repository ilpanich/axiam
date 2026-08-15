import api from "@/lib/api";

// ─── Effective-access preview (B1) ─────────────────────────────────────────────
//
// Mirrors crates/axiam-api-rest/src/handlers/authz_check.rs. `reason_code` is
// a closed three-value vocabulary: "allowed", "no_grant", "denied_by_rule" —
// the deny-override distinction the UI needs to render a DENY badge instead
// of a generic "not allowed" message (T-15-02).

export interface CheckAccessRequest {
  action: string;
  resource_id: string;
  scope?: string;
  /** Cross-subject check; caller must hold `authz:check_as` (T-15-01). */
  subject_id?: string;
}

export interface CheckAccessResult {
  allowed: boolean;
  reason?: string;
  reason_code: "allowed" | "no_grant" | "denied_by_rule" | string;
}

export interface BatchCheckAccessResult {
  results: CheckAccessResult[];
}

export const authzCheckService = {
  check: (body: CheckAccessRequest): Promise<CheckAccessResult> =>
    api.post<CheckAccessResult>("/api/v1/authz/check", body).then((r) => r.data),

  checkBatch: (checks: CheckAccessRequest[]): Promise<BatchCheckAccessResult> =>
    api
      .post<BatchCheckAccessResult>("/api/v1/authz/check/batch", { checks })
      .then((r) => r.data),
};
