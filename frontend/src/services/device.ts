import api from "@/lib/api";

// ─── Device-flow verification (B2 step 3) ─────────────────────────────────────
//
// Mirrors `crates/axiam-api-rest/src/handlers/device.rs` exactly:
//  - GET  /api/v1/device/verify?user_code=…  -> { found, client_id?, scopes? }
//  - POST /api/v1/device/decide              -> { ok }
//
// Both endpoints deliberately collapse "unknown code" / "expired code" /
// "already-decided code" into the same `found: false` / `ok: false` shape —
// the UI must not try to distinguish them (see the handler's module docs).

export interface DeviceVerifyResponse {
  found: boolean;
  client_id?: string;
  scopes?: string[];
}

export interface DeviceDecideResponse {
  ok: boolean;
}

export const deviceService = {
  verify: (userCode: string): Promise<DeviceVerifyResponse> =>
    api
      .get<DeviceVerifyResponse>("/api/v1/device/verify", {
        params: { user_code: userCode },
      })
      .then((r) => r.data),

  decide: (userCode: string, approved: boolean): Promise<DeviceDecideResponse> =>
    api
      .post<DeviceDecideResponse>("/api/v1/device/decide", {
        user_code: userCode,
        approved,
      })
      .then((r) => r.data),
};

/**
 * Normalize a user-typed code the same way the backend does (case, spaces and
 * dashes are all insensitive) so the client can echo a normalized value back
 * without pretending to know the backend's exact alphabet rules — the server
 * remains the source of truth; this only smooths what gets sent.
 */
export function normalizeUserCode(raw: string): string {
  return raw.trim().toUpperCase().replace(/\s+/g, "").replace(/-/g, "");
}

/** Re-insert the conventional WXYZ-1234 dash for display purposes only. */
export function formatUserCode(raw: string): string {
  const normalized = normalizeUserCode(raw);
  if (normalized.length <= 4) return normalized;
  return `${normalized.slice(0, 4)}-${normalized.slice(4)}`;
}
