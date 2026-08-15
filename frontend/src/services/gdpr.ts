import api from "@/lib/api";

// ─── GDPR Art. 15 (export) / Art. 17 (erasure) — mirrors
// crates/axiam-api-rest/src/handlers/gdpr.rs exactly. ─────────────────────────

export interface QueuedResponse {
  queued: boolean;
}

export interface ScheduledResponse {
  scheduled: boolean;
}

export interface CancelledResponse {
  cancelled: boolean;
}

export const gdprService = {
  /**
   * `POST /api/v1/account/export` — enqueue an async data-export job.
   * `userId` targets another account; omit for self. Acting on another
   * account requires `gdpr:export` (enforced server-side; `is_own_resource`
   * lets self-service through without it).
   */
  requestExport: (userId?: string): Promise<QueuedResponse> =>
    api
      .post<QueuedResponse>("/api/v1/account/export", {
        user_id: userId || undefined,
      })
      .then((r) => r.data),

  /**
   * `GET /api/v1/account/export/{token}` — single-use download of the export
   * blob. `token` is the raw value from the export-ready email, never
   * discoverable from any list endpoint by design (D-13).
   */
  downloadExport: (token: string): Promise<unknown> =>
    api.get(`/api/v1/account/export/${encodeURIComponent(token)}`).then((r) => r.data),

  /**
   * `POST /api/v1/account/delete` — initiate Art. 17 erasure: disables the
   * account, revokes sessions, emails a single-use cancel link, and schedules
   * purge at +30 days. `userId` targets another account; omit for self.
   * Acting on another account requires `users:erase`.
   */
  requestErasure: (userId?: string): Promise<ScheduledResponse> =>
    api
      .post<ScheduledResponse>("/api/v1/account/delete", {
        user_id: userId || undefined,
      })
      .then((r) => r.data),

  /**
   * `GET /api/v1/auth/account/delete/cancel?token=…` — public endpoint (the
   * link mailed with the erasure confirmation); aborts a still-pending
   * deletion within its grace window.
   */
  cancelErasure: (token: string): Promise<CancelledResponse> =>
    api
      .get<CancelledResponse>("/api/v1/auth/account/delete/cancel", {
        params: { token },
      })
      .then((r) => r.data),
};

/**
 * Trigger a browser download of the decrypted export JSON. Kept separate
 * from the service call so tests can exercise `downloadExport` without a DOM
 * download side effect.
 */
export function saveExportBlob(data: unknown, filename = "axiam-data-export.json"): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
