import api from "@/lib/api";

/**
 * FIDO MDS3 admin client (X3 wave 4). Server-global, not tenant-scoped —
 * mirrors `crates/axiam-api-rest/src/handlers/mds.rs`, whose two routes take
 * no `{tenant_id}` path segment for exactly the reason its module docs give:
 * `mds_entry`/`mds_blob_meta` hold one shared trust picture for the whole
 * deployment.
 */

/** Mirrors `MdsStatusResponse`. All fields are `None`/`0`/`false` — a
 * meaningful "nothing ingested yet" answer, not an error — when MDS has
 * never been ingested. */
export interface MdsStatus {
  no: number | null;
  /** ISO date string (`YYYY-MM-DD`), the BLOB's own `nextUpdate` claim. */
  next_update: string | null;
  entry_count: number;
  last_refreshed_at: string | null;
  stale: boolean;
}

/** Mirrors `MdsRefreshOutcome` (`#[serde(tag = "outcome", rename_all =
 * "snake_case")]`). A rejected rollback or no-op refresh is still a
 * successful call — the outcome tag is what distinguishes them, not an
 * HTTP error. */
export type MdsRefreshOutcome =
  | { outcome: "initial"; no: number; entry_count: number }
  | { outcome: "replaced"; no: number; entry_count: number }
  | { outcome: "no_op_refresh"; no: number }
  | { outcome: "rollback_rejected"; attempted_no: number; stored_no: number };

export const mdsService = {
  /** `GET /api/v1/mds/status` */
  getStatus: (): Promise<MdsStatus> =>
    api.get<MdsStatus>("/api/v1/mds/status").then((r) => r.data),

  /** `POST /api/v1/mds/refresh` — admin-triggered ingestion. Rejects
   * (400) when `AXIAM__PKI__MDS_ENABLED=false`; that error surfaces to the
   * caller via the normal axios rejection path. */
  refresh: (): Promise<MdsRefreshOutcome> =>
    api.post<MdsRefreshOutcome>("/api/v1/mds/refresh").then((r) => r.data),
};
