import api from "@/lib/api";

// ─── Domain Models ────────────────────────────────────────────────────────────

export type AuditOutcome = "Success" | "Failure" | "Denied";

export interface AuditLog {
  id: string;
  tenant_id: string;
  actor_id: string;
  actor_type: string;
  action: string;
  resource_id?: string | null;
  outcome: AuditOutcome;
  ip_address?: string | null;
  metadata?: Record<string, unknown> | null;
  timestamp: string;
}

/**
 * Backend `PaginatedResult<AuditLogEntry>` shape.
 * Source: crates/axiam-core/src/repository.rs (PaginatedResult, Pagination).
 */
export interface PaginatedAuditLogs {
  items: AuditLog[];
  total: number;
  offset: number;
  limit: number;
}

// ─── Filters ──────────────────────────────────────────────────────────────────

export interface AuditFilters {
  offset?: number;
  limit?: number;
  actor_id?: string;
  action?: string;
  resource_id?: string;
  outcome?: AuditOutcome | "";
  from?: string;
  to?: string;
}

// ─── Date helpers ───────────────────────────────────────────────────────────--

/** Bare `YYYY-MM-DD` → RFC3339 start-of-day UTC. Passes other strings through. */
function toRfc3339Start(value: string): string {
  return /^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T00:00:00Z` : value;
}

/** Bare `YYYY-MM-DD` → RFC3339 end-of-day UTC. Passes other strings through. */
function toRfc3339End(value: string): string {
  return /^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T23:59:59Z` : value;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const auditService = {
  list: (filters: AuditFilters = {}): Promise<PaginatedAuditLogs> => {
    const params = new URLSearchParams();
    params.set("offset", String(filters.offset ?? 0));
    params.set("limit", String(filters.limit ?? 20));
    if (filters.actor_id?.trim()) params.set("actor_id", filters.actor_id.trim());
    if (filters.action?.trim()) params.set("action", filters.action.trim());
    if (filters.resource_id?.trim()) params.set("resource_id", filters.resource_id.trim());
    if (filters.outcome) params.set("outcome", filters.outcome);
    // Backend AuditLogFilter.from/to are RFC3339 datetimes; the UI sends bare
    // `YYYY-MM-DD` dates. Widen to full-day UTC bounds so a bare date filters
    // the whole day instead of 400ing.
    if (filters.from?.trim()) {
      params.set("from", toRfc3339Start(filters.from.trim()));
    }
    if (filters.to?.trim()) {
      params.set("to", toRfc3339End(filters.to.trim()));
    }
    return api
      .get<PaginatedAuditLogs>(`/api/v1/audit-logs?${params.toString()}`)
      .then((r) => r.data);
  },
};
