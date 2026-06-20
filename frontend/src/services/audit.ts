import api from "@/lib/api";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface AuditLog {
  id: string;
  actor_id: string;
  actor_username?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  outcome: "success" | "failure";
  ip_address?: string;
  details?: Record<string, unknown>;
  created_at: string;
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
  outcome?: "success" | "failure" | "";
  from?: string;
  to?: string;
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
    if (filters.from?.trim()) params.set("from", filters.from.trim());
    if (filters.to?.trim()) params.set("to", filters.to.trim());
    return api
      .get<PaginatedAuditLogs>(`/api/v1/audit-logs?${params.toString()}`)
      .then((r) => r.data);
  },
};
