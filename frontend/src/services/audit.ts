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

export interface PaginatedAuditLogs {
  data: AuditLog[];
  total: number;
  page: number;
  per_page: number;
}

// ─── Filters ──────────────────────────────────────────────────────────────────

export interface AuditFilters {
  page?: number;
  per_page?: number;
  actor_id?: string;
  action?: string;
  resource?: string;
  outcome?: "success" | "failure" | "";
  from?: string;
  to?: string;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const auditService = {
  list: (filters: AuditFilters = {}): Promise<PaginatedAuditLogs> => {
    const params = new URLSearchParams();
    params.set("page", String(filters.page ?? 1));
    params.set("per_page", String(filters.per_page ?? 20));
    if (filters.actor_id?.trim()) params.set("actor_id", filters.actor_id.trim());
    if (filters.action?.trim()) params.set("action", filters.action.trim());
    if (filters.resource?.trim()) params.set("resource", filters.resource.trim());
    if (filters.outcome) params.set("outcome", filters.outcome);
    if (filters.from?.trim()) params.set("from", filters.from.trim());
    if (filters.to?.trim()) params.set("to", filters.to.trim());
    return api
      .get<PaginatedAuditLogs>(`/api/v1/audit-logs?${params.toString()}`)
      .then((r) => r.data);
  },
};
