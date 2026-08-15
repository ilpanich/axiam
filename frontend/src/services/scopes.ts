import api from "@/lib/api";
import { unwrapList } from "@/services/_pagination";

// ─── Scopes (nested under resources) ───────────────────────────────────────────
//
// Mirrors crates/axiam-api-rest/src/handlers/scopes.rs. Scopes give
// sub-resource granularity to permission grants (e.g. a "billing" resource
// might carry "invoices" and "reports" scopes); they are always created,
// listed, updated and deleted under a specific `resource_id`.

export interface Scope {
  id: string;
  tenant_id: string;
  resource_id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface CreateScopePayload {
  name: string;
  description: string;
}

export interface UpdateScopePayload {
  name?: string;
  description?: string;
}

export const scopeService = {
  list: (resourceId: string): Promise<Scope[]> =>
    api
      .get<Scope[] | { items: Scope[] }>(`/api/v1/resources/${resourceId}/scopes`)
      .then((r) => unwrapList(r.data)),

  create: (resourceId: string, payload: CreateScopePayload): Promise<Scope> =>
    api
      .post<Scope>(`/api/v1/resources/${resourceId}/scopes`, payload)
      .then((r) => r.data),

  update: (
    resourceId: string,
    scopeId: string,
    payload: UpdateScopePayload,
  ): Promise<Scope> =>
    api
      .put<Scope>(`/api/v1/resources/${resourceId}/scopes/${scopeId}`, payload)
      .then((r) => r.data),

  remove: (resourceId: string, scopeId: string): Promise<void> =>
    api
      .delete(`/api/v1/resources/${resourceId}/scopes/${scopeId}`)
      .then(() => undefined),
};
