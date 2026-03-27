import api from "@/lib/api";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface Permission {
  id: string;
  name: string;
  action: string;
  resource_id?: string;
  description?: string;
  created_at: string;
}

export interface CreatePermissionPayload {
  name: string;
  action: string;
  resource_id?: string;
  description?: string;
}

export type UpdatePermissionPayload = Partial<CreatePermissionPayload>;

// ─── Permissions service ──────────────────────────────────────────────────────

export const permissionService = {
  list: (): Promise<Permission[]> =>
    api.get<Permission[]>("/api/v1/permissions").then((r) => r.data),

  get: (permissionId: string): Promise<Permission> =>
    api
      .get<Permission>(`/api/v1/permissions/${permissionId}`)
      .then((r) => r.data),

  create: (payload: CreatePermissionPayload): Promise<Permission> =>
    api
      .post<Permission>("/api/v1/permissions", payload)
      .then((r) => r.data),

  update: (
    permissionId: string,
    payload: UpdatePermissionPayload
  ): Promise<Permission> =>
    api
      .put<Permission>(`/api/v1/permissions/${permissionId}`, payload)
      .then((r) => r.data),

  remove: (permissionId: string): Promise<void> =>
    api
      .delete(`/api/v1/permissions/${permissionId}`)
      .then(() => undefined),
};
