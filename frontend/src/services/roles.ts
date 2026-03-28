import api from "@/lib/api";
import type { Permission } from "@/services/permissions";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface Role {
  id: string;
  name: string;
  description?: string;
  is_global: boolean;
  created_at: string;
}

export interface CreateRolePayload {
  name: string;
  description?: string;
  is_global?: boolean;
}

export type UpdateRolePayload = Partial<CreateRolePayload>;

// ─── Roles service ────────────────────────────────────────────────────────────

export const roleService = {
  list: (): Promise<Role[]> =>
    api.get<Role[]>("/api/v1/roles").then((r) => r.data),

  get: (roleId: string): Promise<Role> =>
    api.get<Role>(`/api/v1/roles/${roleId}`).then((r) => r.data),

  create: (payload: CreateRolePayload): Promise<Role> =>
    api.post<Role>("/api/v1/roles", payload).then((r) => r.data),

  update: (roleId: string, payload: UpdateRolePayload): Promise<Role> =>
    api.put<Role>(`/api/v1/roles/${roleId}`, payload).then((r) => r.data),

  remove: (roleId: string): Promise<void> =>
    api.delete(`/api/v1/roles/${roleId}`).then(() => undefined),

  // ─── Permission management ────────────────────────────────────────────────

  listPermissions: (roleId: string): Promise<Permission[]> =>
    api
      .get<Permission[]>(`/api/v1/roles/${roleId}/permissions`)
      .then((r) => r.data),

  grantPermission: (roleId: string, permissionId: string): Promise<void> =>
    api
      .post(`/api/v1/roles/${roleId}/permissions`, {
        permission_id: permissionId,
      })
      .then(() => undefined),

  revokePermission: (roleId: string, permissionId: string): Promise<void> =>
    api
      .delete(`/api/v1/roles/${roleId}/permissions/${permissionId}`)
      .then(() => undefined),

  // ─── User assignment ──────────────────────────────────────────────────────

  assignToUser: (roleId: string, userId: string): Promise<void> =>
    api
      .post(`/api/v1/roles/${roleId}/users`, { user_id: userId })
      .then(() => undefined),

  unassignFromUser: (roleId: string, userId: string): Promise<void> =>
    api
      .delete(`/api/v1/roles/${roleId}/users/${userId}`)
      .then(() => undefined),

  // ─── Group assignment ─────────────────────────────────────────────────────

  assignToGroup: (roleId: string, groupId: string): Promise<void> =>
    api
      .post(`/api/v1/roles/${roleId}/groups`, { group_id: groupId })
      .then(() => undefined),

  unassignFromGroup: (roleId: string, groupId: string): Promise<void> =>
    api
      .delete(`/api/v1/roles/${roleId}/groups/${groupId}`)
      .then(() => undefined),
};
