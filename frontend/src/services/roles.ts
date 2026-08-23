import api from "@/lib/api";
import { unwrapList } from "@/services/_pagination";
import type { PermissionEffect, PermissionGrant } from "@/services/permissions";
import type { User } from "@/services/users";
import type { Group } from "@/services/users";

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
  /** Required by the backend; send "" (not undefined) when blank. */
  description: string;
  is_global?: boolean;
}

export type UpdateRolePayload = Partial<CreateRolePayload>;

// ─── Roles service ────────────────────────────────────────────────────────────

export const roleService = {
  list: (): Promise<Role[]> =>
    api
      .get<Role[] | { items: Role[] }>("/api/v1/roles")
      .then((r) => unwrapList(r.data)),

  get: (roleId: string): Promise<Role> =>
    api.get<Role>(`/api/v1/roles/${roleId}`).then((r) => r.data),

  create: (payload: CreateRolePayload): Promise<Role> =>
    api.post<Role>("/api/v1/roles", payload).then((r) => r.data),

  update: (roleId: string, payload: UpdateRolePayload): Promise<Role> =>
    api.put<Role>(`/api/v1/roles/${roleId}`, payload).then((r) => r.data),

  remove: (roleId: string): Promise<void> =>
    api.delete(`/api/v1/roles/${roleId}`).then(() => undefined),

  // ─── Permission management ────────────────────────────────────────────────

  listPermissions: (roleId: string): Promise<PermissionGrant[]> =>
    api
      .get<PermissionGrant[] | { items: PermissionGrant[] }>(
        `/api/v1/roles/${roleId}/permissions`
      )
      .then((r) => unwrapList(r.data)),

  /**
   * Grant a permission to a role.
   *
   * `effect` defaults to `"allow"` server-side, so omitting it is exactly the
   * pre-deny-override behaviour. Passing `"deny"` writes a rule that overrides
   * every allow -- see `PermissionEffect`.
   *
   * `scopeIds` constrains the grant to sub-resource scopes (C4). Empty — the
   * default — is the wildcard: the grant covers every scope of the resource,
   * and unscoped checks too.
   */
  grantPermission: (
    roleId: string,
    permissionId: string,
    effect: PermissionEffect = "allow",
    scopeIds: string[] = [],
  ): Promise<void> =>
    api
      .post(`/api/v1/roles/${roleId}/permissions`, {
        permission_id: permissionId,
        effect,
        // An empty array is the wildcard the server already defaults to, so
        // sending it changes nothing for an unscoped grant. A non-empty one
        // narrows the grant to those scopes — and, for a deny, narrows what it
        // masks: an unscoped deny masks the action entirely on this node and
        // its descendants, a scoped deny only the scopes it names.
        scope_ids: scopeIds,
      })
      .then(() => undefined),

  revokePermission: (roleId: string, permissionId: string): Promise<void> =>
    api
      .delete(`/api/v1/roles/${roleId}/permissions/${permissionId}`)
      .then(() => undefined),

  // ─── User assignment ──────────────────────────────────────────────────────

  listUsers: (roleId: string): Promise<User[]> =>
    api
      .get<User[] | { items: User[] }>(`/api/v1/roles/${roleId}/users`)
      .then((r) => unwrapList(r.data)),

  assignToUser: (roleId: string, userId: string): Promise<void> =>
    api
      .post(`/api/v1/roles/${roleId}/users`, { user_id: userId })
      .then(() => undefined),

  unassignFromUser: (roleId: string, userId: string): Promise<void> =>
    api
      .delete(`/api/v1/roles/${roleId}/users/${userId}`)
      .then(() => undefined),

  // ─── Group assignment ─────────────────────────────────────────────────────

  listGroups: (roleId: string): Promise<Group[]> =>
    api
      .get<Group[] | { items: Group[] }>(`/api/v1/roles/${roleId}/groups`)
      .then((r) => unwrapList(r.data)),

  /** List roles assigned to a group. */
  listByGroup: (groupId: string): Promise<Role[]> =>
    api
      .get<Role[] | { items: Role[] }>(`/api/v1/groups/${groupId}/roles`)
      .then((r) => unwrapList(r.data)),

  assignToGroup: (roleId: string, groupId: string): Promise<void> =>
    api
      .post(`/api/v1/roles/${roleId}/groups`, { group_id: groupId })
      .then(() => undefined),

  unassignFromGroup: (roleId: string, groupId: string): Promise<void> =>
    api
      .delete(`/api/v1/roles/${roleId}/groups/${groupId}`)
      .then(() => undefined),
};
