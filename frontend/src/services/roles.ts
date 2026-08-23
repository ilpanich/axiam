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

/**
 * A role assignment: the grant, plus the resource it applies under.
 *
 * `resource_id === null` is a **global** assignment — the role applies
 * everywhere. A non-null value scopes it to that resource (and, through the
 * hierarchy, its descendants).
 *
 * The distinction is not cosmetic. `DELETE /roles/{id}/users/{userId}` with no
 * `resource_id` deletes the edge whose scope is null, so revoking a scoped
 * assignment without passing the resource back silently removes nothing and
 * still answers 204. Every unassign below therefore forwards the scope it was
 * given.
 */
export interface RoleAssignment {
  role: Role;
  resource_id: string | null;
}

/** A member row of `GET /roles/{id}/users`: the user plus the assignment scope. */
export interface RoleUserAssignment {
  user: User;
  resource_id: string | null;
}

/** A member row of `GET /roles/{id}/groups`: the group plus the assignment scope. */
export interface RoleGroupAssignment {
  group: Group;
  resource_id: string | null;
}

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

  listUsers: (roleId: string): Promise<RoleUserAssignment[]> =>
    api
      .get<RoleUserAssignment[] | { items: RoleUserAssignment[] }>(
        `/api/v1/roles/${roleId}/users`
      )
      .then((r) => unwrapList(r.data)),

  /** List a user's role assignments, including roles reaching them via a group. */
  listByUser: (userId: string): Promise<RoleAssignment[]> =>
    api
      .get<RoleAssignment[] | { items: RoleAssignment[] }>(
        `/api/v1/users/${userId}/roles`
      )
      .then((r) => unwrapList(r.data)),

  /**
   * Assign a role to a user, optionally scoped to a resource.
   *
   * Omitting `resourceId` creates a global assignment — the pre-scoping
   * behaviour. Note the server holds `has_role` unique on (subject, role): a
   * user already holding this role gets a 409, whichever scope is asked for.
   */
  assignToUser: (
    roleId: string,
    userId: string,
    resourceId?: string | null
  ): Promise<void> =>
    api
      .post(`/api/v1/roles/${roleId}/users`, {
        user_id: userId,
        ...(resourceId ? { resource_id: resourceId } : {}),
      })
      .then(() => undefined),

  unassignFromUser: (
    roleId: string,
    userId: string,
    resourceId?: string | null
  ): Promise<void> =>
    api
      // The param is sent only for a scoped assignment: the bare call is what
      // removes a global grant, and an empty value would match neither.
      .delete(
        `/api/v1/roles/${roleId}/users/${userId}`,
        resourceId ? { params: { resource_id: resourceId } } : {}
      )
      .then(() => undefined),

  // ─── Group assignment ─────────────────────────────────────────────────────

  listGroups: (roleId: string): Promise<RoleGroupAssignment[]> =>
    api
      .get<RoleGroupAssignment[] | { items: RoleGroupAssignment[] }>(
        `/api/v1/roles/${roleId}/groups`
      )
      .then((r) => unwrapList(r.data)),

  /** List a group's role assignments. Every member inherits these. */
  listByGroup: (groupId: string): Promise<RoleAssignment[]> =>
    api
      .get<RoleAssignment[] | { items: RoleAssignment[] }>(
        `/api/v1/groups/${groupId}/roles`
      )
      .then((r) => unwrapList(r.data)),

  assignToGroup: (
    roleId: string,
    groupId: string,
    resourceId?: string | null
  ): Promise<void> =>
    api
      .post(`/api/v1/roles/${roleId}/groups`, {
        group_id: groupId,
        ...(resourceId ? { resource_id: resourceId } : {}),
      })
      .then(() => undefined),

  unassignFromGroup: (
    roleId: string,
    groupId: string,
    resourceId?: string | null
  ): Promise<void> =>
    api
      .delete(
        `/api/v1/roles/${roleId}/groups/${groupId}`,
        resourceId ? { params: { resource_id: resourceId } } : {}
      )
      .then(() => undefined),
};
