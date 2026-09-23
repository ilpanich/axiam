import api from "@/lib/api";
import { getApiErrorMessage } from "@/lib/apiError";
import { fetchAllPages } from "@/services/_pagination";
import type { PermissionEffect, PermissionGrant } from "@/services/permissions";
import type { User } from "@/services/users";
import type { Group } from "@/services/users";
import type { ServiceAccount } from "@/services/serviceAccounts";

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
  /**
   * The tenants this assignment reaches, or absent for "wherever the role
   * does".
   *
   * A second axis, not a finer resource scope. A role in an organization's
   * scope reaches every tenant of the organization; naming tenants here
   * confines it to those, and to nothing else — the organization's own scope
   * included. Only ever present on an assignment made in an organization scope.
   */
  tenant_scope?: string[] | null;
  /**
   * S-10 (D-10) — whether the assignment also reaches the descendants of
   * `resource_id` (`true`, the default and the value of every assignment made
   * before the field existed) or applies at that resource only (`false`).
   * Optional so a server older than the field still types; read it through
   * `assignmentInherits`, which maps absent to `true` exactly as the server's
   * repository does.
   */
  inherit?: boolean;
}

/** `inherit`, with absent read as `true` — the server's own reading. */
export function assignmentInherits(a: { inherit?: boolean }): boolean {
  return a.inherit !== false;
}

/**
 * The part of an assignment that identifies it and has to survive a
 * re-assignment: the scope on both axes, and the flag.
 */
export interface AssignmentScopeState {
  resource_id: string | null;
  tenant_scope?: string[] | null;
  inherit?: boolean;
}

/** A member row of `GET /roles/{id}/users`: the user plus the assignment scope. */
export interface RoleUserAssignment {
  user: User;
  resource_id: string | null;
  /** The tenants this assignment reaches. See {@link RoleAssignment}. */
  tenant_scope?: string[] | null;
  /** See {@link RoleAssignment.inherit}. */
  inherit?: boolean;
}

/** A member row of `GET /roles/{id}/groups`: the group plus the assignment scope. */
export interface RoleGroupAssignment {
  group: Group;
  resource_id: string | null;
  /** The tenants this assignment reaches. See {@link RoleAssignment}. */
  tenant_scope?: string[] | null;
  /** See {@link RoleAssignment.inherit}. */
  inherit?: boolean;
}

/** A service account holding this role, with the scope of the grant. */
export interface RoleServiceAccountAssignment {
  service_account: ServiceAccount;
  resource_id: string | null;
  /** The tenants this assignment reaches. See {@link RoleAssignment}. */
  tenant_scope?: string[] | null;
  /** See {@link RoleAssignment.inherit}. */
  inherit?: boolean;
}

/**
 * The `inherit` key of an assign body: present only as `false`.
 *
 * `true` is the server's default, so omitting it keeps every inheritable
 * assignment's body byte-for-byte what it was before the field existed. The
 * server refuses `false` with no `resource_id` and on a global role; the
 * dialogs offer the flag only where it can apply, and the server remains the
 * one that says no.
 */
function inheritField(inherit: boolean | undefined): { inherit?: false } {
  return inherit === false ? { inherit: false } : {};
}

/**
 * Whether an assignment's flag can be changed at all: it names a resource and
 * its role is not global. The server refuses `inherit: false` in both other
 * cases, so offering the change there could only produce a refusal.
 */
export function canChangeInherit(
  assignment: { resource_id: string | null },
  roleIsGlobal: boolean
): assignment is { resource_id: string } {
  return assignment.resource_id !== null && !roleIsGlobal;
}

/** Which kind of principal an assignment belongs to. */
export type AssignmentSubjectKind = "user" | "group" | "service account";

/**
 * A flag change that did not complete. `restored` says which of the two
 * possible states the subject is left in, because the answer is the whole
 * point: `true` — the new assignment was refused and the old one was put back,
 * so nothing changed; `false` — the old assignment is gone and could not be
 * put back, so the subject **no longer holds the role** at this resource.
 */
export class AssignmentToggleError extends Error {
  readonly restored: boolean;
  readonly cause: unknown;
  constructor(message: string, restored: boolean, cause: unknown) {
    super(message);
    this.name = "AssignmentToggleError";
    this.restored = restored;
    this.cause = cause;
  }
}

// ─── Roles service ────────────────────────────────────────────────────────────

export const roleService = {
  list: (): Promise<Role[]> => fetchAllPages<Role>("/api/v1/roles"),

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
    fetchAllPages<PermissionGrant>(`/api/v1/roles/${roleId}/permissions`),

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
    fetchAllPages<RoleUserAssignment>(`/api/v1/roles/${roleId}/users`),

  /** List a user's role assignments, including roles reaching them via a group. */
  listByUser: (userId: string): Promise<RoleAssignment[]> =>
    fetchAllPages<RoleAssignment>(`/api/v1/users/${userId}/roles`),

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
    resourceId?: string | null,
    tenantScope?: string[] | null,
    inherit?: boolean
  ): Promise<void> =>
    api
      .post(`/api/v1/roles/${roleId}/users`, {
        user_id: userId,
        ...(resourceId ? { resource_id: resourceId } : {}),
        ...inheritField(inherit),
        // Sent only when there is one. The server refuses an empty list (an
        // assignment that reaches nothing is not a restriction), and refuses
        // the field at all outside an organization scope — so omitting it is
        // both the default and the only correct value nearly everywhere.
        ...(tenantScope && tenantScope.length > 0
          ? { tenant_scope: tenantScope }
          : {}),
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
    fetchAllPages<RoleGroupAssignment>(`/api/v1/roles/${roleId}/groups`),

  /** List a group's role assignments. Every member inherits these. */
  listByGroup: (groupId: string): Promise<RoleAssignment[]> =>
    fetchAllPages<RoleAssignment>(`/api/v1/groups/${groupId}/roles`),

  assignToGroup: (
    roleId: string,
    groupId: string,
    resourceId?: string | null,
    tenantScope?: string[] | null,
    inherit?: boolean
  ): Promise<void> =>
    api
      .post(`/api/v1/roles/${roleId}/groups`, {
        group_id: groupId,
        ...(resourceId ? { resource_id: resourceId } : {}),
        ...inheritField(inherit),
        // Sent only when there is one. The server refuses an empty list (an
        // assignment that reaches nothing is not a restriction), and refuses
        // the field at all outside an organization scope — so omitting it is
        // both the default and the only correct value nearly everywhere.
        ...(tenantScope && tenantScope.length > 0
          ? { tenant_scope: tenantScope }
          : {}),
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

  // ─── Service-account assignment ───────────────────────────────────────────
  //
  // A service account is a principal like any other: the authorization engine
  // applies RBAC to a machine identity exactly as it does to a person. Until
  // these endpoints existed there was no way to grant one anything, and the only
  // way to give a machine permissions was to hand it a human's account.

  listServiceAccounts: (roleId: string): Promise<RoleServiceAccountAssignment[]> =>
    fetchAllPages<RoleServiceAccountAssignment>(
      `/api/v1/roles/${roleId}/service-accounts`
    ),

  /**
   * List a service account's role assignments, including roles reaching it
   * through a group.
   */
  listByServiceAccount: (serviceAccountId: string): Promise<RoleAssignment[]> =>
    fetchAllPages<RoleAssignment>(
      `/api/v1/service-accounts/${serviceAccountId}/roles`
    ),

  assignToServiceAccount: (
    roleId: string,
    serviceAccountId: string,
    resourceId?: string | null,
    tenantScope?: string[] | null,
    inherit?: boolean
  ): Promise<void> =>
    api
      .post(`/api/v1/roles/${roleId}/service-accounts`, {
        service_account_id: serviceAccountId,
        ...(resourceId ? { resource_id: resourceId } : {}),
        ...inheritField(inherit),
        // Same rule as the user and group paths — see `assignToUser`.
        ...(tenantScope && tenantScope.length > 0
          ? { tenant_scope: tenantScope }
          : {}),
      })
      .then(() => undefined),

  unassignFromServiceAccount: (
    roleId: string,
    serviceAccountId: string,
    resourceId?: string | null
  ): Promise<void> =>
    api
      .delete(
        `/api/v1/roles/${roleId}/service-accounts/${serviceAccountId}`,
        resourceId ? { params: { resource_id: resourceId } } : {}
      )
      .then(() => undefined),

  // ─── Changing `inherit` on an existing assignment ─────────────────────────

  /**
   * Change an assignment's `inherit` flag: **unassign, then assign again**.
   *
   * There is no update endpoint, and a second assign is refused with 409 by
   * design — `has_role` is `UNIQUE(in, out)`, so a subject holds a role once —
   * so the change is two calls, each of which flushes the subject's cached
   * decisions server-side. Between them the subject does not hold the role at
   * all; that is the cost of the model, stated in the confirmation that
   * precedes this call.
   *
   * What this never does is leave the subject without the role **silently**:
   *
   * - the unassign fails → nothing changed; the server's error is thrown as is;
   * - the new assign fails → the old assignment (same resource, same tenants,
   *   old flag) is assigned again, and an {@link AssignmentToggleError} with
   *   `restored: true` carries the server's refusal;
   * - that restore fails too → an {@link AssignmentToggleError} with
   *   `restored: false` says in as many words that the role was removed.
   */
  setAssignmentInherit: async (
    kind: AssignmentSubjectKind,
    roleId: string,
    subjectId: string,
    assignment: AssignmentScopeState,
    inherit: boolean
  ): Promise<void> => {
    const [unassign, assign] =
      kind === "user"
        ? [roleService.unassignFromUser, roleService.assignToUser]
        : kind === "group"
          ? [roleService.unassignFromGroup, roleService.assignToGroup]
          : [
              roleService.unassignFromServiceAccount,
              roleService.assignToServiceAccount,
            ];
    const was = assignmentInherits(assignment);

    await unassign(roleId, subjectId, assignment.resource_id);
    try {
      await assign(
        roleId,
        subjectId,
        assignment.resource_id,
        assignment.tenant_scope,
        inherit
      );
    } catch (err) {
      const reason = getApiErrorMessage(err, "the assignment was refused");
      try {
        await assign(
          roleId,
          subjectId,
          assignment.resource_id,
          assignment.tenant_scope,
          was
        );
      } catch (restoreErr) {
        throw new AssignmentToggleError(
          `The ${kind} no longer holds this role at this resource. It was ` +
            `unassigned so it could be assigned again with the new setting, ` +
            `that assignment was refused (${reason}), and putting the old one ` +
            `back failed too (${getApiErrorMessage(restoreErr, "unknown error")}). ` +
            `Assign the role again.`,
          false,
          err
        );
      }
      throw new AssignmentToggleError(
        `The change was refused and the assignment was restored as it was: ${reason}`,
        true,
        err
      );
    }
  },
};
