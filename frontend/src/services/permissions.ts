import api from "@/lib/api";
import { unwrapList } from "@/services/_pagination";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface Permission {
  id: string;
  action: string;
  description?: string;
  created_at: string;
}

/**
 * Whether a grant permits an action or refuses it (B1, deny-override).
 *
 * A `deny` grant overrides **every** allow, at any depth of the resource
 * hierarchy and at equal specificity. It is not most-specific-wins, and the UI
 * has to make that legible: a deny is not "a red allow", it is the rule that
 * beats all of them.
 */
export type PermissionEffect = "allow" | "deny";

/** A permission together with its scope constraints, as returned by role grants. */
export interface PermissionGrant {
  permission: Permission;
  scope_ids: string[];
  /** Absent on grants written before deny-override shipped; absent means allow. */
  effect?: PermissionEffect;
}

export interface CreatePermissionPayload {
  action: string;
  description: string;
}

export type UpdatePermissionPayload = Partial<CreatePermissionPayload>;

// ─── Permissions service ──────────────────────────────────────────────────────

export const permissionService = {
  list: (): Promise<Permission[]> =>
    api
      .get<Permission[] | { items: Permission[] }>("/api/v1/permissions")
      .then((r) => unwrapList(r.data)),

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
