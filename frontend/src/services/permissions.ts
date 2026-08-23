import api from "@/lib/api";
import { fetchAllPages } from "@/services/_pagination";

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

/**
 * Whether a permission grants materially more than its name suggests, and
 * should be visually marked before an operator grants it.
 *
 * Keyed off the backend description carrying `WARNING:` rather than a
 * hard-coded list of actions. The registry
 * (`crates/axiam-api-rest/src/permissions.rs`) is where the security argument
 * for each of these lives — `scim:provision` confers tenant-wide account
 * takeover because RFC 7643 makes `password` a writable SCIM attribute, which
 * no native `users:*` permission allows — and a list here would be a second
 * copy of that judgement, drifting from the first the moment a permission is
 * added.
 *
 * Case-insensitive so a future registry entry that writes "Warning:" is not
 * silently un-flagged.
 */
export function isElevatedPermission(permission: Permission): boolean {
  return (permission.description ?? "").toUpperCase().includes("WARNING:");
}

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
  /**
   * Every permission in the tenant, registry-seeded and operator-created alike.
   *
   * Paged to the end rather than taking the server's default first page: the
   * seeded registry alone is larger than that page, so a single request never
   * reaches a permission an operator added.
   */
  list: (): Promise<Permission[]> => fetchAllPages<Permission>("/api/v1/permissions"),

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
