import api from "@/lib/api";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface Role {
  id: string;
  name: string;
  description?: string;
  created_at: string;
}

// ─── Roles service ─────────────────────────────────────────────────────────────
// Partial implementation for T15.3 — full CRUD and permission management in T15.4.

export const roleService = {
  list: (): Promise<Role[]> =>
    api.get<Role[]>("/api/v1/roles").then((r) => r.data),

  assignToUser: (roleId: string, userId: string): Promise<void> =>
    api
      .post(`/api/v1/roles/${roleId}/users`, { user_id: userId })
      .then(() => undefined),

  unassignFromUser: (roleId: string, userId: string): Promise<void> =>
    api
      .delete(`/api/v1/roles/${roleId}/users/${userId}`)
      .then(() => undefined),
};
