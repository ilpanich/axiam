import api from "@/lib/api";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface User {
  id: string;
  username: string;
  email: string;
  display_name?: string;
  is_active: boolean;
  mfa_enabled: boolean;
  email_verified: boolean;
  created_at: string;
  updated_at: string;
}

export interface MfaMethod {
  id: string;
  method_type: "totp" | "webauthn";
  name: string;
  created_at: string;
}

export interface PaginatedUsers {
  data: User[];
  total: number;
  page: number;
  per_page: number;
}

// ─── Request payloads ─────────────────────────────────────────────────────────

export interface CreateUserPayload {
  username: string;
  email: string;
  password: string;
  display_name?: string;
  is_active?: boolean;
}

export interface UpdateUserPayload {
  email?: string;
  display_name?: string;
  is_active?: boolean;
}

// ─── Group models ─────────────────────────────────────────────────────────────

export interface Group {
  id: string;
  name: string;
  description?: string;
  created_at: string;
}

export interface CreateGroupPayload {
  name: string;
  description?: string;
}

export type UpdateGroupPayload = Partial<CreateGroupPayload>;

// ─── Users service ────────────────────────────────────────────────────────────

export const userService = {
  list: (page = 1, perPage = 20, search = ""): Promise<PaginatedUsers> => {
    const params = new URLSearchParams({
      page: String(page),
      per_page: String(perPage),
    });
    if (search.trim()) params.set("search", search.trim());
    return api
      .get<PaginatedUsers>(`/api/v1/users?${params.toString()}`)
      .then((r) => r.data);
  },

  get: (userId: string): Promise<User> =>
    api.get<User>(`/api/v1/users/${userId}`).then((r) => r.data),

  create: (payload: CreateUserPayload): Promise<User> =>
    api.post<User>("/api/v1/users", payload).then((r) => r.data),

  update: (userId: string, payload: UpdateUserPayload): Promise<User> =>
    api.put<User>(`/api/v1/users/${userId}`, payload).then((r) => r.data),

  remove: (userId: string): Promise<void> =>
    api.delete(`/api/v1/users/${userId}`).then(() => undefined),

  listMfaMethods: (userId: string): Promise<MfaMethod[]> =>
    api
      .get<MfaMethod[]>(`/api/v1/users/${userId}/mfa-methods`)
      .then((r) => r.data),

  deleteMfaMethod: (userId: string, methodId: string): Promise<void> =>
    api
      .delete(`/api/v1/users/${userId}/mfa-methods/${methodId}`)
      .then(() => undefined),

  resetMfa: (userId: string): Promise<void> =>
    api.post(`/api/v1/users/${userId}/reset-mfa`).then(() => undefined),
};

// ─── Groups service ───────────────────────────────────────────────────────────

export const groupService = {
  list: (): Promise<Group[]> =>
    api.get<Group[]>("/api/v1/groups").then((r) => r.data),

  get: (groupId: string): Promise<Group> =>
    api.get<Group>(`/api/v1/groups/${groupId}`).then((r) => r.data),

  create: (payload: CreateGroupPayload): Promise<Group> =>
    api.post<Group>("/api/v1/groups", payload).then((r) => r.data),

  update: (groupId: string, payload: UpdateGroupPayload): Promise<Group> =>
    api
      .put<Group>(`/api/v1/groups/${groupId}`, payload)
      .then((r) => r.data),

  remove: (groupId: string): Promise<void> =>
    api.delete(`/api/v1/groups/${groupId}`).then(() => undefined),

  listMembers: (groupId: string): Promise<User[]> =>
    api
      .get<User[]>(`/api/v1/groups/${groupId}/members`)
      .then((r) => r.data),

  addMember: (groupId: string, userId: string): Promise<void> =>
    api
      .post(`/api/v1/groups/${groupId}/members`, { user_id: userId })
      .then(() => undefined),

  removeMember: (groupId: string, userId: string): Promise<void> =>
    api
      .delete(`/api/v1/groups/${groupId}/members/${userId}`)
      .then(() => undefined),
};
