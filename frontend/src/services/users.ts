import api from "@/lib/api";
import { unwrapList } from "@/services/_pagination";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface User {
  id: string;
  username: string;
  email: string;
  display_name?: string;
  mfa_enabled: boolean;
  email_verified: boolean;
  created_at: string;
  updated_at: string;
  /** Backend `UserStatus` enum, serialized PascalCase ("Active", "Inactive", …). */
  status: string;
  /** Raw backend metadata; `display_name` is routed through this column. */
  metadata?: Record<string, unknown>;
  is_locked: boolean;
  locked_until: string | null;
  failed_login_attempts: number;
}

/** Backend `UserResponse` shape (no `display_name` column; it lives in `metadata`). */
interface UserResponseDto extends Omit<User, "display_name"> {
  metadata?: Record<string, unknown>;
}

/**
 * Lift `display_name` out of the backend `metadata` blob into a top-level field
 * so the UI can keep reading `user.display_name` unchanged.
 */
function mapUserFromApi(u: UserResponseDto): User {
  const displayName = u.metadata?.display_name;
  return {
    ...u,
    display_name: typeof displayName === "string" ? displayName : undefined,
  };
}

export interface MfaMethod {
  id: string;
  method_type: "totp" | "webauthn";
  name: string;
  created_at: string;
}

export interface PaginatedUsers {
  items: User[];
  total: number;
  offset: number;
  limit: number;
}

// ─── Request payloads ─────────────────────────────────────────────────────────

export interface CreateUserPayload {
  username: string;
  email: string;
  password: string;
  /** UI-only convenience; routed into `metadata.display_name` by the service. */
  display_name?: string;
}

export interface UpdateUserPayload {
  email?: string;
  /** UI-only convenience; routed into `metadata.display_name` by the service. */
  display_name?: string;
  /** Backend `UserStatus`, e.g. "Active" / "Inactive". */
  status?: string;
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
  /** Backend `CreateGroupRequest.description` is a required String. */
  description: string;
}

export type UpdateGroupPayload = Partial<CreateGroupPayload>;

// ─── Users service ────────────────────────────────────────────────────────────

export const userService = {
  /**
   * List users. The backend paginates via `offset`/`limit` (Pagination is
   * `#[serde(default)]` offset/limit) and performs NO server-side search,
   * so `search` is applied client-side to the returned page rather than
   * sent as an unsupported query param.
   */
  list: (page = 1, perPage = 20, search = ""): Promise<PaginatedUsers> => {
    const params = new URLSearchParams({
      offset: String((page - 1) * perPage),
      limit: String(perPage),
    });
    return api
      .get<{ items: UserResponseDto[]; total: number; offset: number; limit: number }>(
        `/api/v1/users?${params.toString()}`
      )
      .then((r) => {
        const mapped: PaginatedUsers = {
          ...r.data,
          items: r.data.items.map(mapUserFromApi),
        };
        const term = search.trim().toLowerCase();
        if (!term) return mapped;
        const items = mapped.items.filter(
          (u) =>
            u.username.toLowerCase().includes(term) ||
            u.email.toLowerCase().includes(term) ||
            (u.display_name?.toLowerCase().includes(term) ?? false)
        );
        return { ...mapped, items };
      });
  },

  get: (userId: string): Promise<User> =>
    api
      .get<UserResponseDto>(`/api/v1/users/${userId}`)
      .then((r) => mapUserFromApi(r.data)),

  create: (payload: CreateUserPayload): Promise<User> => {
    const { display_name, ...rest } = payload;
    const body = {
      ...rest,
      ...(display_name ? { metadata: { display_name } } : {}),
    };
    return api
      .post<UserResponseDto>("/api/v1/users", body)
      .then((r) => mapUserFromApi(r.data));
  },

  update: (userId: string, payload: UpdateUserPayload): Promise<User> => {
    const { display_name, ...rest } = payload;
    const body = {
      ...rest,
      ...(display_name !== undefined ? { metadata: { display_name } } : {}),
    };
    return api
      .put<UserResponseDto>(`/api/v1/users/${userId}`, body)
      .then((r) => mapUserFromApi(r.data));
  },

  remove: (userId: string): Promise<void> =>
    api.delete(`/api/v1/users/${userId}`).then(() => undefined),

  listMfaMethods: (userId: string): Promise<MfaMethod[]> =>
    api
      .get<MfaMethod[] | { items: MfaMethod[] }>(`/api/v1/users/${userId}/mfa-methods`)
      .then((r) => unwrapList(r.data)),

  deleteMfaMethod: (userId: string, methodId: string): Promise<void> =>
    api
      .delete(`/api/v1/users/${userId}/mfa-methods/${methodId}`)
      .then(() => undefined),

  resetMfa: (userId: string): Promise<void> =>
    api.post(`/api/v1/users/${userId}/reset-mfa`).then(() => undefined),

  unlock: (userId: string): Promise<User> =>
    api
      .post<UserResponseDto>(`/api/v1/users/${userId}/unlock`)
      .then((r) => mapUserFromApi(r.data)),
};

// ─── Groups service ───────────────────────────────────────────────────────────

export const groupService = {
  list: (): Promise<Group[]> =>
    api
      .get<Group[] | { items: Group[] }>("/api/v1/groups")
      .then((r) => unwrapList(r.data)),

  get: (groupId: string): Promise<Group> =>
    api.get<Group>(`/api/v1/groups/${groupId}`).then((r) => r.data),

  create: (payload: CreateGroupPayload): Promise<Group> =>
    api
      .post<Group>("/api/v1/groups", {
        ...payload,
        // Backend requires a String; never send undefined/null.
        description: payload.description ?? "",
      })
      .then((r) => r.data),

  update: (groupId: string, payload: UpdateGroupPayload): Promise<Group> =>
    api
      .put<Group>(`/api/v1/groups/${groupId}`, payload)
      .then((r) => r.data),

  remove: (groupId: string): Promise<void> =>
    api.delete(`/api/v1/groups/${groupId}`).then(() => undefined),

  listMembers: (groupId: string): Promise<User[]> =>
    api
      .get<UserResponseDto[] | { items: UserResponseDto[] }>(
        `/api/v1/groups/${groupId}/members`
      )
      .then((r) => unwrapList(r.data).map(mapUserFromApi)),

  addMember: (groupId: string, userId: string): Promise<void> =>
    api
      .post(`/api/v1/groups/${groupId}/members`, { user_id: userId })
      .then(() => undefined),

  removeMember: (groupId: string, userId: string): Promise<void> =>
    api
      .delete(`/api/v1/groups/${groupId}/members/${userId}`)
      .then(() => undefined),
};
