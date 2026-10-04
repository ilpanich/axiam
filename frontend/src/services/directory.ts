import api from "@/lib/api";

/**
 * Tenant directory (LDAP / Active Directory) client (G-3, T23.3.8).
 *
 * Source of truth for every shape below: contract §30
 * (`sdks/CONTRACT.md`, "Directory configuration") and the handler
 * `crates/axiam-api-rest/src/handlers/directory.rs`.
 *
 * # The bind secret
 *
 * `bind_secret` is **write-only**. It exists on the two request payloads below
 * and on nothing the server returns: no response type here has a member for it,
 * a flag that says one is set, or a hash of it — and none may ever be added. The
 * console therefore cannot show "a secret is set", and does not pre-fill the
 * field when it edits. (Contract §30.2, D-15.)
 */

// ─── Domain types ─────────────────────────────────────────────────────────────

/**
 * Chooses defaults only. The server treats the set as open on the way out (an
 * SDK must decode an unknown value without failing), so a read is typed
 * `string` and only a write is held to these two.
 */
export const DIRECTORY_KINDS = ["open_ldap", "active_directory"] as const;
export type DirectoryKind = (typeof DIRECTORY_KINDS)[number];

export const DIRECTORY_KIND_LABELS: Record<DirectoryKind, string> = {
  open_ldap: "OpenLDAP / other LDAP (RFC 4519)",
  active_directory: "Microsoft Active Directory",
};

/** Mirrors `UserAttributeMap`: which directory attribute feeds which field. */
export interface UserAttributeMap {
  username: string;
  email: string;
  display_name: string;
  external_id: string;
}

/** One row of the group-mapping table (D-30). */
export interface GroupMapping {
  directory_group_dn: string;
  /** An AXIAM group of this tenant. */
  group_id: string;
}

/** What every read and write returns. **No secret, flag or hash of one.** */
export interface DirectoryConfig {
  id: string;
  tenant_id: string;
  enabled: boolean;
  /** Open on the way out: render an unknown value as it is. */
  kind: string;
  url: string;
  start_tls: boolean;
  bind_dn: string;
  base_dn: string;
  user_filter: string;
  user_attribute_map: UserAttributeMap;
  group_base_dn: string | null;
  group_filter: string | null;
  group_member_attribute: string;
  group_nesting_depth: number;
  group_mappings: GroupMapping[];
  sync_interval_secs: number;
  jit_provisioning: boolean;
  trust_anchors_pem: string[];
  created_at: string;
  updated_at: string;
}

/** `directory.set` — a replacement. An omitted optional member resets to its default. */
export interface SetDirectoryConfigPayload {
  enabled: boolean;
  kind: DirectoryKind;
  url: string;
  start_tls: boolean;
  bind_dn: string;
  /**
   * Required when the tenant has no configuration; on a replacement, absent
   * keeps the stored secret — unless the write moves the connection
   * ({@link connectionMoved}), which then requires it (`400`, P23W2-01).
   */
  bind_secret?: string;
  base_dn: string;
  user_filter: string;
  user_attribute_map?: UserAttributeMap;
  group_base_dn?: string | null;
  group_filter?: string | null;
  group_member_attribute?: string;
  group_nesting_depth?: number;
  group_mappings?: GroupMapping[];
  sync_interval_secs?: number;
  jit_provisioning?: boolean;
  trust_anchors_pem?: string[];
}

/**
 * `directory.update` — sparse. Absent leaves the stored value; for the two
 * nullable members an explicit `null` clears it ("null is not absent").
 */
export interface UpdateDirectoryConfigPayload {
  enabled?: boolean;
  kind?: DirectoryKind;
  url?: string;
  start_tls?: boolean;
  bind_dn?: string;
  bind_secret?: string;
  base_dn?: string;
  user_filter?: string;
  user_attribute_map?: UserAttributeMap;
  group_base_dn?: string | null;
  group_filter?: string | null;
  group_member_attribute?: string;
  group_nesting_depth?: number;
  group_mappings?: GroupMapping[];
  sync_interval_secs?: number;
  jit_provisioning?: boolean;
  trust_anchors_pem?: string[];
}

/** `directory.link_account` response. */
export interface DirectoryLinkResult {
  user_id: string;
  /** The entry's `entryUUID` / `objectGUID` as text — an identifier, not a secret. */
  directory_external_id: string;
  webauthn_credentials_deleted: number;
  certificates_revoked: number;
  /** `true` when the account was already linked to that entry and only the revocations re-ran. */
  was_already_linked: boolean;
}

/** The results the server names today. The set is open: show another value as it is. */
export const KNOWN_SYNC_RESULTS = ["ok", "partial", "failed", "safety_valve"] as const;

/** `directory.get_sync_status` response. Nulls before the first run. */
export interface DirectorySyncStatus {
  /** One of {@link KNOWN_SYNC_RESULTS}, or another value the server added; null before the first run. */
  last_result: string | null;
  last_attempt_at: string | null;
  last_full_run_at: string | null;
  full_required: boolean;
  has_watermark: boolean;
}

// ─── The P23W2-01 rule ────────────────────────────────────────────────────────

/** The members that decide where, and how, the service bind goes. */
export interface ConnectionFields {
  url: string;
  start_tls: boolean;
  bind_dn: string;
  trust_anchors_pem: string[];
}

/**
 * Whether `next` moves the connection `stored` describes: the URL, StartTLS, the
 * bind DN or the trust anchors (CONTRACT §30.3 rule 2).
 *
 * The server refuses such a write without the bind secret (`400`) because a kept
 * secret sent to a new host, through a trust anchor the editor chose, is the
 * secret handed to whoever runs that host. The console asks for the secret
 * **again** the moment this turns true, instead of letting a save fail. The
 * comparison is the server's: exact, with the anchors compared as lists in order.
 * It is a convenience, not the check — the server re-checks against the stored
 * row in the same statement as the write.
 */
export function connectionMoved(
  stored: ConnectionFields,
  next: ConnectionFields,
): boolean {
  return (
    stored.url !== next.url ||
    stored.start_tls !== next.start_tls ||
    stored.bind_dn !== next.bind_dn ||
    anchorsDiffer(stored.trust_anchors_pem, next.trust_anchors_pem)
  );
}

function anchorsDiffer(a: string[], b: string[]): boolean {
  return a.length !== b.length || a.some((pem, i) => pem !== b[i]);
}

/** Names of the connection members that differ, for the "enter the secret again" notice. */
export function movedConnectionFields(
  stored: ConnectionFields,
  next: ConnectionFields,
): string[] {
  const moved: string[] = [];
  if (stored.url !== next.url) moved.push("URL");
  if (stored.start_tls !== next.start_tls) moved.push("StartTLS");
  if (stored.bind_dn !== next.bind_dn) moved.push("bind DN");
  if (anchorsDiffer(stored.trust_anchors_pem, next.trust_anchors_pem)) {
    moved.push("trust anchors");
  }
  return moved;
}

// ─── Service ──────────────────────────────────────────────────────────────────

/** A singleton that was never configured answers 404: a value, not an error. */
function nullOn404(err: unknown): null {
  const status = (err as { response?: { status?: number } })?.response?.status;
  if (status === 404) return null;
  throw err;
}

const base = (tenantId: string) => `/api/v1/tenants/${tenantId}/directory`;

export const directoryService = {
  /** `null` when the tenant has no configuration yet. */
  get: (tenantId: string): Promise<DirectoryConfig | null> =>
    api
      .get<DirectoryConfig>(base(tenantId))
      .then((r) => r.data)
      .catch(nullOn404),

  /** Create or **replace** (`201` or `200`). */
  set: (
    tenantId: string,
    payload: SetDirectoryConfigPayload,
  ): Promise<DirectoryConfig> =>
    api.put<DirectoryConfig>(base(tenantId), payload).then((r) => r.data),

  /** A sparse edit. */
  update: (
    tenantId: string,
    payload: UpdateDirectoryConfigPayload,
  ): Promise<DirectoryConfig> =>
    api.patch<DirectoryConfig>(base(tenantId), payload).then((r) => r.data),

  /**
   * Remove the configuration and its sync state. Directory accounts can no
   * longer sign in with a password, and keep any session or passkey they hold
   * until it expires or an administrator deactivates them. There is no unlink.
   */
  remove: (tenantId: string): Promise<void> =>
    api.delete(base(tenantId)).then(() => undefined),

  /**
   * Link an existing local account to its directory entry (D-28). The directory
   * finds the entry from the account's own username; the caller names none.
   * **Signs the owner out everywhere.**
   */
  linkAccount: (
    tenantId: string,
    userId: string,
  ): Promise<DirectoryLinkResult> =>
    api
      .post<DirectoryLinkResult>(`${base(tenantId)}/links`, { user_id: userId })
      .then((r) => r.data),

  /** `null` when the tenant has no configuration (the route answers 404). */
  getSyncStatus: (tenantId: string): Promise<DirectorySyncStatus | null> =>
    api
      .get<DirectorySyncStatus>(`${base(tenantId)}/sync-status`)
      .then((r) => r.data)
      .catch(nullOn404),
};
