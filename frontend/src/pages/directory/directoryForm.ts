import {
  connectionMoved,
  type ConnectionFields,
  type DirectoryConfig,
  type DirectoryKind,
  type GroupMapping,
  type SetDirectoryConfigPayload,
  type UpdateDirectoryConfigPayload,
  type UserAttributeMap,
} from "@/services/directory";

/**
 * The directory form's local model, and everything that converts it to and from
 * the wire.
 *
 * Kept out of the page so the three rules that are easy to get subtly wrong are
 * testable without rendering anything:
 *
 * 1. **The secret is never part of a stored value.** The form holds
 *    {@link DirectoryForm.bindSecret} as the empty string until somebody types
 *    one, and {@link formFromConfig} never seeds it — the server returns none.
 * 2. **Moving the connection needs the secret again** ({@link secretRequired}).
 * 3. **Untouched trust anchors are sent back byte for byte**
 *    ({@link currentAnchors}), so opening the form and saving a filter change
 *    does not look like an anchor change to the server (P23W2-01 compares the
 *    stored strings exactly).
 *
 * None of the checks here is the authority. The server validates every write
 * (`axiam_directory::config::validate`) and holds the host to the deployment's
 * address policy; these only turn a `400`-after-submit into a message at the
 * field, for the mistakes that need no network to detect.
 */

export const GROUP_MAPPINGS_MAX = 500;
export const TRUST_ANCHORS_MAX = 16;
export const BIND_SECRET_MAX_LEN = 4096;
export const NESTING_DEPTH_MAX = 10;
export const SYNC_INTERVAL_MIN_SECS = 300;
export const SYNC_INTERVAL_MAX_SECS = 86_400;
export const SYNC_INTERVAL_DEFAULT_SECS = 3_600;
export const NESTING_DEPTH_DEFAULT = 5;

/** The per-kind defaults the server applies to an omitted member. */
export function kindDefaults(kind: DirectoryKind): {
  attributes: UserAttributeMap;
  groupMemberAttribute: string;
} {
  const ad = kind === "active_directory";
  return {
    attributes: {
      username: ad ? "sAMAccountName" : "uid",
      email: "mail",
      display_name: "displayName",
      external_id: ad ? "objectGUID" : "entryUUID",
    },
    groupMemberAttribute: ad ? "memberOf" : "member",
  };
}

export interface MappingRow {
  /** Stable React key; not sent. */
  key: string;
  dn: string;
  groupId: string;
}

export interface DirectoryForm {
  enabled: boolean;
  kind: DirectoryKind;
  url: string;
  startTls: boolean;
  bindDn: string;
  /** Write-only. Empty means "enter nothing": keep the stored secret. */
  bindSecret: string;
  baseDn: string;
  userFilter: string;
  attrUsername: string;
  attrEmail: string;
  attrDisplayName: string;
  attrExternalId: string;
  groupBaseDn: string;
  groupFilter: string;
  groupMemberAttribute: string;
  groupNestingDepth: string;
  syncIntervalSecs: string;
  jitProvisioning: boolean;
  /** One PEM certificate after another. */
  anchorsText: string;
  /** What `anchorsText` was seeded from, to tell "untouched" from "retyped". */
  anchorsOriginal: string[];
  mappings: MappingRow[];
}

let rowCounter = 0;
export function newMappingRow(dn = "", groupId = ""): MappingRow {
  rowCounter += 1;
  return { key: `mapping-${rowCounter}`, dn, groupId };
}

export function anchorsToText(anchors: string[]): string {
  return anchors.map((pem) => pem.trim()).join("\n\n");
}

const PEM_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

/**
 * The certificates in `text`, one string each, in order, each ending in a
 * newline (the shape the server stores them in). Anything that is not a
 * `CERTIFICATE` block is dropped here and caught by the server's validation
 * only if nothing else is left, so {@link validateForm} also compares counts.
 */
export function parseAnchors(text: string): string[] {
  return (text.match(PEM_BLOCK) ?? []).map((block) => `${block.trim()}\n`);
}

/** Whether `text` holds something that is not a certificate block. */
function hasStrayAnchorText(text: string): boolean {
  return text.replace(PEM_BLOCK, "").trim().length > 0;
}

/**
 * The trust anchors the form currently describes. **Untouched text yields the
 * original strings exactly**, which is what keeps an unrelated edit from
 * reading as a moved connection.
 */
export function currentAnchors(form: DirectoryForm): string[] {
  if (form.anchorsText === anchorsToText(form.anchorsOriginal)) {
    return form.anchorsOriginal;
  }
  return parseAnchors(form.anchorsText);
}

export function emptyForm(kind: DirectoryKind = "open_ldap"): DirectoryForm {
  const defaults = kindDefaults(kind);
  return {
    enabled: true,
    kind,
    url: "ldaps://",
    startTls: false,
    bindDn: "",
    bindSecret: "",
    baseDn: "",
    userFilter: kind === "active_directory" ? "(sAMAccountName={username})" : "(uid={username})",
    attrUsername: defaults.attributes.username,
    attrEmail: defaults.attributes.email,
    attrDisplayName: defaults.attributes.display_name,
    attrExternalId: defaults.attributes.external_id,
    groupBaseDn: "",
    groupFilter: "",
    groupMemberAttribute: defaults.groupMemberAttribute,
    groupNestingDepth: String(NESTING_DEPTH_DEFAULT),
    syncIntervalSecs: String(SYNC_INTERVAL_DEFAULT_SECS),
    jitProvisioning: false,
    anchorsText: "",
    anchorsOriginal: [],
    mappings: [],
  };
}

/** A form seeded from a stored configuration. The secret field stays empty. */
export function formFromConfig(config: DirectoryConfig): DirectoryForm {
  return {
    enabled: config.enabled,
    kind: (config.kind === "active_directory" ? "active_directory" : "open_ldap"),
    url: config.url,
    startTls: config.start_tls,
    bindDn: config.bind_dn,
    bindSecret: "",
    baseDn: config.base_dn,
    userFilter: config.user_filter,
    attrUsername: config.user_attribute_map.username,
    attrEmail: config.user_attribute_map.email,
    attrDisplayName: config.user_attribute_map.display_name,
    attrExternalId: config.user_attribute_map.external_id,
    groupBaseDn: config.group_base_dn ?? "",
    groupFilter: config.group_filter ?? "",
    groupMemberAttribute: config.group_member_attribute,
    groupNestingDepth: String(config.group_nesting_depth),
    syncIntervalSecs: String(config.sync_interval_secs),
    jitProvisioning: config.jit_provisioning,
    anchorsText: anchorsToText(config.trust_anchors_pem),
    anchorsOriginal: config.trust_anchors_pem,
    mappings: config.group_mappings.map((m) =>
      newMappingRow(m.directory_group_dn, m.group_id),
    ),
  };
}

/** The four members whose change makes a stored secret unusable. */
export function formConnection(form: DirectoryForm): ConnectionFields {
  return {
    url: form.url.trim(),
    start_tls: form.startTls,
    bind_dn: form.bindDn.trim(),
    trust_anchors_pem: currentAnchors(form),
  };
}

/**
 * Whether saving this form needs a bind secret: always for a new configuration,
 * and for an existing one as soon as the URL, StartTLS, bind DN or trust anchors
 * differ from what is stored (P23W2-01).
 */
export function secretRequired(
  stored: DirectoryConfig | null,
  form: DirectoryForm,
): boolean {
  if (stored === null) return true;
  return connectionMoved(stored, formConnection(form));
}

function wholeNumber(text: string): number | null {
  return /^\d+$/.test(text.trim()) ? Number(text.trim()) : null;
}

/**
 * The first mistake detectable without a network, or `null`. The server's
 * `validate` and address guard are the authority: this does not resolve a host,
 * look at a certificate or parse a DN.
 */
export function validateForm(
  stored: DirectoryConfig | null,
  form: DirectoryForm,
): string | null {
  const url = form.url.trim();
  if (!url) return "Enter the directory URL.";
  const ldaps = url.toLowerCase().startsWith("ldaps://");
  const ldap = url.toLowerCase().startsWith("ldap://");
  if (!ldaps && !ldap) return "The URL must start with ldaps:// or ldap://.";
  if (ldaps && form.startTls) {
    return "ldaps:// is already encrypted; turn StartTLS off.";
  }
  if (ldap && !form.startTls) {
    return "Plaintext ldap:// is refused: use ldaps://, or turn StartTLS on.";
  }
  if (!form.bindDn.trim()) return "Enter the bind DN.";
  if (!form.baseDn.trim()) return "Enter the base DN.";
  const placeholders = form.userFilter.split("{username}").length - 1;
  if (placeholders !== 1) {
    return "The user filter must contain {username} exactly once, e.g. (uid={username}).";
  }
  for (const [label, value] of [
    ["username", form.attrUsername],
    ["e-mail", form.attrEmail],
    ["display-name", form.attrDisplayName],
    ["external-id", form.attrExternalId],
    ["group member", form.groupMemberAttribute],
  ] as const) {
    if (!value.trim()) return `Enter the ${label} attribute.`;
  }
  const depth = wholeNumber(form.groupNestingDepth);
  if (depth === null || depth > NESTING_DEPTH_MAX) {
    return `Group nesting depth must be a whole number from 0 to ${NESTING_DEPTH_MAX}.`;
  }
  const interval = wholeNumber(form.syncIntervalSecs);
  if (
    interval === null ||
    interval < SYNC_INTERVAL_MIN_SECS ||
    interval > SYNC_INTERVAL_MAX_SECS
  ) {
    return `Sync interval must be between ${SYNC_INTERVAL_MIN_SECS} and ${SYNC_INTERVAL_MAX_SECS} seconds.`;
  }
  if (hasStrayAnchorText(form.anchorsText)) {
    return "Trust anchors must be PEM certificates (-----BEGIN CERTIFICATE----- … -----END CERTIFICATE-----).";
  }
  if (currentAnchors(form).length > TRUST_ANCHORS_MAX) {
    return `At most ${TRUST_ANCHORS_MAX} trust anchors.`;
  }
  if (form.mappings.length > GROUP_MAPPINGS_MAX) {
    return `At most ${GROUP_MAPPINGS_MAX} group mappings.`;
  }
  for (const [index, row] of form.mappings.entries()) {
    if (!row.dn.trim()) return `Group mapping #${index + 1}: enter the directory group's DN.`;
    if (!row.groupId) return `Group mapping #${index + 1}: choose an AXIAM group.`;
  }
  if (secretRequired(stored, form)) {
    if (form.bindSecret.length === 0) {
      return stored === null
        ? "Enter the bind secret."
        : "Enter the bind secret again: the URL, StartTLS, bind DN or trust anchors changed, and a stored secret is never sent to a connection it was not entered for.";
    }
  }
  if (form.bindSecret.length > BIND_SECRET_MAX_LEN) {
    return `The bind secret is at most ${BIND_SECRET_MAX_LEN} characters.`;
  }
  return null;
}

function attributeMap(form: DirectoryForm): UserAttributeMap {
  return {
    username: form.attrUsername.trim(),
    email: form.attrEmail.trim(),
    display_name: form.attrDisplayName.trim(),
    external_id: form.attrExternalId.trim(),
  };
}

function mappings(form: DirectoryForm): GroupMapping[] {
  return form.mappings.map((row) => ({
    directory_group_dn: row.dn.trim(),
    group_id: row.groupId,
  }));
}

/** `""` is "no value" for the two nullable members. */
function nullable(text: string): string | null {
  return text.trim() === "" ? null : text.trim();
}

/**
 * A complete `PUT` body: every member the form shows, so a replacement resets
 * nothing by omission. The secret is included only when one was typed.
 */
export function buildSetPayload(form: DirectoryForm): SetDirectoryConfigPayload {
  const payload: SetDirectoryConfigPayload = {
    enabled: form.enabled,
    kind: form.kind,
    url: form.url.trim(),
    start_tls: form.startTls,
    bind_dn: form.bindDn.trim(),
    base_dn: form.baseDn.trim(),
    user_filter: form.userFilter.trim(),
    user_attribute_map: attributeMap(form),
    group_base_dn: nullable(form.groupBaseDn),
    group_filter: nullable(form.groupFilter),
    group_member_attribute: form.groupMemberAttribute.trim(),
    group_nesting_depth: Number(form.groupNestingDepth.trim()),
    group_mappings: mappings(form),
    sync_interval_secs: Number(form.syncIntervalSecs.trim()),
    jit_provisioning: form.jitProvisioning,
    trust_anchors_pem: currentAnchors(form),
  };
  if (form.bindSecret.length > 0) payload.bind_secret = form.bindSecret;
  return payload;
}

/**
 * A sparse `PATCH` body: only the members that differ from `stored`, plus the
 * secret when one was typed. A nullable member cleared in the form is sent as an
 * explicit `null` ("null is not absent"); an untouched one is not sent at all.
 */
export function buildUpdatePayload(
  stored: DirectoryConfig,
  form: DirectoryForm,
): UpdateDirectoryConfigPayload {
  const patch: UpdateDirectoryConfigPayload = {};
  const next = buildSetPayload(form);
  if (next.enabled !== stored.enabled) patch.enabled = next.enabled;
  if (next.kind !== stored.kind) patch.kind = next.kind;
  if (next.url !== stored.url) patch.url = next.url;
  if (next.start_tls !== stored.start_tls) patch.start_tls = next.start_tls;
  if (next.bind_dn !== stored.bind_dn) patch.bind_dn = next.bind_dn;
  if (next.base_dn !== stored.base_dn) patch.base_dn = next.base_dn;
  if (next.user_filter !== stored.user_filter) patch.user_filter = next.user_filter;
  const map = next.user_attribute_map!;
  const was = stored.user_attribute_map;
  if (
    map.username !== was.username ||
    map.email !== was.email ||
    map.display_name !== was.display_name ||
    map.external_id !== was.external_id
  ) {
    patch.user_attribute_map = map;
  }
  if (next.group_base_dn !== stored.group_base_dn) patch.group_base_dn = next.group_base_dn;
  if (next.group_filter !== stored.group_filter) patch.group_filter = next.group_filter;
  if (next.group_member_attribute !== stored.group_member_attribute) {
    patch.group_member_attribute = next.group_member_attribute;
  }
  if (next.group_nesting_depth !== stored.group_nesting_depth) {
    patch.group_nesting_depth = next.group_nesting_depth;
  }
  if (JSON.stringify(next.group_mappings) !== JSON.stringify(stored.group_mappings)) {
    patch.group_mappings = next.group_mappings;
  }
  if (next.sync_interval_secs !== stored.sync_interval_secs) {
    patch.sync_interval_secs = next.sync_interval_secs;
  }
  if (next.jit_provisioning !== stored.jit_provisioning) {
    patch.jit_provisioning = next.jit_provisioning;
  }
  const anchors = next.trust_anchors_pem!;
  if (
    anchors.length !== stored.trust_anchors_pem.length ||
    anchors.some((pem, i) => pem !== stored.trust_anchors_pem[i])
  ) {
    patch.trust_anchors_pem = anchors;
  }
  if (next.bind_secret !== undefined) patch.bind_secret = next.bind_secret;
  return patch;
}
