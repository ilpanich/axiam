import {
  SEGMENT_KINDS,
  SERVICE_TYPES,
  TERMINATION_ACTIONS,
  type CreateNetworkSegmentRequest,
  type NetworkReplyProfile,
  type NetworkReplyProfileInput,
  type NetworkSegment,
  type ReplaceNetworkSegmentRequest,
  type SegmentKind,
  type ServiceType,
  type TerminationAction,
} from "@/services/network";

function isKnown<T extends string>(all: readonly T[], value: string | null | undefined): value is T {
  return value != null && (all as readonly string[]).includes(value);
}

/** `kind` is open on the way out: anything but `quarantine` is shown as access. */
export function segmentKindOf(segment: Pick<NetworkSegment, "kind">): SegmentKind {
  return isKnown(SEGMENT_KINDS, segment.kind) ? segment.kind : "access";
}

// ─── Segment form ─────────────────────────────────────────────────────────────

export interface SegmentFormState {
  kind: SegmentKind;
  siteKey: string;
  name: string;
  vlanId: string;
  rank: string;
  /** Names separated by commas, spaces or new lines. */
  filterIds: string;
  enabled: boolean;
}

export const EMPTY_SEGMENT_FORM: SegmentFormState = {
  kind: "access",
  siteKey: "default",
  name: "",
  vlanId: "",
  rank: "",
  filterIds: "",
  enabled: true,
};

export function segmentFormFrom(segment: NetworkSegment): SegmentFormState {
  return {
    kind: segmentKindOf(segment),
    siteKey: segment.site_key,
    name: segment.name,
    vlanId: String(segment.vlan_id),
    rank: segment.rank == null ? "" : String(segment.rank),
    filterIds: segment.filter_ids.join(", "),
    enabled: segment.enabled,
  };
}

/** Split a typed list into names; duplicates are kept for the server to judge. */
export function parseFilterIds(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** A whole number written in digits only; anything else is `null`. */
export function parseWholeNumber(raw: string): number | null {
  const t = raw.trim();
  return /^\d{1,9}$/.test(t) ? Number(t) : null;
}

export type FormResult<T> = { ok: true; body: T } | { ok: false; error: string };

/**
 * The members the body cannot be built without — nothing else. A VLAN outside
 * 1–4094, a name that breaks the pattern, a duplicate rank: all the server's to
 * refuse (§36.3 rule 5), and its sentence is shown as it comes.
 */
function segmentShape(form: SegmentFormState): FormResult<{ vlan: number; rank?: number }> {
  const vlan = parseWholeNumber(form.vlanId);
  if (vlan === null) return { ok: false, error: "VLAN must be a whole number." };
  if (form.kind === "quarantine") return { ok: true, body: { vlan } };
  const rank = parseWholeNumber(form.rank);
  if (rank === null) {
    return { ok: false, error: "An access segment needs a rank (a whole number)." };
  }
  return { ok: true, body: { vlan, rank } };
}

export function createSegmentBody(
  form: SegmentFormState,
): FormResult<CreateNetworkSegmentRequest> {
  if (!form.name.trim()) return { ok: false, error: "Name is required." };
  if (!form.siteKey.trim()) return { ok: false, error: "Site is required." };
  const shape = segmentShape(form);
  if (!shape.ok) return shape;
  return {
    ok: true,
    body: {
      kind: form.kind,
      site_key: form.siteKey.trim(),
      name: form.name.trim(),
      vlan_id: shape.body.vlan,
      filter_ids: parseFilterIds(form.filterIds),
      ...(shape.body.rank !== undefined ? { rank: shape.body.rank } : {}),
      enabled: form.enabled,
    },
  };
}

/** A replacement: every member, and the `version` the form was opened from. */
export function replaceSegmentBody(
  form: SegmentFormState,
  version: number,
): FormResult<ReplaceNetworkSegmentRequest> {
  const shape = segmentShape(form);
  if (!shape.ok) return shape;
  return {
    ok: true,
    body: {
      version,
      vlan_id: shape.body.vlan,
      filter_ids: parseFilterIds(form.filterIds),
      ...(shape.body.rank !== undefined ? { rank: shape.body.rank } : {}),
      enabled: form.enabled,
    },
  };
}

// ─── Reply profile form ───────────────────────────────────────────────────────

export interface ProfileFormState {
  sessionTimeout: string;
  idleTimeout: string;
  filterId: string;
  serviceType: ServiceType | "";
  terminationAction: TerminationAction;
}

export function emptyProfileForm(cap: number): ProfileFormState {
  return {
    sessionTimeout: String(cap),
    idleTimeout: "",
    filterId: "",
    serviceType: "",
    terminationAction: "radius_request",
  };
}

/**
 * The stored profile as form state. A value this build does not know (the
 * enumerations are open on the way out) is shown as unset, and is therefore not
 * re-sent — "never re-sends one it decoded as unknown" (§36.2).
 */
export function profileFormFrom(profile: NetworkReplyProfile): ProfileFormState {
  return {
    sessionTimeout: String(profile.session_timeout_secs),
    idleTimeout: profile.idle_timeout_secs == null ? "" : String(profile.idle_timeout_secs),
    filterId: profile.filter_id ?? "",
    serviceType: isKnown(SERVICE_TYPES, profile.service_type) ? profile.service_type : "",
    terminationAction: isKnown(TERMINATION_ACTIONS, profile.termination_action)
      ? profile.termination_action
      : "radius_request",
  };
}

/** The profile as written. Optional members are omitted, never sent as `null`. */
export function profileInputFrom(
  form: ProfileFormState,
): FormResult<NetworkReplyProfileInput> {
  const session = parseWholeNumber(form.sessionTimeout);
  if (session === null) {
    return { ok: false, error: "Session-Timeout must be a whole number of seconds." };
  }
  const idleRaw = form.idleTimeout.trim();
  const idle = idleRaw === "" ? undefined : parseWholeNumber(idleRaw);
  if (idle === null) {
    return { ok: false, error: "Idle-Timeout must be a whole number of seconds, or empty." };
  }
  return {
    ok: true,
    body: {
      session_timeout_secs: session,
      termination_action: form.terminationAction,
      ...(idle !== undefined ? { idle_timeout_secs: idle } : {}),
      ...(form.filterId ? { filter_id: form.filterId } : {}),
      ...(form.serviceType ? { service_type: form.serviceType } : {}),
    },
  };
}

/** `3600` as "1 h", `5400` as "1 h 30 min": for hints, never for the wire. */
export function describeSeconds(secs: number): string {
  if (secs < 60) return `${secs} s`;
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  const parts = [h ? `${h} h` : "", m ? `${m} min` : "", s ? `${s} s` : ""].filter(Boolean);
  return parts.join(" ");
}
