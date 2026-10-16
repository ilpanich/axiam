import api from "@/lib/api";
import { fetchAllPages } from "@/services/_pagination";

/**
 * Network access administration client (RADIUS D4, W6.8).
 *
 * Source of truth for every shape below: contract §36 (`sdks/CONTRACT.md`,
 * "Network segments, reply profiles and the RADIUS decision"),
 * `sdks/openapi.json` (tag `network`) and the handler
 * `crates/axiam-api-rest/src/handlers/network.rs`.
 *
 * # What is deliberately absent
 *
 * - **No call to `POST /api/v1/network/decide`.** The decision route is
 *   FreeRADIUS's (`network:decide` on a service account), not console surface
 *   (§36.11). `apiRoutes.test.ts` and `network.test.ts` both pin that nothing
 *   here reaches it.
 * - **No client-side copy of the server's bounds.** VLAN range, the timeout
 *   floors and the tenant cap are the server's to check (§36.3 rule 5); the
 *   console shows the numbers as hints and prints the server's refusal.
 * - **No retry of a write.** A stale version is a `409` the administrator
 *   decides on (§36.7, §36.9).
 */

export const NETWORK_SEGMENTS_URL = "/api/v1/network/segments";
export const NETWORK_PROFILES_URL = "/api/v1/network/profiles";
export const NETWORK_POLICY_URL = "/api/v1/network/policy";

/** Pattern of a site key, a segment name and a `Filter-Id` (§36.2). */
export const NETWORK_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

/** Documented bounds, shown as hints only; the server is the authority. */
export const NETWORK_HINTS = {
  vlanMin: 1,
  vlanMax: 4094,
  filterIdsMax: 32,
  sessionTimeoutFloorSecs: 300,
  idleTimeoutFloorSecs: 60,
  capMinSecs: 300,
  capMaxSecs: 86_400,
  capDefaultSecs: 3600,
} as const;

// ─── Segments ─────────────────────────────────────────────────────────────────

export const SEGMENT_KINDS = ["access", "quarantine"] as const;
export type SegmentKind = (typeof SEGMENT_KINDS)[number];

export const SEGMENT_KIND_LABELS: Record<SegmentKind, string> = {
  access: "Access zones",
  quarantine: "Quarantine",
};

/** The branch of the reserved `/network` subtree a kind lives under. */
export const SEGMENT_KIND_BRANCH: Record<SegmentKind, string> = {
  access: "/network/zones",
  quarantine: "/network/quarantine",
};

/** What every segment read and write returns. `kind` is open on the way out. */
export interface NetworkSegment {
  id: string;
  tenant_id: string;
  path: string;
  name: string;
  site_key: string;
  kind: string;
  vlan_id: number;
  filter_ids: string[];
  rank?: number | null;
  enabled: boolean;
  version: number;
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
}

export interface CreateNetworkSegmentRequest {
  kind: SegmentKind;
  site_key: string;
  name: string;
  vlan_id: number;
  filter_ids: string[];
  /** Required for `access`, absent for `quarantine`. */
  rank?: number;
  enabled: boolean;
}

/** A replacement: kind, site and name do not change (§36.3 rule 4). */
export interface ReplaceNetworkSegmentRequest {
  version: number;
  vlan_id: number;
  filter_ids: string[];
  rank?: number;
  enabled: boolean;
}

// ─── Reply profile ────────────────────────────────────────────────────────────

/** The dictionary this console writes against. */
export const REPLY_DICTIONARY = "axiam-radius-reply/1";

/** `RadiusServiceType`: option B accepts only `framed_user`. */
export const SERVICE_TYPES = ["framed_user"] as const;
export type ServiceType = (typeof SERVICE_TYPES)[number];

export const SERVICE_TYPE_LABELS: Record<ServiceType, string> = {
  framed_user: "Framed-User",
};

/** `RadiusTerminationAction`. */
export const TERMINATION_ACTIONS = ["radius_request", "default"] as const;
export type TerminationAction = (typeof TERMINATION_ACTIONS)[number];

export const TERMINATION_ACTION_LABELS: Record<TerminationAction, string> = {
  radius_request: "RADIUS-Request (re-authenticate at the timeout)",
  default: "Default (disconnect at the timeout)",
};

/** The profile as read: the **effective** one, already clamped to the cap. */
export interface NetworkReplyProfile {
  segment_id: string;
  tenant_id: string;
  dictionary: string;
  session_timeout_secs: number;
  session_timeout_clamped: boolean;
  /** Open on the way out. */
  termination_action: string;
  idle_timeout_secs?: number | null;
  filter_id?: string | null;
  /** Open on the way out. */
  service_type?: string | null;
  version: number;
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
}

/** The profile as written. There is no VLAN member: it is the segment's. */
export interface NetworkReplyProfileInput {
  session_timeout_secs: number;
  termination_action: TerminationAction;
  idle_timeout_secs?: number;
  filter_id?: string;
  service_type?: ServiceType;
}

export interface CreateNetworkReplyProfileRequest {
  segment_id: string;
  segment_version: number;
  profile: NetworkReplyProfileInput;
}

export interface ReplaceNetworkReplyProfileRequest {
  version: number;
  segment_version: number;
  profile: NetworkReplyProfileInput;
}

// ─── Policy ───────────────────────────────────────────────────────────────────

export interface NetworkPolicy {
  tenant_id: string;
  session_timeout_max_secs: number;
  /** `0` until the tenant first writes one. */
  version: number;
  updated_by?: string | null;
  updated_at?: string | null;
}

export interface ReplaceNetworkPolicyRequest {
  session_timeout_max_secs: number;
  version: number;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const networkService = {
  /** Every segment of the tenant, optionally narrowed by `search` / `site`. */
  listSegments: (params?: { search?: string; site?: string }): Promise<NetworkSegment[]> =>
    fetchAllPages<NetworkSegment>(NETWORK_SEGMENTS_URL, params),

  createSegment: (body: CreateNetworkSegmentRequest): Promise<NetworkSegment> =>
    api.post<NetworkSegment>(NETWORK_SEGMENTS_URL, body).then((r) => r.data),

  replaceSegment: (id: string, body: ReplaceNetworkSegmentRequest): Promise<NetworkSegment> =>
    api.put<NetworkSegment>(`${NETWORK_SEGMENTS_URL}/${id}`, body).then((r) => r.data),

  /** `version` is required: a delete is conditional like every other write. */
  deleteSegment: (id: string, version: number): Promise<void> =>
    api
      .delete(`${NETWORK_SEGMENTS_URL}/${id}`, { params: { version } })
      .then(() => undefined),

  /** `404` when the segment has no profile. */
  getProfile: (segmentId: string): Promise<NetworkReplyProfile> =>
    api
      .get<NetworkReplyProfile>(`${NETWORK_PROFILES_URL}/${segmentId}`)
      .then((r) => r.data),

  createProfile: (body: CreateNetworkReplyProfileRequest): Promise<NetworkReplyProfile> =>
    api.post<NetworkReplyProfile>(NETWORK_PROFILES_URL, body).then((r) => r.data),

  replaceProfile: (
    segmentId: string,
    body: ReplaceNetworkReplyProfileRequest,
  ): Promise<NetworkReplyProfile> =>
    api
      .put<NetworkReplyProfile>(`${NETWORK_PROFILES_URL}/${segmentId}`, body)
      .then((r) => r.data),

  deleteProfile: (segmentId: string, version: number): Promise<void> =>
    api
      .delete(`${NETWORK_PROFILES_URL}/${segmentId}`, { params: { version } })
      .then(() => undefined),

  getPolicy: (): Promise<NetworkPolicy> =>
    api.get<NetworkPolicy>(NETWORK_POLICY_URL).then((r) => r.data),

  replacePolicy: (body: ReplaceNetworkPolicyRequest): Promise<NetworkPolicy> =>
    api.put<NetworkPolicy>(NETWORK_POLICY_URL, body).then((r) => r.data),
};
