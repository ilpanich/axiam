import api from "@/lib/api";
import { unwrapList } from "@/services/_pagination";

/**
 * Tenant WebAuthn attestation policy + compliance report client (X3 wave 4).
 *
 * Source of truth for every shape below: `crates/axiam-core/src/models/webauthn_policy.rs`
 * (the policy + `evaluate` decision function) and
 * `crates/axiam-api-rest/src/handlers/webauthn_policy.rs` (the DTOs actually
 * on the wire). `docs/admin/authenticator-policies.md` is authoritative for
 * *wording* shown to admins, not for wire shapes — see the
 * `CertificationLevel` note below for the one place those two sources
 * disagree.
 */

// ─── Domain types ─────────────────────────────────────────────────────────────

/**
 * Mirrors `AttestationMode`. `"none"` is the default and reproduces
 * pre-X3 behavior exactly: no attestation requested, no MDS lookup, every
 * authenticator accepted.
 */
export type AttestationMode = "none" | "indirect" | "direct_required";

/** Mirrors `UnknownAaguidAction`. */
export type UnknownAaguidAction = "allow" | "deny";

/**
 * Mirrors `CertificationLevel` (`crates/axiam-core/src/models/mds.rs`).
 *
 * That enum carries no `#[serde(rename_all = ...)]`, so serde's default
 * unit-variant encoding applies: each wire value is the Rust identifier
 * verbatim — `"L1Plus"`, not `"L1plus"`. The admin guide
 * (`docs/admin/authenticator-policies.md`) writes the levels in
 * lowercase-plus form (`L1plus`) in its policy-fields table; that page is
 * prose describing the concept for humans, not a wire contract, and per this
 * task's own instructions the *handler/model source* is authoritative for
 * what actually goes over HTTP — verified by reading the enum definition
 * directly (no rename attributes present). Do not "fix" this constant to
 * match the doc's casing; if anything the doc has the bug.
 */
export type CertificationLevel =
  | "L1"
  | "L1Plus"
  | "L2"
  | "L2Plus"
  | "L3"
  | "L3Plus";

export const CERTIFICATION_LEVELS: CertificationLevel[] = [
  "L1",
  "L1Plus",
  "L2",
  "L2Plus",
  "L3",
  "L3Plus",
];

export const CERTIFICATION_LEVEL_LABEL: Record<CertificationLevel, string> = {
  L1: "L1",
  L1Plus: "L1+",
  L2: "L2",
  L2Plus: "L2+",
  L3: "L3",
  L3Plus: "L3+",
};

/** Mirrors `WebauthnAttestationPolicy`. One row per tenant; an absent row on
 * the server returns this shape's `Default` (see `DEFAULT_ATTESTATION_POLICY`). */
export interface WebauthnAttestationPolicy {
  mode: AttestationMode;
  /** Only enforceable (and only accepted by the API) when `mode !== "none"`. */
  require_fido_certified: boolean;
  /** Only enforceable (and only accepted by the API) when `mode !== "none"`. */
  min_certification: CertificationLevel | null;
  /** `null` = every AAGUID allowed except `blocked_aaguids`. `[]` is a
   * deliberate lockout — nothing may register — not an accident of leaving
   * the field unset. */
  allowed_aaguids: string[] | null;
  blocked_aaguids: string[];
  block_revoked_status: boolean;
  /** Tri-state: `null` = "use the mode's default" (deny under
   * `direct_required`, allow otherwise) — see `effectiveUnknownAaguid`. An
   * explicit `"allow"`/`"deny"` always wins over the mode-derived default. */
  unknown_aaguid: UnknownAaguidAction | null;
}

/** Reproduces `WebauthnAttestationPolicy::default()` — today's behavior,
 * unchanged, for a tenant with no policy row. */
export const DEFAULT_ATTESTATION_POLICY: WebauthnAttestationPolicy = {
  mode: "none",
  require_fido_certified: false,
  min_certification: null,
  allowed_aaguids: null,
  blocked_aaguids: [],
  block_revoked_status: true,
  unknown_aaguid: null,
};

/**
 * The unknown-AAGUID action actually applied when `unknown_aaguid` is
 * `null`. Mirrors `WebauthnAttestationPolicy::effective_unknown_aaguid`
 * exactly — this is the only place the mode-dependent default lives
 * client-side, so the editor can show "Use mode default (currently: Deny)"
 * rather than leaving the admin to work it out.
 */
export function effectiveUnknownAaguid(
  policy: Pick<WebauthnAttestationPolicy, "mode" | "unknown_aaguid">,
): UnknownAaguidAction {
  if (policy.unknown_aaguid) return policy.unknown_aaguid;
  return policy.mode === "direct_required" ? "deny" : "allow";
}

/**
 * Client-side mirror of `validate_attestation_policy` (axiam-core). Not the
 * authority — the server re-validates on `PUT` and this must not drift into
 * being trusted as the real check — but turns a 400-after-submit into a
 * field-level error at the point of choosing an invalid combination.
 */
export function validateAttestationPolicy(
  policy: WebauthnAttestationPolicy,
): string | null {
  if (policy.mode === "none") {
    const violations: string[] = [];
    if (policy.require_fido_certified) {
      violations.push(
        'require_fido_certified cannot be enforced when mode is "none" (no attestation is requested)',
      );
    }
    if (policy.min_certification !== null) {
      violations.push(
        'min_certification cannot be enforced when mode is "none" (no attestation is requested)',
      );
    }
    if (violations.length > 0) return violations.join("; ");
  }
  return null;
}

// ─── AAGUID list parsing ──────────────────────────────────────────────────────

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isValidAaguid(value: string): boolean {
  return UUID_RE.test(value.trim());
}

/**
 * Parse a comma/whitespace/newline-separated AAGUID list, matching the
 * comma-or-space convention `FederationPage`'s `parseAlgorithms` already
 * established for this codebase's free-text list fields. Blank input yields
 * `[]`, not `null` — the `null` vs `[]` distinction for `allowed_aaguids` is
 * a separate, explicit UI choice (see `AllowedAaguidsMode` in the page), not
 * something inferred from an empty textarea.
 */
export function parseAaguidList(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);
}

// ─── Compliance report ────────────────────────────────────────────────────────

/** Mirrors `ComplianceReportEntry`. */
export interface ComplianceReportEntry {
  credential_id: string;
  user_id: string;
  name: string;
  aaguid: string | null;
  authenticator_name: string | null;
  /** `false` only for a genuine policy violation. A credential with no
   * recorded AAGUID is always `true` here — never reported as a violation. */
  compliant: boolean;
  /** Set for every non-compliant *and* every "unknown" (pre-X3) credential;
   * `null` only when compliant with a recorded AAGUID. */
  reason: string | null;
}

/** Mirrors `axiam_auth::attestation::UNKNOWN_CREDENTIAL_REASON` verbatim
 * (no trailing period — the admin guide's rendering adds one in prose). */
export const UNKNOWN_CREDENTIAL_REASON =
  "registered before attestation policy was enabled";

/**
 * A credential belongs in the "unknown" bucket — never a violation,
 * regardless of policy — whenever it has no recorded AAGUID. This mirrors
 * the admin guide's own framing ("A credential with no recorded AAGUID is
 * reported unknown, never as a violation") more directly than pattern-
 * matching on `reason`, since `aaguid === null` is the actual server-side
 * trigger (D9).
 */
export function isUnknownCredential(entry: ComplianceReportEntry): boolean {
  return entry.aaguid === null;
}

/** Human copy for each machine-readable deny reason — mirrors the reason
 * catalogue documented under "Compliance report" in the admin guide. */
const DENY_REASON_LABEL: Record<string, string> = {
  attestation_required: "Attestation required by policy but not provided",
  aaguid_blocked: "This authenticator model is explicitly blocked",
  aaguid_not_allowed: "This authenticator model is not on the allow list",
  unknown_authenticator:
    "No FIDO metadata for this authenticator model, and policy denies unknowns",
  authenticator_revoked:
    "This authenticator model has a revoked or compromised status in FIDO MDS history",
  not_fido_certified: "This authenticator model is not FIDO-certified",
  certification_too_low:
    "This authenticator model's certification level is below the configured minimum",
};

/** Human-readable label for a compliance-report `reason` value. Falls back
 * to the raw string for a reason the client doesn't recognize, rather than
 * hiding it. */
export function complianceReasonLabel(reason: string | null): string | null {
  if (reason === null) return null;
  return DENY_REASON_LABEL[reason] ?? reason;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const webauthnPolicyService = {
  /** `GET /api/v1/tenants/{tenant_id}/webauthn/attestation-policy` — the
   * server returns default-shaped defaults (not a 404) when no row exists. */
  getPolicy: (tenantId: string): Promise<WebauthnAttestationPolicy> =>
    api
      .get<WebauthnAttestationPolicy>(
        `/api/v1/tenants/${tenantId}/webauthn/attestation-policy`,
      )
      .then((r) => r.data),

  /** `PUT /api/v1/tenants/{tenant_id}/webauthn/attestation-policy` */
  setPolicy: (
    tenantId: string,
    policy: WebauthnAttestationPolicy,
  ): Promise<WebauthnAttestationPolicy> =>
    api
      .put<WebauthnAttestationPolicy>(
        `/api/v1/tenants/${tenantId}/webauthn/attestation-policy`,
        policy,
      )
      .then((r) => r.data),

  /** `GET /api/v1/tenants/{tenant_id}/webauthn/compliance-report` —
   * read-only; never mutates or revokes anything. */
  complianceReport: (tenantId: string): Promise<ComplianceReportEntry[]> =>
    api
      .get<
        ComplianceReportEntry[] | { items: ComplianceReportEntry[] }
      >(`/api/v1/tenants/${tenantId}/webauthn/compliance-report`)
      .then((r) => unwrapList(r.data)),
};
