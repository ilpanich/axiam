import api from "@/lib/api";
import type {
  OpaqueKsf,
  OpaqueMode,
  OpaquePolicy,
  OpaqueSuite,
} from "@/services/opaquePolicy";

export type { OpaqueKsf, OpaqueMode, OpaquePolicy, OpaqueSuite };

// ─── Backend-aligned nested READ shape ─────────────────────────────────────────
// GET /api/v1/settings returns the effective (merged) `SecuritySettings`.
// Source of truth: crates/axiam-core/src/models/settings.rs (SecuritySettings).

export interface PasswordPolicy {
  min_length: number;
  require_uppercase: boolean;
  require_lowercase: boolean;
  require_digits: boolean;
  require_symbols: boolean;
  password_history_count: number;
  hibp_check_enabled: boolean;
}

export interface MfaPolicy {
  mfa_enforced: boolean;
  mfa_challenge_lifetime_secs: number;
}

export interface LockoutPolicy {
  max_failed_login_attempts: number;
  lockout_duration_secs: number;
  lockout_backoff_multiplier: number;
  max_lockout_duration_secs: number;
}

export interface TokenPolicy {
  access_token_lifetime_secs: number;
  refresh_token_lifetime_secs: number;
}

export interface EmailVerificationPolicy {
  email_verification_required: boolean;
  email_verification_grace_period_hours: number;
}

export interface CertificatePolicy {
  default_cert_validity_days: number;
  max_cert_validity_days: number;
}

export interface NotificationPolicy {
  admin_notifications_enabled: boolean;
}

export interface PrivacyPolicy {
  /** How long a requested account erasure stays cancellable, in days. */
  deletion_grace_period_days: number;
}

/**
 * How hard an authenticator must prove *who* is present during a WebAuthn
 * ceremony — the WebAuthn `userVerification`.
 *
 * `required` refuses any security key that cannot set the UV bit, which
 * includes every YubiKey with no PIN configured. `preferred` (the default)
 * asks, accepts either answer, and records which happened.
 *
 * Usernameless sign-in always requires user verification whatever this says:
 * there the credential is the only factor.
 */
export type WebauthnUserVerification = "discouraged" | "preferred" | "required";

export interface WebauthnPolicy {
  webauthn_user_verification: WebauthnUserVerification;
}

/**
 * T21.4 — how a client may register itself (RFC 7591). `disabled` refuses
 * every request; `initial_access_token` requires a single-use credential an
 * administrator minted; `anonymous` accepts anybody who can reach the
 * endpoint. Mirrors `DynamicRegistrationMode` in
 * `crates/axiam-core/src/models/settings.rs`, on the same permissiveness
 * ladder (`disabled` < `initial_access_token` < `anonymous`): a tenant may
 * move down it and never up.
 */
export type DynamicRegistrationMode =
  | "disabled"
  | "initial_access_token"
  | "anonymous";

/**
 * T21.5 — whether, and on what terms, a `client_id` that is a URL is resolved
 * by fetching the document it names
 * (`draft-ietf-oauth-client-id-metadata-document`).
 *
 * The posture is **whole**: a tenant either accepts its organization's CIMD
 * policy or states its own in full. There is no per-field merge on the
 * backend (`Option<CimdPolicy>` on `TenantSettingsOverride`) and there is none
 * here, because a half-merged posture — this tenant's trusted publishers under
 * the organization's `enabled` — is one neither party wrote.
 *
 * Source: `crates/axiam-core/src/models/settings.rs` (`CimdPolicy`).
 */
export interface CimdPolicy {
  /** Ordered against the org baseline: a tenant may turn it off, never on. */
  enabled: boolean;
  /**
   * Ordered like `enabled`. Does more than its name says: the shared SSRF
   * guard couples the scheme rule to the address rule, so a tenant that allows
   * `http` also allows the first hop to resolve to a private address.
   */
  allow_http: boolean;
  /** Refused empty while `enabled`, and refused `*` or `*.<tld>` — see `validateCimdPolicy`. */
  trusted_client_id_domains: string[];
  /** Loopback is always allowed, so empty means "loopback only". `*` is valid here. */
  trusted_redirect_domains: string[];
  restrict_same_domain: boolean;
  confidential_only: boolean;
  min_cache_secs: number;
  max_cache_secs: number;
  max_metadata_bytes: number;
}

/** T21.5 defaults, mirroring `impl Default for CimdPolicy`. */
export const DEFAULT_CIMD_POLICY: CimdPolicy = {
  enabled: false,
  allow_http: false,
  trusted_client_id_domains: [],
  trusted_redirect_domains: [],
  restrict_same_domain: true,
  confidential_only: false,
  min_cache_secs: 300,
  max_cache_secs: 259_200,
  max_metadata_bytes: 5_000,
};

/**
 * The OIDC policy block of `SecuritySettings`, in full.
 *
 * Every field here is `#[serde(default)]` on the backend's `SetOrgSettings`,
 * and `PUT /organizations/{id}/settings` replaces the whole row — so a write
 * shape that omits one resets it. This type therefore models **all** of them,
 * including `sensitive_scopes_enabled` and `default_locale`, which predate
 * T21.4 and still have no form control: a field with no UI still has to make
 * the round trip, or the save turns it off.
 *
 * Source: `crates/axiam-core/src/models/settings.rs` (`OidcPolicy`).
 */
export interface OidcPolicy {
  /** W7 — whether `address` and `phone` may be released at all. */
  sensitive_scopes_enabled?: boolean;
  /** The tenant's preferred UI locale, or `null` for none. */
  default_locale?: string | null;
  dynamic_registration: DynamicRegistrationMode;
  /** May not contain `address` or `phone` — see `validateDcrPolicy`. */
  dcr_allowed_scopes: string[];
  dcr_allowed_redirect_hosts: string[];
  /** D3 — the audiences an externally registered client may address. */
  external_client_allowed_resources: string[];
  dcr_max_clients: number;
  dcr_unused_client_ttl_days: number;
  /** T21.5 — absent on a server older than the field; falls back to the default posture. */
  cimd?: CimdPolicy;
}

/** T21.4 defaults, mirroring `DEFAULT_DCR_MAX_CLIENTS` / `DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS`. */
export const DEFAULT_DCR_MAX_CLIENTS = 20;
export const DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS = 30;

/**
 * Read the OIDC policy out of a settings response, filling in the server's own
 * defaults for anything the response omits.
 *
 * The sibling of `readOpaquePolicy`, and it exists for the same reason: a
 * settings row written before these fields has no `oidc` block, and an
 * `undefined` in a write shape is dropped from the JSON body and lands back on
 * the backend's `#[serde(default)]` — which for `cimd.enabled`,
 * `dynamic_registration` and `sensitive_scopes_enabled` means *off*. Going
 * through the guard makes the fallback the value that server would itself
 * apply, and makes it visible here rather than implicit in the wire format.
 */
export function readOidcPolicy(s: {
  oidc?: OidcPolicy;
}): Required<OidcPolicy> {
  const o = s.oidc;
  return {
    sensitive_scopes_enabled: o?.sensitive_scopes_enabled ?? false,
    default_locale: o?.default_locale ?? null,
    dynamic_registration: o?.dynamic_registration ?? "disabled",
    dcr_allowed_scopes: o?.dcr_allowed_scopes ?? [],
    dcr_allowed_redirect_hosts: o?.dcr_allowed_redirect_hosts ?? [],
    external_client_allowed_resources:
      o?.external_client_allowed_resources ?? [],
    dcr_max_clients: o?.dcr_max_clients ?? DEFAULT_DCR_MAX_CLIENTS,
    dcr_unused_client_ttl_days:
      o?.dcr_unused_client_ttl_days ?? DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS,
    cimd: o?.cimd ?? DEFAULT_CIMD_POLICY,
  };
}

/** Fully-resolved security settings (nested) — GET /api/v1/settings. */
export interface SecuritySettings {
  id: string;
  scope: "Org" | "Tenant";
  scope_id: string;
  password: PasswordPolicy;
  mfa: MfaPolicy;
  lockout: LockoutPolicy;
  token: TokenPolicy;
  email: EmailVerificationPolicy;
  certificate: CertificatePolicy;
  notification: NotificationPolicy;
  /**
   * OPAQUE (RFC 9807) policy. Always present on a current server; see
   * `readOpaquePolicy` for why the write paths never read it directly.
   */
  opaque: OpaquePolicy;
  /**
   * Retention rules after an erasure request. Optional so a server older than
   * the field does not fail the type; callers fall back to the server's own
   * 30-day default.
   */
  privacy?: PrivacyPolicy;
  /**
   * WebAuthn ceremony policy. Optional for the same reason as `privacy`: a
   * server older than the field does not carry it, and callers fall back to
   * the server's own `preferred` default.
   */
  webauthn?: WebauthnPolicy;
  /**
   * T21.4 — dynamic client registration policy. Optional for the same reason
   * as `privacy`/`webauthn`: a server older than the field does not carry it,
   * and callers fall back to the server's own `disabled` default (I1).
   */
  oidc?: OidcPolicy;
  created_at: string;
  updated_at: string;
}

// ─── Backend-aligned flat WRITE shape (all optional, SECONDS) ──────────────────
// PUT /api/v1/settings expects `TenantSettingsOverride` — flat, all fields
// optional. Omitted fields inherit the org baseline. All durations are in
// SECONDS. Source: crates/axiam-core/src/models/settings.rs.

export interface TenantSettingsOverride {
  // Password
  min_length?: number;
  require_uppercase?: boolean;
  require_lowercase?: boolean;
  require_digits?: boolean;
  require_symbols?: boolean;
  password_history_count?: number;
  hibp_check_enabled?: boolean;
  // MFA
  mfa_enforced?: boolean;
  mfa_challenge_lifetime_secs?: number;
  // Lockout
  max_failed_login_attempts?: number;
  lockout_duration_secs?: number;
  lockout_backoff_multiplier?: number;
  max_lockout_duration_secs?: number;
  // Token
  access_token_lifetime_secs?: number;
  refresh_token_lifetime_secs?: number;
  // Email
  email_verification_required?: boolean;
  email_verification_grace_period_hours?: number;
  // Certificate
  default_cert_validity_days?: number;
  max_cert_validity_days?: number;
  // Notification
  admin_notifications_enabled?: boolean;
  // OPAQUE — tighten-only, like every other field here: the server refuses a
  // mode below the org baseline, or a weaker suite/KSF.
  opaque_mode?: OpaqueMode;
  opaque_suite?: OpaqueSuite;
  opaque_ksf?: OpaqueKsf;
  // Privacy — tighten-only means *shorter*: it is time spent holding data the
  // subject has already asked to have erased.
  deletion_grace_period_days?: number;
  // WebAuthn — tighten-only on required > preferred > discouraged.
  webauthn_user_verification?: WebauthnUserVerification;
  // T21.4 — dynamic client registration. `dynamic_registration`,
  // `dcr_max_clients` and `dcr_unused_client_ttl_days` are tighten-only, like
  // every ordered field above; the three lists replace the org baseline whole
  // rather than being ordered against it (see `OidcPolicy` on the backend).
  dynamic_registration?: DynamicRegistrationMode;
  dcr_allowed_scopes?: string[];
  dcr_allowed_redirect_hosts?: string[];
  external_client_allowed_resources?: string[];
  dcr_max_clients?: number;
  dcr_unused_client_ttl_days?: number;
  // T21.5 — the CIMD posture is overridden **whole** or not at all
  // (`Option<CimdPolicy>` on the backend). `enabled` and `allow_http` are
  // ordered against the org baseline; the other seven name this tenant's own
  // publishers, callbacks and bounds and are neither ordered nor clamped.
  cimd?: CimdPolicy;
}

/**
 * The two GDPR-sensitive scopes a self-registered client may never ask for.
 * Mirrors `sensitive_scope_in_dcr_list` in
 * `crates/axiam-core/src/models/settings.rs` — trimmed, exact match, no
 * case-folding, because that is what the backend does.
 */
const DCR_SENSITIVE_SCOPES = ["address", "phone"];

/**
 * Client-side mirror of `validate_dcr_policy`
 * (`crates/axiam-core/src/models/settings.rs`), which the settings handler
 * runs on the *resolved* policy. Both interlocks recorded by the T21.4a
 * amendment:
 *
 * 1. **D3** — `anonymous` registration cannot be enabled while
 *    `external_client_allowed_resources` is empty: a client an unrelated
 *    party registered inherits that list verbatim, and an empty one leaves it
 *    able to obtain only the `axiam:user` tokens AXIAM's own APIs accept.
 * 2. **Amendment 1** — `dcr_allowed_scopes` may not contain `address` or
 *    `phone`: both release personal data under W7's per-client consent
 *    record, and a self-registered client already carries a forced consent
 *    record of its own (D4) — offering them here would need two records in
 *    one namespace.
 *
 * Returns `null` when the policy is valid. Messages match the backend's
 * wording so an operator who has read the docs recognises the refusal.
 */
export function validateDcrPolicy(policy: {
  dynamic_registration: DynamicRegistrationMode;
  dcr_allowed_scopes: string[];
  external_client_allowed_resources: string[];
}): string | null {
  if (
    policy.dynamic_registration === "anonymous" &&
    policy.external_client_allowed_resources.length === 0
  ) {
    return (
      "dynamic_registration: anonymous registration cannot be enabled while " +
      "external_client_allowed_resources is empty (D3). A client registered by an unrelated " +
      "party inherits that list as its allowed_resources, and an empty list leaves it able to " +
      "obtain only the axiam:user tokens AXIAM's own APIs accept. Name the MCP servers this " +
      "tenant fronts first."
    );
  }

  const sensitive = policy.dcr_allowed_scopes.find((s) =>
    DCR_SENSITIVE_SCOPES.includes(s.trim())
  );
  if (sensitive !== undefined) {
    return (
      `dcr_allowed_scopes: ${sensitive.trim()} releases personal data under W7's per-client ` +
      "consent record and cannot be offered to a self-registered client, which already " +
      "carries a forced consent record of its own (D4). Register a client for it through " +
      "POST /oauth2-clients instead."
    );
  }

  return null;
}

// ─── T21.5 — client ID metadata documents ─────────────────────────────────────

/**
 * The deployment constants `validate_cimd_policy` clamps against. Mirrors
 * `CIMD_MIN_CACHE_FLOOR_SECS`, `CIMD_MAX_CACHE_CEILING_SECS` and
 * `CIMD_MAX_METADATA_BYTES_CEILING` in
 * `crates/axiam-core/src/models/settings.rs`.
 */
export const CIMD_MIN_CACHE_FLOOR_SECS = 60;
/** See `CIMD_MIN_CACHE_FLOOR_SECS`. */
export const CIMD_MAX_CACHE_CEILING_SECS = 604_800;
/** See `CIMD_MIN_CACHE_FLOOR_SECS`. */
export const CIMD_MAX_METADATA_BYTES_CEILING = 65_536;

/** The `CimdPolicy` field a refusal belongs under, so the form can place it. */
export type CimdPolicyField =
  | "enabled"
  | "trusted_client_id_domains"
  | "trusted_redirect_domains"
  | "min_cache_secs"
  | "max_cache_secs"
  | "max_metadata_bytes";

export interface CimdPolicyViolation {
  field: CimdPolicyField;
  /** The server's own text, so an operator meets one message, not two. */
  message: string;
}

/** Rust's `{value:?}` for a `String` — the quoted, escaped form. */
function debugQuote(value: string): string {
  return JSON.stringify(value);
}

/**
 * Client-side mirror of `validate_cimd_policy`
 * (`crates/axiam-core/src/models/settings.rs`), which both settings handlers
 * run: on the organization baseline through `validate_org_settings`, and on
 * the merged policy through `validate_tenant_override`. Every message below is
 * the server's, word for word, because the only thing worse than meeting a
 * refusal after the request is meeting two different wordings of it.
 *
 * Nothing is checked while `enabled` is false — the server returns early there
 * too, so a tenant may stage a posture before turning it on.
 *
 * Returns the violations in the order the server collects them; an empty array
 * means the policy would be accepted.
 *
 * What it deliberately does **not** mirror is the *ordering* rule — that a
 * tenant may not set `enabled` or `allow_http` true when its organization has
 * them false. That refusal needs the org baseline, which `GET /api/v1/settings`
 * does not expose, so it stays where every other tighten-only rule in this page
 * is: the server refuses and the form shows the refusal.
 */
export function validateCimdPolicy(policy: {
  external_client_allowed_resources: string[];
  cimd: CimdPolicy;
}): CimdPolicyViolation[] {
  const violations: CimdPolicyViolation[] = [];
  const cimd = policy.cimd;

  if (!cimd.enabled) return violations;

  if (policy.external_client_allowed_resources.length === 0) {
    violations.push({
      field: "enabled",
      message:
        "cimd.enabled: client ID metadata documents cannot be enabled while " +
        "external_client_allowed_resources is empty (D3). A client materialised from a " +
        "stranger's document inherits that list as its allowed_resources, and an empty " +
        "list leaves it able to obtain only the axiam:user tokens AXIAM's own APIs " +
        "accept. Name the MCP servers this tenant fronts first",
    });
  }

  if (cimd.trusted_client_id_domains.length === 0) {
    violations.push({
      field: "trusted_client_id_domains",
      message:
        "cimd.trusted_client_id_domains: client ID metadata documents cannot be enabled " +
        "with no trusted publisher domain. The document is fetched because an " +
        "unauthenticated request named its URL, so an unrestricted list is an outbound " +
        "fetch a stranger chooses the target of. Name the hosts whose documents this " +
        "tenant accepts (globs are allowed: *.example.com)",
    });
  }

  // MCP-03 (#469). `*` was refused as `[]` and admitted as `["*"]`, and a
  // single-label wildcard (`*.com`) is `*` for one top-level domain spelled
  // longer. A floor, not a public-suffix check: `*.github.io` still passes.
  // `trusted_redirect_domains` keeps `*`, because its entries are not fetch
  // targets.
  for (const entry of cimd.trusted_client_id_domains) {
    const e = entry.trim();
    let offence: string | null = null;
    if (e === "*") {
      offence = "matches every host";
    } else if (e.startsWith("*.")) {
      const suffix = e.slice(2);
      if (!suffix.includes("*") && suffix.length > 0 && !suffix.includes(".")) {
        offence = "is a wildcard over a whole top-level domain";
      }
    }
    if (offence !== null) {
      violations.push({
        field: "trusted_client_id_domains",
        message:
          `cimd.trusted_client_id_domains: ${debugQuote(entry)} ${offence}, which is the posture an ` +
          "empty list is refused for. The document is fetched because an " +
          "unauthenticated request named its URL, so the list has to name a publisher: " +
          "a host (mcp.example.com) or a wildcard over one (*.example.com)",
      });
    }
  }

  // A host glob, not a URL. The matcher answers `false` for an entry carrying a
  // scheme, a path or a port, so a tenant that typed one would have a trusted
  // list that silently matches nothing — fail-closed, but indistinguishable
  // from a working list until somebody tries to sign in. The two fields get
  // different advice, because `*` is valid in one of them and refused in the
  // other.
  const shapes: [CimdPolicyField, string[], string][] = [
    [
      "trusted_client_id_domains",
      cimd.trusted_client_id_domains,
      "Write a host (mcp.example.com) or a leftmost-label wildcard over one " +
        "(*.example.com)",
    ],
    [
      "trusted_redirect_domains",
      cimd.trusted_redirect_domains,
      "Write a host (app.example.com), a leftmost-label wildcard (*.example.com) or *",
    ],
  ];
  for (const [field, entries, forms] of shapes) {
    for (const entry of entries) {
      const e = entry.trim();
      if (
        e.length === 0 ||
        e.includes("://") ||
        e.includes("/") ||
        e.includes(":") ||
        e.split(/\s+/).length !== 1
      ) {
        violations.push({
          field,
          message:
            `cimd.${field}: ${debugQuote(entry)} is not a host pattern. ${forms} — not a URL, a path or ` +
            "a host:port",
        });
      }
    }
  }

  if (cimd.min_cache_secs < CIMD_MIN_CACHE_FLOOR_SECS) {
    violations.push({
      field: "min_cache_secs",
      message:
        `cimd.min_cache_secs (${cimd.min_cache_secs}) must be >= ${CIMD_MIN_CACHE_FLOOR_SECS}: the cache ` +
        "lifetime is what stands between one authorization request and one outbound " +
        "fetch",
    });
  }

  if (cimd.max_cache_secs > CIMD_MAX_CACHE_CEILING_SECS) {
    violations.push({
      field: "max_cache_secs",
      message:
        `cimd.max_cache_secs (${cimd.max_cache_secs}) must be <= ${CIMD_MAX_CACHE_CEILING_SECS}: a cached ` +
        "document is a live client registration nobody here created",
    });
  }

  if (cimd.min_cache_secs > cimd.max_cache_secs) {
    violations.push({
      field: "min_cache_secs",
      message:
        `cimd.min_cache_secs (${cimd.min_cache_secs}) must be <= cimd.max_cache_secs (${cimd.max_cache_secs})`,
    });
  }

  if (
    cimd.max_metadata_bytes === 0 ||
    cimd.max_metadata_bytes > CIMD_MAX_METADATA_BYTES_CEILING
  ) {
    violations.push({
      field: "max_metadata_bytes",
      message:
        `cimd.max_metadata_bytes (${cimd.max_metadata_bytes}) must be between 1 and ` +
        `${CIMD_MAX_METADATA_BYTES_CEILING}: an unbounded read of an attacker-chosen URL ` +
        "is a memory-exhaustion primitive",
    });
  }

  return violations;
}

// ─── Service ──────────────────────────────────────────────────────────────────

export const settingsService = {
  /**
   * GET /api/v1/tenants/{id}/settings — the tenant's **own** overrides, sparse.
   *
   * Distinct from `getSettings`, which returns the merged view. The tenant
   * detail page needs to tell an overridden field from an inherited one, and a
   * merged view cannot express that. `404` (this tenant overrides nothing) maps
   * to `null` so "inherits everything" is a value the caller can render.
   */
  async getTenantOverride(
    tenantId: string
  ): Promise<TenantSettingsOverride | null> {
    try {
      const res = await api.get<TenantSettingsOverride>(
        `/api/v1/tenants/${tenantId}/settings`
      );
      return res.data;
    } catch (err) {
      const status = (err as { response?: { status?: number } })?.response
        ?.status;
      if (status === 404) return null;
      throw err;
    }
  },

  /** PUT /api/v1/tenants/{id}/settings — replace the sparse override set. */
  async setTenantOverride(
    tenantId: string,
    data: TenantSettingsOverride
  ): Promise<TenantSettingsOverride> {
    const res = await api.put<TenantSettingsOverride>(
      `/api/v1/tenants/${tenantId}/settings`,
      data
    );
    return res.data;
  },

  /** DELETE /api/v1/tenants/{id}/settings — inherit the org baseline entirely. */
  async deleteTenantOverride(tenantId: string): Promise<void> {
    await api.delete(`/api/v1/tenants/${tenantId}/settings`);
  },

  /** GET /api/v1/settings — effective (merged) tenant security settings. */
  async getSettings(): Promise<SecuritySettings> {
    const res = await api.get<SecuritySettings>("/api/v1/settings");
    return res.data;
  },

  /**
   * PUT /api/v1/settings — set tenant-level overrides. Only fields that are
   * MORE restrictive than the org baseline are accepted. All durations are in
   * seconds.
   */
  async updateSettings(
    data: TenantSettingsOverride
  ): Promise<SecuritySettings> {
    const res = await api.put<SecuritySettings>("/api/v1/settings", data);
    return res.data;
  },
};
