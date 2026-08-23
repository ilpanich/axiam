// ─── OPAQUE (RFC 9807) policy — types, ordering, presentation ─────────────────
//
// One home for the three `opaque_*` policy fields, because they appear in three
// request/response shapes (`SecuritySettings`, `SetOrgSettings`,
// `TenantSettingsOverride`) and on two admin pages, and a fourth hand-rolled
// copy is how the frontend came to omit them entirely.
//
// Source of truth: `crates/axiam-core/src/models/opaque.rs` (the enums and their
// `rank()` ladders) and `crates/axiam-core/src/models/settings.rs`
// (`OpaquePolicy`, `validate_tenant_override`).
//
// Distinct from `services/opaque.ts`, which drives the protocol exchange itself
// and only ever asks whether the mode is `disabled`. This module is about
// *administering* the policy.

/** Whether OPAQUE is offered, and whether password login is still accepted. */
export type OpaqueMode = "disabled" | "optional" | "required";

/** RFC 9807 ciphersuite new registration records are enrolled under. */
export type OpaqueSuite = "ristretto255_sha512";

/** Client-side key-stretching function new records are enrolled under. */
export type OpaqueKsf = "argon2id" | "scrypt";

/** The three policy fields as they appear inside `SecuritySettings.opaque`. */
export interface OpaquePolicy {
  opaque_mode: OpaqueMode;
  opaque_suite: OpaqueSuite;
  opaque_ksf: OpaqueKsf;
}

/**
 * What the backend resolves an absent policy to.
 *
 * `SetOrgSettings`'s three fields are `#[serde(default)]` and a settings row
 * written before the OPAQUE migration has no such column, so "missing" means
 * `disabled` on both sides of the wire — not "leave whatever is there".
 */
export const DEFAULT_OPAQUE_POLICY: OpaquePolicy = {
  opaque_mode: "disabled",
  opaque_suite: "ristretto255_sha512",
  opaque_ksf: "argon2id",
};

/** Selectable values, in the order the ladder ranks them (weakest first). */
export const OPAQUE_MODES: readonly OpaqueMode[] = [
  "disabled",
  "optional",
  "required",
];
export const OPAQUE_SUITES: readonly OpaqueSuite[] = ["ristretto255_sha512"];
export const OPAQUE_KSFS: readonly OpaqueKsf[] = ["scrypt", "argon2id"];

// Ranks mirror `OpaqueMode`'s derived `Ord` and the explicit `rank()` methods on
// `OpaqueSuite`/`OpaqueKsf`. Written out per variant for the same reason the
// Rust side does: adding a value must force a decision about where it sits,
// not inherit one from declaration order.
const MODE_RANK: Record<OpaqueMode, number> = {
  disabled: 0,
  optional: 1,
  required: 2,
};
const SUITE_RANK: Record<OpaqueSuite, number> = { ristretto255_sha512: 1 };
const KSF_RANK: Record<OpaqueKsf, number> = { scrypt: 0, argon2id: 1 };

/** True when `candidate` is at least as restrictive as `baseline`. */
export function opaqueModeIsAtLeast(
  candidate: OpaqueMode,
  baseline: OpaqueMode
): boolean {
  return MODE_RANK[candidate] >= MODE_RANK[baseline];
}

/** True when `candidate` is at least as strong as `baseline`. */
export function opaqueSuiteIsAtLeast(
  candidate: OpaqueSuite,
  baseline: OpaqueSuite
): boolean {
  return SUITE_RANK[candidate] >= SUITE_RANK[baseline];
}

/** True when `candidate` is at least as strong as `baseline`. */
export function opaqueKsfIsAtLeast(
  candidate: OpaqueKsf,
  baseline: OpaqueKsf
): boolean {
  return KSF_RANK[candidate] >= KSF_RANK[baseline];
}

// ─── Presentation ────────────────────────────────────────────────────────────

export const OPAQUE_MODE_LABEL: Record<OpaqueMode, string> = {
  disabled: "Disabled",
  optional: "Optional",
  required: "Required",
};

export const OPAQUE_MODE_DESCRIPTION: Record<OpaqueMode, string> = {
  disabled:
    "OPAQUE is off. No registration record is created when a password is set.",
  optional:
    "OPAQUE is offered and password login still works. Users gain a record as they next set a password.",
  required:
    "Password login is refused for every user in the tenant. Only users with a registration record can sign in.",
};

export const OPAQUE_SUITE_LABEL: Record<OpaqueSuite, string> = {
  ristretto255_sha512: "ristretto255 / SHA-512 (RFC 9807 recommended)",
};

export const OPAQUE_KSF_LABEL: Record<OpaqueKsf, string> = {
  argon2id: "Argon2id (stronger)",
  scrypt: "scrypt",
};

// ─── Guards ──────────────────────────────────────────────────────────────────

/**
 * The policy carried by a settings response, or the `disabled` default.
 *
 * Every field of the flat write shapes is required, so a read that produced
 * `undefined` here would send `undefined` straight back on the next save. A
 * server old enough to omit the block means `disabled`, which is what this
 * substitutes.
 */
export function readOpaquePolicy(
  source: { opaque?: Partial<OpaquePolicy> } | null | undefined
): OpaquePolicy {
  const p = source?.opaque;
  return {
    opaque_mode: p?.opaque_mode ?? DEFAULT_OPAQUE_POLICY.opaque_mode,
    opaque_suite: p?.opaque_suite ?? DEFAULT_OPAQUE_POLICY.opaque_suite,
    opaque_ksf: p?.opaque_ksf ?? DEFAULT_OPAQUE_POLICY.opaque_ksf,
  };
}

/**
 * Advisory shown on the *tenant* settings page when a chosen policy is weaker
 * than the tenant's current effective one.
 *
 * `GET /api/v1/settings` returns only the merged result, so the page cannot see
 * the org baseline and must not pretend to: dropping from a tenant override of
 * `required` back to an `optional` baseline is legal, and a hard block would
 * strand the admin. This warns without blocking, and names the rule the server
 * will apply — `validate_tenant_override` rejects anything below the baseline
 * with a 400 that the page surfaces verbatim.
 */
export function opaqueRelaxationWarning(
  candidate: OpaquePolicy,
  effective: OpaquePolicy
): string | null {
  const weakened: string[] = [];
  if (!opaqueModeIsAtLeast(candidate.opaque_mode, effective.opaque_mode)) {
    weakened.push(
      `mode (${OPAQUE_MODE_LABEL[effective.opaque_mode]} → ${OPAQUE_MODE_LABEL[candidate.opaque_mode]})`
    );
  }
  if (!opaqueSuiteIsAtLeast(candidate.opaque_suite, effective.opaque_suite)) {
    weakened.push("ciphersuite");
  }
  if (!opaqueKsfIsAtLeast(candidate.opaque_ksf, effective.opaque_ksf)) {
    weakened.push(
      `key-stretching function (${effective.opaque_ksf} → ${candidate.opaque_ksf})`
    );
  }
  if (weakened.length === 0) return null;
  return `This relaxes the tenant's current effective OPAQUE policy — ${weakened.join(", ")}. A tenant may only be more restrictive than its organization baseline, so the server will refuse this unless the baseline is already at or below the value you picked.`;
}
