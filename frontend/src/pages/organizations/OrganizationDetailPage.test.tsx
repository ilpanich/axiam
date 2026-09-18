import { describe, it, expect } from "vitest";
import { shouldSeedForm, computeIsDirty } from "./settingsForm";
import type { SetOrgSettings } from "@/services/organizations";
import { DEFAULT_CIMD_POLICY } from "@/services/settings";

// D-19 regression guard: SettingsTab must seed `form` from `settings` only
// on the first successful load per mount, and must track dirtiness so a
// background refetch/refocus never silently overwrites in-progress edits.
// Tested against the pure helpers extracted in settingsForm.ts since this
// project has no DOM-rendering test harness for a full component render.

const baseSettings: SetOrgSettings = {
  min_length: 8,
  require_uppercase: true,
  require_lowercase: true,
  require_digits: true,
  require_symbols: false,
  password_history_count: 5,
  hibp_check_enabled: true,
  mfa_enforced: false,
  mfa_challenge_lifetime_secs: 300,
  max_failed_login_attempts: 5,
  lockout_duration_secs: 900,
  lockout_backoff_multiplier: 2,
  max_lockout_duration_secs: 3600,
  access_token_lifetime_secs: 900,
  refresh_token_lifetime_secs: 604800,
  email_verification_required: true,
  email_verification_grace_period_hours: 24,
  default_cert_validity_days: 365,
  max_cert_validity_days: 730,
  admin_notifications_enabled: true,
  opaque_mode: "optional",
  opaque_suite: "ristretto255_sha512",
  opaque_ksf: "argon2id",
  deletion_grace_period_days: 30,
  webauthn_user_verification: "preferred",
  sensitive_scopes_enabled: false,
  default_locale: null,
  dynamic_registration: "disabled",
  dcr_allowed_scopes: [],
  dcr_allowed_redirect_hosts: [],
  external_client_allowed_resources: [],
  dcr_max_clients: 20,
  dcr_unused_client_ttl_days: 30,
  cimd: DEFAULT_CIMD_POLICY,
};

describe("shouldSeedForm (init-once guard)", () => {
  it("seeds on first load when settings have arrived and not yet initialized", () => {
    expect(shouldSeedForm(false, baseSettings)).toBe(true);
  });

  it("does not seed when settings have not arrived yet", () => {
    expect(shouldSeedForm(false, undefined)).toBe(false);
  });

  it("does NOT re-seed on a later settings change once already initialized (the D-19 bug)", () => {
    // A background refetch (e.g. refetchOnWindowFocus) delivers a new
    // `settings` reference/value while the user is mid-edit — this must be
    // a no-op once the form has already been initialized once.
    const refetchedSettings: SetOrgSettings = { ...baseSettings, min_length: 12 };
    expect(shouldSeedForm(true, refetchedSettings)).toBe(false);
  });
});

describe("computeIsDirty", () => {
  it("is false when the form exactly matches the last-loaded snapshot", () => {
    expect(computeIsDirty(baseSettings, baseSettings)).toBe(false);
  });

  it("flips true when editing any single field", () => {
    const edited: SetOrgSettings = { ...baseSettings, min_length: 12 };
    expect(computeIsDirty(edited, baseSettings)).toBe(true);
  });

  it("flips true for a boolean field edit", () => {
    const edited: SetOrgSettings = { ...baseSettings, mfa_enforced: true };
    expect(computeIsDirty(edited, baseSettings)).toBe(true);
  });

  it("a post-seed settings change does not overwrite an edited field: dirty form stays dirty relative to the ORIGINAL snapshot", () => {
    // Simulates: user edits min_length -> a background refetch arrives with
    // a different server value -> shouldSeedForm blocks the re-seed (above)
    // -> the edited form is still compared against the ORIGINAL snapshot the
    // user started editing from, and remains correctly flagged dirty.
    const edited: SetOrgSettings = { ...baseSettings, min_length: 12 };
    const serverRefetch: SetOrgSettings = { ...baseSettings, min_length: 10 };
    expect(shouldSeedForm(true, serverRefetch)).toBe(false);
    expect(computeIsDirty(edited, baseSettings)).toBe(true);
  });

  it("returns to clean when every field matches the snapshot again", () => {
    const editedBack: SetOrgSettings = { ...baseSettings };
    expect(computeIsDirty(editedBack, baseSettings)).toBe(false);
  });

  // The OIDC block put arrays and one nested object into a shape that had been
  // scalars throughout. Under reference equality a list the user typed into and
  // emptied again would stay dirty for the rest of the session, holding the
  // navigate-away guard open over no edit at all.
  it("flips true for an edited OIDC list, and back to clean when it is restored", () => {
    const edited: SetOrgSettings = {
      ...baseSettings,
      dcr_allowed_scopes: ["openid"],
    };
    expect(computeIsDirty(edited, baseSettings)).toBe(true);
    const restored: SetOrgSettings = { ...baseSettings, dcr_allowed_scopes: [] };
    expect(computeIsDirty(restored, baseSettings)).toBe(false);
  });

  it("flips true for an edited CIMD posture, and back to clean when it is restored", () => {
    const edited: SetOrgSettings = {
      ...baseSettings,
      cimd: { ...DEFAULT_CIMD_POLICY, enabled: true },
    };
    expect(computeIsDirty(edited, baseSettings)).toBe(true);
    const restored: SetOrgSettings = {
      ...baseSettings,
      cimd: { ...DEFAULT_CIMD_POLICY },
    };
    expect(computeIsDirty(restored, baseSettings)).toBe(false);
  });
});
