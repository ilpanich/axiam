import type { SetOrgSettings } from "@/services/organizations";

// ---------------------------------------------------------------------------
// SettingsTab pure logic (D-19)
// ---------------------------------------------------------------------------
//
// Extracted from OrganizationDetailPage.tsx's SettingsTab so the init-once
// seed decision and the dirty computation can be unit-tested without a full
// component render (this project has no DOM-rendering test harness —
// testing-library/jsdom are not installed).

/**
 * Decide whether the form should be (re-)seeded from freshly-loaded server
 * settings.
 *
 * Seeds only on the FIRST successful load per mount (per orgId, since
 * SettingsTab remounts on orgId change). A later background refetch/refocus
 * with `hasInitialized=true` must NOT re-seed — that would silently discard
 * in-progress edits (the D-19 bug).
 */
export function shouldSeedForm(
  hasInitialized: boolean,
  settings: unknown
): boolean {
  return !hasInitialized && settings != null;
}

/**
 * Compute whether `current` differs from `snapshot` (the last-loaded server
 * state) across every field of the flat SetOrgSettings shape.
 *
 * Used to derive `isDirty` — true means the form has in-progress edits that
 * would be lost by a re-seed, a browser refresh, or in-app navigation away.
 */
export function computeIsDirty(
  current: SetOrgSettings,
  snapshot: SetOrgSettings
): boolean {
  const keys = Object.keys(snapshot) as (keyof SetOrgSettings)[];
  return keys.some((key) => current[key] !== snapshot[key]);
}
