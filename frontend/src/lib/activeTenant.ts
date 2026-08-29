/**
 * The tenant an organization-level principal is currently acting on.
 *
 * Module state rather than React state, because the axios request interceptor
 * that sends it runs outside React and cannot read a store.
 *
 * # Why this is not inside `lib/api`
 *
 * It was, and that made `@/lib/api` a module with a default export *and* named
 * ones. Fifty-four test files mock it as `{ default: apiMock }`, so every one
 * of them broke the moment anything imported a named export — with
 * `No "setActiveTenant" export is defined on the "@/lib/api" mock`, which
 * points at the mock rather than at the design decision that invalidated it.
 *
 * Separating them is also the more honest arrangement: which tenant is being
 * acted on is not a fact about the HTTP client. `lib/api` reads it; the auth
 * store writes it; neither has to know about the other.
 *
 * `null` means "act on my own tenant" — every ordinary principal, and an
 * organization-level one that has not switched. The header is then omitted
 * rather than sent with the caller's own tenant id: the server treats a header
 * naming the principal's own tenant as a no-op anyway, and omitting it keeps
 * ordinary requests byte-identical to what they were.
 */
/**
 * Where the selection is persisted, and why `sessionStorage`.
 *
 * Per TAB, not per browser: an operator administering two tenants side by side
 * is a normal thing to do, and `localStorage` would have the two tabs fighting
 * over one value. Per tab also means closing the tab ends the selection, which
 * is the right default for something that changes what every subsequent write
 * applies to.
 *
 * Not security state: the server decides whether the caller may act on the
 * named tenant, and refuses with a 403 rather than falling back silently. This
 * only remembers the operator's choice.
 */
const STORAGE_KEY = "axiam.activeTenant";

/**
 * Reads the stored selection.
 *
 * Wrapped because `sessionStorage` *throws* — not returns null — in a private
 * window, with site data blocked, or inside a sandboxed frame. An unreadable
 * store means "no selection", which is the safe answer: the caller's own scope.
 */
function readStored(): { id: string; name: string | null } | null {
  try {
    const raw = globalThis.sessionStorage?.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { id?: unknown; name?: unknown };
    return typeof parsed.id === "string"
      ? { id: parsed.id, name: typeof parsed.name === "string" ? parsed.name : null }
      : null;
  } catch {
    // Unreadable, or written by an older version in a different shape. Either
    // way: no selection, which is the caller's own scope — the safe answer.
    return null;
  }
}

const restored = readStored();
let activeTenantId: string | null = restored?.id ?? null;
let activeTenantName: string | null = restored?.name ?? null;

/**
 * The selection restored from this tab's storage at load, for the auth store to
 * hydrate from. `null` when there is none.
 *
 * Exposed as a snapshot rather than as live state: the store owns what the UI
 * renders, this module owns what the HTTP client sends, and this is the one
 * point where the second seeds the first.
 */
export function restoredActiveTenant(): { id: string; name: string | null } | null {
  return restored;
}

/** The display name of the tenant being acted on, if one was remembered. */
export function getActiveTenantName(): string | null {
  return activeTenantName;
}

/** Header the server reads to decide which tenant a request acts on. */
export const ACTIVE_TENANT_HEADER = "X-Axiam-Tenant";

/**
 * Set (or clear) the tenant subsequent requests act on.
 *
 * Honoured by the server only for an organization-level principal, and only for
 * a tenant in that principal's own organization — anything else is a 403 rather
 * than a silent fallback. So sending it wrongly fails loudly instead of
 * returning another tenant's data.
 */
export function setActiveTenant(
  tenantId: string | null,
  tenantName: string | null = null,
): void {
  activeTenantId = tenantId;
  activeTenantName = tenantName;
  // Persisted so the choice survives a reload. Without this the selection lived
  // only in module state: pressing F5, following a bookmark, or opening a
  // deep link put an organization-level principal silently back in the
  // organization scope mid-task.
  try {
    if (tenantId === null) {
      globalThis.sessionStorage?.removeItem(STORAGE_KEY);
    } else {
      globalThis.sessionStorage?.setItem(
        STORAGE_KEY,
        JSON.stringify({ id: tenantId, name: tenantName }),
      );
    }
  } catch {
    // Unavailable storage costs persistence, not correctness — the in-memory
    // value above is still authoritative for this page's lifetime.
  }
}

/** The tenant currently being acted on, or `null` for the caller's own. */
export function getActiveTenant(): string | null {
  return activeTenantId;
}
