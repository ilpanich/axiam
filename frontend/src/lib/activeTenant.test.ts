import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ACTIVE_TENANT_HEADER,
  getActiveTenant,
  getActiveTenantName,
  setActiveTenant,
} from "@/lib/activeTenant";

const STORAGE_KEY = "axiam.activeTenant";

/**
 * Re-import the module with `sessionStorage` already in the given state.
 *
 * `readStored()` runs exactly once, at module load — that is the whole point of
 * it, since the restored selection has to be available before the auth store
 * hydrates. So the only way to exercise its branches is to load the module
 * again with the store seeded.
 */
async function reimportWith(raw: string | null) {
  vi.resetModules();
  if (raw === null) sessionStorage.removeItem(STORAGE_KEY);
  else sessionStorage.setItem(STORAGE_KEY, raw);
  return import("@/lib/activeTenant");
}

describe("activeTenant", () => {
  beforeEach(() => setActiveTenant(null));

  it("starts unset, so an ordinary principal sends no header at all", () => {
    // The property that keeps every existing request byte-identical: a tenant
    // principal never switches, so the header is never present.
    expect(getActiveTenant()).toBeNull();
  });

  it("remembers the selected tenant", () => {
    setActiveTenant("tenant-a");
    expect(getActiveTenant()).toBe("tenant-a");
  });

  it("clears back to the caller's own tenant", () => {
    setActiveTenant("tenant-a");
    setActiveTenant(null);
    expect(getActiveTenant()).toBeNull();
  });

  it("names the header the server reads", () => {
    // Spelled here and in `extractors::auth::ACTIVE_TENANT_HEADER`; a mismatch
    // is a silently ignored header rather than an error, which is exactly the
    // failure worth pinning.
    expect(ACTIVE_TENANT_HEADER).toBe("X-Axiam-Tenant");
  });
});

describe("activeTenant persistence", () => {
  beforeEach(() => {
    sessionStorage.clear();
    setActiveTenant(null);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it("remembers the tenant's display name alongside its id", () => {
    setActiveTenant("tenant-a", "Tenant A");
    expect(getActiveTenantName()).toBe("Tenant A");
  });

  it("defaults the name to null when only an id is given", () => {
    setActiveTenant("tenant-a");
    expect(getActiveTenantName()).toBeNull();
  });

  it("writes the selection to sessionStorage so a reload keeps it", () => {
    setActiveTenant("tenant-a", "Tenant A");
    expect(JSON.parse(sessionStorage.getItem(STORAGE_KEY) as string)).toEqual({
      id: "tenant-a",
      name: "Tenant A",
    });
  });

  it("removes the entry when the selection is cleared", () => {
    setActiveTenant("tenant-a", "Tenant A");
    setActiveTenant(null);
    expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();
    expect(getActiveTenantName()).toBeNull();
  });

  it("keeps the in-memory value when the store refuses the write", () => {
    // Unavailable storage costs persistence, not correctness: a private window
    // must not turn a tenant switch into a silent no-op.
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("QuotaExceededError");
    });
    setActiveTenant("tenant-a", "Tenant A");
    expect(getActiveTenant()).toBe("tenant-a");
    expect(getActiveTenantName()).toBe("Tenant A");
  });

  it("restores a selection written by an earlier page load", async () => {
    const mod = await reimportWith(
      JSON.stringify({ id: "tenant-b", name: "Tenant B" }),
    );
    expect(mod.restoredActiveTenant()).toEqual({
      id: "tenant-b",
      name: "Tenant B",
    });
    expect(mod.getActiveTenant()).toBe("tenant-b");
    expect(mod.getActiveTenantName()).toBe("Tenant B");
  });

  it("restores an id whose name was never recorded", async () => {
    const mod = await reimportWith(JSON.stringify({ id: "tenant-b" }));
    expect(mod.restoredActiveTenant()).toEqual({ id: "tenant-b", name: null });
  });

  it("has no selection when nothing was stored", async () => {
    const mod = await reimportWith(null);
    expect(mod.restoredActiveTenant()).toBeNull();
    expect(mod.getActiveTenant()).toBeNull();
  });

  it("ignores an entry written in an older shape", async () => {
    // No `id`, or an `id` that is not a string: a selection that cannot be sent
    // as a header. "No selection" is the caller's own scope — the safe answer.
    expect((await reimportWith(JSON.stringify({ id: 42 }))).restoredActiveTenant()).toBeNull();
    expect((await reimportWith(JSON.stringify({ name: "x" }))).restoredActiveTenant()).toBeNull();
  });

  it("ignores an unparseable entry rather than throwing at import", async () => {
    const mod = await reimportWith("{not json");
    expect(mod.restoredActiveTenant()).toBeNull();
  });

  it("has no selection when reading the store throws", async () => {
    // `sessionStorage.getItem` throws — it does not return null — with site
    // data blocked or inside a sandboxed frame.
    vi.resetModules();
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("SecurityError");
    });
    const mod = await import("@/lib/activeTenant");
    expect(mod.restoredActiveTenant()).toBeNull();
  });
});
