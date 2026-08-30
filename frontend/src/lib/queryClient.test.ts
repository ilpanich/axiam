import { afterEach, describe, it, expect } from "vitest";
import { QueryClient } from "@tanstack/react-query";

import { setActiveTenant } from "@/lib/activeTenant";
import {
  OWN_SCOPE_CACHE_SLOT,
  queryClient,
  tenantScopedQueryKeyHash,
} from "./queryClient";

// Exercises the shared QueryClient's retry policy (D-14): 401/403 never retry,
// everything else retries up to 2 times.
describe("queryClient retry policy", () => {
  const retry = queryClient.getDefaultOptions().queries?.retry as (
    failureCount: number,
    error: unknown
  ) => boolean;

  it("is configured as a function", () => {
    expect(typeof retry).toBe("function");
  });

  it("never retries on 401 or 403", () => {
    expect(retry(0, { response: { status: 401 } })).toBe(false);
    expect(retry(0, { response: { status: 403 } })).toBe(false);
  });

  it("retries other errors up to twice then stops", () => {
    const err = { response: { status: 500 } };
    expect(retry(0, err)).toBe(true);
    expect(retry(1, err)).toBe(true);
    expect(retry(2, err)).toBe(false);
  });

  it("treats an error with no response as retryable", () => {
    expect(retry(0, new Error("network"))).toBe(true);
  });

  it("uses a 60s stale time", () => {
    expect(queryClient.getDefaultOptions().queries?.staleTime).toBe(60_000);
  });
});

// ---------------------------------------------------------------------------
// Tenant namespacing
// ---------------------------------------------------------------------------

describe("tenant-scoped query key hashing", () => {
  afterEach(() => setActiveTenant(null));

  it("gives the same key a different cache identity per acting tenant", () => {
    // The bug this prevents: `["users", 1, ""]` means "page 1 of the users of
    // whichever tenant the request header named". Two tenants sharing one cache
    // entry is how one tenant's rows end up on screen under another's name.
    const key = ["users", 1, ""] as const;

    setActiveTenant(null);
    const own = tenantScopedQueryKeyHash(key);
    setActiveTenant("tenant-a");
    const a = tenantScopedQueryKeyHash(key);
    setActiveTenant("tenant-b");
    const b = tenantScopedQueryKeyHash(key);

    expect(new Set([own, a, b]).size).toBe(3);
  });

  it("is stable for the same key and tenant", () => {
    setActiveTenant("tenant-a");
    expect(tenantScopedQueryKeyHash(["roles"])).toBe(
      tenantScopedQueryKeyHash(["roles"])
    );
  });

  it("still distinguishes different keys within one tenant", () => {
    setActiveTenant("tenant-a");
    expect(tenantScopedQueryKeyHash(["roles"])).not.toBe(
      tenantScopedQueryKeyHash(["groups"])
    );
  });

  it("cannot be collided by a key that spells the sentinel itself", () => {
    // `hashKey` serialises the array, so a leading element equal to the
    // no-tenant sentinel produces a two-element array under one tenant and a
    // one-element array under none — different JSON, different hash.
    setActiveTenant(null);
    const spoofed = tenantScopedQueryKeyHash([OWN_SCOPE_CACHE_SLOT, "users"]);
    setActiveTenant(OWN_SCOPE_CACHE_SLOT);
    expect(tenantScopedQueryKeyHash(["users"])).not.toBe(spoofed);
  });

  it("is the QueryClient's configured hash function", () => {
    expect(queryClient.getDefaultOptions().queries?.queryKeyHashFn).toBe(
      tenantScopedQueryKeyHash
    );
  });

  it("leaves partial-key matching alone, so invalidation still works", () => {
    // `invalidateQueries` matches on the key ARRAY, not on this hash. If that
    // stopped being true every mutation in the app would silently stop
    // refreshing its list.
    setActiveTenant("tenant-a");
    const client = new QueryClient({
      defaultOptions: { queries: { queryKeyHashFn: tenantScopedQueryKeyHash } },
    });
    client.setQueryData(["users", 1], ["row"]);
    expect(client.getQueryData(["users", 1])).toEqual(["row"]);
    expect(
      client.getQueryCache().findAll({ queryKey: ["users"] })
    ).toHaveLength(1);
  });
});
