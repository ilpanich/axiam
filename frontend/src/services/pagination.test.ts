import { describe, it, expect, beforeEach, vi } from "vitest";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import {
  fetchAllPages,
  unwrapList,
  MAX_PAGE_SIZE,
} from "@/services/_pagination";
import { permissionService, type Permission } from "@/services/permissions";

beforeEach(() => {
  vi.clearAllMocks();
});

/** Build `count` throwaway rows, numbered so page boundaries are visible. */
function rows(count: number, offset = 0): Array<{ id: string }> {
  return Array.from({ length: count }, (_, i) => ({ id: `r${offset + i}` }));
}

describe("unwrapList", () => {
  it("passes a bare array through", () => {
    expect(unwrapList([{ id: "a" }])).toEqual([{ id: "a" }]);
  });

  it("takes items out of a paginated envelope", () => {
    expect(unwrapList({ items: [{ id: "a" }] })).toEqual([{ id: "a" }]);
  });

  it("treats null, undefined and a missing items key as empty", () => {
    expect(unwrapList(null)).toEqual([]);
    expect(unwrapList(undefined)).toEqual([]);
    expect(unwrapList({})).toEqual([]);
  });
});

describe("fetchAllPages", () => {
  it("asks for the server's maximum page size, not its default", async () => {
    apiMock.get.mockResolvedValueOnce(res({ items: [], total: 0 }));
    await fetchAllPages("/api/v1/things");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/things", {
      params: { offset: 0, limit: MAX_PAGE_SIZE },
    });
  });

  it("stops after one request when the page is short", async () => {
    apiMock.get.mockResolvedValueOnce(res({ items: rows(3), total: 3 }));
    const out = await fetchAllPages("/api/v1/things");
    expect(out).toHaveLength(3);
    expect(apiMock.get).toHaveBeenCalledTimes(1);
  });

  it("follows every page and returns the whole collection in order", async () => {
    apiMock.get
      .mockResolvedValueOnce(res({ items: rows(MAX_PAGE_SIZE, 0), total: 250 }))
      .mockResolvedValueOnce(res({ items: rows(50, MAX_PAGE_SIZE), total: 250 }));

    const out = await fetchAllPages<{ id: string }>("/api/v1/things");

    expect(out).toHaveLength(250);
    expect(out[0].id).toBe("r0");
    expect(out[249].id).toBe("r249");
    expect(apiMock.get).toHaveBeenNthCalledWith(2, "/api/v1/things", {
      params: { offset: MAX_PAGE_SIZE, limit: MAX_PAGE_SIZE },
    });
  });

  it("stops on a full final page once total is reached", async () => {
    // Exactly one page's worth: `items.length < MAX_PAGE_SIZE` is false, so
    // only the `total` check can end the loop.
    apiMock.get
      .mockResolvedValueOnce(
        res({ items: rows(MAX_PAGE_SIZE), total: MAX_PAGE_SIZE })
      )
      .mockResolvedValue(res({ items: [], total: MAX_PAGE_SIZE }));

    const out = await fetchAllPages("/api/v1/things");

    expect(out).toHaveLength(MAX_PAGE_SIZE);
    expect(apiMock.get).toHaveBeenCalledTimes(1);
  });

  it("terminates on a short page even when total is wrong", async () => {
    apiMock.get.mockResolvedValueOnce(res({ items: rows(2), total: 9999 }));
    const out = await fetchAllPages("/api/v1/things");
    expect(out).toHaveLength(2);
    expect(apiMock.get).toHaveBeenCalledTimes(1);
  });

  it("returns a bare-array response as-is without paging", async () => {
    apiMock.get.mockResolvedValueOnce(res(rows(MAX_PAGE_SIZE)));
    const out = await fetchAllPages("/api/v1/things");
    expect(out).toHaveLength(MAX_PAGE_SIZE);
    expect(apiMock.get).toHaveBeenCalledTimes(1);
  });

  it("sends caller-supplied params on every page", async () => {
    apiMock.get
      .mockResolvedValueOnce(res({ items: rows(MAX_PAGE_SIZE), total: 201 }))
      .mockResolvedValueOnce(res({ items: rows(1), total: 201 }));

    await fetchAllPages("/api/v1/things", { resource_id: "res-1" });

    expect(apiMock.get).toHaveBeenNthCalledWith(1, "/api/v1/things", {
      params: { resource_id: "res-1", offset: 0, limit: MAX_PAGE_SIZE },
    });
    expect(apiMock.get).toHaveBeenNthCalledWith(2, "/api/v1/things", {
      params: { resource_id: "res-1", offset: MAX_PAGE_SIZE, limit: MAX_PAGE_SIZE },
    });
  });

  it("gives up rather than looping forever when total is never reached", async () => {
    // A server that always reports more than it delivers: pathological, but an
    // unbounded client loop against it is worse than a truncated list.
    apiMock.get.mockResolvedValue(
      res({ items: rows(MAX_PAGE_SIZE), total: Number.MAX_SAFE_INTEGER })
    );
    const out = await fetchAllPages("/api/v1/things");
    expect(apiMock.get.mock.calls.length).toBeLessThanOrEqual(100);
    expect(out.length).toBeGreaterThan(0);
  });
});

describe("permissionService.list", () => {
  it("reaches a permission that sits past the server's default first page", async () => {
    // The regression this exists for: ~110 registry-seeded permissions plus
    // two an operator created. The default page is 50, so a single request
    // never showed the operator's own permissions in the Permissions page or
    // in the role grant picker.
    const seeded: Permission[] = Array.from({ length: 210 }, (_, i) => ({
      id: `seed-${i}`,
      action: `seed:${i}`,
      created_at: "2026-01-01T00:00:00Z",
    }));
    const custom: Permission[] = [
      { id: "custom-1", action: "invoices:approve", created_at: "2026-01-01T00:00:00Z" },
      { id: "custom-2", action: "invoices:void", created_at: "2026-01-01T00:00:00Z" },
    ];

    apiMock.get
      .mockResolvedValueOnce(res({ items: seeded.slice(0, 200), total: 212 }))
      .mockResolvedValueOnce(
        res({ items: [...seeded.slice(200), ...custom], total: 212 })
      );

    const out = await permissionService.list();

    expect(out).toHaveLength(212);
    expect(out.map((p) => p.action)).toContain("invoices:approve");
    expect(out.map((p) => p.action)).toContain("invoices:void");
  });
});
