import { describe, it, expect, beforeEach, vi } from "vitest";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { mdsService, type MdsStatus, type MdsRefreshOutcome } from "./mds";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("mdsService.getStatus", () => {
  it("calls the global (non-tenant-scoped) status endpoint", async () => {
    const status: MdsStatus = {
      no: 42,
      next_update: "2026-09-01",
      entry_count: 1200,
      last_refreshed_at: "2026-08-01T00:00:00Z",
      stale: false,
    };
    apiMock.get.mockResolvedValue(res(status));
    const result = await mdsService.getStatus();
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/mds/status");
    expect(result).toEqual(status);
  });

  it("returns the never-ingested shape as a normal value, not an error", async () => {
    const status: MdsStatus = {
      no: null,
      next_update: null,
      entry_count: 0,
      last_refreshed_at: null,
      stale: false,
    };
    apiMock.get.mockResolvedValue(res(status));
    await expect(mdsService.getStatus()).resolves.toEqual(status);
  });
});

describe("mdsService.refresh", () => {
  it("POSTs with no body and returns the outcome", async () => {
    const outcome: MdsRefreshOutcome = {
      outcome: "replaced",
      no: 43,
      entry_count: 1201,
    };
    apiMock.post.mockResolvedValue(res(outcome));
    const result = await mdsService.refresh();
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/mds/refresh");
    expect(result).toEqual(outcome);
  });

  it("a rejected rollback is still a successful call, distinguished by the outcome tag", async () => {
    const outcome: MdsRefreshOutcome = {
      outcome: "rollback_rejected",
      attempted_no: 10,
      stored_no: 43,
    };
    apiMock.post.mockResolvedValue(res(outcome));
    await expect(mdsService.refresh()).resolves.toEqual(outcome);
  });

  it("propagates a rejection (e.g. MDS disabled -> 400) to the caller", async () => {
    apiMock.post.mockRejectedValue(new Error("MDS ingestion is disabled"));
    await expect(mdsService.refresh()).rejects.toThrow("MDS ingestion is disabled");
  });
});
