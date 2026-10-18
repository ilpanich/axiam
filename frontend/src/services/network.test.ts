import { describe, it, expect, vi, beforeEach } from "vitest";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { networkService, SERVICE_TYPES, TERMINATION_ACTIONS } from "./network";

beforeEach(() => vi.clearAllMocks());

describe("networkService", () => {
  it("reaches the eleven management operations and nothing else", async () => {
    apiMock.get.mockResolvedValue(res({ items: [], total: 0, offset: 0, limit: 200 }));
    apiMock.post.mockResolvedValue(res({}));
    apiMock.put.mockResolvedValue(res({}));
    apiMock.delete.mockResolvedValue(res(undefined));

    await networkService.listSegments({ search: "x", site: "hq" });
    await networkService.createSegment({
      kind: "access",
      site_key: "hq",
      name: "n",
      vlan_id: 10,
      filter_ids: [],
      rank: 1,
      enabled: true,
    });
    await networkService.replaceSegment("s1", { version: 1, vlan_id: 10, filter_ids: [], enabled: true });
    await networkService.deleteSegment("s1", 2);
    await networkService.getProfile("s1");
    await networkService.createProfile({
      segment_id: "s1",
      segment_version: 1,
      profile: { session_timeout_secs: 900, termination_action: "default" },
    });
    await networkService.replaceProfile("s1", {
      version: 1,
      segment_version: 2,
      profile: { session_timeout_secs: 900, termination_action: "default" },
    });
    await networkService.deleteProfile("s1", 3);
    await networkService.getPolicy();
    await networkService.replacePolicy({ session_timeout_max_secs: 600, version: 0 });

    expect(apiMock.get.mock.calls.map((c) => c[0])).toEqual([
      "/api/v1/network/segments",
      "/api/v1/network/profiles/s1",
      "/api/v1/network/policy",
    ]);
    expect(apiMock.get.mock.calls[0][1]).toEqual({
      params: { search: "x", site: "hq", offset: 0, limit: 200 },
    });
    expect(apiMock.post.mock.calls.map((c) => c[0])).toEqual([
      "/api/v1/network/segments",
      "/api/v1/network/profiles",
    ]);
    expect(apiMock.put.mock.calls.map((c) => c[0])).toEqual([
      "/api/v1/network/segments/s1",
      "/api/v1/network/profiles/s1",
      "/api/v1/network/policy",
    ]);
    expect(apiMock.delete.mock.calls).toEqual([
      ["/api/v1/network/segments/s1", { params: { version: 2 } }],
      ["/api/v1/network/profiles/s1", { params: { version: 3 } }],
    ]);
    const all = [
      ...apiMock.get.mock.calls,
      ...apiMock.post.mock.calls,
      ...apiMock.put.mock.calls,
      ...apiMock.delete.mock.calls,
    ].map((c) => String(c[0]));
    expect(all.some((u) => u.includes("decide"))).toBe(false);
  });

  it("offers only the dictionary's service type and termination actions", () => {
    expect([...SERVICE_TYPES]).toEqual(["framed_user"]);
    expect([...TERMINATION_ACTIONS].sort()).toEqual(["default", "radius_request"]);
  });
});
