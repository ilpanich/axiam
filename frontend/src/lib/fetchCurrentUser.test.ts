import { describe, it, expect, beforeEach, vi } from "vitest";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { fetchCurrentUser } from "./fetchCurrentUser";

beforeEach(() => vi.clearAllMocks());

describe("fetchCurrentUser", () => {
  it("returns null when the response has no user", async () => {
    apiMock.get.mockResolvedValue(res({ permissions: [] }));
    expect(await fetchCurrentUser()).toBeNull();
  });

  it("returns null on a thrown request (401 / network)", async () => {
    apiMock.get.mockRejectedValue(new Error("401"));
    expect(await fetchCurrentUser()).toBeNull();
  });

  it("maps user, defaults permissions to [] when absent, and reads top-level slugs", async () => {
    apiMock.get.mockResolvedValue(
      res({
        user: { id: "u1", username: "alice", email: "a@x.io", tenant_id: "t1" },
        tenant_slug: "ten",
        org_slug: "org",
      })
    );
    const u = await fetchCurrentUser();
    expect(u).toMatchObject({ id: "u1", tenantSlug: "ten", orgSlug: "org" });
    expect(u?.permissions).toEqual([]);
  });

  it("passes through a permissions array and falls back to user-level slugs", async () => {
    apiMock.get.mockResolvedValue(
      res({
        user: {
          id: "u1",
          username: "alice",
          email: "a@x.io",
          tenant_id: "t1",
          tenant_slug: "uten",
          org_slug: "uorg",
        },
        permissions: ["*"],
      })
    );
    const u = await fetchCurrentUser();
    expect(u?.permissions).toEqual(["*"]);
    expect(u?.tenantSlug).toBe("uten");
    expect(u?.orgSlug).toBe("uorg");
  });

  it("leaves slugs undefined when neither top-level nor user-level provided", async () => {
    apiMock.get.mockResolvedValue(
      res({ user: { id: "u1", username: "a", email: "a@x.io", tenant_id: "t1" } })
    );
    const u = await fetchCurrentUser();
    expect(u?.tenantSlug).toBeUndefined();
    expect(u?.orgSlug).toBeUndefined();
  });
});
