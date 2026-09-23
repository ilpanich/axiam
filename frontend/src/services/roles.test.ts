import { describe, it, expect, beforeEach, vi } from "vitest";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import {
  AssignmentToggleError,
  assignmentInherits,
  canChangeInherit,
  roleService,
} from "@/services/roles";

beforeEach(() => {
  vi.clearAllMocks();
});

/** An axios-shaped rejection carrying the server's `ErrorBody`. */
function refusal(status: number, message: string) {
  return {
    message: `Request failed with status code ${status}`,
    response: { status, data: { error: "validation_error", message } },
  };
}

// ─── S-10b — the flag on the wire ─────────────────────────────────────────────

describe("the inherit field on the three assign calls", () => {
  it.each([
    ["user", () => roleService.assignToUser("r1", "u1", "res1", null, false), "/api/v1/roles/r1/users", { user_id: "u1" }],
    ["group", () => roleService.assignToGroup("r1", "g1", "res1", null, false), "/api/v1/roles/r1/groups", { group_id: "g1" }],
    [
      "service account",
      () => roleService.assignToServiceAccount("r1", "sa1", "res1", null, false),
      "/api/v1/roles/r1/service-accounts",
      { service_account_id: "sa1" },
    ],
  ] as const)("%s: sends inherit: false beside the resource", async (_, call, url, subject) => {
    apiMock.post.mockResolvedValue(res(undefined));
    await call();
    expect(apiMock.post).toHaveBeenCalledWith(url, {
      ...subject,
      resource_id: "res1",
      inherit: false,
    });
  });

  it.each([
    ["omitted", undefined],
    ["true", true],
  ] as const)("I4 twin: inherit %s sends no inherit key — today's body", async (_, inherit) => {
    apiMock.post.mockResolvedValue(res(undefined));
    await roleService.assignToUser("r1", "u1", "res1", null, inherit);
    await roleService.assignToGroup("r1", "g1", "res1", null, inherit);
    await roleService.assignToServiceAccount("r1", "sa1", "res1", null, inherit);
    for (const [, body] of apiMock.post.mock.calls) {
      expect(body).not.toHaveProperty("inherit");
    }
  });

  it("passes the server's refusal of inherit: false without a resource through", async () => {
    // The dialogs never send this; if something else does, the answer is the
    // server's, not a client-side rule.
    const err = refusal(
      400,
      "inherit: false needs a resource_id — an assignment that names no resource applies across the whole tenant and has no resource to stop at"
    );
    apiMock.post.mockRejectedValue(err);
    await expect(roleService.assignToUser("r1", "u1", null, null, false)).rejects.toBe(err);
    expect(apiMock.post.mock.calls[0][1]).toEqual({ user_id: "u1", inherit: false });
  });
});

describe("assignmentInherits / canChangeInherit", () => {
  it("reads absent as true, as the server's repository does", () => {
    expect(assignmentInherits({})).toBe(true);
    expect(assignmentInherits({ inherit: true })).toBe(true);
    expect(assignmentInherits({ inherit: false })).toBe(false);
  });

  it("offers a change only on a resource-scoped assignment of a non-global role", () => {
    expect(canChangeInherit({ resource_id: "res1" }, false)).toBe(true);
    expect(canChangeInherit({ resource_id: null }, false)).toBe(false);
    expect(canChangeInherit({ resource_id: "res1" }, true)).toBe(false);
  });
});

// ─── S-10b — changing the flag: unassign, then assign ─────────────────────────

describe("roleService.setAssignmentInherit", () => {
  const scoped = { resource_id: "res1", tenant_scope: ["t2"], inherit: true };

  it("unassigns, then assigns again with the new flag and the same scopes", async () => {
    apiMock.delete.mockResolvedValue(res(undefined));
    apiMock.post.mockResolvedValue(res(undefined));
    await roleService.setAssignmentInherit("user", "r1", "u1", scoped, false);

    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/roles/r1/users/u1", {
      params: { resource_id: "res1" },
    });
    expect(apiMock.post).toHaveBeenCalledTimes(1);
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/roles/r1/users", {
      user_id: "u1",
      resource_id: "res1",
      inherit: false,
      tenant_scope: ["t2"],
    });
    // Two calls, in that order: a second assign alone would be a 409
    // (`has_role` is UNIQUE(in, out)).
    expect(apiMock.delete.mock.invocationCallOrder[0]).toBeLessThan(
      apiMock.post.mock.invocationCallOrder[0]
    );
  });

  it("makes an assignment inheritable again with today's body", async () => {
    apiMock.delete.mockResolvedValue(res(undefined));
    apiMock.post.mockResolvedValue(res(undefined));
    await roleService.setAssignmentInherit(
      "group",
      "r1",
      "g1",
      { resource_id: "res1", inherit: false },
      true
    );
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/roles/r1/groups/g1", {
      params: { resource_id: "res1" },
    });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/roles/r1/groups", {
      group_id: "g1",
      resource_id: "res1",
    });
  });

  it("uses the service-account routes for a service account", async () => {
    apiMock.delete.mockResolvedValue(res(undefined));
    apiMock.post.mockResolvedValue(res(undefined));
    await roleService.setAssignmentInherit("service account", "r1", "sa1", scoped, false);
    expect(apiMock.delete.mock.calls[0][0]).toBe("/api/v1/roles/r1/service-accounts/sa1");
    expect(apiMock.post.mock.calls[0][0]).toBe("/api/v1/roles/r1/service-accounts");
  });

  it("a refused unassign changes nothing and is thrown as it came", async () => {
    const err = refusal(403, "missing permission roles:unassign");
    apiMock.delete.mockRejectedValue(err);
    await expect(
      roleService.setAssignmentInherit("user", "r1", "u1", scoped, false)
    ).rejects.toBe(err);
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("a refused re-assign restores the old assignment and says so", async () => {
    apiMock.delete.mockResolvedValue(res(undefined));
    apiMock.post
      .mockRejectedValueOnce(
        refusal(
          400,
          "inherit: false cannot be set on a global role — a global role applies to every resource whatever its assignment names"
        )
      )
      .mockResolvedValueOnce(res(undefined));

    const out = roleService.setAssignmentInherit("user", "r1", "u1", scoped, false);
    await expect(out).rejects.toBeInstanceOf(AssignmentToggleError);
    await out.catch((e: AssignmentToggleError) => {
      expect(e.restored).toBe(true);
      expect(e.message).toMatch(/^The change was refused and the assignment was restored as it was: /);
      expect(e.message).toMatch(/cannot be set on a global role/);
    });
    // The restore is the old assignment exactly: same resource, same tenants,
    // and the old flag — inheritable, so no inherit key.
    expect(apiMock.post).toHaveBeenCalledTimes(2);
    expect(apiMock.post.mock.calls[1][1]).toEqual({
      user_id: "u1",
      resource_id: "res1",
      tenant_scope: ["t2"],
    });
  });

  it("restores a non-inheritable assignment as non-inheritable", async () => {
    apiMock.delete.mockResolvedValue(res(undefined));
    apiMock.post
      .mockRejectedValueOnce(refusal(409, "role already assigned"))
      .mockResolvedValueOnce(res(undefined));
    await expect(
      roleService.setAssignmentInherit(
        "group",
        "r1",
        "g1",
        { resource_id: "res1", inherit: false },
        true
      )
    ).rejects.toMatchObject({ restored: true });
    expect(apiMock.post.mock.calls[1][1]).toEqual({
      group_id: "g1",
      resource_id: "res1",
      inherit: false,
    });
  });

  it("never leaves the subject without the role silently: a failed restore says the role is gone", async () => {
    apiMock.delete.mockResolvedValue(res(undefined));
    apiMock.post
      .mockRejectedValueOnce(refusal(503, "the four-eyes reactor did not answer"))
      .mockRejectedValueOnce(refusal(503, "the four-eyes reactor did not answer"));
    const out = roleService.setAssignmentInherit("user", "r1", "u1", scoped, false);
    await expect(out).rejects.toMatchObject({ restored: false });
    await out.catch((e: AssignmentToggleError) => {
      expect(e.message).toMatch(/^The user no longer holds this role at this resource\./);
      expect(e.message).toMatch(/Assign the role again\.$/);
      expect(e.message).toMatch(/the four-eyes reactor did not answer/);
    });
  });
});
