import { describe, it, expect, vi } from "vitest";
import {
  INVALIDATION_GRAPH,
  relatedQueryKeys,
  invalidateEntity,
  invalidateEntities,
} from "@/lib/queryInvalidation";

function recordingClient() {
  const invalidated: string[] = [];
  return {
    invalidated,
    invalidateQueries({ queryKey }: { queryKey: unknown[] }) {
      invalidated.push(String(queryKey[0]));
    },
  };
}

describe("relatedQueryKeys", () => {
  it("always includes the entity itself", () => {
    for (const entity of Object.keys(INVALIDATION_GRAPH)) {
      expect(relatedQueryKeys(entity), entity).toContain(entity);
    }
  });

  it("falls back to just the entity when it has no declared relations", () => {
    // Standalone entities — webhooks, reactors, audit logs — keep exactly the
    // behaviour every mutation had before the graph existed.
    expect(relatedQueryKeys("webhooks")).toEqual(["webhooks"]);
    expect(relatedQueryKeys("reactors")).toEqual(["reactors"]);
  });

  it("returns a fresh array the caller cannot use to mutate the graph", () => {
    const keys = relatedQueryKeys("permissions");
    keys.push("nonsense");
    expect(relatedQueryKeys("permissions")).not.toContain("nonsense");
  });
});

describe("the graph itself", () => {
  it("declares no duplicate keys within one entity", () => {
    for (const [entity, keys] of Object.entries(INVALIDATION_GRAPH)) {
      expect(new Set(keys).size, entity).toBe(keys.length);
    }
  });

  it("is symmetric where both sides show the same rows", () => {
    // A role's members and a user's roles are one fact viewed from two ends.
    // If only one direction is declared, mutating from the other end leaves a
    // stale view — which is the whole class of bug this graph exists to close,
    // so the asymmetry is worth failing a test over.
    const pairs: [string, string][] = [
      ["roles", "role-permissions"],
      ["permissions", "role-permissions"],
      ["groups", "group-members"],
      ["groups", "group-roles"],
      ["resources", "scopes"],
      ["certificates", "service-accounts"],
      ["tenants", "organizations"],
    ];
    for (const [a, b] of pairs) {
      expect(relatedQueryKeys(a), `${a} → ${b}`).toContain(b);
      expect(relatedQueryKeys(b), `${b} → ${a}`).toContain(a);
    }
  });
});

describe("invalidateEntity", () => {
  it("invalidates role grant lists when a permission changes", () => {
    // The reported bug, exactly: delete a permission, open a role that had it
    // granted, and the grant is still listed. `["role-permissions"]` holds its
    // own copy and `staleTime` gives react-query no reason to refetch it.
    const client = recordingClient();
    invalidateEntity(client, "permissions");
    expect(client.invalidated).toContain("permissions");
    expect(client.invalidated).toContain("role-permissions");
  });

  it("invalidates by key root so every parameterised variant is covered", () => {
    // `["role-permissions", roleId]` exists once per role. The client cannot
    // know which roles held the deleted permission, so the root is invalidated
    // and react-query's prefix matching reaches all of them.
    const client = recordingClient();
    invalidateEntity(client, "permissions");
    expect(client.invalidated).toContain("role-permissions");
    expect(client.invalidated.every((k) => !k.includes(","))).toBe(true);
  });

  it("invalidates scoped grants when a scope disappears", () => {
    // A scoped grant names scopes by id; deleting one leaves the grant
    // pointing at nothing until the grant list is refetched.
    const client = recordingClient();
    invalidateEntity(client, "scopes");
    expect(client.invalidated).toContain("role-permissions");
    expect(client.invalidated).toContain("resources");
  });

  it("reaches both ends of a membership edge", () => {
    const client = recordingClient();
    invalidateEntity(client, "users");
    expect(client.invalidated).toContain("group-members");
    expect(client.invalidated).toContain("role-users");
  });

  it("leaves a standalone entity alone", () => {
    const client = recordingClient();
    invalidateEntity(client, "webhooks");
    expect(client.invalidated).toEqual(["webhooks"]);
  });
});

describe("invalidateEntities", () => {
  it("invalidates each key at most once across overlapping graphs", () => {
    const client = recordingClient();
    invalidateEntities(client, ["roles", "permissions"]);
    // Both graphs name `role-permissions`; it must be invalidated once.
    expect(new Set(client.invalidated).size).toBe(client.invalidated.length);
    expect(client.invalidated).toContain("role-permissions");
  });

  it("covers the union of both entities", () => {
    const client = recordingClient();
    invalidateEntities(client, ["certificates", "users"]);
    expect(client.invalidated).toContain("service-accounts");
    expect(client.invalidated).toContain("role-users");
  });

  it("does nothing when given nothing", () => {
    const client = recordingClient();
    const spy = vi.spyOn(client, "invalidateQueries");
    invalidateEntities(client, []);
    expect(spy).not.toHaveBeenCalled();
  });
});
