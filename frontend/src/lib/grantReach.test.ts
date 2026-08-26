import { describe, expect, it } from "vitest";

import { reachLabel, reachTitle, roleReach } from "@/lib/grantReach";

describe("roleReach", () => {
  it("calls a global role in the organization scope organization-wide", () => {
    expect(roleReach(true, true)).toBe("organization");
  });

  it("calls a global role in an ordinary tenant tenant-wide", () => {
    // The label this replaces said "Global" for both, which claimed the
    // stronger reach for a role that only ever applied inside one tenant.
    expect(roleReach(true, false)).toBe("tenant");
  });

  it("calls a resource-scoped role resource-scoped, in either scope", () => {
    // Previously labelled "Tenant" — backwards, since a resource-scoped role is
    // the narrowest kind there is, narrower than the tenant it lives in.
    expect(roleReach(false, false)).toBe("resource");
    expect(roleReach(false, true)).toBe("resource");
  });
});

describe("labels", () => {
  it("gives every reach a distinct label and explanation", () => {
    const reaches = ["organization", "tenant", "resource"] as const;
    const labels = reaches.map(reachLabel);
    const titles = reaches.map(reachTitle);
    expect(new Set(labels).size).toBe(reaches.length);
    expect(new Set(titles).size).toBe(reaches.length);
    expect(labels.every((l) => l.length > 0)).toBe(true);
  });

  it("never labels a tenant-scoped grant 'Global'", () => {
    // The word is the whole problem: it is true of an organization-level role
    // and false of every other kind, and it was applied to both.
    expect(reachLabel(roleReach(true, false))).not.toMatch(/global/i);
    expect(reachLabel(roleReach(false, false))).not.toMatch(/global/i);
  });
});
