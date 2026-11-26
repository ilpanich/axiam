import { describe, expect, it } from "vitest";

import {
  organizationPrincipalReaches,
  reachLabel,
  reachTitle,
  roleReach,
  useCanActOnOrganization,
  useIsOrganizationScope,
  useIsTenantRestricted,
} from "@/lib/grantReach";
import { renderHook } from "@testing-library/react";
import { useAuthStore, type AuthUser } from "@/stores/auth";

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

describe("useCanActOnOrganization", () => {
  /** Populate the auth store as a given kind of principal. */
  function signInAs(user: Partial<AuthUser> | null) {
    useAuthStore.setState({
      user: user
        ? ({
            id: "u1",
            username: "u",
            email: "u@x.io",
            permissions: ["*"],
            tenant_id: "t1",
            ...user,
          } as AuthUser)
        : null,
      isAuthenticated: user !== null,
      isInitializing: false,
    });
  }

  it("says no to a tenant principal, whatever permissions it holds", () => {
    // The reported defect in one assertion: a tenant's seeded `super-admin`
    // holds the whole permission registry, wildcard included, and is still
    // refused every organization-level action by
    // `require_organization_principal`. A permission-based gate cannot see
    // that; this one can.
    signInAs({ organization_level: false, permissions: ["*"] });
    expect(renderHook(() => useCanActOnOrganization()).result.current).toBe(
      false,
    );
  });

  it("says yes to an unrestricted organization principal", () => {
    signInAs({ organization_level: true });
    expect(renderHook(() => useCanActOnOrganization()).result.current).toBe(
      true,
    );
  });

  it("says no to an organization principal confined to some tenants", () => {
    // It lives in the organization scope like any other, so the residence test
    // alone would say yes — and the server would then answer 403.
    signInAs({ organization_level: true, reachable_tenant_ids: ["t-a"] });
    expect(renderHook(() => useCanActOnOrganization()).result.current).toBe(
      false,
    );
  });

  it("says no while nobody is signed in", () => {
    signInAs(null);
    expect(renderHook(() => useCanActOnOrganization()).result.current).toBe(
      false,
    );
  });

  it("is independent of which tenant is currently selected", () => {
    // `useIsOrganizationScope` deliberately goes false the moment a tenant is
    // selected, because it answers "which scope am I editing". This one must
    // not: the server does not consult the selected tenant when it is asked to
    // create another organization, and a gate that did would hide the
    // organization's controls from its own administrator mid-task.
    signInAs({ organization_level: true });
    useAuthStore.setState({ activeTenantId: "t-a", activeTenantName: "A" });
    expect(renderHook(() => useCanActOnOrganization()).result.current).toBe(
      true,
    );
    expect(renderHook(() => useIsOrganizationScope()).result.current).toBe(
      false,
    );
  });
});

describe("useIsTenantRestricted", () => {
  it("is true only when a reach list is present", () => {
    useAuthStore.setState({
      user: {
        id: "u1",
        username: "u",
        email: "u@x.io",
        permissions: [],
        tenant_id: "t1",
        organization_level: true,
        reachable_tenant_ids: ["t-a"],
      },
      isAuthenticated: true,
      isInitializing: false,
    });
    expect(renderHook(() => useIsTenantRestricted()).result.current).toBe(true);

    useAuthStore.setState({
      user: {
        id: "u1",
        username: "u",
        email: "u@x.io",
        permissions: [],
        tenant_id: "t1",
        organization_level: true,
      },
      isAuthenticated: true,
      isInitializing: false,
    });
    expect(renderHook(() => useIsTenantRestricted()).result.current).toBe(false);
  });
});

describe("organizationPrincipalReaches", () => {
  // Mirrors `require_organization_principal_for_tenant` (QR9-2).
  const base: AuthUser = {
    id: "u1",
    username: "u",
    email: "u@x.io",
    permissions: ["*"],
    tenant_id: "org-tenant",
    principal_tenant_id: "org-tenant",
    organization_level: true,
  };

  it("admits an unrestricted organization principal for any tenant", () => {
    expect(organizationPrincipalReaches(base, "t1")).toBe(true);
    expect(organizationPrincipalReaches(base, "t9")).toBe(true);
  });

  it("admits a restricted organization principal only for the tenants it reaches", () => {
    const restricted = { ...base, reachable_tenant_ids: ["t1"] };
    expect(organizationPrincipalReaches(restricted, "t1")).toBe(true);
    expect(organizationPrincipalReaches(restricted, "t9")).toBe(false);
    expect(
      organizationPrincipalReaches({ ...base, reachable_tenant_ids: [] }, "t1"),
    ).toBe(false);
  });

  it("refuses a tenant principal, its own tenant included", () => {
    const tenantAdmin = {
      ...base,
      tenant_id: "t1",
      principal_tenant_id: "t1",
      organization_level: false,
    };
    expect(organizationPrincipalReaches(tenantAdmin, "t1")).toBe(false);
    expect(organizationPrincipalReaches(null, "t1")).toBe(false);
  });
});
