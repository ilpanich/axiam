import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import {
  AssignmentScopeBadge,
  ResourceScopePicker,
  TenantScopeBadge,
  TenantScopePicker,
} from "./AssignmentScope";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore } from "@/stores/auth";

const TENANTS = [
  {
    id: "t1",
    name: "Production",
    slug: "production",
    status: "Active",
    kind: "standard",
    organization_id: "o1",
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "t2",
    name: "Staging",
    slug: "staging",
    status: "Active",
    kind: "standard",
    organization_id: "o1",
    created_at: "2026-01-02T00:00:00Z",
  },
  {
    id: "t3",
    name: "Billing",
    slug: "billing",
    status: "Active",
    kind: "standard",
    organization_id: "o1",
    created_at: "2026-01-03T00:00:00Z",
  },
  // The organization's own scope. `useReachableTenants` filters it out: an
  // assignment scoped to it is the unrestricted assignment, so offering it as
  // a checkbox would be offering "restrict this to everything".
  {
    id: "org-tenant",
    name: "Acme (organization)",
    slug: "acme",
    status: "Active",
    kind: "organization",
    organization_id: "o1",
    created_at: "2026-01-01T00:00:00Z",
  },
];

const RESOURCES = [
  { id: "r1", name: "billing-service", tenant_id: "t1" },
  { id: "r2", name: "reporting-service", tenant_id: "t1" },
];

/** Serve the two list endpoints these components read, both paginated. */
function mockLists({ tenants = TENANTS, resources = RESOURCES } = {}) {
  apiMock.get.mockImplementation((url: string) => {
    if (url === "/api/v1/organizations/o1/tenants")
      return Promise.resolve(res({ items: tenants, total: tenants.length }));
    if (url === "/api/v1/resources")
      return Promise.resolve(res({ items: resources, total: resources.length }));
    return Promise.reject(new Error(`unexpected GET ${url}`));
  });
}

/**
 * An organization-level principal that has NOT switched into a tenant — the
 * one standing in which `useIsOrganizationScope()` is true, and therefore the
 * only one in which the tenant picker renders at all.
 */
function signInAtOrganizationScope() {
  useAuthStore.setState({
    user: {
      id: "u1",
      username: "org-admin",
      email: "org-admin@acme.test",
      permissions: ["*"],
      tenant_id: "org-tenant",
      principal_tenant_id: "org-tenant",
      org_id: "o1",
      organization_level: true,
    },
    activeTenantId: null,
    isAuthenticated: true,
    isInitializing: false,
  });
}

/** The same person, but looking at one tenant — no longer organization scope. */
function switchToTenant(tenantId: string) {
  useAuthStore.setState({ activeTenantId: tenantId });
}

/** An ordinary tenant administrator: never at organization scope. */
function signInAsTenantAdmin() {
  useAuthStore.setState({
    user: {
      id: "u2",
      username: "tenant-admin",
      email: "tenant-admin@acme.test",
      permissions: ["*"],
      tenant_id: "t1",
      principal_tenant_id: "t1",
      org_id: "o1",
      organization_level: false,
    },
    activeTenantId: null,
    isAuthenticated: true,
    isInitializing: false,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockLists();
  signInAtOrganizationScope();
});

const nameFor = (id: string) => (id === "r1" ? "billing-service" : id);

describe("AssignmentScopeBadge", () => {
  it("says Organization-wide for an unscoped assignment at organization scope", () => {
    renderWithProviders(
      <AssignmentScopeBadge resourceId={null} nameFor={nameFor} />,
    );
    const badge = screen.getByText("Organization-wide");
    expect(badge).toBeInTheDocument();
    expect(badge.closest("span")).toHaveAttribute(
      "title",
      expect.stringContaining("every tenant of this organization"),
    );
  });

  it("says Tenant-wide for the same assignment seen from inside a tenant", () => {
    signInAsTenantAdmin();
    renderWithProviders(
      <AssignmentScopeBadge resourceId={null} nameFor={nameFor} />,
    );
    expect(screen.getByText("Tenant-wide")).toBeInTheDocument();
    expect(screen.queryByText("Organization-wide")).not.toBeInTheDocument();
  });

  it("an organization admin who switched into a tenant sees Tenant-wide", () => {
    // Both halves of `useIsOrganizationScope` matter: the roles being edited
    // live in `t1` and reach exactly `t1`, however privileged the editor is.
    switchToTenant("t1");
    renderWithProviders(
      <AssignmentScopeBadge resourceId={null} nameFor={nameFor} />,
    );
    expect(screen.getByText("Tenant-wide")).toBeInTheDocument();
  });

  it("names the resource for a resource-scoped assignment", () => {
    renderWithProviders(
      <AssignmentScopeBadge resourceId="r1" nameFor={nameFor} />,
    );
    const badge = screen.getByText("billing-service");
    expect(badge).toBeInTheDocument();
    expect(badge.closest("span")).toHaveAttribute(
      "title",
      'Applies only under the resource "billing-service" and its descendants',
    );
  });

  it("replaces the wide label outright when the assignment names tenants", async () => {
    renderWithProviders(
      <AssignmentScopeBadge
        resourceId={null}
        nameFor={nameFor}
        tenantScope={["t1"]}
      />,
    );
    // "Organization-wide" would be exactly backwards for a confined grant.
    await waitFor(() =>
      expect(screen.getByText("Production")).toBeInTheDocument(),
    );
    expect(screen.queryByText("Organization-wide")).not.toBeInTheDocument();
  });

  it("shows both badges when an assignment is tenant- and resource-scoped", async () => {
    renderWithProviders(
      <AssignmentScopeBadge
        resourceId="r1"
        nameFor={nameFor}
        tenantScope={["t1", "t2"]}
      />,
    );
    await waitFor(() =>
      expect(screen.getByText("Production, Staging")).toBeInTheDocument(),
    );
    expect(screen.getByText("billing-service")).toBeInTheDocument();
  });

  it("treats an empty tenant_scope array as unrestricted", () => {
    // The server reads `[]` and `null` alike as "every tenant", so the badge
    // must not claim a restriction that does not exist.
    renderWithProviders(
      <AssignmentScopeBadge resourceId={null} nameFor={nameFor} tenantScope={[]} />,
    );
    expect(screen.getByText("Organization-wide")).toBeInTheDocument();
  });
});

describe("TenantScopeBadge", () => {
  it("names the tenants when there are at most two", async () => {
    renderWithProviders(<TenantScopeBadge tenantIds={["t1", "t2"]} />);
    await waitFor(() =>
      expect(screen.getByText("Production, Staging")).toBeInTheDocument(),
    );
  });

  it("counts them past two, but still names them all in the tooltip", async () => {
    renderWithProviders(<TenantScopeBadge tenantIds={["t1", "t2", "t3"]} />);
    // The count renders immediately — each unresolved id falls back to a
    // shortened form of itself — so the assertion has to wait for the names.
    const badge = await screen.findByText("3 tenants");
    await waitFor(() =>
      expect(badge.closest("span")).toHaveAttribute(
        "title",
        "Applies only in: Production, Staging, Billing",
      ),
    );
  });

  it("shows a shortened id for a tenant this operator cannot see", async () => {
    // Not hidden and not counted silently: "3 tenants" that is really 2 you can
    // see and 1 you cannot is what makes an access review wrong.
    renderWithProviders(<TenantScopeBadge tenantIds={["deadbeef-1111-2222"]} />);
    await waitFor(() =>
      expect(screen.getByText("deadbeef…")).toBeInTheDocument(),
    );
  });
});

describe("ResourceScopePicker", () => {
  it("offers the organization-wide empty option at organization scope", async () => {
    const onChange = vi.fn();
    renderWithProviders(
      <ResourceScopePicker
        id="scope"
        value=""
        onChange={onChange}
        subject="user"
      />,
    );
    await waitFor(() =>
      expect(
        screen.getByRole("option", {
          name: "Organization-wide — every resource in every tenant",
        }),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByText("The user gets this role everywhere in the tenant."),
    ).toBeInTheDocument();
  });

  it("offers the tenant-wide empty option inside a tenant", async () => {
    signInAsTenantAdmin();
    renderWithProviders(
      <ResourceScopePicker
        id="scope"
        value=""
        onChange={vi.fn()}
        subject="group"
      />,
    );
    await waitFor(() =>
      expect(
        screen.getByRole("option", {
          name: "Tenant-wide — every resource in this tenant",
        }),
      ).toBeInTheDocument(),
    );
  });

  it("lists the tenant's resources and reports the chosen one", async () => {
    const onChange = vi.fn();
    renderWithProviders(
      <ResourceScopePicker
        id="scope"
        value=""
        onChange={onChange}
        subject="service account"
      />,
    );
    await waitFor(() =>
      expect(
        screen.getByRole("option", { name: "reporting-service" }),
      ).toBeInTheDocument(),
    );
    await userEvent.selectOptions(screen.getByRole("combobox"), "r1");
    expect(onChange).toHaveBeenCalledWith("r1");
  });

  it("changes the caption once a resource is chosen", async () => {
    renderWithProviders(
      <ResourceScopePicker
        id="scope"
        value="r1"
        onChange={vi.fn()}
        subject="service account"
      />,
    );
    expect(
      screen.getByText(
        "The service account gets this role only under the selected resource and its descendants.",
      ),
    ).toBeInTheDocument();
  });

  it("disables the select when the dialog is submitting", () => {
    renderWithProviders(
      <ResourceScopePicker
        id="scope"
        value=""
        onChange={vi.fn()}
        subject="user"
        disabled
      />,
    );
    expect(screen.getByRole("combobox")).toBeDisabled();
  });
});

describe("TenantScopePicker", () => {
  it("renders nothing outside an organization scope", () => {
    // In an ordinary tenant the only tenant an assignment could name is that
    // tenant itself, and the server refuses the field there outright.
    signInAsTenantAdmin();
    const { container } = renderWithProviders(
      <TenantScopePicker value={[]} onChange={vi.fn()} subject="user" />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("points an organization administrator inside a tenant at the switcher", async () => {
    // The control still cannot be offered — roles edited from inside `t1` live
    // in `t1` and reach it alone — but disappearing without a word left the
    // scope selector as an unmarked prerequisite for the whole feature.
    switchToTenant("t1");
    renderWithProviders(
      <TenantScopePicker value={[]} onChange={vi.fn()} subject="user" />,
    );
    expect(
      screen.getByText(/to confine this assignment to particular tenants/),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole("checkbox")).not.toBeInTheDocument(),
    );
  });

  it("says nothing to a principal that cannot reach the organization scope", () => {
    // An organization account already confined to particular tenants is never
    // offered the organization scope by the switcher, and cannot set a tenant
    // scope at all. Telling it to switch would describe a door that is not
    // there.
    useAuthStore.setState({
      user: {
        id: "u3",
        username: "two-tenant-admin",
        email: "two-tenant-admin@acme.test",
        permissions: ["*"],
        tenant_id: "org-tenant",
        principal_tenant_id: "org-tenant",
        org_id: "o1",
        organization_level: true,
        reachable_tenant_ids: ["t1", "t2"],
      },
      activeTenantId: "t1",
    });
    const { container } = renderWithProviders(
      <TenantScopePicker value={[]} onChange={vi.fn()} subject="user" />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("offers every standard tenant, and not the organization scope itself", async () => {
    renderWithProviders(
      <TenantScopePicker value={[]} onChange={vi.fn()} subject="user" />,
    );
    await waitFor(() =>
      expect(screen.getAllByRole("checkbox")).toHaveLength(3),
    );
    expect(screen.getByText("Production")).toBeInTheDocument();
    expect(screen.queryByText("Acme (organization)")).not.toBeInTheDocument();
  });

  it("says an empty selection reaches every tenant", async () => {
    renderWithProviders(
      <TenantScopePicker value={[]} onChange={vi.fn()} subject="user" />,
    );
    expect(
      screen.getByText(
        "The user gets this role in every tenant of the organization.",
      ),
    ).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByRole("checkbox")).toHaveLength(3));
  });

  it("uses the singular for one selected tenant and the plural for more", async () => {
    const { rerender } = renderWithProviders(
      <TenantScopePicker value={["t1"]} onChange={vi.fn()} subject="group" />,
    );
    expect(
      screen.getByText(
        "The group gets this role only in the selected tenant — not in the organization scope itself.",
      ),
    ).toBeInTheDocument();

    rerender(
      <TenantScopePicker
        value={["t1", "t2"]}
        onChange={vi.fn()}
        subject="group"
      />,
    );
    expect(
      screen.getByText(
        "The group gets this role only in the selected tenants — not in the organization scope itself.",
      ),
    ).toBeInTheDocument();
  });

  it("adds a tenant on check and removes it on uncheck", async () => {
    const onChange = vi.fn();
    const { rerender } = renderWithProviders(
      <TenantScopePicker value={[]} onChange={onChange} subject="user" />,
    );
    await waitFor(() => expect(screen.getAllByRole("checkbox")).toHaveLength(3));

    await userEvent.click(screen.getByRole("checkbox", { name: "Production" }));
    expect(onChange).toHaveBeenCalledWith(["t1"]);

    onChange.mockClear();
    rerender(
      <TenantScopePicker value={["t1"]} onChange={onChange} subject="user" />,
    );
    await userEvent.click(screen.getByRole("checkbox", { name: "Production" }));
    expect(onChange).toHaveBeenCalledWith([]);
  });

  it("shows a loading note before the tenant list arrives", () => {
    let release: (value: unknown) => void = () => {};
    apiMock.get.mockImplementation((url: string) => {
      if (url === "/api/v1/organizations/o1/tenants")
        return new Promise((resolve) => {
          release = resolve;
        });
      return Promise.resolve(res({ items: [], total: 0 }));
    });
    renderWithProviders(
      <TenantScopePicker value={[]} onChange={vi.fn()} subject="user" />,
    );
    expect(screen.getByText("Loading tenants…")).toBeInTheDocument();
    release(res({ items: [], total: 0 }));
  });

  it("says so when the organization has no tenants to scope to", async () => {
    mockLists({ tenants: [TENANTS[3]] });
    renderWithProviders(
      <TenantScopePicker value={[]} onChange={vi.fn()} subject="user" />,
    );
    await waitFor(() =>
      expect(
        screen.getByText("This organization has no tenants yet."),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  });

  it("disables every checkbox while the dialog is submitting", async () => {
    renderWithProviders(
      <TenantScopePicker value={[]} onChange={vi.fn()} subject="user" disabled />,
    );
    await waitFor(() => expect(screen.getAllByRole("checkbox")).toHaveLength(3));
    for (const box of screen.getAllByRole("checkbox")) {
      expect(box).toBeDisabled();
    }
  });
});
