import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { createMemoryRouter } from "react-router";
import { RouterProvider } from "react-router/dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { TenantDetailPage } from "./TenantDetailPage";
import { makeClient } from "@/test/renderWithProviders";
import { useAuthStore } from "@/stores/auth";

const org = { id: "o1", name: "Acme Corp", slug: "acme", created_at: "2026-01-01T00:00:00Z" };

const tenant = {
  id: "t1",
  name: "Production",
  slug: "prod",
  status: "Active",
  metadata: { description: "Prod tenant" },
  organization_id: "o1",
  created_at: "2026-01-01T00:00:00Z",
};

const URLS = {
  org: "/api/v1/organizations/o1",
  tenant: "/api/v1/organizations/o1/tenants/t1",
};

function routeGet(map: Record<string, unknown>) {
  apiMock.get.mockImplementation((url: string) => {
    if (url in map) return Promise.resolve(res(map[url]));
    return Promise.resolve(res([]));
  });
}

function renderPage() {
  const client = makeClient();
  const router = createMemoryRouter(
    [
      { path: "/organizations", element: <div>Orgs list</div> },
      { path: "/organizations/:orgId", element: <div>Org detail</div> },
      {
        path: "/organizations/:orgId/tenants/:tenantId",
        element: <TenantDetailPage />,
      },
    ],
    { initialEntries: ["/organizations/o1/tenants/t1"] }
  );
  return render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}

/**
 * Sign in as the organization's own, unrestricted administrator.
 *
 * `tenants::get` calls `require_organization_principal_for_tenant` (SA-02): it
 * serves the record to a principal whose own record lives in the organization
 * scope (`organization_level`) and whose roles reach the named tenant — every
 * tenant when `reachable_tenant_ids` is absent, as here.
 */
function signInAsOrganizationAdmin() {
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
    isAuthenticated: true,
    isInitializing: false,
  });
}

/** A Standard tenant's own administrator: cannot act on the organization. */
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
    isAuthenticated: true,
    isInitializing: false,
  });
}

/**
 * An organization-level account whose roles are restricted to `reach` — what
 * `/auth/me` reports as `reachable_tenant_ids`.
 */
function signInAsRestrictedOrganizationPrincipal(reach: string[]) {
  useAuthStore.setState({
    user: {
      id: "u3",
      username: "restricted",
      email: "restricted@acme.test",
      permissions: ["tenants:get"],
      tenant_id: reach[0] ?? "org-tenant",
      principal_tenant_id: "org-tenant",
      org_id: "o1",
      organization_level: true,
      reachable_tenant_ids: reach,
    },
    isAuthenticated: true,
    isInitializing: false,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  signInAsOrganizationAdmin();
});

describe("TenantDetailPage", () => {
  it("shows a loading placeholder while the tenant is fetching", () => {
    apiMock.get.mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(screen.getByText("Loading...")).toBeInTheDocument();
  });

  it("renders the tenant details with breadcrumb org name", async () => {
    routeGet({ [URLS.org]: org, [URLS.tenant]: tenant });
    renderPage();
    expect((await screen.findAllByText("Production")).length).toBeGreaterThan(0);
    expect(screen.getByText("prod")).toBeInTheDocument();
    // "Prod tenant" appears both as the header description and the detail row.
    expect(screen.getAllByText("Prod tenant").length).toBeGreaterThan(0);
    expect(screen.getByText("t1")).toBeInTheDocument();
    // Breadcrumb links to org.
    expect(screen.getByRole("link", { name: "Acme Corp" })).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
  });

  it("falls back to the tenant id in the breadcrumb before the tenant name resolves", async () => {
    routeGet({ [URLS.org]: org, [URLS.tenant]: { ...tenant, metadata: {} } });
    renderPage();
    // Description row is omitted when metadata has no description.
    expect((await screen.findAllByText("Production")).length).toBeGreaterThan(0);
    expect(screen.queryByText("Prod tenant")).not.toBeInTheDocument();
  });

  it("refuses a tenant administrator without fetching the tenant (QR8-1)", async () => {
    // A tenant's own administrator does not live in the organization scope, so
    // `require_organization_principal_for_tenant` answers 403 to
    // `GET /organizations/{org}/tenants/{tenant}` — its own tenant included
    // (SA-02). The page must say so instead of fetching, getting the 403 and
    // dead-ending on "Tenant not found.".
    signInAsTenantAdmin();
    routeGet({ [URLS.org]: org, [URLS.tenant]: tenant });
    renderPage();
    expect(await screen.findByText("Access Denied")).toBeInTheDocument();
    expect(screen.queryByText("Tenant not found.")).not.toBeInTheDocument();
    expect(screen.queryByText("Production")).not.toBeInTheDocument();
    const fetched = apiMock.get.mock.calls.map((c) => c[0]);
    expect(fetched).not.toContain(URLS.tenant);
    expect(fetched).not.toContain(URLS.org);
  });

  it("shows the tenant to an organization principal whose reach covers it (QR9-2)", async () => {
    // `reachable_tenant_ids` names t1: the server's
    // `require_organization_principal_for_tenant` admits this account for t1,
    // so the page shows the record.
    signInAsRestrictedOrganizationPrincipal(["t1"]);
    routeGet({ [URLS.org]: org, [URLS.tenant]: tenant });
    renderPage();
    expect((await screen.findAllByText("Production")).length).toBeGreaterThan(0);
    expect(screen.queryByText("Access Denied")).not.toBeInTheDocument();
    expect(apiMock.get.mock.calls.map((c) => c[0])).toContain(URLS.tenant);
  });

  it("refuses an organization principal whose reach does not cover the tenant (QR9-2)", async () => {
    // Its roles reach t9 only; the server answers 403 for t1 ("this account's
    // roles do not reach the tenant this action names"), so nothing is fetched.
    signInAsRestrictedOrganizationPrincipal(["t9"]);
    routeGet({ [URLS.org]: org, [URLS.tenant]: tenant });
    renderPage();
    expect(await screen.findByText("Access Denied")).toBeInTheDocument();
    const fetched = apiMock.get.mock.calls.map((c) => c[0]);
    expect(fetched).not.toContain(URLS.tenant);
    expect(fetched).not.toContain(URLS.org);
  });

  it("shows the organization administrator the tenant record", async () => {
    routeGet({ [URLS.org]: org, [URLS.tenant]: tenant });
    renderPage();
    expect((await screen.findAllByText("Production")).length).toBeGreaterThan(0);
    expect(screen.queryByText("Access Denied")).not.toBeInTheDocument();
    expect(apiMock.get.mock.calls.map((c) => c[0])).toContain(URLS.tenant);
  });

  it("shows 'Tenant not found.' when the tenant is missing", async () => {
    apiMock.get.mockImplementation((url: string) => {
      if (url === URLS.org) return Promise.resolve(res(org));
      if (url === URLS.tenant) return Promise.reject(new Error("not found"));
      return Promise.resolve(res([]));
    });
    renderPage();
    expect(await screen.findByText("Tenant not found.")).toBeInTheDocument();
  });
});
