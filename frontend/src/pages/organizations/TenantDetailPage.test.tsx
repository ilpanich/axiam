import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { TenantDetailPage } from "./TenantDetailPage";
import { makeClient } from "@/test/renderWithProviders";

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

beforeEach(() => {
  vi.clearAllMocks();
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
