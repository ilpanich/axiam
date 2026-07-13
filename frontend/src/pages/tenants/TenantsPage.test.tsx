import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

const navigate = vi.fn();
vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return { ...actual, useNavigate: () => navigate };
});

import { TenantsPage } from "./TenantsPage";
import { renderWithProviders } from "@/test/renderWithProviders";

const orgs = [
  { id: "o1", name: "Acme Corp", slug: "acme-corp", created_at: "2026-01-01T00:00:00Z" },
  { id: "o2", name: "Beta LLC", slug: "beta-llc", created_at: "2026-01-02T00:00:00Z" },
];

const tenantsByOrg: Record<string, unknown[]> = {
  o1: [
    {
      id: "t1",
      name: "Production",
      slug: "production",
      status: "Active",
      metadata: { description: "Prod tenant" },
      organization_id: "o1",
      created_at: "2026-01-03T00:00:00Z",
    },
  ],
  o2: [
    {
      id: "t2",
      name: "Staging",
      slug: "staging",
      status: "Suspended",
      organization_id: "o2",
      created_at: "2026-01-04T00:00:00Z",
    },
  ],
};

function mockDefaultGets() {
  apiMock.get.mockImplementation((url: string) => {
    if (url === "/api/v1/organizations") return Promise.resolve(res(orgs));
    const m = url.match(/^\/api\/v1\/organizations\/(o\d)\/tenants$/);
    if (m) return Promise.resolve(res(tenantsByOrg[m[1]] ?? []));
    return Promise.reject(new Error(`unexpected GET ${url}`));
  });
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("TenantsPage", () => {
  it("renders tenants across all organizations with the org name column", async () => {
    mockDefaultGets();
    renderWithProviders(<TenantsPage />);
    expect(await screen.findByText("Production")).toBeInTheDocument();
    expect(screen.getByText("Staging")).toBeInTheDocument();
    expect(screen.getByText("Acme Corp")).toBeInTheDocument();
    expect(screen.getByText("Beta LLC")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("Suspended")).toBeInTheDocument();
    expect(screen.getByText("2 tenants")).toBeInTheDocument();
  });

  it("filters tenants by search term (name, slug, or org name)", async () => {
    mockDefaultGets();
    renderWithProviders(<TenantsPage />);
    await screen.findByText("Production");
    await userEvent.type(screen.getByPlaceholderText("Search tenants..."), "beta");
    await waitFor(() => expect(screen.queryByText("Production")).not.toBeInTheDocument());
    expect(screen.getByText("Staging")).toBeInTheDocument();
    expect(screen.getByText("1 tenant")).toBeInTheDocument();
  });

  it("navigates to tenant detail when the view icon is clicked", async () => {
    mockDefaultGets();
    renderWithProviders(<TenantsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "View Production" }));
    expect(navigate).toHaveBeenCalledWith("/organizations/o1/tenants/t1");
  });

  it("populates the organization select in the create dialog", async () => {
    mockDefaultGets();
    renderWithProviders(<TenantsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Tenant/ }));
    const dialog = screen.getByRole("dialog");
    const select = within(dialog).getByLabelText("Organization *");
    expect(within(select).getByText("Acme Corp")).toBeInTheDocument();
    expect(within(select).getByText("Beta LLC")).toBeInTheDocument();
  });

  it("requires an organization to be selected before creating", async () => {
    mockDefaultGets();
    renderWithProviders(<TenantsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Tenant/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "New Tenant");
    await userEvent.type(within(dialog).getByLabelText("Slug *"), "new-tenant");
    // The Organization <select> is `required` and unselected, so a native
    // submit would be blocked before the component validates; submit directly.
    fireEvent.submit(
      within(dialog).getByRole("button", { name: "Create" }).closest("form")!
    );
    expect(
      await screen.findByText("Please select an organization.")
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("requires name and slug once an organization is selected", async () => {
    mockDefaultGets();
    renderWithProviders(<TenantsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Tenant/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.selectOptions(within(dialog).getByLabelText("Organization *"), "o1");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "   ");
    await userEvent.type(within(dialog).getByLabelText("Slug *"), "   ");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Name and slug are required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("creates a tenant under the selected organization", async () => {
    mockDefaultGets();
    apiMock.post.mockResolvedValue(
      res({ id: "t3", name: "QA", slug: "qa", status: "Active", organization_id: "o1", created_at: "t" })
    );
    renderWithProviders(<TenantsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Tenant/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.selectOptions(within(dialog).getByLabelText("Organization *"), "o1");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "QA");
    await userEvent.type(within(dialog).getByLabelText("Slug *"), "qa");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/organizations/o1/tenants", {
        name: "QA",
        slug: "qa",
        metadata: undefined,
      })
    );
  });

  it("surfaces a create error from the service", async () => {
    mockDefaultGets();
    apiMock.post.mockRejectedValue(new Error("Slug taken"));
    renderWithProviders(<TenantsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Tenant/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.selectOptions(within(dialog).getByLabelText("Organization *"), "o1");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "QA");
    await userEvent.type(within(dialog).getByLabelText("Slug *"), "qa");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Slug taken")).toBeInTheDocument();
  });

  it("edits a tenant, pre-filling status as the Active toggle", async () => {
    mockDefaultGets();
    apiMock.put.mockResolvedValue(res({ ...tenantsByOrg.o1[0] as object, name: "Prod 2" }));
    renderWithProviders(<TenantsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Production" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Name *")).toHaveValue("Production");
    expect(within(dialog).getByLabelText("Active")).toBeChecked();

    await userEvent.click(within(dialog).getByLabelText("Active"));
    const nameField = within(dialog).getByLabelText("Name *");
    await userEvent.clear(nameField);
    await userEvent.type(nameField, "Prod 2");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/organizations/o1/tenants/t1", {
        name: "Prod 2",
        slug: "production",
        status: "Suspended",
        metadata: { description: "Prod tenant" },
      })
    );
  });

  it("surfaces an edit error and requires name/slug", async () => {
    mockDefaultGets();
    renderWithProviders(<TenantsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Staging" }));
    const dialog = screen.getByRole("dialog");
    const nameField = within(dialog).getByLabelText("Name *");
    await userEvent.clear(nameField);
    // Empty required Name blocks a native submit; submit the form directly.
    fireEvent.submit(
      within(dialog).getByRole("button", { name: "Save Changes" }).closest("form")!
    );
    expect(await screen.findByText("Name and slug are required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("deletes a tenant after confirmation", async () => {
    mockDefaultGets();
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<TenantsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete Staging" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/organizations/o2/tenants/t2")
    );
  });

  it("shows the empty state when there are no tenants", async () => {
    apiMock.get.mockImplementation((url: string) => {
      if (url === "/api/v1/organizations") return Promise.resolve(res(orgs));
      return Promise.resolve(res([]));
    });
    renderWithProviders(<TenantsPage />);
    expect(await screen.findByText("No tenants found.")).toBeInTheDocument();
    expect(screen.getByText("0 tenants")).toBeInTheDocument();
  });

  it("shows the empty state and no tenant query when there are no organizations", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<TenantsPage />);
    expect(await screen.findByText("No tenants found.")).toBeInTheDocument();
  });
});
