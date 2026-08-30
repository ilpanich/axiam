import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

const navigate = vi.fn();
vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return { ...actual, useNavigate: () => navigate };
});

import { OrganizationsPage } from "./OrganizationsPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore } from "@/stores/auth";

const orgs = [
  {
    id: "o1",
    name: "Acme Corp",
    slug: "acme-corp",
    metadata: { description: "Widgets Inc" },
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "o2",
    name: "Beta LLC",
    slug: "beta-llc",
    created_at: "2026-01-02T00:00:00Z",
  },
];


/**
 * Sign in as the organization's own administrator.
 *
 * Every control on this page — creating an organization, editing one, deleting
 * one — is refused by the server to a principal that does not live in the
 * organization's reserved tenant, so the page no longer renders them to one.
 * A test that did not say who it was would be exercising a tenant
 * administrator, for whom the buttons correctly do not exist.
 *
 * `organization_level` alone is what makes it one; the absent
 * `reachable_tenant_ids` is what makes it an unrestricted one. See
 * `lib/grantReach`'s `useCanActOnOrganization`.
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

beforeEach(() => {
  vi.clearAllMocks();
  signInAsOrganizationAdmin();
});

describe("OrganizationsPage", () => {
  it("renders the fetched organizations with slug and description", async () => {
    apiMock.get.mockResolvedValue(res(orgs));
    renderWithProviders(<OrganizationsPage />);
    expect(await screen.findByText("Acme Corp")).toBeInTheDocument();
    expect(screen.getByText("acme-corp")).toBeInTheDocument();
    expect(screen.getByText("Widgets Inc")).toBeInTheDocument();
    expect(screen.getByText("Beta LLC")).toBeInTheDocument();
    expect(screen.getByText("beta-llc")).toBeInTheDocument();
  });

  it("navigates to organization detail when its name is clicked", async () => {
    apiMock.get.mockResolvedValue(res(orgs));
    renderWithProviders(<OrganizationsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Acme Corp" }));
    expect(navigate).toHaveBeenCalledWith("/organizations/o1");
  });

  it("auto-generates the slug from the name while typing", async () => {
    apiMock.get.mockResolvedValue(res(orgs));
    renderWithProviders(<OrganizationsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Organization/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "My New Org");
    expect(within(dialog).getByLabelText("Slug *")).toHaveValue("my-new-org");
  });

  it("validates that name and slug are required before creating", async () => {
    apiMock.get.mockResolvedValue(res(orgs));
    renderWithProviders(<OrganizationsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Organization/ }));
    const dialog = screen.getByRole("dialog");
    // Whitespace satisfies the native `required` attribute on both fields but
    // trims to empty, exercising the JS-level validation branch. Typing into
    // Name would auto-slugify to "", so type into Slug directly afterward.
    await userEvent.type(within(dialog).getByLabelText("Name *"), "   ");
    await userEvent.type(within(dialog).getByLabelText("Slug *"), "   ");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Name and slug are required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("creates an organization with a description and refetches", async () => {
    apiMock.get.mockResolvedValue(res(orgs));
    apiMock.post.mockResolvedValue(
      res({ id: "o3", name: "Gamma", slug: "gamma", created_at: "t" })
    );
    renderWithProviders(<OrganizationsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Organization/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Gamma");
    await userEvent.type(within(dialog).getByLabelText("Description"), "Third org");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/organizations", {
        name: "Gamma",
        slug: "gamma",
        metadata: { description: "Third org" },
      })
    );
    // Dialog closes on success.
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("creates an organization without a description (metadata undefined)", async () => {
    apiMock.get.mockResolvedValue(res(orgs));
    apiMock.post.mockResolvedValue(
      res({ id: "o3", name: "Delta", slug: "delta", created_at: "t" })
    );
    renderWithProviders(<OrganizationsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Organization/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Delta");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/organizations", {
        name: "Delta",
        slug: "delta",
        metadata: undefined,
      })
    );
  });

  it("surfaces a create error from the service", async () => {
    apiMock.get.mockResolvedValue(res(orgs));
    apiMock.post.mockRejectedValue(new Error("Slug already exists"));
    renderWithProviders(<OrganizationsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Organization/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Dup");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Slug already exists")).toBeInTheDocument();
  });

  it("edits an existing organization, pre-filling from metadata", async () => {
    apiMock.get.mockResolvedValue(res(orgs));
    apiMock.put.mockResolvedValue(res({ ...orgs[0], name: "Acme Corp 2" }));
    renderWithProviders(<OrganizationsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Acme Corp" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Name *")).toHaveValue("Acme Corp");
    expect(within(dialog).getByLabelText("Slug *")).toHaveValue("acme-corp");
    expect(within(dialog).getByLabelText("Description")).toHaveValue("Widgets Inc");

    const nameField = within(dialog).getByLabelText("Name *");
    await userEvent.clear(nameField);
    await userEvent.type(nameField, "Acme Corp 2");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/organizations/o1", {
        name: "Acme Corp 2",
        slug: "acme-corp-2",
        metadata: { description: "Widgets Inc" },
      })
    );
  });

  it("surfaces an edit error from the service", async () => {
    apiMock.get.mockResolvedValue(res(orgs));
    apiMock.put.mockRejectedValue(new Error("Failed to update"));
    renderWithProviders(<OrganizationsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Beta LLC" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Failed to update")).toBeInTheDocument();
  });

  it("deletes an organization after confirmation", async () => {
    apiMock.get.mockResolvedValue(res(orgs));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<OrganizationsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete Beta LLC" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Beta LLC/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/organizations/o2"));
  });

  it("shows the empty state when there are no organizations", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<OrganizationsPage />);
    expect(
      await screen.findByText(/No organizations yet. Create your first one./)
    ).toBeInTheDocument();
  });

  it("offers no organization controls to a tenant administrator", async () => {
    // The reported defect: a tenant's `super-admin` holds the whole permission
    // registry — `organizations:create` included — so no permission check would
    // have hidden anything. `require_organization_principal` refuses it anyway,
    // on the basis of where the account lives, and the page now agrees.
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
    apiMock.get.mockResolvedValue(res(orgs));

    renderWithProviders(<OrganizationsPage />);

    // The list still renders — reading is not what was refused.
    expect(await screen.findByText("Acme Corp")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /new organization/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /edit acme corp/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /delete acme corp/i }),
    ).not.toBeInTheDocument();
  });

  it("offers no organization controls to a tenant-restricted organization principal", async () => {
    useAuthStore.setState({
      user: {
        id: "u3",
        username: "alpha-admin",
        email: "alpha-admin@acme.test",
        permissions: ["organizations:list", "organizations:create"],
        tenant_id: "org-tenant",
        principal_tenant_id: "org-tenant",
        org_id: "o1",
        organization_level: true,
        reachable_tenant_ids: ["t-alpha"],
      },
      isAuthenticated: true,
      isInitializing: false,
    });
    apiMock.get.mockResolvedValue(res(orgs));

    renderWithProviders(<OrganizationsPage />);

    expect(await screen.findByText("Acme Corp")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /new organization/i }),
    ).not.toBeInTheDocument();
  });
});
