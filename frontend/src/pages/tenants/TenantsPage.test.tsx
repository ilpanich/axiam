import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";
import { setToastDispatch } from "@/hooks/useToast";

vi.mock("@/lib/api", () => ({ default: apiMock }));

// T-118: deleting a tenant now exports its audit trail first and hands the
// file to the browser. jsdom has no `URL.createObjectURL`, and what these
// tests care about is the ORDER of the two calls, not the download plumbing
// (which `lib/download.test.ts` covers).
const downloadTextFile = vi.fn();
vi.mock("@/lib/download", () => ({
  downloadTextFile: (...args: unknown[]) => downloadTextFile(...args),
}));

const navigate = vi.fn();
vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return { ...actual, useNavigate: () => navigate };
});

import { TenantsPage } from "./TenantsPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore } from "@/stores/auth";

const orgs = [
  { id: "o1", name: "Acme Corp", slug: "acme-corp", created_at: "2026-01-01T00:00:00Z" },
  { id: "o2", name: "Beta LLC", slug: "beta-llc", created_at: "2026-01-02T00:00:00Z" },
];

/// One audit entry line plus the manifest line the server appends last.
const EXPORT_NDJSON =
  '{"id":"a1","action":"users.created"}\n' +
  '{"axiam_export":"tenant_audit","record_count":1,"digest":"sha256:abc","receipt_id":"r1"}\n';

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


/**
 * Sign in as the organization's own administrator.
 *
 * The tenant roster belongs to the organization: creating a tenant, renaming
 * one and deleting one are all refused by the server to a principal that does
 * not live in the organization's reserved tenant, so the page no longer renders
 * those controls to one. A test that did not say who it was would be exercising
 * a tenant administrator, for whom the buttons correctly do not exist.
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

  it("refreshes the topbar tenant switcher after creating a tenant", async () => {
    // The switcher caches the same list under its own key root. Without an edge
    // from `tenants` to it, creating a tenant refreshed this page and left the
    // switcher answering from the copy it fetched before the tenant existed —
    // so the obvious next action, switching into the tenant just created, was
    // impossible for up to the 60s stale time.
    mockDefaultGets();
    apiMock.post.mockResolvedValue(
      res({ id: "t3", name: "QA", slug: "qa", status: "Active", organization_id: "o1", created_at: "t" })
    );
    const { client } = renderWithProviders(<TenantsPage />);
    const invalidate = vi.spyOn(client, "invalidateQueries");

    await userEvent.click(await screen.findByRole("button", { name: /New Tenant/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.selectOptions(within(dialog).getByLabelText("Organization *"), "o1");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "QA");
    await userEvent.type(within(dialog).getByLabelText("Slug *"), "qa");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(invalidate).toHaveBeenCalledWith({ queryKey: ["topbar-tenants"] })
    );
    expect(invalidate).toHaveBeenCalledWith({
      queryKey: ["assignment-scope-tenants"],
    });
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

  it("exports the audit trail, then deletes the tenant (T-118)", async () => {
    mockDefaultGets();
    apiMock.post.mockResolvedValue(res(EXPORT_NDJSON));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<TenantsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete Staging" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));

    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/organizations/o2/tenants/t2")
    );
    expect(apiMock.post).toHaveBeenCalledWith(
      "/api/v1/organizations/o2/tenants/t2/audit-export",
      undefined,
      { responseType: "text" }
    );
    // The operator ends up holding the trail, not merely having triggered it.
    expect(downloadTextFile).toHaveBeenCalledWith(
      expect.stringContaining("axiam-audit-staging-"),
      EXPORT_NDJSON,
      "application/x-ndjson"
    );
  });

  it("does not delete the tenant when the audit export fails (T-118)", async () => {
    const toastFn = vi.fn();
    setToastDispatch(toastFn);
    mockDefaultGets();
    apiMock.post.mockRejectedValue(new Error("audit export failed"));
    renderWithProviders(<TenantsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete Staging" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));

    await waitFor(() =>
      expect(toastFn).toHaveBeenCalledWith({
        description: "audit export failed",
        variant: "destructive",
      })
    );
    expect(apiMock.delete).not.toHaveBeenCalled();
    setToastDispatch(null);
  });

  it("surfaces a delete error via toast (CQ-F09)", async () => {
    const toastFn = vi.fn();
    setToastDispatch(toastFn);
    mockDefaultGets();
    apiMock.post.mockResolvedValue(res(EXPORT_NDJSON));
    apiMock.delete.mockRejectedValue(new Error("Tenant has active users"));
    renderWithProviders(<TenantsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete Staging" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(toastFn).toHaveBeenCalledWith({
        description: "Tenant has active users",
        variant: "destructive",
      })
    );
    setToastDispatch(null);
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

  it("offers no tenant lifecycle controls to a tenant administrator", async () => {
    // The tenant roster belongs to the organization. A tenant administrator can
    // see the one tenant the server returns for it and open the detail page —
    // what it cannot do is create, rename or delete, and those buttons are
    // therefore not drawn.
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

    mockDefaultGets();
    renderWithProviders(<TenantsPage />);

    expect(await screen.findByText("Production")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /new tenant/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /^edit production$/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /^delete production$/i }),
    ).not.toBeInTheDocument();
    // ...but the way into the tenant it administers is still there.
    expect(
      screen.getByRole("button", { name: /view production/i }),
    ).toBeInTheDocument();
  });
});
