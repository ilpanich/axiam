import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

const navigate = vi.fn();
vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return { ...actual, useNavigate: () => navigate };
});

import { OrganizationsPage } from "./OrganizationsPage";
import { renderWithProviders } from "@/test/renderWithProviders";

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

beforeEach(() => {
  vi.clearAllMocks();
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
});
