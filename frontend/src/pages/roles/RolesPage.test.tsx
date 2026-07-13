import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

const navigate = vi.fn();
vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return { ...actual, useNavigate: () => navigate };
});

import { RolesPage } from "./RolesPage";
import { renderWithProviders } from "@/test/renderWithProviders";

const roles = [
  { id: "r1", name: "Admin", description: "Full access", is_global: true, created_at: "2026-01-01T00:00:00Z" },
  { id: "r2", name: "Viewer", is_global: false, created_at: "2026-01-02T00:00:00Z" },
];

beforeEach(() => {
  vi.clearAllMocks();
});

describe("RolesPage", () => {
  it("renders the fetched roles with scope badges", async () => {
    apiMock.get.mockResolvedValue(res(roles));
    renderWithProviders(<RolesPage />);
    expect(await screen.findByText("Admin")).toBeInTheDocument();
    expect(screen.getByText("Viewer")).toBeInTheDocument();
    expect(screen.getByText("Full access")).toBeInTheDocument();
    expect(screen.getByText("Global")).toBeInTheDocument();
    expect(screen.getByText("Tenant")).toBeInTheDocument();
  });

  it("shows the empty state when there are no roles", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<RolesPage />);
    expect(await screen.findByText("No roles found.")).toBeInTheDocument();
  });

  it("navigates to the role detail when View is clicked", async () => {
    apiMock.get.mockResolvedValue(res(roles));
    renderWithProviders(<RolesPage />);
    await userEvent.click(await screen.findByRole("button", { name: "View Admin" }));
    expect(navigate).toHaveBeenCalledWith("/roles/r1");
  });

  it("validates a non-blank name before creating", async () => {
    apiMock.get.mockResolvedValue(res(roles));
    renderWithProviders(<RolesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Role/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "   ");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("creates a global role", async () => {
    apiMock.get.mockResolvedValue(res(roles));
    apiMock.post.mockResolvedValue(res({ id: "r3", name: "Editor", is_global: true, created_at: "t" }));
    renderWithProviders(<RolesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Role/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Editor");
    await userEvent.type(within(dialog).getByLabelText("Description"), "can edit");
    await userEvent.click(
      within(dialog).getByLabelText("Global role (applies across all tenants)")
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/roles", {
        name: "Editor",
        description: "can edit",
        is_global: true,
      })
    );
  });

  it("surfaces a create error inside the dialog", async () => {
    apiMock.get.mockResolvedValue(res(roles));
    apiMock.post.mockRejectedValue(new Error("Role exists"));
    renderWithProviders(<RolesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Role/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Dup");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Role exists")).toBeInTheDocument();
  });

  it("edits an existing role", async () => {
    apiMock.get.mockResolvedValue(res(roles));
    apiMock.put.mockResolvedValue(res({ ...roles[0], name: "Admin 2" }));
    renderWithProviders(<RolesPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Admin" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Name *")).toHaveValue("Admin");
    const name = within(dialog).getByLabelText("Name *");
    await userEvent.clear(name);
    await userEvent.type(name, "Admin 2");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/roles/r1", {
        name: "Admin 2",
        description: "Full access",
        is_global: true,
      })
    );
  });

  it("validates a blank name when editing", async () => {
    apiMock.get.mockResolvedValue(res(roles));
    renderWithProviders(<RolesPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Admin" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.clear(within(dialog).getByLabelText("Name *"));
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("surfaces an edit error inside the dialog", async () => {
    apiMock.get.mockResolvedValue(res(roles));
    apiMock.put.mockRejectedValue(new Error("Update failed"));
    renderWithProviders(<RolesPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Viewer" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Update failed")).toBeInTheDocument();
  });

  it("deletes a role after confirmation", async () => {
    apiMock.get.mockResolvedValue(res(roles));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<RolesPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete Viewer" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Delete Role/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/roles/r2"));
  });
});
