import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { PermissionsPage } from "./PermissionsPage";
import { renderWithProviders } from "@/test/renderWithProviders";

const permissions = [
  { id: "p1", action: "read", description: "Read things", created_at: "2026-01-01T00:00:00Z" },
  { id: "p2", action: "manage_billing", description: null, created_at: "2026-01-02T00:00:00Z" },
];

beforeEach(() => {
  vi.clearAllMocks();
});

describe("PermissionsPage", () => {
  it("renders the fetched permissions", async () => {
    apiMock.get.mockResolvedValue(res(permissions));
    renderWithProviders(<PermissionsPage />);
    expect(await screen.findByText("read")).toBeInTheDocument();
    expect(screen.getByText("manage_billing")).toBeInTheDocument();
    expect(screen.getByText("Read things")).toBeInTheDocument();
  });

  it("shows the empty state when there are no permissions", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<PermissionsPage />);
    expect(await screen.findByText("No permissions defined yet.")).toBeInTheDocument();
  });

  it("creates a standard permission with a description", async () => {
    apiMock.get.mockResolvedValue(res(permissions));
    apiMock.post.mockResolvedValue(res({ id: "p3", action: "write", description: "d", created_at: "t" }));
    renderWithProviders(<PermissionsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Permission/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.selectOptions(within(dialog).getByLabelText("Action *"), "write");
    await userEvent.type(within(dialog).getByLabelText("Description"), "can write");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/permissions", {
        action: "write",
        description: "can write",
      })
    );
  });

  it("requires a custom action when 'custom' is chosen but left blank", async () => {
    apiMock.get.mockResolvedValue(res(permissions));
    renderWithProviders(<PermissionsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Permission/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.selectOptions(within(dialog).getByLabelText("Action *"), "custom");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Action is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("creates a custom permission", async () => {
    apiMock.get.mockResolvedValue(res(permissions));
    apiMock.post.mockResolvedValue(res({ id: "p4", action: "deploy", description: "", created_at: "t" }));
    renderWithProviders(<PermissionsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Permission/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.selectOptions(within(dialog).getByLabelText("Action *"), "custom");
    await userEvent.type(within(dialog).getByPlaceholderText("Enter custom action"), "deploy");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/permissions", {
        action: "deploy",
        description: "",
      })
    );
  });

  it("surfaces a create error inside the dialog", async () => {
    apiMock.get.mockResolvedValue(res(permissions));
    apiMock.post.mockRejectedValue(new Error("Action exists"));
    renderWithProviders(<PermissionsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Permission/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Action exists")).toBeInTheDocument();
  });

  it("edits a custom-action permission preselecting custom", async () => {
    apiMock.get.mockResolvedValue(res(permissions));
    apiMock.put.mockResolvedValue(res({ ...permissions[1], description: "billing" }));
    renderWithProviders(<PermissionsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit manage_billing" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByPlaceholderText("Enter custom action")).toHaveValue("manage_billing");
    await userEvent.type(within(dialog).getByLabelText("Description"), "billing");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/permissions/p2", {
        action: "manage_billing",
        description: "billing",
      })
    );
  });

  it("surfaces an edit error inside the dialog", async () => {
    apiMock.get.mockResolvedValue(res(permissions));
    apiMock.put.mockRejectedValue(new Error("Update failed"));
    renderWithProviders(<PermissionsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit read" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Update failed")).toBeInTheDocument();
  });

  it("deletes a permission after confirmation", async () => {
    apiMock.get.mockResolvedValue(res(permissions));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<PermissionsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete read" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Delete Permission/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/permissions/p1")
    );
  });
});
