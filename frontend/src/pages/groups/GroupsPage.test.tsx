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

import { GroupsPage } from "./GroupsPage";
import { renderWithProviders } from "@/test/renderWithProviders";

const groups = [
  { id: "g1", name: "Engineering", description: "Builders", created_at: "2026-01-01T00:00:00Z" },
  { id: "g2", name: "Ops", created_at: "2026-01-02T00:00:00Z" },
];

beforeEach(() => {
  vi.clearAllMocks();
});

describe("GroupsPage", () => {
  it("renders the fetched groups", async () => {
    apiMock.get.mockResolvedValue(res(groups));
    renderWithProviders(<GroupsPage />);
    expect(await screen.findByText("Engineering")).toBeInTheDocument();
    expect(screen.getByText("Ops")).toBeInTheDocument();
  });

  it("navigates to a group detail when its name is clicked", async () => {
    apiMock.get.mockResolvedValue(res(groups));
    renderWithProviders(<GroupsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Engineering" }));
    expect(navigate).toHaveBeenCalledWith("/groups/g1");
  });

  it("validates that a non-blank name is required before creating", async () => {
    apiMock.get.mockResolvedValue(res(groups));
    renderWithProviders(<GroupsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Group/ }));
    const dialog = screen.getByRole("dialog");
    // Whitespace satisfies the native `required` attribute but trims to empty,
    // exercising the JS-level validation branch.
    await userEvent.type(within(dialog).getByLabelText("Name *"), "   ");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("creates a group and refetches", async () => {
    apiMock.get.mockResolvedValue(res(groups));
    apiMock.post.mockResolvedValue(res({ id: "g3", name: "Security", created_at: "t" }));
    renderWithProviders(<GroupsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Group/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Security");
    await userEvent.type(within(dialog).getByLabelText("Description"), "sec team");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/groups", {
        name: "Security",
        description: "sec team",
      })
    );
  });

  it("surfaces a create error from the service", async () => {
    apiMock.get.mockResolvedValue(res(groups));
    apiMock.post.mockRejectedValue(new Error("Group exists"));
    renderWithProviders(<GroupsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Group/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Dup");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Group exists")).toBeInTheDocument();
  });

  it("edits an existing group", async () => {
    apiMock.get.mockResolvedValue(res(groups));
    apiMock.put.mockResolvedValue(res({ ...groups[0], name: "Engineering 2" }));
    renderWithProviders(<GroupsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Engineering" }));
    const dialog = screen.getByRole("dialog");
    const nameField = within(dialog).getByLabelText("Name *");
    await userEvent.clear(nameField);
    await userEvent.type(nameField, "Engineering 2");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/groups/g1", {
        name: "Engineering 2",
        description: "Builders",
      })
    );
  });

  it("deletes a group after confirmation", async () => {
    apiMock.get.mockResolvedValue(res(groups));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<GroupsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete Ops" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/groups/g2"));
  });

  it("shows the empty state when there are no groups", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<GroupsPage />);
    expect(await screen.findByText(/No groups yet/)).toBeInTheDocument();
  });

  it("navigates to the group detail via the View action", async () => {
    apiMock.get.mockResolvedValue(res(groups));
    renderWithProviders(<GroupsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "View Engineering" }));
    expect(navigate).toHaveBeenCalledWith("/groups/g1");
  });

  it("validates a blank name when editing", async () => {
    apiMock.get.mockResolvedValue(res(groups));
    renderWithProviders(<GroupsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Engineering" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.clear(within(dialog).getByLabelText("Name *"));
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("surfaces an edit error from the service", async () => {
    apiMock.get.mockResolvedValue(res(groups));
    apiMock.put.mockRejectedValue(new Error("Update failed"));
    renderWithProviders(<GroupsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Engineering" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Update failed")).toBeInTheDocument();
  });

  it("closes the create, edit and delete dialogs on cancel", async () => {
    apiMock.get.mockResolvedValue(res(groups));
    renderWithProviders(<GroupsPage />);
    // Create
    await userEvent.click(await screen.findByRole("button", { name: /New Group/ }));
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    // Edit
    await userEvent.click(screen.getByRole("button", { name: "Edit Engineering" }));
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    // Delete
    await userEvent.click(screen.getByRole("button", { name: "Delete Ops" }));
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });
});
