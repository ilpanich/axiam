import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { ResourcesPage } from "./ResourcesPage";
import { renderWithProviders } from "@/test/renderWithProviders";

const resources = [
  {
    id: "r1",
    name: "Gateway",
    resource_type: "api",
    metadata: { description: "Main gateway" },
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "r2",
    name: "Sensor",
    resource_type: "iot_device",
    parent_id: "r1",
    created_at: "2026-01-02T00:00:00Z",
  },
  {
    id: "r3",
    name: "Legacy",
    resource_type: "widget",
    created_at: "2026-01-03T00:00:00Z",
  },
];

beforeEach(() => {
  vi.clearAllMocks();
});

describe("ResourcesPage", () => {
  it("renders resources in the tree view by default", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    renderWithProviders(<ResourcesPage />);
    expect(await screen.findByText("Gateway")).toBeInTheDocument();
    expect(screen.getByText("Sensor")).toBeInTheDocument();
    expect(screen.getByText("Legacy")).toBeInTheDocument();
    expect(screen.getByRole("tree")).toBeInTheDocument();
  });

  it("switches to the list view and shows parent names", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    renderWithProviders(<ResourcesPage />);
    await screen.findByText("Gateway");
    await userEvent.click(screen.getByRole("button", { name: "List view" }));
    // Parent name resolved for the child row.
    expect(await screen.findByText("Main gateway")).toBeInTheDocument();
    const rows = screen.getAllByText("Gateway");
    expect(rows.length).toBeGreaterThan(0);
    // The IoT Device label appears (resourceTypeLabel mapping).
    expect(screen.getAllByText("IoT Device").length).toBeGreaterThan(0);
  });

  it("requires a non-blank name before creating", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    renderWithProviders(<ResourcesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Resource/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "   ");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("requires a resource type when 'custom' is chosen but left blank", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    renderWithProviders(<ResourcesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Resource/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Thing");
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Resource Type *"),
      "custom"
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Resource type is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("creates a resource with a custom type, parent and description", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    apiMock.post.mockResolvedValue(res({ id: "r4", name: "New", resource_type: "widget" }));
    renderWithProviders(<ResourcesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Resource/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "New Thing");
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Resource Type *"),
      "custom"
    );
    await userEvent.type(
      within(dialog).getByPlaceholderText("Enter custom type"),
      "widget"
    );
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Parent Resource"),
      "r1"
    );
    await userEvent.type(
      within(dialog).getByLabelText("Description"),
      "a new thing"
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/resources", {
        name: "New Thing",
        resource_type: "widget",
        parent_id: "r1",
        metadata: { description: "a new thing" },
      })
    );
  });

  it("surfaces a create error inside the dialog", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    apiMock.post.mockRejectedValue(new Error("Name already exists"));
    renderWithProviders(<ResourcesPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Resource/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Dup");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Name already exists")).toBeInTheDocument();
  });

  it("edits a resource, pre-filling a custom type and clearing the parent", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    apiMock.put.mockResolvedValue(res({ ...resources[1], name: "Sensor 2" }));
    renderWithProviders(<ResourcesPage />);
    await screen.findByText("Gateway");
    await userEvent.click(screen.getByRole("button", { name: "List view" }));
    await userEvent.click(await screen.findByRole("button", { name: "Edit Sensor" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Name *")).toHaveValue("Sensor");
    // Parent currently r1 — clear it back to root.
    await userEvent.selectOptions(within(dialog).getByLabelText("Parent Resource"), "");
    const name = within(dialog).getByLabelText("Name *");
    await userEvent.clear(name);
    await userEvent.type(name, "Sensor 2");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/resources/r2", {
        name: "Sensor 2",
        resource_type: "iot_device",
        parent_id: null,
        metadata: { description: "" },
      })
    );
  });

  it("edits a custom-typed resource preselecting the custom option", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    renderWithProviders(<ResourcesPage />);
    await screen.findByText("Gateway");
    await userEvent.click(screen.getByRole("button", { name: "List view" }));
    await userEvent.click(await screen.findByRole("button", { name: "Edit Legacy" }));
    const dialog = screen.getByRole("dialog");
    // Custom type resource pre-fills the custom text input.
    expect(within(dialog).getByPlaceholderText("Enter custom type")).toHaveValue("widget");
  });

  it("surfaces an edit error inside the dialog", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    apiMock.put.mockRejectedValue(new Error("Update rejected"));
    renderWithProviders(<ResourcesPage />);
    await screen.findByText("Gateway");
    await userEvent.click(screen.getByRole("button", { name: "List view" }));
    await userEvent.click(await screen.findByRole("button", { name: "Edit Gateway" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Update rejected")).toBeInTheDocument();
  });

  it("deletes a resource after confirmation", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<ResourcesPage />);
    await screen.findByText("Gateway");
    await userEvent.click(screen.getByRole("button", { name: "List view" }));
    await userEvent.click(await screen.findByRole("button", { name: "Delete Legacy" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Delete Resource/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/resources/r3")
    );
  });

  it("edits a resource from the tree action buttons", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    renderWithProviders(<ResourcesPage />);
    await screen.findByText("Gateway");
    // Tree action buttons carry the same aria-labels.
    await userEvent.click(screen.getByRole("button", { name: "Edit Gateway" }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(within(screen.getByRole("dialog")).getByLabelText("Name *")).toHaveValue(
      "Gateway"
    );
  });

  it("shows the empty list state when there are no resources", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<ResourcesPage />);
    await waitFor(() => expect(apiMock.get).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: "List view" }));
    expect(await screen.findByText("No resources defined yet.")).toBeInTheDocument();
  });
});
