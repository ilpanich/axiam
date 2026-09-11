import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { ResourcesPage } from "./ResourcesPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { setToastDispatch } from "@/hooks/useToast";

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
  {
    id: "r4",
    name: "Invoice",
    resource_type: "document",
    uma_registered_by: "resource-server-1",
    created_at: "2026-01-04T00:00:00Z",
  },
];

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  setToastDispatch(null);
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

  it("badges only resources registered through the UMA Protection API", async () => {
    // The badge asserts provenance, so it must appear exactly where the
    // backend recorded one and nowhere else — a badge on a hand-made resource
    // would be a claim the server never made.
    apiMock.get.mockResolvedValue(res(resources));
    renderWithProviders(<ResourcesPage />);
    await screen.findByText("Gateway");
    await userEvent.click(screen.getByRole("button", { name: "List view" }));

    const badges = await screen.findAllByText("UMA");
    expect(badges).toHaveLength(1);
    expect(badges[0]).toHaveAttribute(
      "title",
      "Registered through the UMA Protection API by resource-server-1",
    );
  });
});

// ─── Selection, the tree's own delete, and the ways out of a dialog ───────────
//
// Selecting a node in the tree is what drives the two panels beside it, and it
// clears the deny badges from the previous selection — a preview left over from
// another resource is a wrong answer rendered confidently. The tree's delete
// button, the validation on edit, and all three dismissals were untested.

describe("ResourcesPage — selection, tree actions and dismissal", () => {
  it("selecting a resource in the tree drives the panels beside it", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    renderWithProviders(<ResourcesPage />);

    const tree = await screen.findByRole("tree");
    await userEvent.click(within(tree).getByText("Gateway"));
    expect(await screen.findByText(/Scopes — Gateway/)).toBeInTheDocument();

    await userEvent.click(within(tree).getByText("Legacy"));
    expect(await screen.findByText(/Scopes — Legacy/)).toBeInTheDocument();
  });

  it("returns to the tree view after switching to the list", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    renderWithProviders(<ResourcesPage />);
    await screen.findByText("Gateway");

    await userEvent.click(screen.getByRole("button", { name: "List view" }));
    expect(screen.queryByRole("tree")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Tree view" }));
    expect(await screen.findByRole("tree")).toBeInTheDocument();
  });

  it("deletes from the tree's own action button", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<ResourcesPage />);

    await screen.findByText("Gateway");
    await userEvent.click(screen.getByRole("button", { name: "Delete Legacy" }));
    await userEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "Delete" })
    );

    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/resources/r3")
    );
  });

  it("toasts the server's reason when a resource cannot be deleted", async () => {
    // A resource with children or live grants is refused server-side, and the
    // confirmation offers no inline place to say so.
    apiMock.get.mockResolvedValue(res(resources));
    apiMock.delete.mockRejectedValue({
      response: {
        status: 409,
        data: { message: "Resource has child resources" },
      },
    });
    const toastSpy = vi.fn();
    setToastDispatch(toastSpy);
    renderWithProviders(<ResourcesPage />);

    await screen.findByText("Gateway");
    await userEvent.click(screen.getByRole("button", { name: "Delete Gateway" }));
    await userEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "Delete" })
    );

    await waitFor(() =>
      expect(toastSpy).toHaveBeenCalledWith({
        description: "Resource has child resources",
        variant: "destructive",
      })
    );
  });

  it("refuses an edit that blanks the name", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    renderWithProviders(<ResourcesPage />);

    await screen.findByText("Gateway");
    await userEvent.click(screen.getByRole("button", { name: "Edit Gateway" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.clear(within(dialog).getByLabelText("Name *"));
    // The name input is `required`, so a button click would be stopped by
    // native constraint validation before the component's own check runs.
    fireEvent.submit(dialog.querySelector("form")!);

    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("refuses an edit whose custom type is left blank", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    renderWithProviders(<ResourcesPage />);

    await screen.findByText("Gateway");
    // "Legacy" carries a non-standard type, so its editor opens on "custom".
    await userEvent.click(screen.getByRole("button", { name: "Edit Legacy" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.clear(within(dialog).getByPlaceholderText("Enter custom type"));
    fireEvent.submit(dialog.querySelector("form")!);

    expect(await screen.findByText("Resource type is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("discards a half-filled create form when dismissed", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    renderWithProviders(<ResourcesPage />);

    await screen.findByText("Gateway");
    await userEvent.click(screen.getByRole("button", { name: /New Resource/ }));
    let dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Half typed");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    );

    await userEvent.click(screen.getByRole("button", { name: /New Resource/ }));
    dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Name *")).toHaveValue("");
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("closes the edit and delete dialogs without writing", async () => {
    apiMock.get.mockResolvedValue(res(resources));
    renderWithProviders(<ResourcesPage />);

    await screen.findByText("Gateway");
    await userEvent.click(screen.getByRole("button", { name: "Edit Gateway" }));
    await userEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" })
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    );

    await userEvent.click(screen.getByRole("button", { name: "Delete Gateway" }));
    await userEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" })
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    );

    expect(apiMock.put).not.toHaveBeenCalled();
    expect(apiMock.delete).not.toHaveBeenCalled();
  });
});
