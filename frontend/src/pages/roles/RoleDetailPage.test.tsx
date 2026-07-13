import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { RoleDetailPage } from "./RoleDetailPage";
import { makeClient } from "@/test/renderWithProviders";

const role = {
  id: "r1",
  name: "Editor",
  description: "Can edit things",
  is_global: false,
  created_at: "2026-01-01T00:00:00Z",
};

const grants = [
  {
    permission: { id: "p1", action: "read", description: "Read stuff", created_at: "2026-01-01T00:00:00Z" },
    scope_ids: [],
  },
];

const allPermissions = [
  { id: "p1", action: "read", description: "Read stuff", created_at: "2026-01-01T00:00:00Z" },
  { id: "p2", action: "write", description: "Write stuff", created_at: "2026-01-01T00:00:00Z" },
];

const assignedUsers = [
  {
    id: "u1",
    username: "alice",
    email: "alice@x.io",
    display_name: "Alice A",
    mfa_enabled: false,
    email_verified: true,
    created_at: "t",
    updated_at: "t",
    status: "Active",
    is_locked: false,
    locked_until: null,
    failed_login_attempts: 0,
  },
];

const assignedGroups = [{ id: "g1", name: "Admins", created_at: "t" }];

const URLS = {
  role: "/api/v1/roles/r1",
  perms: "/api/v1/roles/r1/permissions",
  users: "/api/v1/roles/r1/users",
  groups: "/api/v1/roles/r1/groups",
  allPerms: "/api/v1/permissions",
  allGroups: "/api/v1/groups",
};

function routeGet(map: Record<string, unknown>) {
  apiMock.get.mockImplementation((url: string) => {
    if (url in map) return Promise.resolve(res(map[url]));
    if (url.startsWith("/api/v1/users?"))
      return Promise.resolve(res({ items: assignedUsers, total: 1, offset: 0, limit: 20 }));
    return Promise.resolve(res([]));
  });
}

function defaultData(overrides: Record<string, unknown> = {}) {
  return {
    [URLS.role]: role,
    [URLS.perms]: grants,
    [URLS.users]: assignedUsers,
    [URLS.groups]: assignedGroups,
    [URLS.allPerms]: allPermissions,
    [URLS.allGroups]: assignedGroups,
    ...overrides,
  };
}

function renderPage() {
  const client = makeClient();
  const router = createMemoryRouter(
    [{ path: "/roles/:roleId", element: <RoleDetailPage /> }],
    { initialEntries: ["/roles/r1"] }
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

describe("RoleDetailPage", () => {
  it("shows an error state when the role fails to load", async () => {
    apiMock.get.mockImplementation((url: string) => {
      if (url === URLS.role) return Promise.reject(new Error("nope"));
      return Promise.resolve(res([]));
    });
    renderPage();
    expect(
      await screen.findByText("Role not found or failed to load.")
    ).toBeInTheDocument();
  });

  it("renders role info, granted permissions and assigned users", async () => {
    routeGet(defaultData());
    renderPage();
    expect(await screen.findByText("Editor")).toBeInTheDocument();
    expect(screen.getByText("Can edit things")).toBeInTheDocument();
    expect(screen.getByText("Tenant")).toBeInTheDocument();
    expect(await screen.findByText("read")).toBeInTheDocument();
    expect(await screen.findByText("Alice A")).toBeInTheDocument();
    expect(screen.getByText("alice@x.io")).toBeInTheDocument();
  });

  it("edits the role and submits the update", async () => {
    routeGet(defaultData());
    apiMock.put.mockResolvedValue(res({ ...role, name: "Editor 2" }));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Edit" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Name *")).toHaveValue("Editor");
    const name = within(dialog).getByLabelText("Name *");
    await userEvent.clear(name);
    await userEvent.type(name, "Editor 2");
    const desc = within(dialog).getByLabelText("Description");
    await userEvent.clear(desc);
    await userEvent.type(desc, "New desc");
    await userEvent.click(within(dialog).getByLabelText("Global role"));
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(URLS.role, {
        name: "Editor 2",
        description: "New desc",
        is_global: true,
      })
    );
  });

  it("closes the edit dialog on cancel without saving", async () => {
    routeGet(defaultData());
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Edit" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("keeps the grant dialog open when granting fails", async () => {
    routeGet(defaultData());
    apiMock.post.mockRejectedValue(new Error("grant failed"));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /Grant Permission/ }));
    const dialog = screen.getByRole("dialog");
    await within(dialog).findByText("Granted");
    await userEvent.click(within(dialog).getByRole("button", { name: "Grant" }));
    await waitFor(() => expect(apiMock.post).toHaveBeenCalled());
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("surfaces an assign-group error from the service", async () => {
    routeGet(defaultData());
    apiMock.post.mockRejectedValue(new Error("Assign failed"));
    renderPage();
    await screen.findByText("Editor");
    await userEvent.click(screen.getByRole("button", { name: "groups" }));
    await userEvent.click(screen.getByRole("button", { name: /Assign Group/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.selectOptions(within(dialog).getByLabelText("Group"), "g1");
    await userEvent.click(within(dialog).getByRole("button", { name: "Assign" }));
    expect(await screen.findByText("Assign failed")).toBeInTheDocument();
  });

  it("still calls the API when an unassign fails (error is toasted)", async () => {
    routeGet(defaultData());
    apiMock.delete.mockRejectedValue(new Error("boom"));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Unassign alice" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/roles/r1/users/u1")
    );
  });

  it("validates a blank name when editing", async () => {
    routeGet(defaultData());
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Edit" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.clear(within(dialog).getByLabelText("Name *"));
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("surfaces an edit error from the service", async () => {
    routeGet(defaultData());
    apiMock.put.mockRejectedValue(new Error("Update failed"));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Edit" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Update failed")).toBeInTheDocument();
  });

  it("revokes a granted permission after confirmation", async () => {
    routeGet(defaultData());
    apiMock.delete.mockResolvedValue(res(undefined));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Revoke read" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Revoke Permission/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/roles/r1/permissions/p1")
    );
  });

  it("grants a permission from the grant dialog", async () => {
    routeGet(defaultData());
    apiMock.post.mockResolvedValue(res(undefined));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /Grant Permission/ }));
    const dialog = screen.getByRole("dialog");
    // p1 is already granted; p2 has a Grant button.
    expect(await within(dialog).findByText("Granted")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Grant" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(URLS.perms, { permission_id: "p2" })
    );
  });

  it("filters permissions in the grant dialog", async () => {
    routeGet(defaultData());
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /Grant Permission/ }));
    const dialog = screen.getByRole("dialog");
    await within(dialog).findByText("Granted");
    await userEvent.type(screen.getByLabelText("Filter permissions"), "nomatch");
    expect(await screen.findByText("No permissions found.")).toBeInTheDocument();
  });

  it("switches to the groups assignment tab and lists groups", async () => {
    routeGet(defaultData());
    renderPage();
    await screen.findByText("Editor");
    await userEvent.click(screen.getByRole("button", { name: "groups" }));
    expect(await screen.findByText("Admins")).toBeInTheDocument();
  });

  it("unassigns a user after confirmation", async () => {
    routeGet(defaultData());
    apiMock.delete.mockResolvedValue(res(undefined));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Unassign alice" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Unassign User/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/roles/r1/users/u1")
    );
  });

  it("unassigns a group after confirmation", async () => {
    routeGet(defaultData());
    apiMock.delete.mockResolvedValue(res(undefined));
    renderPage();
    await screen.findByText("Editor");
    await userEvent.click(screen.getByRole("button", { name: "groups" }));
    await userEvent.click(await screen.findByRole("button", { name: "Unassign group Admins" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/roles/r1/groups/g1")
    );
  });

  it("validates group selection then assigns a group", async () => {
    routeGet(defaultData());
    apiMock.post.mockResolvedValue(res(undefined));
    renderPage();
    await screen.findByText("Editor");
    await userEvent.click(screen.getByRole("button", { name: "groups" }));
    await userEvent.click(screen.getByRole("button", { name: /Assign Group/ }));
    const dialog = screen.getByRole("dialog");
    // Submit with nothing selected -> validation error.
    await userEvent.click(within(dialog).getByRole("button", { name: "Assign" }));
    expect(await screen.findByText("Please select a group.")).toBeInTheDocument();
    await userEvent.selectOptions(within(dialog).getByLabelText("Group"), "g1");
    await userEvent.click(within(dialog).getByRole("button", { name: "Assign" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(URLS.groups, { group_id: "g1" })
    );
  });

  it("assigns a user via the user search dialog", async () => {
    routeGet(defaultData());
    apiMock.post.mockResolvedValue(res(undefined));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /Assign User/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Search users"), "al");
    await userEvent.click(await within(dialog).findByRole("button", { name: "Assign" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(URLS.users, { user_id: "u1" })
    );
  });

  it("shows the empty assignment states when nothing is assigned", async () => {
    routeGet(defaultData({ [URLS.users]: [], [URLS.groups]: [] }));
    renderPage();
    expect(
      await screen.findByText(/No users assigned/)
    ).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "groups" }));
    expect(await screen.findByText(/No groups assigned/)).toBeInTheDocument();
  });
});
