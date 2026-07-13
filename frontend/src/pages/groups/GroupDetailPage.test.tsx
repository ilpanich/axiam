import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { GroupDetailPage } from "./GroupDetailPage";
import { makeClient } from "@/test/renderWithProviders";

const group = {
  id: "g1",
  name: "Engineering",
  description: "Builders",
  created_at: "2026-01-01T00:00:00Z",
};

const members = [
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
    metadata: { display_name: "Alice A" },
    is_locked: false,
    locked_until: null,
    failed_login_attempts: 0,
  },
];

const groupRoles = [{ id: "r1", name: "Deploy", description: "Deploy access", is_global: false, created_at: "t" }];

const URLS = {
  group: "/api/v1/groups/g1",
  members: "/api/v1/groups/g1/members",
  roles: "/api/v1/groups/g1/roles",
};

function routeGet(map: Record<string, unknown>) {
  apiMock.get.mockImplementation((url: string) => {
    if (url in map) return Promise.resolve(res(map[url]));
    if (url.startsWith("/api/v1/users?"))
      return Promise.resolve(res({ items: [{ ...members[0], id: "u2", username: "carol", email: "carol@x.io", display_name: "Carol" }], total: 1, offset: 0, limit: 20 }));
    return Promise.resolve(res([]));
  });
}

function defaults(overrides: Record<string, unknown> = {}) {
  return { [URLS.group]: group, [URLS.members]: members, [URLS.roles]: groupRoles, ...overrides };
}

function renderPage() {
  const client = makeClient();
  const router = createMemoryRouter(
    [{ path: "/groups/:groupId", element: <GroupDetailPage /> }],
    { initialEntries: ["/groups/g1"] }
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

describe("GroupDetailPage", () => {
  it("shows an error state when the group fails to load", async () => {
    apiMock.get.mockImplementation((url: string) => {
      if (url === URLS.group) return Promise.reject(new Error("nope"));
      return Promise.resolve(res([]));
    });
    renderPage();
    expect(
      await screen.findByText("Group not found or failed to load.")
    ).toBeInTheDocument();
  });

  it("renders group info, members and assigned roles", async () => {
    routeGet(defaults());
    renderPage();
    expect(await screen.findByText("Engineering")).toBeInTheDocument();
    expect(screen.getByText("Builders")).toBeInTheDocument();
    expect(await screen.findByText("Alice A")).toBeInTheDocument();
    expect(screen.getByText("alice@x.io")).toBeInTheDocument();
    expect(await screen.findByText("Deploy")).toBeInTheDocument();
  });

  it("edits the group and submits the update", async () => {
    routeGet(defaults());
    apiMock.put.mockResolvedValue(res({ ...group, name: "Engineering 2" }));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Edit" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Name *")).toHaveValue("Engineering");
    const name = within(dialog).getByLabelText("Name *");
    await userEvent.clear(name);
    await userEvent.type(name, "Engineering 2");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/groups/g1", {
        name: "Engineering 2",
        description: "Builders",
      })
    );
  });

  it("validates a blank name when editing", async () => {
    routeGet(defaults());
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Edit" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.clear(within(dialog).getByLabelText("Name *"));
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("surfaces an edit error from the service", async () => {
    routeGet(defaults());
    apiMock.put.mockRejectedValue(new Error("Update failed"));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Edit" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Update failed")).toBeInTheDocument();
  });

  it("removes a member after confirmation", async () => {
    routeGet(defaults());
    apiMock.delete.mockResolvedValue(res(undefined));
    renderPage();
    await userEvent.click(
      await screen.findByRole("button", { name: "Remove alice from group" })
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Remove Member/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/groups/g1/members/u1")
    );
  });

  it("adds a member via the user search dialog", async () => {
    routeGet(defaults());
    apiMock.post.mockResolvedValue(res(undefined));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /Add Member/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Search users"), "ca");
    await userEvent.click(await within(dialog).findByRole("button", { name: "Add" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/groups/g1/members", { user_id: "u2" })
    );
  });

  it("unassigns a role after confirmation", async () => {
    routeGet(defaults());
    apiMock.delete.mockResolvedValue(res(undefined));
    renderPage();
    await userEvent.click(
      await screen.findByRole("button", { name: "Unassign role Deploy" })
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Unassign Role/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/roles/r1/groups/g1")
    );
  });

  it("shows empty member/role states when nothing is present", async () => {
    routeGet(defaults({ [URLS.members]: [], [URLS.roles]: [] }));
    renderPage();
    expect(await screen.findByText("No members in this group yet.")).toBeInTheDocument();
    expect(
      await screen.findByText("No roles assigned to this group.")
    ).toBeInTheDocument();
  });
});
