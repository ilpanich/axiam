import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { UserDetailPage } from "./UserDetailPage";
import { makeClient } from "@/test/renderWithProviders";

const user = {
  id: "u1",
  username: "alice",
  email: "alice@x.io",
  display_name: "Alice Smith",
  mfa_enabled: true,
  email_verified: true,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-02T00:00:00Z",
  status: "Active",
  metadata: { display_name: "Alice Smith" },
  is_locked: false,
  locked_until: null,
  failed_login_attempts: 0,
};

const mfaMethods = [
  { id: "m1", method_type: "totp", name: "Authenticator", created_at: "2026-01-01T00:00:00Z" },
];

const roles = [
  { id: "r1", name: "Admin", is_global: true, created_at: "t" },
  { id: "r2", name: "Viewer", is_global: false, created_at: "t" },
];

const URLS = {
  user: "/api/v1/users/u1",
  mfa: "/api/v1/users/u1/mfa-methods",
  roles: "/api/v1/roles",
};

function routeGet(map: Record<string, unknown>) {
  apiMock.get.mockImplementation((url: string) => {
    if (url in map) return Promise.resolve(res(map[url]));
    return Promise.resolve(res([]));
  });
}

function defaults(overrides: Record<string, unknown> = {}) {
  return { [URLS.user]: user, [URLS.mfa]: mfaMethods, [URLS.roles]: roles, ...overrides };
}

function renderPage() {
  const client = makeClient();
  const router = createMemoryRouter(
    [{ path: "/users/:userId", element: <UserDetailPage /> }],
    { initialEntries: ["/users/u1"] }
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

describe("UserDetailPage", () => {
  it("shows an error state when the user fails to load", async () => {
    apiMock.get.mockImplementation((url: string) => {
      if (url === URLS.user) return Promise.reject(new Error("nope"));
      return Promise.resolve(res([]));
    });
    renderPage();
    expect(
      await screen.findByText("User not found or failed to load.")
    ).toBeInTheDocument();
  });

  it("renders the user info, MFA methods and role section", async () => {
    routeGet(defaults());
    renderPage();
    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(screen.getByText("alice@x.io")).toBeInTheDocument();
    expect(screen.getByText("Alice Smith")).toBeInTheDocument();
    expect(screen.getByText("Verified")).toBeInTheDocument();
    expect(screen.getByText("Enabled")).toBeInTheDocument();
    expect(await screen.findByText("Authenticator")).toBeInTheDocument();
    expect(screen.getByText("TOTP")).toBeInTheDocument();
  });

  it("edits the user and submits the update", async () => {
    routeGet(defaults());
    apiMock.put.mockResolvedValue(res({ ...user, email: "new@x.io" }));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Edit" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Email *")).toHaveValue("alice@x.io");
    const email = within(dialog).getByLabelText("Email *");
    await userEvent.clear(email);
    await userEvent.type(email, "new@x.io");
    // Toggle active off.
    await userEvent.click(within(dialog).getByLabelText("Active"));
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/users/u1", {
        email: "new@x.io",
        // The service folds display_name into metadata on the wire.
        metadata: { display_name: "Alice Smith" },
        status: "Inactive",
      })
    );
  });

  it("validates a blank email when editing", async () => {
    routeGet(defaults());
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Edit" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.clear(within(dialog).getByLabelText("Email *"));
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Email is required.")).toBeInTheDocument();
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

  it("removes an MFA method after confirmation", async () => {
    routeGet(defaults());
    apiMock.delete.mockResolvedValue(res(undefined));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Remove Authenticator" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Remove MFA Method/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/users/u1/mfa-methods/m1")
    );
  });

  it("resets MFA after confirmation", async () => {
    routeGet(defaults());
    apiMock.post.mockResolvedValue(res(undefined));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /Reset MFA/ }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/re-enroll/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/users/u1/reset-mfa")
    );
  });

  it("disables Reset MFA when there are no MFA methods", async () => {
    routeGet(defaults({ [URLS.mfa]: [] }));
    renderPage();
    await screen.findByText("alice");
    expect(await screen.findByText("No MFA methods registered.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Reset MFA/ })).toBeDisabled();
  });

  it("validates role selection then assigns a role", async () => {
    routeGet(defaults());
    apiMock.post.mockResolvedValue(res(undefined));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Assign Role" }));
    const dialog = screen.getByRole("dialog");
    // Submit without selecting -> validation error.
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Please select a role.")).toBeInTheDocument();
    await userEvent.selectOptions(within(dialog).getByLabelText("Role"), "r1");
    await userEvent.click(within(dialog).getByRole("button", { name: "Assign" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/roles/r1/users", { user_id: "u1" })
    );
  });

  it("surfaces a role-assignment error from the service", async () => {
    routeGet(defaults());
    apiMock.post.mockRejectedValue(new Error("Assign failed"));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Assign Role" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.selectOptions(within(dialog).getByLabelText("Role"), "r2");
    await userEvent.click(within(dialog).getByRole("button", { name: "Assign" }));
    expect(await screen.findByText("Assign failed")).toBeInTheDocument();
  });

  it("shows a message when no roles are available to assign", async () => {
    routeGet(defaults({ [URLS.roles]: [] }));
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Assign Role" }));
    expect(
      await screen.findByText("No roles available. Create roles in the Roles page first.")
    ).toBeInTheDocument();
  });

  it("renders an unverified/disabled/inactive user with the fallback labels", async () => {
    routeGet(
      defaults({
        [URLS.user]: {
          ...user,
          display_name: undefined,
          metadata: {},
          email_verified: false,
          mfa_enabled: false,
          status: "Inactive",
        },
      })
    );
    renderPage();
    expect(await screen.findByText("Not verified")).toBeInTheDocument();
    expect(screen.getByText("Disabled")).toBeInTheDocument();
  });
});
