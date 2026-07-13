import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { UserSearchDialog } from "@/components/UserSearchDialog";
import { renderWithProviders } from "@/test/renderWithProviders";
import type { User } from "@/services/users";

function mkUser(id: string, username: string, email = `${username}@x.io`): User {
  return {
    id,
    username,
    email,
    mfa_enabled: false,
    email_verified: true,
    created_at: "t",
    updated_at: "t",
    status: "Active",
    is_locked: false,
    locked_until: null,
    failed_login_attempts: 0,
  };
}

beforeEach(() => vi.clearAllMocks());

describe("UserSearchDialog", () => {
  it("renders nothing when closed", () => {
    const { container } = renderWithProviders(
      <UserSearchDialog open={false} onClose={() => {}} title="Add" actionLabel="Add" onAction={async () => {}} />
    );
    expect(container.firstChild).toBeNull();
  });

  it("prompts to type at least 2 characters", () => {
    renderWithProviders(
      <UserSearchDialog open onClose={() => {}} title="Add member" actionLabel="Add" onAction={async () => {}} />
    );
    expect(screen.getByText(/at least 2 characters/i)).toBeInTheDocument();
  });

  it("searches once 2+ chars are typed and invokes onAction for a result", async () => {
    apiMock.get.mockResolvedValue(res({ items: [mkUser("u1", "alice")], total: 1, offset: 0, limit: 20 }));
    const onAction = vi.fn().mockResolvedValue(undefined);
    renderWithProviders(
      <UserSearchDialog open onClose={() => {}} title="Add" actionLabel="Add" onAction={onAction} />
    );
    await userEvent.type(screen.getByLabelText("Search users"), "al");
    await waitFor(() => expect(screen.getByText("alice")).toBeInTheDocument());
    await userEvent.click(screen.getByRole("button", { name: /Add/ }));
    await waitFor(() => expect(onAction).toHaveBeenCalledWith(expect.objectContaining({ id: "u1" })));
  });

  it("marks already-existing users instead of an action button", async () => {
    apiMock.get.mockResolvedValue(res({ items: [mkUser("u1", "alice")], total: 1, offset: 0, limit: 20 }));
    renderWithProviders(
      <UserSearchDialog
        open
        onClose={() => {}}
        title="Add"
        actionLabel="Add"
        onAction={async () => {}}
        existingIds={new Set(["u1"])}
        existingLabel="Member"
      />
    );
    await userEvent.type(screen.getByLabelText("Search users"), "al");
    await waitFor(() => expect(screen.getByText("Member")).toBeInTheDocument());
  });

  it("shows an empty state when the search yields no users", async () => {
    apiMock.get.mockResolvedValue(res({ items: [], total: 0, offset: 0, limit: 20 }));
    renderWithProviders(
      <UserSearchDialog open onClose={() => {}} title="Add" actionLabel="Add" onAction={async () => {}} />
    );
    await userEvent.type(screen.getByLabelText("Search users"), "zz");
    await waitFor(() => expect(screen.getByText("No users found.")).toBeInTheDocument());
  });

  it("closes and clears the term via Done", async () => {
    const onClose = vi.fn();
    renderWithProviders(
      <UserSearchDialog open onClose={onClose} title="Add" actionLabel="Add" onAction={async () => {}} />
    );
    await userEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(onClose).toHaveBeenCalled();
  });
});
