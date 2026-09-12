import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { EffectiveAccessPanel } from "./EffectiveAccessPanel";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore } from "@/stores/auth";
import type { Resource } from "@/services/resources";

function setUser(permissions: string[]) {
  useAuthStore.setState({
    user: { id: "u1", username: "admin", email: "a@x.io", permissions, tenant_id: "t1" },
    tenantSlug: "acme-tenant",
    orgSlug: "acme",
    isAuthenticated: true,
    isInitializing: false,
  });
}

function r(id: string, name: string, parent_id?: string): Resource {
  return { id, name, resource_type: "api", parent_id, created_at: "t" };
}

const resources: Resource[] = [
  r("root", "Root"),
  r("child1", "Child One", "root"),
  r("child2", "Child Two", "root"),
];

beforeEach(() => {
  vi.clearAllMocks();
  setUser([]);
});

describe("EffectiveAccessPanel", () => {
  it("prompts to select a resource when none is selected", () => {
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={undefined}
        onDenyResourceIdsChange={vi.fn()}
      />
    );
    expect(
      screen.getByText("Select a resource in the tree to preview effective access for it.")
    ).toBeInTheDocument();
  });

  it("hides the subject picker without authz:check_as", () => {
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={resources[0]}
        onDenyResourceIdsChange={vi.fn()}
      />
    );
    expect(screen.queryByRole("button", { name: /Choose user/ })).not.toBeInTheDocument();
    expect(screen.getByText(/preview your own effective access/)).toBeInTheDocument();
  });

  it("shows the subject picker with authz:check_as", () => {
    setUser(["authz:check_as"]);
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={resources[0]}
        onDenyResourceIdsChange={vi.fn()}
      />
    );
    expect(screen.getByRole("button", { name: /Choose user/ })).toBeInTheDocument();
  });

  it("checks access for self and shows an Allow badge", async () => {
    apiMock.post.mockResolvedValue(
      res({ allowed: true, reason_code: "allowed" })
    );
    const onDenyChange = vi.fn();
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={resources[0]}
        onDenyResourceIdsChange={onDenyChange}
      />
    );
    await userEvent.click(screen.getByRole("button", { name: "Check access" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/authz/check", {
        action: "read",
        resource_id: "root",
        scope: undefined,
        subject_id: undefined,
      })
    );
    expect(await screen.findByText("Allow")).toBeInTheDocument();
    expect(onDenyChange).toHaveBeenCalledWith(new Set());
  });

  it("shows a Deny badge and previews inheritance to descendants", async () => {
    apiMock.post.mockImplementation((url: string, body: unknown) => {
      if (url === "/api/v1/authz/check") {
        return Promise.resolve(
          res({ allowed: false, reason_code: "denied_by_rule", reason: "explicit deny" })
        );
      }
      if (url === "/api/v1/authz/check/batch") {
        const checks = (body as { checks: { resource_id: string }[] }).checks;
        return Promise.resolve(
          res({
            results: checks.map((c) => ({
              allowed: false,
              reason_code: c.resource_id === "child1" ? "denied_by_rule" : "no_grant",
            })),
          })
        );
      }
      return Promise.reject(new Error("unexpected url"));
    });
    const onDenyChange = vi.fn();
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={resources[0]}
        onDenyResourceIdsChange={onDenyChange}
      />
    );
    await userEvent.click(screen.getByRole("button", { name: "Check access" }));
    expect(await screen.findByText("Deny")).toBeInTheDocument();
    await waitFor(() =>
      expect(onDenyChange).toHaveBeenCalledWith(new Set(["root", "child1"]))
    );
    expect(
      await screen.findByText(/This deny reaches 1 descendant resource/)
    ).toBeInTheDocument();
  });

  it("surfaces an error when the check fails", async () => {
    apiMock.post.mockRejectedValue(new Error("Forbidden"));
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={resources[0]}
        onDenyResourceIdsChange={vi.fn()}
      />
    );
    await userEvent.click(screen.getByRole("button", { name: "Check access" }));
    expect(await screen.findByText("Forbidden")).toBeInTheDocument();
  });
});

// ─── Choosing a subject, and asking about a real action ───────────────────────
//
// The two halves of this panel that were never exercised are the ones that
// decide *what question is asked*: whose access, and which action. A preview of
// the wrong subject or an action no permission in the tenant uses answers
// truthfully and unhelpfully — which is exactly what the datalist hint exists
// to catch.

const tenantPermissions = [
  { id: "p1", action: "invoices:read", description: "", created_at: "t" },
  { id: "p2", action: "invoices:write", description: "", created_at: "t" },
];

/** As `GET /api/v1/users` really answers: the display name lives in
 *  `metadata`, and `userService.list` is what lifts it to a top-level field. */
const pickableUser = {
  id: "u9",
  username: "bob",
  email: "bob@x.io",
  metadata: { display_name: "Bob B" },
  mfa_enabled: false,
  email_verified: true,
  created_at: "t",
  updated_at: "t",
  status: "Active",
  is_locked: false,
  locked_until: null,
  failed_login_attempts: 0,
};

/** Route the two GETs this panel makes: the action vocabulary and user search. */
function routeGets(permissions: unknown[] = tenantPermissions) {
  apiMock.get.mockImplementation((url: string) => {
    if (url.startsWith("/api/v1/permissions"))
      return Promise.resolve(res(permissions));
    if (url.startsWith("/api/v1/users"))
      return Promise.resolve(
        res({ items: [pickableUser], total: 1, offset: 0, limit: 20 })
      );
    return Promise.resolve(res([]));
  });
}

describe("EffectiveAccessPanel — subject and action", () => {
  it("checks another user's access once one is picked, and reverts on Clear", async () => {
    setUser(["authz:check_as"]);
    routeGets();
    apiMock.post.mockResolvedValue(res({ allowed: true, reason_code: "allowed" }));
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={resources[0]}
        onDenyResourceIdsChange={vi.fn()}
      />
    );

    await userEvent.click(screen.getByRole("button", { name: /Choose user/ }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Search users"), "bo");
    await userEvent.click(await within(dialog).findByRole("button", { name: "Select" }));

    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    );
    expect(screen.getByLabelText(/Subject/)).toHaveValue("Bob B");

    await userEvent.click(screen.getByRole("button", { name: "Check access" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/authz/check",
        expect.objectContaining({ subject_id: "u9" })
      )
    );

    // Clearing goes back to previewing your own access, not a blank subject.
    await userEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(screen.getByLabelText(/Subject/)).toHaveValue("");
    await userEvent.click(screen.getByRole("button", { name: "Check access" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenLastCalledWith(
        "/api/v1/authz/check",
        expect.objectContaining({ subject_id: undefined })
      )
    );
  });

  it("closes the subject picker without changing who is previewed", async () => {
    setUser(["authz:check_as"]);
    routeGets();
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={resources[0]}
        onDenyResourceIdsChange={vi.fn()}
      />
    );

    await userEvent.click(screen.getByRole("button", { name: /Choose user/ }));
    await userEvent.click(
      within(await screen.findByRole("dialog")).getByRole("button", { name: "Done" })
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    );
    expect(screen.getByLabelText(/Subject/)).toHaveValue("");
  });

  it("says when the typed action matches no permission in this tenant", async () => {
    // The failure this replaced: a hard-coded read/write/delete/admin datalist
    // made a correct rule set look broken, because the question was wrong.
    routeGets();
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={resources[0]}
        onDenyResourceIdsChange={vi.fn()}
      />
    );

    // "read" is the default and is not one of this tenant's actions.
    expect(
      await screen.findByText(/No permission in this tenant has the action/)
    ).toBeInTheDocument();

    const actionField = screen.getByLabelText("Action");
    await userEvent.clear(actionField);
    await userEvent.type(actionField, "invoices:read");
    await waitFor(() =>
      expect(
        screen.queryByText(/No permission in this tenant has the action/)
      ).not.toBeInTheDocument()
    );
  });

  it("stays quiet about unknown actions when the permission list is unreadable", async () => {
    // Failure is deliberately silent: a permissions read the caller may not
    // make costs suggestions, not the panel.
    apiMock.get.mockRejectedValue({ response: { status: 403 } });
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={resources[0]}
        onDenyResourceIdsChange={vi.fn()}
      />
    );

    expect(screen.getByLabelText("Action")).toHaveValue("read");
    await waitFor(() =>
      expect(
        screen.queryByText(/No permission in this tenant has the action/)
      ).not.toBeInTheDocument()
    );
  });

  it("sends the scope when one is typed", async () => {
    routeGets();
    apiMock.post.mockResolvedValue(res({ allowed: true, reason_code: "allowed" }));
    renderWithProviders(
      <EffectiveAccessPanel
        resources={resources}
        selectedResource={resources[0]}
        onDenyResourceIdsChange={vi.fn()}
      />
    );

    await userEvent.type(screen.getByLabelText(/Scope/), "invoices");
    await userEvent.click(screen.getByRole("button", { name: "Check access" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/authz/check",
        expect.objectContaining({ scope: "invoices" })
      )
    );
  });
});
