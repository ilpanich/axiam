import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { AssignRoleDialog } from "./AssignRoleDialog";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore } from "@/stores/auth";
import { roleService } from "@/services/roles";

const ROLES = [
  { id: "role-scoped", name: "resident", is_global: false, created_at: "t" },
  { id: "role-global", name: "auditor", is_global: true, created_at: "t" },
];
const RESOURCES = [{ id: "res1", name: "apartment-7", tenant_id: "t1" }];

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({
    user: {
      id: "u9",
      username: "tenant-admin",
      email: "a@x.io",
      permissions: ["*"],
      tenant_id: "t1",
      principal_tenant_id: "t1",
      org_id: "o1",
      organization_level: false,
    },
    activeTenantId: null,
    isAuthenticated: true,
    isInitializing: false,
  });
  apiMock.get.mockImplementation((url: string) => {
    if (url === "/api/v1/roles") return Promise.resolve(res({ items: ROLES, total: ROLES.length }));
    if (url === "/api/v1/resources")
      return Promise.resolve(res({ items: RESOURCES, total: RESOURCES.length }));
    return Promise.resolve(res({ items: [], total: 0 }));
  });
  apiMock.post.mockResolvedValue(res(undefined));
});

/** The user page's wiring, exactly: `assignToUser` with all four arguments. */
function renderForUser() {
  const onClose = vi.fn();
  renderWithProviders(
    <AssignRoleDialog
      open
      onClose={onClose}
      subject="user"
      onAssign={(roleId, resourceId, tenantScope, inherit) =>
        roleService.assignToUser(roleId, "u1", resourceId, tenantScope, inherit)
      }
    />
  );
  return { onClose };
}

const inheritBox = () =>
  screen.queryByLabelText(/Also applies to the resource.s descendants/);

async function pick(role: string, resource: string) {
  await userEvent.selectOptions(await screen.findByLabelText("Role"), role);
  await waitFor(() =>
    expect(screen.getByRole("option", { name: "apartment-7" })).toBeInTheDocument()
  );
  await userEvent.selectOptions(screen.getByLabelText("Scope"), resource);
}

describe("AssignRoleDialog — inherit (S-10b)", () => {
  it("offers the flag only once a resource is chosen for a non-global role", async () => {
    renderForUser();
    await userEvent.selectOptions(await screen.findByLabelText("Role"), "role-scoped");
    expect(inheritBox()).not.toBeInTheDocument(); // no resource yet
    await pick("role-scoped", "res1");
    expect(inheritBox()).toBeChecked();
    await userEvent.selectOptions(screen.getByLabelText("Scope"), "");
    expect(inheritBox()).not.toBeInTheDocument(); // back to tenant-wide
  });

  it("never offers it for a global role, which the server would refuse", async () => {
    renderForUser();
    await pick("role-global", "res1");
    expect(inheritBox()).not.toBeInTheDocument();
  });

  it("sends inherit: false when unchecked", async () => {
    const { onClose } = renderForUser();
    await pick("role-scoped", "res1");
    await userEvent.click(inheritBox()!);
    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/roles/role-scoped/users", {
      user_id: "u1",
      resource_id: "res1",
      inherit: false,
    });
  });

  it("I4 twin: a resource-scoped assignment left checked is today's body", async () => {
    const { onClose } = renderForUser();
    await pick("role-scoped", "res1");
    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(apiMock.post.mock.calls[0][1]).toEqual({ user_id: "u1", resource_id: "res1" });
  });

  it("drops an unchecked flag once the resource is cleared, instead of sending a refusal", async () => {
    const { onClose } = renderForUser();
    await pick("role-scoped", "res1");
    await userEvent.click(inheritBox()!);
    await userEvent.selectOptions(screen.getByLabelText("Scope"), "");
    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(apiMock.post.mock.calls[0][1]).toEqual({ user_id: "u1" });
  });

  it("drops it too when the role is switched to a global one", async () => {
    const { onClose } = renderForUser();
    await pick("role-scoped", "res1");
    await userEvent.click(inheritBox()!);
    await userEvent.selectOptions(screen.getByLabelText("Role"), "role-global");
    expect(inheritBox()).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(apiMock.post.mock.calls[0][1]).toEqual({ user_id: "u1", resource_id: "res1" });
  });

  it("shows the server's refusal verbatim", async () => {
    const message =
      "inherit: false cannot be set on a global role — a global role applies to every resource whatever its assignment names";
    apiMock.post.mockRejectedValue({
      message: "Request failed with status code 400",
      response: { status: 400, data: { error: "validation_error", message } },
    });
    renderForUser();
    await pick("role-scoped", "res1");
    await userEvent.click(inheritBox()!);
    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    expect(await screen.findByText(message)).toBeInTheDocument();
  });

  it("the group page's wiring sends the flag to the group route", async () => {
    renderWithProviders(
      <AssignRoleDialog
        open
        onClose={() => {}}
        subject="group"
        onAssign={(roleId, resourceId, tenantScope, inherit) =>
          roleService.assignToGroup(roleId, "g1", resourceId, tenantScope, inherit)
        }
      />
    );
    await pick("role-scoped", "res1");
    await userEvent.click(inheritBox()!);
    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/roles/role-scoped/groups", {
        group_id: "g1",
        resource_id: "res1",
        inherit: false,
      })
    );
  });
});
