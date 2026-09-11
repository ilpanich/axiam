import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { ScopesPanel } from "./ScopesPanel";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore } from "@/stores/auth";
import { setToastDispatch } from "@/hooks/useToast";

function setUser(permissions: string[]) {
  useAuthStore.setState({
    user: { id: "u1", username: "admin", email: "a@x.io", permissions, tenant_id: "t1" },
    tenantSlug: "acme-tenant",
    orgSlug: "acme",
    isAuthenticated: true,
    isInitializing: false,
  });
}

const scopes = [
  {
    id: "s1",
    tenant_id: "t1",
    resource_id: "r1",
    name: "invoices",
    description: "Invoice access",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  },
];

beforeEach(() => {
  vi.clearAllMocks();
  setUser(["*"]);
});

afterEach(() => {
  setToastDispatch(null);
});

describe("ScopesPanel", () => {
  it("lists scopes for the given resource", async () => {
    apiMock.get.mockResolvedValue(res(scopes));
    renderWithProviders(<ScopesPanel resourceId="r1" resourceName="Billing" />);
    expect(await screen.findByText("invoices")).toBeInTheDocument();
    expect(screen.getByText("Invoice access")).toBeInTheDocument();
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/resources/r1/scopes", { params: { offset: 0, limit: 200 } });
  });

  it("hides the New Scope button without scopes:create", async () => {
    setUser(["scopes:list"]);
    apiMock.get.mockResolvedValue(res(scopes));
    renderWithProviders(<ScopesPanel resourceId="r1" resourceName="Billing" />);
    await screen.findByText("invoices");
    expect(screen.queryByRole("button", { name: /New Scope/ })).not.toBeInTheDocument();
  });

  it("creates a scope on the resource", async () => {
    apiMock.get.mockResolvedValue(res([]));
    apiMock.post.mockResolvedValue(res({ ...scopes[0], id: "s2", name: "reports" }));
    renderWithProviders(<ScopesPanel resourceId="r1" resourceName="Billing" />);
    await userEvent.click(await screen.findByRole("button", { name: /New Scope/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "reports");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/resources/r1/scopes", {
        name: "reports",
        description: "",
      })
    );
  });

  it("requires a name before creating", async () => {
    apiMock.get.mockResolvedValue(res(scopes));
    renderWithProviders(<ScopesPanel resourceId="r1" resourceName="Billing" />);
    await userEvent.click(await screen.findByRole("button", { name: /New Scope/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("edits a scope", async () => {
    apiMock.get.mockResolvedValue(res(scopes));
    apiMock.put.mockResolvedValue(res({ ...scopes[0], name: "invoices-v2" }));
    renderWithProviders(<ScopesPanel resourceId="r1" resourceName="Billing" />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit scope invoices" }));
    const dialog = screen.getByRole("dialog");
    const name = within(dialog).getByLabelText("Name *");
    await userEvent.clear(name);
    await userEvent.type(name, "invoices-v2");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/resources/r1/scopes/s1", {
        name: "invoices-v2",
        description: "Invoice access",
      })
    );
  });

  it("deletes a scope after confirmation", async () => {
    apiMock.get.mockResolvedValue(res(scopes));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<ScopesPanel resourceId="r1" resourceName="Billing" />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Delete scope invoices" })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/resources/r1/scopes/s1")
    );
  });

  it("shows the empty state when there are no scopes", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<ScopesPanel resourceId="r1" resourceName="Billing" />);
    expect(
      await screen.findByText("No scopes defined for this resource.")
    ).toBeInTheDocument();
  });
});

// ─── Failures, descriptions, and the ways out ─────────────────────────────────
//
// Each of the three writes reports a refusal twice — inline in the dialog it
// came from, and as a toast — because a dialog that stays open with no message
// reads as a click that did nothing. None of those paths were exercised, nor
// was the description field, nor any of the three dismissals.

describe("ScopesPanel — failures and dismissal", () => {
  it("sends the description along with the name", async () => {
    apiMock.get.mockResolvedValue(res([]));
    apiMock.post.mockResolvedValue(res({ ...scopes[0], id: "s2" }));
    renderWithProviders(<ScopesPanel resourceId="r1" resourceName="Billing" />);

    await userEvent.click(await screen.findByRole("button", { name: /New Scope/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "refunds");
    await userEvent.type(
      within(dialog).getByLabelText("Description"),
      "Issuing refunds",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/resources/r1/scopes", {
        name: "refunds",
        description: "Issuing refunds",
      })
    );
  });

  it("keeps the create dialog open and says why when the name is taken", async () => {
    apiMock.get.mockResolvedValue(res(scopes));
    apiMock.post.mockRejectedValue({
      response: {
        status: 409,
        data: { message: "A scope named invoices already exists on this resource" },
      },
    });
    const toastSpy = vi.fn();
    setToastDispatch(toastSpy);
    renderWithProviders(<ScopesPanel resourceId="r1" resourceName="Billing" />);

    await userEvent.click(await screen.findByRole("button", { name: /New Scope/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "invoices");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    expect(
      await screen.findByText(/A scope named invoices already exists/)
    ).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(toastSpy).toHaveBeenCalledWith({
      description: "A scope named invoices already exists on this resource",
      variant: "destructive",
    });
  });

  it("keeps the edit dialog open and says why when a rename is refused", async () => {
    apiMock.get.mockResolvedValue(res(scopes));
    apiMock.put.mockRejectedValue({
      response: { status: 403, data: { message: "Scope is managed by the organization" } },
    });
    const toastSpy = vi.fn();
    setToastDispatch(toastSpy);
    renderWithProviders(<ScopesPanel resourceId="r1" resourceName="Billing" />);

    await userEvent.click(
      await screen.findByRole("button", { name: "Edit scope invoices" })
    );
    await userEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "Save Changes" })
    );

    expect(
      await screen.findByText("Scope is managed by the organization")
    ).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(toastSpy).toHaveBeenCalledWith({
      description: "Scope is managed by the organization",
      variant: "destructive",
    });
  });

  it("refuses a rename that blanks the name", async () => {
    apiMock.get.mockResolvedValue(res(scopes));
    renderWithProviders(<ScopesPanel resourceId="r1" resourceName="Billing" />);

    await userEvent.click(
      await screen.findByRole("button", { name: "Edit scope invoices" })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.clear(within(dialog).getByLabelText("Name *"));
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));

    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("toasts the server's reason when a delete is refused", async () => {
    apiMock.get.mockResolvedValue(res(scopes));
    apiMock.delete.mockRejectedValue({
      response: { status: 409, data: { message: "Scope is referenced by 3 grants" } },
    });
    const toastSpy = vi.fn();
    setToastDispatch(toastSpy);
    renderWithProviders(<ScopesPanel resourceId="r1" resourceName="Billing" />);

    await userEvent.click(
      await screen.findByRole("button", { name: "Delete scope invoices" })
    );
    await userEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "Delete" })
    );

    await waitFor(() =>
      expect(toastSpy).toHaveBeenCalledWith({
        description: "Scope is referenced by 3 grants",
        variant: "destructive",
      })
    );
  });

  it("discards a half-filled create form when dismissed", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<ScopesPanel resourceId="r1" resourceName="Billing" />);

    await userEvent.click(await screen.findByRole("button", { name: /New Scope/ }));
    let dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "half-typed");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    );

    await userEvent.click(screen.getByRole("button", { name: /New Scope/ }));
    dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Name *")).toHaveValue("");
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("closes the edit and delete dialogs without writing", async () => {
    apiMock.get.mockResolvedValue(res(scopes));
    renderWithProviders(<ScopesPanel resourceId="r1" resourceName="Billing" />);

    await userEvent.click(
      await screen.findByRole("button", { name: "Edit scope invoices" })
    );
    await userEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" })
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    );

    await userEvent.click(
      screen.getByRole("button", { name: "Delete scope invoices" })
    );
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
