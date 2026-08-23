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
