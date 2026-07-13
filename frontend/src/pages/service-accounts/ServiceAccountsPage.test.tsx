import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { ServiceAccountsPage } from "./ServiceAccountsPage";
import { renderWithProviders } from "@/test/renderWithProviders";

const accounts = [
  {
    id: "sa1",
    tenant_id: "t1",
    name: "ci-runner",
    description: "CI pipeline account",
    client_id: "client-abc-123",
    status: "Active",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "sa2",
    tenant_id: "t1",
    name: "legacy-bot",
    description: null,
    client_id: "client-def-456",
    status: "Inactive",
    created_at: "2026-01-02T00:00:00Z",
    updated_at: "2026-01-02T00:00:00Z",
  },
];

beforeEach(() => {
  vi.clearAllMocks();
});

describe("ServiceAccountsPage", () => {
  it("renders the fetched service accounts", async () => {
    apiMock.get.mockResolvedValue(res(accounts));
    renderWithProviders(<ServiceAccountsPage />);
    expect(await screen.findByText("ci-runner")).toBeInTheDocument();
    expect(screen.getByText("legacy-bot")).toBeInTheDocument();
    expect(screen.getByText("CI pipeline account")).toBeInTheDocument();
    expect(screen.getByText("client-abc-123")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("Inactive")).toBeInTheDocument();
    // No description falls back to the em-dash placeholder
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("shows the empty state when there are no service accounts", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<ServiceAccountsPage />);
    expect(await screen.findByText("No service accounts found.")).toBeInTheDocument();
  });

  it("filters by name or client id via the search box", async () => {
    apiMock.get.mockResolvedValue(res(accounts));
    renderWithProviders(<ServiceAccountsPage />);
    await screen.findByText("ci-runner");
    const search = screen.getByPlaceholderText("Search service accounts...");
    await userEvent.type(search, "legacy");
    await waitFor(() => expect(screen.queryByText("ci-runner")).not.toBeInTheDocument());
    expect(screen.getByText("legacy-bot")).toBeInTheDocument();
  });

  it("validates that a non-blank name is required before creating", async () => {
    apiMock.get.mockResolvedValue(res(accounts));
    renderWithProviders(<ServiceAccountsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Service Account/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "   ");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("creates a service account and reveals the client secret once", async () => {
    apiMock.get.mockResolvedValue(res(accounts));
    apiMock.post.mockResolvedValue(
      res({
        id: "sa3",
        tenant_id: "t1",
        name: "new-account",
        description: "fresh",
        client_id: "client-new-999",
        client_secret: "super-secret-value",
        status: "Active",
        created_at: "t",
        updated_at: "t",
      }),
    );
    renderWithProviders(<ServiceAccountsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Service Account/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "new-account");
    await userEvent.type(within(dialog).getByLabelText("Description"), "fresh");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/service-accounts", {
        name: "new-account",
        description: "fresh",
      }),
    );

    // The create dialog closes and the one-time secret modal appears.
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    const secretDialog = await screen.findByRole("alertdialog");
    expect(within(secretDialog).getByText("Service Account Created")).toBeInTheDocument();
    expect(within(secretDialog).getByText("client-new-999")).toBeInTheDocument();
    expect(within(secretDialog).getByText("super-secret-value")).toBeInTheDocument();

    await userEvent.click(
      within(secretDialog).getByRole("button", { name: "I've saved this information" }),
    );
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("creates without a description sending undefined", async () => {
    apiMock.get.mockResolvedValue(res(accounts));
    apiMock.post.mockResolvedValue(
      res({
        id: "sa4",
        tenant_id: "t1",
        name: "bare-account",
        client_id: "client-bare",
        client_secret: "s3cr3t",
        status: "Active",
        created_at: "t",
        updated_at: "t",
      }),
    );
    renderWithProviders(<ServiceAccountsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Service Account/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "bare-account");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/service-accounts", {
        name: "bare-account",
        description: undefined,
      }),
    );
  });

  it("surfaces a create error from the service", async () => {
    apiMock.get.mockResolvedValue(res(accounts));
    apiMock.post.mockRejectedValue(new Error("Name already in use"));
    renderWithProviders(<ServiceAccountsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Service Account/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "dup");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Name already in use")).toBeInTheDocument();
  });

  it("surfaces a generic create error message for non-Error rejections", async () => {
    apiMock.get.mockResolvedValue(res(accounts));
    apiMock.post.mockRejectedValue("boom");
    renderWithProviders(<ServiceAccountsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Service Account/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "dup");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(
      await screen.findByText("Failed to create service account."),
    ).toBeInTheDocument();
  });

  it("edits an existing account, prefilling its current values", async () => {
    apiMock.get.mockResolvedValue(res(accounts));
    apiMock.put.mockResolvedValue(res({ ...accounts[0], name: "ci-runner-2" }));
    renderWithProviders(<ServiceAccountsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit ci-runner" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Name *")).toHaveValue("ci-runner");
    expect(within(dialog).getByLabelText("Description")).toHaveValue("CI pipeline account");
    expect(within(dialog).getByLabelText("Active")).toBeChecked();

    const nameField = within(dialog).getByLabelText("Name *");
    await userEvent.clear(nameField);
    await userEvent.type(nameField, "ci-runner-2");
    await userEvent.click(within(dialog).getByLabelText("Active"));
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/service-accounts/sa1", {
        name: "ci-runner-2",
        description: "CI pipeline account",
        status: "Inactive",
      }),
    );
  });

  it("blocks saving an edit with a blank name", async () => {
    apiMock.get.mockResolvedValue(res(accounts));
    renderWithProviders(<ServiceAccountsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit ci-runner" }));
    const dialog = screen.getByRole("dialog");
    const nameField = within(dialog).getByLabelText("Name *");
    await userEvent.clear(nameField);
    await userEvent.type(nameField, "   ");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("surfaces an edit error from the service", async () => {
    apiMock.get.mockResolvedValue(res(accounts));
    apiMock.put.mockRejectedValue(new Error("Update rejected"));
    renderWithProviders(<ServiceAccountsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit ci-runner" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Update rejected")).toBeInTheDocument();
  });

  it("deletes an account after confirmation", async () => {
    apiMock.get.mockResolvedValue(res(accounts));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<ServiceAccountsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete legacy-bot" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Delete Service Account/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/service-accounts/sa2"),
    );
  });

  it("rotates a client secret and reveals the new value while keeping the client id", async () => {
    apiMock.get.mockResolvedValue(res(accounts));
    apiMock.post.mockResolvedValue(res({ client_secret: "rotated-secret-xyz" }));
    renderWithProviders(<ServiceAccountsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Rotate secret for ci-runner" }),
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Rotate Client Secret/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Rotate" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/service-accounts/sa1/rotate-secret",
      ),
    );

    const secretDialog = await screen.findByRole("alertdialog");
    expect(within(secretDialog).getByText("Secret Rotated")).toBeInTheDocument();
    expect(within(secretDialog).getByText("client-abc-123")).toBeInTheDocument();
    expect(within(secretDialog).getByText("rotated-secret-xyz")).toBeInTheDocument();
  });
});
