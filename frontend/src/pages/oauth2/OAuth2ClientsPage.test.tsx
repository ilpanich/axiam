import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { OAuth2ClientsPage } from "./OAuth2ClientsPage";
import { renderWithProviders } from "@/test/renderWithProviders";

const clients = [
  {
    id: "c1",
    client_id: "client-abc-123",
    name: "Web App",
    redirect_uris: ["https://app.example.com/callback"],
    grant_types: ["authorization_code", "refresh_token"],
    scopes: ["openid", "profile"],
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "c2",
    client_id: "client-def-456",
    name: "Backend Service",
    redirect_uris: [],
    grant_types: ["client_credentials"],
    scopes: [],
    created_at: "2026-01-02T00:00:00Z",
  },
];

beforeEach(() => {
  vi.clearAllMocks();
});

describe("OAuth2ClientsPage", () => {
  it("renders the fetched clients with grant badges and URI counts", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    renderWithProviders(<OAuth2ClientsPage />);
    expect(await screen.findByText("Web App")).toBeInTheDocument();
    expect(screen.getByText("Backend Service")).toBeInTheDocument();
    expect(screen.getByText("client-abc-123")).toBeInTheDocument();
    expect(screen.getByText("Auth Code")).toBeInTheDocument();
    expect(screen.getByText("Client Creds")).toBeInTheDocument();
    expect(screen.getByText("1 URI")).toBeInTheDocument();
    expect(screen.getByText("0 URIs")).toBeInTheDocument();
  });

  it("shows the empty state when there are no clients", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<OAuth2ClientsPage />);
    expect(await screen.findByText("No OAuth2 clients registered.")).toBeInTheDocument();
  });

  it("requires a name before creating", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Client/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "   ");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("requires at least one grant type", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Client/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "App");
    // Uncheck the default authorization_code grant type.
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "authorization_code" }));
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Select at least one grant type.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("creates a client and reveals the one-time secret", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    apiMock.post.mockResolvedValue(
      res({
        id: "c3",
        client_id: "client-new-999",
        client_secret: "s3cr3t-value",
        name: "New App",
        redirect_uris: ["https://x/cb"],
        grant_types: ["authorization_code"],
        scopes: ["openid", "profile"],
        created_at: "t",
      })
    );
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Client/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "New App");
    fireEvent.change(within(dialog).getByLabelText("Redirect URIs (one per line)"), {
      target: { value: "https://x/cb\n  https://x/cb2  \n" },
    });
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/oauth2-clients", {
        name: "New App",
        redirect_uris: ["https://x/cb", "https://x/cb2"],
        grant_types: ["authorization_code"],
        scopes: ["openid", "profile"],
      })
    );
    const secret = await screen.findByRole("alertdialog");
    expect(within(secret).getByText("OAuth2 Client Created")).toBeInTheDocument();
    expect(within(secret).getByText("client-new-999")).toBeInTheDocument();
    expect(within(secret).getByText("s3cr3t-value")).toBeInTheDocument();
    await userEvent.click(
      within(secret).getByRole("button", { name: "I've saved this information" })
    );
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("creates a client with no scopes sending scopes undefined", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    apiMock.post.mockResolvedValue(
      res({
        id: "c4",
        client_id: "client-bare",
        client_secret: "bare-secret",
        name: "Bare",
        redirect_uris: [],
        grant_types: ["authorization_code"],
        scopes: [],
        created_at: "t",
      })
    );
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Client/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Bare");
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "openid" }));
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "profile" }));
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/oauth2-clients", {
        name: "Bare",
        redirect_uris: [],
        grant_types: ["authorization_code"],
        scopes: undefined,
      })
    );
  });

  it("surfaces a create error inside the dialog", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    apiMock.post.mockRejectedValue(new Error("Name taken"));
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Client/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Dup");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Name taken")).toBeInTheDocument();
  });

  it("edits a client, pre-filling its current values", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    apiMock.put.mockResolvedValue(res({ ...clients[0], name: "Web App 2" }));
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit OAuth2 client Web App" })
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Name *")).toHaveValue("Web App");
    expect(within(dialog).getByLabelText("Redirect URIs (one per line)")).toHaveValue(
      "https://app.example.com/callback"
    );
    expect(within(dialog).getByRole("checkbox", { name: "authorization_code" })).toBeChecked();
    expect(within(dialog).getByRole("checkbox", { name: "refresh_token" })).toBeChecked();
    const name = within(dialog).getByLabelText("Name *");
    await userEvent.clear(name);
    await userEvent.type(name, "Web App 2");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/oauth2-clients/c1", {
        name: "Web App 2",
        redirect_uris: ["https://app.example.com/callback"],
        grant_types: ["authorization_code", "refresh_token"],
        scopes: ["openid", "profile"],
      })
    );
  });

  it("validates a blank name when editing", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit OAuth2 client Web App" })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.clear(within(dialog).getByLabelText("Name *"));
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("requires a grant type when editing", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit OAuth2 client Backend Service" })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "client_credentials" }));
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Select at least one grant type.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("surfaces an edit error inside the dialog", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    apiMock.put.mockRejectedValue(new Error("Update failed"));
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit OAuth2 client Web App" })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Update failed")).toBeInTheDocument();
  });

  it("deletes a client after confirmation", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Delete OAuth2 client Backend Service" })
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Delete OAuth2 Client/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/oauth2-clients/c2")
    );
  });
});
