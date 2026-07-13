import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, waitFor, within, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { FederationPage } from "./FederationPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { setToastDispatch } from "@/hooks/useToast";

const configs = [
  {
    id: "f1",
    tenant_id: "t1",
    provider: "Okta",
    protocol: "OidcConnect",
    metadata_url: "https://okta.example.com/.well-known/openid-configuration",
    client_id: "okta-client-id",
    attribute_map: { email: "mail" },
    enabled: true,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "f2",
    tenant_id: "t1",
    provider: "ADFS",
    protocol: "Saml",
    metadata_url: null,
    client_id: "adfs-client-id",
    attribute_map: {},
    enabled: false,
    created_at: "2026-01-02T00:00:00Z",
    updated_at: "2026-01-02T00:00:00Z",
  },
];

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  setToastDispatch(null);
});

describe("FederationPage", () => {
  it("renders the fetched configs with protocol badges and status", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    renderWithProviders(<FederationPage />);
    expect(await screen.findByText("Okta")).toBeInTheDocument();
    expect(screen.getByText("ADFS")).toBeInTheDocument();
    expect(screen.getByText("OIDC")).toBeInTheDocument();
    expect(screen.getByText("SAML")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("Inactive")).toBeInTheDocument();
    expect(screen.getByText("okta-client-id")).toBeInTheDocument();
  });

  it("shows the empty state when there are no federation configs", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<FederationPage />);
    expect(await screen.findByText("No federation configs defined.")).toBeInTheDocument();
  });

  it("filters by provider or client id via the search box", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    renderWithProviders(<FederationPage />);
    await screen.findByText("Okta");
    const search = screen.getByPlaceholderText("Search by provider or client ID...");
    await userEvent.type(search, "adfs");
    await waitFor(() => expect(screen.queryByText("Okta")).not.toBeInTheDocument());
    expect(screen.getByText("ADFS")).toBeInTheDocument();
  });

  // ─── Create: field-level validation ────────────────────────────────────────

  it("requires a provider before creating", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");
    // Submit the form directly: the empty provider field is `required`, so
    // native constraint validation would block a submit-button click before the
    // component's own validation could set the message.
    fireEvent.submit(
      within(dialog).getByRole("button", { name: "Create" }).closest("form")!
    );
    expect(await screen.findByText("Provider is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("requires a client id before creating", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Provider *"), "Auth0");
    // Client ID (required, still empty) would block a native submit; submit the
    // form directly to reach the component's validation.
    fireEvent.submit(
      within(dialog).getByRole("button", { name: "Create" }).closest("form")!
    );
    expect(await screen.findByText("Client ID is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("requires a client secret before creating", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Provider *"), "Auth0");
    await userEvent.type(within(dialog).getByLabelText("Client ID *"), "abc");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Client Secret is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("shows SAML-only fields only when the SAML protocol is selected", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");

    expect(
      within(dialog).queryByLabelText(/IdP Signing Certificate/),
    ).not.toBeInTheDocument();

    await userEvent.selectOptions(
      within(dialog).getByLabelText("Federation protocol"),
      "Saml",
    );

    expect(within(dialog).getByLabelText(/IdP Signing Certificate/)).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Allowed Algorithms")).toBeInTheDocument();
  });

  it("requires an IdP signing certificate for SAML configs", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Provider *"), "ADFS2");
    await userEvent.type(within(dialog).getByLabelText("Client ID *"), "abc");
    await userEvent.type(within(dialog).getByLabelText(/Client Secret/), "shh");
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Federation protocol"),
      "Saml",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(
      await screen.findByText("IdP signing certificate is required for SAML."),
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("rejects an invalid JSON attribute map", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Provider *"), "Auth0");
    await userEvent.type(within(dialog).getByLabelText("Client ID *"), "abc");
    await userEvent.type(within(dialog).getByLabelText(/Client Secret/), "shh");
    await userEvent.type(
      within(dialog).getByLabelText(/Attribute Map/),
      // `{{` escapes the literal `{` (userEvent treats `{`/`[` as special).
      "{{not json",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(
      await screen.findByText("Attribute map must be valid JSON."),
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("rejects a JSON array attribute map", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Provider *"), "Auth0");
    await userEvent.type(within(dialog).getByLabelText("Client ID *"), "abc");
    await userEvent.type(within(dialog).getByLabelText(/Client Secret/), "shh");
    // `[[` escapes the literal `[` (userEvent treats `[`/`{` as special).
    await userEvent.type(within(dialog).getByLabelText(/Attribute Map/), "[[1,2,3]");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(
      await screen.findByText("Attribute map must be a JSON object."),
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  // ─── Create: success paths ──────────────────────────────────────────────────

  it("creates an OIDC config with a default empty attribute map and null metadata url", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    apiMock.post.mockResolvedValue(res({ ...configs[0], id: "f3" }));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Provider *"), "Auth0");
    await userEvent.type(within(dialog).getByLabelText("Client ID *"), "auth0-client");
    await userEvent.type(within(dialog).getByLabelText(/Client Secret/), "shh-secret");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/federation-configs", {
        provider: "Auth0",
        protocol: "OidcConnect",
        client_id: "auth0-client",
        client_secret: "shh-secret",
        metadata_url: null,
        attribute_map: {},
      }),
    );
  });

  it("creates a SAML config including cert and parsed allowed algorithms", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    apiMock.post.mockResolvedValue(res({ ...configs[1], id: "f4" }));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Provider *"), "ADFS2");
    await userEvent.type(within(dialog).getByLabelText("Client ID *"), "adfs2-client");
    await userEvent.type(within(dialog).getByLabelText(/Client Secret/), "shh-secret");
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Federation protocol"),
      "Saml",
    );
    await userEvent.type(
      within(dialog).getByLabelText(/IdP Signing Certificate/),
      "-----BEGIN CERTIFICATE-----abc",
    );
    await userEvent.type(
      within(dialog).getByLabelText("Allowed Algorithms"),
      "RS256, RS384",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/federation-configs", {
        provider: "ADFS2",
        protocol: "Saml",
        client_id: "adfs2-client",
        client_secret: "shh-secret",
        metadata_url: null,
        attribute_map: {},
        idp_signing_cert_pem: "-----BEGIN CERTIFICATE-----abc",
        allowed_algorithms: ["RS256", "RS384"],
      }),
    );
  });

  it("surfaces a create error via inline message and toast", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    apiMock.post.mockRejectedValue({
      isAxiosError: true,
      response: { data: { error: "Provider already configured" } },
    });
    const toastSpy = vi.fn();
    setToastDispatch(toastSpy);
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Provider *"), "Okta");
    await userEvent.type(within(dialog).getByLabelText("Client ID *"), "abc");
    await userEvent.type(within(dialog).getByLabelText(/Client Secret/), "shh");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    expect(
      await screen.findByText("Provider already configured"),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(toastSpy).toHaveBeenCalledWith({
        description: "Provider already configured",
        variant: "destructive",
      }),
    );
  });

  // ─── Edit ───────────────────────────────────────────────────────────────────

  it("prefills the edit form, disables the protocol select, and never prefills the secret", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Okta" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Provider *")).toHaveValue("Okta");
    expect(within(dialog).getByLabelText("Client ID *")).toHaveValue("okta-client-id");
    expect(within(dialog).getByLabelText(/Client Secret/)).toHaveValue("");
    expect(within(dialog).getByLabelText("Federation protocol")).toBeDisabled();
    expect(
      within(dialog).getByLabelText(/Attribute Map/),
    ).toHaveValue(JSON.stringify({ email: "mail" }, null, 2));
    expect(within(dialog).getByLabelText("Enabled")).toBeChecked();
  });

  it("updates a config without changing the secret when left blank", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    apiMock.put.mockResolvedValue(res({ ...configs[0], provider: "Okta Prod" }));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Okta" }));
    const dialog = screen.getByRole("dialog");
    const providerField = within(dialog).getByLabelText("Provider *");
    await userEvent.clear(providerField);
    await userEvent.type(providerField, "Okta Prod");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/federation-configs/f1", {
        provider: "Okta Prod",
        client_id: "okta-client-id",
        metadata_url: "https://okta.example.com/.well-known/openid-configuration",
        attribute_map: { email: "mail" },
        enabled: true,
      }),
    );
  });

  it("includes a new client secret in the update payload only when entered", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    apiMock.put.mockResolvedValue(res(configs[0]));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Okta" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText(/Client Secret/), "new-secret");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        "/api/v1/federation-configs/f1",
        expect.objectContaining({ client_secret: "new-secret" }),
      ),
    );
  });

  it("includes SAML cert and algorithms in the update payload for SAML configs", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    apiMock.put.mockResolvedValue(res(configs[1]));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit ADFS" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(
      within(dialog).getByLabelText(/IdP Signing Certificate/),
      "-----BEGIN CERTIFICATE-----xyz",
    );
    await userEvent.type(
      within(dialog).getByLabelText("Allowed Algorithms"),
      "RS512",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        "/api/v1/federation-configs/f2",
        expect.objectContaining({
          idp_signing_cert_pem: "-----BEGIN CERTIFICATE-----xyz",
          allowed_algorithms: ["RS512"],
        }),
      ),
    );
  });

  it("requires a provider when editing", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Okta" }));
    const dialog = screen.getByRole("dialog");
    const providerField = within(dialog).getByLabelText("Provider *");
    await userEvent.clear(providerField);
    // Empty required provider blocks a native submit; submit the form directly.
    fireEvent.submit(
      within(dialog).getByRole("button", { name: "Save Changes" }).closest("form")!
    );
    expect(await screen.findByText("Provider is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("rejects an invalid attribute map on edit", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Okta" }));
    const dialog = screen.getByRole("dialog");
    const attrField = within(dialog).getByLabelText(/Attribute Map/);
    await userEvent.clear(attrField);
    await userEvent.type(attrField, "not json");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(
      await screen.findByText("Attribute map must be valid JSON."),
    ).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("surfaces an edit error via inline message and toast", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    apiMock.put.mockRejectedValue(new Error("Update failed"));
    const toastSpy = vi.fn();
    setToastDispatch(toastSpy);
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Okta" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Update failed")).toBeInTheDocument();
    await waitFor(() =>
      expect(toastSpy).toHaveBeenCalledWith({
        description: "Update failed",
        variant: "destructive",
      }),
    );
  });

  // ─── Delete ─────────────────────────────────────────────────────────────────

  it("deletes a config after confirmation", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete ADFS" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Delete Federation Config/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/federation-configs/f2"),
    );
  });

  it("shows a toast when delete fails", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    apiMock.delete.mockRejectedValue(new Error("Cannot delete in use"));
    const toastSpy = vi.fn();
    setToastDispatch(toastSpy);
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete ADFS" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(toastSpy).toHaveBeenCalledWith({
        description: "Cannot delete in use",
        variant: "destructive",
      }),
    );
  });
});
