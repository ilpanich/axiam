import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, waitFor, within, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { FederationPage } from "./FederationPage";
import { DEFAULT_TOKEN_EXCHANGE_TRUST } from "@/services/federation";
import { renderWithProviders } from "@/test/renderWithProviders";
import { setToastDispatch } from "@/hooks/useToast";
import { useAuthStore } from "@/stores/auth";

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
    expect(await screen.findByText("Display name is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("requires a client id before creating", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Display name *"), "Auth0");
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
    await userEvent.type(within(dialog).getByLabelText("Display name *"), "Auth0");
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

    // The protocol follows the provider now: a kind and a protocol that
    // disagree is a configuration the server refuses, so the form does not
    // offer the pairing at all.
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Provider *"),
      "generic_saml",
    );

    expect(within(dialog).getByLabelText(/IdP Signing Certificate/)).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Allowed signature algorithms")).toBeInTheDocument();
  });

  it("requires an IdP signing certificate for SAML configs", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Display name *"), "ADFS2");
    await userEvent.type(within(dialog).getByLabelText("Client ID *"), "abc");
    await userEvent.type(within(dialog).getByLabelText(/Client Secret/), "shh");
    // The protocol follows the provider now: a kind and a protocol that
    // disagree is a configuration the server refuses, so the form does not
    // offer the pairing at all.
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Provider *"),
      "generic_saml",
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
    await userEvent.type(within(dialog).getByLabelText("Display name *"), "Auth0");
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
    await userEvent.type(within(dialog).getByLabelText("Display name *"), "Auth0");
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
    await userEvent.type(within(dialog).getByLabelText("Display name *"), "Auth0");
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
        // Every login-provider field is sent explicitly, including the ones
        // left at their defaults. The server never has to guess what an older
        // client meant, and an operator who clears a field gets it cleared —
        // rather than keeping whatever was stored because the key was omitted.
        provider_kind: "generic_oidc",
        provider_slug: null,
        allow_tenant_inheritance: false,
        scopes: [],
        authorization_endpoint: null,
        token_endpoint: null,
        userinfo_endpoint: null,
        allowed_issuer_tenants: [],
        apple_team_id: null,
        apple_key_id: null,
        require_pkce: false,
        button_icon: null,
      }),
    );
  });

  it("creates a SAML config including cert and parsed allowed algorithms", async () => {
    apiMock.get.mockResolvedValue(res(configs));
    apiMock.post.mockResolvedValue(res({ ...configs[1], id: "f4" }));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Display name *"), "ADFS2");
    await userEvent.type(within(dialog).getByLabelText("Client ID *"), "adfs2-client");
    await userEvent.type(within(dialog).getByLabelText(/Client Secret/), "shh-secret");
    // The protocol follows the provider now: a kind and a protocol that
    // disagree is a configuration the server refuses, so the form does not
    // offer the pairing at all.
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Provider *"),
      "generic_saml",
    );
    await userEvent.type(
      within(dialog).getByLabelText(/IdP Signing Certificate/),
      "-----BEGIN CERTIFICATE-----abc",
    );
    await userEvent.type(
      within(dialog).getByLabelText("Allowed signature algorithms"),
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
        // Every login-provider field is sent explicitly, including the ones
        // left at their defaults. The server never has to guess what an older
        // client meant, and an operator who clears a field gets it cleared —
        // rather than keeping whatever was stored because the key was omitted.
        provider_kind: "generic_saml",
        provider_slug: null,
        allow_tenant_inheritance: false,
        scopes: [],
        authorization_endpoint: null,
        token_endpoint: null,
        userinfo_endpoint: null,
        allowed_issuer_tenants: [],
        apple_team_id: null,
        apple_key_id: null,
        require_pkce: false,
        button_icon: null,
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
    await userEvent.type(within(dialog).getByLabelText("Display name *"), "Okta");
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
    expect(within(dialog).getByLabelText("Display name *")).toHaveValue("Okta");
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
    const providerField = within(dialog).getByLabelText("Display name *");
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
        // `provider_kind` is absent on purpose: it is immutable after creation,
        // because it decides the protocol and which inherited provider a tenant
        // overrides. Everything else is sent whole, for the same reason the
        // create payload is.
        provider_slug: null,
        allow_tenant_inheritance: false,
        scopes: [],
        authorization_endpoint: null,
        token_endpoint: null,
        userinfo_endpoint: null,
        allowed_issuer_tenants: [],
        apple_team_id: null,
        apple_key_id: null,
        require_pkce: false,
        button_icon: null,
        allowed_algorithms: [],
        // X4: an OIDC provider always carries its complete trust block. The
        // server replaces it wholesale, so sending a patch — or omitting it —
        // is how an operator keeps a setting they believed they had changed.
        // This fixture has none configured, so it is the disabled default.
        token_exchange: DEFAULT_TOKEN_EXCHANGE_TRUST,
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
      within(dialog).getByLabelText("Allowed signature algorithms"),
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
    const providerField = within(dialog).getByLabelText("Display name *");
    await userEvent.clear(providerField);
    // Empty required provider blocks a native submit; submit the form directly.
    fireEvent.submit(
      within(dialog).getByRole("button", { name: "Save Changes" }).closest("form")!
    );
    expect(await screen.findByText("Display name is required.")).toBeInTheDocument();
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

// ─── Provider kinds, inheritance, and the paths that refuse a save ────────────
//
// The suite above walks the generic OIDC and SAML kinds. The rest of the form
// only appears for other kinds — Apple's team/key IDs, an OAuth2 provider's
// three endpoints, a generic kind's slug, Entra's accepted-tenant list — and
// the inherited-providers section only appears for a tenant that inherits one,
// which needs the effective-providers endpoint to answer.

/** A config list plus an effective-providers response, routed by URL. */
function mockFederationGets(options: {
  configs?: unknown[];
  providers?: unknown[];
}) {
  apiMock.get.mockImplementation((url: string) => {
    if (url === "/api/v1/auth/federation/providers") {
      return Promise.resolve(res({ providers: options.providers ?? [] }));
    }
    return Promise.resolve(res(options.configs ?? []));
  });
}

const inheritedGoogle = {
  id: "p1",
  provider_kind: "google",
  display_name: "Google",
  protocol: "OidcConnect",
  has_bundled_mark: true,
  button_icon: null,
  inherited: true,
};

describe("FederationPage — provider kinds", () => {
  it("sends Apple's team and key IDs, which no other kind has", async () => {
    mockFederationGets({ configs });
    apiMock.post.mockResolvedValue(res({ ...configs[0], id: "f5" }));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");

    await userEvent.selectOptions(
      within(dialog).getByLabelText("Provider *"),
      "apple",
    );
    await userEvent.type(within(dialog).getByLabelText("Display name *"), "Apple");
    await userEvent.type(
      within(dialog).getByLabelText("Services ID *"),
      "com.example.service",
    );
    // Apple's "client secret" is the .p8 private key, and the field says so.
    await userEvent.type(
      within(dialog).getByLabelText(/Signing key/),
      "-----BEGIN PRIVATE KEY-----p8",
    );
    await userEvent.type(within(dialog).getByLabelText("Team ID"), "ABCDE12345");
    await userEvent.type(within(dialog).getByLabelText("Key ID"), "KEYID67890");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/federation-configs",
        expect.objectContaining({
          provider_kind: "apple",
          apple_team_id: "ABCDE12345",
          apple_key_id: "KEYID67890",
        }),
      ),
    );
  });

  it("sends the three endpoints an OAuth2 provider authenticates through", async () => {
    // There is no ID token on this protocol, so the userinfo endpoint *is* the
    // authentication — a wrong one is not a broken button, it is a wrong answer
    // to "who is this". All three go out explicitly.
    mockFederationGets({ configs });
    apiMock.post.mockResolvedValue(res({ ...configs[0], id: "f6" }));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");

    await userEvent.selectOptions(
      within(dialog).getByLabelText("Provider *"),
      "generic_oauth2",
    );
    await userEvent.type(within(dialog).getByLabelText("Display name *"), "Partner");
    await userEvent.type(within(dialog).getByLabelText("Client ID *"), "partner-id");
    await userEvent.type(within(dialog).getByLabelText(/Client Secret/), "partner-secret");
    // `fireEvent.change` rather than `type`: these are long URLs, and a
    // per-keystroke type of three of them is slow enough to matter under
    // coverage instrumentation. One change event is what a paste looks like.
    fireEvent.change(within(dialog).getByLabelText("Authorization endpoint *"), {
      target: { value: "https://partner.example/authorize" },
    });
    fireEvent.change(within(dialog).getByLabelText("Token endpoint *"), {
      target: { value: "https://partner.example/token" },
    });
    fireEvent.change(within(dialog).getByLabelText("Userinfo endpoint *"), {
      target: { value: "https://partner.example/userinfo" },
    });
    await userEvent.type(within(dialog).getByLabelText("Scopes"), "profile email");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/federation-configs",
        expect.objectContaining({
          protocol: "OAuth2",
          authorization_endpoint: "https://partner.example/authorize",
          token_endpoint: "https://partner.example/token",
          userinfo_endpoint: "https://partner.example/userinfo",
          scopes: ["profile", "email"],
        }),
      ),
    );
  });

  it("lets Facebook change protocol, which is the only kind that offers two", async () => {
    mockFederationGets({ configs });
    apiMock.post.mockResolvedValue(res({ ...configs[0], id: "f7" }));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");

    await userEvent.selectOptions(
      within(dialog).getByLabelText("Provider *"),
      "generic_oidc",
    );
    expect(within(dialog).getByLabelText("Federation protocol")).toBeDisabled();

    await userEvent.selectOptions(
      within(dialog).getByLabelText("Provider *"),
      "facebook",
    );
    const protocol = within(dialog).getByLabelText("Federation protocol");
    expect(protocol).toBeEnabled();
    await userEvent.selectOptions(protocol, "OidcConnect");

    await userEvent.type(within(dialog).getByLabelText("Display name *"), "Facebook");
    await userEvent.type(within(dialog).getByLabelText("Client ID *"), "fb-app-id");
    await userEvent.type(within(dialog).getByLabelText(/Client Secret/), "fb-secret");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/federation-configs",
        expect.objectContaining({ provider_kind: "facebook", protocol: "OidcConnect" }),
      ),
    );
  });

  it("sends the slug a generic provider is overridden by", async () => {
    // The slug is what a tenant override matches on, so it is the one field a
    // generic kind cannot be identified without when there are two of them.
    mockFederationGets({ configs });
    apiMock.post.mockResolvedValue(res({ ...configs[0], id: "f8" }));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");

    await userEvent.type(within(dialog).getByLabelText("Display name *"), "Okta EU");
    await userEvent.type(within(dialog).getByLabelText("Identifier"), "okta-eu");
    await userEvent.type(within(dialog).getByLabelText("Client ID *"), "okta-eu-client");
    await userEvent.type(within(dialog).getByLabelText(/Client Secret/), "eu-secret");
    fireEvent.change(within(dialog).getByLabelText(/Discovery URL/), {
      target: {
        value: "https://eu.okta.example/.well-known/openid-configuration",
      },
    });
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/federation-configs",
        expect.objectContaining({
          provider_slug: "okta-eu",
          metadata_url:
            "https://eu.okta.example/.well-known/openid-configuration",
        }),
      ),
    );
  });

  it("asks for accepted tenants only once the discovery URL is a templated authority", async () => {
    // Entra's `common` authority publishes a templated issuer, so *any*
    // Microsoft tenant could otherwise sign in. The field appears in response
    // to the URL rather than always, so it is never filled in for no reason.
    mockFederationGets({ configs });
    apiMock.post.mockResolvedValue(res({ ...configs[0], id: "f9" }));
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    const dialog = screen.getByRole("dialog");

    await userEvent.selectOptions(
      within(dialog).getByLabelText("Provider *"),
      "microsoft",
    );
    expect(
      within(dialog).queryByLabelText("Accepted provider tenants *"),
    ).not.toBeInTheDocument();

    fireEvent.change(within(dialog).getByLabelText(/Discovery URL/), {
      target: {
        value:
          "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
      },
    });
    await userEvent.type(
      await within(dialog).findByLabelText("Accepted provider tenants *"),
      "72f988bf-86f1-41af-91ab-2d7cd011db47",
    );

    await userEvent.type(within(dialog).getByLabelText("Display name *"), "Entra");
    await userEvent.type(within(dialog).getByLabelText("Client ID *"), "entra-client");
    await userEvent.type(within(dialog).getByLabelText(/Client Secret/), "entra-secret");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/federation-configs",
        expect.objectContaining({
          allowed_issuer_tenants: ["72f988bf-86f1-41af-91ab-2d7cd011db47"],
        }),
      ),
    );
  });
});

describe("FederationPage — inherited providers", () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: {
        id: "u1",
        username: "admin",
        email: "admin@example.com",
        permissions: [],
        tenant_id: "t1",
        orgSlug: "acme",
        tenantSlug: "eng",
      },
      isAuthenticated: true,
      isInitializing: false,
    });
  });

  afterEach(() => {
    useAuthStore.setState({ user: null, isAuthenticated: false });
  });

  it("lists what the tenant inherits separately from what it owns", async () => {
    // A tenant admin whose login page shows a Google button but whose table is
    // empty has no way to tell whether that is a bug. This section is the
    // explanation.
    mockFederationGets({ configs: [], providers: [inheritedGoogle] });
    renderWithProviders(<FederationPage />);

    expect(
      await screen.findByRole("heading", { name: /Inherited from the organization/ }),
    ).toBeInTheDocument();
    const inherited = screen.getByRole("listitem");
    expect(within(inherited).getByText("Google")).toBeInTheDocument();
    expect(within(inherited).getByText("Inherited")).toBeInTheDocument();
    // The table's empty message changes to say the distinction out loud.
    expect(
      screen.getByText("No federation configs of this tenant's own."),
    ).toBeInTheDocument();
  });

  it("omits the section when every effective provider is the tenant's own", async () => {
    mockFederationGets({
      configs: [],
      providers: [{ ...inheritedGoogle, inherited: false }],
    });
    renderWithProviders(<FederationPage />);

    expect(
      await screen.findByText("No federation configs defined."),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: /Inherited from the organization/ }),
    ).not.toBeInTheDocument();
  });

  it("seeds the create form from the provider being overridden", async () => {
    mockFederationGets({ configs: [], providers: [inheritedGoogle] });
    renderWithProviders(<FederationPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: "Override in this tenant" }),
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Display name *")).toHaveValue("Google");
    expect(within(dialog).getByLabelText("Provider *")).toHaveValue("google");
    // Google's discovery URL is prefilled from the kind's defaults, so the
    // override does not have to be looked up.
    expect(within(dialog).getByLabelText(/Discovery URL/)).toHaveValue(
      "https://accounts.google.com/.well-known/openid-configuration",
    );
  });

  it("carries the slug across when overriding a generic inherited provider", async () => {
    // The override matches on the slug, so a generic kind's must be the same
    // one — derived from the display name exactly as the organization's was.
    mockFederationGets({
      configs: [],
      providers: [
        {
          ...inheritedGoogle,
          id: "p2",
          provider_kind: "generic_oidc",
          display_name: "Partner IdP",
          has_bundled_mark: false,
        },
      ],
    });
    renderWithProviders(<FederationPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: "Override in this tenant" }),
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Identifier")).toHaveValue("partner-idp");
  });

  it("keeps the table when the effective-providers endpoint fails", async () => {
    // Deliberately quiet: this list is supplementary, and a fault in it must
    // not take the CRUD table with it.
    apiMock.get.mockImplementation((url: string) => {
      if (url === "/api/v1/auth/federation/providers") {
        return Promise.reject(new Error("Service unavailable"));
      }
      return res(configs);
    });
    renderWithProviders(<FederationPage />);

    expect(await screen.findByText("Okta")).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: /Inherited from the organization/ }),
    ).not.toBeInTheDocument();
  });
});

describe("FederationPage — edit refusals and dialog dismissal", () => {
  it("requires a client id when editing", async () => {
    mockFederationGets({ configs });
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Okta" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.clear(within(dialog).getByLabelText("Client ID *"));
    fireEvent.submit(
      within(dialog).getByRole("button", { name: "Save Changes" }).closest("form")!,
    );

    expect(await screen.findByText("Client ID is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("refuses an unparseable scope map rather than sending a partial one", async () => {
    // X4: the trust block is replaced wholesale by the server, so a half-parsed
    // scope map submitted by accident silently changes what a partner is
    // granted. Nothing goes out until every line parses.
    mockFederationGets({ configs });
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Okta" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(
      within(dialog).getByLabelText("Scope map"),
      "this is not a mapping",
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));

    expect(await screen.findByText(/Line 1/)).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("refuses to enable token exchange with no accepted audience", async () => {
    // There is deliberately no accept-all audience: a token that was not
    // addressed to you is one you captured, not one you were given.
    mockFederationGets({ configs });
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Okta" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(
      within(dialog).getByLabelText("Accept this provider's tokens for exchange"),
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));

    expect(
      await screen.findByText(/At least one accepted audience is required/),
    ).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("discards a half-filled create form when the dialog is dismissed", async () => {
    mockFederationGets({ configs });
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Config/ }));
    await userEvent.type(
      within(screen.getByRole("dialog")).getByLabelText("Display name *"),
      "Half typed",
    );
    await userEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }),
    );

    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    await userEvent.click(screen.getByRole("button", { name: /New Config/ }));
    expect(
      within(screen.getByRole("dialog")).getByLabelText("Display name *"),
    ).toHaveValue("");
  });

  it("closes the edit dialog without saving when dismissed", async () => {
    mockFederationGets({ configs });
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Okta" }));
    await userEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }),
    );

    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("closes the delete confirmation without deleting when dismissed", async () => {
    mockFederationGets({ configs });
    renderWithProviders(<FederationPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete ADFS" }));
    await userEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }),
    );

    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(apiMock.delete).not.toHaveBeenCalled();
  });
});
