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

/**
 * X5.1 — the posture block an untouched Security Posture section sends.
 *
 * Spread into every create/update assertion below rather than repeated: these
 * are the backend's own `#[serde(default)]` values, so a form the operator
 * never scrolled to still registers the pre-X5.1 client shape, and asserting
 * that explicitly is the point.
 */
const DEFAULT_POSTURE = {
  profile: "standard",
  token_endpoint_auth_method: "client_secret_post",
  tls_client_auth_subject_dn: "",
  tls_client_auth_san_dns: "",
  tls_client_auth_san_uri: "",
  tls_client_certificate_bound_access_tokens: false,
  jwks: "",
  jwks_uri: "",
  dpop_bound_access_tokens: false,
  require_par: false,
  self_signed_tls_client_auth_thumbprints: [],
};

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
        post_logout_redirect_uris: [],
        backchannel_logout_uri: undefined,
        ...DEFAULT_POSTURE,
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
        post_logout_redirect_uris: [],
        backchannel_logout_uri: undefined,
        ...DEFAULT_POSTURE,
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
        post_logout_redirect_uris: [],
        backchannel_logout_uri: "",
        ...DEFAULT_POSTURE,
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

  it("sends post_logout_redirect_uris and backchannel_logout_uri when creating (B5)", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    apiMock.post.mockResolvedValue(
      res({
        id: "c5",
        client_id: "client-logout",
        client_secret: "s3cr3t",
        name: "Logout App",
        redirect_uris: ["https://x/cb"],
        grant_types: ["authorization_code"],
        scopes: [],
        created_at: "t",
      })
    );
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Client/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Logout App");
    fireEvent.change(within(dialog).getByLabelText("Redirect URIs (one per line)"), {
      target: { value: "https://x/cb" },
    });
    fireEvent.change(
      within(dialog).getByLabelText("Post-Logout Redirect URIs (one per line)"),
      { target: { value: "https://x/logged-out" } }
    );
    await userEvent.type(
      within(dialog).getByLabelText("Back-Channel Logout URI"),
      "https://x/backchannel-logout"
    );
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "openid" }));
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "profile" }));
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/oauth2-clients", {
        name: "Logout App",
        redirect_uris: ["https://x/cb"],
        grant_types: ["authorization_code"],
        scopes: undefined,
        post_logout_redirect_uris: ["https://x/logged-out"],
        backchannel_logout_uri: "https://x/backchannel-logout",
        ...DEFAULT_POSTURE,
      })
    );
  });

  // ─── X5.1 security posture ─────────────────────────────────────────────────

  it("badges a client's registered posture in the list", async () => {
    apiMock.get.mockResolvedValue(
      res([
        {
          ...clients[0],
          profile: "fapi2",
          token_endpoint_auth_method: "private_key_jwt",
          dpop_bound_access_tokens: true,
          require_par: true,
        },
        clients[1],
      ])
    );
    renderWithProviders(<OAuth2ClientsPage />);

    expect(await screen.findByText("FAPI 2.0")).toBeInTheDocument();
    expect(screen.getByText("Private Key JWT")).toBeInTheDocument();
    expect(screen.getByText("DPoP")).toBeInTheDocument();
    expect(screen.getByText("PAR")).toBeInTheDocument();
    // A client with no hardening reads as plain "Standard" rather than a row
    // of badges nobody needs to scan.
    expect(screen.getByText("Standard")).toBeInTheDocument();
  });

  it("reveals the mTLS binding fields only for an mTLS auth method", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Client/ }));
    const dialog = screen.getByRole("dialog");

    expect(within(dialog).queryByLabelText("Subject DN")).not.toBeInTheDocument();

    await userEvent.selectOptions(
      within(dialog).getByLabelText("Token Endpoint Authentication"),
      "tls_client_auth"
    );
    expect(within(dialog).getByLabelText("Subject DN")).toBeInTheDocument();
    expect(within(dialog).getByLabelText("SAN dNSName")).toBeInTheDocument();

    await userEvent.selectOptions(
      within(dialog).getByLabelText("Token Endpoint Authentication"),
      "private_key_jwt"
    );
    expect(within(dialog).queryByLabelText("Subject DN")).not.toBeInTheDocument();
    expect(within(dialog).getByLabelText("JWKS URI")).toBeInTheDocument();
  });

  it("names the unmet FAPI 2.0 constraint instead of posting a doomed registration", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Client/ }));
    const dialog = screen.getByRole("dialog");

    await userEvent.type(within(dialog).getByLabelText("Name *"), "FAPI App");
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Client Profile"),
      "fapi2"
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    expect(await screen.findByText(/must require pushed authorization requests/))
      .toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("registers a complete fapi2 client", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    apiMock.post.mockResolvedValue(
      res({ ...clients[0], client_id: "c-fapi", client_secret: "s" })
    );
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Client/ }));
    const dialog = screen.getByRole("dialog");

    await userEvent.type(within(dialog).getByLabelText("Name *"), "FAPI App");
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Client Profile"),
      "fapi2"
    );
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Token Endpoint Authentication"),
      "private_key_jwt"
    );
    await userEvent.type(
      within(dialog).getByLabelText("JWKS URI"),
      "https://client.example.com/jwks.json"
    );
    await userEvent.click(
      within(dialog).getByLabelText(/DPoP-bound access tokens/)
    );
    await userEvent.click(
      within(dialog).getByLabelText(/Require pushed authorization requests/)
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() => expect(apiMock.post).toHaveBeenCalled());
    const body = apiMock.post.mock.calls[0][1] as Record<string, unknown>;
    expect(body).toMatchObject({
      profile: "fapi2",
      token_endpoint_auth_method: "private_key_jwt",
      jwks_uri: "https://client.example.com/jwks.json",
      dpop_bound_access_tokens: true,
      require_par: true,
    });
    // SEC-097: the backend refuses `true` and reads nothing, so the UI must
    // not send the key at all.
    expect(body).not.toHaveProperty("dpop_require_nonce");
  });

  it("offers uma_protection so a UMA resource server can be onboarded", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Client/ }));
    const dialog = screen.getByRole("dialog");
    expect(
      within(dialog).getByRole("checkbox", { name: "uma_protection" })
    ).toBeInTheDocument();
  });

  it("pre-fills the posture when editing a hardened client", async () => {
    apiMock.get.mockResolvedValue(
      res([
        {
          ...clients[0],
          profile: "fapi2",
          token_endpoint_auth_method: "self_signed_tls_client_auth",
          self_signed_tls_client_auth_thumbprints: ["a".repeat(43)],
          tls_client_certificate_bound_access_tokens: true,
          require_par: true,
        },
      ])
    );
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: /Edit OAuth2 client Web App/ })
    );
    const dialog = screen.getByRole("dialog");

    expect(within(dialog).getByLabelText("Client Profile")).toHaveValue("fapi2");
    expect(
      within(dialog).getByLabelText("Token Endpoint Authentication")
    ).toHaveValue("self_signed_tls_client_auth");
    expect(
      within(dialog).getByLabelText("Certificate Thumbprints")
    ).toHaveValue("a".repeat(43));
    expect(
      within(dialog).getByLabelText(/Certificate-bound access tokens/)
    ).toBeChecked();
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
