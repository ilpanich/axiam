import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { OAuth2ClientsPage } from "./OAuth2ClientsPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import type { SecuritySettings } from "@/services/settings";

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
  it("lists from the registered route, not an /oauth2 sub-path", async () => {
    // The regression this page shipped with: it asked for an "oauth2/clients"
    // sub-path, which is not a route — the "/oauth2/…" prefix belongs to the
    // protocol endpoints and is not under /api/v1 at all. Every load answered
    // 404, and because the empty state is what an empty result looks like, the
    // page read as "this tenant has no OAuth2 clients" rather than as an error.
    //
    // Every other test here mocks `api.get` to resolve for ANY url, which is
    // correct for a component test and precisely why none of them could notice.
    // This one asserts the url itself; `src/test/apiRoutes.test.ts` checks the
    // same property for the whole app against the server's OpenAPI document.
    apiMock.get.mockResolvedValue(res(clients));
    renderWithProviders(<OAuth2ClientsPage />);
    await screen.findByText("Web App");

    expect(apiMock.get).toHaveBeenCalledWith(
      "/api/v1/oauth2-clients",
      expect.anything()
    );
  });

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

  // ─── T21.2 — public clients (token_endpoint_auth_method: none) ────────────

  it("I1/I4 — defaults the auth method to client_secret_post, never to none", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Client/ }));
    const dialog = screen.getByRole("dialog");
    expect(
      within(dialog).getByLabelText("Token Endpoint Authentication")
    ).toHaveValue("client_secret_post");
  });

  it("offers Public client (no secret) as an auth method option", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Client/ }));
    const dialog = screen.getByRole("dialog");
    const select = within(dialog).getByLabelText(
      "Token Endpoint Authentication"
    ) as HTMLSelectElement;
    expect(
      within(select).getByRole("option", { name: "Public client (no secret)" })
    ).toBeInTheDocument();
  });

  it("registers a public client with no secret and skips the secret-reveal modal", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    apiMock.post.mockResolvedValue(
      // T21.2 — the response the server actually sends for a public client:
      // client_secret is omitted entirely, not "".
      res({
        id: "c-pub",
        client_id: "client-public-1",
        name: "Public App",
        redirect_uris: ["http://127.0.0.1/callback"],
        grant_types: ["authorization_code", "refresh_token"],
        scopes: ["openid"],
        created_at: "t",
      })
    );
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Client/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Public App");
    fireEvent.change(within(dialog).getByLabelText("Redirect URIs (one per line)"), {
      target: { value: "http://127.0.0.1/callback" },
    });
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "refresh_token" }));
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Token Endpoint Authentication"),
      "none"
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/oauth2-clients",
        expect.objectContaining({ token_endpoint_auth_method: "none" })
      )
    );
    // No secret was returned, so there is nothing to acknowledge.
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("refuses a public client registered for client_credentials", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New Client/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Public CC");
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Token Endpoint Authentication"),
      "none"
    );
    await userEvent.click(
      within(dialog).getByRole("checkbox", { name: "client_credentials" })
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));

    expect(
      await screen.findByText(/may not be registered for the client_credentials grant/)
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("I4 — refuses moving a confidential client to public by editing it", async () => {
    apiMock.get.mockResolvedValue(res(clients));
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit OAuth2 client Web App" })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Token Endpoint Authentication"),
      "none"
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));

    expect(
      await screen.findByText(/token_endpoint_auth_method cannot be changed/)
    ).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("I4 — refuses moving a public client to confidential by editing it", async () => {
    apiMock.get.mockResolvedValue(
      res([
        {
          ...clients[0],
          id: "c-pub",
          name: "Public App",
          token_endpoint_auth_method: "none",
        },
      ])
    );
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit OAuth2 client Public App" })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Token Endpoint Authentication"),
      "client_secret_post"
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));

    expect(
      await screen.findByText(/token_endpoint_auth_method cannot be changed/)
    ).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
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

// ─── T21.4 / T21.4b — dynamic client registration admin surfaces ───────────

const BASE_SETTINGS: SecuritySettings = {
  id: "s1",
  scope: "Tenant",
  scope_id: "t1",
  password: {
    min_length: 12,
    require_uppercase: true,
    require_lowercase: true,
    require_digits: true,
    require_symbols: false,
    password_history_count: 5,
    hibp_check_enabled: true,
  },
  mfa: { mfa_enforced: false, mfa_challenge_lifetime_secs: 300 },
  lockout: {
    max_failed_login_attempts: 5,
    lockout_duration_secs: 900,
    lockout_backoff_multiplier: 2,
    max_lockout_duration_secs: 3600,
  },
  token: {
    access_token_lifetime_secs: 900,
    refresh_token_lifetime_secs: 1_209_600,
  },
  email: {
    email_verification_required: true,
    email_verification_grace_period_hours: 24,
  },
  certificate: { default_cert_validity_days: 365, max_cert_validity_days: 3650 },
  notification: { admin_notifications_enabled: true },
  opaque: {
    opaque_mode: "optional",
    opaque_suite: "ristretto255_sha512",
    opaque_ksf: "argon2id",
  },
  oidc: {
    dynamic_registration: "disabled",
    dcr_allowed_scopes: [],
    dcr_allowed_redirect_hosts: [],
    external_client_allowed_resources: [],
    dcr_max_clients: 20,
    dcr_unused_client_ttl_days: 30,
  },
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

const dcrClients = [
  clients[0],
  {
    ...clients[1],
    id: "c-dcr",
    name: "Self-Registered App",
    managed_by: "dcr" as const,
    last_authorized_at: "2026-02-01T00:00:00Z",
  },
];

/** Routes GET by url so a settings-shaped response doesn't collide with the client list. */
function mockGetByUrl(opts: {
  clients?: unknown;
  settings?: SecuritySettings;
  tokens?: unknown[];
}) {
  apiMock.get.mockImplementation((url: string) => {
    if (url === "/api/v1/settings") {
      return Promise.resolve(res(opts.settings ?? BASE_SETTINGS));
    }
    if (url === "/api/v1/oauth2-clients/registration-tokens") {
      return Promise.resolve(res(opts.tokens ?? []));
    }
    return Promise.resolve(res(opts.clients ?? clients));
  });
}

describe("OAuth2ClientsPage — T21.4 managed_by badge and filter", () => {
  it("badges a dcr client and leaves an admin client unbadged", async () => {
    mockGetByUrl({ clients: dcrClients });
    renderWithProviders(<OAuth2ClientsPage />);
    expect(await screen.findByText("Self-Registered App")).toBeInTheDocument();
    const table = screen.getByRole("table");
    expect(within(table).getByText("Self-registered (DCR)")).toBeInTheDocument();
    expect(within(table).getAllByText("Admin").length).toBeGreaterThan(0);
  });

  it("filters the fetched page down to the selected managed_by value", async () => {
    mockGetByUrl({ clients: dcrClients });
    renderWithProviders(<OAuth2ClientsPage />);
    await screen.findByText("Self-Registered App");
    expect(screen.getByText("Web App")).toBeInTheDocument();

    await userEvent.selectOptions(
      screen.getByLabelText("Filter by managed by"),
      "dcr"
    );
    expect(screen.getByText("Self-Registered App")).toBeInTheDocument();
    expect(screen.queryByText("Web App")).not.toBeInTheDocument();
  });
});

describe("OAuth2ClientsPage — T21.4 / D5 read-only dcr client detail", () => {
  it("opens a read-only detail view instead of the edit form for a dcr client", async () => {
    mockGetByUrl({ clients: dcrClients });
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "View OAuth2 client Self-Registered App" })
    );
    const dialog = screen.getByRole("dialog");
    // Read-only: no editable "Name *" field, and no Save Changes button — the
    // server does not model an administrator editing a self-registration.
    expect(within(dialog).queryByLabelText("Name *")).not.toBeInTheDocument();
    expect(
      within(dialog).queryByRole("button", { name: "Save Changes" })
    ).not.toBeInTheDocument();
    expect(within(dialog).getByText(/does not model an administrator editing/))
      .toBeInTheDocument();

    await userEvent.click(within(dialog).getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("still opens the editable form for an admin client", async () => {
    mockGetByUrl({ clients: dcrClients });
    renderWithProviders(<OAuth2ClientsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit OAuth2 client Web App" })
    );
    expect(screen.getByLabelText("Name *")).toBeInTheDocument();
  });
});

describe("OAuth2ClientsPage — T21.4 registration-token issuance", () => {
  // I1 — mandatory: the mint endpoint refuses outside initial_access_token
  // mode, so the panel that fills it out must not render for the default
  // (disabled) policy — nor, since the mode gate is the same either way, for
  // anonymous.
  it("I1 — hides the registration-token panel when dynamic_registration is disabled", async () => {
    mockGetByUrl({ settings: BASE_SETTINGS });
    renderWithProviders(<OAuth2ClientsPage />);
    await screen.findByText("Web App");
    expect(screen.queryByText("Dynamic Registration Tokens")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Issue Registration Token/ })
    ).not.toBeInTheDocument();
  });

  it("I1 — hides the registration-token panel under anonymous mode too", async () => {
    mockGetByUrl({
      settings: {
        ...BASE_SETTINGS,
        oidc: {
          ...BASE_SETTINGS.oidc!,
          dynamic_registration: "anonymous",
          external_client_allowed_resources: ["https://mcp.example.com/mcp"],
        },
      },
    });
    renderWithProviders(<OAuth2ClientsPage />);
    await screen.findByText("Web App");
    expect(screen.queryByText("Dynamic Registration Tokens")).not.toBeInTheDocument();
  });

  it("shows the panel under initial_access_token mode and issues a token, revealed once", async () => {
    mockGetByUrl({
      settings: {
        ...BASE_SETTINGS,
        oidc: { ...BASE_SETTINGS.oidc!, dynamic_registration: "initial_access_token" },
      },
      tokens: [],
    });
    apiMock.post.mockResolvedValue(
      res({
        token: {
          id: "tok1",
          tenant_id: "t1",
          name: "mcp-demo",
          created_by: "u1",
          expires_at: "2026-02-01T00:00:00Z",
          used_at: null,
          created_at: "2026-01-01T00:00:00Z",
        },
        initial_access_token: "axiam_dcr_secretvalue",
      })
    );
    renderWithProviders(<OAuth2ClientsPage />);
    await screen.findByText("Dynamic Registration Tokens");

    await userEvent.click(
      screen.getByRole("button", { name: /Issue Registration Token/ })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "mcp-demo");
    await userEvent.click(within(dialog).getByRole("button", { name: "Issue" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/oauth2-clients/registration-tokens",
        { name: "mcp-demo", expires_in_hours: 24 }
      )
    );

    const secret = await screen.findByRole("alertdialog");
    expect(within(secret).getByText("axiam_dcr_secretvalue")).toBeInTheDocument();
    await userEvent.click(
      within(secret).getByRole("button", { name: "I've saved this information" })
    );
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("requires a name before issuing a token", async () => {
    mockGetByUrl({
      settings: {
        ...BASE_SETTINGS,
        oidc: { ...BASE_SETTINGS.oidc!, dynamic_registration: "initial_access_token" },
      },
      tokens: [],
    });
    renderWithProviders(<OAuth2ClientsPage />);
    await screen.findByText("Dynamic Registration Tokens");
    await userEvent.click(
      screen.getByRole("button", { name: /Issue Registration Token/ })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Issue" }));
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });
});
