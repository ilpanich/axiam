import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, fireEvent, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { SettingsPage } from "./SettingsPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import type { SecuritySettings } from "@/services/settings";

const settings: SecuritySettings = {
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
  mfa: {
    mfa_enforced: false,
    mfa_challenge_lifetime_secs: 300, // 5 min
  },
  lockout: {
    max_failed_login_attempts: 5,
    lockout_duration_secs: 900, // 15 min
    lockout_backoff_multiplier: 2,
    max_lockout_duration_secs: 3600,
  },
  token: {
    access_token_lifetime_secs: 900, // 15 min
    refresh_token_lifetime_secs: 1_209_600, // 14 days
  },
  email: {
    email_verification_required: true,
    email_verification_grace_period_hours: 24,
  },
  certificate: {
    default_cert_validity_days: 365,
    max_cert_validity_days: 3650,
  },
  notification: {
    admin_notifications_enabled: true,
  },
  opaque: {
    opaque_mode: "optional",
    opaque_suite: "ristretto255_sha512",
    opaque_ksf: "argon2id",
  },
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("SettingsPage", () => {
  it("shows a loading spinner before settings resolve", () => {
    apiMock.get.mockReturnValue(new Promise(() => {}));
    renderWithProviders(<SettingsPage />);
    expect(screen.queryByText("Settings")).not.toBeInTheDocument();
  });

  it("shows an error message when settings fail to load", async () => {
    apiMock.get.mockRejectedValue(new Error("boom"));
    renderWithProviders(<SettingsPage />);
    expect(
      await screen.findByText("Failed to load system settings. Please refresh the page.")
    ).toBeInTheDocument();
  });

  it("renders converted view-mode values for all four sections", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);

    expect(await screen.findByText("12 characters")).toBeInTheDocument();
    expect(screen.getByText("5 passwords")).toBeInTheDocument();
    expect(screen.getByText("5 attempts")).toBeInTheDocument();
    // access_token_lifetime_min (15) and lockout_duration_min (15) both render
    // as "15 minutes" — assert there are exactly two matches for that pair.
    expect(screen.getAllByText("15 minutes")).toHaveLength(2);
    expect(screen.getByText("14 days")).toBeInTheDocument();
    expect(screen.getByText("5 minutes")).toBeInTheDocument(); // mfa challenge lifetime
    expect(screen.getByText("365 days")).toBeInTheDocument();

    // Boolean badges
    expect(screen.getAllByText("Enabled").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Disabled").length).toBeGreaterThan(0);
  });

  it("enters edit mode with inputs pre-filled from the loaded settings", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));

    expect(screen.getByLabelText("Password minimum length")).toHaveValue(12);
    expect(screen.getByLabelText("Password history count")).toHaveValue(5);
    expect(screen.getByLabelText("Max failed login attempts")).toHaveValue(5);
    expect(screen.getByLabelText("Account lockout duration (minutes)")).toHaveValue(15);
    expect(screen.getByLabelText("Access token lifetime (minutes)")).toHaveValue(15);
    expect(screen.getByLabelText("Refresh token lifetime (days)")).toHaveValue(14);
    expect(screen.getByLabelText("MFA challenge lifetime (minutes)")).toHaveValue(5);
    expect(screen.getByLabelText("Default certificate validity (days)")).toHaveValue(365);

    expect(screen.getByLabelText("Require uppercase letter")).toBeChecked();
    expect(screen.getByLabelText("Require symbol")).not.toBeChecked();
    // These toggles wrap a description inside the <label>, so the accessible
    // name includes that extra copy — match on a substring.
    expect(
      screen.getByLabelText("Require MFA for all users", { exact: false })
    ).not.toBeChecked();
    expect(
      screen.getByLabelText("Require email verification", { exact: false })
    ).toBeChecked();
    expect(
      screen.getByLabelText("Admin notifications", { exact: false })
    ).toBeChecked();

    // Edit Settings action button is hidden while editing.
    expect(screen.queryByRole("button", { name: /Edit Settings/ })).not.toBeInTheDocument();
  });

  it("toggles checkboxes and edits numeric fields, then saves the full converted override", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    apiMock.put.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));

    // Flip several booleans.
    await userEvent.click(screen.getByLabelText("Require symbol"));
    // These toggles include a description inside the <label>; match a substring.
    await userEvent.click(
      screen.getByLabelText("Require MFA for all users", { exact: false })
    );
    await userEvent.click(
      screen.getByLabelText("Check passwords against breach database (HIBP)", {
        exact: false,
      })
    );

    // Edit a numeric field.
    const minLength = screen.getByLabelText("Password minimum length");
    await userEvent.clear(minLength);
    await userEvent.type(minLength, "16");

    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));

    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    const [, body] = apiMock.put.mock.calls[0];
    expect(body).toMatchObject({
      min_length: 16,
      require_uppercase: true,
      require_lowercase: true,
      require_digits: true,
      require_symbols: true,
      password_history_count: 5,
      hibp_check_enabled: false,
      mfa_enforced: true,
      mfa_challenge_lifetime_secs: 300,
      max_failed_login_attempts: 5,
      lockout_duration_secs: 900,
      access_token_lifetime_secs: 900,
      refresh_token_lifetime_secs: 1_209_600,
      email_verification_required: true,
      default_cert_validity_days: 365,
      admin_notifications_enabled: true,
    });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/settings", body);
  });

  it("renders the effective OPAQUE policy in view mode", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    expect(await screen.findByText("Optional")).toBeInTheDocument();
    expect(
      screen.getByText("ristretto255 / SHA-512 (RFC 9807 recommended)")
    ).toBeInTheDocument();
    expect(screen.getByText("Argon2id (stronger)")).toBeInTheDocument();
  });

  it("sends the OPAQUE policy as part of the tenant override", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    apiMock.put.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    await userEvent.selectOptions(screen.getByLabelText("Mode"), "required");
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));

    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    const [, body] = apiMock.put.mock.calls[0];
    expect(body).toMatchObject({
      opaque_mode: "required",
      opaque_suite: "ristretto255_sha512",
      opaque_ksf: "argon2id",
    });
  });

  // A tenant may only tighten. This page sees just the merged result, so the
  // advisory is a warning rather than a block — relaxing a tenant override back
  // towards a lower org baseline is legal, and the server has the last word.
  it("warns when a selection relaxes the effective policy, without blocking it", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    apiMock.put.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    await userEvent.selectOptions(screen.getByLabelText("Mode"), "disabled");

    expect(
      await screen.findByText(/relaxes the tenant's current effective OPAQUE policy/)
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save Settings" })).toBeEnabled();
  });

  it("surfaces the server's tighten-only rejection verbatim", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    apiMock.put.mockRejectedValue({
      message: "Request failed with status code 400",
      response: {
        status: 400,
        data: {
          error: "validation_error",
          message:
            "Tenant override violates org baseline: opaque_mode: tenant value disabled is less restrictive than org baseline optional",
        },
      },
    });
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    await userEvent.selectOptions(screen.getByLabelText("Mode"), "disabled");
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));

    expect(
      await screen.findByText(/is less restrictive than org baseline optional/)
    ).toBeInTheDocument();
  });

  it("shows a success message and returns to view mode after a successful save", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    apiMock.put.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));

    expect(await screen.findByText("Settings saved successfully.")).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /Edit Settings/ })).toBeInTheDocument()
    );
  });

  it("shows the Error instance message when saving fails", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    apiMock.put.mockRejectedValue(new Error("Value too permissive."));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));

    expect(await screen.findByText("Value too permissive.")).toBeInTheDocument();
    // Stays in edit mode on failure.
    expect(screen.getByRole("button", { name: "Save Settings" })).toBeInTheDocument();
  });

  it("falls back to a generic error message when the rejection is not an Error", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    apiMock.put.mockRejectedValue("network fell over");
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));

    expect(
      await screen.findByText("Failed to save settings. Please try again.")
    ).toBeInTheDocument();
  });

  it("discards edits and returns to view mode on Cancel", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));

    const minLength = screen.getByLabelText("Password minimum length");
    await userEvent.clear(minLength);
    await userEvent.type(minLength, "99");

    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(screen.queryByLabelText("Password minimum length")).not.toBeInTheDocument();
    expect(screen.getByText("12 characters")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("edits every field in every section and saves the full converted override", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    apiMock.put.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));

    const numbers: [string, string][] = [
      ["Password minimum length", "14"],
      ["Password history count", "7"],
      ["Max failed login attempts", "9"],
      ["Account lockout duration (minutes)", "30"],
      ["Access token lifetime (minutes)", "20"],
      ["Refresh token lifetime (days)", "7"],
      ["MFA challenge lifetime (minutes)", "10"],
      ["Default certificate validity (days)", "180"],
    ];
    for (const [label, value] of numbers) {
      const input = screen.getByLabelText(label);
      fireEvent.change(input, { target: { value } });
    }

    const toggles = [
      "Require uppercase letter",
      "Require lowercase letter",
      "Require digit",
      "Require symbol",
    ];
    for (const label of toggles) {
      await userEvent.click(screen.getByLabelText(label));
    }
    // These toggles include a description in their accessible name.
    for (const label of [
      "Check passwords against breach database (HIBP)",
      "Require MFA for all users",
      "Require email verification",
      "Admin notifications",
    ]) {
      await userEvent.click(screen.getByLabelText(label, { exact: false }));
    }

    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    const [, body] = apiMock.put.mock.calls[0];
    expect(body).toMatchObject({
      min_length: 14,
      password_history_count: 7,
      max_failed_login_attempts: 9,
      lockout_duration_secs: 30 * 60,
      access_token_lifetime_secs: 20 * 60,
      refresh_token_lifetime_secs: 7 * 86_400,
      mfa_challenge_lifetime_secs: 10 * 60,
      default_cert_validity_days: 180,
      // Flipped from their loaded values.
      require_uppercase: false,
      require_symbols: true,
      hibp_check_enabled: false,
      mfa_enforced: true,
      email_verification_required: false,
      admin_notifications_enabled: false,
    });
  });

  it("clears a prior success feedback message when re-entering edit mode", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    apiMock.put.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));
    expect(await screen.findByText("Settings saved successfully.")).toBeInTheDocument();

    // Re-enter edit mode before the 4s auto-dismiss — handleEdit clears
    // feedback immediately rather than waiting for the timeout.
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    expect(screen.queryByText("Settings saved successfully.")).not.toBeInTheDocument();
  });
});

// ─── T21.4 — Dynamic Client Registration ───────────────────────────────────

describe("SettingsPage — T21.4 dynamic client registration", () => {
  // I1 — mandatory: with the default (disabled) policy, the read view shows
  // only that fact — no scope/host/audience detail, which would exist but be
  // meaningless while nothing can reach the endpoint.
  it("I1 — shows only 'Disabled' in view mode when dynamic_registration is at its default", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await screen.findByText("Dynamic Client Registration");

    const selfRegistrationLabel = screen.getByText("Self-registration");
    expect(
      within(selfRegistrationLabel.parentElement!).getByText("Disabled")
    ).toBeInTheDocument();
    expect(screen.queryByText(/Allowed scopes:/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Allowed audiences/)).not.toBeInTheDocument();
    expect(screen.queryByText("Max self-registered clients")).not.toBeInTheDocument();
  });

  it("renders the effective policy in view mode once a mode is set", async () => {
    apiMock.get.mockResolvedValue(
      res({
        ...settings,
        oidc: {
          dynamic_registration: "anonymous",
          dcr_allowed_scopes: ["openid", "profile"],
          dcr_allowed_redirect_hosts: ["*.example.com"],
          external_client_allowed_resources: ["https://mcp.example.com/mcp"],
          dcr_max_clients: 5,
          dcr_unused_client_ttl_days: 7,
        },
      })
    );
    renderWithProviders(<SettingsPage />);
    await screen.findByText("Dynamic Client Registration");

    expect(screen.getByText(/Anonymous/)).toBeInTheDocument();
    expect(screen.getByText("openid, profile")).toBeInTheDocument();
    expect(screen.getByText("*.example.com")).toBeInTheDocument();
    expect(screen.getByText("https://mcp.example.com/mcp")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
  });

  it("pre-fills the DCR edit fields from the loaded policy", async () => {
    apiMock.get.mockResolvedValue(
      res({
        ...settings,
        oidc: {
          dynamic_registration: "initial_access_token",
          dcr_allowed_scopes: ["openid"],
          dcr_allowed_redirect_hosts: [],
          external_client_allowed_resources: [],
          dcr_max_clients: 10,
          dcr_unused_client_ttl_days: 14,
        },
      })
    );
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));

    expect(screen.getByLabelText("Self-registration mode")).toHaveValue(
      "initial_access_token"
    );
    expect(screen.getByLabelText("Allowed scopes (one per line)")).toHaveValue(
      "openid"
    );
    expect(screen.getByLabelText("Max self-registered clients")).toHaveValue(10);
    expect(screen.getByLabelText("Unused-client sweep (days)")).toHaveValue(14);
  });

  it("D3 — refuses saving anonymous mode with an empty allowed-audiences list", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));

    await userEvent.selectOptions(
      screen.getByLabelText("Self-registration mode"),
      "anonymous"
    );
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));

    expect(
      await screen.findByText(/anonymous registration cannot be enabled while/)
    ).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("D3 — allows saving anonymous mode once an audience is named", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    apiMock.put.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));

    await userEvent.selectOptions(
      screen.getByLabelText("Self-registration mode"),
      "anonymous"
    );
    fireEvent.change(screen.getByLabelText("Allowed audiences (one per line)"), {
      target: { value: "https://mcp.example.com/mcp" },
    });
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));

    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    const [, body] = apiMock.put.mock.calls[0];
    expect(body).toMatchObject({
      dynamic_registration: "anonymous",
      external_client_allowed_resources: ["https://mcp.example.com/mcp"],
    });
  });

  it("amendment 1 — refuses saving dcr_allowed_scopes containing address or phone", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));

    fireEvent.change(screen.getByLabelText("Allowed scopes (one per line)"), {
      target: { value: "openid\naddress" },
    });
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));

    expect(
      await screen.findByText(/address releases personal data under W7's per-client/)
    ).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("sends the full DCR policy as part of the tenant override", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    apiMock.put.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));

    await userEvent.selectOptions(
      screen.getByLabelText("Self-registration mode"),
      "initial_access_token"
    );
    fireEvent.change(screen.getByLabelText("Allowed scopes (one per line)"), {
      target: { value: "openid\nprofile" },
    });
    fireEvent.change(
      screen.getByLabelText("Allowed redirect hosts (one per line)"),
      { target: { value: "*.example.com" } }
    );
    const maxClients = screen.getByLabelText("Max self-registered clients");
    await userEvent.clear(maxClients);
    await userEvent.type(maxClients, "3");

    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    const [, body] = apiMock.put.mock.calls[0];
    expect(body).toMatchObject({
      dynamic_registration: "initial_access_token",
      dcr_allowed_scopes: ["openid", "profile"],
      dcr_allowed_redirect_hosts: ["*.example.com"],
      dcr_max_clients: 3,
      dcr_unused_client_ttl_days: 30,
    });
  });
});

// ─── T21.5 — client ID metadata documents ──────────────────────────────────

/** A tenant that has a CIMD posture, and the audiences D3 requires for one. */
const cimdSettings = {
  ...settings,
  oidc: {
    dynamic_registration: "disabled",
    dcr_allowed_scopes: [],
    dcr_allowed_redirect_hosts: [],
    external_client_allowed_resources: ["https://mcp.example.com/mcp"],
    dcr_max_clients: 20,
    dcr_unused_client_ttl_days: 30,
    cimd: {
      enabled: true,
      allow_http: false,
      trusted_client_id_domains: ["mcp.example.com"],
      trusted_redirect_domains: [],
      restrict_same_domain: false,
      confidential_only: false,
      min_cache_secs: 600,
      max_cache_secs: 86_400,
      max_metadata_bytes: 4_000,
    },
  },
};

const ENABLE_CIMD =
  "Resolve a URL-shaped client_id by fetching the document it names";

describe("SettingsPage — T21.5 client ID metadata documents", () => {
  // I1 — mandatory, and the same rule DcrPolicySummary follows: on the default
  // posture the read view says only that it is off. An empty publisher list and
  // the shipped bounds are true but invite significance into a policy that does
  // nothing.
  it("I1 — shows only 'Disabled' in view mode on the default posture", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await screen.findByText("Client ID Metadata Documents");

    const label = screen.getByText("Client ID metadata documents");
    expect(within(label.parentElement!).getByText("Disabled")).toBeInTheDocument();
    expect(
      screen.queryByText(/Trusted publisher domains:/)
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Cache floor")).not.toBeInTheDocument();
    expect(screen.queryByText("Document read cap")).not.toBeInTheDocument();
  });

  it("renders the effective posture in view mode once it is enabled", async () => {
    apiMock.get.mockResolvedValue(res(cimdSettings));
    renderWithProviders(<SettingsPage />);
    await screen.findByText("Client ID Metadata Documents");

    expect(screen.getByText("mcp.example.com")).toBeInTheDocument();
    expect(screen.getByText("600 seconds")).toBeInTheDocument();
    expect(screen.getByText("4000 bytes")).toBeInTheDocument();
    expect(screen.getByText(/loopback always allowed/)).toBeInTheDocument();
  });

  it("pre-fills the CIMD edit fields from the loaded posture", async () => {
    apiMock.get.mockResolvedValue(res(cimdSettings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));

    expect(screen.getByLabelText(ENABLE_CIMD)).toBeChecked();
    expect(
      screen.getByLabelText("Trusted publisher domains (one per line)")
    ).toHaveValue("mcp.example.com");
    expect(screen.getByLabelText("Cache floor (seconds)")).toHaveValue(600);
    expect(screen.getByLabelText("Document read cap (bytes)")).toHaveValue(4000);
    expect(
      screen.getByLabelText(
        "Require a document's redirect hosts to match the client_id's host"
      )
    ).not.toBeChecked();
  });

  it("D3 — refuses enabling while the allowed-audiences list is empty", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    await userEvent.click(screen.getByLabelText(ENABLE_CIMD));

    expect(
      await screen.findByText(
        /cimd\.enabled: client ID metadata documents cannot be enabled while external_client_allowed_resources is empty \(D3\)/
      )
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save Settings" })).toBeDisabled();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("refuses enabling with no trusted publisher domain", async () => {
    apiMock.get.mockResolvedValue(
      res({
        ...cimdSettings,
        oidc: {
          ...cimdSettings.oidc,
          cimd: { ...cimdSettings.oidc.cimd, enabled: false },
        },
      })
    );
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    fireEvent.change(
      screen.getByLabelText("Trusted publisher domains (one per line)"),
      { target: { value: "" } }
    );
    await userEvent.click(screen.getByLabelText(ENABLE_CIMD));

    expect(
      await screen.findByText(
        /cannot be enabled with no trusted publisher domain/
      )
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save Settings" })).toBeDisabled();
  });

  // MCP-03 (#469). `*` is refused for the publishers and admitted for the
  // redirects, which is a distinction worth showing at the point of typing.
  it("refuses `*` as a trusted publisher domain, in the server's words", async () => {
    apiMock.get.mockResolvedValue(res(cimdSettings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    fireEvent.change(
      screen.getByLabelText("Trusted publisher domains (one per line)"),
      { target: { value: "*" } }
    );

    expect(
      await screen.findByText(
        /cimd\.trusted_client_id_domains: "\*" matches every host, which is the posture an empty list is refused for/
      )
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save Settings" })).toBeDisabled();
  });

  it("refuses a wildcard over a whole top-level domain", async () => {
    apiMock.get.mockResolvedValue(res(cimdSettings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    fireEvent.change(
      screen.getByLabelText("Trusted publisher domains (one per line)"),
      { target: { value: "*.com" } }
    );

    expect(
      await screen.findByText(
        /"\*\.com" is a wildcard over a whole top-level domain/
      )
    ).toBeInTheDocument();
  });

  it("admits `*` as a trusted redirect domain", async () => {
    apiMock.get.mockResolvedValue(res(cimdSettings));
    apiMock.put.mockResolvedValue(res(cimdSettings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    fireEvent.change(
      screen.getByLabelText("Trusted redirect domains (one per line)"),
      { target: { value: "*" } }
    );

    expect(screen.getByRole("button", { name: "Save Settings" })).toBeEnabled();
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
  });

  it("refuses a publisher entry that is a URL rather than a host pattern", async () => {
    apiMock.get.mockResolvedValue(res(cimdSettings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    fireEvent.change(
      screen.getByLabelText("Trusted publisher domains (one per line)"),
      { target: { value: "https://mcp.example.com" } }
    );

    expect(
      await screen.findByText(
        /"https:\/\/mcp\.example\.com" is not a host pattern/
      )
    ).toBeInTheDocument();
  });

  it("refuses a cache floor below the deployment floor", async () => {
    apiMock.get.mockResolvedValue(res(cimdSettings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    fireEvent.change(screen.getByLabelText("Cache floor (seconds)"), {
      target: { value: "30" },
    });

    expect(
      await screen.findByText(/cimd\.min_cache_secs \(30\) must be >= 60/)
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save Settings" })).toBeDisabled();
  });

  it("refuses a zero read cap", async () => {
    apiMock.get.mockResolvedValue(res(cimdSettings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    fireEvent.change(screen.getByLabelText("Document read cap (bytes)"), {
      target: { value: "0" },
    });

    expect(
      await screen.findByText(
        /cimd\.max_metadata_bytes \(0\) must be between 1 and 65536/
      )
    ).toBeInTheDocument();
  });

  it("sends the whole nine-field posture as part of the tenant override", async () => {
    apiMock.get.mockResolvedValue(res(cimdSettings));
    apiMock.put.mockResolvedValue(res(cimdSettings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));

    await userEvent.click(
      screen.getByLabelText("Refuse a document whose token_endpoint_auth_method is none")
    );
    fireEvent.change(
      screen.getByLabelText("Trusted redirect domains (one per line)"),
      { target: { value: "app.example.com" } }
    );
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));

    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    const [, body] = apiMock.put.mock.calls[0];
    expect(body).toMatchObject({
      cimd: {
        enabled: true,
        allow_http: false,
        trusted_client_id_domains: ["mcp.example.com"],
        trusted_redirect_domains: ["app.example.com"],
        restrict_same_domain: false,
        confidential_only: true,
        min_cache_secs: 600,
        max_cache_secs: 86_400,
        max_metadata_bytes: 4_000,
      },
    });
  });

  // The server returns early while `enabled` is false, so a tenant may stage a
  // posture before turning it on. A mirror that refused here would refuse a
  // save the server accepts — the one direction it must never fail in.
  it("saves a staged posture that is invalid but not enabled", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    apiMock.put.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    fireEvent.change(
      screen.getByLabelText("Trusted publisher domains (one per line)"),
      { target: { value: "*" } }
    );

    expect(screen.getByRole("button", { name: "Save Settings" })).toBeEnabled();
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    const [, body] = apiMock.put.mock.calls[0];
    expect(body).toMatchObject({
      cimd: { enabled: false, trusted_client_id_domains: ["*"] },
    });
  });
});

// ─── S-7b — Server certificate names ──────────────────────────────────────────

describe("SettingsPage — S-7b server certificate names", () => {
  const withNames = (names: string[]): SecuritySettings => ({
    ...settings,
    certificate: { ...settings.certificate, server_cert_allowed_names: names },
  });

  function card() {
    return screen
      .getByText("Server Certificate Names")
      .closest("[class*='rounded']") as HTMLElement;
  }

  it("I1/I4 — with no allow-list, says every Server request is refused and explains the three forms", async () => {
    apiMock.get.mockResolvedValue(res(settings)); // no field at all: an older-shaped response
    renderWithProviders(<SettingsPage />);
    await screen.findByText("Server Certificate Names");
    const c = card();
    expect(within(c).getByText(/Effective for this tenant/)).toBeInTheDocument();
    expect(within(c).getByText(/Empty — every Server certificate request is refused/)).toBeInTheDocument();
    expect(c).toHaveTextContent("api.lakeside.internal");
    expect(c).toHaveTextContent(".lakeside.internal");
    expect(c).toHaveTextContent("10.0.0.0/8");
    expect(c).toHaveTextContent(/strictly below/);
    expect(c).toHaveTextContent(/may only remove an entry or narrow one/);
  });

  it("shows the effective list the server read back", async () => {
    apiMock.get.mockResolvedValue(res(withNames([".plant.lakeside.internal", "10.1.0.0/16"])));
    renderWithProviders(<SettingsPage />);
    await screen.findByText("Server Certificate Names");
    const list = within(card()).getByRole("list", { name: "Allowed server names" });
    expect(within(list).getAllByRole("listitem").map((li) => li.textContent)).toEqual([
      ".plant.lakeside.internal",
      "10.1.0.0/16",
    ]);
  });

  it("saving an unrelated setting sends the effective list back unchanged", async () => {
    // The regression: this PUT stores only what differs from the organization
    // baseline, so a body without the list dropped a tenant's narrowing and put
    // it back on the organization's wider list.
    apiMock.get.mockResolvedValue(res(withNames([".plant.lakeside.internal"])));
    apiMock.put.mockResolvedValue(res(withNames([".plant.lakeside.internal"])));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    await userEvent.click(screen.getByLabelText("Require symbol"));
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    expect(apiMock.put.mock.calls[0][1].server_cert_allowed_names).toEqual([
      ".plant.lakeside.internal",
    ]);
  });

  it("I4 twin: with no allow-list, the body carries the empty list the server already stores", async () => {
    apiMock.get.mockResolvedValue(res(settings));
    apiMock.put.mockResolvedValue(res(settings));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    expect(apiMock.put.mock.calls[0][1].server_cert_allowed_names).toEqual([]);
  });

  it("edits the list row by row, sending it trimmed with blank rows dropped", async () => {
    apiMock.get.mockResolvedValue(res(withNames([".lakeside.internal", "10.0.0.0/8"])));
    apiMock.put.mockResolvedValue(res(withNames([".plant.lakeside.internal"])));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    const c = card();
    expect(within(c).getByLabelText("Allowed name 1")).toHaveValue(".lakeside.internal");
    expect(within(c).getByLabelText("Allowed name 2")).toHaveValue("10.0.0.0/8");
    // Narrow the first, remove the second, add a blank row.
    const first = within(c).getByLabelText("Allowed name 1");
    await userEvent.clear(first);
    await userEvent.type(first, " .plant.lakeside.internal ");
    await userEvent.click(within(c).getByRole("button", { name: "Remove allowed name 2" }));
    await userEvent.click(within(c).getByRole("button", { name: "Add entry" }));
    expect(within(c).getByLabelText("Allowed name 2")).toHaveValue("");
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    expect(apiMock.put.mock.calls[0][1].server_cert_allowed_names).toEqual([
      ".plant.lakeside.internal",
    ]);
  });

  it("removing every entry says so before saving, and sends an empty list", async () => {
    apiMock.get.mockResolvedValue(res(withNames([".lakeside.internal"])));
    apiMock.put.mockResolvedValue(res(withNames([])));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    const c = card();
    await userEvent.click(within(c).getByRole("button", { name: "Remove allowed name 1" }));
    expect(within(c).getByRole("note")).toHaveTextContent(
      /Empty — every Server certificate request is refused/
    );
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    expect(apiMock.put.mock.calls[0][1].server_cert_allowed_names).toEqual([]);
  });

  it("shows the server's refusal of a widening verbatim", async () => {
    apiMock.get.mockResolvedValue(res(withNames([".lakeside.internal"])));
    // `validate_tenant_override`'s own wording (axiam-core, settings.rs).
    const message =
      'Tenant override violates org baseline: server_cert_allowed_names: ".example.com" is not within the org baseline; a tenant may remove an entry or narrow one, never add or widen one';
    apiMock.put.mockRejectedValue({
      message: "Request failed with status code 400",
      response: { status: 400, data: { error: "validation_error", message } },
    });
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    const c = card();
    await userEvent.click(within(c).getByRole("button", { name: "Add entry" }));
    await userEvent.type(within(c).getByLabelText("Allowed name 2"), ".example.com");
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));
    expect(await screen.findByText(message)).toBeInTheDocument();
    // Nothing was pre-judged: the widening reached the server as typed.
    expect(apiMock.put.mock.calls[0][1].server_cert_allowed_names).toEqual([
      ".lakeside.internal",
      ".example.com",
    ]);
  });

  it("after a save, shows what the server reads back rather than what was sent", async () => {
    // The organization withdrew `10.1.0.0/16` between load and save: the server
    // intersects on every read, so the effective list is shorter than the body.
    apiMock.get
      .mockResolvedValueOnce(res(withNames([".plant.lakeside.internal", "10.1.0.0/16"])))
      .mockResolvedValue(res(withNames([".plant.lakeside.internal"])));
    apiMock.put.mockResolvedValue(res(withNames([".plant.lakeside.internal"])));
    renderWithProviders(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Settings/ }));
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));
    expect(await screen.findByText("Settings saved successfully.")).toBeInTheDocument();
    await waitFor(() => {
      const list = within(card()).getByRole("list", { name: "Allowed server names" });
      expect(within(list).getAllByRole("listitem").map((li) => li.textContent)).toEqual([
        ".plant.lakeside.internal",
      ]);
    });
    expect(apiMock.put.mock.calls[0][1].server_cert_allowed_names).toEqual([
      ".plant.lakeside.internal",
      "10.1.0.0/16",
    ]);
  });
});
