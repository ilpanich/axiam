import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { OrganizationDetailPage } from "./OrganizationDetailPage";
import { makeClient } from "@/test/renderWithProviders";
import type {
  Organization,
  Tenant,
  CaCertificate,
  SecuritySettings,
} from "@/services/organizations";

const org: Organization = {
  id: "o1",
  name: "Acme Corp",
  slug: "acme-corp",
  metadata: { description: "Widgets Inc" },
  created_at: "2026-01-01T00:00:00Z",
};

const tenants: Tenant[] = [
  {
    id: "t1",
    name: "Prod",
    slug: "prod",
    status: "Active",
    metadata: { description: "Production" },
    organization_id: "o1",
    created_at: "2026-01-01T00:00:00Z",
  },
  {
    id: "t2",
    name: "Staging",
    slug: "staging",
    status: "Active",
    organization_id: "o1",
    created_at: "2026-01-02T00:00:00Z",
  },
];

const certs: CaCertificate[] = [
  {
    id: "c1",
    organization_id: "o1",
    subject: "CN=Root CA",
    fingerprint: "abcdef0123456789deadbeef",
    public_cert_pem: "PEM",
    key_algorithm: "Rsa4096",
    status: "Active",
    not_before: "2026-01-01T00:00:00Z",
    not_after: "2027-01-01T00:00:00Z",
  },
  {
    id: "c2",
    organization_id: "o1",
    subject: "CN=Old CA",
    fingerprint: "1111222233334444",
    public_cert_pem: "PEM",
    key_algorithm: "Ed25519",
    status: "Revoked",
    not_before: "2025-01-01T00:00:00Z",
    not_after: "2026-01-01T00:00:00Z",
  },
];

const settings: SecuritySettings = {
  id: "s1",
  scope: "Org",
  scope_id: "o1",
  password: {
    min_length: 8,
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
    refresh_token_lifetime_secs: 604800,
  },
  email: {
    email_verification_required: true,
    email_verification_grace_period_hours: 24,
  },
  certificate: { default_cert_validity_days: 365, max_cert_validity_days: 730 },
  notification: { admin_notifications_enabled: true },
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

/**
 * Route GET calls by exact URL to the payloads a test cares about. Any
 * unspecified URL resolves to an empty list so unrelated queries stay quiet.
 */
function routeGet(map: Record<string, unknown>) {
  apiMock.get.mockImplementation((url: string) => {
    if (url in map) return Promise.resolve(res(map[url]));
    return Promise.resolve(res([]));
  });
}

const URLS = {
  org: "/api/v1/organizations/o1",
  tenants: "/api/v1/organizations/o1/tenants",
  certs: "/api/v1/organizations/o1/ca-certificates",
  settings: "/api/v1/organizations/o1/settings",
};

function renderDetail() {
  const client = makeClient();
  const router = createMemoryRouter(
    [
      { path: "/organizations", element: <div>Organizations list</div> },
      { path: "/organizations/:orgId", element: <OrganizationDetailPage /> },
      {
        path: "/organizations/:orgId/tenants/:tenantId",
        element: <div>Tenant detail screen</div>,
      },
    ],
    { initialEntries: ["/organizations/o1"] }
  );
  return render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("OrganizationDetailPage — header & tenants tab", () => {
  it("shows a loading placeholder while the organization is fetching", () => {
    apiMock.get.mockReturnValue(new Promise(() => {}));
    renderDetail();
    expect(screen.getByText("Loading...")).toBeInTheDocument();
  });

  it("renders the org name, description and its tenants", async () => {
    routeGet({ [URLS.org]: org, [URLS.tenants]: tenants });
    renderDetail();
    expect(await screen.findAllByText("Acme Corp")).not.toHaveLength(0);
    expect(screen.getByText("Widgets Inc")).toBeInTheDocument();
    expect(await screen.findByText("Prod")).toBeInTheDocument();
    expect(screen.getByText("Staging")).toBeInTheDocument();
  });

  it("navigates to tenant detail when a tenant name is clicked", async () => {
    routeGet({ [URLS.org]: org, [URLS.tenants]: tenants });
    renderDetail();
    await userEvent.click(await screen.findByRole("button", { name: "Prod" }));
    expect(await screen.findByText("Tenant detail screen")).toBeInTheDocument();
  });

  it("shows the empty state when there are no tenants", async () => {
    routeGet({ [URLS.org]: org, [URLS.tenants]: [] });
    renderDetail();
    expect(await screen.findByText("No tenants yet.")).toBeInTheDocument();
  });

  it("validates that name and slug are required before creating a tenant", async () => {
    routeGet({ [URLS.org]: org, [URLS.tenants]: tenants });
    renderDetail();
    await userEvent.click(await screen.findByRole("button", { name: /New Tenant/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "   ");
    await userEvent.type(within(dialog).getByLabelText("Slug *"), "   ");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Name and slug are required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("creates a tenant, auto-slugifying the name, and closes the dialog", async () => {
    routeGet({ [URLS.org]: org, [URLS.tenants]: tenants });
    apiMock.post.mockResolvedValue(res({ id: "t3", name: "QA", slug: "qa" }));
    renderDetail();
    await userEvent.click(await screen.findByRole("button", { name: /New Tenant/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "QA Env");
    expect(within(dialog).getByLabelText("Slug *")).toHaveValue("qa-env");
    await userEvent.type(within(dialog).getByLabelText("Description"), "test env");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(URLS.tenants, {
        name: "QA Env",
        slug: "qa-env",
        metadata: { description: "test env" },
      })
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("surfaces a create-tenant error from the service", async () => {
    routeGet({ [URLS.org]: org, [URLS.tenants]: tenants });
    apiMock.post.mockRejectedValue(new Error("Slug taken"));
    renderDetail();
    await userEvent.click(await screen.findByRole("button", { name: /New Tenant/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Dup");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await screen.findByText("Slug taken")).toBeInTheDocument();
  });

  it("edits a tenant, pre-filling from its metadata", async () => {
    routeGet({ [URLS.org]: org, [URLS.tenants]: tenants });
    apiMock.put.mockResolvedValue(res({ ...tenants[0], name: "Prod 2" }));
    renderDetail();
    await userEvent.click(await screen.findByRole("button", { name: "Edit Prod" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Name *")).toHaveValue("Prod");
    expect(within(dialog).getByLabelText("Description")).toHaveValue("Production");
    const name = within(dialog).getByLabelText("Name *");
    await userEvent.clear(name);
    await userEvent.type(name, "Prod 2");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/organizations/o1/tenants/t1", {
        name: "Prod 2",
        slug: "prod-2",
        metadata: { description: "Production" },
      })
    );
  });

  it("validates a blank name when editing a tenant", async () => {
    routeGet({ [URLS.org]: org, [URLS.tenants]: tenants });
    renderDetail();
    await userEvent.click(await screen.findByRole("button", { name: "Edit Prod" }));
    const dialog = screen.getByRole("dialog");
    // Clearing the name auto-slugifies to an empty slug too; submit the form
    // node directly to bypass native `required` and hit the JS validation.
    await userEvent.clear(within(dialog).getByLabelText("Name *"));
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Name and slug are required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("surfaces an edit-tenant error from the service", async () => {
    routeGet({ [URLS.org]: org, [URLS.tenants]: tenants });
    apiMock.put.mockRejectedValue(new Error("Update failed"));
    renderDetail();
    await userEvent.click(await screen.findByRole("button", { name: "Edit Staging" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByText("Update failed")).toBeInTheDocument();
  });

  it("deletes a tenant after confirmation", async () => {
    routeGet({ [URLS.org]: org, [URLS.tenants]: tenants });
    apiMock.delete.mockResolvedValue(res(undefined));
    renderDetail();
    await userEvent.click(await screen.findByRole("button", { name: "Delete Staging" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Delete Tenant/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/organizations/o1/tenants/t2")
    );
  });
});

describe("OrganizationDetailPage — CA certificates tab", () => {
  async function goToCerts() {
    renderDetail();
    await screen.findByText("Widgets Inc");
    await userEvent.click(screen.getByRole("tab", { name: "CA Certificates" }));
  }

  it("lists the CA certificates", async () => {
    routeGet({ [URLS.org]: org, [URLS.certs]: certs });
    await goToCerts();
    expect(await screen.findByText("CN=Root CA")).toBeInTheDocument();
    expect(screen.getByText("CN=Old CA")).toBeInTheDocument();
  });

  it("shows the empty state when there are no certificates", async () => {
    routeGet({ [URLS.org]: org, [URLS.certs]: [] });
    await goToCerts();
    expect(await screen.findByText("No CA certificates yet.")).toBeInTheDocument();
  });

  it("requires a subject when generating (JS validation branch)", async () => {
    routeGet({ [URLS.org]: org, [URLS.certs]: certs });
    await goToCerts();
    await userEvent.click(
      await screen.findByRole("button", { name: /Generate Certificate/ })
    );
    const dialog = screen.getByRole("dialog");
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Subject is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("rejects a validity of less than one day", async () => {
    routeGet({ [URLS.org]: org, [URLS.certs]: certs });
    await goToCerts();
    await userEvent.click(
      await screen.findByRole("button", { name: /Generate Certificate/ })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Subject *"), "CN=New");
    fireEvent.change(within(dialog).getByLabelText("Validity (days)"), {
      target: { value: "0" },
    });
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Validity must be at least 1 day.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("generates a certificate and reveals the one-time private key", async () => {
    routeGet({ [URLS.org]: org, [URLS.certs]: certs });
    apiMock.post.mockResolvedValue(
      res({ ...certs[0], id: "c3", private_key_pem: "-----BEGIN KEY-----xyz" })
    );
    await goToCerts();
    await userEvent.click(
      await screen.findByRole("button", { name: /Generate Certificate/ })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Subject *"), "CN=New Root");
    await userEvent.selectOptions(
      within(dialog).getByLabelText("Key Algorithm"),
      "Ed25519"
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Generate" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(URLS.certs, {
        subject: "CN=New Root",
        key_algorithm: "Ed25519",
        validity_days: 365,
      })
    );
    const secret = await screen.findByRole("alertdialog");
    expect(within(secret).getByText("CA Certificate Generated")).toBeInTheDocument();
    expect(within(secret).getByText("-----BEGIN KEY-----xyz")).toBeInTheDocument();
    await userEvent.click(
      within(secret).getByRole("button", { name: "I've saved this information" })
    );
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("surfaces a generate error from the service", async () => {
    routeGet({ [URLS.org]: org, [URLS.certs]: certs });
    apiMock.post.mockRejectedValue(new Error("CA limit reached"));
    await goToCerts();
    await userEvent.click(
      await screen.findByRole("button", { name: /Generate Certificate/ })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Subject *"), "CN=Fail");
    await userEvent.click(within(dialog).getByRole("button", { name: "Generate" }));
    expect(await screen.findByText("CA limit reached")).toBeInTheDocument();
  });

  it("revokes an active certificate after confirmation", async () => {
    routeGet({ [URLS.org]: org, [URLS.certs]: certs });
    apiMock.post.mockResolvedValue(res(undefined));
    await goToCerts();
    await userEvent.click(await screen.findByRole("button", { name: "Revoke CN=Root CA" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Revoke Certificate/)).toBeInTheDocument();
    // ConfirmDialog uses its default confirm label ("Delete") here.
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(
        "/api/v1/organizations/o1/ca-certificates/c1/revoke"
      )
    );
  });
});

describe("OrganizationDetailPage — settings tab", () => {
  async function goToSettings() {
    renderDetail();
    await screen.findByText("Widgets Inc");
    await userEvent.click(screen.getByRole("tab", { name: "Settings" }));
  }

  it("shows a loading state until settings resolve", async () => {
    apiMock.get.mockImplementation((url: string) => {
      if (url === URLS.org) return Promise.resolve(res(org));
      if (url === URLS.settings) return new Promise(() => {});
      return Promise.resolve(res([]));
    });
    await goToSettings();
    expect(await screen.findByText("Loading settings...")).toBeInTheDocument();
  });

  it("seeds the form from settings and edits/saves the full payload", async () => {
    routeGet({ [URLS.org]: org, [URLS.settings]: settings });
    apiMock.put.mockResolvedValue(res(settings));
    await goToSettings();
    const minLen = await screen.findByLabelText("Minimum length");
    expect(minLen).toHaveValue(8);
    fireEvent.change(minLen, { target: { value: "10" } });
    expect(await screen.findByText("Unsaved changes")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        URLS.settings,
        expect.objectContaining({ min_length: 10, mfa_enforced: false })
      )
    );
    expect(await screen.findByText("Settings saved successfully.")).toBeInTheDocument();
    // Dirty flag clears after save.
    await waitFor(() =>
      expect(screen.queryByText("Unsaved changes")).not.toBeInTheDocument()
    );
  });

  it("toggles a checkbox to mark the form dirty", async () => {
    routeGet({ [URLS.org]: org, [URLS.settings]: settings });
    await goToSettings();
    const mfa = await screen.findByLabelText("Enforce MFA for all users");
    expect(mfa).not.toBeChecked();
    await userEvent.click(mfa);
    expect(mfa).toBeChecked();
    expect(await screen.findByText("Unsaved changes")).toBeInTheDocument();
  });

  it("surfaces a save error from the service", async () => {
    routeGet({ [URLS.org]: org, [URLS.settings]: settings });
    apiMock.put.mockRejectedValue(new Error("Too permissive"));
    await goToSettings();
    const minLen = await screen.findByLabelText("Minimum length");
    fireEvent.change(minLen, { target: { value: "10" } });
    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));
    expect(await screen.findByText("Too permissive")).toBeInTheDocument();
  });

  it("guards an in-page tab switch away from dirty settings and discards on confirm", async () => {
    routeGet({ [URLS.org]: org, [URLS.settings]: settings, [URLS.tenants]: tenants });
    await goToSettings();
    const minLen = await screen.findByLabelText("Minimum length");
    fireEvent.change(minLen, { target: { value: "10" } });
    await screen.findByText("Unsaved changes");

    // Attempt to switch to the Tenants tab — the guard dialog intercepts.
    await userEvent.click(screen.getByRole("tab", { name: "Tenants" }));
    expect(await screen.findByText("Discard unsaved changes?")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Discard changes" }));
    // Now on the tenants tab.
    expect(await screen.findByText("Prod")).toBeInTheDocument();
  });

  it("keeps editing when the tab-switch guard is dismissed", async () => {
    routeGet({ [URLS.org]: org, [URLS.settings]: settings, [URLS.tenants]: tenants });
    await goToSettings();
    const minLen = await screen.findByLabelText("Minimum length");
    fireEvent.change(minLen, { target: { value: "10" } });
    await screen.findByText("Unsaved changes");
    await userEvent.click(screen.getByRole("tab", { name: "Tenants" }));
    await userEvent.click(await screen.findByRole("button", { name: "Keep editing" }));
    // Still on settings, still dirty.
    expect(screen.getByText("Unsaved changes")).toBeInTheDocument();
  });

  it("blocks route navigation away while dirty and proceeds on discard", async () => {
    routeGet({ [URLS.org]: org, [URLS.settings]: settings });
    await goToSettings();
    const minLen = await screen.findByLabelText("Minimum length");
    fireEvent.change(minLen, { target: { value: "10" } });
    await screen.findByText("Unsaved changes");

    // Click the breadcrumb link to leave the page — useBlocker intercepts.
    await userEvent.click(screen.getByRole("link", { name: "Organizations" }));
    expect(await screen.findByText("Discard unsaved changes?")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Discard changes" }));
    expect(await screen.findByText("Organizations list")).toBeInTheDocument();
  });

  it("resets the route-navigation blocker when 'Keep editing' is chosen", async () => {
    routeGet({ [URLS.org]: org, [URLS.settings]: settings });
    await goToSettings();
    const minLen = await screen.findByLabelText("Minimum length");
    fireEvent.change(minLen, { target: { value: "10" } });
    await screen.findByText("Unsaved changes");
    await userEvent.click(screen.getByRole("link", { name: "Organizations" }));
    await screen.findByText("Discard unsaved changes?");
    await userEvent.click(screen.getByRole("button", { name: "Keep editing" }));
    // Stayed on the settings tab.
    expect(screen.getByText("Unsaved changes")).toBeInTheDocument();
    expect(screen.queryByText("Organizations list")).not.toBeInTheDocument();
  });

  it("edits every settings field and submits the fully-updated payload", async () => {
    routeGet({ [URLS.org]: org, [URLS.settings]: settings });
    apiMock.put.mockResolvedValue(res(settings));
    await goToSettings();
    await screen.findByLabelText("Minimum length");

    const num: [string, string][] = [
      ["Minimum length", "12"],
      ["Password history count", "3"],
      ["MFA challenge lifetime (seconds)", "120"],
      ["Max failed login attempts", "10"],
      ["Lockout duration (seconds)", "600"],
      ["Lockout backoff multiplier", "3"],
      ["Max lockout duration (seconds)", "7200"],
      ["Access token lifetime (seconds)", "600"],
      ["Refresh token lifetime (seconds)", "1209600"],
      ["Verification grace period (hours)", "48"],
      ["Default certificate validity (days)", "90"],
      ["Max certificate validity (days)", "365"],
    ];
    for (const [label, value] of num) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }

    const checks = [
      "Require uppercase letter",
      "Require lowercase letter",
      "Require digit",
      "Require symbol",
      "Check against breach database (HIBP)",
      "Enforce MFA for all users",
      "Require email verification",
      "Enable admin notifications",
    ];
    for (const label of checks) {
      await userEvent.click(screen.getByLabelText(label));
    }

    await userEvent.click(screen.getByRole("button", { name: "Save Settings" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(
        URLS.settings,
        expect.objectContaining({
          min_length: 12,
          password_history_count: 3,
          mfa_challenge_lifetime_secs: 120,
          max_failed_login_attempts: 10,
          lockout_duration_secs: 600,
          lockout_backoff_multiplier: 3,
          max_lockout_duration_secs: 7200,
          access_token_lifetime_secs: 600,
          refresh_token_lifetime_secs: 1209600,
          email_verification_grace_period_hours: 48,
          default_cert_validity_days: 90,
          max_cert_validity_days: 365,
          require_uppercase: false,
          require_symbols: true,
          mfa_enforced: true,
          email_verification_required: false,
          admin_notifications_enabled: false,
        })
      )
    );
  });
});

describe("OrganizationDetailPage — small branches", () => {
  it("resets and closes the create-tenant dialog on cancel", async () => {
    routeGet({ [URLS.org]: org, [URLS.tenants]: tenants });
    renderDetail();
    await userEvent.click(await screen.findByRole("button", { name: /New Tenant/ }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "Temp");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    // Reopening starts blank (state was reset).
    await userEvent.click(screen.getByRole("button", { name: /New Tenant/ }));
    expect(within(screen.getByRole("dialog")).getByLabelText("Name *")).toHaveValue("");
  });

  it("renders an Expired CA certificate with the neutral badge", async () => {
    const expired: CaCertificate = { ...certs[0], id: "c9", subject: "CN=Expired CA", status: "Expired" };
    routeGet({ [URLS.org]: org, [URLS.certs]: [expired] });
    renderDetail();
    await screen.findByText("Widgets Inc");
    await userEvent.click(screen.getByRole("tab", { name: "CA Certificates" }));
    expect(await screen.findByText("CN=Expired CA")).toBeInTheDocument();
  });

  it("generates a certificate with the default RSA algorithm and no reveal when no key is returned", async () => {
    routeGet({ [URLS.org]: org, [URLS.certs]: [] });
    // Response without private_key_pem — the reveal modal must NOT open.
    apiMock.post.mockResolvedValue(res({ ...certs[0], id: "c8", private_key_pem: "" }));
    renderDetail();
    await screen.findByText("Widgets Inc");
    await userEvent.click(screen.getByRole("tab", { name: "CA Certificates" }));
    await userEvent.click(
      await screen.findByRole("button", { name: /Generate Certificate/ })
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Subject *"), "CN=RSA CA");
    await userEvent.click(within(dialog).getByRole("button", { name: "Generate" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(URLS.certs, {
        subject: "CN=RSA CA",
        key_algorithm: "Rsa4096",
        validity_days: 365,
      })
    );
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });
});
