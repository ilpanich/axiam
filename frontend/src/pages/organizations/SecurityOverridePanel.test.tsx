import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { TenantSecurityOverridePanel } from "./SecurityOverridePanel";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore, type AuthUser } from "@/stores/auth";

const admin: AuthUser = {
  id: "u1",
  username: "admin",
  email: "admin@example.com",
  permissions: ["settings:get", "settings:update"],
  tenant_id: "t1",
};

/** The merged view `GET /api/v1/settings` returns. */
const effective = {
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
    lockout_duration_secs: 300,
    lockout_backoff_multiplier: 2,
    max_lockout_duration_secs: 3600,
  },
  token: {
    access_token_lifetime_secs: 900,
    refresh_token_lifetime_secs: 2_592_000,
  },
  email: {
    email_verification_required: true,
    email_verification_grace_period_hours: 24,
  },
  certificate: { default_cert_validity_days: 365, max_cert_validity_days: 730 },
  notification: { admin_notifications_enabled: true },
  opaque: {
    opaque_mode: "disabled",
    opaque_suite: "ristretto255_sha512",
    opaque_ksf: "argon2id",
  },
  privacy: { deletion_grace_period_days: 30 },
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

/** Route GETs by URL: the panel reads both the override and the merged view. */
function mockGets(override: unknown | { notFound: true }) {
  apiMock.get.mockImplementation((url: string) => {
    if (url === "/api/v1/settings") return res(effective);
    if (url === "/api/v1/tenants/t1/settings") {
      if (override && (override as { notFound?: true }).notFound) {
        return Promise.reject({ response: { status: 404 } });
      }
      return res(override);
    }
    return res({});
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({
    user: admin,
    isAuthenticated: true,
    isInitializing: false,
  });
});

describe("TenantSecurityOverridePanel", () => {
  it("shows every group un-overridden when the tenant inherits everything", async () => {
    mockGets({ notFound: true });
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    for (const name of [
      /Override password policy/,
      /Override multi-factor authentication/,
      /Override account lockout/,
      /Override token lifetimes/,
      /Override email verification/,
      /Override certificate validity/,
      /Override admin notifications/,
      /Override OPAQUE policy/,
      /Override the pending-deletion window/,
    ]) {
      expect(await screen.findByRole("checkbox", { name })).not.toBeChecked();
    }
    // Nothing to clear when nothing is overridden.
    expect(
      screen.queryByRole("button", { name: /Clear All/ })
    ).not.toBeInTheDocument();
  });

  it("sends only the groups the operator checked", async () => {
    mockGets({ notFound: true });
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override password policy/ })
    );
    const minLength = screen.getByLabelText("Minimum length");
    await userEvent.clear(minLength);
    await userEvent.type(minLength, "16");
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/tenants/t1/settings", {
        min_length: 16,
        require_uppercase: true,
        require_lowercase: true,
        require_digits: true,
        require_symbols: false,
        password_history_count: 5,
        hibp_check_enabled: true,
      })
    );
    // No MFA, lockout, token, certificate, OPAQUE or privacy keys anywhere: an
    // absent field inherits, which is the entire point of the endpoint.
    const sent = apiMock.put.mock.calls[0][1] as Record<string, unknown>;
    expect(sent).not.toHaveProperty("mfa_enforced");
    expect(sent).not.toHaveProperty("opaque_mode");
    expect(sent).not.toHaveProperty("deletion_grace_period_days");
  });

  it("seeds each group's fields from the effective settings", async () => {
    // An un-overridden group opens showing what the tenant currently gets,
    // rather than a default that would silently loosen something on save.
    mockGets({ notFound: true });
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override account lockout/ })
    );
    expect(screen.getByLabelText("Failed attempts before lockout")).toHaveValue(
      5
    );
    expect(screen.getByLabelText("Lockout duration (seconds)")).toHaveValue(300);
  });

  it("seeds the group checkboxes from what the tenant already overrides", async () => {
    mockGets({ opaque_mode: "optional", deletion_grace_period_days: 7 });
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    expect(
      await screen.findByRole("checkbox", { name: /Override OPAQUE policy/ })
    ).toBeChecked();
    expect(
      screen.getByRole("checkbox", {
        name: /Override the pending-deletion window/,
      })
    ).toBeChecked();
    expect(
      screen.getByRole("checkbox", { name: /Override password policy/ })
    ).not.toBeChecked();
  });

  it("offers OPAQUE and the pending-deletion window, which the page never had", async () => {
    // The two the tenant page was missing outright: OPAQUE was reachable only
    // from /settings, and the erasure window was hard-coded server-side.
    mockGets({ notFound: true });
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override OPAQUE policy/ })
    );
    expect(screen.getByLabelText("Mode")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent(/Tighten-only/);

    await userEvent.click(
      screen.getByRole("checkbox", {
        name: /Override the pending-deletion window/,
      })
    );
    expect(
      screen.getByLabelText("Pending-deletion window (days)")
    ).toHaveValue(30);
  });

  it("surfaces the server's refusal of a loosening override", async () => {
    mockGets({ notFound: true });
    apiMock.put.mockRejectedValue({
      response: {
        status: 400,
        data: {
          message:
            "Tenant override violates org baseline: min_length: tenant value 8 is less restrictive than org baseline 12",
        },
      },
    });
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override password policy/ })
    );
    const minLength = screen.getByLabelText("Minimum length");
    await userEvent.clear(minLength);
    await userEvent.type(minLength, "8");
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /less restrictive than org baseline/
    );
  });

  it("clears every override back to the baseline", async () => {
    mockGets({ min_length: 16 });
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("button", { name: /Clear All/ })
    );
    const confirm = await screen.findByRole("dialog");
    await userEvent.click(
      within(confirm).getByRole("button", { name: "Clear overrides" })
    );

    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/tenants/t1/settings")
    );
  });

  it("surfaces a failed load rather than showing empty toggles", async () => {
    // What a cross-tenant view looks like: the endpoint refuses a tenant that
    // is not the caller's own, and "nothing is overridden" would be a lie.
    apiMock.get.mockImplementation((url: string) => {
      if (url === "/api/v1/settings") return res(effective);
      return Promise.reject(new Error("Forbidden"));
    });
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t-other" />);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /Could not load this tenant.s security overrides/
    );
    expect(
      screen.queryByRole("button", { name: "Save Overrides" })
    ).not.toBeInTheDocument();
  });

  it("hides the write controls without settings:update", async () => {
    useAuthStore.setState({
      user: { ...admin, permissions: ["settings:get"] },
      isAuthenticated: true,
      isInitializing: false,
    });
    mockGets({ notFound: true });
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    expect(
      await screen.findByRole("checkbox", { name: /Override password policy/ })
    ).toBeDisabled();
    expect(
      screen.queryByRole("button", { name: "Save Overrides" })
    ).not.toBeInTheDocument();
  });
});

// ─── Every group, every control ───────────────────────────────────────────────
//
// The panel's payload builder is nine independent `if (groups.x)` blocks, and
// the rest of it is one `onChange` per control. A test that touches only the
// password group proves the sparse-payload idea but leaves the other eight
// blocks and ~20 controls unexercised — a field wired to the wrong `setField`
// key would ship silently. These exercise the whole surface against a
// deliberately *loose* baseline, so every edit below moves in the tightening
// direction the server actually accepts.

/** A baseline loose enough that every control has somewhere stricter to go. */
const looseEffective = {
  ...effective,
  password: {
    min_length: 8,
    require_uppercase: false,
    require_lowercase: false,
    require_digits: false,
    require_symbols: false,
    password_history_count: 0,
    hibp_check_enabled: false,
  },
  mfa: { mfa_enforced: false, mfa_challenge_lifetime_secs: 600 },
  lockout: {
    max_failed_login_attempts: 10,
    lockout_duration_secs: 60,
    lockout_backoff_multiplier: 1,
    max_lockout_duration_secs: 600,
  },
  token: {
    access_token_lifetime_secs: 3600,
    refresh_token_lifetime_secs: 2_592_000,
  },
  email: {
    email_verification_required: false,
    email_verification_grace_period_hours: 48,
  },
  certificate: { default_cert_validity_days: 730, max_cert_validity_days: 1095 },
  notification: { admin_notifications_enabled: false },
  opaque: {
    opaque_mode: "disabled",
    opaque_suite: "ristretto255_sha512",
    opaque_ksf: "scrypt",
  },
  privacy: { deletion_grace_period_days: 90 },
};

function mockLooseGets() {
  apiMock.get.mockImplementation((url: string) => {
    if (url === "/api/v1/settings") return res(looseEffective);
    if (url === "/api/v1/tenants/t1/settings") {
      return Promise.reject({ response: { status: 404 } });
    }
    return res({});
  });
}

/** Replace a number input's contents, the way an operator retyping it would. */
async function retype(label: string, value: string) {
  const input = screen.getByLabelText(label);
  await userEvent.clear(input);
  await userEvent.type(input, value);
}

describe("TenantSecurityOverridePanel — every group", () => {
  it("sends every password field when the password group is overridden", async () => {
    mockLooseGets();
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override password policy/ })
    );
    await retype("Minimum length", "16");
    await retype("Password history", "10");
    for (const label of [
      "Require an uppercase letter",
      "Require a lowercase letter",
      "Require a digit",
      "Require a symbol",
      "Check against known breached passwords (HIBP)",
    ]) {
      await userEvent.click(screen.getByLabelText(label));
    }
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/tenants/t1/settings", {
        min_length: 16,
        require_uppercase: true,
        require_lowercase: true,
        require_digits: true,
        require_symbols: true,
        password_history_count: 10,
        hibp_check_enabled: true,
      })
    );
    expect(await screen.findByRole("status")).toHaveTextContent("Saved.");
  });

  it("sends both MFA fields when the MFA group is overridden", async () => {
    mockLooseGets();
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", {
        name: /Override multi-factor authentication/,
      })
    );
    await userEvent.click(
      screen.getByLabelText("Require MFA for every user in this tenant")
    );
    await retype("Challenge lifetime (seconds)", "120");
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/tenants/t1/settings", {
        mfa_enforced: true,
        mfa_challenge_lifetime_secs: 120,
      })
    );
  });

  it("sends all four lockout fields when the lockout group is overridden", async () => {
    mockLooseGets();
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override account lockout/ })
    );
    await retype("Failed attempts before lockout", "3");
    await retype("Lockout duration (seconds)", "900");
    await retype("Backoff multiplier", "3");
    await retype("Maximum lockout duration (seconds)", "7200");
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/tenants/t1/settings", {
        max_failed_login_attempts: 3,
        lockout_duration_secs: 900,
        lockout_backoff_multiplier: 3,
        max_lockout_duration_secs: 7200,
      })
    );
  });

  it("sends both token lifetimes when the token group is overridden", async () => {
    mockLooseGets();
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override token lifetimes/ })
    );
    await retype("Access token lifetime (seconds)", "300");
    await retype("Refresh token lifetime (seconds)", "86400");
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/tenants/t1/settings", {
        access_token_lifetime_secs: 300,
        refresh_token_lifetime_secs: 86400,
      })
    );
  });

  it("sends both email-verification fields when that group is overridden", async () => {
    mockLooseGets();
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override email verification/ })
    );
    await userEvent.click(
      screen.getByLabelText("Require a verified email address")
    );
    await retype("Verification grace period (hours)", "2");
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/tenants/t1/settings", {
        email_verification_required: true,
        email_verification_grace_period_hours: 2,
      })
    );
  });

  it("sends both certificate validities when that group is overridden", async () => {
    mockLooseGets();
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", {
        name: /Override certificate validity/,
      })
    );
    await retype("Default certificate validity (days)", "90");
    await retype("Maximum certificate validity (days)", "180");
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/tenants/t1/settings", {
        default_cert_validity_days: 90,
        max_cert_validity_days: 180,
      })
    );
  });

  it("sends the admin-notification flag when that group is overridden", async () => {
    mockLooseGets();
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", {
        name: /Override admin notifications/,
      })
    );
    await userEvent.click(
      screen.getByLabelText("Send admin notifications for this tenant")
    );
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/tenants/t1/settings", {
        admin_notifications_enabled: true,
      })
    );
  });

  it("sends all three OPAQUE fields when the OPAQUE group is overridden", async () => {
    // The mode raises one step, the KSF to the stronger of the two — both
    // directions the server's tighten-only check accepts. The ciphersuite has
    // only one value today and so rides along unchanged.
    mockLooseGets();
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override OPAQUE policy/ })
    );
    await userEvent.selectOptions(screen.getByLabelText("Mode"), "optional");
    await userEvent.selectOptions(
      screen.getByLabelText("Key-stretching function"),
      "argon2id"
    );
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/tenants/t1/settings", {
        opaque_mode: "optional",
        opaque_suite: "ristretto255_sha512",
        opaque_ksf: "argon2id",
      })
    );
  });

  it("sends the pending-deletion window when the privacy group is overridden", async () => {
    mockLooseGets();
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", {
        name: /Override the pending-deletion window/,
      })
    );
    await retype("Pending-deletion window (days)", "7");
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/tenants/t1/settings", {
        deletion_grace_period_days: 7,
      })
    );
  });

  it("unchecking a group drops its fields from the payload again", async () => {
    // The inverse of the sparse payload: an operator who opens a group, edits
    // it, then decides to inherit after all must not still ship those fields.
    mockLooseGets();
    apiMock.put.mockResolvedValue(res({}));
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    const lockout = await screen.findByRole("checkbox", {
      name: /Override account lockout/,
    });
    await userEvent.click(lockout);
    await retype("Failed attempts before lockout", "3");
    await userEvent.click(lockout);

    expect(
      screen.queryByLabelText("Failed attempts before lockout")
    ).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Save Overrides" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/tenants/t1/settings", {})
    );
  });

  it("warns before OPAQUE 'required' locks the tenant out", async () => {
    // Required refuses password login for everyone without a registration
    // record — including the operator setting it. The panel says so.
    mockLooseGets();
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("checkbox", { name: /Override OPAQUE policy/ })
    );
    expect(
      screen.queryByText(/locks out anyone without a registration record/)
    ).not.toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText("Mode"), "required");
    expect(
      screen.getByText(/locks out anyone without a registration record/)
    ).toBeInTheDocument();
  });

  it("surfaces a failed clear instead of silently leaving the overrides in place", async () => {
    mockGets({ min_length: 16 });
    apiMock.delete.mockRejectedValue({
      response: { status: 403, data: { message: "Forbidden" } },
    });
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("button", { name: /Clear All/ })
    );
    const confirm = await screen.findByRole("dialog");
    await userEvent.click(
      within(confirm).getByRole("button", { name: "Clear overrides" })
    );

    expect(await screen.findByRole("alert")).toHaveTextContent("Forbidden");
    // The dialog closes either way — an operator staring at a spinner over a
    // hidden error message is the failure mode this replaced.
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    );
  });

  it("cancelling the clear dialog leaves the override untouched", async () => {
    mockGets({ min_length: 16 });
    renderWithProviders(<TenantSecurityOverridePanel tenantId="t1" />);

    await userEvent.click(
      await screen.findByRole("button", { name: /Clear All/ })
    );
    const confirm = await screen.findByRole("dialog");
    await userEvent.click(within(confirm).getByRole("button", { name: "Cancel" }));

    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    );
    expect(apiMock.delete).not.toHaveBeenCalled();
    expect(
      screen.getByRole("checkbox", { name: /Override password policy/ })
    ).toBeChecked();
  });
});
