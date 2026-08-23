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
