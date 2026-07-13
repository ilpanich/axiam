import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor, fireEvent } from "@testing-library/react";
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
