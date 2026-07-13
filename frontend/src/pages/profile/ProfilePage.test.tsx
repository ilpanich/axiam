import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { ProfilePage } from "./ProfilePage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore, type AuthUser } from "@/stores/auth";

const authUser: AuthUser = {
  id: "u1",
  username: "admin",
  email: "admin@x.io",
  permissions: ["*"],
  tenant_id: "t1",
  tenantSlug: "acme",
  orgSlug: "acme-org",
};

const profile = {
  id: "u1",
  username: "admin",
  email: "admin@x.io",
  display_name: "Admin User",
  mfa_enabled: false,
  email_verified: true,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  status: "Active",
  metadata: { display_name: "Admin User" },
  is_locked: false,
  locked_until: null,
  failed_login_attempts: 0,
};

function mockGetByUrl(handlers: Record<string, unknown>) {
  apiMock.get.mockImplementation((url: string) => {
    for (const key of Object.keys(handlers)) {
      if (url === key) return Promise.resolve(res(handlers[key]));
    }
    return Promise.reject(new Error("unexpected GET " + url));
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({
    user: authUser,
    tenantSlug: "acme",
    orgSlug: "acme-org",
    isAuthenticated: true,
    isInitializing: false,
  });
});

afterEach(() => {
  useAuthStore.setState({
    user: null,
    tenantSlug: null,
    orgSlug: null,
    isAuthenticated: false,
    isInitializing: true,
  });
});

describe("ProfilePage", () => {
  it("shows a loading spinner before data resolves", () => {
    apiMock.get.mockReturnValue(new Promise(() => {}));
    const { container } = renderWithProviders(<ProfilePage />);
    // While loading, only a spinner renders (the "My Profile" header and all
    // profile content are gated behind the resolved query).
    expect(container.querySelector("svg.animate-spin")).toBeInTheDocument();
    expect(screen.queryByText("My Profile")).not.toBeInTheDocument();
    expect(screen.queryByText("@admin")).not.toBeInTheDocument();
  });

  it("shows an error message when the profile fails to load", async () => {
    apiMock.get.mockRejectedValue(new Error("boom"));
    renderWithProviders(<ProfilePage />);
    expect(
      await screen.findByText("Failed to load profile. Please refresh the page.")
    ).toBeInTheDocument();
  });

  it("renders profile details, verified badge, and MFA enabled status", async () => {
    mockGetByUrl({
      "/api/v1/users/u1": profile,
      "/api/v1/users/u1/mfa-methods": [
        { id: "m1", method_type: "totp", name: "Auth app", created_at: "2026-01-01T00:00:00Z" },
      ],
    });
    renderWithProviders(<ProfilePage />);
    expect(await screen.findAllByText("Admin User")).toHaveLength(2);
    expect(screen.getByText("@admin")).toBeInTheDocument();
    expect(screen.getByText("Verified")).toBeInTheDocument();
    expect(await screen.findByText("Enabled · 1 method")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Change Password" })).toHaveAttribute(
      "href",
      "/profile/change-password"
    );
    expect(screen.getByRole("link", { name: "Manage MFA" })).toHaveAttribute(
      "href",
      "/profile/mfa"
    );
  });

  it("shows Unverified badge, resend button, and pluralized MFA disabled copy", async () => {
    mockGetByUrl({
      "/api/v1/users/u1": { ...profile, email_verified: false },
      "/api/v1/users/u1/mfa-methods": [],
    });
    renderWithProviders(<ProfilePage />);
    expect(await screen.findByText("Unverified")).toBeInTheDocument();
    expect(screen.getByText("Disabled — recommended for security")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Resend verification email" })
    ).toBeInTheDocument();
  });

  it("resends the verification email successfully", async () => {
    mockGetByUrl({
      "/api/v1/users/u1": { ...profile, email_verified: false },
      "/api/v1/users/u1/mfa-methods": [],
    });
    apiMock.post.mockResolvedValue(res(undefined));
    renderWithProviders(<ProfilePage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Resend verification email" })
    );
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/resend-verification", {
        tenant_id: "t1",
        email: "admin@x.io",
      })
    );
    expect(
      await screen.findByText("Verification email sent. Please check your inbox.")
    ).toBeInTheDocument();
  });

  it("shows a failure message when the resend mutation errors", async () => {
    mockGetByUrl({
      "/api/v1/users/u1": { ...profile, email_verified: false },
      "/api/v1/users/u1/mfa-methods": [],
    });
    apiMock.post.mockRejectedValue(new Error("nope"));
    renderWithProviders(<ProfilePage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Resend verification email" })
    );
    expect(
      await screen.findByText("Failed to resend verification email. Try again later.")
    ).toBeInTheDocument();
  });

  it("rejects resend locally when tenant context/email is missing from the store", async () => {
    mockGetByUrl({
      "/api/v1/users/u1": { ...profile, email_verified: false },
      "/api/v1/users/u1/mfa-methods": [],
    });
    useAuthStore.setState({ user: { ...authUser, tenant_id: "", email: "" } });
    renderWithProviders(<ProfilePage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Resend verification email" })
    );
    expect(
      await screen.findByText("Failed to resend verification email. Try again later.")
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("enters edit mode, submits updated fields, and returns to view mode", async () => {
    mockGetByUrl({
      "/api/v1/users/u1": profile,
      "/api/v1/users/u1/mfa-methods": [],
    });
    apiMock.put.mockResolvedValue(res({ ...profile, display_name: "New Name" }));
    renderWithProviders(<ProfilePage />);

    await userEvent.click(await screen.findByRole("button", { name: /Edit Profile/ }));
    const displayNameInput = screen.getByLabelText("Display Name");
    await userEvent.clear(displayNameInput);
    await userEvent.type(displayNameInput, "New Name");
    await userEvent.click(screen.getByRole("button", { name: "Save Changes" }));

    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith("/api/v1/users/u1", {
        email: "admin@x.io",
        metadata: { display_name: "New Name" },
      })
    );
    await waitFor(() =>
      expect(screen.queryByLabelText("Display Name")).not.toBeInTheDocument()
    );
  });

  it("shows an error banner in edit mode when the update fails", async () => {
    mockGetByUrl({
      "/api/v1/users/u1": profile,
      "/api/v1/users/u1/mfa-methods": [],
    });
    apiMock.put.mockRejectedValue({ response: { data: { error: "Email already in use." } } });
    renderWithProviders(<ProfilePage />);

    await userEvent.click(await screen.findByRole("button", { name: /Edit Profile/ }));
    await userEvent.click(screen.getByRole("button", { name: "Save Changes" }));

    expect(await screen.findByText("Email already in use.")).toBeInTheDocument();
  });

  it("cancels edit mode without saving", async () => {
    mockGetByUrl({
      "/api/v1/users/u1": profile,
      "/api/v1/users/u1/mfa-methods": [],
    });
    renderWithProviders(<ProfilePage />);
    await userEvent.click(await screen.findByRole("button", { name: /Edit Profile/ }));
    expect(screen.getByLabelText("Display Name")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByLabelText("Display Name")).not.toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("omits the display name section in view mode when unset", async () => {
    mockGetByUrl({
      "/api/v1/users/u1": { ...profile, display_name: undefined, metadata: {} },
      "/api/v1/users/u1/mfa-methods": [],
    });
    renderWithProviders(<ProfilePage />);
    expect(await screen.findByText("@admin")).toBeInTheDocument();
    expect(screen.queryByText("Display Name")).not.toBeInTheDocument();
  });
});
