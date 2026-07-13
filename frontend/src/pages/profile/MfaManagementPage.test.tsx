import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { MfaManagementPage } from "./MfaManagementPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore, type AuthUser } from "@/stores/auth";

const user: AuthUser = {
  id: "u1",
  username: "admin",
  email: "a@x.io",
  permissions: ["*"],
  tenant_id: "t1",
  tenantSlug: "acme",
  orgSlug: "acme-org",
};

const methods = [
  { id: "m1", method_type: "totp", name: "Phone authenticator", created_at: "2026-01-01T00:00:00Z" },
];

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({
    user,
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

describe("MfaManagementPage", () => {
  it("renders registered MFA methods", async () => {
    apiMock.get.mockResolvedValue(res(methods));
    renderWithProviders(<MfaManagementPage />);
    expect(await screen.findByText("Phone authenticator")).toBeInTheDocument();
    expect(screen.getByText("TOTP")).toBeInTheDocument();
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/users/u1/mfa-methods");
  });

  it("shows the empty state when there are no methods", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<MfaManagementPage />);
    expect(
      await screen.findByText(/No MFA methods registered/)
    ).toBeInTheDocument();
  });

  it("starts TOTP setup, opens the dialog, and confirms with a valid code", async () => {
    apiMock.get.mockResolvedValue(res([]));
    apiMock.post.mockImplementation((url: string) => {
      if (url === "/api/v1/auth/mfa/enroll") {
        return Promise.resolve(
          res({ secret_base32: "ABC123SECRET", totp_uri: "otpauth://totp/test" })
        );
      }
      if (url === "/api/v1/auth/mfa/confirm") {
        return Promise.resolve(res(undefined));
      }
      return Promise.reject(new Error("unexpected " + url));
    });

    renderWithProviders(<MfaManagementPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Set up TOTP Authenticator" })
    );

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("ABC123SECRET")).toBeInTheDocument();

    const codeInput = within(dialog).getByLabelText("Verification Code");
    await userEvent.type(codeInput, "123456");
    await userEvent.click(within(dialog).getByRole("button", { name: "Confirm" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/mfa/confirm", {
        totp_code: "123456",
      })
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("shows an error alert when starting TOTP setup fails", async () => {
    apiMock.get.mockResolvedValue(res([]));
    apiMock.post.mockRejectedValue(new Error("network down"));
    renderWithProviders(<MfaManagementPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Set up TOTP Authenticator" })
    );
    expect(
      await screen.findByText("Failed to start TOTP setup. Please try again.")
    ).toBeInTheDocument();
  });

  it("surfaces a confirm error inside the dialog and keeps it open", async () => {
    apiMock.get.mockResolvedValue(res([]));
    apiMock.post.mockImplementation((url: string) => {
      if (url === "/api/v1/auth/mfa/enroll") {
        return Promise.resolve(
          res({ secret_base32: "SECRETXYZ", totp_uri: "otpauth://totp/test2" })
        );
      }
      if (url === "/api/v1/auth/mfa/confirm") {
        return Promise.reject({ response: { data: { message: "Invalid code." } } });
      }
      return Promise.reject(new Error("unexpected " + url));
    });

    renderWithProviders(<MfaManagementPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Set up TOTP Authenticator" })
    );
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Verification Code"), "000000");
    await userEvent.click(within(dialog).getByRole("button", { name: "Confirm" }));

    expect(await screen.findByText("Invalid code.")).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("closes the TOTP dialog via Cancel and clears state", async () => {
    apiMock.get.mockResolvedValue(res([]));
    apiMock.post.mockResolvedValue(
      res({ secret_base32: "SECRET2", totp_uri: "otpauth://totp/test3" })
    );
    renderWithProviders(<MfaManagementPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Set up TOTP Authenticator" })
    );
    const dialog = await screen.findByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("deletes an MFA method after confirmation", async () => {
    apiMock.get.mockResolvedValue(res(methods));
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<MfaManagementPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Remove Phone authenticator" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Remove "Phone authenticator"/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Remove" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/users/u1/mfa-methods/m1")
    );
  });

  it("closes the delete confirm dialog on cancel without deleting", async () => {
    apiMock.get.mockResolvedValue(res(methods));
    renderWithProviders(<MfaManagementPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Remove Phone authenticator" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(apiMock.delete).not.toHaveBeenCalled();
  });

  it("shows the disabled 'Coming soon' passkeys section", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<MfaManagementPage />);
    expect(await screen.findByText("Coming soon")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Add Passkey/ })).toBeDisabled();
  });
});
