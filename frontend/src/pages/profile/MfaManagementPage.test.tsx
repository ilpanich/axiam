import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

// C1: the WebAuthn ceremony itself is browser API surface jsdom does not
// implement, so the thin helper around it is mocked and the page's own
// behaviour (feature gating, naming, error copy, cache invalidation) is what
// gets tested. The ceremony's *contract* with the server is covered by
// services/webauthn.test.ts.
const registerMock = vi.fn();
let webauthnSupported = true;
vi.mock("@/services/webauthn", async () => {
  const actual = await vi.importActual<typeof import("@/services/webauthn")>(
    "@/services/webauthn",
  );
  return {
    ...actual,
    isWebauthnSupported: () => webauthnSupported,
    webauthnService: { register: (...a: unknown[]) => registerMock(...a) },
  };
});

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
  webauthnSupported = true;
  // `classifyWebauthnError` consults the REAL feature detection (it is
  // deliberately not mocked — its whole job is to say "unsupported" when the
  // browser cannot do WebAuthn at all). jsdom has no PublicKeyCredential, so
  // the error-classification tests need one present or every failure would
  // classify as "unsupported" regardless of its DOMException name.
  Object.defineProperty(window, "PublicKeyCredential", {
    value: function PublicKeyCredential() {},
    configurable: true,
    writable: true,
  });
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

  it("no longer advertises passkeys as unavailable (C1)", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<MfaManagementPage />);

    await screen.findByText("Passkeys & security keys");
    // The panel used to be a disabled "Coming soon" teaser while the server
    // had shipped the full ceremonies for releases. Asserting its absence is
    // what stops it coming back.
    expect(screen.queryByText(/coming soon/i)).not.toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// C1 — passkeys & security keys
// ---------------------------------------------------------------------------

describe("MfaManagementPage — passkeys (C1)", () => {
  it("offers both enrolment flows when the browser supports WebAuthn", async () => {
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<MfaManagementPage />);

    expect(
      await screen.findByRole("button", { name: /add a passkey/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /add a security key/i }),
    ).toBeInTheDocument();
  });

  it("hides the buttons and explains why on an unsupported browser", async () => {
    webauthnSupported = false;
    apiMock.get.mockResolvedValue(res([]));
    renderWithProviders(<MfaManagementPage />);

    expect(
      await screen.findByText(/does not support passkeys/i),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /add a passkey/i }),
    ).not.toBeInTheDocument();
  });

  it("registers a platform authenticator when 'Add a passkey' is used", async () => {
    apiMock.get.mockResolvedValue(res([]));
    registerMock.mockResolvedValue(undefined);
    renderWithProviders(<MfaManagementPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: /add a passkey/i }),
    );

    await waitFor(() =>
      expect(registerMock).toHaveBeenCalledWith("Passkey", "platform"),
    );
  });

  it("registers a cross-platform authenticator for a security key", async () => {
    apiMock.get.mockResolvedValue(res([]));
    registerMock.mockResolvedValue(undefined);
    renderWithProviders(<MfaManagementPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: /add a security key/i }),
    );

    await waitFor(() =>
      expect(registerMock).toHaveBeenCalledWith("Security key", "cross-platform"),
    );
  });

  it("numbers additional credentials so they can be told apart later", async () => {
    apiMock.get.mockResolvedValue(
      res([
        { id: "m1", method_type: "totp", name: "Phone", created_at: "2026-01-01T00:00:00Z" },
        { id: "m2", method_type: "passkey", name: "Passkey", created_at: "2026-01-01T00:00:00Z" },
      ]),
    );
    registerMock.mockResolvedValue(undefined);
    renderWithProviders(<MfaManagementPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: /add a passkey/i }),
    );

    // One existing WebAuthn credential (the TOTP row does not count), so the
    // next one is #2 — "Passkey" twice in the list would be useless.
    await waitFor(() =>
      expect(registerMock).toHaveBeenCalledWith("Passkey 2", "platform"),
    );
  });

  it("shows actionable copy when the user cancels the ceremony", async () => {
    apiMock.get.mockResolvedValue(res([]));
    const err = new Error("nope");
    err.name = "NotAllowedError";
    registerMock.mockRejectedValue(err);
    renderWithProviders(<MfaManagementPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: /add a passkey/i }),
    );

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/cancelled or timed out/i);
  });

  it("explains a duplicate credential rather than showing a generic error", async () => {
    apiMock.get.mockResolvedValue(res([]));
    const err = new Error("dup");
    err.name = "InvalidStateError";
    registerMock.mockRejectedValue(err);
    renderWithProviders(<MfaManagementPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: /add a security key/i }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(/already registered/i);
  });

  it("distinguishes passkeys from security keys in the list", async () => {
    apiMock.get.mockResolvedValue(
      res([
        { id: "m1", method_type: "Passkey", name: "MacBook", created_at: "2026-01-01T00:00:00Z" },
        { id: "m2", method_type: "SecurityKey", name: "YubiKey", created_at: "2026-01-01T00:00:00Z" },
      ]),
    );
    renderWithProviders(<MfaManagementPage />);

    // A user deciding what to remove needs to tell the rows apart; one
    // "WEBAUTHN" badge on both would make that guesswork.
    expect(await screen.findByText("Passkey")).toBeInTheDocument();
    expect(screen.getByText("Security key")).toBeInTheDocument();
  });
});
