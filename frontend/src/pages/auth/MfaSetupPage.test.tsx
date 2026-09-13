import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

const navigate = vi.fn();
let searchParamsString = "setup_token=setup-tok-1";
vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return {
    ...actual,
    useNavigate: () => navigate,
    useSearchParams: () => [new URLSearchParams(searchParamsString), vi.fn()],
  };
});

import { MfaSetupPage } from "./MfaSetupPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore } from "@/stores/auth";

const enrollData = {
  secret_base32: "JBSWY3DPEHPK3PXP",
  totp_uri: "otpauth://totp/AXIAM:user?secret=JBSWY3DPEHPK3PXP&issuer=AXIAM",
};

beforeEach(() => {
  vi.clearAllMocks();
  searchParamsString = "setup_token=setup-tok-1";
  useAuthStore.setState({
    user: null,
    tenantSlug: null,
    orgSlug: null,
    isAuthenticated: false,
    isInitializing: false,
  });
});

async function getToReadyState() {
  apiMock.post.mockResolvedValueOnce(res(enrollData));
  renderWithProviders(<MfaSetupPage />);
  expect(await screen.findByText("Set up your authenticator")).toBeInTheDocument();
}

describe("MfaSetupPage", () => {
  it("shows the invalid-link state when setup_token is missing", () => {
    searchParamsString = "";
    renderWithProviders(<MfaSetupPage />);
    expect(screen.getByText("Invalid setup link")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to Login" })).toHaveAttribute(
      "href",
      "/login"
    );
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("shows a loading state while enrolling", () => {
    apiMock.post.mockReturnValue(new Promise(() => {}));
    renderWithProviders(<MfaSetupPage />);
    expect(screen.getByText("Preparing your authenticator setup…")).toBeInTheDocument();
  });

  it("enrolls and renders the TOTP setup panel, calling the setup-enroll endpoint", async () => {
    await getToReadyState();
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/mfa/setup/enroll", {
      setup_token: "setup-tok-1",
    });
    expect(screen.getByText(enrollData.secret_base32)).toBeInTheDocument();
    expect(screen.getByLabelText("Verification Code")).toBeInTheDocument();
  });

  it("shows the enroll-error state when enrollment fails", async () => {
    apiMock.post.mockRejectedValueOnce(new Error("expired"));
    renderWithProviders(<MfaSetupPage />);
    expect(await screen.findByText("Invalid setup link")).toBeInTheDocument();
  });

  it("confirms the code, hydrates the user, sets tenant context, and navigates to the dashboard", async () => {
    await getToReadyState();
    apiMock.post.mockResolvedValueOnce(res(undefined)); // setup/confirm
    apiMock.get.mockResolvedValueOnce(
      res({
        user: { id: "u1", username: "alice", email: "alice@x.io", tenant_id: "ten-1" },
        permissions: ["*"],
        tenant_slug: "main",
        org_slug: "acme",
      })
    );

    await userEvent.type(screen.getByLabelText("Verification Code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Confirm & Continue" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/mfa/setup/confirm", {
        setup_token: "setup-tok-1",
        totp_code: "123456",
      })
    );
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));

    expect(useAuthStore.getState().user?.username).toBe("alice");
    expect(useAuthStore.getState().tenantSlug).toBe("main");
    expect(useAuthStore.getState().orgSlug).toBe("acme");
  });

  it("navigates without setting tenant context when fetchCurrentUser returns no slugs", async () => {
    await getToReadyState();
    apiMock.post.mockResolvedValueOnce(res(undefined)); // setup/confirm
    apiMock.get.mockResolvedValueOnce(
      res({
        user: { id: "u1", username: "alice", email: "alice@x.io", tenant_id: "ten-1" },
        permissions: ["*"],
      })
    );

    await userEvent.type(screen.getByLabelText("Verification Code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Confirm & Continue" }));

    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
    expect(useAuthStore.getState().tenantSlug).toBeNull();
  });

  it("navigates even when fetchCurrentUser fails to hydrate (401 on /auth/me)", async () => {
    await getToReadyState();
    apiMock.post.mockResolvedValueOnce(res(undefined)); // setup/confirm
    apiMock.get.mockRejectedValueOnce(new Error("unauthorized"));

    await userEvent.type(screen.getByLabelText("Verification Code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Confirm & Continue" }));

    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
    expect(useAuthStore.getState().user).toBeNull();
  });

  it("shows an inline error for a wrong code without leaving the ready state", async () => {
    await getToReadyState();
    apiMock.post.mockRejectedValueOnce({
      response: { status: 400, data: { message: "Invalid code" } },
    });

    await userEvent.type(screen.getByLabelText("Verification Code"), "000000");
    await userEvent.click(screen.getByRole("button", { name: "Confirm & Continue" }));

    expect(await screen.findByText("Invalid code")).toBeInTheDocument();
    expect(screen.getByText("Set up your authenticator")).toBeInTheDocument();
    expect(navigate).not.toHaveBeenCalled();
  });

  it("falls back to a generic error message when the failure has no response data", async () => {
    await getToReadyState();
    apiMock.post.mockRejectedValueOnce(new Error("boom"));

    await userEvent.type(screen.getByLabelText("Verification Code"), "111111");
    await userEvent.click(screen.getByRole("button", { name: "Confirm & Continue" }));

    expect(
      await screen.findByText("Invalid or expired code. Please try again.")
    ).toBeInTheDocument();
  });

  it("falls back to the error field when message is absent", async () => {
    await getToReadyState();
    apiMock.post.mockRejectedValueOnce({
      response: { status: 400, data: { error: "Bad code" } },
    });

    await userEvent.type(screen.getByLabelText("Verification Code"), "222222");
    await userEvent.click(screen.getByRole("button", { name: "Confirm & Continue" }));

    expect(await screen.findByText("Bad code")).toBeInTheDocument();
  });

  it("bounces to the invalid-link state on a 401/410 token-level failure", async () => {
    await getToReadyState();
    apiMock.post.mockRejectedValueOnce({ response: { status: 410, data: {} } });

    await userEvent.type(screen.getByLabelText("Verification Code"), "333333");
    await userEvent.click(screen.getByRole("button", { name: "Confirm & Continue" }));

    expect(await screen.findByText("Invalid setup link")).toBeInTheDocument();
  });

  it("provides a back-to-login link from the ready state", async () => {
    await getToReadyState();
    expect(screen.getByRole("link", { name: "Back to login" })).toHaveAttribute(
      "href",
      "/login"
    );
  });

  /**
   * M-4 (R-D) — this page is the second half of the OAuth2 login-hop resume:
   * LoginPage's mfa_setup_required branch carries `return_to` here as a query
   * param, and once enrolment completes the user must land back at the
   * pending `/oauth2/authorize` request rather than in the admin UI.
   *
   * `window.location.assign` and not the router — the destination is a server
   * route, exactly as it is for LoginPage's own resume (see that file's
   * `completeSignIn`). jsdom's `location.assign` is not implemented, so it is
   * replaced the same way `LoginPage.test.tsx` replaces it.
   */
  describe("return_to (M-4 / R-D)", () => {
    let assign: ReturnType<typeof vi.fn>;
    beforeEach(() => {
      assign = vi.fn();
      Object.defineProperty(window, "location", {
        configurable: true,
        value: { ...window.location, assign },
      });
    });

    it("resumes the pending authorization request after confirming", async () => {
      const returnTo =
        "/oauth2/authorize?response_type=code&client_id=oa_1&axiam_login_hop=1";
      searchParamsString = `setup_token=setup-tok-1&return_to=${encodeURIComponent(returnTo)}`;
      await getToReadyState();
      apiMock.post.mockResolvedValueOnce(res(undefined)); // setup/confirm
      apiMock.get.mockResolvedValueOnce(
        res({
          user: { id: "u1", username: "alice", email: "alice@x.io", tenant_id: "ten-1" },
          permissions: ["*"],
          tenant_slug: "main",
          org_slug: "acme",
        })
      );

      await userEvent.type(screen.getByLabelText("Verification Code"), "123456");
      await userEvent.click(screen.getByRole("button", { name: "Confirm & Continue" }));

      await waitFor(() => expect(assign).toHaveBeenCalledWith(returnTo));
      expect(navigate).not.toHaveBeenCalledWith("/dashboard");
    });

    it.each([
      ["an off-origin return_to", "https://evil.example/oauth2/authorize?x=1"],
      ["a malformed return_to", "/not-the-authorize-path?x=1"],
    ])("drops %s and lands on /dashboard instead", async (_label, hostile) => {
      searchParamsString = `setup_token=setup-tok-1&return_to=${encodeURIComponent(hostile)}`;
      await getToReadyState();
      apiMock.post.mockResolvedValueOnce(res(undefined)); // setup/confirm
      apiMock.get.mockResolvedValueOnce(
        res({
          user: { id: "u1", username: "alice", email: "alice@x.io", tenant_id: "ten-1" },
          permissions: ["*"],
          tenant_slug: "main",
          org_slug: "acme",
        })
      );

      await userEvent.type(screen.getByLabelText("Verification Code"), "123456");
      await userEvent.click(screen.getByRole("button", { name: "Confirm & Continue" }));

      await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
      expect(assign).not.toHaveBeenCalled();
    });

    it("lands on /dashboard when no return_to was carried at all", async () => {
      await getToReadyState();
      apiMock.post.mockResolvedValueOnce(res(undefined)); // setup/confirm
      apiMock.get.mockResolvedValueOnce(
        res({
          user: { id: "u1", username: "alice", email: "alice@x.io", tenant_id: "ten-1" },
          permissions: ["*"],
        })
      );

      await userEvent.type(screen.getByLabelText("Verification Code"), "123456");
      await userEvent.click(screen.getByRole("button", { name: "Confirm & Continue" }));

      await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
      expect(assign).not.toHaveBeenCalled();
    });
  });
});
