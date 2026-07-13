import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

const navigate = vi.fn();
vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return { ...actual, useNavigate: () => navigate };
});

import { LoginPage } from "./LoginPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore } from "@/stores/auth";

const loginUser = {
  id: "u1",
  username: "alice",
  email: "alice@example.com",
  tenant_id: "tenant-1",
};

/** Drive the org/tenant step (step 1) then land on the credentials step. */
async function goToCredentials(route = "/login") {
  const utils = renderWithProviders(<LoginPage />, { route });
  await userEvent.type(screen.getByLabelText("Organization slug"), "acme");
  await userEvent.type(screen.getByLabelText("Tenant slug"), "default");
  await userEvent.click(screen.getByRole("button", { name: /Continue/ }));
  await screen.findByRole("heading", { name: "Sign in" });
  return utils;
}

async function submitCredentials(username = "alice", password = "hunter2") {
  await userEvent.type(screen.getByLabelText("Username or email"), username);
  await userEvent.type(screen.getByLabelText("Password"), password);
  await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMock.get.mockRejectedValue(new Error("unexpected get"));
  apiMock.post.mockRejectedValue(new Error("unexpected post"));
  useAuthStore.getState().clearAuth();
});

afterEach(() => {
  useAuthStore.getState().clearAuth();
});

describe("LoginPage — org/tenant step", () => {
  it("requires both organization and tenant slug", async () => {
    renderWithProviders(<LoginPage />);
    await userEvent.click(screen.getByRole("button", { name: /Continue/ }));
    expect(
      await screen.findByText("Please enter both organization and tenant slug.")
    ).toBeInTheDocument();
  });

  it("advances to the credentials step once both slugs are filled", async () => {
    await goToCredentials();
    expect(screen.getByText("acme/default")).toBeInTheDocument();
  });

  it("shows the bootstrap notice when ?bootstrapped=1 is present and strips the query param", async () => {
    renderWithProviders(<LoginPage />, { route: "/login?bootstrapped=1" });
    expect(
      await screen.findByText("Admin account created. Sign in to continue.")
    ).toBeInTheDocument();
  });
});

describe("LoginPage — credentials step", () => {
  it("requires username and password", async () => {
    await goToCredentials();
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(
      await screen.findByText("Please enter your username and password.")
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("goes back to the org/tenant step", async () => {
    await goToCredentials();
    await userEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(
      screen.getByText("Enter your organization and tenant to continue.")
    ).toBeInTheDocument();
  });

  it("logs in, hydrates via /auth/me, updates the store and navigates to /dashboard", async () => {
    apiMock.post.mockImplementation((url: string) => {
      if (url === "/api/v1/auth/login") {
        return Promise.resolve(res({ user: loginUser, session_id: "s1", expires_in: 900 }));
      }
      return Promise.reject(new Error("unexpected post " + url));
    });
    apiMock.get.mockImplementation((url: string) => {
      if (url === "/api/v1/auth/me") {
        return Promise.resolve(
          res({
            user: loginUser,
            permissions: ["*"],
            tenant_slug: "default",
            org_slug: "acme",
          })
        );
      }
      return Promise.reject(new Error("unexpected get " + url));
    });

    await goToCredentials();
    await submitCredentials();

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/login", {
        username: "alice",
        password: "hunter2",
        tenant_slug: "default",
        org_slug: "acme",
      })
    );
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
    expect(useAuthStore.getState().user?.permissions).toEqual(["*"]);
    expect(useAuthStore.getState().tenantSlug).toBe("default");
    expect(useAuthStore.getState().orgSlug).toBe("acme");
  });

  it("falls back to the login payload with empty permissions when /auth/me fails", async () => {
    apiMock.post.mockImplementation((url: string) => {
      if (url === "/api/v1/auth/login") {
        return Promise.resolve(res({ user: loginUser }));
      }
      return Promise.reject(new Error("unexpected post " + url));
    });
    apiMock.get.mockRejectedValue(new Error("network down"));

    await goToCredentials();
    await submitCredentials();

    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
    expect(useAuthStore.getState().user).toEqual({ ...loginUser, permissions: [] });
  });

  it("moves to the MFA step when mfa_required is returned", async () => {
    apiMock.post.mockResolvedValue(
      res({ mfa_required: true, challenge_token: "chal-1" })
    );
    await goToCredentials();
    await submitCredentials();
    expect(
      await screen.findByText("Two-factor authentication")
    ).toBeInTheDocument();
  });

  it("navigates to mfa-setup with the setup token when mfa_setup_required is returned", async () => {
    apiMock.post.mockResolvedValue(
      res({ mfa_setup_required: true, setup_token: "setup-abc" })
    );
    await goToCredentials();
    await submitCredentials();
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith(
        "/auth/mfa-setup?setup_token=setup-abc"
      )
    );
  });

  it("navigates to mfa-setup with an empty token when setup_token is missing", async () => {
    apiMock.post.mockResolvedValue(res({ mfa_setup_required: true }));
    await goToCredentials();
    await submitCredentials();
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("/auth/mfa-setup?setup_token=")
    );
  });

  it("shows a generic auth error and redirects to /login when no user or mfa flags come back", async () => {
    apiMock.post.mockResolvedValue(res({}));
    await goToCredentials();
    await submitCredentials();
    expect(
      await screen.findByText("Authentication error. Please sign in again.")
    ).toBeInTheDocument();
    expect(navigate).toHaveBeenCalledWith("/login");
  });

  it("shows a security-rejection message on a 403 response", async () => {
    apiMock.post.mockRejectedValue({ response: { status: 403 } });
    await goToCredentials();
    await submitCredentials();
    expect(
      await screen.findByText(
        "Request rejected for security reasons. Please refresh the page and try again."
      )
    ).toBeInTheDocument();
  });

  it("surfaces a server-provided error message", async () => {
    apiMock.post.mockRejectedValue({
      response: { status: 401, data: { message: "Bad credentials" } },
    });
    await goToCredentials();
    await submitCredentials();
    expect(await screen.findByText("Bad credentials")).toBeInTheDocument();
  });

  it("falls back to the error field, then a default message, on failure", async () => {
    apiMock.post.mockRejectedValue({
      response: { status: 401, data: { error: "err-field" } },
    });
    await goToCredentials();
    await submitCredentials();
    expect(await screen.findByText("err-field")).toBeInTheDocument();
  });

  it("shows the default invalid-credentials message for a bare network error", async () => {
    apiMock.post.mockRejectedValue(new Error("network down"));
    await goToCredentials();
    await submitCredentials();
    expect(
      await screen.findByText("Invalid credentials. Please try again.")
    ).toBeInTheDocument();
  });

  it("shows a signing-in busy state while the login request is pending", async () => {
    let resolvePost: (v: unknown) => void = () => {};
    apiMock.post.mockReturnValue(
      new Promise((resolve) => {
        resolvePost = resolve;
      })
    );
    await goToCredentials();
    await userEvent.type(screen.getByLabelText("Username or email"), "alice");
    await userEvent.type(screen.getByLabelText("Password"), "hunter2");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Signing in...")).toBeInTheDocument();
    resolvePost(res({}));
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/login"));
  });
});

describe("LoginPage — MFA step", () => {
  async function goToMfa() {
    apiMock.post.mockImplementation((url: string) => {
      if (url === "/api/v1/auth/login") {
        return Promise.resolve(
          res({ mfa_required: true, challenge_token: "chal-1" })
        );
      }
      return Promise.reject(new Error("unexpected post " + url));
    });
    await goToCredentials();
    await submitCredentials();
    await screen.findByText("Two-factor authentication");
  }

  it("requires a full 6-digit code", async () => {
    await goToMfa();
    await userEvent.type(screen.getByLabelText("Authentication code"), "123");
    await userEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(
      await screen.findByText(
        "Please enter the 6-digit code from your authenticator app."
      )
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalledWith(
      "/api/v1/auth/mfa/verify",
      expect.anything()
    );
  });

  it("strips non-digit characters and caps the code at 6 digits", async () => {
    await goToMfa();
    const input = screen.getByLabelText("Authentication code");
    await userEvent.type(input, "12a3456789");
    expect(input).toHaveValue("123456");
  });

  it("goes back to the credentials step and clears the code", async () => {
    await goToMfa();
    await userEvent.type(screen.getByLabelText("Authentication code"), "123");
    await userEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(
      screen.getByRole("heading", { name: "Sign in" })
    ).toBeInTheDocument();
  });

  it("verifies the code, hydrates via /auth/me and navigates to /dashboard", async () => {
    // goToMfa() re-installs the post mock (login → mfa_required), so configure
    // the verify handler AFTER reaching the MFA step or it would be clobbered.
    await goToMfa();
    apiMock.post.mockImplementation((url: string) => {
      if (url === "/api/v1/auth/mfa/verify") {
        return Promise.resolve(res({ user: loginUser }));
      }
      return Promise.reject(new Error("unexpected post " + url));
    });
    apiMock.get.mockImplementation((url: string) => {
      if (url === "/api/v1/auth/me") {
        return Promise.resolve(
          res({ user: loginUser, permissions: ["read"] })
        );
      }
      return Promise.reject(new Error("unexpected get " + url));
    });

    await userEvent.type(screen.getByLabelText("Authentication code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/mfa/verify", {
        challenge_token: "chal-1",
        totp_code: "123456",
      })
    );
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
  });

  it("shows a generic auth error and redirects to /login when verify returns no user", async () => {
    await goToMfa();
    apiMock.post.mockImplementation((url: string) => {
      if (url === "/api/v1/auth/mfa/verify") {
        return Promise.resolve(res({}));
      }
      return Promise.reject(new Error("unexpected post " + url));
    });
    await userEvent.type(screen.getByLabelText("Authentication code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(
      await screen.findByText("Authentication error. Please sign in again.")
    ).toBeInTheDocument();
    expect(navigate).toHaveBeenCalledWith("/login");
  });

  it("shows a security-rejection message on a 403 verify response", async () => {
    await goToMfa();
    apiMock.post.mockImplementation((url: string) => {
      if (url === "/api/v1/auth/mfa/verify") {
        return Promise.reject({ response: { status: 403 } });
      }
      return Promise.reject(new Error("unexpected post " + url));
    });
    await userEvent.type(screen.getByLabelText("Authentication code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(
      await screen.findByText(
        "Request rejected for security reasons. Please refresh the page and try again."
      )
    ).toBeInTheDocument();
  });

  it("shows the default invalid-or-expired message for a bare verify failure", async () => {
    apiMock.post.mockImplementation((url: string) => {
      if (url === "/api/v1/auth/login") {
        return Promise.resolve(
          res({ mfa_required: true, challenge_token: "chal-1" })
        );
      }
      if (url === "/api/v1/auth/mfa/verify") {
        return Promise.reject(new Error("boom"));
      }
      return Promise.reject(new Error("unexpected post " + url));
    });
    await goToMfa();
    await userEvent.type(screen.getByLabelText("Authentication code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(
      await screen.findByText("Invalid or expired MFA code.")
    ).toBeInTheDocument();
  });

  it("shows a verifying busy state while the verify request is pending", async () => {
    let resolveVerify: (v: unknown) => void = () => {};
    await goToMfa();
    apiMock.post.mockImplementation((url: string) => {
      if (url === "/api/v1/auth/mfa/verify") {
        return new Promise((resolve) => {
          resolveVerify = resolve;
        });
      }
      return Promise.reject(new Error("unexpected post " + url));
    });
    await userEvent.type(screen.getByLabelText("Authentication code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByText("Verifying...")).toBeInTheDocument();
    resolveVerify(res({}));
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/login"));
  });
});
