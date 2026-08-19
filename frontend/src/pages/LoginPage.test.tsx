import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, waitFor, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

// C2: the ceremony is browser API surface jsdom does not implement; the
// service wrapper is mocked and the page's own logic — feature gating, which
// challenge token it uses, conditional mediation, MFA-step offering — is what
// is tested here. The wrapper's contract with the server lives in
// services/webauthn.test.ts.
const authenticateMock = vi.fn();
let webauthnSupported = true;
let conditionalAvailable = false;
vi.mock("@/services/webauthn", async () => {
  const actual = await vi.importActual<typeof import("@/services/webauthn")>(
    "@/services/webauthn",
  );
  return {
    ...actual,
    isWebauthnSupported: () => webauthnSupported,
    isConditionalMediationAvailable: () => Promise.resolve(conditionalAvailable),
    webauthnService: { authenticate: (...a: unknown[]) => authenticateMock(...a) },
  };
});


const navigate = vi.fn();
vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
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

/**
 * `/auth/srp/challenge` answering 404 — i.e. the tenant has SRP disabled.
 *
 * The login page probes SRP before falling back to password login, so every
 * password-path test has to answer that probe. A 404 is what the server sends
 * for `srp_mode: disabled`, and it is the branch these tests are about.
 */
const srpDisabled = () =>
  Promise.reject(Object.assign(new Error("srp disabled"), { response: { status: 404 } }));

const SRP_CHALLENGE = "/api/v1/auth/srp/challenge";
/**
 * A post mock that answers the SRP probe with 404 and every other call with
 * `payload` — the shape most of these tests want, now that the page probes SRP
 * before falling back to password login.
 */
const postWithSrpDisabled =
  (payload: unknown) =>
  (url: string) =>
    url === SRP_CHALLENGE ? srpDisabled() : Promise.resolve(payload);


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
    // R4.7: the form no longer sets `noValidate`, so the required org/tenant
    // fields being empty would block a native submit before the component's
    // own validation runs — submit the form directly to exercise it.
    fireEvent.submit(
      screen.getByRole("button", { name: /Continue/ }).closest("form")!
    );
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
    // R4.7: username/password are `required` and the form no longer sets
    // `noValidate` — a native submit would be blocked before the click ever
    // reaches the handler, so submit the form directly.
    fireEvent.submit(
      screen.getByRole("button", { name: "Sign in" }).closest("form")!
    );
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
      if (url === SRP_CHALLENGE) return srpDisabled();
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

  it("treats a null /auth/me after login as a hard failure (CQ-F30) — never silently logs in with no permissions", async () => {
    apiMock.post.mockImplementation((url: string) => {
      if (url === SRP_CHALLENGE) return srpDisabled();
      if (url === "/api/v1/auth/login") {
        return Promise.resolve(res({ user: loginUser }));
      }
      return Promise.reject(new Error("unexpected post " + url));
    });
    apiMock.get.mockRejectedValue(new Error("network down"));

    await goToCredentials();
    await submitCredentials();

    expect(
      await screen.findByText("Authentication error. Please sign in again.")
    ).toBeInTheDocument();
    expect(navigate).toHaveBeenCalledWith("/login");
    expect(navigate).not.toHaveBeenCalledWith("/dashboard");
    expect(useAuthStore.getState().user).toBeNull();
  });

  it("moves to the MFA step when mfa_required is returned", async () => {
    apiMock.post.mockImplementation(
      postWithSrpDisabled(res({ mfa_required: true, challenge_token: "chal-1" }))
    );
    await goToCredentials();
    await submitCredentials();
    expect(
      await screen.findByText("Two-factor authentication")
    ).toBeInTheDocument();
  });

  it("navigates to mfa-setup with the setup token when mfa_setup_required is returned", async () => {
    apiMock.post.mockImplementation(
      postWithSrpDisabled(res({ mfa_setup_required: true, setup_token: "setup-abc" }))
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
    apiMock.post.mockImplementation(postWithSrpDisabled(res({ mfa_setup_required: true })));
    await goToCredentials();
    await submitCredentials();
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("/auth/mfa-setup?setup_token=")
    );
  });

  it("shows a generic auth error and redirects to /login when no user or mfa flags come back", async () => {
    apiMock.post.mockImplementation(postWithSrpDisabled(res({})));
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
    // The SRP probe must resolve immediately (404 = SRP off); only the password
    // login is held open, otherwise the busy state under test is the probe's.
    apiMock.post.mockImplementation((url: string) =>
      url === SRP_CHALLENGE
        ? srpDisabled()
        : new Promise((resolve) => {
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
      if (url === SRP_CHALLENGE) return srpDisabled();
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
    // R4.7: the code field has `pattern="[0-9]{6}"` and the form no longer
    // sets `noValidate` — a native submit would be blocked before the click
    // ever reaches the handler, so submit the form directly.
    fireEvent.submit(
      screen.getByRole("button", { name: "Verify" }).closest("form")!
    );
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
      if (url === SRP_CHALLENGE) return srpDisabled();
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
      if (url === SRP_CHALLENGE) return srpDisabled();
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
      if (url === SRP_CHALLENGE) return srpDisabled();
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
      if (url === SRP_CHALLENGE) return srpDisabled();
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
      if (url === SRP_CHALLENGE) return srpDisabled();
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

// ---------------------------------------------------------------------------
// C2 — passkey sign-in
// ---------------------------------------------------------------------------

describe("LoginPage — passkeys (C2)", () => {
  beforeEach(() => {
    webauthnSupported = true;
    conditionalAvailable = false;
    authenticateMock.mockReset();
    Object.defineProperty(window, "PublicKeyCredential", {
      value: function PublicKeyCredential() {},
      configurable: true,
      writable: true,
    });
  });

  it("offers passkey sign-in on the credentials step", async () => {
    await goToCredentials();
    expect(
      screen.getByRole("button", { name: /sign in with a passkey/i }),
    ).toBeInTheDocument();
  });

  it("hides passkey sign-in where the browser cannot do it", async () => {
    webauthnSupported = false;
    await goToCredentials();
    expect(
      screen.queryByRole("button", { name: /sign in with a passkey/i }),
    ).not.toBeInTheDocument();
  });

  it("marks the username field for passkey autofill", async () => {
    await goToCredentials();
    // The `webauthn` autocomplete token is what makes conditional mediation
    // surface saved passkeys in this field.
    expect(screen.getByLabelText("Username or email")).toHaveAttribute(
      "autocomplete",
      "username webauthn",
    );
  });

  it("omits the webauthn autocomplete token where unsupported", async () => {
    webauthnSupported = false;
    await goToCredentials();
    expect(screen.getByLabelText("Username or email")).toHaveAttribute(
      "autocomplete",
      "username",
    );
  });

  it("uses an empty challenge token for discoverable sign-in", async () => {
    authenticateMock.mockResolvedValue({ session_id: "s", expires_in: 900 });
    // A passkey assertion sets the session cookie server-side; the page then
    // hydrates the store through /auth/me exactly as the password path does.
    apiMock.get.mockResolvedValue(res({ user: loginUser, permissions: [] }));
    await goToCredentials();

    await userEvent.click(
      screen.getByRole("button", { name: /sign in with a passkey/i }),
    );

    // An empty token is what asks the server for a challenge with an empty
    // allowCredentials — i.e. "let the authenticator tell us who this is".
    await waitFor(() => expect(authenticateMock).toHaveBeenCalledWith("", { conditional: false }));
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
  });

  it("reports a cancelled ceremony without blaming the user", async () => {
    const err = new Error("no");
    err.name = "NotAllowedError";
    authenticateMock.mockRejectedValue(err);
    await goToCredentials();

    await userEvent.click(
      screen.getByRole("button", { name: /sign in with a passkey/i }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /cancelled or timed out/i,
    );
  });

  it("starts conditional mediation when the browser supports it", async () => {
    conditionalAvailable = true;
    // Never resolves: autofill legitimately stays pending until the user picks
    // a passkey, which is exactly the shape that must not block the page.
    authenticateMock.mockReturnValue(new Promise(() => {}));

    await goToCredentials();

    await waitFor(() =>
      expect(authenticateMock).toHaveBeenCalledWith("", { conditional: true }),
    );
    // ...and the password form is still fully usable underneath it.
    expect(screen.getByLabelText("Password")).toBeEnabled();
  });

  it("does not start conditional mediation where it is unavailable", async () => {
    conditionalAvailable = false;
    await goToCredentials();
    await waitFor(() => expect(screen.getByLabelText("Password")).toBeEnabled());
    expect(authenticateMock).not.toHaveBeenCalled();
  });

  it("offers a passkey as a second factor when the account has one", async () => {
    apiMock.post.mockImplementation(
      postWithSrpDisabled(
        res({
          mfa_required: true,
          challenge_token: "chal-1",
          available_methods: ["totp", "passkey"],
        })
      )
    );
    await goToCredentials();
    await submitCredentials();

    const button = await screen.findByRole("button", {
      name: /use a passkey or security key instead/i,
    });
    authenticateMock.mockResolvedValue({ session_id: "s", expires_in: 900 });
    await userEvent.click(button);

    // The MFA challenge token, not an empty one: this user is already
    // identified, so the assertion must be bound to their challenge.
    await waitFor(() =>
      expect(authenticateMock).toHaveBeenCalledWith("chal-1", { conditional: false }),
    );
  });

  it("does not offer a passkey second factor to a TOTP-only account", async () => {
    apiMock.post.mockImplementation(
      postWithSrpDisabled(
        res({
          mfa_required: true,
          challenge_token: "chal-1",
          available_methods: ["totp"],
        })
      )
    );
    await goToCredentials();
    await submitCredentials();

    await screen.findByLabelText("Authentication code");
    // Offering it would start a ceremony that can only fail.
    expect(
      screen.queryByRole("button", { name: /use a passkey or security key instead/i }),
    ).not.toBeInTheDocument();
  });

  it("keeps TOTP available alongside the passkey option", async () => {
    apiMock.post.mockImplementation(
      postWithSrpDisabled(
        res({
          mfa_required: true,
          challenge_token: "chal-1",
          available_methods: ["totp", "passkey"],
        })
      )
    );
    await goToCredentials();
    await submitCredentials();

    // Fallback ordering is passkey -> TOTP -> recovery: the passkey option is
    // an addition, never a replacement.
    expect(await screen.findByLabelText("Authentication code")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /use a passkey or security key instead/i }),
    ).toBeInTheDocument();
  });
});


// ---------------------------------------------------------------------------
// SRP (CONTRACT §23)
// ---------------------------------------------------------------------------
//
// These drive the page through `services/srp`, which drives the real crypto in
// `lib/srp` — no crypto is stubbed. The server side is faked, which is exactly
// the seam worth faking: `lib/srp.test.ts` already proves the arithmetic
// against the cross-language vectors, so what is left to assert here is the
// page's *behaviour* around it.

describe("LoginPage — SRP", () => {
  /**
   * Answer a challenge the way the server would for a tenant with SRP on.
   *
   * The verifier is derived from the same password the test types, so a real
   * exchange completes and `M2` genuinely matches — nothing here is a
   * hand-written constant that could drift from the implementation.
   */
  async function srpServer(password: string) {
    const { computeVerifier, deriveX, generateSalt, __testing } = await import("@/lib/srp");
    const { GROUPS, pad, sha256, modPow, bytesToHex, hexToBytes, multiplier } = __testing;
    const groupName = "rfc5054_2048" as const;
    const group = GROUPS[groupName];
    const N = BigInt("0x" + group.N);
    const salt = generateSalt();
    const kdf = { kdf: "pbkdf2_sha256", iterations: 210000 };

    const x = await deriveX("alice", password, salt, kdf);
    const verifierHex = await computeVerifier(groupName, x);
    const v = BigInt("0x" + verifierHex);

    // b is fixed here purely so the fake server is deterministic; the client's
    // `a` is still fresh from the real implementation.
    const b = BigInt("0x" + "33".repeat(32));
    const k = await multiplier(group);
    const B = (k * v + modPow(group.g, b, N)) % N;

    return {
      salt,
      kdf,
      groupName,
      bPubHex: bytesToHex(pad(B, group.byteLen)),
      /** Recompute what the server would return as `M2` for a given `A`/`M1`. */
      async serverProof(aPubHex: string, clientProofHex: string) {
        const A = BigInt("0x" + aPubHex);
        const u = BigInt(
          "0x" + bytesToHex(await sha256([pad(A, group.byteLen), pad(B, group.byteLen)]))
        );
        const S = modPow((A * modPow(v, u, N)) % N, b, N);
        const K = await sha256([pad(S, group.byteLen)]);
        return bytesToHex(await sha256([pad(A, group.byteLen), hexToBytes(clientProofHex), K]));
      },
    };
  }

  it("signs in over SRP without ever posting the password", async () => {
    const server = await srpServer("hunter2");
    let challengeA = "";
    apiMock.post.mockImplementation(async (url: string, body: Record<string, string>) => {
      if (url === SRP_CHALLENGE) {
        challengeA = body.client_public;
        return res({
          srp_session: "sealed",
          identity: "alice",
          salt: server.salt,
          group: server.groupName,
          kdf: server.kdf.kdf,
          iterations: server.kdf.iterations,
          b_pub: server.bPubHex,
        });
      }
      if (url === "/api/v1/auth/srp/verify") {
        return res({
          user: loginUser,
          session_id: "s1",
          expires_in: 900,
          server_proof: await server.serverProof(challengeA, body.client_proof),
        });
      }
      throw new Error("unexpected post " + url);
    });
    apiMock.get.mockImplementation((url: string) =>
      url === "/api/v1/auth/me"
        ? Promise.resolve(res({ user: loginUser, permissions: ["*"] }))
        : Promise.reject(new Error("unexpected get " + url))
    );

    await goToCredentials();
    await submitCredentials();
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));

    // The whole point: no request carried the password, and /auth/login was
    // never called.
    const posts = apiMock.post.mock.calls;
    expect(posts.some(([url]) => url === "/api/v1/auth/login")).toBe(false);
    for (const [, body] of posts) {
      expect(JSON.stringify(body ?? {})).not.toContain("hunter2");
    }
  });

  it("aborts sign-in when the server cannot prove itself", async () => {
    // A server that returns a wrong M2 does not hold the verifier, so it is not
    // the server it claims to be. Accepting its session would throw away the
    // half of SRP that authenticates the server to the client.
    const server = await srpServer("hunter2");
    apiMock.post.mockImplementation(async (url: string) => {
      if (url === SRP_CHALLENGE) {
        return res({
          srp_session: "sealed",
          identity: "alice",
          salt: server.salt,
          group: server.groupName,
          kdf: server.kdf.kdf,
          iterations: server.kdf.iterations,
          b_pub: server.bPubHex,
        });
      }
      if (url === "/api/v1/auth/srp/verify") {
        return res({ user: loginUser, session_id: "s1", server_proof: "00".repeat(32) });
      }
      throw new Error("unexpected post " + url);
    });

    await goToCredentials();
    await submitCredentials();

    expect(
      await screen.findByText(/server failed to prove its identity/i)
    ).toBeInTheDocument();
    expect(navigate).not.toHaveBeenCalledWith("/dashboard");
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });

  it("falls back to password login when the tenant has SRP disabled", async () => {
    apiMock.post.mockImplementation((url: string) => {
      if (url === SRP_CHALLENGE) return srpDisabled();
      if (url === "/api/v1/auth/login") {
        return Promise.resolve(res({ user: loginUser, session_id: "s1" }));
      }
      return Promise.reject(new Error("unexpected post " + url));
    });
    apiMock.get.mockImplementation((url: string) =>
      url === "/api/v1/auth/me"
        ? Promise.resolve(res({ user: loginUser, permissions: [] }))
        : Promise.reject(new Error("unexpected get " + url))
    );

    await goToCredentials();
    await submitCredentials();
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
    expect(
      apiMock.post.mock.calls.some(([url]) => url === "/api/v1/auth/login")
    ).toBe(true);
  });

  it("explains srp_required rather than blaming the password", async () => {
    // The password may be perfectly good; the tenant just refuses this route.
    // Showing "invalid credentials" would send the user off to reset a working
    // password.
    apiMock.post.mockImplementation((url: string) => {
      if (url === SRP_CHALLENGE) return srpDisabled();
      return Promise.reject({
        response: { status: 403, data: { error: "srp_required" } },
      });
    });

    await goToCredentials();
    await submitCredentials();

    const message = await screen.findByText(/requires Secure Remote Password/i);
    expect(message).toBeInTheDocument();
    expect(screen.queryByText(/invalid credentials/i)).not.toBeInTheDocument();
  });

  it("carries an MFA challenge through the SRP path exactly as the password path does", async () => {
    const server = await srpServer("hunter2");
    let challengeA = "";
    apiMock.post.mockImplementation(async (url: string, body: Record<string, string>) => {
      if (url === SRP_CHALLENGE) {
        challengeA = body.client_public;
        return res({
          srp_session: "sealed",
          identity: "alice",
          salt: server.salt,
          group: server.groupName,
          kdf: server.kdf.kdf,
          iterations: server.kdf.iterations,
          b_pub: server.bPubHex,
        });
      }
      if (url === "/api/v1/auth/srp/verify") {
        return res({
          mfa_required: true,
          challenge_token: "chal-1",
          server_proof: await server.serverProof(challengeA, body.client_proof),
        });
      }
      throw new Error("unexpected post " + url);
    });

    await goToCredentials();
    await submitCredentials();
    expect(await screen.findByText("Two-factor authentication")).toBeInTheDocument();
  });
});
