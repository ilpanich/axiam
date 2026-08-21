import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

const startRegistrationMock = vi.fn();
const startAuthenticationMock = vi.fn();
vi.mock("@simplewebauthn/browser", () => ({
  startRegistration: (...args: unknown[]) => startRegistrationMock(...args),
  startAuthentication: (...args: unknown[]) => startAuthenticationMock(...args),
}));

import {
  webauthnService,
  isWebauthnSupported,
  isConditionalMediationAvailable,
  classifyWebauthnError,
  webauthnErrorMessage,
} from "./webauthn";

/** Minimal stand-in for the server's start-registration payload. */
const registrationChallenge = {
  challenge: {
    publicKey: {
      challenge: "Y2hhbGxlbmdl",
      rp: { id: "localhost", name: "AXIAM" },
      user: { id: "dTE", name: "admin", displayName: "admin" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
    },
  },
  state_token: "state-abc",
};

const authenticationChallenge = {
  challenge: {
    publicKey: { challenge: "Y2hhbGxlbmdl", rpId: "localhost" },
  },
  state_token: "state-xyz",
};

function setPublicKeyCredential(value: unknown) {
  Object.defineProperty(window, "PublicKeyCredential", {
    value,
    configurable: true,
    writable: true,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  setPublicKeyCredential(function PublicKeyCredential() {});
});

afterEach(() => {
  setPublicKeyCredential(undefined);
});

describe("feature detection", () => {
  it("reports support when PublicKeyCredential exists", () => {
    expect(isWebauthnSupported()).toBe(true);
  });

  it("reports no support when PublicKeyCredential is absent", () => {
    setPublicKeyCredential(undefined);
    expect(isWebauthnSupported()).toBe(false);
  });

  it("reports no conditional mediation when the probe is missing", async () => {
    // Older browsers have PublicKeyCredential but not the probe. Returning
    // false (rather than throwing) is what keeps the login page usable there.
    await expect(isConditionalMediationAvailable()).resolves.toBe(false);
  });

  it("reports conditional mediation when the probe says yes", async () => {
    const ctor = function PublicKeyCredential() {} as unknown as Record<string, unknown>;
    ctor.isConditionalMediationAvailable = () => Promise.resolve(true);
    setPublicKeyCredential(ctor);
    await expect(isConditionalMediationAvailable()).resolves.toBe(true);
  });

  it("treats a throwing probe as no support rather than propagating", async () => {
    const ctor = function PublicKeyCredential() {} as unknown as Record<string, unknown>;
    ctor.isConditionalMediationAvailable = () => {
      throw new Error("boom");
    };
    setPublicKeyCredential(ctor);
    await expect(isConditionalMediationAvailable()).resolves.toBe(false);
  });
});

describe("registration", () => {
  it("passes the server's options through and posts the response back", async () => {
    apiMock.post.mockImplementation((url: string) => {
      if (url.endsWith("/register/start")) return Promise.resolve(res(registrationChallenge));
      return Promise.resolve(res(undefined));
    });
    startRegistrationMock.mockResolvedValue({ id: "cred-1" });

    await webauthnService.register("My laptop", "platform");

    const passed = startRegistrationMock.mock.calls[0][0].optionsJSON;
    // The server's policy fields must reach the browser untouched — a client
    // that "helpfully" adjusts one has silently weakened the ceremony.
    expect(passed.challenge).toBe("Y2hhbGxlbmdl");
    expect(passed.authenticatorSelection.residentKey).toBe("required");
    expect(passed.authenticatorSelection.userVerification).toBe("required");

    expect(apiMock.post).toHaveBeenCalledWith(
      "/api/v1/auth/webauthn/register/finish",
      expect.objectContaining({
        state_token: "state-abc",
        credential_name: "My laptop",
        response: { id: "cred-1" },
      }),
    );
  });

  it("hints platform attachment for a passkey", async () => {
    apiMock.post.mockResolvedValue(res(registrationChallenge));
    startRegistrationMock.mockResolvedValue({ id: "c" });

    await webauthnService.register("n", "platform");

    expect(
      startRegistrationMock.mock.calls[0][0].optionsJSON.authenticatorSelection
        .authenticatorAttachment,
    ).toBe("platform");
  });

  it("hints cross-platform attachment for a security key", async () => {
    apiMock.post.mockResolvedValue(res(registrationChallenge));
    startRegistrationMock.mockResolvedValue({ id: "c" });

    await webauthnService.register("n", "cross-platform");

    expect(
      startRegistrationMock.mock.calls[0][0].optionsJSON.authenticatorSelection
        .authenticatorAttachment,
    ).toBe("cross-platform");
  });

  it("does not post a finish when the ceremony fails", async () => {
    apiMock.post.mockResolvedValue(res(registrationChallenge));
    const err = new Error("cancelled");
    err.name = "NotAllowedError";
    startRegistrationMock.mockRejectedValue(err);

    await expect(webauthnService.register("n", "platform")).rejects.toThrow();

    expect(apiMock.post).toHaveBeenCalledTimes(1);
    expect(apiMock.post).not.toHaveBeenCalledWith(
      "/api/v1/auth/webauthn/register/finish",
      expect.anything(),
    );
  });
});

describe("authentication", () => {
  it("runs the ceremony and returns the session result", async () => {
    apiMock.post.mockImplementation((url: string) => {
      if (url.endsWith("/authenticate/start")) {
        return Promise.resolve(res(authenticationChallenge));
      }
      return Promise.resolve(res({ session_id: "s1", expires_in: 900 }));
    });
    startAuthenticationMock.mockResolvedValue({ id: "assertion" });

    await expect(webauthnService.authenticate("challenge-token")).resolves.toEqual({
      session_id: "s1",
      expires_in: 900,
    });

    expect(apiMock.post).toHaveBeenCalledWith(
      "/api/v1/auth/webauthn/authenticate/start",
      { challenge_token: "challenge-token" },
    );
    expect(startAuthenticationMock.mock.calls[0][0].useBrowserAutofill).toBe(false);
  });

  it("enables browser autofill in conditional mode", async () => {
    apiMock.post.mockImplementation((url: string) =>
      url.endsWith("/authenticate/start")
        ? Promise.resolve(res(authenticationChallenge))
        : Promise.resolve(res({ session_id: "s1", expires_in: 900 })),
    );
    startAuthenticationMock.mockResolvedValue({ id: "assertion" });

    await webauthnService.authenticate("", { conditional: true });

    expect(startAuthenticationMock.mock.calls[0][0].useBrowserAutofill).toBe(true);
  });
});

describe("discoverable (usernameless) authentication", () => {
  const mockDiscoverableEndpoints = () =>
    apiMock.post.mockImplementation((url: string) =>
      url.endsWith("/authenticate/discoverable/start")
        ? Promise.resolve(res(authenticationChallenge))
        : Promise.resolve(res({ session_id: "s1", expires_in: 900 })),
    );

  it("sends the workspace, never a challenge token", async () => {
    mockDiscoverableEndpoints();
    startAuthenticationMock.mockResolvedValue({ id: "assertion" });

    await expect(
      webauthnService.authenticateDiscoverable("acme", "default"),
    ).resolves.toEqual({ session_id: "s1", expires_in: 900 });

    // The distinct endpoints are the fix, not a refactor: the challenge-token
    // ones cannot serve this flow, because they decode that token to learn who
    // is signing in and reject an empty one before doing anything else.
    expect(apiMock.post).toHaveBeenCalledWith(
      "/api/v1/auth/webauthn/authenticate/discoverable/start",
      { org_slug: "acme", tenant_slug: "default" },
    );
    expect(apiMock.post).toHaveBeenCalledWith(
      "/api/v1/auth/webauthn/authenticate/discoverable/finish",
      { state_token: "state-xyz", response: { id: "assertion" } },
    );
    expect(apiMock.post).not.toHaveBeenCalledWith(
      "/api/v1/auth/webauthn/authenticate/start",
      expect.anything(),
    );
  });

  it("passes the server's options through untouched", async () => {
    mockDiscoverableEndpoints();
    startAuthenticationMock.mockResolvedValue({ id: "assertion" });

    await webauthnService.authenticateDiscoverable("acme", "default");

    expect(startAuthenticationMock.mock.calls[0][0].optionsJSON).toEqual(
      authenticationChallenge.challenge.publicKey,
    );
    expect(startAuthenticationMock.mock.calls[0][0].useBrowserAutofill).toBe(false);
  });

  it("enables browser autofill in conditional mode", async () => {
    mockDiscoverableEndpoints();
    startAuthenticationMock.mockResolvedValue({ id: "assertion" });

    await webauthnService.authenticateDiscoverable("acme", "default", {
      conditional: true,
    });

    expect(startAuthenticationMock.mock.calls[0][0].useBrowserAutofill).toBe(true);
  });

  it("does not post a finish when the ceremony fails", async () => {
    mockDiscoverableEndpoints();
    startAuthenticationMock.mockRejectedValue(
      Object.assign(new Error("no"), { name: "NotAllowedError" }),
    );

    await expect(
      webauthnService.authenticateDiscoverable("acme", "default"),
    ).rejects.toThrow();

    expect(apiMock.post).not.toHaveBeenCalledWith(
      "/api/v1/auth/webauthn/authenticate/discoverable/finish",
      expect.anything(),
    );
  });
});

describe("error classification", () => {
  it.each([
    ["NotAllowedError", "cancelled"],
    ["InvalidStateError", "already-registered"],
    ["AbortError", "timeout"],
    ["NotSupportedError", "unsupported"],
    ["SecurityError", "unsupported"],
    ["SomethingElse", "unknown"],
  ])("maps %s to %s", (name, expected) => {
    const err = new Error("x");
    err.name = name;
    expect(classifyWebauthnError(err)).toBe(expected);
  });

  it("classifies anything as unsupported when the browser cannot do WebAuthn", () => {
    setPublicKeyCredential(undefined);
    const err = new Error("x");
    err.name = "NotAllowedError";
    expect(classifyWebauthnError(err)).toBe("unsupported");
  });

  it("does not blame the user for a cancelled ceremony", () => {
    // The spec deliberately cannot distinguish "user cancelled" from "timed
    // out", so the copy must not assert which one happened.
    const message = webauthnErrorMessage("cancelled");
    expect(message).toMatch(/cancelled or timed out/i);
    expect(message).toMatch(/try again/i);
  });

  it("explains the duplicate-credential case actionably", () => {
    expect(webauthnErrorMessage("already-registered")).toMatch(/already registered/i);
  });

  it("has copy for every failure kind", () => {
    for (const kind of ["cancelled", "already-registered", "timeout", "unsupported", "unknown"] as const) {
      expect(webauthnErrorMessage(kind).length).toBeGreaterThan(10);
    }
  });
});
