import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from "@simplewebauthn/browser";
import api from "@/lib/api";

/**
 * WebAuthn (passkey / security key) API client — C1/C2.
 *
 * The server has shipped the full registration and authentication ceremonies
 * since well before this file existed; the frontend simply had no way to
 * exercise them, so passkey support was invisible to users.
 *
 * ## Division of labour
 *
 * **The server does all the crypto and all the policy.** It generates the
 * challenge, chooses `residentKey`, `userVerification`, the attestation
 * conveyance and the credential-exclusion list, and it verifies the resulting
 * assertion. This module hands the server's options to the browser **unchanged**
 * and posts the browser's response back.
 *
 * That is deliberate: every WebAuthn option is a security parameter, and a
 * client that "helpfully" adjusts one is a client that has quietly weakened a
 * ceremony the server believes it configured. The only thing this module adds
 * is `authenticatorAttachment`, which is a *hint* about which authenticator the
 * user is trying to enrol — it cannot weaken verification, and without it a
 * user asking for a security key gets prompted for Touch ID.
 *
 * `@simplewebauthn/browser` is used only for its base64url plumbing and feature
 * detection, which is genuinely fiddly and genuinely not worth hand-rolling. It
 * does not make policy decisions either.
 */

// ─── Wire types ──────────────────────────────────────────────────────────────

/** `StartRegistrationResponse` from the server. */
interface StartRegistrationDto {
  /** Raw `PublicKeyCredentialCreationOptions`, JSON-encoded per the WebAuthn spec. */
  challenge: { publicKey: PublicKeyCredentialCreationOptionsJSON };
  state_token: string;
}

/** `StartAuthenticationResponse` from the server. */
interface StartAuthenticationDto {
  challenge: { publicKey: PublicKeyCredentialRequestOptionsJSON };
  state_token: string;
}

/** `WebauthnLoginResponse` from the server. */
export interface WebauthnLoginResult {
  session_id: string;
  expires_in: number;
}

/**
 * Which kind of authenticator the user asked for.
 *
 * A hint only — see the module docs. `platform` is a passkey built into the
 * device (Touch ID, Windows Hello, a phone); `cross-platform` is a removable
 * security key (YubiKey and friends).
 */
export type AuthenticatorKind = "platform" | "cross-platform";

// ─── Feature detection ───────────────────────────────────────────────────────

/**
 * Whether this browser can do WebAuthn at all.
 *
 * Used to hide the enrolment buttons rather than to let a user click one and
 * receive an exception they cannot act on.
 */
export function isWebauthnSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential !== "undefined"
  );
}

/**
 * Whether this browser supports **conditional mediation** — passkey autofill,
 * where the browser offers saved passkeys from the username field itself
 * rather than behind a button (C2).
 *
 * Returns `false` rather than throwing on browsers where the probe itself is
 * missing: conditional UI is a progressive enhancement, and its absence must
 * degrade to the explicit button, never to a broken login page.
 */
export async function isConditionalMediationAvailable(): Promise<boolean> {
  if (!isWebauthnSupported()) return false;
  const probe = window.PublicKeyCredential
    ?.isConditionalMediationAvailable as (() => Promise<boolean>) | undefined;
  if (typeof probe !== "function") return false;
  try {
    return await probe.call(window.PublicKeyCredential);
  } catch {
    return false;
  }
}

// ─── Error classification ────────────────────────────────────────────────────

/**
 * A ceremony failure the UI can say something useful about.
 *
 * Every WebAuthn failure arrives as a `DOMException` whose `name` is the only
 * machine-readable part, and the browser's own `message` is written for
 * developers. Classifying here keeps that translation in one place instead of
 * in every component that runs a ceremony.
 */
export type WebauthnFailure =
  | "cancelled"
  | "already-registered"
  | "timeout"
  | "unsupported"
  | "unknown";

export function classifyWebauthnError(err: unknown): WebauthnFailure {
  if (!isWebauthnSupported()) return "unsupported";
  if (typeof err !== "object" || err === null) return "unknown";
  const name = (err as { name?: string }).name;
  switch (name) {
    // NotAllowedError covers BOTH an explicit cancel and a silent timeout —
    // the spec deliberately does not distinguish them, because telling a
    // website which one happened is itself an information leak about the
    // user. "cancelled" is therefore the honest label for both, and the
    // copy that goes with it must not accuse the user of anything.
    case "NotAllowedError":
      return "cancelled";
    // The authenticator already holds a credential for this account. The
    // server sent it in `excludeCredentials`; the authenticator refused
    // rather than silently making a second one.
    case "InvalidStateError":
      return "already-registered";
    case "AbortError":
      return "timeout";
    case "NotSupportedError":
    case "SecurityError":
      return "unsupported";
    default:
      return "unknown";
  }
}

/** User-facing copy for each failure. */
export function webauthnErrorMessage(failure: WebauthnFailure): string {
  switch (failure) {
    case "cancelled":
      return "The request was cancelled or timed out. You can try again.";
    case "already-registered":
      return "This device is already registered on your account. Try a different device, or remove the existing one first.";
    case "timeout":
      return "The request timed out before it completed. Please try again.";
    case "unsupported":
      return "This browser or device cannot be used for passkeys. Try a different browser, or use another sign-in method.";
    case "unknown":
      return "Something went wrong setting up this device. Please try again.";
  }
}

// ─── Service ─────────────────────────────────────────────────────────────────

export const webauthnService = {
  /**
   * Register a new passkey or security key for the signed-in user.
   *
   * `kind` selects the `authenticatorAttachment` hint. Everything else — the
   * challenge, `residentKey`, `userVerification`, `excludeCredentials` — comes
   * from the server untouched.
   */
  async register(name: string, kind: AuthenticatorKind): Promise<void> {
    const { data } = await api.post<StartRegistrationDto>(
      "/api/v1/auth/webauthn/register/start",
    );

    const options: PublicKeyCredentialCreationOptionsJSON = {
      ...data.challenge.publicKey,
      authenticatorSelection: {
        ...data.challenge.publicKey.authenticatorSelection,
        authenticatorAttachment: kind,
      },
    };

    const response: RegistrationResponseJSON = await startRegistration({
      optionsJSON: options,
    });

    await api.post("/api/v1/auth/webauthn/register/finish", {
      state_token: data.state_token,
      credential_name: name,
      response,
    });
  },

  /**
   * Run an authentication ceremony against a login challenge token.
   *
   * `mediation: "conditional"` turns this into passkey autofill: the browser
   * shows saved passkeys inside the username field and resolves only when the
   * user picks one, so the call may stay pending indefinitely. Callers using it
   * must be prepared to abandon it (the browser aborts it when the page
   * navigates).
   */
  async authenticate(
    challengeToken: string,
    opts?: { conditional?: boolean },
  ): Promise<WebauthnLoginResult> {
    const { data } = await api.post<StartAuthenticationDto>(
      "/api/v1/auth/webauthn/authenticate/start",
      { challenge_token: challengeToken },
    );

    const response: AuthenticationResponseJSON = await startAuthentication({
      optionsJSON: data.challenge.publicKey,
      useBrowserAutofill: opts?.conditional === true,
    });

    const result = await api.post<WebauthnLoginResult>(
      "/api/v1/auth/webauthn/authenticate/finish",
      {
        state_token: data.state_token,
        response,
      },
    );
    return result.data;
  },

  /**
   * Sign in with a passkey without typing a username first.
   *
   * Distinct endpoints from {@link authenticate}, not an empty
   * `challenge_token` against the same ones. That was the original shape and it
   * could not work: `authenticate/start` decodes the challenge token to learn
   * who is signing in, so an empty string is rejected as an invalid token
   * before anything else happens. There is no user to name here — that is what
   * the ceremony is for — so the server needs a different entry point, one that
   * takes the workspace instead.
   *
   * The workspace is the one thing the browser must still supply: a
   * discoverable credential is resolved inside a single tenant. The login page
   * has already collected it in its first step.
   *
   * `conditional` selects passkey autofill over a modal prompt. Both mediation
   * modes run this same server ceremony; only the browser UI differs.
   */
  async authenticateDiscoverable(
    orgSlug: string,
    tenantSlug: string,
    opts?: { conditional?: boolean },
  ): Promise<WebauthnLoginResult> {
    const { data } = await api.post<StartAuthenticationDto>(
      "/api/v1/auth/webauthn/authenticate/discoverable/start",
      {
        org_slug: orgSlug,
        // Omitted when blank, exactly as the two password paths omit it: the
        // server reads "no tenant named" as the organization's own scope,
        // which is where the administrator bootstrap creates lives. An empty
        // string is a slug lookup that cannot match.
        ...(tenantSlug.trim() ? { tenant_slug: tenantSlug.trim() } : {}),
      },
    );

    const response: AuthenticationResponseJSON = await startAuthentication({
      optionsJSON: data.challenge.publicKey,
      useBrowserAutofill: opts?.conditional === true,
    });

    const result = await api.post<WebauthnLoginResult>(
      "/api/v1/auth/webauthn/authenticate/discoverable/finish",
      {
        state_token: data.state_token,
        response,
      },
    );
    return result.data;
  },
};
