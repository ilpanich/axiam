/**
 * OPAQUE (RFC 9807) sign-in and enrolment against the AXIAM REST API.
 *
 * The protocol itself lives in `@/lib/opaque`, which loads the one shared
 * implementation. This module is the HTTP half: which endpoint, which body,
 * and what a failure means.
 */

import api from "@/lib/api";
import {
  OpaqueUnavailableError,
  OpaqueUnsupportedError,
  type OpaqueKsfFields,
  startLogin,
  startRegistration,
} from "@/lib/opaque";

/** Server response to `POST /api/v1/auth/opaque/login/start`. */
interface LoginStartResponse extends OpaqueKsfFields {
  opaque_session: string;
  ke2: string;
  suite: string;
}

/** Server response to `POST /api/v1/auth/opaque/register/start`. */
interface RegisterStartResponse extends OpaqueKsfFields {
  opaque_session: string;
  registration_response: string;
  suite: string;
}

/**
 * The `opaque` object embedded in every request body that sets a password.
 *
 * Two fields, where SRP's had seven. The server chose the credential
 * identifier, the suite and the costs, and sealed them into `opaque_session`,
 * so a client cannot name any of them — which is also why it cannot enrol a
 * record against somebody else's account.
 */
export interface OpaqueEnrollment {
  opaque_session: string;
  registration_record: string;
}

/**
 * Raised when this browser or this tenant cannot do OPAQUE, so the caller
 * should fall back to password login.
 *
 * Distinct from a credential failure on purpose: falling back on a wrong
 * password would send the plaintext to the server the user just failed to
 * authenticate against.
 */
export class OpaqueNotOfferedError extends Error {
  constructor(message = "OPAQUE is not available for this sign-in.") {
    super(message);
    this.name = "OpaqueNotOfferedError";
  }
}

function isNotFound(err: unknown): boolean {
  const status = (err as { response?: { status?: number } })?.response?.status;
  return status === 404;
}

/** The login result body, shared with the password path. */
export interface OpaqueLoginOutcome {
  data: unknown;
}

/**
 * Complete a full OPAQUE sign-in.
 *
 * Throws {@link OpaqueNotOfferedError} when the tenant has OPAQUE disabled
 * (`404`) or this browser could not load the module — both cases where the
 * caller should try the password endpoint.
 *
 * Note what this function does **not** do at the end: verify a server proof.
 * Under SRP it had to, and CONTRACT §23.3 rule 6 had to say so in capitals,
 * because skipping it kept only the half of the protocol that authenticates the
 * client. RFC 9807's AKE authenticates the server during the handshake — the
 * envelope only opens if the server holds the record — so the mutual
 * authentication is complete by the time `finish` returns, and there is nothing
 * left to forget.
 */
export async function loginOpaque(args: {
  usernameOrEmail: string;
  password: string;
  orgSlug: string;
  tenantSlug: string;
}): Promise<OpaqueLoginOutcome> {
  let exchange;
  try {
    exchange = await startLogin(args.password);
  } catch (err) {
    if (err instanceof OpaqueUnavailableError) throw new OpaqueNotOfferedError();
    throw err;
  }

  let started: LoginStartResponse;
  try {
    const response = await api.post<LoginStartResponse>(
      "/api/v1/auth/opaque/login/start",
      {
        org_slug: args.orgSlug,
        tenant_slug: args.tenantSlug,
        username_or_email: args.usernameOrEmail,
        ke1: exchange.ke1,
      }
    );
    started = response.data;
  } catch (err) {
    // 404 is a property of the tenant, not of any user. Every other status —
    // including a 200 for an account that does not exist — is deliberately
    // indistinguishable, which is what stops this endpoint enumerating.
    if (isNotFound(err)) throw new OpaqueNotOfferedError();
    throw err;
  }

  let ke3: string;
  try {
    ke3 = exchange.finish(started.ke2, started);
  } catch (err) {
    if (err instanceof OpaqueUnsupportedError) throw new OpaqueNotOfferedError(err.message);
    // The envelope did not open: wrong password, no account, or a server that
    // does not hold the record. Indistinguishable by design, and nothing
    // further may be sent (CONTRACT §23.4 rule 7).
    throw new Error("Invalid credentials. Please try again.");
  }

  const response = await api.post("/api/v1/auth/opaque/login/finish", {
    opaque_session: started.opaque_session,
    ke3,
  });
  return { data: response.data };
}

/**
 * Build an enrolment for `password`, or `null` when the tenant does not use
 * OPAQUE or this browser cannot.
 *
 * `null` means "omit the `opaque` field", which is the correct fallback in both
 * cases: the server rejects a record outright under `disabled`, and under
 * `optional` a password change without one simply leaves the account
 * unenrolled rather than failing.
 *
 * There is no `identity` argument, where the SRP equivalent required one. The
 * record binds to a credential identifier the server chooses, so nothing here
 * depends on the account's username — which is also why a rename no longer
 * invalidates a credential.
 */
export async function buildEnrollment(args: {
  password: string;
  orgSlug?: string;
  tenantSlug?: string;
  orgId?: string;
  tenantId?: string;
}): Promise<OpaqueEnrollment | null> {
  let exchange;
  try {
    exchange = await startRegistration(args.password);
  } catch {
    return null;
  }

  try {
    const response = await api.post<RegisterStartResponse>(
      "/api/v1/auth/opaque/register/start",
      {
        ...(args.orgSlug ? { org_slug: args.orgSlug } : {}),
        ...(args.tenantSlug ? { tenant_slug: args.tenantSlug } : {}),
        ...(args.orgId ? { org_id: args.orgId } : {}),
        ...(args.tenantId ? { tenant_id: args.tenantId } : {}),
        registration_request: exchange.request,
      }
    );
    const started = response.data;
    return {
      opaque_session: started.opaque_session,
      registration_record: exchange.finish(started.registration_response, started),
    };
  } catch {
    // A failure here must not block the password change or reset it belongs
    // to: the account keeps working on the password path, and the user can
    // enrol on their next password change. Failing loudly would turn a
    // transient error into a user who cannot recover their account.
    return null;
  }
}

/**
 * Build an enrolment for an authenticated user changing their own password.
 *
 * Returns `null` when the user's tenant does not use OPAQUE.
 */
export async function buildEnrollmentForUser(
  user: {
    tenant_slug?: string;
    org_slug?: string;
    opaque?: { opaque_mode: string; opaque_suite: string; opaque_ksf: string };
  } | null,
  password: string
): Promise<OpaqueEnrollment | null> {
  const policy = user?.opaque;
  if (!user || !policy || policy.opaque_mode === "disabled") return null;
  return buildEnrollment({
    password,
    orgSlug: user.org_slug,
    tenantSlug: user.tenant_slug,
  });
}

/**
 * What the unauthenticated reset page needs in order to enrol.
 *
 * The SRP version of this also carried the account's `identity`, because SRP
 * derived its key over the username and the reset page had no other way to
 * learn it. OPAQUE does not, so the endpoint no longer discloses it.
 */
export interface ResetContext {
  opaque?: { opaque_mode: string; opaque_suite: string; opaque_ksf: string };
}

/**
 * Build the enrolment for a password reset.
 *
 * Returns `null` when the tenant does not use OPAQUE or the context lookup
 * fails. A lookup failure must not block the reset: the confirm call is the
 * authoritative check on the token.
 */
export async function buildEnrollmentForReset(args: {
  tenantId: string;
  token: string;
  password: string;
}): Promise<OpaqueEnrollment | null> {
  let context: ResetContext;
  try {
    const response = await api.get<ResetContext>("/api/v1/auth/reset/context", {
      params: { tenant_id: args.tenantId, token: args.token },
    });
    context = response.data;
  } catch {
    return null;
  }

  if (!context.opaque || context.opaque.opaque_mode === "disabled") return null;
  return buildEnrollment({ password: args.password, tenantId: args.tenantId });
}
