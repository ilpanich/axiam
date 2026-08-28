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
  /**
   * The tenant's mode — `"optional"` or `"required"`. Absent on a server older
   * than the field, which is read as `"required"`: the conservative direction,
   * since it is the one that never transmits a plaintext password.
   */
  mode?: "optional" | "required";
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

/**
 * Raised when the exchange failed under a tenant in `optional` mode, where the
 * password endpoint is still live and is the right next thing to try.
 *
 * The overwhelmingly common cause is an account with no registration record.
 * Every account has none the moment an operator turns OPAQUE on, and they
 * acquire one only as they next set a password — that gradual crossover *is*
 * what `optional` mode is. The server cannot say so: `/auth/opaque/login/start`
 * answers a decoy exchange for an unenrolled identity precisely so that this
 * endpoint cannot be used to enumerate who is enrolled, which means an
 * unenrolled user and a wrong password are indistinguishable to the client, by
 * design.
 *
 * Treating both as a hard failure is what made enabling `optional` lock out
 * every existing user of a tenant: the browser tries OPAQUE first (it must, or
 * `optional` would never produce a single OPAQUE login), the envelope does not
 * open, and the attempt ended there.
 *
 * Under `required` this is never raised. `/auth/login` refuses for the whole
 * tenant before examining any credential, so there is nothing to fall back to
 * and an honest client never puts the plaintext on the wire at all. That — not
 * anything the client does — is what closes the downgrade: a hostile server
 * could always answer `404` here and get the fallback regardless.
 */
export class OpaqueExchangeFailedError extends Error {
  constructor(message = "The OPAQUE exchange did not complete.") {
    super(message);
    this.name = "OpaqueExchangeFailedError";
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
        // Omitted entirely when blank, exactly as the password path omits it.
        // The server reads "no tenant named" as "sign in at organization
        // level", which is where the administrator bootstrap creates lives;
        // an empty string is a slug lookup that cannot match, and the 401 it
        // produced was raised *before* the tenant's OPAQUE mode was read — so
        // this probe never reached the 404 that tells the caller to fall back,
        // and organization-level sign-in failed even with OPAQUE disabled.
        ...(args.tenantSlug.trim() ? { tenant_slug: args.tenantSlug.trim() } : {}),
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
    // The envelope did not open: wrong password, no account, or an account
    // with no registration record. Indistinguishable by design.
    //
    // Under `optional` the third case is the ordinary one and the password
    // endpoint is still live, so the caller may retry there (CONTRACT §23.4
    // rule 7 as amended). Under `required` — including a server too old to
    // report its mode — nothing further may be sent.
    if (started.mode === "optional") {
      throw new OpaqueExchangeFailedError();
    }
    throw new Error("Invalid credentials. Please try again.");
  }

  const response = await api.post("/api/v1/auth/opaque/login/finish", {
    opaque_session: started.opaque_session,
    ke3,
  });
  return { data: response.data };
}

/**
 * Identifies the workspace an enrolment is being built for.
 *
 * `tenantId` alone is enough and is the preferred form: a tenant identifies its
 * organization on its own, and a UUID cannot be ambiguous the way a pair of
 * slugs can. The slug fields remain for callers that genuinely only hold slugs.
 */
export interface EnrollmentWorkspace {
  orgSlug?: string;
  tenantSlug?: string;
  orgId?: string;
  tenantId?: string;
}

/**
 * Build an enrolment for `password` in a named workspace.
 *
 * Returns `null` — meaning "omit the `opaque` field" — for exactly two reasons,
 * and **throws** for everything else:
 *
 * * this browser cannot do OPAQUE at all (no WebAssembly artifact), or
 * * the server answered `404`, which is how it says the tenant has OPAQUE
 *   disabled. Omitting the field is then not a fallback but the correct
 *   request: the server *rejects* a record under `disabled`.
 *
 * # Why the tenant's policy is not consulted first
 *
 * It used to be, from the copy of it the auth store cached at login, and that
 * cache is what made enabling OPAQUE look like it did nothing. An operator
 * switched the organization from `disabled` to `optional` and then changed a
 * password in the same session; the store still said `disabled`, so this
 * function returned `null` without asking, the `opaque` field was omitted, and
 * no record was ever written. The tenant then accumulated no coverage at all,
 * and switching to `required` locked everybody out — including the only
 * administrator.
 *
 * `register/start` already answers the question authoritatively and costs one
 * round trip, which is a round trip this function was making anyway whenever
 * the cached policy happened to be right. So it asks.
 *
 * # Why a transient failure is no longer swallowed
 *
 * Returning `null` for a network blip meant an account could be created, or a
 * password set, with no record under `optional` — silently unenrolled — or
 * refused by the server under `required` with a message about a missing record
 * the operator had no way to act on. A thrown error surfaces on the form, where
 * "try again" is a thing the person in front of it can actually do.
 */
export async function buildEnrollment(
  args: EnrollmentWorkspace & { password: string }
): Promise<OpaqueEnrollment | null> {
  let exchange;
  try {
    exchange = await startRegistration(args.password);
  } catch {
    // No OPAQUE implementation in this browser. Nothing to enrol with, and
    // nothing a retry would fix.
    return null;
  }

  let started: RegisterStartResponse;
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
    started = response.data;
  } catch (err) {
    if (isNotFound(err)) return null;
    throw err;
  }

  return {
    opaque_session: started.opaque_session,
    registration_record: exchange.finish(started.registration_response, started),
  };
}

/**
 * Build an enrolment for the authenticated caller's **own** new password.
 *
 * Scoped to the tenant the caller *lives in*, never the one it is acting on. An
 * organization-level administrator with a child tenant selected is still
 * changing a password that belongs to the organization's own scope, and the
 * server stores the record there; building it against the selected tenant would
 * produce a session the server refuses with "the OPAQUE session was issued for
 * a different tenant".
 *
 * `principal_tenant_id` is the field that says which one that is. It comes from
 * `/auth/me` and is stable across tenant switches, where `tenant_id` follows
 * whichever tenant the request acts on.
 */
export async function buildEnrollmentForUser(
  user: {
    /** The tenant the caller lives in — stable across tenant switches. */
    principal_tenant_id?: string;
    /** The tenant the caller is acting on; equal to the above until it switches. */
    tenant_id?: string;
  } | null,
  password: string
): Promise<OpaqueEnrollment | null> {
  const tenantId = user?.principal_tenant_id ?? user?.tenant_id;
  if (!tenantId) return null;
  return buildEnrollment({ password, tenantId });
}

/**
 * Build an enrolment for an account being created in `tenantId`.
 *
 * The distinction from {@link buildEnrollmentForUser} is the entire bug behind
 * "Validation error: the OPAQUE session was issued for a different tenant".
 * Creating a user is the one password-setting flow whose subject is somebody
 * else, in a tenant that need not be the caller's: an organization
 * administrator selects a child tenant, `POST /api/v1/users` is scoped to it by
 * the `X-Axiam-Tenant` header, and the record has to be sealed against *that*
 * tenant's key material. Building it from the caller's own identity sealed it
 * against the organization scope, and every such creation failed with a 400.
 */
export async function buildEnrollmentForTenant(args: {
  tenantId: string;
  password: string;
}): Promise<OpaqueEnrollment | null> {
  return buildEnrollment({ password: args.password, tenantId: args.tenantId });
}

/**
 * Build the enrolment for a password reset.
 *
 * The emailed link carries `?token=…&tenant_id=…` and nothing else — there is no
 * session to learn an organization from, which is why this passes only the
 * tenant. The server resolves the organization from the tenant record.
 *
 * This used to ask `/auth/reset/context` for the tenant's OPAQUE policy first
 * and skip enrolment when it could not be read. That made reset the hole in
 * OPAQUE coverage: under `required`, a user who forgot their password could
 * complete the reset and still be unable to sign in, because the reset wrote a
 * password and no record. `register/start` answers the same question and is the
 * request that has to succeed anyway.
 */
export async function buildEnrollmentForReset(args: {
  tenantId: string;
  password: string;
}): Promise<OpaqueEnrollment | null> {
  return buildEnrollment({ password: args.password, tenantId: args.tenantId });
}
