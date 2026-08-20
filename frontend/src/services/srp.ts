/**
 * SRP transport: the two `/auth/srp/*` calls and the enrolment payload builder.
 *
 * The arithmetic lives in `@/lib/srp` and knows nothing about HTTP; this module
 * knows nothing about the arithmetic beyond calling into it. Pages orchestrate
 * the two. Keeping that seam is what lets `lib/srp.ts` be tested against the
 * cross-language vectors with no server and no mock.
 */

import api from "@/lib/api";
import {
  type SrpGroupName,
  type SrpKdfParams,
  beginClientSession,
  computeVerifier,
  deriveX,
  generateSalt,
  isKnownGroup,
  verifyServerProof,
} from "@/lib/srp";

/** Server response to `POST /api/v1/auth/srp/challenge`. */
export interface SrpChallenge {
  srp_session: string;
  /**
   * The canonical identity to feed into the KDF.
   *
   * This is the server's answer, not the user's input: a user may sign in with
   * a username or an email while only one of the two is bound into `x`.
   */
  identity: string;
  salt: string;
  group: string;
  kdf: string;
  memory_kib?: number;
  iterations: number;
  parallelism?: number;
  b_pub: string;
}

/** The `srp` object accepted by every endpoint that sets a password. */
export interface SrpEnrollment {
  group: string;
  kdf: string;
  memory_kib?: number;
  iterations: number;
  parallelism?: number;
  salt: string;
  verifier: string;
}

/** What a completed exchange hands back to the caller. */
export interface SrpVerifyOutcome {
  /** Raw `/auth/srp/verify` body — the same union `/auth/login` returns. */
  data: Record<string, unknown> & {
    server_proof?: string;
    mfa_required?: boolean;
    mfa_setup_required?: boolean;
  };
}

/**
 * Thrown when the tenant does not offer SRP, so the caller can fall back to
 * password login. Distinct from an authentication failure — nothing about the
 * user's credentials was wrong.
 */
export class SrpUnavailableError extends Error {
  constructor() {
    super("This tenant does not use Secure Remote Password.");
    this.name = "SrpUnavailableError";
  }
}

/**
 * Thrown when the server's `M2` does not match.
 *
 * Treated as fatal by every caller: it means the endpoint that answered does
 * not hold the verifier and therefore is not the server it claims to be. Any
 * session it handed out must be discarded rather than used.
 */
export class SrpServerProofMismatchError extends Error {
  constructor() {
    super("The server failed to prove its identity. Sign-in was aborted.");
    this.name = "SrpServerProofMismatchError";
  }
}

function isNotFound(err: unknown): boolean {
  const status = (err as { response?: { status?: number } })?.response?.status;
  return status === 404;
}

/**
 * Run a full SRP login.
 *
 * Throws {@link SrpUnavailableError} when the tenant has SRP disabled, so a
 * caller can transparently fall back to `/auth/login`.
 */
export async function loginSrp(args: {
  usernameOrEmail: string;
  password: string;
  orgSlug: string;
  tenantSlug: string;
}): Promise<SrpVerifyOutcome> {
  // The group is not known until the challenge answers, and `A` has to be
  // computed in the group the server names — so the exchange starts with a
  // probe using the default group, and restarts in the right one if the server
  // names another. In practice the first guess is right; the restart exists so
  // that a tenant on a narrower group is not simply broken.
  let challenge = await requestChallenge(args, "rfc5054_4096");
  let session = challenge.session;

  if (challenge.body.group !== "rfc5054_4096") {
    if (!isKnownGroup(challenge.body.group)) {
      throw new Error(
        `This browser does not support the SRP group this tenant requires (${challenge.body.group}).`
      );
    }
    challenge = await requestChallenge(args, challenge.body.group);
    session = challenge.session;
  }

  const body = challenge.body;
  const params: SrpKdfParams = {
    kdf: body.kdf,
    iterations: body.iterations,
    memory_kib: body.memory_kib,
    parallelism: body.parallelism,
  };

  // `body.identity`, not `args.usernameOrEmail` — CONTRACT §23.3 rule 2.
  const x = await deriveX(body.identity, args.password, body.salt, params);
  const { clientProof, expectedServerProof } = await session.finish({
    identity: body.identity,
    saltHex: body.salt,
    serverPublicHex: body.b_pub,
    x,
  });

  const response = await api.post<SrpVerifyOutcome["data"]>("/api/v1/auth/srp/verify", {
    srp_session: body.srp_session,
    client_proof: clientProof,
  });

  // Mutual authentication. Without this check the client has proved itself to
  // the server but has not proved the server to itself, and an endpoint that
  // never knew the verifier is indistinguishable from the real one.
  if (!verifyServerProof(expectedServerProof, response.data?.server_proof)) {
    throw new SrpServerProofMismatchError();
  }

  return { data: response.data };
}

async function requestChallenge(
  args: { usernameOrEmail: string; orgSlug: string; tenantSlug: string },
  groupName: SrpGroupName
) {
  const session = await beginClientSession(groupName);
  try {
    const response = await api.post<SrpChallenge>("/api/v1/auth/srp/challenge", {
      org_slug: args.orgSlug,
      tenant_slug: args.tenantSlug,
      username_or_email: args.usernameOrEmail,
      client_public: session.clientPublic,
    });
    return { session, body: response.data };
  } catch (err) {
    // 404 is a property of the tenant ("SRP is off here"), not of the user.
    if (isNotFound(err)) throw new SrpUnavailableError();
    throw err;
  }
}

/**
 * Build the `srp` object for any endpoint that sets a password.
 *
 * `identity` must be the account's **username** — the canonical identity the
 * challenge endpoint will later hand back. Passing an email produces a verifier
 * no login can satisfy.
 *
 * Returns `null` when the tenant has SRP disabled, which callers should treat
 * as "omit the field" rather than as an error.
 */
export async function buildEnrollment(args: {
  identity: string;
  password: string;
  group: string;
  kdf: string;
  memoryKib?: number;
  iterations?: number;
  parallelism?: number;
}): Promise<SrpEnrollment | null> {
  if (!isKnownGroup(args.group)) return null;

  const kdf = args.kdf === "pbkdf2_sha256" ? "pbkdf2_sha256" : "argon2id";
  const iterations = args.iterations ?? (kdf === "argon2id" ? 2 : 600_000);
  const memoryKib = kdf === "argon2id" ? (args.memoryKib ?? 19456) : undefined;
  const parallelism = kdf === "argon2id" ? (args.parallelism ?? 1) : undefined;

  const salt = generateSalt();
  const x = await deriveX(args.identity, args.password, salt, {
    kdf,
    iterations,
    memory_kib: memoryKib,
    parallelism,
  });
  const verifier = await computeVerifier(args.group, x);

  return {
    group: args.group,
    kdf,
    ...(memoryKib !== undefined ? { memory_kib: memoryKib } : {}),
    iterations,
    ...(parallelism !== undefined ? { parallelism } : {}),
    salt,
    verifier,
  };
}

/**
 * Build an enrolment for an authenticated user changing their own password.
 *
 * Returns `null` — meaning "omit the `srp` field" — when the user's tenant does
 * not use SRP, when the policy could not be resolved, or when the group is one
 * this browser does not implement. Omitting is the correct fallback in all
 * three cases: the server rejects a verifier outright under `disabled`, and
 * under `optional` a password change without one simply leaves the account
 * unenrolled rather than failing.
 *
 * `user.username` is deliberate: the verifier is bound to the canonical
 * identity, which is always the username even for a user who signs in with
 * their email.
 */
export async function buildEnrollmentForUser(
  user: {
    username: string;
    srp?: { srp_mode: string; srp_group: string; srp_kdf: string };
  } | null,
  password: string
): Promise<SrpEnrollment | null> {
  const policy = user?.srp;
  if (!user || !policy || policy.srp_mode === "disabled") return null;
  return buildEnrollment({
    identity: user.username,
    password,
    group: policy.srp_group,
    kdf: policy.srp_kdf,
  });
}

/**
 * What the unauthenticated reset page needs in order to enrol a verifier.
 *
 * The page holds a token and a tenant id, and knows neither the account's
 * username — which the verifier is bound to — nor the tenant's group and KDF.
 * `GET /api/v1/auth/reset/context` supplies both to a caller who has already
 * proved they hold a valid reset token, and reads that token without consuming
 * it.
 */
export interface ResetContext {
  identity: string;
  srp?: { srp_mode: string; srp_group: string; srp_kdf: string };
}

/**
 * Build the enrolment for a password reset.
 *
 * Returns `null` — "omit the `srp` field" — when the tenant does not use SRP,
 * or when the context lookup fails. A lookup failure must not block the reset:
 * the confirm call is the authoritative check on the token, and failing here
 * would turn a transient error into a user who cannot recover their account.
 */
export async function buildEnrollmentForReset(args: {
  tenantId: string;
  token: string;
  password: string;
}): Promise<SrpEnrollment | null> {
  let context: ResetContext;
  try {
    const response = await api.get<ResetContext>("/api/v1/auth/reset/context", {
      params: { tenant_id: args.tenantId, token: args.token },
    });
    context = response.data;
  } catch {
    return null;
  }

  if (!context.srp || context.srp.srp_mode === "disabled") return null;
  return buildEnrollment({
    identity: context.identity,
    password: args.password,
    group: context.srp.srp_group,
    kdf: context.srp.srp_kdf,
  });
}
