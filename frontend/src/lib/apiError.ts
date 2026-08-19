/**
 * The body shape AXIAM's HTTP surfaces actually return.
 *
 * Two conventions overlap here and the difference is load-bearing:
 *
 * - `axiam-api-rest`'s `ErrorBody` sends **both** `error` and `message` on
 *   every failure, and `error` is a *machine slug* — `not_found`,
 *   `validation_error`, `already_exists`, `authorization_denied`. The
 *   human-readable sentence is always in `message`.
 * - OAuth2/OIDC endpoints follow RFC 6749: `error` is again a slug
 *   (`invalid_grant`, `invalid_client`) and the prose lives in
 *   `error_description`.
 *
 * In both conventions `error` is the field a *program* branches on and the
 * last one a *person* should be shown. Exported so pages can type a response
 * body without re-declaring this interface — six of them used to.
 */
export interface ApiErrorData {
  /** Machine-readable slug. Branch on it; do not render it. */
  error?: string;
  /** Human-readable sentence (axiam-api-rest `ErrorBody`). */
  message?: string;
  /** Human-readable sentence (RFC 6749 OAuth2/OIDC errors). */
  error_description?: string;
}

// ─── Secret redaction ─────────────────────────────────────────────────────────

/**
 * Longest error message the UI will render.
 *
 * Not cosmetic. Every message this module returns is server-controlled text
 * rendered verbatim, and the failure mode that matters is a body that echoes
 * the *request* — a proxy 413 page, an upstream gateway error, a future
 * handler that interpolates its input. Those are long, and length is the one
 * signal available before any pattern matches. A message this long is not a
 * sentence written for a human; truncating it costs nothing and bounds how
 * much of an echoed payload can reach a screenshot or a bug report.
 */
const MAX_MESSAGE_LENGTH = 500;

/**
 * Patterns for values that are credentials wherever they appear.
 *
 * Deliberately narrow. An over-eager redactor that mangles ordinary errors
 * gets worked around — somebody starts reading the network tab instead — and
 * then it protects nothing. Every pattern below matches a shape that is a
 * secret *by construction*, not one that merely might be.
 */
const SECRET_PATTERNS: readonly { re: RegExp; label: string }[] = [
  // AXIAM SCIM provisioning handles. The `axiam_scim_` prefix exists so
  // scanners can find a leaked token (see `axiam_core::models::scim_token`);
  // that same prefix is what lets this redact one with no false positives.
  { re: /axiam_scim_[A-Za-z0-9_-]{8,}/g, label: "[redacted: scim token]" },
  // JWTs — access tokens, id tokens, client assertions, DPoP proofs.
  {
    re: /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+/g,
    label: "[redacted: jwt]",
  },
  // An Authorization header echoed into a message.
  {
    re: /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi,
    label: "[redacted: bearer token]",
  },
  // PEM private key material.
  {
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    label: "[redacted: private key]",
  },
  // `"password": "..."` / `client_secret=...` and friends, as they appear when
  // a request body or query string is echoed back. The key must be one of the
  // named secrets, so `scim:provision` and `provisioning_token bound to them`
  // — both real substrings of messages this app shows — are left intact.
  {
    re: /"?\b(password|api_key|apiKey|client_secret|clientSecret|secret|private_key|privateKey|provisioning_token|refresh_token|access_token)\b"?\s*[:=]\s*"?[^"',;&}\s]+/gi,
    label: "$1=[redacted]",
  },
];

/** Last-resort message, used when nothing else yields text. */
const GENERIC_ERROR_MESSAGE = "An unexpected error occurred. Please try again.";

/**
 * Strip credential-shaped content from a message before it reaches the UI.
 *
 * `getApiErrorMessage` hands back whatever the server put in the body, at ~38
 * call sites — including the forms that carry passwords, SMTP passwords,
 * provider API keys, OAuth2 client secrets, PGP plaintext, device codes,
 * account-export tokens and SCIM provisioning handles. AXIAM's own handlers
 * are careful today and none of them echo a secret; this exists because
 * "careful today" is a property of ~35 handler modules that keep being added
 * to, and because the body is not always written by AXIAM at all — a reverse
 * proxy, a load balancer, or a gateway can answer instead, and those echo
 * requests routinely.
 *
 * Exported for tests and for callers that surface a server message through
 * some path other than this module.
 */
export function redactSecrets(message: string): string {
  let out = message;
  for (const { re, label } of SECRET_PATTERNS) {
    // `re` is a module-level /g regex; `replace` resets lastIndex itself, but
    // the shared object means `test`/`exec` must not be used on these.
    out = out.replace(re, label);
  }
  if (out.length > MAX_MESSAGE_LENGTH) {
    out = `${out.slice(0, MAX_MESSAGE_LENGTH)}… (truncated)`;
  }
  return out;
}

/**
 * The subset of a rejected request this module reads.
 *
 * Deliberately structural rather than `AxiosError`. Axios brands its own
 * errors with `isAxiosError: true`, and keying off that brand would put the
 * transport back into every caller — and, worse, into every *test*, which
 * would then have to fake an axios internal to exercise an error path. The
 * shape below is what an HTTP client rejection looks like in any library, so
 * a component, a hook and a test double all describe an error the same way.
 */
interface ErrorLike {
  response?: { status?: number; data?: ApiErrorData };
  message?: string;
}

/** Read `value` as {@link ErrorLike} when it could plausibly be one. */
function asErrorLike(value: unknown): ErrorLike | undefined {
  return typeof value === "object" && value !== null ? (value as ErrorLike) : undefined;
}

/** The first non-empty string in `candidates`, or `undefined`. */
function firstNonEmpty(candidates: readonly (string | undefined)[]): string | undefined {
  return candidates.find((c): c is string => typeof c === "string" && c.length > 0);
}

/**
 * Extract a human-readable error message from any thrown value.
 *
 * Priority order:
 *   1. response.data.message            (axiam-api-rest's human sentence)
 *   2. response.data.error_description  (RFC 6749's human sentence)
 *   3. response.data.error              (a slug — last resort, see below)
 *   4. `fallback`, when the caller supplied one
 *   5. error.message                    (a plain Error, or a network message)
 *   6. a generic constant               (never returns empty)
 *
 * **`message` outranks `error`, and that ordering is the point.** This helper
 * used to read `error` first, on the reasonable-sounding basis that it is "the
 * backend field name used in most handlers". It is — but what it *carries* is
 * `axiam_api_rest::error::ErrorBody`'s slug, not prose. Both fields are always
 * present on an AXIAM error, so reading `error` first meant every one of the
 * ~40 call sites rendered `validation_error` where the server had written
 * "Validation error: email must be a valid email address".
 *
 * Six pages had already noticed and hand-rolled the correct order inline. That
 * is how the ordering bug survived: the pages that would have exposed it were
 * the ones routing around it — and three of them dropped {@link redactSecrets}
 * on the way past, which is the more expensive half of the same mistake.
 *
 * `fallback` supplies the page-specific last resort those inline versions had
 * ("This reset link is invalid or has expired.") so that migrating to this
 * helper costs no message quality.
 *
 * **`fallback` outranks `error.message`, and only `fallback`.** `error.message`
 * on a transport failure is a developer string — "Network Error", "timeout of
 * 0ms exceeded", "Request failed with status code 500". A page that has
 * bothered to write "This reset link is invalid or has expired. Please request
 * a new one." has said something more useful than any of those, and the inline
 * implementations this replaces all agreed: none of them read `err.message` at
 * all. Callers that pass no `fallback` keep the old behaviour and still see
 * `error.message`, because for them the alternative is only the generic
 * constant.
 *
 * Every branch that returns server- or exception-supplied text passes through
 * {@link redactSecrets} first. `fallback` and the generic constant are
 * caller-authored constants and need no such treatment.
 */
export function getApiErrorMessage(err: unknown, fallback?: string): string {
  const last = fallback ?? GENERIC_ERROR_MESSAGE;
  const e = asErrorLike(err);
  if (!e) {
    return last;
  }
  const data = e.response?.data;
  const serverText = firstNonEmpty([data?.message, data?.error_description, data?.error]);
  if (serverText !== undefined) {
    return redactSecrets(serverText);
  }
  if (fallback !== undefined) {
    return fallback;
  }
  const transportText = firstNonEmpty([e.message]);
  return transportText === undefined ? last : redactSecrets(transportText);
}

/**
 * The machine-readable slug from an API error body, or `undefined`.
 *
 * The counterpart to {@link getApiErrorMessage}: this is the field to branch
 * on, and the one never to render. Kept here so a caller that needs to
 * distinguish `password_policy_violation` from `validation_error` does not
 * reach for `AxiosError` to do it.
 */
export function getApiErrorCode(err: unknown): string | undefined {
  const code = asErrorLike(err)?.response?.data?.error;
  return typeof code === "string" && code.length > 0 ? code : undefined;
}

/**
 * The HTTP status of a failed request, or `undefined` if there was no response.
 *
 * Exists so a page can ask "was this a 403?" without importing `AxiosError`.
 * That import was the last reason any component needed to know the app talks
 * to the server over Axios, and a page that knows its transport is a page that
 * has to change when the transport does.
 *
 * `undefined` means *no HTTP response arrived* — a timeout, a DNS failure, a
 * TLS error. It is deliberately not conflated with `0`, so
 * `getApiErrorStatus(err) === undefined` is a usable test for "the request
 * never landed" rather than an ambiguous falsy check.
 */
export function getApiErrorStatus(err: unknown): number | undefined {
  const status = asErrorLike(err)?.response?.status;
  return typeof status === "number" ? status : undefined;
}
