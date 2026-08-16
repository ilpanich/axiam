import type { AxiosError } from "axios";

interface ApiErrorData {
  error?: string;
  message?: string;
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
 * Extract a human-readable error message from any thrown value.
 *
 * Priority order (mirrors LoginPage.tsx AxiosError unwrapping):
 *   1. response.data.error  (backend field name used in most handlers)
 *   2. response.data.message
 *   3. error.message        (plain Error or AxiosError network message)
 *   4. Generic fallback     (never returns empty)
 *
 * Every branch that returns server- or exception-supplied text passes through
 * [`redactSecrets`] first. The generic fallback is a constant and needs no
 * such treatment.
 */
export function getApiErrorMessage(err: unknown): string {
  if (err == null) {
    return "An unexpected error occurred. Please try again.";
  }

  const axiosErr = err as AxiosError<ApiErrorData>;
  if (axiosErr.isAxiosError) {
    if (axiosErr.response?.data) {
      const data = axiosErr.response.data;
      if (typeof data.error === "string" && data.error.length > 0) {
        return redactSecrets(data.error);
      }
      if (typeof data.message === "string" && data.message.length > 0) {
        return redactSecrets(data.message);
      }
    }
    if (typeof axiosErr.message === "string" && axiosErr.message.length > 0) {
      return redactSecrets(axiosErr.message);
    }
  }

  if (err instanceof Error && err.message.length > 0) {
    return redactSecrets(err.message);
  }

  return "An unexpected error occurred. Please try again.";
}
