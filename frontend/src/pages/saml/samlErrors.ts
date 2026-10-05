import { getApiErrorMessage } from "@/lib/apiError";

/** The longest server sentence shown in place. */
const MAX_LENGTH = 500;

/**
 * The answers whose wording *is* the instruction. Contract §29.4: `400` names
 * the field and the rule, `409` says which slot is occupied or which credential
 * is not the current `next`, `404` says which CA the caller may not use, `503`
 * says the server was built without SAML.
 */
const VERBATIM = new Set([
  "validation_error",
  "conflict",
  "not_found",
  "service_unavailable",
]);

const PRIVATE_KEY_BLOCK =
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;

/**
 * The text to show for a failed SAML request: **the server's own sentence,
 * verbatim**, for `validation_error`, `conflict`, `not_found` and
 * `service_unavailable`.
 *
 * §29.3 rule 1 promises a `400` message names the field and the rule and "never
 * echoes a certificate", and rule 6 that a metadata refusal is one of three
 * generic categories that never carry the fetched body. The generic redactor in
 * `getApiErrorMessage` cannot know that: it rewrites any `key: value` shape
 * that ends in a secret-sounding word, which turns a rule such as
 * "sp_signing_cert_pem: private key not accepted" into noise. So these answers
 * bypass it. Anything else (a `403`, a `429`, a gateway's page, a network
 * failure) goes through {@link getApiErrorMessage} as everywhere.
 *
 * As a second line of defence, a PEM private-key block is blanked out of
 * whatever is returned: nothing on this page ever holds one, but an
 * administrator who pastes one into a certificate field must not see it
 * reflected back.
 */
export function samlErrorMessage(
  err: unknown,
  fallback = "The SAML request failed.",
): string {
  const data = (
    err as { response?: { data?: { error?: unknown; message?: unknown } } }
  )?.response?.data;
  const verbatim =
    typeof data?.error === "string" &&
    VERBATIM.has(data.error) &&
    typeof data.message === "string" &&
    data.message.length > 0;
  const text = verbatim
    ? (data.message as string).slice(0, MAX_LENGTH)
    : getApiErrorMessage(err, fallback);
  return text.replace(PRIVATE_KEY_BLOCK, "[redacted: private key]");
}
