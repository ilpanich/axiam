import { getApiErrorMessage } from "@/lib/apiError";

/** The longest server sentence shown in place. */
const MAX_LENGTH = 500;

/**
 * The text to show for a failed directory write — **the server's own sentence,
 * verbatim**, for the two answers whose wording *is* the instruction.
 *
 * `400 validation_error` names the rule that refused the write (a plaintext URL,
 * an address the deployment will not connect to, "requires entering the bind
 * secret again", …) and `409 conflict` says that an enabled directory and
 * `opaque_mode = required` cannot both be in force. §30.3 promises neither ever
 * echoes the bind secret, so the generic redactor — which rewrites "secret:
 * must not be empty" into `secret=[redacted]` because it cannot know that — is
 * not applied to them. Anything else (a `503`, a gateway's page, a network
 * failure) goes through {@link getApiErrorMessage} as everywhere.
 *
 * As a second line of defence for the one value that matters here, an
 * occurrence of the secret the operator just typed is blanked out of whatever is
 * returned.
 */
export function directoryErrorMessage(
  err: unknown,
  typedSecret: string,
  fallback = "The directory request failed.",
): string {
  const data = (
    err as { response?: { data?: { error?: unknown; message?: unknown } } }
  )?.response?.data;
  const verbatim =
    (data?.error === "validation_error" || data?.error === "conflict") &&
    typeof data.message === "string" &&
    data.message.length > 0;
  let text = verbatim
    ? (data.message as string).slice(0, MAX_LENGTH)
    : getApiErrorMessage(err, fallback);
  if (typedSecret.length >= 4) {
    text = text.split(typedSecret).join("[redacted]");
  }
  return text;
}
