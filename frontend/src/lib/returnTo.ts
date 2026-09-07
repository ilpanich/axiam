/**
 * The `return_to` a login hop comes back to (W3, `claude_dev/basic-op-gap-plan.md` §4.0).
 *
 * When `/oauth2/authorize` is reached by an anonymous browser on behalf of a
 * client registered `browser_sso`, the server redirects here with
 * `?return_to=<path>` and the page navigates back to it once the user has
 * signed in. That value decides where a browser goes immediately after
 * authenticating, which makes an unvalidated one an open redirect with the best
 * possible timing.
 *
 * So it is validated on **both** sides. The server builds it and checks it
 * (`axiam_oauth2::login_hop::validate_return_to`, plus a resolve-and-compare
 * against the deployment's own origin), and this module checks it again before
 * the page will navigate to it. The two implementations are deliberately the
 * same short list of rules, in the same order, so that a change to one is
 * visibly a change to the other:
 *
 * 1. bounded length;
 * 2. no control characters, whitespace, `#` or `\`;
 * 3. begins with a single `/` — not `//`, which reads as a path and resolves
 *    to a different host;
 * 4. the path is exactly `/oauth2/authorize` and there is a query.
 *
 * Rule 4 is what makes traversal a non-question: nothing is normalised and
 * then compared, because nothing but the exact path is accepted in the first
 * place.
 */

/** The only path a `return_to` may name. Mirrors `login_hop::AUTHORIZE_PATH`. */
export const AUTHORIZE_PATH = "/oauth2/authorize";

/** Mirrors `login_hop::MAX_RETURN_TO_LEN`. */
export const MAX_RETURN_TO_LENGTH = 4096;

/**
 * The `return_to` this page may navigate to, or `null`.
 *
 * `null` for every rejected value and for an absent one alike: the caller's
 * behaviour is the same either way — go to the dashboard — and giving the two
 * different names would invite a caller to treat "rejected" as recoverable.
 */
export function sanitizeReturnTo(raw: string | null | undefined): string | null {
  if (!raw) return null;
  if (raw.length > MAX_RETURN_TO_LENGTH) return null;

  // Control characters (C0 and C1, plus DEL), any whitespace, a fragment, and
  // the backslash several browsers normalise to `/`. Two expressions because
  // JavaScript's `\s` already covers Unicode whitespace and a hand-written
  // range would not — the same set Rust's `char::is_whitespace` gives the
  // server-side check.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f#\\]/.test(raw)) return null;
  if (/\s/.test(raw)) return null;

  if (!raw.startsWith("/")) return null;
  if (raw.startsWith("//")) return null;

  const queryStart = raw.indexOf("?");
  if (queryStart < 0) return null;
  const path = raw.slice(0, queryStart);
  const query = raw.slice(queryStart + 1);
  if (path !== AUTHORIZE_PATH) return null;
  if (query.length === 0) return null;

  return raw;
}
