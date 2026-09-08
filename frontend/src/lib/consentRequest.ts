/**
 * What a consent hop is being asked about (W7, `claude_dev/basic-op-gap-plan.md` §4.8).
 *
 * `/oauth2/authorize` sends a signed-in browser to `/consent?return_to=<path>`
 * when a request asks for `address` or `phone` and no consent record covers
 * them. The redirect carries **no** `client_id` and **no** `scope` of its own,
 * and that is deliberate: `return_to` already contains the whole authorization
 * request, it has already been validated on both sides
 * (`@/lib/returnTo`, `axiam_oauth2::login_hop::validate_return_to`), and a
 * second copy of either value would be a second thing to keep in agreement
 * with the first — and the one an attacker would edit.
 *
 * So the page reads both back out of the value it was going to navigate to
 * anyway. If the two ever disagreed, the request the user consented to and the
 * request that gets a code would be different requests.
 *
 * # This is a display and a form input, not an authorisation
 *
 * Nothing here decides anything. The server re-derives the client and the
 * scope set from the authorization request on the return leg, re-checks the
 * tenant switch, re-checks that the client has the scopes registered, and
 * re-reads the consent record before UserInfo releases anything. A person who
 * edits this URL changes what they are *shown* and what they *ask to record* —
 * and `POST /api/v1/account/consents/oidc-scopes` refuses a client that does
 * not exist, a scope the client has not registered, and a scope that is not
 * one of the two. The worst outcome is recording a consent for a release that
 * then never happens.
 */

import { sanitizeReturnTo } from "./returnTo";

/** Mirrors `axiam_oauth2::fapi::SENSITIVE_SCOPES`, in the same order. */
export const SENSITIVE_SCOPES = ["address", "phone"] as const;

export type SensitiveScope = (typeof SENSITIVE_SCOPES)[number];

export interface ConsentRequest {
  /** The relying party, verbatim from the authorization request. */
  clientId: string;
  /**
   * The sensitive scopes it asked for, in the canonical order
   * `SENSITIVE_SCOPES` declares — not the order the relying party sent.
   *
   * The server names its consent record by this same canonical ordering
   * (`axiam_oauth2::sensitive::consent_version`), so a page that posted the
   * request's order would record a version the release gate never matches.
   */
  scopes: SensitiveScope[];
}

/**
 * Read the client and the sensitive scopes out of a `return_to`.
 *
 * `null` when the value is not a `return_to` this page may act on at all, when
 * it names no client, or when it asks for nothing sensitive — the three cases
 * a caller answers the same way, by showing "there is nothing to decide here"
 * rather than a consent form with no subject.
 */
export function parseConsentRequest(
  rawReturnTo: string | null | undefined,
): ConsentRequest | null {
  const returnTo = sanitizeReturnTo(rawReturnTo);
  if (!returnTo) return null;

  const query = returnTo.slice(returnTo.indexOf("?") + 1);
  const params = new URLSearchParams(query);

  const clientId = params.get("client_id");
  if (!clientId) return null;

  const asked = new Set((params.get("scope") ?? "").split(/\s+/));
  const scopes = SENSITIVE_SCOPES.filter((s) => asked.has(s));
  if (scopes.length === 0) return null;

  return { clientId, scopes };
}
