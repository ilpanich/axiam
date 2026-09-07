/**
 * The two inputs a reauthentication hop carries (W4, `claude_dev/basic-op-gap-plan.md` §4.2/§4.4).
 *
 * `/oauth2/authorize` sends the browser here with `?reauth=1` when it needs the
 * end user to authenticate again — because the relying party sent
 * `prompt=login`, because the session is older than the `max_age` it asked for,
 * because an `id_token_hint` names somebody else, or because it asked for an
 * authentication context class this session does not satisfy. In the last case
 * the redirect also carries `?acr=…`, naming the one factor this sign-in has to
 * demand.
 *
 * Two things live here, and both are guards rather than features:
 *
 * 1. {@link sanitizeRequiredAcr} — an allow-list of exactly two values. The
 *    page never *chooses* an authentication context class and never reports
 *    one; the server derives the class from what the session actually proves,
 *    from evidence the request cannot reach (`axiam_oauth2::acr::acr_for`). All
 *    this value does is decide which factor the form insists on, so accepting
 *    an arbitrary string would put a relying-party- or attacker-chosen value on
 *    a page for no gain at all.
 * 2. {@link recordReauthAttempt} — the loop guard the plan asks for (T1.6).
 *
 * # Why the loop guard exists when the server already has one
 *
 * The server's guard bounds one chain: an authorization request it redirected
 * is answered rather than redirected again. That is enough to stop the server
 * looping. It is not enough to stop a *relying party* looping — an RP that
 * receives `login_required` and immediately restarts the authorization request
 * produces a fresh chain each time, and every chain is individually
 * well-behaved. From the end user's side that is an unbroken sequence of login
 * pages.
 *
 * Each iteration does require a user action, so it is not automatic. It is
 * still the shape a misconfigured deployment produces — an RP demanding
 * `max_age=0`, or an essential authentication context class nobody can
 * satisfy — and the honest answer after three tries in a minute is to stop and
 * say so rather than to show a fourth form.
 */

/** Mirrors `axiam_oauth2::oidc::ACR_SINGLE_FACTOR`. */
export const ACR_SINGLE_FACTOR = "urn:axiam:acr:1fa";

/** Mirrors `axiam_oauth2::oidc::ACR_MULTI_FACTOR`. */
export const ACR_MULTI_FACTOR = "urn:axiam:acr:mfa";

/** The whole vocabulary. Two values, and no way to add a third from a URL. */
export type RequiredAcr = typeof ACR_SINGLE_FACTOR | typeof ACR_MULTI_FACTOR;

/**
 * The factor this sign-in must demand, or `null`.
 *
 * `null` for an absent value, an unknown one, and a well-formed one this build
 * does not know — all three mean the same thing to the caller: sign in the
 * ordinary way and let the server judge the result.
 */
export function sanitizeRequiredAcr(
  raw: string | null | undefined,
): RequiredAcr | null {
  if (raw === ACR_SINGLE_FACTOR) return ACR_SINGLE_FACTOR;
  if (raw === ACR_MULTI_FACTOR) return ACR_MULTI_FACTOR;
  return null;
}

/** How many reauthentication hops for one destination are tolerated. */
export const REAUTH_MAX_ATTEMPTS = 3;

/** The window those attempts are counted over, in milliseconds. */
export const REAUTH_WINDOW_MS = 60_000;

/** Where the counter lives. Per tab, and gone when the tab is. */
const STORAGE_KEY = "axiam.reauth.attempts";

/** The largest number of destinations tracked at once. */
const MAX_TRACKED = 8;

type Attempts = Record<string, number[]>;

function read(storage: Storage): Attempts {
  try {
    const raw = storage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const out: Attempts = {};
    for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (Array.isArray(value)) {
        out[key] = value.filter((t): t is number => typeof t === "number");
      }
    }
    return out;
  } catch {
    // A private window, a quota, a value somebody else wrote. The guard is a
    // convenience for the end user and must never be the reason a sign-in
    // cannot proceed.
    return {};
  }
}

function write(storage: Storage, attempts: Attempts): void {
  try {
    storage.setItem(STORAGE_KEY, JSON.stringify(attempts));
  } catch {
    // As above.
  }
}

/**
 * Record one reauthentication hop for `returnTo` and say whether to proceed.
 *
 * `true` — show the form. `false` — this destination has asked for
 * {@link REAUTH_MAX_ATTEMPTS} sign-ins inside {@link REAUTH_WINDOW_MS} and the
 * caller should show an error instead.
 *
 * Keyed by destination rather than counted globally: a user legitimately
 * signing in to three relying parties in a minute is not looping, and a user
 * being sent back to the *same* authorization request four times is.
 *
 * `now` and `storage` are parameters so the guard is testable without a clock
 * or a browser; both default to the real thing.
 */
export function recordReauthAttempt(
  returnTo: string,
  now: number = Date.now(),
  storage: Storage | null = typeof window === "undefined"
    ? null
    : window.sessionStorage,
): boolean {
  if (!storage) return true;

  const attempts = read(storage);
  const recent = (attempts[returnTo] ?? []).filter(
    (at) => now - at < REAUTH_WINDOW_MS && at <= now,
  );
  recent.push(now);

  // Drop destinations whose attempts have all aged out, then bound the map so
  // a tab that visits many relying parties cannot grow it without limit. The
  // cost of evicting too eagerly is one forgotten counter.
  const pruned: Attempts = {};
  for (const [key, times] of Object.entries(attempts)) {
    if (key === returnTo) continue;
    const live = times.filter((at) => now - at < REAUTH_WINDOW_MS && at <= now);
    if (live.length > 0) pruned[key] = live;
  }
  const keys = Object.keys(pruned);
  for (const stale of keys.slice(0, Math.max(0, keys.length - (MAX_TRACKED - 1)))) {
    delete pruned[stale];
  }
  pruned[returnTo] = recent;
  write(storage, pruned);

  return recent.length <= REAUTH_MAX_ATTEMPTS;
}

/**
 * Forget the attempts recorded for `returnTo`.
 *
 * Called once a sign-in has completed and the browser is about to be sent
 * back: the hop that produced this page is over, and counting it against the
 * next one would make a user who signs in slowly look like a loop.
 */
export function clearReauthAttempts(
  returnTo: string,
  storage: Storage | null = typeof window === "undefined"
    ? null
    : window.sessionStorage,
): void {
  if (!storage) return;
  const attempts = read(storage);
  delete attempts[returnTo];
  write(storage, attempts);
}
