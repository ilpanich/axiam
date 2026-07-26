# G4 — AXIAM `token_refresh` harness diagnosis (A8 residual)

**Status:** root cause proven from server source; fix applied to
`benchmarks/scenarios/lib/auth.js` and `benchmarks/scenarios/token_refresh.js`.
No live stack in this sandbox (no docker/k6) — the laptop confirmation command
is at the bottom. `benchmarks/scenarios/lib/targets.js` is **not** edited here
(owned by another agent this round); the exact change it still needs is
described in §4.

## Symptom (run 3)

AXIAM's `token_refresh` cell fired `bench_fallback` on 100% of iterations
(9,774/9,774), 2 HTTP requests/iteration (the client-credentials-fallback
signature), while Keycloak's identical code path measured 379 req/s with
**zero** fallback and **one** request/iteration.

## Root cause 1 (primary, sufficient by itself): cookie `Path` mismatch

`readAccessFromLogin()` (`benchmarks/scenarios/lib/auth.js`, pre-fix line 43)
read the jar with:

```js
const cookies = jar.cookiesForURL(built.url);   // built.url = .../api/v1/auth/login
```

but the server scopes the three login cookies to **different paths**:

- `axiam_access` — `Path=/` —
  `crates/axiam-api-rest/src/middleware/csrf.rs:209-217` (`access_cookie()`)
- `axiam_csrf` — `Path=/` —
  `crates/axiam-api-rest/src/middleware/csrf.rs:242-250` (`csrf_cookie()`)
- `axiam_refresh` — **`Path=/api/v1/auth/refresh`** —
  `crates/axiam-api-rest/src/middleware/csrf.rs:224-231` (`refresh_cookie()`):

  ```rust
  pub fn refresh_cookie(token: &str, max_age_secs: u64, cookie_secure: bool) -> Cookie<'static> {
      Cookie::build(COOKIE_REFRESH, token.to_owned())
          .http_only(true)
          .secure(cookie_secure)
          .same_site(SameSite::Strict)
          .path("/api/v1/auth/refresh")
          .max_age(Duration::seconds(max_age_secs as i64))
          .finish()
  }
  ```

Per RFC 6265 path-matching, a cookie scoped to `/api/v1/auth/refresh` is
**not** returned for a request/jar-lookup against `/api/v1/auth/login`
(`/api/v1/auth/refresh` is not a path-prefix of `/api/v1/auth/login` — they
diverge at `refresh` vs `login`). So `jar.cookiesForURL(loginUrl)` correctly
returns `axiam_access`/`axiam_csrf` (both `Path=/`) but **never**
`axiam_refresh`. `readAccessFromLogin()` therefore always returned
`refresh_token: undefined` for AXIAM, and `mintUserToken()` /
`token_refresh.js` always took the "target issued no refresh token" fallback
branch (`m.fallback.add(1); doOp(a.clientCredentials())`) — 100% fallback,
exactly as observed.

This is fully proven by source and is **not** dependent on the `Secure`
question below: `authz_check_rest` uses the exact same `readAccessFromLogin()`
at the same `p0-plaintext` profile and correctly retrieves `axiam_access`/
`axiam_csrf` every time (737-1013+ req/s in run 3, no fallback) — proof that
whatever the jar does with `Secure` cookies over `http://`, it isn't blocking
these two `Path=/` cookies. Only the narrowly-scoped `axiam_refresh` cookie
was ever missed, and Path is the only attribute that differs.

### Secondary/latent finding: `Secure` is not profile-aware (worth fixing, not the cause here)

`AuthConfig::cookie_secure` defaults to `true`
(`crates/axiam-auth/src/config.rs:189`) and is applied unconditionally to all
three cookies (`crates/axiam-api-rest/src/middleware/csrf.rs:212,227,245`).
`benchmarks/targets/axiam/docker-compose.yml` sets no
`AXIAM__AUTH__COOKIE_SECURE` override for any profile (grepped, no match), so
even under `p0-plaintext` (`http://`, no TLS) the server still sends
`Set-Cookie: ...; Secure`. As shown above this did **not** turn out to be why
`token_refresh` failed (the `Path`-scoped cookies without this problem also
worked fine), but it's a real config gap: a `Secure` cookie set from a plain
`http://` origin is out-of-spec and some HTTP clients refuse to attach it back
to later `http://` requests (RFC 6265bis §4.1.2.5 discourages exactly this).
Recommend (not part of this diff, `docker-compose.yml` is out of scope):
`AXIAM__AUTH__COOKIE_SECURE=false` for the `p0-plaintext` bench profile only,
matching the profile's own `BENCH_VERIFY_TLS=false` intent.

## Root cause 2 (would have surfaced immediately after fixing #1): wrong redemption endpoint

Even with the cookie correctly extracted, the pre-fix `token_refresh.js` calls
`doOp(a.refresh(vuRefresh))`, and `targets.js`'s `axiam.refresh()` POSTs to
**`/oauth2/token?grant_type=refresh_token`**. That is the wrong endpoint for a
login-issued refresh token:

- `POST /api/v1/auth/login` mints its refresh token via axiam-auth's
  **`SessionRepository`** —
  `crates/axiam-auth/src/service.rs:942-980` (`create_session_and_tokens()`,
  called from `login()`), token stored via `session_repo.create(...)`.
- `POST /oauth2/token` with `grant_type=refresh_token` looks the presented
  token up in a **different** store, the OAuth2
  **`RefreshTokenRepository`** —
  `crates/axiam-oauth2/src/token.rs:446-649` (`handle_refresh_token()`),
  specifically the lookup at lines 501-509:

  ```rust
  // Look up the refresh token by hash (after client auth)
  let token_hash = hash_refresh_token(raw_token);
  self.refresh_token_repo
      .find_by_hash(tenant_id, &token_hash)
      ...
      OAuth2Error::InvalidGrant("refresh token is invalid, expired, or revoked".into())
  ```

A session-login refresh token is never written to that table (only
`authorization_code`-flow refresh issuance would write there — see
`token.rs:268-287` — and AXIAM's `client_credentials` grant issues **no**
refresh token at all, `token.rs:335,436`). So posting a login-issued refresh
token to `/oauth2/token` always returns `invalid_grant`/401. This is why the
harness fix could not simply "read the cookie correctly" — it also had to
target the correct endpoint.

The correct redemption target is the REST **session** refresh endpoint:

- `POST /api/v1/auth/refresh` —
  `crates/axiam-api-rest/src/handlers/auth.rs:421-480`.
  - Reads the refresh token **only** from the `axiam_refresh` cookie (no body
    or header alternative) — lines 429-434.
  - Requires the JSON body `RefreshRequest { tenant_id: Uuid, org_id: Uuid }`
    (`handlers/auth.rs:99-103`) — `org_id` must deserialize as a UUID but is
    not actually trusted; the handler re-derives the authoritative org from
    `tenant_id` (`handlers/auth.rs:449-451`, `org_id: tenant.organization_id`).
  - Requires the CSRF double-submit header `X-CSRF-Token` matching the
    `axiam_csrf` cookie — this path is **not** in `CSRF_EXEMPT_SUFFIXES`
    (`crates/axiam-api-rest/src/middleware/csrf.rs:42-68`; only `/login`,
    the MFA/reset/federation endpoints, and the `/oauth2/` prefix are
    exempt), so a request missing the header/cookie pair 403s
    (`AuthorizationDenied`, `middleware/csrf.rs:170-181`) before the handler
    even runs.
  - On success, rotates **all three** cookies (new access/refresh/csrf,
    `handlers/auth.rs:461-476`) but the JSON body carries only
    `{ expires_in }` (`RefreshSuccessResponse`, `handlers/auth.rs:95-97`) —
    **no tokens in the body**. The new refresh/csrf values are therefore only
    obtainable from `Set-Cookie` on that response (i.e., read back out of the
    jar), never from `doOp()`'s parsed body.

## The fix

`benchmarks/scenarios/lib/auth.js`:

1. `readAccessFromLogin()` now also probes the jar against the refresh
   cookie's own path (`${origin}/api/v1/auth/refresh`), in addition to the
   login URL, and merges the result. Pure jar read, no extra request; a
   harmless no-op for targets that never set an `axiam_refresh`-named cookie.
2. `mintUserToken()` now also returns `csrf_token` (previously dropped on the
   floor — `loginSession()` already extracted it, `mintUserToken()` didn't).
3. New `axiamRefreshOp(refreshToken, csrfToken)`: builds a
   `POST /api/v1/auth/refresh` request with the `axiam_refresh`/`axiam_csrf`
   cookies set explicitly, the `X-CSRF-Token` header, and a
   `{ tenant_id, org_id }` JSON body from `cfg` (same assumption
   `axiam.clientCredentials()`/`axiam.introspect()`/`axiam.refresh()` already
   make in `targets.js` today — `cfg.tenantId` is expected to hold a real UUID,
   populated by `seed.sh`'s `BENCH_TENANT_ID`/`BENCH_ORG_ID`).
4. New `readAxiamRefreshCookies(jar)`: re-reads the rotated
   `axiam_refresh`/`axiam_csrf` pair from the jar after redemption (JSON body
   has nothing to read).

`benchmarks/scenarios/token_refresh.js`:

- Tracks a per-VU `vuCsrf` alongside `vuRefresh`.
- For `cfg.target === 'axiam'`, calls `axiamRefreshOp()`/
  `readAxiamRefreshCookies()` instead of the generic `a.refresh(vuRefresh)`
  (which remains used, unchanged, for Keycloak/Zitadel — Keycloak's path was
  already proven correct at 379 req/s and is untouched).
- On a failed redemption, `vuRefresh` resets to `null` so the VU re-mints via
  `mintUserToken()` on the next iteration, same recovery pattern as before.

Both files pass `node --check` (validated via `.mjs` copies, since this
sandbox's Node auto-detects module syntax inconsistently for the bare `.js`
extension used by k6 scenario files — see caveat in §5). k6 itself is not
installed in this sandbox; the import graph (`k6/http`, `k6/encoding`, `k6`)
cannot be resolved or exercised here.

## §4 — the change `targets.js` still needs (not applied here; out of scope this round)

The fix above is deliberately implemented as an AXIAM-only branch inside
`token_refresh.js` + AXIAM-only helpers in `auth.js`, so it does not require
touching `targets.js`. For architectural consistency (targets.js's own header
comment: "This is the ONLY place where vendor differences live"), the
long-term move is to fold this into `targets.js`'s `axiam` adapter so
`token_refresh.js` can go back to calling `a.refresh(vuRefresh)` uniformly for
every target:

1. Change `axiam.refresh(refreshToken)` (currently `targets.js:70-83`, POSTs
   form-encoded `grant_type=refresh_token` to `/oauth2/token`) to instead
   build the `POST /api/v1/auth/refresh` request: JSON body
   `{ tenant_id: cfg.tenantId, org_id: cfg.orgId }`, and accept an **explicit
   second parameter** for the CSRF token (the builder signature would need to
   become `refresh(refreshToken, csrfToken)` — a shape change from every other
   adapter's `refresh(refreshToken)`, since AXIAM alone needs the CSRF
   double-submit header/cookie). Set `cookies: { axiam_refresh: refreshToken,
   axiam_csrf: csrfToken }` and header `X-CSRF-Token: csrfToken` in `params`.
2. Because the response carries the rotated refresh token only via
   `Set-Cookie` (not JSON body), either (a) have `token_refresh.js` special-case
   reading the jar after the call for AXIAM only (what this patch does today,
   just relocated), or (b) — cleaner — extend `doOp()` in `metrics.js` to
   optionally return `{ body, res }` so callers needing cookies don't have to
   special-case; that's a `metrics.js` change, also out of scope for any
   single-file-owner this round.
3. `mintUserToken()`'s existing `csrf_token` field (now returned, this patch)
   is exactly what a uniform `a.refresh(refreshToken, csrfToken)` call site in
   `token_refresh.js` would need — no further plumbing required once (1)/(2)
   land.

Once that lands, `benchmarks/scenarios/lib/auth.js`'s `axiamRefreshOp`/
`readAxiamRefreshCookies` and `token_refresh.js`'s `isAxiam` branch introduced
by this change become dead code and should be deleted in the same PR that
makes the `targets.js` change, to avoid two parallel implementations.

## Zitadel `offline_access` — not implemented, ≤50 lines not achievable

Assessed per the G4 spec's ask. Not implemented; the fallback tag for
Zitadel's `token_refresh` cell stays.

Zitadel disables the ROPC (resource-owner password) grant by default, which is
why `targets.js`'s Zitadel `login()` already uses the Session API v2
(`POST /v2/sessions`) instead — and a session-API session is not an OIDC token
(no `access_token`/`refresh_token`, just a `sessionToken`), so it cannot seed a
refresh grant. The only way to obtain a real Zitadel refresh token (scope
`offline_access`) is to complete an actual **OIDC Authorization Code flow**:
`GET /oauth/v2/authorize` → Zitadel's *hosted, stateful login UI* (its own
HTML form, its own CSRF token embedded in that form, likely multi-step if MFA
is configured) → `POST` the credentials to that UI → follow the redirect chain
back to the registered `redirect_uri` with a `code` → exchange the code at
`/oauth/v2/token`. This is fundamentally different from every other op this
harness performs: it requires parsing and resubmitting a third-party HTML
form and following an interactive redirect chain, not just building a request
against a documented JSON/form API. k6's `http` module has no DOM/form
handling, and k6's separate browser-automation module (a different execution
model entirely, incompatible with this protocol-level VU/iteration harness)
would be required to do it reliably. Zitadel's Session API v2 also supports an
SSO shortcut (`prompt=none` / `id_token_hint` against `/authorize` using the
just-created session's cookie) that in principle could skip the login form,
but its exact contract (session-to-authorize cookie linkage, response shape)
is not verifiable from this sandbox without a live Zitadel instance to probe,
and getting it wrong would silently produce another mislabeled-as-real
fallback — worse than the honest, documented fallback tag already in place.
Recommend leaving this as a explicitly out-of-scope, tagged fallback unless a
future task can verify the SSO shortcut against a live Zitadel instance.

## §5 — what's proven vs. what needs laptop confirmation

**Proven by source (this sandbox, no live stack needed):**
- The `Path` mismatch is the actual, sufficient root cause (RFC 6265
  path-matching is deterministic; `authz_check_rest`'s working `Path=/`
  cookies at the same profile rule out `Secure` as the explanation here).
- `/oauth2/token`'s refresh grant and `/api/v1/auth/login`'s refresh token are
  backed by two disjoint repositories/tables — a login-issued token can never
  validate at `/oauth2/token`.
- `/api/v1/auth/refresh`'s exact contract (cookie-only token, CSRF-required,
  JSON-body-has-no-tokens) — read directly from the handler and the CSRF
  middleware's exemption list.

**Needs laptop confirmation:**
- That k6's actual cookie jar implementation performs RFC 6265-conformant
  path-matching in `cookiesForURL()` (assumed, standard, but not verified
  against k6's Go source in this sandbox).
- The end-to-end numbers below.
- Whether `cfg.orgId`/`cfg.tenantId` are populated as real UUIDs in the
  laptop's actual seed output for every target/profile combination run (the
  `axiamRefreshOp` JSON body will 400 if `org_id` is empty-string when only a
  slug was seeded — no different from the pre-existing assumption
  `axiam.clientCredentials()` already makes).

## Laptop confirmation command

```
just target=axiam profile=p0-plaintext bench-up
just target=axiam bench-seed
just target=axiam profile=p0-plaintext scenario=token_refresh.js bench-run
```

Then check `results/<run>/axiam/p0-plaintext/token_refresh/summary.json` (or
equivalent report output) for:

- `bench_fallback == 0`
- one HTTP request per iteration (`http_reqs` / iterations ≈ 1, not ≈ 2)
- throughput **not** ≈ ½ × the `client_credentials` cell's throughput for the
  same target/profile (the fallback-op signature), and directionally
  comparable to Keycloak's 379 req/s head-to-head number.

---

## 6. Comparability correction (added by the integrating agent, 2026-07-26)

The pass criteria above end with "directionally comparable to Keycloak's
379 req/s head-to-head number". **That comparison needs a label, and the report
must carry it**, otherwise this fix trades one mislabeled cell for another.

After the fix the two cells measure *different protocol operations*:

| target | endpoint | operation | credential store |
|---|---|---|---|
| AXIAM | `POST /api/v1/auth/refresh` | **session refresh** (cookie + CSRF double-submit) | `axiam-auth` `SessionRepository` |
| Keycloak | `POST /realms/…/protocol/openid-connect/token` `grant_type=refresh_token` | **OAuth2 refresh grant** | Keycloak's OAuth2 store |

AXIAM *cannot* be made to match Keycloak's shape from a password login, and this
is deliberate rather than a gap: `TokenService::exchange`
(`crates/axiam-oauth2/src/token.rs:143-147`) supports exactly
`authorization_code`, `client_credentials` and `refresh_token` — there is **no
password/ROPC grant**, which is the OAuth 2.1-recommended posture (the password
grant is removed in OAuth 2.1; Keycloak's cell depends on it). So the only way
to obtain an *OAuth2* refresh token from AXIAM is a full authorization-code
flow.

**Consequences to act on:**

1. **Label the cell.** Both operations are legitimately "renew an access
   credential without re-authenticating" — comparable at the product level, not
   at the protocol level. The cell should carry a comparability label of its own
   (suggest `protocol-variant`, alongside the existing `fallback-op` and
   `cc-token-setup`), so `report.py` keeps it visible with a footnote rather
   than presenting it as a like-for-like head-to-head. This is a `report.py`
   change and is tracked in the plan, not applied here.
2. **The apples-to-apples option, if we want it.** Drive AXIAM's
   `/oauth2/authorize` with the session cookie obtained at login to get an
   authorization code, exchange it for an OAuth2 access+refresh pair, then
   exercise `grant_type=refresh_token` exactly as Keycloak does. This is
   plausible in ~40-60 lines *if* the authorize endpoint accepts the session
   cookie and does not require an interactive consent step — verify before
   committing to it. That would give a true protocol-level head-to-head and
   would additionally cover AXIAM's authorization-code path, which no scenario
   currently benchmarks at all.
3. **Publishing rule until then:** AXIAM's refresh number may be published as
   AXIAM's *session-refresh* capability, and Keycloak's as its *OAuth2-refresh*
   capability, side by side with the distinction stated — never as "AXIAM is
   N× Keycloak at refresh".
