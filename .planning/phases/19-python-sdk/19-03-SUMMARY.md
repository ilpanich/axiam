---
phase: 19-python-sdk
plan: 03
subsystem: sdk
tags: [python, httpx, rest, sync-async, single-flight, csrf, tls]

# Dependency graph
requires:
  - phase: 19-python-sdk
    plan: "01"
    provides: "src-layout package skeleton, committed gRPC stubs, AMQP HMAC verifier, tests/conftest.py shared fixtures"
  - phase: 19-python-sdk
    plan: "02"
    provides: "_errors.py taxonomy, _models.py (LoginResult/AccessCheck/AccessResult/BatchCheckResult), token/refresh_guard.py RefreshGuard, _jwks.py"
provides:
  - "_session.py: _Session — one shared http.cookiejar.CookieJar across lazily-built sync+async httpx clients, CSRF capture/echo, verify=True hardcoded"
  - "_client.py: AxiamClient — sync login/verify_mfa/refresh/logout/check_access/can/batch_check + async_* twins on one object (SC#1), context-manager lifecycle (D-19)"
  - "__init__.py public export surface: AxiamClient, LoginResult, User, AccessCheck, AccessResult, BatchCheckResult, AuthError, AuthzError, NetworkError"
affects: [19-04, 19-05, 19-06, 19-07]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Cookie-jar sharing requires passing a raw http.cookiejar.CookieJar (not an httpx.Cookies() wrapper) to both httpx.Client and httpx.AsyncClient — httpx.Cookies.__init__ copies an existing Cookies argument into a brand-new jar instead of sharing it (Assumption A1, empirically verified against pinned httpx 0.27.2)"
    - "_Session._prepare_request/_capture_csrf/_send_sync/_send_async are the single choke points for X-Tenant-ID injection, CSRF capture/echo, and refresh-guard integration — mirrors sdks/go/client.go's decorateRequest/captureCSRFFromResponse/doRequest"
    - "cookie_value() disambiguates same-name cookies at different Paths (axiam_access at Path=/ vs. the refreshed axiam_access at Path=/api/v1/auth/refresh) by preferring the most specific (longest) path, since httpx.Cookies.get() raises CookieConflict on ambiguous multi-path matches"
    - "401-triggered authz retry rebuilds the failed request via build_request() with stale Content-Length/X-CSRF-Token headers stripped, then re-sends through the same _send_sync/_send_async choke point so the retry also re-decorates with the freshly captured CSRF token"

key-files:
  created:
    - sdks/python/src/axiam_sdk/_session.py
    - sdks/python/src/axiam_sdk/_client.py
    - sdks/python/tests/test_session_cookies.py
    - sdks/python/tests/test_client_login.py
  modified:
    - sdks/python/src/axiam_sdk/__init__.py

key-decisions:
  - "Cookie-jar sharing implemented via a raw http.cookiejar.CookieJar (session._shared_jar()) rather than the RESEARCH.md sketch's httpx.Cookies() instance passed directly to both clients — the sketch does NOT share state under the pinned httpx 0.27.2 (proven empirically: sync_client.cookies.jar is async_client.cookies.jar was False when using two httpx.Cookies() wrappers of the same instance, True when using a shared raw CookieJar)"
  - "cookie_value() picks the cookie with the longest (most specific) Path when a name collision exists across paths, rather than raising or picking arbitrarily — required because the server legitimately sets axiam_access at Path=/ (login) and again at Path=/api/v1/auth/refresh (refresh response), which httpx.Cookies.get() treats as an unresolvable CookieConflict"
  - "The 401-retry-once path (check_access/batch_check) rebuilds the original request via build_request(...) with Content-Length and the stale X-CSRF-Token stripped, rather than resending the exact same httpx.Request object — a raw resend would carry the CSRF token captured before the retry and could hold a stale Content-Length after any header change"
  - "logout() rotates the session's RefreshGuard to a fresh instance after a successful server-side logout, mirroring Go's Client.guard.Store(&refreshguard.Guard{}), so a stale cached access token can never satisfy a subsequent refresh_if_needed_* double-check after logout"

patterns-established:
  - "_Session is the sole owner of the shared cookie jar / CSRF state / RefreshGuard instance; AxiamClient never touches httpx internals directly — every REST call goes through session.sync_client.build_request(...) / session._send_sync(...) or the async twins"

requirements-completed: [PY-01]

coverage:
  - id: T1
    description: "sync_client/async_client share one cookie jar via a raw http.cookiejar.CookieJar; verify=True hardcoded unless custom_ca; X-Tenant-ID always set; CSRF captured from response header and echoed on state-changing methods"
    requirement: "PY-01"
    verification:
      - kind: unit
        ref: "sdks/python/tests/test_session_cookies.py (15 tests: jar identity, cross-paradigm cookie visibility, lazy construction, verify=True/custom_ca, CSRF prepare/capture, respx-backed send)"
        status: pass
      - kind: other
        ref: "grep -rEc 'verify\\s*=\\s*(False|0)' sdks/python/src/axiam_sdk/_session.py returns 0; grep -c 'httpx.Cookies' returns 1"
        status: pass
    human_judgment: false
  - id: T2
    description: "AxiamClient.login()/async_login() both return typed LoginResult with mfa_required (SC#1); tenant_slug required at construction; org_slug/org_id mutually exclusive; refresh POSTs the exact literal /api/v1/auth/refresh path; context managers close the constructed httpx clients"
    requirement: "PY-01"
    verification:
      - kind: unit
        ref: "sdks/python/tests/test_client_login.py (login/verify_mfa/refresh/construction-validation subset)"
        status: pass
      - kind: other
        ref: "python -c \"from axiam_sdk import AxiamClient, LoginResult, AuthError, AuthzError, NetworkError\" succeeds; grep -c '\"/api/v1/auth/refresh\"' sdks/python/src/axiam_sdk/_client.py returns 3; mypy --strict passes"
        status: pass
    human_judgment: false
  - id: T3
    description: "check_access/can/batch_check POST /api/v1/authz/check(/batch); a 401 triggers exactly one single-flight refresh then one retry; 403 maps to AuthzError; async_* variants share the session/guard"
    requirement: "PY-01"
    verification:
      - kind: unit
        ref: "sdks/python/tests/test_client_login.py (authz subset: test_authz_401_triggers_exactly_one_refresh_and_one_retry, test_authz_403_raises_authz_error, test_async_check_access_shares_session_with_sync_login)"
        status: pass
      - kind: other
        ref: "grep -c '\"/api/v1/authz/check\"'/'\"/api/v1/authz/check/batch\"' each >= 1; grep -c 'error_from_http_status' sdks/python/src/axiam_sdk/_client.py returns 7 (>=1)"
        status: pass
    human_judgment: false

# Metrics
duration: 35min
completed: 2026-07-01
status: complete
---

# Phase 19 Plan 03: REST Core — Unified AxiamClient Summary

**Built the shared `_Session` (one cookie jar across lazily-built sync+async httpx clients, CSRF capture, strict TLS) and the unified `AxiamClient` exposing sync `login`/`verify_mfa`/`refresh`/`logout`/`check_access`/`can`/`batch_check` plus `async_*` twins on the same object, closing SC#1 with single-flight 401-retry-once authz and context-manager lifecycle.**

## Performance

- **Duration:** ~35 min
- **Started:** 2026-07-01
- **Completed:** 2026-07-01
- **Tasks:** 3 (Task 2 and Task 3 committed together — both target `_client.py`/`test_client_login.py` per the plan's own file list, and were implemented as one coherent pass)
- **Files modified:** 4 (2 new, 1 modified, plus 2 new test files) across 2 commits

## Accomplishments

- `_session.py`: `_Session` owns one shared cookie jar, CSRF token capture/echo, tenant header injection, and the shared `RefreshGuard` (from 19-02). `sync_client`/`async_client` are lazy `@property`-built (never both constructed eagerly). `verify=True` is hardcoded unless an explicit `custom_ca` is supplied — never a boolean bypass. `_prepare_request`/`_capture_csrf`/`_send_sync`/`_send_async` are the single choke points every REST call routes through, mirroring `sdks/go/client.go`'s `decorateRequest`/`captureCSRFFromResponse`/`doRequest`.
- **Assumption A1 resolved empirically, with a correction to the research sketch:** passing the same `httpx.Cookies()` instance to both `httpx.Client` and `httpx.AsyncClient` does **NOT** share the underlying jar under the pinned httpx 0.27.2 — `httpx.Cookies.__init__` copies an existing `Cookies` argument's entries into a brand-new `http.cookiejar.CookieJar()` rather than referencing it. The fix: construct one raw `http.cookiejar.CookieJar()` and hand that same raw jar to both clients' `cookies=` kwarg (httpx's `Cookies.__init__` takes a raw `CookieJar` as-is, without copying). Proven via `sync_client.cookies.jar is async_client.cookies.jar` and a cross-paradigm cookie-visibility test.
- `_client.py`: `AxiamClient` exposes sync `login`/`verify_mfa`/`refresh`/`logout`/`check_access`/`can`/`batch_check` and their `async_*` twins on the same object, sharing one `_Session`. Constructor requires `tenant_slug` (empty raises `AuthError`, CF-04) and treats `org_slug`/`org_id` as mutually exclusive (Pitfall 3). Login/refresh bodies carry `org_slug`/`org_id`, falling back to the value resolved from the access token's `org_id` claim after first login. `refresh()` POSTs the exact literal `/api/v1/auth/refresh` path (Pitfall 4) so the Path-scoped `axiam_refresh` cookie attaches, routed through the shared `RefreshGuard` (19-02) — a 401 on the refresh call itself is `AuthError` with no retry (§9.3). `check_access`/`can`/`batch_check` POST `/api/v1/authz/check(/batch)`; a 401 triggers exactly one single-flight refresh then retries the failed call exactly once via the central `error_from_http_status` mapper (no independent status table). `with AxiamClient(...) as c` / `async with AxiamClient(...) as c` plus explicit `close()`/`aclose()` close only the httpx client(s) actually constructed (D-19).
- `__init__.py` now re-exports the phase's public surface: `AxiamClient`, `LoginResult`, `User`, `AccessCheck`, `AccessResult`, `BatchCheckResult`, `AuthError`, `AuthzError`, `NetworkError` — `python -c "from axiam_sdk import AxiamClient, LoginResult, AuthError, AuthzError, NetworkError"` succeeds.

## Task Commits

Each task was committed atomically:

1. **Task 1: Shared `_Session` — cookie jar, CSRF capture, TLS, lazy dual httpx clients (CF-01/CF-02/CF-03)** - `2c49f59` (feat)
2. **Task 2 + Task 3: `AxiamClient` — sync+async login/verify_mfa/refresh/logout + org_id + lifecycle, and REST authz + 401 single-flight refresh-and-retry** - `e0fa309` (feat) — committed together since both tasks target the same `_client.py`/`test_client_login.py` files per the plan's own `<files>` declarations and were implemented as one coherent pass

**Plan metadata:** committed alongside this SUMMARY (see final commit below)

## Files Created/Modified

- `sdks/python/src/axiam_sdk/_session.py` - `_Session`: shared cookie jar, CSRF capture/echo, lazy sync/async httpx clients, TLS, `RefreshGuard` holder, `close`/`aclose`
- `sdks/python/src/axiam_sdk/_client.py` - `AxiamClient`: sync + `async_*` `login`/`verify_mfa`/`refresh`/`logout`/`check_access`/`can`/`batch_check`, context-manager lifecycle, org_id resolution
- `sdks/python/src/axiam_sdk/__init__.py` - Populated public re-export surface (was a 19-01 placeholder)
- `sdks/python/tests/test_session_cookies.py` - 15 tests: jar-identity/cross-paradigm cookie sharing (Assumption A1), lazy construction, TLS defaults, CSRF prepare/capture, respx-backed sync+async send
- `sdks/python/tests/test_client_login.py` - 20 tests: construction validation, sync+async login/verify_mfa (SC#1), org_slug wire-body assertion, refresh literal-path + 401-no-retry, check_access/can/batch_check, 401-single-flight-retry-once, 403→AuthzError, cross-paradigm session sharing, public import surface

## Decisions Made

- Cookie-jar sharing implemented via a raw `http.cookiejar.CookieJar` (`_Session._shared_jar()`) rather than the RESEARCH.md sketch's approach of passing one `httpx.Cookies()` instance directly to both clients — the sketch does not share state under the pinned httpx 0.27.2, confirmed by an empirical Python REPL check before writing any code (see module docstring in `_session.py` for the exact mechanism).
- `_Session.cookie_value()` picks the cookie with the longest (most specific) `Path` when a same-name collision exists across paths, rather than raising or picking arbitrarily. Discovered via `test_refresh_posts_exact_literal_path`: the server legitimately sets `axiam_access` at `Path=/` (login) and again at `Path=/api/v1/auth/refresh` (a refresh response), which `httpx.Cookies.get()` treats as an unresolvable `CookieConflict`.
- The 401-retry-once path in `check_access`/`batch_check` rebuilds the original request via `build_request(...)` with `Content-Length` and the stale `X-CSRF-Token` header stripped, rather than resending the exact same `httpx.Request` object — a raw resend would carry the CSRF token captured before the retry (now stale) and risk a mismatched `Content-Length` after header changes; the rebuilt request re-enters `_send_sync`/`_send_async` so it is freshly decorated with the current CSRF token.
- `logout()` rotates the session's `RefreshGuard` to a fresh instance after a successful server-side logout (mirrors Go's `Client.guard.Store(&refreshguard.Guard{})`), so a stale cached access token can never satisfy a subsequent `refresh_if_needed_*` double-check after logout.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `httpx.CookieConflict` raised on `cookie_value("axiam_access")` after `refresh()`**
- **Found during:** Task 2, running `test_refresh_posts_exact_literal_path`.
- **Issue:** The mocked login response sets `axiam_access` at `Path=/`; the mocked refresh response (correctly, per Pitfall 4) sets a fresh `axiam_access` at `Path=/api/v1/auth/refresh`. `httpx.Cookies.get(name)` raises `CookieConflict` when two jar entries share a name but differ by path, since it cannot determine which value the caller wants.
- **Fix:** `_Session.cookie_value()` now iterates the raw jar directly and selects the entry with the longest (most specific) `path`, which is always the entry set by the most path-specific (and therefore most recent, in this SDK's flows) response.
- **Files modified:** `sdks/python/src/axiam_sdk/_session.py`
- **Verification:** `test_refresh_posts_exact_literal_path` and all other cookie-reading tests pass; `pytest sdks/python/tests -q` green (74/74).
- **Committed in:** `e0fa309` (Task 2/3 commit)

**2. [Rule 1 - Bug] `httpx.Cookies()` instance sharing does not share state under pinned httpx 0.27.2 (Assumption A1)**
- **Found during:** Task 1, before writing `_session.py`'s cookie-jar-sharing code — confirmed via an empirical REPL check as instructed by the plan's own "empirical Assumption-A1 unit test" requirement.
- **Issue:** RESEARCH.md's Pattern 1 code sketch passes one `httpx.Cookies()` instance to both `httpx.Client(cookies=...)` and `httpx.AsyncClient(cookies=...)`, asserting this shares the jar. Empirically, it does not: `httpx.Cookies.__init__` copies an existing `Cookies` argument's entries into a brand-new `CookieJar()` per client, so a cookie set via the sync client was invisible to the async client.
- **Fix:** Construct a single raw `http.cookiejar.CookieJar()` and pass that same raw object to both clients' `cookies=` kwarg — `httpx.Cookies.__init__`'s `else` branch takes a raw `CookieJar` as-is (no copy).
- **Files modified:** `sdks/python/src/axiam_sdk/_session.py` (written correctly from the start, informed by this pre-implementation empirical check — not a post-hoc fix)
- **Verification:** `test_sync_and_async_clients_share_one_cookie_jar`, `test_cookie_set_via_sync_client_visible_via_async_client`, `test_cookie_set_via_async_client_visible_via_sync_client` all pass.
- **Committed in:** `2c49f59` (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (both Rule 1 correctness fixes to code paths this plan itself introduces — no scope creep, no new features beyond what the plan specified).
**Impact on plan:** Both deviations strengthen correctness of behavior the plan's own acceptance criteria require (cross-paradigm session sharing; refresh's path-scoped cookie handling). No plan requirement was weakened or skipped.

## Issues Encountered

None beyond the auto-fixed deviations above — no unresolved issues.

## User Setup Required

None — no external service configuration required. `mypy`/`ruff` were invoked from their existing tool locations (`/root/.local/bin/mypy`, `/root/.local/bin/ruff`) per the pattern established in 19-02's Summary; no new installs were needed.

## Next Phase Readiness

- SC#1 is closed: one `AxiamClient` exposes sync `login` and async `async_login`, both returning typed `LoginResult` with `mfa_required`, sharing one session.
- REST authz (`check_access`/`can`/`batch_check`) works end-to-end with single-flight 401-refresh-and-retry-once, proven by a concrete respx-backed test asserting exactly one refresh call and one retry.
- TLS is strict-by-default (`verify=True` hardcoded; `grep -rn 'verify=False' sdks/python/` returns nothing) and the session shares one cookie jar across sync/async paradigms, cleaning up deterministically via context managers.
- 19-04 (gRPC transport) can now decouple its own refresh closure from this REST session (per the Go/TS precedent of accepting a caller-supplied `RefreshFunc` rather than importing `_client.py` directly) and reuse `_errors.py`'s central mapper.
- 19-06 (FastAPI/Django integrations) can reuse `_jwks.py`'s `JwksVerifier` independently of this REST client, as already noted in 19-02's Summary.
- No blockers.

## Self-Check: PASSED

All claimed files verified present on disk; all claimed commit hashes (`2c49f59`, `e0fa309`) verified present in `git log --oneline --all`.

## Self-Check: PASSED (verified)

All claimed files confirmed present on disk via direct filesystem check; commit hashes `2c49f59` and `e0fa309` confirmed present in `git log --oneline --all`.

---
*Phase: 19-python-sdk*
*Completed: 2026-07-01*
