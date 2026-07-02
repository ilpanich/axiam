---
phase: 19-python-sdk
plan: 02
subsystem: sdk
tags: [python, pydantic, pyjwt, jwks, asyncio, threading, security]

# Dependency graph
requires:
  - phase: 19-python-sdk
    plan: "01"
    provides: "src-layout package skeleton, committed gRPC stubs, AMQP HMAC verifier, tests/conftest.py shared fixtures"
provides:
  - "_errors.py: AuthError/AuthzError/NetworkError taxonomy with a single redact-before-wrap chokepoint (error_from_http_status/error_from_grpc_status)"
  - "_models.py: Pydantic v2 LoginResult/User/AccessCheck/AccessResult/BatchCheckResult with SecretStr token redaction"
  - "token/refresh_guard.py: RefreshGuard dual-lock single-flight primitive (threading.Lock sync + asyncio.Lock async)"
  - "_jwks.py: JwksVerifier — PyJWKClient wrapper against {base_url}/oauth2/jwks with EdDSA-only allowlist and forced-refetch-on-unknown-kid"
affects: [19-03, 19-04, 19-05, 19-06]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "error_from_http_status/error_from_grpc_status are the SOLE constructors accepting an httpx.Response — no other call site may build NetworkError from raw headers (redact-before-wrap chokepoint, D-08/CR-04)"
    - "Two independent locks (threading.Lock + asyncio.Lock) rather than one unified lock for single-flight refresh — sync and async call paths never block on each other's lock type (CF-05)"
    - "JwksVerifier checks the token's alg header against an EdDSA allowlist BEFORE any PyJWKClient keyset lookup — algorithm-confusion defense applied at the earliest possible point"
    - "PyJWTError (not just PyJWKClientError) is the catch target for the forced-refetch-once retry, since PyJWT raises the sibling PyJWKSetError (not a PyJWKClientError subclass) for an empty/malformed keyset response"

key-files:
  created:
    - sdks/python/src/axiam_sdk/_errors.py
    - sdks/python/src/axiam_sdk/_models.py
    - sdks/python/src/axiam_sdk/_jwks.py
    - sdks/python/src/axiam_sdk/token/__init__.py
    - sdks/python/src/axiam_sdk/token/refresh_guard.py
    - sdks/python/tests/test_error_redaction.py
    - sdks/python/tests/test_single_flight.py
    - sdks/python/tests/test_jwks.py
  modified: []

key-decisions:
  - "error_from_http_status(status, message, response=None) does not accept a caller-supplied cause at all when a response is present — the sanitized response is the SOLE source of the wrapped cause, closing the redact-before-wrap bypass class the Go/TS references' docstrings warn about"
  - "RefreshGuard._store_refreshed() accepts either a mapping or an attribute-bearing object from do_refresh's return value, keeping the guard fully decoupled from any concrete token/session type in 19-03/19-04"
  - "JwksVerifier catches jwt.exceptions.PyJWTError (not the narrower PyJWKClientError) around get_signing_key_from_jwt, because PyJWT raises PyJWKSetError — a PyJWTError sibling, not a PyJWKClientError subclass — when the fetched keyset is empty/malformed; narrowing to PyJWKClientError alone would let that failure mode crash instead of triggering the forced-refetch-once path"
  - "Applied ruff's PEP 604 `X | None` modernization (UP045/UP035) across all four Task 1/2/3 files while satisfying D-20's ruff/mypy --strict gate for this plan's complete file set — pure style, no behavioral change"

patterns-established:
  - "mypy --strict must be invoked with --python-executable pointing at the interpreter that actually has the project's runtime deps installed (this sandbox's system `mypy` binary lives in an isolated uv-tool venv with none of pydantic/httpx/jwt installed) — later plans running mypy locally should use the same flag or a project venv"

requirements-completed: [PY-01]

coverage:
  - id: T1
    description: "Exception taxonomy maps HTTP/gRPC statuses per CONTRACT §2, redacts sensitive headers through a single chokepoint (non-vacuously proven), and LoginResult redacts its token fields via SecretStr"
    requirement: "PY-01"
    verification:
      - kind: unit
        ref: "sdks/python/tests/test_error_redaction.py (15 tests)"
        status: pass
      - kind: other
        ref: "grep -rEc 'NetworkError\\(.*headers' sdks/python/src/axiam_sdk returns 0 everywhere"
        status: pass
    human_judgment: false
  - id: T2
    description: "Exactly one refresh fires under 5 concurrent asyncio tasks (SC#2), locks are independent, cached reads are non-blocking"
    requirement: "PY-01"
    verification:
      - kind: unit
        ref: "sdks/python/tests/test_single_flight.py (6 tests, incl. pytest-asyncio 5-task exactly-once assertion)"
        status: pass
      - kind: other
        ref: "grep -c asyncio.Lock / threading.Lock each return 1; cached_access_token acquires no lock"
        status: pass
    human_judgment: false
  - id: T3
    description: "JWKS verification uses PyJWKClient against the org-wide endpoint with EdDSA-only allowlist before keyset lookup, rotates once on unknown kid, never enables the no-TTL per-key cache"
    requirement: "PY-01"
    verification:
      - kind: unit
        ref: "sdks/python/tests/test_jwks.py (7 tests, incl. HS256/none-alg rejection with zero network fetches, unknown-kid + empty-keyset forced-refetch)"
        status: pass
      - kind: other
        ref: "grep gates: cache_keys=True=0, algorithms=None=0, get_unverified_header=1, /oauth2/jwks path=1"
        status: pass
    human_judgment: false

# Metrics
duration: 30min
completed: 2026-07-01
status: complete
---

# Phase 19 Plan 02: Core Primitives Summary

**Built the transport-independent core of the Python SDK: a redact-before-wrap exception taxonomy, Pydantic v2 typed models with SecretStr token redaction, a dual-lock (threading+asyncio) single-flight refresh guard proving SC#2, and a local EdDSA-only JWKS verifier — each with a non-vacuous regression test.**

## Performance

- **Duration:** ~30 min
- **Started:** 2026-07-01T~19:55:00Z
- **Completed:** 2026-07-01T20:23:00Z
- **Tasks:** 3
- **Files modified:** 8 created (across 3 commits)

## Accomplishments

- `_errors.py`: `AuthError`/`AuthzError`/`NetworkError` exception taxonomy with `error_from_http_status`/`error_from_grpc_status` as the sole constructors accepting an `httpx.Response`. `_sanitize_response()` is the single chokepoint that redacts `Set-Cookie`/`Authorization`/`Cookie` before any response data can enter an exception's `__cause__`. Proven non-vacuously: a raw `axiam_access`/`axiam_refresh` secret never survives into `repr`/`str`/`repr(__cause__)`, while a non-sensitive header (`x-request-id`) does survive — proving redaction is selective, not blanket (D-08, CR-04 carry-forward).
- `_models.py`: Pydantic v2 `LoginResult` (single model, `mfa_required: bool`, frozen), `User`, `AccessCheck`, `AccessResult`, `BatchCheckResult`. `mfa_token` (renamed from the server's wire-level `challenge_token`) is a `SecretStr`, redacting in both `repr()` and `model_dump()` while remaining accessible via `.get_secret_value()` (D-06/D-07/D-21).
- `token/refresh_guard.py`: `RefreshGuard` with two fully independent locks — `threading.Lock` for `refresh_if_needed_sync` and `asyncio.Lock` for `refresh_if_needed_async` — each implementing its own double-check-after-lock body over shared cached-token state. 5 concurrent asyncio tasks racing an expired token trigger exactly 1 `do_refresh` call (SC#2, proven by `pytest-asyncio`); `do_refresh` failures propagate without retry (§9.3). Non-blocking `cached_access_token()`/`cached_refresh_token()`/`cached_exp()` reads back the future gRPC interceptor's hot path (19-04); `seed()` primes the cache after login/verify_mfa.
- `_jwks.py`: `JwksVerifier` wraps `PyJWKClient` against `{base_url}/oauth2/jwks` (org-wide, not tenant-scoped), with `cache_jwk_set=True, lifespan=300` and `cache_keys` left at its default-disabled state (no-TTL per-key LRU avoided per Pattern 5's documented pitfall). `verify()` rejects any non-EdDSA `alg` header before touching `PyJWKClient` at all — proven by tests asserting zero JWKS network fetches for HS256/`alg:none` tokens. Unknown-kid and empty/stale-keyset failures both route through one rate-limited (60s) forced-refetch-and-retry-once path; `verify()` deliberately does not check `exp` (documented as the caller's responsibility for 19-06's FastAPI/Django integrations).

## Task Commits

Each task was committed atomically:

1. **Task 1: Exception taxonomy + redact-before-wrap + LoginResult/models (D-08/D-06/D-07/D-21)** - `4389d03` (feat)
2. **Task 2: Dual-lock single-flight refresh guard (SC#2, CF-05)** - `4e3edc4` (feat)
3. **Task 3: Local JWKS verifier — EdDSA-only allowlist + rotate-on-unknown-kid (D-16/CF-07)** - `0c7e142` (feat)

**Plan metadata:** committed alongside this SUMMARY (see final commit below)

## Files Created/Modified

- `sdks/python/src/axiam_sdk/_errors.py` - `AuthError`/`AuthzError`/`NetworkError`, `_sanitize_response`, `error_from_http_status`/`error_from_grpc_status`
- `sdks/python/src/axiam_sdk/_models.py` - `LoginResult`, `User`, `AccessCheck`, `AccessResult`, `BatchCheckResult` (Pydantic v2, `SecretStr` on token fields)
- `sdks/python/src/axiam_sdk/_jwks.py` - `JwksVerifier`, `JWKS_PATH` constant, cache/rate-limit constants
- `sdks/python/src/axiam_sdk/token/__init__.py` - re-exports `RefreshGuard`
- `sdks/python/src/axiam_sdk/token/refresh_guard.py` - `RefreshGuard` dual-lock single-flight guard
- `sdks/python/tests/test_error_redaction.py` - 15 tests: status-mapping table, non-vacuous redaction, `LoginResult` `SecretStr` behavior
- `sdks/python/tests/test_single_flight.py` - 6 tests: exactly-once async/sync refresh, double-check-after-lock, no-retry-on-failure, cache seeding
- `sdks/python/tests/test_jwks.py` - 7 tests: valid EdDSA verify, HS256/`none`-alg rejection with zero fetches, wrong-key rejection, unknown-kid + empty-keyset forced-refetch

## Decisions Made

- `error_from_http_status` does not accept a caller-supplied `cause` parameter at all — when a `response` is provided, the sanitized response is the *only* source of the wrapped cause, structurally preventing any call site from smuggling an unredacted cause in alongside a response (stronger than the Go/TS references, which document the invariant but still accept a `cause` parameter that must be manually ignored).
- `RefreshGuard._store_refreshed()` accepts either a mapping (`{"access": ..., "refresh": ..., "exp": ...}`) or an attribute-bearing object from `do_refresh`'s return value, so 19-03 (REST) and 19-04 (gRPC) can each supply whatever refresh-result shape is natural to their transport without `token/refresh_guard.py` importing either.
- `JwksVerifier` catches `jwt.exceptions.PyJWTError` (the common base), not the narrower `PyJWKClientError`, around `get_signing_key_from_jwt` — empirically confirmed against installed PyJWT 2.13.0 that an empty/malformed JWKS response raises `PyJWKSetError`, a `PyJWTError` sibling that is **not** a `PyJWKClientError` subclass. Narrowing the catch to `PyJWKClientError` alone (as RESEARCH.md's example code sketched) would let that failure mode crash instead of engaging the forced-refetch-once path — this resolves Assumption A3 empirically rather than assuming the sketch was correct as written.
- Applied ruff's PEP 604 `X | None` modernization (`UP045`/`UP035` auto-fixes) across all of Task 1/2/3's files in one pass while satisfying D-20's `ruff check` + `ruff format --check` gate for this plan's complete file set — pure style, verified zero behavioral change (all 40 tests still pass after the fix).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] System `cryptography` package could not be imported (`_cffi_backend` missing)**
- **Found during:** Task 3, first attempt to `import jwt` to inspect the installed PyJWT source for Assumption A3.
- **Issue:** `/usr/lib/python3/dist-packages/cryptography` (v41.0.7) required a Rust-compiled `_cffi_backend` extension that was not importable in this environment, causing every `import jwt` (and therefore any JWKS/EdDSA code) to crash at import time with a PyO3 panic.
- **Fix:** `pip install --user --force-reinstall cryptography` (installed 49.0.0 + `cffi` 2.0.0 wheels with working binary extensions), a local tooling-environment fix, not a source-code change.
- **Verification:** `python3 -c "import jwt; from jwt import PyJWKClient, PyJWKClientError"` succeeds.
- **Committed in:** N/A (local environment tooling upgrade only; no repo files changed).

**2. [Rule 1 - Bug] `PyJWKSetError` (empty/malformed JWKS response) was not caught by the forced-refetch-once retry path**
- **Found during:** Task 3, running `test_unknown_kid_triggers_exactly_one_forced_refetch` against an empty mock keyset.
- **Issue:** The initial implementation caught only `PyJWKClientError` around `get_signing_key_from_jwt`. Empirically inspecting installed PyJWT 2.13.0's source showed that an empty/malformed keyset (`PyJWKSet.from_dict({"keys": []})`) raises `PyJWKSetError`, which is a `PyJWTError` sibling — **not** a `PyJWKClientError` subclass — so that failure mode bypassed the retry path entirely and crashed `verify()` uncaught.
- **Fix:** Widened the `except` clause to `jwt.exceptions.PyJWTError` (the common base of both `PyJWKClientError` and `PyJWKSetError`), so both an unknown-kid failure and an empty/stale-keyset failure route through the same rate-limited forced-refetch-and-retry-once logic.
- **Files modified:** `sdks/python/src/axiam_sdk/_jwks.py`
- **Verification:** `test_empty_keyset_triggers_forced_refetch` and `test_unknown_kid_triggers_exactly_one_forced_refetch` (both scenarios, added as separate tests) pass.
- **Committed in:** `0c7e142` (Task 3 commit).

**3. [Rule 1 - Bug] `grep -c` acceptance-gate counts inflated by docstring mentions of the literal strings**
- **Found during:** Task 2/3, verifying the plan's `grep -c 'asyncio.Lock'`/`grep -c 'threading.Lock'`/`grep -c 'cache_keys=True'`/`grep -c 'algorithms=None'` acceptance criteria (each specified to return exactly `1` or `0`).
- **Issue:** Explanatory docstrings/comments describing the anti-patterns being avoided (e.g. "never enable `cache_keys=True`") contained the literal grep-matched substrings, inflating counts beyond the plan's specified exact values.
- **Fix:** Rephrased the docstrings/comments to convey the same intent without repeating the literal substrings, leaving exactly one real code occurrence of each lock constructor / zero occurrences of the two forbidden constructs.
- **Files modified:** `sdks/python/src/axiam_sdk/token/refresh_guard.py`, `sdks/python/src/axiam_sdk/_jwks.py`
- **Verification:** All four grep gates now return the plan's specified exact values.
- **Committed in:** `4e3edc4` (Task 2 commit), `0c7e142` (Task 3 commit).

**4. [Rule 2 - Missing Critical] `types-grpcio` stub package was missing, blocking a clean `mypy --strict` pass on `_errors.py`**
- **Found during:** Task 3, running the plan's `<verification>`-block `mypy --strict` command across all four files.
- **Issue:** `_errors.py`'s lazy `import grpc` inside `error_from_grpc_status` triggered mypy's `import-untyped` diagnostic without the `types-grpcio` stub package installed, which `--strict` treats as an error.
- **Fix:** `pip install types-grpcio` (dev-tooling install, matching the `dev` optional-dependency group's existing `grpcio-tools` pin intent — no `pyproject.toml` change was required since this is a type-checking-only stub package, not a runtime dependency).
- **Verification:** `mypy --strict --python-executable=/usr/local/bin/python3 src/axiam_sdk/_errors.py src/axiam_sdk/_models.py src/axiam_sdk/_jwks.py src/axiam_sdk/token/refresh_guard.py` reports "Success: no issues found in 4 source files".
- **Committed in:** N/A (local dev-tooling install only; no repo files changed).

---

**Total deviations:** 4 auto-fixed (1 Rule 3 blocking/tooling, 1 Rule 1 bug fix affecting shipped code, 1 Rule 1 grep-gate cleanup, 1 Rule 2 missing dev-tooling).
**Impact on plan:** The `PyJWKSetError` fix (#2) is the only deviation that changed shipped source behavior, and it strictly *improves* correctness — the plan's own acceptance criteria ("rotates on unknown kid") implicitly requires this broader catch to hold for all JWKS-lookup-failure shapes PyJWT can raise, not just the one class explicitly named in the plan text. No scope creep — no new features were added beyond what the plan specified.

## Issues Encountered

None beyond the auto-fixed deviations above — no unresolved issues.

## User Setup Required

None — no external service configuration required. (Local dev-tooling fixes — `cryptography`/`cffi` reinstall and `types-grpcio` install — were performed in this execution environment via `pip install`, matching the existing `dev` optional-dependency group's spirit; no `pyproject.toml` changes were needed since neither is a new runtime dependency.)

## Next Phase Readiness

- All four core primitives (`_errors.py`, `_models.py`, `token/refresh_guard.py`, `_jwks.py`) are complete, tested, `mypy --strict`-clean, and `ruff`-clean. SC#2 (exactly-one-refresh) and the CR-04 leak class (redact-before-wrap) are closed before any transport (REST/gRPC/AMQP) code exists.
- 19-03 (REST transport) can now build `AxiamClient.login`/`async_login` returning `LoginResult`, wire 401 responses through `error_from_http_status`, and drive `RefreshGuard.refresh_if_needed_sync`/`_async` from the REST session's 401 handler.
- 19-04 (gRPC transport) can wire `UNAUTHENTICATED` through `error_from_grpc_status` and read `RefreshGuard.cached_access_token()` non-blockingly from its interceptor's metadata-building closure.
- 19-06 (FastAPI/Django integrations) can call `JwksVerifier.verify()` directly, adding their own `exp` check and the cross-tenant `claims.tenant_id == configured_tenant` guard documented in 19-PATTERNS.md's Shared Patterns section.
- No blockers.

## Self-Check: PASSED

All claimed files verified present on disk; all claimed commit hashes (`4389d03`, `4e3edc4`, `0c7e142`) verified present in `git log --oneline --all`.

---
*Phase: 19-python-sdk*
*Completed: 2026-07-01*
