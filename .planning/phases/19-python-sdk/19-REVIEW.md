---
phase: 19-python-sdk
reviewed: 2026-07-01T00:00:00Z
depth: deep
files_reviewed: 27
files_reviewed_list:
  - sdks/python/src/axiam_sdk/_client.py
  - sdks/python/src/axiam_sdk/_session.py
  - sdks/python/src/axiam_sdk/_errors.py
  - sdks/python/src/axiam_sdk/_models.py
  - sdks/python/src/axiam_sdk/_jwks.py
  - sdks/python/src/axiam_sdk/token/refresh_guard.py
  - sdks/python/src/axiam_sdk/grpc/_interceptor.py
  - sdks/python/src/axiam_sdk/grpc/_tls.py
  - sdks/python/src/axiam_sdk/grpc/client.py
  - sdks/python/src/axiam_sdk/grpc/__init__.py
  - sdks/python/src/axiam_sdk/amqp/_hmac.py
  - sdks/python/src/axiam_sdk/amqp/_consumer.py
  - sdks/python/src/axiam_sdk/amqp/__init__.py
  - sdks/python/src/axiam_sdk/fastapi/__init__.py
  - sdks/python/src/axiam_sdk/django/__init__.py
  - sdks/python/src/axiam_sdk/django/middleware.py
  - sdks/python/src/axiam_sdk/__init__.py
  - sdks/python/pyproject.toml
  - sdks/python/scripts/gen_grpc.sh
  - .github/workflows/sdk-ci-python.yml
  - sdks/python/examples/login_mfa.py
  - sdks/python/examples/amqp_consumer.py
  - sdks/python/examples/grpc_checkaccess.py
  - sdks/python/examples/rest_authz.py
  - sdks/python/tests/*.py (13 test modules)
findings:
  critical: 1
  warning: 5
  info: 2
  total: 8
status: clean
resolved_at: 2026-07-01T00:00:00Z
resolution:
  CR-01: fixed — single threading.Lock guards both sync+async paths; mixed-mode test fails on old design (call_count==2), passes now (call_count==1)
  WR-01: fixed — error_from_grpc_status redacts token/cookie material from call.details() before wrapping
  WR-02: fixed — scope:null normalized to empty roles (== absent) in FastAPI + Django; no more 500
  WR-03: fixed — observed_access=None forces a refresh instead of returning stale cached token
  WR-04: fixed — bare asserts replaced with explicit RuntimeError raise (survives python -O)
  WR-05: fixed — added non-vacuous negative TLS tests (gRPC + REST, sync + async) rejecting untrusted certs
  IN-01: fixed — injectable logger now logs refresh/login lifecycle events (status only, never tokens)
  IN-02: fixed — _decode_unverified_claims raises AuthError on non-dict JWT payloads
---

# Phase 19: Code Review Report — Python SDK

**Reviewed:** 2026-07-01
**Depth:** deep
**Files Reviewed:** 27 (+ 13 test modules)
**Status:** clean (all 8 findings fixed 2026-07-01 — see `resolution` in frontmatter; each fix has a proving test and was committed atomically)

## Summary

The Python SDK is well-structured and closely mirrors the Go/Rust/TS reference
implementations, with strong test coverage for the HMAC canonicalization
(byte-for-byte fixture cross-checked against the Rust signer), the
algorithm-confusion defense in JWKS verification, the cross-tenant replay
defense (both FastAPI and Django), and error redaction. `mypy --strict` and
`ruff` are clean, and 115/115 tests pass.

However, deep cross-file/cross-paradigm analysis surfaced one **critical**
defect in the single-flight refresh guard: the dual-lock (`threading.Lock` +
`asyncio.Lock`) design does **not** actually provide mutual exclusion between
the sync and async call paths, so a sync REST call and a concurrent async
gRPC/REST call sharing the same `AxiamClient`/`_Session`/`RefreshGuard` can
both trigger an in-flight refresh at the same time — directly violating
CONTRACT.md §9's "exactly one in-flight refresh at any time" and the module's
own docstring claim. This is exactly the scenario the unified sync+async
client (D-01) is built to support, and the existing single-flight tests never
exercise it (they test same-paradigm concurrency only).

Additional findings: a gRPC error-message redaction gap inconsistent with the
REST path's `_sanitize_response`, an unhandled-exception path in both
framework integrations reachable via a valid, signature-verified token whose
`scope` claim is `null`, a silent-refresh-skip edge case in `RefreshGuard`
when `observed_access` is `None`, `assert`-based invariant enforcement that
Python's `-O` flag strips, an inert `logger` parameter on `AxiamClient`, and
a coverage gap: no test proves TLS certificate verification actually
*rejects* an untrusted certificate (only that a correctly-configured client
connects successfully).

## Critical Issues

### CR-01: Dual-lock single-flight guard does not prevent concurrent sync+async refresh (violates CONTRACT.md §9)

**File:** `sdks/python/src/axiam_sdk/token/refresh_guard.py:34-87`
**Issue:**

`RefreshGuard` uses two **independent** locks — `self._sync_lock` (a
`threading.Lock`) for `refresh_if_needed_sync` and `self._async_lock` (an
`asyncio.Lock`) for `refresh_if_needed_async` — that both read/write the same
shared state (`_cached_access`, `_cached_refresh`, `_cached_exp`, `_has_any`)
with **no cross-lock coordination**. The module docstring explicitly claims
"exactly one in-flight `POST /api/v1/auth/refresh` call across any number of
concurrent callers" (CONTRACT.md §9) and rationalizes the two-lock design,
but never addresses that two independent locks cannot provide mutual
exclusion across each other — a thread holding `_sync_lock` and a coroutine
holding `_async_lock` can execute concurrently, each independently deciding
"no refresh has happened yet, I'll do one."

Reproduced concretely: a sync caller and an async caller, both observing the
same stale `observed_access`, run on separate threads/event loop and **both**
invoke `do_refresh()` — i.e. **two** `POST /api/v1/auth/refresh` calls fire
for what should be a single-flight collapse. This is precisely the scenario
`AxiamClient` (D-01) is designed to support: one client object exposing
`login()`/`check_access()` (sync, via `threading.Lock`) and
`async_login()`/`async_check_access()` (async, via `asyncio.Lock`) on **one
shared `_Session`/`RefreshGuard` instance** (`_session.py:97-99`). A real
consumer mixing sync REST calls with the async gRPC transport (both backed by
the same `RefreshGuard` per `grpc/client.py`'s `refresh_fn` contract) will hit
this race under load — most concerning is that a second unnecessary refresh
call can invalidate/rotate the refresh token server-side (single-use rotation
per CLAUDE.md's security standards: "Refresh tokens: Opaque, server-stored,
single-use with rotation"), causing the loser of the race to receive a
`401`/refresh-token-already-used failure and forcing a spurious
re-authentication for a legitimate concurrent caller — a functional
correctness/availability bug, not just a redundant-network-call inefficiency.

Confirmed via direct reproduction:
```python
# sync caller and async caller both observe "token-0" concurrently
# -> call_count == 2 (should be 1 per CONTRACT.md §9)
```
Running a sync `refresh_if_needed_sync("token-0", ...)` on a background
thread concurrently with `await refresh_if_needed_async("token-0", ...)` in
the main event loop produces `call_count == 2`, and the two callers land on
two *different* final cached access tokens depending on interleaving
(`"async-new-token"` overwrote `"sync-new-token"` in the reproduction) — a
real cache-corruption / lost-update scenario, not just a duplicate call.

The existing test suite (`tests/test_single_flight.py`) never exercises this:
`test_single_flight_refresh_exactly_once_async` uses 5 `asyncio.gather`ed
async tasks only; `test_single_flight_refresh_exactly_once_sync` uses 5
`threading.Thread`s only. No test mixes a sync caller and an async caller
against the same `RefreshGuard` instance, which is why this regression was
never caught despite SC#2's literal wording ("5 (≥5) concurrent requests")
not restricting itself to same-paradigm callers, and D-01's explicit design
goal of one shared session across both paradigms.

**Fix:** Introduce genuine cross-paradigm mutual exclusion. Two viable
approaches:
1. Guard both entry points with a single OS-level lock usable from both
   sync and async code (e.g., wrap a `threading.Lock` and have the async path
   acquire it via `asyncio.to_thread`/`loop.run_in_executor` with a
   non-blocking `acquire(blocking=False)` retry loop, or use a library like
   `anyio`'s `Lock` which is usable from both sync and async — though `anyio`
   locks are still async-only for acquisition, so this still needs a bridge).
2. Simpler and more robust: make the async path funnel through the **same**
   `threading.Lock` via `await asyncio.get_running_loop().run_in_executor(None, self._sync_refresh_if_needed, observed_access, do_refresh_sync_wrapper)` — i.e., always execute the actual refresh critical section (including the do_refresh call) under the sync lock, using a thread-pool bridge for the async entry point, so there is truly only one lock guarding the shared state regardless of caller paradigm. This does block one thread pool worker per waiting async caller, but correctly enforces single-flight.
3. At minimum, add an outer coordination primitive (e.g., a `threading.Lock`
   acquired non-blockingly with a short poll/backoff loop from the async path
   before entering the `asyncio.Lock` section) so the two paths cannot be
   simultaneously "in the critical section."

Whichever approach is chosen, add a regression test that starts a
`threading.Thread` running `refresh_if_needed_sync` and, concurrently in the
event loop, awaits `refresh_if_needed_async`, both observing the same stale
token, and asserts `call_count == 1` — the literal cross-paradigm case D-01
introduces and CONTRACT.md §9 requires.

## Warnings

### WR-01: gRPC error path has no redaction, inconsistent with the REST path's `_sanitize_response`

**File:** `sdks/python/src/axiam_sdk/_errors.py:127-159`, `sdks/python/src/axiam_sdk/grpc/client.py:125-127,202-204`
**Issue:** `error_from_http_status` (the REST mapper) always redacts
`Set-Cookie`/`Authorization`/`Cookie` from any wrapped `httpx.Response` before
it can reach a `NetworkError`'s cause (`_sanitize_response`,
`_errors.py:78-89`). `error_from_grpc_status` has no equivalent: it takes a
caller-supplied `message: str` verbatim into the constructed
`AuthError`/`AuthzError`/`NetworkError`. Both gRPC client call sites pass
`call.details() or "gRPC call failed"` — `call.details()` is a
server-controlled free-text string with no sanitization applied anywhere in
the call chain. The docstring on `error_from_grpc_status` says "`message` is
caller-controlled and MUST NOT contain a raw token value," but nothing
enforces that invariant — it merely shifts the responsibility to the caller
without any code-level guarantee, unlike the REST path's structural defense.
A misbehaving or compromised backend (or, in a future streaming-RPC
extension, a metadata/trailer echo bug) that reflects sensitive data into
`status.details` would leak directly into an exception's `str()`/`repr()`,
logs, and any place callers `str(exc)` the error — which is exactly the class
of bug CR-04 (the TS SDK carry-forward this phase is built to prevent)
addressed for the REST path.
**Fix:** Add a `_sanitize_grpc_message(message: str) -> str` step (or reuse
a shared redaction helper) that strips/redacts anything resembling
`Bearer <token>`, `axiam_access=...`, `axiam_refresh=...`, or generic
`Authorization:`/`Set-Cookie:`-shaped substrings from `call.details()` before
constructing the exception — mirroring the REST path's redact-before-wrap
guarantee so both transports uphold the same invariant from one source of
truth, as the module's own docstring claims ("This is the single source of
truth for both the REST and gRPC transports so the two cannot drift on the
error taxonomy").

### WR-02: Unhandled `TypeError` when a signature-valid token's `scope` claim is explicitly `null`

**File:** `sdks/python/src/axiam_sdk/fastapi/__init__.py:132-133`, `sdks/python/src/axiam_sdk/django/middleware.py:82-84`
**Issue:** Both integrations compute
`roles_claim = claims.get("scope", "")` then
`list(roles_claim)` when `roles_claim` is not a `str`. `dict.get(key, default)`
only returns `default` when the key is **absent** — if the claim is present
with value `None` (`claims["scope"] = None`), `claims.get("scope", "")`
returns `None`, and `list(None)` raises `TypeError: 'NoneType' object is not
iterable`. This exception is raised **after** the try/except that wraps
`verifier.verify()` (FastAPI: `_dependency`, lines 110-115; Django:
`_authenticate`, lines 156-159), so it propagates uncaught — FastAPI returns
an unhandled-exception 500 instead of the standardized 401, and Django's
`_authenticate` (called from both `_sync_call`/`__acall__`) raises straight
through the middleware, producing Django's default 500 error page instead of
the standardized `{"error": "authentication_failed", ...}` 401 body the class
docstring promises. Since this fires on an otherwise **signature-valid**
token from the trusted AXIAM server, this is a legitimate resilience gap:
CONTRACT.md §10 requires "The middleware MUST surface `AuthError` as HTTP 401
and `AuthzError` as HTTP 403" — an uncaught `TypeError` for a malformed-but-
signed claim violates that even though the token itself is authentic.
**Fix:** Normalize defensively, e.g.
`roles_claim = claims.get("scope") or ""` (falls back to `""` for both
absent and `None`), or wrap the whole roles-derivation + `AxiamUser`
construction in the same try/except as `verify()` so any claim-shape
surprise degrades to a standardized 401 rather than an unhandled 500.

### WR-03: `RefreshGuard` silently skips refresh when `observed_access=None` and cache is already populated

**File:** `sdks/python/src/axiam_sdk/token/refresh_guard.py:61-64, 79-82`
**Issue:** The double-check condition
`if self._has_any and self._cached_access != observed_access:` treats a
`None` `observed_access` the same as "caller observed a stale token that has
already been superseded" — since `None != "any-cached-string"` is always
`True` once the guard has been seeded, calling
`refresh_if_needed_async(None, do_refresh)` (or the sync twin) returns the
**existing cached (possibly stale/expired) token without ever calling
`do_refresh`**, silently. Confirmed via direct reproduction: seeding the
guard with `"stale-token"` then calling
`refresh_if_needed_async(None, fake_refresh)` returns `"stale-token"` with
`call_count == 0`. `_client.py`'s own `refresh()`/`async_refresh()` guard
against this by checking `if not observed_access: raise AuthError(...)`
before calling into the guard, so the REST path is not directly exposed —
but `RefreshGuard` is a standalone, transport-independent, publicly reusable
primitive by its own docstring ("this module has no import of the REST
session... `do_refresh` is a caller-supplied... callable"), and the gRPC
`refresh_fn: Callable[[], None]` contract on `AuthzGrpcClient`/
`AsyncAuthzGrpcClient` (`grpc/client.py`) is entirely caller-supplied with no
enforcement that the closure passed to `RefreshGuard` always supplies a
non-`None` `observed_access`. A caller wiring the gRPC `refresh_fn` directly
against `RefreshGuard.refresh_if_needed_*` without first reading a cached
token (a plausible integration mistake given the class is exported as a
reusable building block) would silently never refresh.
**Fix:** Either (a) document this as a required precondition loudly in the
public API and raise `ValueError`/`TypeError` when `observed_access is None`
and `has_any` is `True` rather than silently returning stale data, or (b)
change the comparison to explicitly treat `None` as "no observed baseline —
always attempt a refresh" (i.e. `if self._has_any and observed_access is not
None and self._cached_access != observed_access:`).

### WR-04: `assert`-based invariant enforcement is stripped under `python -O`

**File:** `sdks/python/src/axiam_sdk/token/refresh_guard.py:63,68,81,86`
**Issue:** `RefreshGuard.refresh_if_needed_async`/`_sync` use bare `assert
self._cached_access is not None` to guarantee the `-> str` return type after
`_store_refreshed(result)`. Python strips all `assert` statements when run
with `-O`/`PYTHONOPTIMIZE=1`. Confirmed via reproduction: running under
`python -O` with a `do_refresh` callable that returns `{"access": None, ...}`
(e.g. a bug in a caller-supplied refresh closure, or a
`refresh/AuthzGrpcClient`-adjacent integration that doesn't validate its own
response shape) causes `refresh_if_needed_async` to return `None` silently
instead of raising `AssertionError` — violating the function's own
documented and type-hinted contract (`-> str`) and potentially propagating
`None` into a `Bearer None` Authorization header or an `X-Tenant-ID`-adjacent
downstream call. `_client.py`'s own `_handle_refresh_response` happens to
never construct such a payload today (it raises `AuthError` first if
`new_access` is falsy), so this is latent rather than presently triggered by
the shipped call sites — but `assert` is the wrong tool for a runtime
invariant on a publicly-reusable class explicitly designed to accept
arbitrary caller-supplied `do_refresh` callables.
**Fix:** Replace the `assert` calls with an explicit
`if self._cached_access is None: raise RuntimeError("refresh guard invariant violated: do_refresh did not populate access token")`,
which survives `-O` and gives a clear diagnostic instead of returning `None`
typed as `str`.

### WR-05: No test proves TLS certificate verification actually rejects an untrusted certificate

**File:** `sdks/python/tests/test_grpc_client.py` (all classes), `sdks/python/tests/test_session_cookies.py:61-70`
**Issue:** Every gRPC test constructs `AuthzGrpcClient`/`AsyncAuthzGrpcClient`
with `custom_ca=ca_file` pointing at the exact CA that signed the in-process
test server's self-signed certificate — proving only the happy path (a
correctly configured client connects). There is no test that omits
`custom_ca` (or supplies a wrong one) against that same self-signed server
and asserts the connection **fails** — i.e., no test proves
`build_channel_credentials`/`grpc.ssl_channel_credentials` is actually doing
verification rather than being a no-op. Similarly, `test_session_cookies.py`
only asserts `session._verify is True` (an attribute check) and that
`custom_ca` overrides it to a path string — no test performs a live TLS
handshake against an untrusted/self-signed httpx server and asserts it is
rejected. Given TLS verification is explicitly named as one of the
highest-priority security invariants for this review (security-critical
invariant #6), the absence of a negative-path test is a meaningful gap: a
future refactor that accidentally flips `verify=self._verify` to
`verify=True or custom_ca` or otherwise weakens the check would not be caught
by the existing suite (the `verify=False` grep CI gate only catches the
literal string pattern, not a logic regression that keeps `verify=True`
textually present but non-functional).
**Fix:** Add `test_untrusted_server_connection_is_rejected` (REST, via
`httpx` against a self-signed server with no `custom_ca` supplied — expect an
`ssl.SSLCertVerificationError`/`httpx.ConnectError`) and an analogous gRPC
test (construct `AuthzGrpcClient`/`AsyncAuthzGrpcClient` against
`test_server` with `custom_ca=None` and assert the RPC fails with
`UNAVAILABLE`/a TLS-handshake-failure `grpc.RpcError`, not a hang or silent
success).

## Info

### IN-01: `AxiamClient`'s injectable `logger` parameter is accepted but never used to log anything

**File:** `sdks/python/src/axiam_sdk/_client.py:71,85,92`, `sdks/python/src/axiam_sdk/_session.py:68,101`
**Issue:** `AxiamClient.__init__` accepts a `logger: logging.Logger | None`
parameter (D-15: "Observability = injectable stdlib `logging.Logger`, OFF by
default"), stores it as `self._logger`, and passes it through to `_Session`,
which stores it as `self._logger` too — but neither `_client.py` nor
`_session.py` ever calls `.debug()`/`.info()`/`.warning()`/`.error()` on it
anywhere. Contrast with `amqp/_consumer.py`, which genuinely uses its
`logger` parameter for security-event logging on HMAC/parse failures. The
REST/session layer's `logger` parameter is currently a fully inert
constructor argument — D-15's stated intent ("an injectable `logging.Logger`
integrates with users' existing config") is unmet for the REST transport.
This is not a security bug (nothing can leak from a logger that's never
called) but is an incomplete feature relative to the phase's own locked
decision.
**Fix:** Add at least minimal diagnostic logging at natural points (e.g.
`self._logger.debug("refresh triggered")` in `refresh()`/`async_refresh()`,
`self._logger.warning("login failed: status=%s", response.status_code)` on
non-2xx responses) — being careful to never include token values, matching
the redaction guarantee already enforced elsewhere in this module.

### IN-02: `_decode_unverified_claims` does not validate the decoded JWT payload is a JSON object

**File:** `sdks/python/src/axiam_sdk/_client.py:35-51`
**Issue:** `json.loads(decoded)` is typed and returned as
`dict[str, Any]` without a runtime `isinstance(claims, dict)` check. A token
whose payload segment decodes to valid JSON that is not an object (e.g. a
JSON array or scalar) causes `json.loads` to succeed, and the function
returns e.g. a `list`. Every caller (`_absorb_session_cookies`,
`_refresh_identifiers`, `_session_id_for_logout`) then calls `.get(...)` on
the result, raising an unhandled `AttributeError` instead of the intended
`AuthError`. Confirmed via reproduction: a token with payload `[1,2,3]`
raises `AttributeError: 'list' object has no attribute 'get'` from
`_decode_unverified_claims`'s caller, not a clean `AuthError`. This code path
only processes cookies set by the trusted AXIAM server over TLS (not
directly attacker-reachable in the normal trust model), so severity is low,
but the function's own type signature (`-> dict[str, Any]`) is not actually
enforced at runtime.
**Fix:** Add `if not isinstance(claims, dict): raise AuthError("access token
payload is not a JSON object")` immediately after `json.loads`, consistent
with how `_jwks.py`/`amqp/_hmac.py` both explicitly check
`isinstance(msg, dict)` after their own `json.loads` calls elsewhere in this
same codebase.

---

_Reviewed: 2026-07-01_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
