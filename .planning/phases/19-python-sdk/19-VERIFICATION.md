---
phase: 19-python-sdk
verified: 2026-07-01T21:27:23Z
status: passed
score: 5/5 must-haves verified
behavior_unverified: 0
overrides_applied: 0
---

# Phase 19: Python SDK Verification Report

**Phase Goal:** A Python developer using sync or async patterns can authenticate and make authorized requests, with FastAPI dependency injection and Django middleware as first-class integrations.
**Verified:** 2026-07-01T21:27:23Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `pip install axiam-sdk` installs; `client.login()` (sync via httpx) AND `await client.async_login()` (async) both return a typed `LoginResult` with `mfa_required` | ✓ VERIFIED | `sdks/python/src/axiam_sdk/_client.py:138,148` define `login`/`async_login` on one `AxiamClient`, both routing through `_handle_login_response` which always constructs `LoginResult(mfa_required=...)` (`_models.py:13-33`, `mfa_required: bool` is a required field). `pytest tests/test_client_login.py` — 19 passed. Package builds and installs cleanly (`pip install -e .` succeeded; `python -m build` succeeded — see SC#5). |
| 2 | `asyncio.Lock` single-flight refresh: 5 concurrent asyncio tasks on an expired token trigger exactly 1 refresh (pytest-asyncio test) | ✓ VERIFIED | `RefreshGuard` (`token/refresh_guard.py:35`) uses an independent `asyncio.Lock` for the async path and `threading.Lock` for sync (never unified, per explicit prohibition). `tests/test_single_flight.py::test_single_flight_refresh_exactly_once_async` spawns 5 concurrent `asyncio.gather` tasks against one expired token and asserts `call_count == 1`. Ran directly: `pytest tests/test_single_flight.py -q` — 6 passed. |
| 3 | `httpx` constructed with `verify=True` hardcoded; CI grep gate confirms `verify=False` appears nowhere in SDK source or examples | ✓ VERIFIED | `_session.py:82` — `self._verify: bool | str = custom_ca if custom_ca else True` — no boolean parameter path exists on `_Session`/`AxiamClient` that could carry `False`. `grep -rn "verify=False" src/ examples/ tests/` → empty. Extended grep for `ssl._create_unverified_context`/`verify=0`/`CERT_NONE` → empty. `.github/workflows/sdk-ci-python.yml` has a dedicated `tls-bypass-gate` job (lines 61-84) running the same extended grep (`verify\s*=\s*(False|0)|ssl\._create_unverified_context`) and failing the build on any match. gRPC channel also strict: `grpc/_tls.py` uses `grpc.ssl_channel_credentials` only, no insecure-channel path. |
| 4 | FastAPI dependency + Django middleware both provided and demonstrated in runnable example scripts | ✓ VERIFIED | `src/axiam_sdk/fastapi/__init__.py` (`require_authenticated_user` factory, `Depends`-compatible, raises `HTTPException` 401/403) and `src/axiam_sdk/django/middleware.py` (`AxiamAuthMiddleware`, `sync_capable=True`/`async_capable=True`, attaches `request.axiam_user`) both exist. `examples/fastapi_dependency.py` and `examples/django_middleware.py` both import only the public submodule surface and byte-compile cleanly (`python -m py_compile examples/*.py` succeeded). Both integrations independently enforce `claims["tenant_id"] == configured_tenant` before trusting any claim (cross-tenant replay defense) — confirmed by reading both modules and `pytest tests/test_middleware_tenant.py tests/test_fastapi_dependency.py tests/test_django_middleware.py` — 39 passed combined with error-redaction tests. Confirmed `import axiam_sdk` does NOT pull in `fastapi`/`django` modules (import-safety check run live — no leaked modules). |
| 5 | `python -m build && twine check dist/*` succeeds; PyPI publish CI runs on release tag | ✓ VERIFIED | Ran `python -m build` in `sdks/python/` — built `axiam_sdk-0.0.0.tar.gz` and `axiam_sdk-0.0.0-py3-none-any.whl` successfully, wheel includes committed gRPC stubs as package-data. Ran `twine check dist/*` — both artifacts PASSED. `.github/workflows/sdk-ci-python.yml` has a `publish` job gated `if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/sdks/python/v')` (never runs on PR), using PyPI Trusted Publishing (OIDC, `id-token: write`), re-running the gRPC drift-check and build/twine-check before publishing. Build artifacts cleaned up after verification; tree left clean (`git status --short` empty). |

**Score:** 5/5 truths verified (0 present-but-behavior-unverified)

### Required Artifacts (sample — full tree confirmed present)

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `sdks/python/pyproject.toml` | `setuptools.build_meta`, `>=3.10`, src-layout, package-data | ✓ VERIFIED | Confirmed all fields present and correct |
| `sdks/python/src/axiam_sdk/_client.py` | `AxiamClient` sync+async login/authz | ✓ VERIFIED | Full read; matches must_haves |
| `sdks/python/src/axiam_sdk/_session.py` | shared cookie jar, CSRF, TLS | ✓ VERIFIED | `verify=True` hardcoded confirmed |
| `sdks/python/src/axiam_sdk/token/refresh_guard.py` | dual-lock single-flight | ✓ VERIFIED | `asyncio.Lock` + `threading.Lock`, independent |
| `sdks/python/src/axiam_sdk/_errors.py` | redact-before-wrap taxonomy | ✓ VERIFIED | Sole chokepoint confirmed, tests pass |
| `sdks/python/src/axiam_sdk/_jwks.py` | EdDSA-only JWKS verifier | ✓ VERIFIED | alg checked before keyset lookup |
| `sdks/python/src/axiam_sdk/amqp/_hmac.py` + `_consumer.py` | HMAC verify-before-handler | ✓ VERIFIED | Insertion-order canonicalization; full ack/nack matrix |
| `sdks/python/src/axiam_sdk/grpc/{client,_interceptor,_tls}.py` | sync+async gRPC, strict TLS | ✓ VERIFIED | `grpc.ssl_channel_credentials` only |
| `sdks/python/src/axiam_sdk/fastapi/__init__.py` | Depends-based dependency | ✓ VERIFIED | Cross-tenant check present |
| `sdks/python/src/axiam_sdk/django/middleware.py` | middleware class | ✓ VERIFIED | Cross-tenant check present |
| `sdks/python/examples/*.py` (6 files) | runnable per-capability examples | ✓ VERIFIED | All 6 present, byte-compile clean |
| `.github/workflows/sdk-ci-python.yml` | full CI matrix + gates + publish | ✓ VERIFIED | All 7 jobs present and correctly gated |
| `sdks/python/README.md` | CONTRACT.md §1-§10 conformance statement | ✓ VERIFIED | Literal statement present at line 15 |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `AxiamClient.login`/`async_login` | `LoginResult` | direct construction in `_handle_login_response` | WIRED | Both sync and async paths converge on the same handler |
| `_client.py` | `RefreshGuard` (19-02) | `self._session.refresh_guard` | WIRED | Reused, not reimplemented |
| `grpc/_interceptor.py` | `RefreshGuard.cached_access_token()` | non-blocking read | WIRED | No lock acquired on RPC hot path (confirmed by reading interceptor + guard) |
| `amqp/_consumer.py` | `amqp/_hmac.py::verify_hmac` | direct call before handler | WIRED | `_on_message` verifies before any parse/dispatch |
| `fastapi/__init__.py` + `django/middleware.py` | `_jwks.py::JwksVerifier` | `verifier.verify(token)` | WIRED | Both integrations use the same primitive, both add independent `exp` + tenant checks |
| CI `tls-bypass-gate` job | SDK source/examples/tests | grep pattern | WIRED | Verified pattern matches SC#3 wording exactly |
| CI `publish` job | tag ref | `startsWith(github.ref, 'refs/tags/sdks/python/v')` | WIRED | Confirmed never triggers on `pull_request` |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full test suite passes | `python3 -m pytest -q` (run once) | `115 passed` | ✓ PASS |
| SC#1 login test | `pytest tests/test_client_login.py -q` | `19 passed` | ✓ PASS |
| SC#2 single-flight test | `pytest tests/test_single_flight.py -q` | `6 passed` (incl. the exact 5-concurrent-asyncio-tasks-exactly-1-refresh test) | ✓ PASS |
| SC#3 verify=False grep | `grep -rn "verify=False" src/ examples/ tests/` | empty | ✓ PASS |
| SC#3 extended TLS-bypass grep | `grep -rnE 'verify\s*=\s*(False\|0)\|ssl\._create_unverified_context'` | empty | ✓ PASS |
| SC#4 examples byte-compile | `python -m py_compile examples/*.py` | success | ✓ PASS |
| SC#4 import-safety | `python -c "import axiam_sdk; check sys.modules"` | no fastapi/django leaked | ✓ PASS |
| SC#4/5 security + integration tests | `pytest tests/test_amqp_hmac.py tests/test_error_redaction.py tests/test_middleware_tenant.py tests/test_jwks.py -q` | `36 passed` | ✓ PASS |
| SC#5 build | `python -m build` (in `sdks/python/`) | sdist + wheel built successfully | ✓ PASS |
| SC#5 twine check | `twine check dist/*` | both PASSED | ✓ PASS |
| gRPC stub drift-check | `bash scripts/gen_grpc.sh && git diff --exit-code src/axiam_sdk/grpc/gen` | no diff | ✓ PASS |
| Type/lint gates | `mypy --strict src`, `ruff check .`, `ruff format --check .` | all clean | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|--------------|--------|----------|
| PY-01 | 19-01..19-07 | Python SDK — REST+gRPC+AMQP sync+async, `asyncio.Lock` single-flight, `httpx.Cookies` jar, `verify=True` hardcoded, httpx 0.27 + grpcio 1.78 + aio-pika 9.6 + Pydantic v2 + PyJWT, FastAPI dependency + Django middleware, examples, PyPI publish pipeline | ✓ SATISFIED | All acceptance criteria in REQUIREMENTS.md §PY-01 confirmed against code: pinned deps match `pyproject.toml` exactly; all behaviors verified above. No orphaned requirements — PY-01 is the sole requirement mapped to Phase 19 and is claimed by all 7 plans. |

### Anti-Patterns Found

None. Grep for `TBD`/`FIXME`/`XXX`, `TODO`/`HACK`/`PLACEHOLDER`, "not yet implemented"/"coming soon"/"placeholder", and empty-return stubs across `src/` and `examples/` returned zero matches.

### Human Verification Required

None required for phase-goal achievement. One **informational, non-blocking, external** action is documented in `19-07-SUMMARY.md` and does not affect SC#5's literal wording (which only requires the publish CI *pipeline* to run on a release tag, not that a first real publish has occurred):

- **PyPI Trusted Publisher registration** — a human with PyPI project-owner access to `axiam-sdk` must register this repo's GitHub Actions workflow (`sdk-ci-python.yml`, environment `pypi`) as a Trusted Publisher on PyPI before the first tag push will actually complete a publish. Until then, a `sdks/python/vX.Y.Z` tag push will run the full CI pipeline (drift-check, build, twine check) and fail safely and non-destructively only at the final OIDC publish step. This is explicitly called out in the SUMMARY as a step outside the executor's credentials/capability, and does not block the phase goal (a Python developer can already `pip install` a locally-built wheel and use sync/async auth + FastAPI/Django integrations today; the SDK does not need to be live on PyPI for the phase's technical deliverables to be complete).

### Gaps Summary

No gaps found. All 5 ROADMAP success criteria are verified against running code and passing tests, not just SUMMARY claims. All 7 plans' `must_haves` (truths/artifacts/key_links/prohibitions) were spot-checked and hold. Security-critical controls (redact-before-wrap `NetworkError`, AMQP HMAC verify-before-handler with byte-for-byte Rust-matching canonicalization, EdDSA-only JWKS allowlist checked before keyset lookup, cross-tenant `tenant_id` claim check in both FastAPI and Django integrations enforced before any claim is trusted) all exist in code and are covered by passing regression tests, including non-vacuous control cases (e.g. `test_network_error_redaction_is_non_vacuous`). `mypy --strict`, `ruff check`, and `ruff format --check` all pass clean. The full 115-test suite passes in one run. `python -m build && twine check dist/*` succeeds. The gRPC stub drift-check produces zero diff. The working tree was left clean after verification (all build artifacts removed).

---

_Verified: 2026-07-01T21:27:23Z_
_Verifier: Claude (gsd-verifier)_
