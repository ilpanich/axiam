# Phase 19: Python SDK - Research

**Researched:** 2026-07-01
**Domain:** Dual-interface (sync+async) Python SDK — httpx, grpcio/grpc.aio, aio-pika, Pydantic v2, PyJWT, FastAPI, Django
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Sync/Async Architecture**
- **D-01 [LOCKED]:** Single `AxiamClient` exposing sync methods + `async_*` variants. `client.login(...)` (sync via `httpx.Client`) and `await client.async_login(...)` (async via `httpx.AsyncClient`) both exist on the same client object and both return a typed `LoginResult`. One shared session (cookie jar, tenant context, JWKS cache); lazily-constructed sync/async httpx clients. `threading.Lock` guards sync single-flight; `asyncio.Lock` guards async single-flight.
- **D-02:** AMQP is async-only via `aio-pika`. Closure-handler consumer, SDK owns ack/nack loop, HMAC-SHA256 verify-before-handler (§8). Handler returns `None` → ack; raises retryable error → nack WITH requeue; raises exported drop sentinel → nack WITHOUT requeue; HMAC-fail → nack WITHOUT requeue + security log (handler never sees it).
- **D-12 [LOCKED]:** gRPC ships BOTH sync (`grpcio`) and async (`grpc.aio`) clients for `CheckAccess`/`BatchCheckAccess` — one codegen emits both. Sync-safe auth/tenant interceptor on both.
- **D-19 [LOCKED]:** Client lifecycle via context managers: `with AxiamClient(...) as c:` (sync `__enter__`/`__exit__`) AND `async with AxiamClient(...) as c:` (async `__aenter__`/`__aexit__`), plus explicit `.close()`/`.aclose()`. Deterministically tear down httpx clients, gRPC channel, aio-pika connection.

**Packaging, Layout & Distribution**
- **D-03 [LOCKED]:** `setuptools.build_meta` build backend (replaces invalid `setuptools.backends.legacy:build`). `python -m build && twine check dist/*` must pass (SC#5).
- **D-04:** Commit gRPC stubs (`*_pb2.py`/`*_pb2_grpc.py`/`*.pyi`) into `sdks/python/`, include in wheel AND sdist (package-data), CI drift-check via regenerate + `git diff --exit-code`.
- **D-05:** Tag-triggered PyPI publish via Trusted Publishing (OIDC) on tag `sdks/python/vX.Y.Z`. `python -m build` + `twine check` (+ TestPyPI/dry-run) gate PRs touching `sdks/python/**`.
- **D-11 [LOCKED]:** `requires-python = ">=3.10"` (raised from EOL `>=3.9`).
- **D-14 [LOCKED]:** src-layout (`src/axiam_sdk/`).
- **D-18 [LOCKED]:** CI test matrix = Python 3.10/3.11/3.12/3.13 on `ubuntu-latest`. Runs pytest (incl. pytest-asyncio single-flight test SC#2), `verify=False` grep gate (SC#3), buf/protoc drift-check (D-04).
- **D-20 [LOCKED]:** Ship PEP 561 `py.typed`; enforce `mypy --strict` and `ruff` (lint+format) in CI.

**Token Safety & Models**
- **D-06:** Pydantic v2 typed models — `User`, authz result models, `LoginResult` (shape pinned by D-21).
- **D-21 [LOCKED]:** `LoginResult` = single Pydantic model with `mfa_required: bool` (+ optional `mfa_token`/authenticated identity). Caller checks the flag then calls `verify_mfa(mfa_token, code)`.
- **D-07:** `§7 Sensitive` = Pydantic `SecretStr` for token-bearing fields. Redacts `repr`/`str`/`model_dump`; raw value only via `.get_secret_value()`.
- **D-08:** Exception taxonomy `AuthError`/`AuthzError`/`NetworkError` (§2), one central status→error mapper (HTTP + gRPC tables). `NetworkError` MUST redact `Set-Cookie`/`Authorization`/`Cookie` from any wrapped httpx request/response/error BEFORE storing it. Regression test: raw `axiam_access`/`axiam_refresh` value never appears in `repr`/`str`/`json`/log of a raised error, with a non-vacuous control case.
- **D-16 [LOCKED]:** JWKS via PyJWT `PyJWKClient` — built-in fetch/cache/rotation on unknown `kid`, pointed at the org-wide JWKS endpoint. Proactive refresh; reactive 401/`UNAUTHENTICATED` remains fallback.

**Runtime Behavior**
- **D-15 [LOCKED]:** Injectable stdlib `logging.Logger`, `NullHandler` attached, OFF by default. Redaction guarantees no token values logged. No `structlog` dependency.
- **D-17 [LOCKED]:** Sane HTTP defaults, overridable: connect/read timeouts + bounded exponential backoff WITH jitter on idempotent ops only for 429/503 (honoring `Retry-After`). aio-pika auto-reconnect with backoff+jitter. Concrete numeric constants = planner's call.

**Framework Integrations**
- **D-09 [LOCKED]:** FastAPI = `Depends(...)` dependency-injection callable, dependency-only (no ASGI-middleware variant). Verifies session LOCALLY via PyJWT/`PyJWKClient` against cached JWKS; returns identity (`user_id`, `tenant_id`, `roles`); raises `HTTPException` 401 on `AuthError` / 403 on `AuthzError`. Async-native.
- **D-10 [LOCKED]:** Django = middleware class attaching `request.axiam_user`, sync-WSGI-primary + ASGI-capable (declares `sync_capable`/`async_capable`). Local JWKS verify via PyJWT; standardized 401/403 responses.
- **D-13 [LOCKED]:** Full per-capability examples: login+MFA, REST authz, gRPC, AMQP consumer, FastAPI dependency, Django middleware.

### Carried Forward from Rust/TS/Go references
- **CF-01:** §3 CSRF — non-browser SDK → capture `X-CSRF-Token` from response header, echo on mutating requests.
- **CF-02:** §4 cookie jar — SDK owns `httpx.Cookies` jar; cookies flow transparently for REST; gRPC metadata/JWKS read the access-token cookie by name.
- **CF-03:** §6 TLS — httpx clients constructed with `verify=True` hardcoded (SC#3); only escape hatch is explicit `verify=<ca-path/ssl.SSLContext>`; CI grep gate confirms `verify=False` appears nowhere.
- **CF-04:** §5 tenant — `tenant_slug`/`tenant_id` required at client construction, enforced at call time.
- **CF-05:** §9 single-flight — `asyncio.Lock` (async) + `threading.Lock` (sync), shared across REST+gRPC on one session; 5 concurrent tasks on expired token ⇒ exactly 1 refresh.
- **CF-06:** Retry = bounded backoff, idempotent ops only; observability = injectable logger OFF by default, never emits token values; sane timeouts; aio-pika auto-reconnect w/ backoff+jitter; `base_url` required.
- **CF-07:** Local JWKS via PyJWT (EdDSA/Ed25519), rotation on unknown `kid`, proactive refresh; reactive 401/`UNAUTHENTICATED` fallback — implemented via `PyJWKClient` (D-16).

### Claude's Discretion
- Internal module layout within `src/axiam_sdk/` and file names.
- Concrete numeric timeout/backoff/retry values and default AMQP prefetch/QoS.
- Exact `async_*` method naming and precise `LoginResult` optional-field set beyond `mfa_required`.
- Exact `PyJWKClient` cache-TTL/lifespan and rotation API usage.
- `__init__.py` public export surface and README structure.

### Deferred Ideas (OUT OF SCOPE)
- SC#1 wording ↔ two-class idiom reconciliation — flagged for planner, do not silently diverge from the unified-client decision.
- Sync AMQP (`pika`) — rejected; PY-01 pins `aio-pika` async-only.
- REQUIREMENTS PY-01 wording audit (package/tag/module identifiers vs scaffold).
- Automated cross-language conformance harness.
- macOS/Windows CI matrix.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| PY-01 | Deliver `sdks/python/` with sync + async interfaces (REST/gRPC/AMQP), FastAPI + Django integrations, PyPI `axiam-sdk` package | Standard Stack (verified versions), Architecture Patterns (unified client, single-flight, gRPC dual-stub, AMQP consumer), Code Examples (login/refresh/JWKS/HMAC/interceptor/FastAPI/Django), Package Legitimacy Audit, Runtime State Inventory (scaffold fixes), CI/publish pipeline design |
</phase_requirements>

## Summary

Phase 19 ports the proven Rust (16) / TypeScript (17) / Go (18) reference patterns into idiomatic
dual-interface Python. The 15 user-locked decisions in `19-CONTEXT.md` already fix every
architectural choice; this research focuses on the exact APIs, library idioms, and pitfalls needed
to implement them correctly: `httpx.Client`/`httpx.AsyncClient` sharing one `httpx.Cookies` jar,
`threading.Lock`+`asyncio.Lock` single-flight refresh guards that must never deadlock each other,
`grpcio`+`grpc.aio` dual codegen from raw `protoc` (no `buf` CLI in this environment — same gap
Phase 18 hit), `aio-pika`'s closure/QueueIterator consumer model with HMAC-SHA256
verify-before-handler matching `crates/axiam-amqp/src/messages.rs` byte-for-byte, PyJWT's
`PyJWKClient` two-tier cache for local JWKS verification, Pydantic v2 `SecretStr` for token
redaction, and the FastAPI `Depends`/Django `sync_capable`+`async_capable` framework integration
idioms.

Three server-side facts materially change the Python implementation versus what CONTRACT.md's
abstract description implies: (1) the real login/refresh endpoints require `org_id`/`org_slug` in
addition to `tenant_id`/`tenant_slug` — a Pitfall carried forward from Rust/Go; (2) the
`axiam_refresh` cookie is `Path`-scoped to `/api/v1/auth/refresh` specifically, not `/` — the
`httpx.Cookies` jar will only attach it on requests to that exact path; (3) the JWKS endpoint is
`{base_url}/oauth2/jwks`, organization-wide (not tenant-scoped, not a generic
`/.well-known/jwks.json` OIDC discovery path), serving exactly one Ed25519 key today. All three
are locked-in facts from the server code, not assumptions.

**Primary recommendation:** Fix the scaffold first (`setuptools.build_meta`, `>=3.10`, src-layout),
then build a single internal `_core.py` (or `session.py`) module owning the shared cookie jar +
CSRF token + dual locks + JWKS cache, with `client.py` exposing the public sync/async method pairs
as thin wrappers that call shared private helpers — mirroring the Go `Client`/`refreshguard`
split and the TS `SharedSession` pattern, adapted to Python's sync+async duality.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Login/MFA/refresh/logout (REST) | SDK Client (non-browser) | Server (`axiam-api-rest`) | SDK is a pure external HTTP client; cookie jar + CSRF capture live in the SDK; the server issues tokens and enforces auth |
| Single-flight refresh guard | SDK Client | — | Client-side concurrency control (CONTRACT §9); server has no visibility into concurrent SDK callers |
| Authz check (REST `can`/`check_access`) | SDK Client (REST transport) | Server (`FND-04` endpoint) | SDK calls `POST /api/v1/authz/check`; server's `AuthorizationEngine` is authoritative |
| Authz check (gRPC `CheckAccess`/`BatchCheckAccess`) | SDK Client (gRPC transport) | Server (`axiam-api-grpc`) | Same authorization engine, different transport; SDK dual-stub (sync+async) is a pure client concern |
| AMQP event consumption + HMAC verify | SDK Client (async-only) | Server (`axiam-amqp` publisher) | SDK verifies signatures the server produces; verification logic is duplicated (not imported) per the "SDK must not depend on server crates" constraint |
| Local JWKS/JWT verification | SDK Client | Server (`/oauth2/jwks` issuer) | SDK caches and verifies locally to avoid a server round-trip on every request; server remains the key-rotation source of truth |
| FastAPI dependency injection | SDK (framework integration layer) | — | Runs inside the FastAPI consumer's own process; local-verify only, no new server endpoint |
| Django middleware | SDK (framework integration layer) | — | Runs inside the Django consumer's own process (WSGI/ASGI); local-verify only |
| Token/session redaction (`SecretStr`) | SDK Client (data model) | — | Pydantic model-level concern; must hold regardless of transport |
| PyPI packaging / CI / publish | SDK repo tooling | — | Build/release concern, no runtime tier |

## Standard Stack

### Core

| Library | Version (pinned by PY-01 / verified latest) | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `httpx` | **0.27.x** pinned by PY-01/CONTEXT.md (latest on PyPI: 0.28.1) [VERIFIED: pip index] | Sync `httpx.Client` + async `httpx.AsyncClient`, `httpx.Cookies` jar | Only mainstream Python HTTP client offering one API surface for both sync and async — required to satisfy D-01's unified client without duplicating request-building code |
| `grpcio` | 1.78 pinned by PY-01 (latest: 1.81.1) [VERIFIED: pip index] | gRPC sync client runtime | Canonical gRPC Python runtime |
| `grpcio-tools` | matches `grpcio` minor (latest: 1.81.1) [VERIFIED: pip index] | `python -m grpc_tools.protoc` codegen (protoc + `grpc_python_plugin` bundled) | Standard way to generate `_pb2.py`/`_pb2_grpc.py` without a separate `buf` CLI install |
| `aio-pika` | 9.6.x pinned by PY-01 (latest: 9.6.2) [VERIFIED: pip index] | Async-only AMQP 0.9.1 client | Idiomatic asyncio RabbitMQ client wrapping `aiormq`; `RobustConnection` gives auto-reconnect for free |
| `pydantic` | v2, latest 2.13.4 [VERIFIED: pip index] | Typed models (`LoginResult`, `User`, authz results), `SecretStr` | PY-01 pin; v2's Rust core gives fast validation; `SecretStr` is the built-in §7 Sensitive equivalent |
| `PyJWT` | latest 2.13.0 [VERIFIED: pip index] | `PyJWKClient` JWKS fetch/cache/rotation, EdDSA verify | PY-01 pin; smallest, most widely audited pure-Python JWT library with native JWKS client support |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `fastapi` | latest 0.139.0 [VERIFIED: pip index] | Dev/test dependency only (examples + FastAPI integration tests) | Not a runtime dependency of `axiam-sdk` itself — an optional extra (`axiam-sdk[fastapi]`) or dev-only, since the FastAPI dependency helper only needs `fastapi.HTTPException`/`Depends` type hints, both importable without pulling FastAPI as a hard install for non-FastAPI consumers |
| `django` | latest 5.2.15 [VERIFIED: pip index] | Dev/test dependency only (examples + Django middleware tests) | Same rationale — Django middleware should be import-safe as an optional extra (`axiam-sdk[django]`) so a pure-REST consumer doesn't pull in all of Django |
| `pytest` + `pytest-asyncio` | latest pytest-asyncio 1.4.0 [VERIFIED: pip index] | Test framework; `asyncio_mode` for async tests | Required for SC#2's concurrent-asyncio-tasks single-flight test |
| `pytest-httpx` or `respx` | — | Mock httpx transport in tests without a live server | `respx` mocks at the `httpx` transport layer (recommended — matches both sync and async clients from one mock definition) |
| `mypy` | latest 2.1.0 [VERIFIED: pip index] | `--strict` type checking (D-20) | CI gate |
| `ruff` | latest 0.15.20 [VERIFIED: pip index] | Lint + format (D-20) | CI gate; replaces black+flake8+isort in one tool |
| `build` | latest 1.5.0 [VERIFIED: pip index] | `python -m build` (PEP 517 frontend) | SC#5 |
| `twine` | latest 6.2.0 [VERIFIED: pip index] | `twine check dist/*`, PyPI upload | SC#5 |
| `setuptools` | `>=68` per scaffold (latest 82.0.1) [VERIFIED: pip index] | Build backend (D-03) | Keep scaffold's floor; no need to bump beyond `>=68` unless a specific package-data feature is required (none found) |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `httpx` | `requests` + `aiohttp` (two separate libraries) | CONTRACT.md's own per-language table literally names `httpx.AsyncClient`; using two libraries would duplicate request/cookie/retry logic and contradict D-01's single shared-session design |
| `PyJWKClient` (D-16 locked) | hand-rolled JWKS cache (`jwt.PyJWK` + manual TTL dict) | Rejected by user — more custom crypto-adjacent code, more surface for cache-poisoning/rotation bugs |
| `respx`/`pytest-httpx` for mocking | live test server (Docker-based integration tests) | Unit-level mocking is faster and sufficient for SC#2/SC#3; a docker-based integration suite is out of scope for this phase (no such infra in prior SDK phases either) |
| `grpcio-tools` codegen | `buf generate` (as `buf.gen.yaml` already declares for Python) | `buf` CLI is not installed in this environment (confirmed: `command -v buf` → not found); Phase 18 (Go) hit the identical gap and worked around it with `protoc` + `protoc-gen-go`/`protoc-gen-go-grpc` directly. Python's analog is `python -m grpc_tools.protoc` (bundles protoc + `grpc_python_plugin`), which produces functionally identical stubs to what `buf.gen.yaml`'s `buf.build/protocolbuffers/python` + `buf.build/grpc/python` remote plugins would generate. Document as a reproducible, deterministic local codegen path; CI drift-check regenerates with the same `grpc_tools.protoc` invocation and pinned proto files, then `git diff --exit-code`. |

**Installation:**
```bash
pip install httpx==0.27.* grpcio==1.78.* pydantic>=2 PyJWT>=2.13 aio-pika==9.6.*
pip install --group dev grpcio-tools mypy ruff build twine pytest pytest-asyncio respx
pip install --group fastapi fastapi
pip install --group django django
```

**Version verification:** `pip index versions <pkg>` run 2026-07-01 against the live PyPI index
(see table above); all packages current and non-EOL relative to the `>=3.10` floor (D-11).
`httpx` is pinned to the 0.27.x line by PY-01/CONTEXT.md even though 0.28.1 is latest — do not
silently bump the major/minor without a follow-up decision, since 0.28 dropped some deprecated
`app=` transport shortcuts that are irrelevant here but the pin is still a locked constraint from
REQUIREMENTS.md, not a recommendation to chase latest.

## Package Legitimacy Audit

| Package | Registry | Signal notes | Verdict (raw) | Disposition |
|---------|----------|---------------|---------|-------------|
| httpx | PyPI | Extremely well-known (encode/httpx), millions of downloads/week, active repo | OK (raw seam flagged "unknown-downloads" — PyPI API doesn't surface download counts, false-positive signal) | Approved |
| grpcio / grpcio-tools | PyPI | Official `grpc/grpc` project artifact | OK | Approved |
| aio-pika | PyPI | `mosquito/aio-pika`, long-lived, standard async RabbitMQ client | OK | Approved |
| pydantic | PyPI | Official `pydantic/pydantic`, extremely widely used | OK | Approved |
| PyJWT | PyPI | Official `jpadilla/pyjwt` | OK | Approved |
| fastapi | PyPI | Official `fastapi/fastapi`; raw seam flagged SUS on "too-new"/"unknown-downloads" — signal artifact of PyPI publish-date metadata (0.139.0 released recently as part of normal fast release cadence), not a legitimacy concern | OK | Approved |
| django | PyPI | Official Django Software Foundation project; same false-positive pattern as fastapi | OK | Approved |
| pytest-asyncio | PyPI | Official `pytest-dev/pytest-asyncio` | OK | Approved |
| mypy | PyPI | Official `python/mypy` | OK | Approved |
| ruff | PyPI | Official `astral-sh/ruff`; frequent releases (weekly), flagged "too-new" as a metadata artifact | OK | Approved |
| build | PyPI | Official PyPA `build` project; `repoUrl: null` in raw signal is because PyPI metadata doesn't list it, not because it's unofficial (confirmed via `pypa/build` GitHub) [CITED: pypi.org/project/build] | OK | Approved |
| twine | PyPI | Official PyPA `twine` project | OK | Approved |

**Note on the raw legitimacy-check seam output:** every package above was flagged `SUS` by the
automated seam, but every reason given (`too-new`, `unknown-downloads`, `no-repository`) is a
metadata-availability artifact of PyPI's JSON API (which does not expose weekly download counts
the way npm does, and reports the *latest release* timestamp as `publishedAt`, not package
inception date) — not an actual legitimacy signal. All twelve packages are top-tier, long-running,
canonical projects in the Python ecosystem, independently cross-checked against their official
GitHub repositories and PyPI project pages. **No package is downgraded to `[ASSUMED]`** — package
identity was confirmed via direct `pip index versions` registry lookups (an authoritative source)
cross-referenced against each project's well-known GitHub org (`encode/httpx`, `grpc/grpc`,
`mosquito/aio-pika`, `pydantic/pydantic`, `jpadilla/pyjwt`, `fastapi/fastapi`,
`django/django`, `pytest-dev/pytest-asyncio`, `python/mypy`, `astral-sh/ruff`, `pypa/build`,
`pypa/twine`).

**Packages removed due to [SLOP] verdict:** none.
**Packages flagged as suspicious [SUS] by the raw seam but reclassified OK after manual cross-check:** all twelve listed above — reasons are PyPI-metadata artifacts, not legitimacy concerns; no `checkpoint:human-verify` gate is needed for any of them.

## Architecture Patterns

### System Architecture Diagram

```
                         ┌─────────────────────────────────────────┐
                         │           AxiamClient (public)           │
                         │  login()/async_login()  verify_mfa()/... │
                         │  check_access()/async_check_access()...  │
                         └───────────────┬───────────────────────────┘
                                         │ delegates to
             ┌───────────────────────────┼────────────────────────────┐
             ▼                           ▼                            ▼
   ┌───────────────────┐      ┌────────────────────┐        ┌──────────────────┐
   │  REST transport     │      │  gRPC transport      │        │  AMQP transport    │
   │  httpx.Client        │      │  grpcio (sync stub)  │        │  aio-pika (async)  │
   │  httpx.AsyncClient   │      │  grpc.aio (async)    │        │  Consume() loop    │
   │  httpx.Cookies jar   │      │  auth/tenant          │        │  HMAC verify       │
   │  (shared)             │      │  interceptor          │        │  BEFORE handler    │
   └─────────┬───────────┘      └──────────┬──────────┘        └────────┬─────────┘
             │  on 401 / UNAUTHENTICATED               │                          │ nack/ack
             ▼                                          ▼                          ▼
   ┌─────────────────────────────────────────────────────────────┐      handler(event)
   │           Single-flight Refresh Guard (shared)                │
   │   threading.Lock (sync path)  +  asyncio.Lock (async path)    │
   │   double-check-after-lock; exactly 1 in-flight refresh;       │
   │   no retry loop on failure (§9.3)                              │
   └───────────────────────────┬─────────────────────────────────┘
                               │ POST /api/v1/auth/refresh (path-scoped cookie)
                               ▼
                    ┌─────────────────────────┐
                    │   AXIAM server (v1.0)     │
                    │  /api/v1/auth/*            │
                    │  /oauth2/jwks              │
                    │  axiam.v1.AuthorizationService │
                    └───────────┬───────────────┘
                               │ EdDSA-signed JWT (Set-Cookie: axiam_access)
                               ▼
                    ┌─────────────────────────┐
                    │   PyJWKClient (PyJWT)     │
                    │  fetch+cache {base}/oauth2/jwks │
                    │  rotate on unknown kid     │
                    └───────────┬───────────────┘
                               │ verified Claims (user_id, tenant_id, roles)
                     ┌─────────┴──────────┐
                     ▼                    ▼
          ┌────────────────────┐  ┌─────────────────────────┐
          │ FastAPI Depends(...) │  │ Django Middleware          │
          │ local verify → returns│  │ request.axiam_user          │
          │ identity or raises    │  │ sync_capable+async_capable  │
          │ HTTPException 401/403 │  │ 401/403 JSON response       │
          └────────────────────┘  └─────────────────────────┘
```

Trace the primary use case (SC#1/SC#2): a caller invokes `client.login(...)` → REST transport
POSTs to `/api/v1/auth/login` → server sets `axiam_access`/`axiam_refresh`/`axiam_csrf` cookies →
`LoginResult` returned. Later, `client.check_access(...)` fires with an expired access token →
server returns 401 → REST transport calls into the shared Single-flight Refresh Guard → guard
POSTs `/api/v1/auth/refresh` exactly once even under 5 concurrent async callers → the retried
`check_access` succeeds. Independently, `AxiamMiddleware`/`Depends(...)` verify inbound tokens
locally against the cached JWKS without touching the refresh guard at all (resource-server side,
not client side).

### Recommended Project Structure

```
sdks/python/
├── pyproject.toml                # setuptools.build_meta, src-layout, package-data
├── README.md
├── LICENSE
├── src/
│   └── axiam_sdk/
│       ├── __init__.py           # public re-exports: AxiamClient, LoginResult, errors, Sensitive-equivalent note
│       ├── py.typed              # PEP 561 marker (empty file)
│       ├── _client.py            # AxiamClient: sync+async method pairs, __enter__/__aenter__, lifecycle
│       ├── _session.py           # shared cookie jar, CSRF capture, tenant/org header injection, dual refresh guard
│       ├── _models.py            # Pydantic v2 models: LoginResult, User, CheckAccessResult, BatchCheckAccessResult
│       ├── _errors.py            # AuthError/AuthzError/NetworkError + central status→error mapper
│       ├── _jwks.py              # PyJWKClient wrapper, EdDSA-only alg allowlist
│       ├── grpc/
│       │   ├── __init__.py       # AuthzGrpcClient (sync) + AsyncAuthzGrpcClient
│       │   ├── _interceptor.py   # sync-safe auth/tenant metadata interceptor (both grpcio + grpc.aio variants)
│       │   └── gen/               # COMMITTED generated stubs (D-04)
│       │       ├── __init__.py
│       │       ├── authorization_pb2.py
│       │       ├── authorization_pb2.pyi
│       │       └── authorization_pb2_grpc.py
│       ├── amqp/
│       │   ├── __init__.py       # consume(), ErrDrop sentinel
│       │   └── _hmac.py          # verify_hmac() — canonical-JSON + hex-HMAC-SHA256, byte-for-byte match to Rust
│       ├── fastapi/
│       │   └── __init__.py       # require_authenticated_user Depends callable (optional extra)
│       └── django/
│           └── middleware.py     # AxiamAuthMiddleware (optional extra)
├── examples/
│   ├── login_mfa.py
│   ├── rest_authz.py
│   ├── grpc_checkaccess.py
│   ├── amqp_consumer.py
│   ├── fastapi_dependency.py
│   └── django_middleware.py
├── tests/
│   ├── conftest.py
│   ├── test_client_login.py
│   ├── test_single_flight.py      # pytest-asyncio, SC#2
│   ├── test_tls_gate.py            # grep-based, or import-time assertion, SC#3
│   ├── test_error_redaction.py     # SC-adjacent, CR-04 carry-forward
│   ├── test_amqp_hmac.py
│   ├── test_jwks.py
│   ├── test_fastapi_dependency.py
│   └── test_django_middleware.py
└── .github/workflows/python-sdk.yml   # (or repo-root .github/workflows/ per existing convention)
```

Module names use a leading underscore (`_client.py`, `_session.py`, etc.) for internal modules not
meant as public import paths, mirroring the Go SDK's `internal/` package convention — Python has no
enforced internal-package mechanism, so the underscore-prefix + curated `__init__.py` re-export
surface is the idiomatic equivalent (PEP 8 convention: leading underscore signals "not part of the
public API" even though it remains importable).

### Pattern 1: Unified sync+async client with one shared session

**What:** A single `AxiamClient` class holds one `_Session` object. `_Session` lazily constructs
`httpx.Client` and `httpx.AsyncClient` on first use (not both eagerly — avoids opening a sync
connection pool a purely-async caller never needs, and vice versa), sharing one `httpx.Cookies`
jar instance passed to both.

**When to use:** This is the mandatory shape per D-01/SC#1 — `client.login()` and
`client.async_login()` must exist on the same object.

**Example:**
```python
# Adapted from httpx docs (https://www.python-httpx.org/advanced/clients/) +
# CONTRACT.md §4 (cookie jar) + §1 (method map) + D-01/D-19.
import httpx
import threading
import asyncio
from typing import Optional


class _Session:
    """Shared REST session state: one cookie jar, lazily-built sync/async
    httpx clients, CSRF token capture, and the dual single-flight guards.
    Not part of the public API (see PEP 8 leading-underscore convention).
    """

    def __init__(self, base_url: str, tenant_slug: str, *, custom_ca: Optional[str] = None,
                 timeout: httpx.Timeout, logger=None) -> None:
        self._base_url = base_url
        self._tenant_slug = tenant_slug
        self._cookies = httpx.Cookies()
        self._csrf_token: Optional[str] = None
        self._csrf_lock = threading.Lock()
        self._timeout = timeout
        self._verify = custom_ca if custom_ca else True   # CF-03: NEVER False.
        self._sync_client: Optional[httpx.Client] = None
        self._async_client: Optional[httpx.AsyncClient] = None
        self._sync_refresh_lock = threading.Lock()
        self._async_refresh_lock = asyncio.Lock()
        self._logger = logger

    @property
    def sync_client(self) -> httpx.Client:
        if self._sync_client is None:
            self._sync_client = httpx.Client(
                base_url=self._base_url,
                cookies=self._cookies,
                timeout=self._timeout,
                verify=self._verify,   # hardcoded True unless custom CA (SC#3 gate).
            )
        return self._sync_client

    @property
    def async_client(self) -> httpx.AsyncClient:
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                base_url=self._base_url,
                cookies=self._cookies,
                timeout=self._timeout,
                verify=self._verify,
            )
        return self._async_client
```

**Why the cookie jar must be the SAME `httpx.Cookies` instance passed to both clients:**
`httpx.Client(cookies=...)` copies the argument into its own `httpx.Cookies` wrapper internally in
older httpx versions but in 0.27+, passing an existing `httpx.Cookies` instance is safe and
`httpx.Cookies` itself wraps a shared `http.cookiejar.CookieJar` — verify this at implementation
time by asserting `sync_client.cookies.jar is async_client.cookies.jar` in a unit test, since a
silent copy-instead-of-share regression would break session continuity across sync/async calls on
the same `AxiamClient` (a caller mixing `client.login()` then `await client.async_check_access()`
must reuse the session cookie). [ASSUMED — confirm empirically against the exact pinned 0.27.x
patch release, since httpx's Cookies-sharing behavior has had subtle changes across versions.]

### Pattern 2: Dual-lock single-flight refresh guard (SC#2's literal target)

**What:** One guard object exposes both a sync entry point (`refresh_if_needed_sync`, using
`threading.Lock`) and an async entry point (`refresh_if_needed_async`, using `asyncio.Lock`), each
independently guarding their own call path — sync REST calls never block on the asyncio lock and
vice versa, avoiding any cross-loop deadlock risk. The **double-check-after-lock** pattern (Go
reference) is mandatory: after acquiring the lock, re-check whether another caller already
refreshed (cached token differs from the token that triggered this 401) before calling the actual
refresh endpoint.

**When to use:** Every REST 401 and gRPC `UNAUTHENTICATED` response when a refresh token is
present (CONTRACT §9).

**Example (async path — the literal SC#2 target):**
```python
# Source: pattern mirrors sdks/go/internal/refreshguard/guard.go, adapted to
# asyncio.Lock (CONTRACT.md §9 Python row: "asyncio.Lock + shared asyncio.Future").
import asyncio
from typing import Optional


class RefreshGuard:
    def __init__(self) -> None:
        self._async_lock = asyncio.Lock()
        self._sync_lock = __import__("threading").Lock()
        self._cached_access: Optional[str] = None

    async def refresh_if_needed_async(self, observed_access: str, do_refresh) -> str:
        async with self._async_lock:
            # Double-check: another task may have refreshed while we waited.
            if self._cached_access is not None and self._cached_access != observed_access:
                return self._cached_access
            new_access = await do_refresh()   # no retry loop on failure (§9.3) — propagate as-is.
            self._cached_access = new_access
            return new_access
```

**pytest-asyncio test proving exactly-1-refresh under 5 concurrent tasks (SC#2):**
```python
# Source: pattern adapted from CONTRACT.md §9 "Test requirement" +
# sdks/go/internal/refreshguard/guard_test.go's concurrency assertion.
import asyncio
import pytest


@pytest.mark.asyncio
async def test_single_flight_refresh_exactly_once():
    call_count = 0

    async def fake_refresh():
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0.01)  # simulate network latency so tasks actually overlap
        return "new-access-token"

    guard = RefreshGuard()
    expired_token = "expired-access-token"

    results = await asyncio.gather(*[
        guard.refresh_if_needed_async(expired_token, fake_refresh)
        for _ in range(5)
    ])

    assert call_count == 1, "expected exactly one refresh call across 5 concurrent tasks"
    assert all(r == "new-access-token" for r in results)
```
Requires `pytest-asyncio` configured with `asyncio_mode = "auto"` (or explicit `@pytest.mark.asyncio`
per test, as above) in `pyproject.toml`'s `[tool.pytest.ini_options]`.

**Pitfall — do not share one Lock object across both sync and async paths.** `asyncio.Lock` is not
thread-safe and `threading.Lock.acquire()` blocks the event loop if called from async code. Keep
them as two independent locks (as above) rather than trying to unify into one — the sync and async
call paths are never in the same OS thread simultaneously by construction (a sync `httpx.Client`
call runs on whatever thread invoked `client.login()`; an async call runs on the event loop thread),
so two independent locks correctly serialize each path without any cross-lock coordination needed,
UNLESS a caller mixes sync calls from a worker thread with async calls on the event loop
concurrently on the SAME client instance — in that mixed-mode case, only same-path calls are
deduplicated (5 concurrent async tasks → 1 refresh; a simultaneous sync call from another thread
could trigger a second, independent refresh). Document this as a known limitation: full
cross-paradigm single-flight would require a `threading.Lock`-guarded flag checked from both paths,
which adds blocking-in-async-context risk. **Recommendation: implement the two-lock design above
per CONTRACT.md's own per-language table** (which lists `asyncio.Lock + shared asyncio.Future` as
the Python mechanism, not a unified cross-paradigm lock) — SC#2 only tests the async path with 5
concurrent asyncio tasks, so this satisfies the literal requirement. If mixed sync+async single
client instances become a real concern later, escalate to Claude's Discretion / a follow-up phase.

### Pattern 3: gRPC dual sync+async client from one codegen, sync-safe interceptor

**What:** `python -m grpc_tools.protoc` generates ONE set of message stubs (`*_pb2.py`) usable by
both sync and async stub classes — `grpcio` and `grpc.aio` both consume the same
`*_pb2_grpc.py`-generated `AuthorizationServiceStub` message shapes; only the *channel* and
*stub-instantiation* differ (`grpc.insecure_channel`/`grpc.secure_channel` +
`authorization_pb2_grpc.AuthorizationServiceStub(channel)` for sync vs.
`grpc.aio.insecure_channel`/`grpc.aio.secure_channel` + the same stub class for async — `grpc.aio`
reuses the identical generated stub class, it does not need a separate async-specific codegen
output). This is a key simplification versus Go/TS, which need separate codegen configs.

**When to use:** D-12's both-sync-and-async gRPC requirement.

**Example — codegen invocation (no `buf` CLI available; mirrors Phase 18's protoc fallback):**
```bash
# Source: grpcio-tools official docs (https://grpc.io/docs/languages/python/quickstart/)
python -m grpc_tools.protoc \
  -I proto \
  --python_out=sdks/python/src/axiam_sdk/grpc/gen \
  --grpc_python_out=sdks/python/src/axiam_sdk/grpc/gen \
  --pyi_out=sdks/python/src/axiam_sdk/grpc/gen \
  proto/axiam/v1/authorization.proto
```
Generates `authorization_pb2.py`, `authorization_pb2.pyi`, and `authorization_pb2_grpc.py` in one
invocation. `grpc_tools.protoc` bundles its own `protoc` binary AND the `grpc_python_plugin` — no
separate `protoc-gen-grpc-python` binary needs to be on `PATH` (this differs from Go's model, which
needed separately-installed `protoc-gen-go`/`protoc-gen-go-grpc` binaries). This is the single
biggest Python-specific codegen simplification worth documenting for the planner: **one pip package
(`grpcio-tools`), one command, three output files, zero external binary PATH dependencies** beyond
`grpcio-tools` itself.

**Known post-generation fixup required:** `grpc_tools.protoc`-generated `_pb2_grpc.py` files use a
relative import (`import authorization_pb2 as authorization__pb2`) that breaks when the generated
package is nested (`axiam_sdk.grpc.gen.authorization_pb2_grpc` importing bare `authorization_pb2`
fails outside the exact generation directory). This is a well-documented `grpcio-tools` limitation.
**Fix:** either (a) post-process the generated `_grpc.py` file's import line to a relative import
(`from . import authorization_pb2 as authorization__pb2`) as part of the codegen script/Makefile
target — the same class of fixup the `buf.build/grpc/python` remote plugin's `grpc_python`
insertion-point option would otherwise handle automatically — or (b) generate directly into the
final package directory with a package-qualified `-I` root so the plugin emits absolute imports
matching the final import path. Document this as a **Common Pitfall** (below) since it is the #1
reported gRPC-Python codegen frustration and will silently produce an `ImportError` at first import
if missed, not caught by mypy/ruff.

**Sync-safe auth/tenant interceptor (both variants needed — grpcio interceptors and grpc.aio
interceptors are DIFFERENT base classes):**
```python
# Source: grpc.aio docs (grpc.github.io/grpc/python/grpc_asyncio.html) +
# sdks/go/grpc/interceptor.go's non-blocking TokenFunc pattern.
import grpc
import grpc.aio
from typing import Callable, Optional, Tuple


class _AuthMetadataMixin:
    """Shared metadata-building logic for both interceptor variants. Never
    acquires the async refresh lock directly — tokenFn MUST be a
    non-blocking cache read (RESEARCH.md Pitfall, mirrors Go/Rust)."""

    def __init__(self, token_fn: Callable[[], Optional[str]], tenant_id: str) -> None:
        self._token_fn = token_fn
        self._tenant_id = tenant_id

    def _build_metadata(self, existing) -> list:
        md = list(existing or [])
        token = self._token_fn()
        if token:
            md.append(("authorization", f"Bearer {token}"))
        md.append(("x-tenant-id", self._tenant_id))
        return md


class SyncAuthInterceptor(_AuthMetadataMixin, grpc.UnaryUnaryClientInterceptor):
    def intercept_unary_unary(self, continuation, client_call_details, request):
        new_details = client_call_details._replace(
            metadata=self._build_metadata(client_call_details.metadata)
        )
        return continuation(new_details, request)


class AsyncAuthInterceptor(_AuthMetadataMixin, grpc.aio.UnaryUnaryClientInterceptor):
    async def intercept_unary_unary(self, continuation, client_call_details, request):
        new_details = client_call_details._replace(
            metadata=self._build_metadata(client_call_details.metadata)
        )
        return await continuation(new_details, request)
```
Note the async variant's `intercept_unary_unary` is itself `async def` and its `continuation` must
be `await`-ed — this is the key grpc.aio-specific divergence from sync grpcio interceptors (which
call `continuation` synchronously). Both must also implement `intercept_unary_stream` /
`intercept_stream_unary` / `intercept_stream_stream` if streaming RPCs are added later; PY-01's
scope (`CheckAccess`/`BatchCheckAccess`) is unary-unary only, so only that method is strictly
required for this phase, but declare the class name generically (`AuthInterceptor`, not
`UnaryAuthInterceptor`) to avoid a rename when streaming is added post-v1.0-beta.

### Pattern 4: AMQP closure-handler consumer with HMAC verify-before-handler

**What:** `aio-pika`'s `Queue.iterator()` (a `QueueIterator`) or a per-message callback registered
via `queue.consume(callback)` both work; the closure-handler shape (mirroring Go's `Consume(...,
handler)`) maps most naturally onto `queue.consume(callback, no_ack=False)` with a `Message` wrapped
in `message.process(ignore_processed=True)` so the SDK — not `aio-pika`'s automatic
context-manager — decides ack vs. nack(requeue=True) vs. nack(requeue=False).

**When to use:** D-02's AMQP consumer.

**Example:**
```python
# Source: aio-pika docs (docs.aio-pika.com/quick-start.html) +
# CONTRACT.md §8 + crates/axiam-amqp/src/messages.rs canonical protocol +
# sdks/go/amqp/consumer.go's verifyAndDispatch structure.
import hmac
import hashlib
import json
from typing import Callable, Awaitable, Any
import aio_pika
from aio_pika.abc import AbstractIncomingMessage


class ErrDrop(Exception):
    """Raised by a handler to signal 'poison message, nack WITHOUT requeue'
    (mirrors Go's exported ErrDrop sentinel, D-02)."""


def verify_hmac(signing_key: bytes, body: bytes) -> bool:
    """Byte-for-byte port of crates/axiam-amqp/src/messages.rs verify_payload,
    matching the server's canonical-JSON + hex-HMAC-SHA256 protocol.
    Returns False (never raises) for malformed JSON, missing signature, or
    a non-hex/wrong-length signature — never a silent pass-through."""
    try:
        msg: dict = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False

    sig_hex = msg.pop("hmac_signature", None)
    if sig_hex is None:
        return False  # strict mode default (§8.3): missing signature = reject.

    # json.dumps with sort_keys=True must match serde_json's BTreeMap-backed
    # canonical ordering used by the Rust signer — separators must also match
    # (no extra whitespace) since HMAC is over exact bytes.
    canonical = json.dumps(msg, sort_keys=True, separators=(",", ":")).encode("utf-8")

    try:
        expected = bytes.fromhex(sig_hex)
    except ValueError:
        return False

    computed = hmac.new(signing_key, canonical, hashlib.sha256).digest()
    return hmac.compare_digest(computed, expected)


async def consume(
    channel: aio_pika.abc.AbstractChannel,
    queue_name: str,
    signing_key: bytes,
    handler: Callable[[dict], Awaitable[None]],
    *,
    prefetch: int = 10,
    logger=None,
) -> None:
    await channel.set_qos(prefetch_count=prefetch)
    queue = await channel.declare_queue(queue_name, durable=True, passive=True)

    async def _on_message(message: AbstractIncomingMessage) -> None:
        async with message.process(ignore_processed=True):
            if not verify_hmac(signing_key, message.body):
                if logger:
                    logger.warning(
                        "axiam_sdk_security: AMQP HMAC verification failed; "
                        "nacking without requeue"
                    )
                await message.nack(requeue=False)
                return
            try:
                event = json.loads(message.body)
                event.pop("hmac_signature", None)
            except (json.JSONDecodeError, UnicodeDecodeError):
                if logger:
                    logger.warning(
                        "axiam_sdk_security: AMQP body failed to parse after "
                        "HMAC verification; nacking without requeue"
                    )
                await message.nack(requeue=False)
                return
            try:
                await handler(event)
            except ErrDrop:
                await message.nack(requeue=False)
                return
            except Exception:
                await message.nack(requeue=True)
                return
            await message.ack()

    await queue.consume(_on_message, no_ack=False)
```

**Critical correctness note — `json.dumps(..., sort_keys=True, separators=(",", ":"))` must be
verified against the server's actual `serde_json::to_vec` output byte-for-byte**, not assumed.
`serde_json`'s default `Serialize` for a `struct` (not a `HashMap`) preserves FIELD DECLARATION
ORDER, not alphabetical order — `AuthzRequest`/`AuditEventMessage` are Rust structs with fields in
a fixed declared order (`correlation_id, tenant_id, subject_id, action, resource_id, scope,
hmac_signature` for `AuthzRequest`), NOT a `BTreeMap`. The Go reference's comment claiming
"`serde_json::to_vec` ordering (BTreeMap-backed, no preserve_order feature)" describes `serde_json`'s
behavior for a generic `Value`/`HashMap`/`BTreeMap`, but the actual wire messages are typed structs
— **[ASSUMED, HIGH-RISK]: this needs empirical verification against a real server-signed message
in a Wave 0 test**, comparing Python's canonicalization against a captured real `sign_payload`
output, before trusting `sort_keys=True` reproduces the correct byte sequence. If the server's
struct-field order differs from alphabetical, `sort_keys=True` will produce a DIFFERENT byte
sequence than what `sign_payload` signed, and every HMAC check will fail. **The safest
implementation is to NOT reorder keys purely alphabetically but instead preserve the EXACT key
order the message arrives in** (Python's `json.loads` into a `dict` already preserves insertion
order per PEP 468/3.7+ guarantee, and `json.dumps` on that dict without `sort_keys` re-emits the
same order) — after removing `hmac_signature`, re-serializing the remaining dict in its
original-received key order should exactly reproduce the signer's byte sequence, SINCE the
signature was computed over the message AS THE SERVER SERIALIZED IT (struct field order) and the
message arrives over the wire in that same order — Python's JSON parser then re-serializer round
trip preserves it. **Recommendation: use `json.dumps(msg, separators=(",", ":"))` WITHOUT
`sort_keys=True`** (relying on dict insertion-order preservation), and add a Wave-0 regression test
using a real HMAC signature computed via `crates/axiam-amqp/src/messages.rs::sign_payload` (or a
fixture captured from a live publish) to prove byte-for-byte compatibility BEFORE building the rest
of the AMQP module on top of an unverified assumption. This is the single highest-risk pitfall in
this phase — get a fixture-based cross-language test in Wave 0.

### Pattern 5: PyJWT `PyJWKClient` for local JWKS verification

**What:** `PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=300)` fetches the org-wide JWKS,
caches the whole set (Tier 1) and individual signing keys via `lru_cache` (Tier 2, no TTL — see
Pitfall below), and `get_signing_key_from_jwt(token)` resolves the correct key by the token's `kid`
header, raising `PyJWKClientError` on an unknown `kid` (which the caller must catch and treat as a
"force refetch" trigger — `PyJWKClient` does NOT auto-refetch on unknown-kid by default the way the
Go `jwx` library's cache does; this must be implemented explicitly).

**Example:**
```python
# Source: PyJWT official docs (pyjwt.readthedocs.io/en/latest/usage.html)
import jwt
from jwt import PyJWKClient, PyJWKClientError

JWKS_PATH = "/oauth2/jwks"  # org-wide, NOT tenant-scoped, NOT generic OIDC
                             # discovery — confirmed via crates/axiam-api-rest
                             # server.rs route registration + sdks/rust,go
                             # references (D-16's "exact path confirmed in
                             # research" resolves to this literal path).


class JwksVerifier:
    def __init__(self, base_url: str, *, lifespan: int = 300) -> None:
        jwks_url = base_url.rstrip("/") + JWKS_PATH
        self._client = PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=lifespan)

    def verify(self, token: str) -> dict:
        # Reject non-EdDSA alg BEFORE any keyset lookup (algorithm-confusion
        # defense — mirrors Rust/Go references).
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "EdDSA":
            raise ValueError("unexpected alg: only EdDSA is accepted")

        try:
            signing_key = self._client.get_signing_key_from_jwt(token)
        except PyJWKClientError:
            # Unknown kid or fetch failure: force exactly one refetch, retry once.
            self._client.jwk_set_cache = None  # invalidate Tier-1 cache to force refetch
            signing_key = self._client.get_signing_key_from_jwt(token)

        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["EdDSA"],
            options={"require": ["exp", "sub"]},
        )
```

**Pitfall — `PyJWKClient`'s `lru_cache`-backed per-key cache (`cache_keys=True`) has NO
expiration**, so a key that is later rotated/revoked stays servable from the LRU cache indefinitely
even after `jwk_set_cache` (Tier 1) expires and refetches [CITED:
github.com/jpadilla/pyjwt/issues/1051]. Given AXIAM serves exactly one Ed25519 key today
(D-16/CF-07), this is lower-risk short-term, but **do not enable `cache_keys=True`** — rely on Tier
1 (`cache_jwk_set=True`, `lifespan=300`) alone, matching the Go/Rust references' single JWKS-set
cache with a TTL (Go: `minRefetchInterval=60s`, `maxCacheInterval=300s`; Rust:
`JWKS_CACHE_TTL=300s`, `FORCED_REFETCH_MIN_INTERVAL=60s`). Recommended Python defaults: `lifespan=300`
(matches Rust/Go's 300s TTL) with a manually-implemented forced-refetch-on-unknown-kid path
rate-limited to once per 60s (mirroring the Rust `FORCED_REFETCH_MIN_INTERVAL`) — `PyJWKClient` has
no built-in rate-limit for forced refetches, so add one at the wrapper level to avoid a
hostile/rotating-kid token stream hammering the JWKS endpoint (same concern the Rust/Go references
already documented).

### Pattern 6: FastAPI dependency-injection helper

**What:** A callable (function or class with `__call__`) used via `Depends(...)`, verifying the
bearer token/cookie locally and returning an identity object, or raising `HTTPException`.

**Example:**
```python
# Source: FastAPI official docs pattern (fastapi.tiangolo.com/tutorial/dependencies/) +
# CONTRACT.md §10 (FastAPI row: "Depends(require_authenticated_user)").
from fastapi import Depends, HTTPException, Request
from axiam_sdk import AuthError, AuthzError
from axiam_sdk._jwks import JwksVerifier


class AxiamUser:
    def __init__(self, user_id: str, tenant_id: str, roles: list[str]) -> None:
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.roles = roles


def require_authenticated_user(verifier: JwksVerifier, configured_tenant: str):
    async def _dependency(request: Request) -> AxiamUser:
        token = _extract_token(request)  # Authorization: Bearer, fallback to axiam_access cookie
        try:
            claims = verifier.verify(token)
        except Exception as exc:
            raise HTTPException(status_code=401, detail="invalid or expired token") from exc

        if claims.get("tenant_id") != configured_tenant:
            raise HTTPException(status_code=401, detail="token tenant_id mismatch")

        return AxiamUser(
            user_id=claims["sub"], tenant_id=claims["tenant_id"], roles=claims.get("scope", "").split()
        )
    return _dependency


def _extract_token(request: Request) -> str:
    auth = request.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:].strip()
    cookie = request.cookies.get("axiam_access")
    if cookie:
        return cookie
    raise HTTPException(status_code=401, detail="missing authentication credentials")
```
This is a dependency **factory** (`require_authenticated_user(verifier, tenant)` returns the actual
`Depends`-compatible callable) rather than a bare importable dependency, since the verifier and
tenant must be configured per-app — mirrors the Go middleware's `Middleware(verifier,
configuredTenant, opts...)` factory pattern. Route usage:
`@app.get("/me") async def me(user: AxiamUser = Depends(require_authenticated_user(verifier,
"acme"))):`.

### Pattern 7: Django middleware, sync-WSGI-primary + ASGI-capable

**What:** A middleware class declaring `sync_capable = True` and `async_capable = True`, detecting
at `__init__` time whether `get_response` is a coroutine function (via
`asgiref.sync.iscoroutinefunction`) and marking itself accordingly (via
`asgiref.sync.markcoroutinefunction(self)`) so Django's `BaseHandler` does not force an unnecessary
sync↔async adaptation.

**Example:**
```python
# Source: Django official docs (docs.djangoproject.com/en/5.2/topics/http/middleware.html
# "Marking middleware as async-capable") + sdks/go/middleware/nethttp.go's
# extraction/verification/injection structure.
from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from django.http import JsonResponse


class AxiamAuthMiddleware:
    sync_capable = True
    async_capable = True

    def __init__(self, get_response):
        self.get_response = get_response
        if iscoroutinefunction(self.get_response):
            markcoroutinefunction(self)

    def __call__(self, request):
        if iscoroutinefunction(self.get_response):
            return self.__acall__(request)
        return self._sync_call(request)

    def _sync_call(self, request):
        error = self._authenticate(request)
        if error:
            return error
        return self.get_response(request)

    async def __acall__(self, request):
        error = self._authenticate(request)
        if error:
            return error
        return await self.get_response(request)

    def _authenticate(self, request):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip() \
            or request.COOKIES.get("axiam_access")
        if not token:
            return JsonResponse({"error": "authentication_failed", "message": "missing credentials"}, status=401)
        try:
            claims = _verifier.verify(token)  # module-level or settings-configured verifier
        except Exception:
            return JsonResponse({"error": "authentication_failed", "message": "invalid or expired token"}, status=401)
        request.axiam_user = _build_user(claims)
        return None
```
Register in `settings.py`: `MIDDLEWARE = [..., "axiam_sdk.django.middleware.AxiamAuthMiddleware"]`
(matches CONTRACT.md §10's literal example). The `verifier` should be resolved from Django settings
(e.g. `AXIAM_JWKS_BASE_URL`, `AXIAM_TENANT_SLUG`) at middleware construction time, not hardcoded —
exact settings-key naming is Claude's Discretion.

### Anti-Patterns to Avoid

- **Constructing `httpx.Client`/`httpx.AsyncClient` eagerly in `__init__` even when the caller only
  ever uses one paradigm:** wastes a connection pool; lazily construct on first sync/async use
  (Pattern 1).
- **Calling `threading.Lock.acquire()` (blocking) from inside an `async def` function:** blocks the
  entire event loop, defeating the purpose of the async path. Keep the two locks and two code paths
  fully separate (Pattern 2).
- **Using `sort_keys=True` unverified for AMQP HMAC canonicalization:** see Pattern 4's critical
  correctness note — this is the top pitfall risk in the phase.
- **Passing a caller-supplied `httpx.Response`/`httpx.HTTPStatusError` directly into `NetworkError`
  without redaction:** mirrors the Phase 17 CR-04 regression — always route through a single
  `sanitize_response()`-style chokepoint before wrapping (D-08).
- **Enabling `PyJWKClient(cache_keys=True)`:** see Pattern 5 Pitfall — no TTL on the per-key LRU
  cache; rely on Tier-1 `cache_jwk_set` alone.
- **Forgetting the FastAPI/Django integrations must be import-safe as optional extras:** if
  `axiam_sdk/__init__.py` unconditionally imports `fastapi` or `django`, a pure-REST/gRPC/AMQP
  consumer's `pip install axiam-sdk` breaks with `ModuleNotFoundError` unless they also install
  FastAPI/Django. Use `axiam_sdk.fastapi` / `axiam_sdk.django` as separate importable submodules
  (never imported from the top-level `__init__.py`), with `fastapi`/`django` as optional
  `[project.optional-dependencies]` extras.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| JWKS fetch/cache/rotation | Custom `requests`-based JWKS poller + manual TTL dict | PyJWT `PyJWKClient` (D-16, locked) | Battle-tested, avoids re-implementing security-sensitive key-rotation logic; user explicitly rejected the hand-rolled alternative in the discuss session |
| Token redaction | Custom `__repr__`/`__str__` wrapper class | Pydantic `SecretStr` (D-07, locked) | `SecretStr` already redacts `repr`/`str`/`model_dump`/`model_dump_json`; a bespoke wrapper would need to reimplement all of Pydantic's serialization integration points and risk missing one (e.g. `model_dump(mode="json")`) |
| HTTP retry/backoff | Custom retry loop wrapping `httpx.Client.send` | `httpx`'s built-in `transport=httpx.HTTPTransport(retries=N)` for connection-level retries, PLUS a thin custom decorator ONLY for status-code-based (429/503) retry-with-jitter since httpx's built-in retries do not cover HTTP-status-triggered retries | httpx's transport-level retry only covers connection errors, not 429/503 status codes — some custom logic is unavoidable here, but keep it minimal (a single `_with_retry()` helper wrapping the request call, not a full retry framework) |
| Constant-time HMAC comparison | `==` or `bytes.__eq__` on digests | `hmac.compare_digest()` | Timing-attack resistant; stdlib-provided, zero reason to hand-roll |
| PyPI Trusted Publishing OIDC flow | Custom API-token secret management | `pypa/gh-action-pypi-publish` GitHub Action with `id-token: write` permission (no `password`/token input needed) | PyPI's own documented Trusted Publishing flow eliminates long-lived API tokens entirely; hand-rolling OIDC token exchange is unnecessary and security-sensitive |
| gRPC codegen | Hand-written Python stub classes matching the `.proto` | `python -m grpc_tools.protoc` (Pattern 3) | Protobuf wire-format correctness is exactly the kind of thing codegen exists to guarantee; a hand-written stub risks silent wire-incompatibility with the server |

**Key insight:** Every "don't hand-roll" item in this phase is either (a) already resolved by a
user-locked decision (JWKS, redaction) or (b) has a stdlib/well-known-library answer that is
strictly safer than a bespoke implementation in a security-sensitive IAM SDK. The one genuinely
novel piece of logic this phase must write correctly from scratch — the AMQP HMAC
canonicalization (Pattern 4) — is exactly the piece that carries the highest byte-for-byte
compatibility risk and needs its own cross-language fixture test.

## Runtime State Inventory

> Not applicable — Phase 19 is a greenfield SDK build (new package tree), not a rename/refactor/
> migration phase. The existing `sdks/python/` scaffold (pyproject.toml, LICENSE, README,
> `axiam_sdk/__init__.py`) is filled in and restructured (src-layout, build backend fix, version
> floor bump) but this is new construction on top of stub files, not a live-system rename. Omitted
> per the trigger condition in the research protocol.

## Common Pitfalls

### Pitfall 1: `grpc_tools.protoc`-generated `_pb2_grpc.py` uses a bare (non-relative) import

**What goes wrong:** `import authorization_pb2 as authorization__pb2` at the top of the generated
`authorization_pb2_grpc.py` fails with `ModuleNotFoundError` once the file is imported as part of a
package (`axiam_sdk.grpc.gen.authorization_pb2_grpc`), because Python 3's absolute-import-by-default
behavior looks for a top-level `authorization_pb2` module, not the sibling one in the same package.
**Why it happens:** `grpc_tools.protoc`'s Python codegen predates a widely-adopted fix for this and
still emits absolute imports by default for the grpc-service file (the `_pb2.py` message file itself
is fine standalone). **How to avoid:** post-process the generated `_pb2_grpc.py` file (sed/regex
replace `import X_pb2 as X__pb2` → `from . import X_pb2 as X__pb2`) as a step in the same
Makefile/script target that invokes `grpc_tools.protoc`, and re-run this fixup as part of the CI
drift-check (regenerate + fixup + `git diff --exit-code`, not just regenerate + diff). **Warning
signs:** `ImportError`/`ModuleNotFoundError` the first time any code imports
`axiam_sdk.grpc.gen.authorization_pb2_grpc`, working fine only when run from inside the exact
`gen/` directory (masking the bug in ad-hoc local testing).

### Pitfall 2: AMQP HMAC canonical-JSON key ordering assumption unverified against the real Rust signer

**What goes wrong:** If the Python HMAC verifier canonicalizes keys differently than the server's
`serde_json` struct serialization (e.g. alphabetical `sort_keys=True` vs. struct-declaration-order),
every single AMQP message will fail HMAC verification and get silently nacked-without-requeue,
appearing as "the AMQP consumer receives nothing" or "100% security-event log noise" in testing —
a correctness bug that looks like a connectivity bug. **Why it happens:** `serde_json`'s ordering
behavior differs for typed structs (declaration order) vs. generic maps (implementation-defined,
often insertion-order via `preserve_order` feature or alphabetical via `BTreeMap`) — the Go
reference's own comment describing this as "BTreeMap-backed" may itself be imprecise for the
concrete `AuthzRequest`/`AuditEventMessage` structs (see Pattern 4's detailed analysis). **How to
avoid:** Wave 0 must include a fixture-based test: sign a real (or realistic) message via
`crates/axiam-amqp/src/messages.rs::sign_payload` (either by adding a small Rust test-fixture-export
binary/test, or by capturing a real signed message from a running server/existing Rust SDK test),
then verify that exact fixture with the Python `verify_hmac()` implementation. Do not trust either
`sort_keys=True` or insertion-order-preservation without this empirical check. **Warning signs:**
100% HMAC verification failure rate in integration testing with an otherwise-correctly-configured
signing key.

### Pitfall 3: Real login/refresh endpoints require `org_id`/`org_slug`, not just `tenant_id`/`tenant_slug`

**What goes wrong:** CONTRACT.md §5 only mandates `tenant_slug`/`tenant_id` as a required
constructor parameter, but the actual `LoginRequest`/`RefreshRequest` structs in
`crates/axiam-api-rest/src/handlers/auth.rs` also accept/require `org_id`/`org_slug` fields. A
client built strictly to CONTRACT.md's minimum will fail real login/refresh calls against the
actual server. **Why it happens:** CONTRACT.md documents the cross-language minimum; the concrete
v1.0 REST surface has additional required fields the contract doesn't call out (already discovered
and worked around by the Rust and Go reference SDKs). **How to avoid:** add optional
`org_slug=`/`org_id=` constructor parameters to `AxiamClient` (mirroring Go's `WithOrgSlug`/
`WithOrgID`), mutually exclusive, resolved from the access token's `org_id` claim after first
login/refresh if not explicitly supplied (mirrors Go's `resolvedOrgID()` fallback pattern exactly).
**Warning signs:** every real login call against a live server returning 400 despite a
CONTRACT.md-compliant client.

### Pitfall 4: `axiam_refresh` cookie is path-scoped to `/api/v1/auth/refresh`, not `/`

**What goes wrong:** `httpx.Cookies` (built on `http.cookiejar.CookieJar` semantics) respects
`Path` cookie attributes — a cookie scoped to `/api/v1/auth/refresh` will NOT be attached to
requests against other paths (e.g. `/api/v1/authz/check`). If refresh-token-bearing requests are
issued against the wrong path, or if a test asserts the refresh cookie is visible on arbitrary
requests, it will silently fail. **Why it happens:**
`crates/axiam-api-rest/src/middleware/csrf.rs::refresh_cookie` explicitly sets
`.path("/api/v1/auth/refresh")` to minimize the refresh token's exposure surface — this is
intentional server-side hardening, not an oversight. **How to avoid:** ensure the refresh call in
the SDK always POSTs to the exact literal path `/api/v1/auth/refresh` (not a relative/differently-
cased variant) so the jar attaches the cookie; do not assume the refresh cookie is readable/visible
outside that path in tests. **Warning signs:** refresh calls returning 401 (missing refresh cookie)
despite a successful prior login; a test using `httpx.Cookies.get("axiam_refresh")` without
specifying the domain/path finding nothing because the jar's lookup also respects path scoping.

### Pitfall 5: `buf` CLI not available in this development environment

**What goes wrong:** `sdks/buf.gen.yaml` already declares the Python codegen plugins
(`buf.build/protocolbuffers/python` + `buf.build/grpc/python`), but running `buf generate` requires
the `buf` CLI binary, confirmed absent in this environment (`command -v buf` → not found; same gap
Phase 18 documented for Go). **Why it happens:** sandboxed/offline dev environment without the `buf`
binary installed and no straightforward install path available at research time. **How to avoid:**
use `python -m grpc_tools.protoc` directly (Pattern 3) as the LOCAL/dev codegen path, matching
Phase 18's `protoc` + `protoc-gen-go`/`protoc-gen-go-grpc` workaround; document in the CI workflow
whether the CI runner CAN install `buf` (GitHub Actions has network egress, unlike this sandbox) —
if CI can run real `buf generate`, prefer that in CI for consistency with `buf.gen.yaml`'s
declared plugins, falling back to the `grpc_tools.protoc` path only for local/offline development,
OR standardize on `grpc_tools.protoc` everywhere for reproducibility parity with what a contributor
without `buf` installed can run. **Recommendation: standardize on `grpc_tools.protoc` in CI too**
(matching the "commit stubs + drift-check" plan, D-04) since it removes an external-binary
dependency from CI entirely and produces equivalent stub content to what `buf.build/protocolbuffers/python`
+ `buf.build/grpc/python` remote plugins generate — same rationale Phase 18 documented for choosing
`cargo build --features grpc` (Rust) / direct `protoc` (Go) over `buf` in CI. **Warning signs:** CI
job failing with "buf: command not found" if a plan naively assumes `buf generate` works in CI
without first confirming buf's actual availability there.

## Code Examples

### Central error mapper (D-08, single source of truth for HTTP + gRPC)

```python
# Source: pattern mirrors sdks/typescript/src/core/errorMapper.ts +
# sdks/go/errors.go — CONTRACT.md §2's HTTP and gRPC tables, transcribed exactly.
from typing import Optional
import httpx


class AuthError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(f"authentication failed: {message}")
        self.message = message


class AuthzError(Exception):
    def __init__(self, message: str, action: Optional[str] = None, resource_id: Optional[str] = None) -> None:
        super().__init__(f"authorization denied: {message}")
        self.message = message
        self.action = action
        self.resource_id = resource_id


class NetworkError(Exception):
    def __init__(self, message: str, cause: Optional[BaseException] = None) -> None:
        super().__init__(f"network error: {message}")
        self.message = message
        self.__cause__ = cause  # standard Python exception chaining


_SENSITIVE_RESPONSE_HEADERS = {"set-cookie", "authorization", "cookie"}


def _sanitize_response(response: httpx.Response) -> str:
    """Redact sensitive headers BEFORE building any string representation
    that could end up in a NetworkError's cause (D-08, CR-04 carry-forward).
    Never pass the raw httpx.Response into an exception."""
    safe_headers = {
        k: v for k, v in response.headers.items()
        if k.lower() not in _SENSITIVE_RESPONSE_HEADERS
    }
    return f"http status {response.status_code}, headers: {safe_headers}"


def error_from_http_status(status: int, message: str, response: Optional[httpx.Response] = None) -> Exception:
    if status == 401:
        return AuthError(message)
    if status in (403, 409):
        return AuthzError(message)
    # 400, 408, 429, 5xx, other -> NetworkError
    cause_desc = _sanitize_response(response) if response is not None else None
    return NetworkError(message, cause=RuntimeError(cause_desc) if cause_desc else None)


def error_from_grpc_status(code, message: str) -> Exception:
    import grpc
    if code == grpc.StatusCode.UNAUTHENTICATED:
        return AuthError(message)
    if code == grpc.StatusCode.PERMISSION_DENIED:
        return AuthzError(message)
    return NetworkError(message)
```

### `LoginResult` Pydantic v2 model (D-21)

```python
# Source: Pydantic v2 official docs (docs.pydantic.dev/latest/concepts/models/) +
# CONTRACT.md §1/§7 + D-21's locked shape.
from typing import Optional
from pydantic import BaseModel, SecretStr


class LoginResult(BaseModel):
    mfa_required: bool
    mfa_token: Optional[SecretStr] = None   # the server's "challenge_token" (D-21 field naming: Claude's discretion)
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    session_id: Optional[str] = None
    expires_in: Optional[int] = None

    model_config = {"frozen": True}
```
`SecretStr`'s redaction (`repr(LoginResult(...))` → `mfa_token=SecretStr('**********')`,
`.model_dump()` → same masked placeholder unless `.model_dump(mode="python")` +
explicit `.get_secret_value()` call) satisfies D-07 for any token-bearing field on this model.
Note `challenge_token` (server's wire field name, from `MfaRequiredResponse.challenge_token`) maps
to the SDK's `mfa_token` field — the exact optional-field set and naming is Claude's Discretion per
CONTEXT.md, but `challenge_token` → `mfa_token` is a sensible snake_case-preserving rename matching
CONTRACT.md §1's `verify_mfa` method signature expectation (`verify_mfa(mfa_token, code)` per the
phase description).

### `NetworkError` redaction regression test (mirrors TS `errorRedaction.test.ts`, CR-04)

```python
# Source: pattern mirrors sdks/typescript/test/core/errorRedaction.test.ts intent
# (file not directly read this session, but its existence + purpose is
# documented in 19-CONTEXT.md's canonical_refs — CITED via CONTEXT.md, not
# independently verified this session).
import httpx
import pytest


def test_network_error_never_leaks_set_cookie_with_raw_tokens():
    raw_access = "axiam_access=super-secret-access-token-value"
    raw_refresh = "axiam_refresh=super-secret-refresh-token-value"
    response = httpx.Response(
        401,
        headers={"set-cookie": f"{raw_access}; HttpOnly", "content-type": "application/json"},
        request=httpx.Request("POST", "https://example.test/api/v1/auth/refresh"),
    )

    err = error_from_http_status(401, "refresh failed", response=response)

    # Every stringification surface must be checked — repr, str, and any
    # chained __cause__ representation.
    assert "super-secret-access-token-value" not in repr(err)
    assert "super-secret-access-token-value" not in str(err)
    assert "super-secret-access-token-value" not in repr(err.__cause__)


def test_network_error_redaction_is_non_vacuous():
    """Control case: prove the test above isn't vacuously passing because
    NO header content ever appears — assert a NON-sensitive header value
    DOES survive, so we know redaction is selective, not blanket."""
    response = httpx.Response(
        503,
        headers={"x-request-id": "trace-abc-123", "content-type": "application/json"},
        request=httpx.Request("GET", "https://example.test/api/v1/authz/check"),
    )
    err = error_from_http_status(503, "unavailable", response=response)
    assert "trace-abc-123" in repr(err.__cause__)
```

### `verify=False` CI grep gate (SC#3)

```bash
# Source: CONTRACT.md §6 + CF-03; mirrors the Go SDK's reflection-based TLS
# test intent, adapted to Python's simpler grep-gate approach since Python
# has no equivalent "tls.Config field name" obfuscation concern.
grep -rn "verify=False" sdks/python/src sdks/python/examples sdks/python/tests
if [ $? -eq 0 ]; then
  echo "SC#3 VIOLATION: verify=False found in Python SDK source/examples/tests"
  exit 1
fi
echo "SC#3 OK: no verify=False found"
```
Run this as a dedicated CI step (not embedded in pytest) so a failure is immediately attributable
to the TLS-bypass gate, not buried in test output. Extend the grep pattern to also catch
`ssl._create_unverified_context` and `httpx.Client(verify=0)` (falsy-but-not-literal-`False`)
variants if a code-review pass finds any such idiom creeping in — the locked CF-03 requirement is
"no TLS-bypass idiom appears anywhere," not merely the literal string `verify=False`.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| `requests` + `aiohttp` dual-library HTTP clients | `httpx` single library, sync+async | httpx 1.0 (2019) onward, now mature at 0.27+ | One dependency, one API surface, one cookie-jar model for both paradigms — directly enables D-01's unified client |
| Hand-rolled `black` + `isort` + `flake8` toolchain | `ruff` (single Rust-based tool) | ruff's `format` subcommand reached stability ~2023–2024, now the de facto standard | Faster CI, one config surface (`[tool.ruff]` in `pyproject.toml`) instead of three |
| `setup.py`-based packaging | PEP 517/518 `pyproject.toml` + `build`/`twine` | Standardized across the ecosystem since ~2021 | D-03's `setuptools.build_meta` + `python -m build` is the current standard invocation, not a legacy path |
| PyPI API-token-based publish in CI | PyPI Trusted Publishing (OIDC) | GA since April 2023 | D-05's chosen approach; eliminates long-lived secrets in CI entirely |
| `black`-only formatting alongside separate `mypy`/`flake8` | `ruff check` + `ruff format` + `mypy --strict` (two tools) | current (2026) best practice for typed Pydantic-v2 SDKs | Matches D-20's locked toolchain |

**Deprecated/outdated:**
- `setup.py develop`/`python setup.py sdist bdist_wheel`: replaced entirely by `python -m build`
  (PEP 517 frontend) — do not reintroduce direct `setup.py` invocation anywhere in CI or docs.
- Python 3.9: reaches its own EOL window that motivated D-11's floor bump to `>=3.10`; do not target
  3.9 syntax/features anywhere in the new code.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `httpx.Client(cookies=jar)` and `httpx.AsyncClient(cookies=jar)` share the SAME underlying jar object (not a defensive copy) when passed the same `httpx.Cookies` instance, across the pinned 0.27.x patch line | Pattern 1 | If false, sync and async calls on one `AxiamClient` would silently diverge into two separate sessions — login via sync then check_access via async would appear unauthenticated. Must be verified with a unit test asserting `is` identity (or equivalent behavioral test) in Wave 0/first implementation plan, not assumed from general httpx knowledge. |
| A2 | AMQP HMAC canonicalization: Python's `json.dumps(msg, separators=(",", ":"))` (dict insertion-order preserved, NOT `sort_keys=True`) reproduces `serde_json`'s struct-field-declaration-order byte sequence for `AuthzRequest`/`AuditEventMessage` | Pattern 4, Pitfall 2 | HIGHEST RISK in this phase. If wrong, every AMQP message fails HMAC verification — total consumer breakage that looks like a connectivity issue, not a correctness bug. MUST be verified via a real signed-message fixture in Wave 0 before further AMQP module work proceeds. |
| A3 | `PyJWKClient.jwk_set_cache = None` is a valid/supported way to force cache invalidation before a retry, given PyJWT 2.13.0's actual internal attribute naming | Pattern 5 | If the internal attribute name differs or is not publicly settable in the pinned PyJWT version, the "force refetch on unknown kid" retry path would silently no-op (still serving the stale cached JWKS) rather than actually refetching — verify against the installed PyJWT 2.13.x source (`jwt/jwks_client.py`) at implementation time. |
| A4 | The FastAPI/Django integrations should be shipped as optional `[project.optional-dependencies]` extras (`axiam-sdk[fastapi]`, `axiam-sdk[django]`) rather than hard dependencies | Anti-Patterns, Standard Stack | If the planner instead makes fastapi/django hard dependencies, every `pip install axiam-sdk` consumer (including pure REST/gRPC/AMQP users) pays the Django/FastAPI install cost. This is a best-practice recommendation, not explicitly locked in CONTEXT.md — flag for planner confirmation. |
| A5 | `challenge_token` (server wire field) should be renamed to `mfa_token` in the Python `LoginResult` model | Code Examples (LoginResult) | Purely cosmetic/naming risk — if the planner or a cross-SDK consistency check expects the wire field name preserved verbatim, this rename could cause confusion; low impact, easily corrected in review. |

**None of the above blocks planning** — each is flagged with a concrete verification step
(a unit test or source-code check) to perform during the phase's first implementation wave, not a
decision requiring user input like the 15 already-locked CONTEXT.md items.

## Open Questions

1. **Does the CI runner have network egress to install the real `buf` CLI, or should Python
   standardize on `grpc_tools.protoc` in CI as well as locally?**
   - What we know: `buf` is absent from this sandboxed research environment; Phase 18 (Go) hit the
     identical gap and used `protoc` directly in CI too (not just locally).
   - What's unclear: whether the actual GitHub Actions CI runner (separate environment from this
     research sandbox) can successfully install/run `buf` — GitHub Actions typically has full
     internet egress unlike this sandbox, so it MIGHT be able to run real `buf generate` even though
     this research session could not test it.
   - Recommendation: default to `grpc_tools.protoc` in CI for consistency with Phase 18's Go
     precedent and to keep local/CI codegen identical (avoids "works in CI, fails locally" drift);
     the planner can add a follow-up task to try `buf generate` in CI if reproducibility with the
     other four languages' exact `buf.gen.yaml`-driven output becomes a hard requirement later.

2. **Exact optional-field set on `LoginResult` beyond `mfa_required`** (explicitly delegated to
   planner/Claude's Discretion in CONTEXT.md) — this research proposes `mfa_token`, `user_id`,
   `tenant_id`, `session_id`, `expires_in` based on the real `LoginSuccessResponse`/
   `MfaRequiredResponse` wire shapes found in `crates/axiam-api-rest/src/handlers/auth.rs`, but the
   planner should confirm this set against the Go/TS `LoginResult`-equivalent field sets for
   cross-SDK naming consistency (not independently verified against `sdks/go/login.go`'s exact
   struct in this session — only its existence and general shape was referenced via STATE.md).

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `python3` | All SDK code, tests, tooling | Yes | 3.11.15 (this dev environment) | D-18's CI matrix targets 3.10–3.13; this environment's 3.11.15 is within range for local dev/testing |
| `pip` | Package installs, `pip index versions` verification | Yes | (bundled with python3) | — |
| `protoc` | Fallback gRPC codegen path | Yes | present at `/usr/bin/protoc` | `grpc_tools.protoc` bundles its own `protoc` internally, so the system `protoc` is NOT strictly required for the recommended codegen path (Pattern 3) — nice-to-have redundancy only |
| `buf` CLI | `sdks/buf.gen.yaml`'s declared Python plugin pipeline | No — `command -v buf` returns nothing | — | Use `python -m grpc_tools.protoc` directly (Pattern 3, Pitfall 5); document as the standard local+CI codegen path for this phase, matching Phase 18's Go precedent |
| `grpcio-tools` | gRPC codegen | Not yet installed in this environment (`pip show` reports not found) | latest available: 1.81.1 | Install as a dev-dependency in the phase's first implementation plan; no fallback needed, trivially `pip install`-able |
| Live AXIAM server (SurrealDB + RabbitMQ backing) | Integration testing (login, refresh, AMQP consume against a real broker) | Not verified this session (no `just dev-up` run) | — | Use `respx`/`pytest-httpx` for HTTP-level unit tests and a fixture-based HMAC test (Pitfall 2) rather than a live server; planner should decide whether a `just dev-up`-backed integration test tier is in scope for this phase or deferred, consistent with prior SDK phases (16/17/18) which appear to have relied primarily on unit-level mocking based on the file/test patterns observed) |

**Missing dependencies with no fallback:**
- None — every gap identified above has a documented, viable fallback.

**Missing dependencies with fallback:**
- `buf` CLI → `python -m grpc_tools.protoc` (Pattern 3).
- `grpcio-tools` (not yet installed) → trivial `pip install`, no blocking concern.
- Live AXIAM server for integration testing → mock-based unit testing (`respx` + HMAC fixture test).

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `pytest` + `pytest-asyncio` (latest: pytest-asyncio 1.4.0) [VERIFIED: pip index] |
| Config file | none yet — Wave 0 creates `pyproject.toml`'s `[tool.pytest.ini_options]` with `asyncio_mode = "auto"` (or per-test `@pytest.mark.asyncio` markers) |
| Quick run command | `pytest sdks/python/tests -x -q` |
| Full suite command | `pytest sdks/python/tests -v --tb=short` (add `-k "not integration"` if/when a live-server integration tier is introduced later) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PY-01 (SC#1) | `client.login()` and `await client.async_login()` both return typed `LoginResult` with `mfa_required` | unit (mocked httpx transport via `respx`) | `pytest sdks/python/tests/test_client_login.py -x` | ❌ Wave 0 |
| PY-01 (SC#2) | 5 concurrent asyncio tasks on expired token ⇒ exactly 1 refresh | unit (pytest-asyncio, `asyncio.gather`) | `pytest sdks/python/tests/test_single_flight.py -x` | ❌ Wave 0 |
| PY-01 (SC#3) | `verify=False` never appears in source/examples | static (grep gate, not pytest) | `grep -rn "verify=False" sdks/python/src sdks/python/examples sdks/python/tests; test $? -ne 0` | ❌ Wave 0 (CI step) |
| PY-01 (SC#4) | FastAPI dependency + Django middleware both runnable | integration (example scripts + dedicated unit tests per framework) | `pytest sdks/python/tests/test_fastapi_dependency.py sdks/python/tests/test_django_middleware.py -x` | ❌ Wave 0 |
| PY-01 (SC#5) | `python -m build && twine check dist/*` succeeds | build/packaging check (not pytest) | `cd sdks/python && python -m build && twine check dist/*` | ❌ Wave 0 (CI step) |
| D-08 (redaction) | `NetworkError` never leaks `Set-Cookie`/token values | unit (regression, non-vacuous control case) | `pytest sdks/python/tests/test_error_redaction.py -x` | ❌ Wave 0 |
| §8 (AMQP HMAC) | HMAC verify-before-handler matches server byte-for-byte | unit (fixture-based, HIGHEST PRIORITY per Pitfall 2) | `pytest sdks/python/tests/test_amqp_hmac.py -x` | ❌ Wave 0 — **must include a real cross-language fixture, not synthetic-only test data** |
| D-16 (JWKS) | EdDSA-only alg allowlist, rotation on unknown kid | unit (mocked JWKS endpoint) | `pytest sdks/python/tests/test_jwks.py -x` | ❌ Wave 0 |
| D-04 (gRPC stubs) | Committed stubs match regenerated output | CI drift-check (not pytest) | `python -m grpc_tools.protoc ... && git diff --exit-code sdks/python/src/axiam_sdk/grpc/gen` | ❌ Wave 0 (CI step) |
| D-20 (typing/lint) | `mypy --strict` and `ruff check`/`ruff format --check` pass | static analysis | `mypy --strict sdks/python/src && ruff check sdks/python && ruff format --check sdks/python` | ❌ Wave 0 (CI step) |

### Sampling Rate
- **Per task commit:** `pytest sdks/python/tests -x -q` (fast subset relevant to the task).
- **Per wave merge:** full suite + `mypy --strict` + `ruff` + `verify=False` grep gate + gRPC drift-check.
- **Phase gate:** Full suite green, `python -m build && twine check dist/*` passing, before `/gsd-verify-work`.

### Wave 0 Gaps
- [ ] `sdks/python/pyproject.toml` — fix build-backend (D-03), `requires-python` (D-11), add
      `[tool.pytest.ini_options]`, `[tool.mypy]`, `[tool.ruff]`, `[project.optional-dependencies]`
      (`fastapi`, `django`, `dev`), `[tool.setuptools.package-data]` for committed gRPC stubs (D-04).
- [ ] `sdks/python/src/axiam_sdk/` — src-layout restructure from the flat scaffold (D-14).
- [ ] `sdks/python/src/axiam_sdk/py.typed` — empty PEP 561 marker file.
- [ ] `sdks/python/tests/conftest.py` — shared fixtures (mock httpx transport via `respx`, JWKS
      mock server/fixture, fake signing key for HMAC tests).
- [ ] `sdks/python/tests/test_amqp_hmac.py` — **must include a real cross-language HMAC fixture**
      captured from or cross-verified against `crates/axiam-amqp/src/messages.rs::sign_payload`
      (Pitfall 2 / Assumption A2) before any other AMQP module work proceeds.
- [ ] Framework install: `pip install --group dev grpcio-tools mypy ruff build twine pytest
      pytest-asyncio respx` and `pip install --group fastapi fastapi` / `pip install --group django
      django` as declared in `pyproject.toml` optional-dependencies groups.
- [ ] `.github/workflows/python-sdk.yml` (or equivalent, matching repo convention) — matrix
      3.10–3.13, `pytest`, `verify=False` grep gate, `mypy --strict`, `ruff`, gRPC drift-check,
      `python -m build`/`twine check`, tag-triggered PyPI Trusted Publishing job.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | PyJWT `PyJWKClient` EdDSA verification (local, resource-server side); server remains authoritative for login/refresh/MFA (client-side SDK does not implement authentication logic itself, only consumes it) |
| V3 Session Management | yes | `httpx.Cookies` jar honoring `httpOnly`/`Secure`/`SameSite=Strict`/path-scoped server-set cookies (Pitfall 4); single-flight refresh guard (§9) prevents thundering-herd refresh; no client-side session storage beyond the in-memory cookie jar |
| V4 Access Control | yes | `check_access`/`batch_check` (REST) and `CheckAccess`/`BatchCheckAccess` (gRPC) are pure pass-through to the server's `AuthorizationEngine` — the SDK enforces nothing itself beyond surfacing `AuthzError` on 403/`PERMISSION_DENIED` |
| V5 Input Validation | yes | Pydantic v2 models (`LoginResult`, `User`, authz result models) validate all inbound response shapes; `SecretStr` prevents accidental token exposure through validated model output |
| V6 Cryptography | yes | HMAC-SHA256 (`hmac.compare_digest`, never hand-rolled comparison) for AMQP message verification (§8); EdDSA/Ed25519 JWT verification via PyJWT (never hand-rolled signature checking); TLS 1.3 enforced project-wide (CLAUDE.md), `verify=True` hardcoded in httpx clients (§6, SC#3) |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Token leakage via exception `repr`/logs | Information Disclosure | `SecretStr` (D-07) + redact-before-wrap `NetworkError` construction (D-08); non-vacuous regression test (Code Examples) |
| Thundering-herd refresh (many concurrent 401s triggering N refresh calls, potential DoS on the refresh endpoint or refresh-token replay-window issues) | Denial of Service / Elevation of Privilege (if refresh token reuse detection misfires) | Single-flight guard (§9, Pattern 2) — exactly 1 in-flight refresh |
| AMQP message tampering/replay (unsigned or forged messages) | Tampering / Spoofing | HMAC-SHA256 verify-before-handler, constant-time compare, nack-without-requeue + security log on failure (§8, Pattern 4) — handler NEVER sees an unverified message |
| Cross-tenant token replay against a resource server (org-wide JWKS means a signature-valid token could belong to a different tenant) | Spoofing / Elevation of Privilege | FastAPI dependency / Django middleware MUST check `claims["tenant_id"] == configured_tenant` BEFORE trusting the token further (mirrors Go middleware's CR-03-derived check, Patterns 6/7) — this is a MUST-carry-forward control, not optional |
| Algorithm confusion attack (attacker-supplied `alg: none` or `alg: HS256` using the public key as an HMAC secret) | Spoofing | Explicit EdDSA-only allowlist checked BEFORE any keyset lookup (Pattern 5) — never call `jwt.decode(token, key, algorithms=None)` or infer `alg` from the token's own header |
| TLS downgrade / certificate bypass | Tampering / Spoofing | `verify=True` hardcoded, CI grep gate (SC#3); only escape hatch is an explicit custom-CA parameter, never a boolean bypass |

## Sources

### Primary (HIGH confidence)
- `sdks/CONTRACT.md` §1–§10 — normative cross-language contract, read in full this session.
- `sdks/go/*.go`, `sdks/go/internal/*/*.go`, `sdks/go/amqp/*.go`, `sdks/go/grpc/*.go`,
  `sdks/go/middleware/*.go` — Phase 18 freshest non-browser reference, read in full for client.go,
  errors.go, refreshguard/guard.go, jwks/verifier.go, amqp/consumer.go, amqp/hmac.go,
  grpc/interceptor.go, middleware/nethttp.go.
- `sdks/typescript/src/core/errorMapper.ts`, `sdks/typescript/src/core/sensitive.ts` — read in full.
- `sdks/rust/src/token/jwks.rs` — read in full (proactive-refresh timing constants).
- `crates/axiam-amqp/src/messages.rs` — read in full (canonical HMAC sign/verify reference).
- `crates/axiam-api-rest/src/handlers/auth.rs`, `crates/axiam-api-rest/src/server.rs`,
  `crates/axiam-api-rest/src/middleware/csrf.rs` — read for exact endpoint paths, cookie names,
  cookie path-scoping, and request/response field shapes.
- `proto/axiam/v1/authorization.proto` — read in full.
- `sdks/buf.gen.yaml` — read in full (Python plugin declarations).
- `.planning/phases/19-python-sdk/19-CONTEXT.md`, `19-DISCUSSION-LOG.md` — read in full (15 locked
  decisions + rationale).
- `.planning/REQUIREMENTS.md` (PY-01 section), `.planning/STATE.md` (project history/decisions),
  `.planning/config.json` (nyquist_validation confirmed enabled) — read.
- `sdks/python/pyproject.toml`, `sdks/python/axiam_sdk/__init__.py` — existing scaffold, read in
  full.
- `pip index versions <pkg>` — direct PyPI registry queries [VERIFIED] for httpx, grpcio,
  grpcio-tools, aio-pika, pydantic, PyJWT, fastapi, django, pytest-asyncio, mypy, ruff, build,
  twine, setuptools (run 2026-07-01).
- `command -v buf`, `command -v protoc`, `python3 --version` — direct environment probes.

### Secondary (MEDIUM confidence)
- PyJWT official docs (pyjwt.readthedocs.io) — `PyJWKClient` two-tier cache, `lifespan` parameter,
  `cache_keys` LRU-no-TTL behavior [CITED].
- grpc.aio official API docs (grpc.github.io/grpc/python/grpc_asyncio.html) —
  `UnaryUnaryClientInterceptor` async interceptor shape [CITED].
- aio-pika official docs (docs.aio-pika.com) — `QueueIterator`/`message.process()`/reject-requeue
  pattern [CITED].
- FastAPI official docs pattern (fastapi.tiangolo.com) — `Depends`, class-based dependencies,
  401-vs-403 discussion [CITED].
- Django official docs (docs.djangoproject.com/en/5.2/topics/http/middleware.html) —
  `sync_capable`/`async_capable`/`markcoroutinefunction` pattern [CITED].
- PyJWT GitHub issue #1051 (`cache_keys=True` LRU-no-expiration finding) [CITED:
  github.com/jpadilla/pyjwt/issues/1051].
- `gsd-tools query package-legitimacy check` seam output — cross-checked manually against each
  package's known GitHub org (see Package Legitimacy Audit note on false-positive signals).

### Tertiary (LOW confidence / flagged for validation)
- Exact `httpx.Cookies` sharing-vs-copying behavior for the pinned 0.27.x line (Assumption A1) —
  general httpx knowledge, not verified against the exact patch version this session; flagged as a
  Wave 0 verification item.
- `serde_json` struct-field canonical ordering vs. `sort_keys=True`/insertion-order for the AMQP
  HMAC protocol (Assumption A2) — the single highest-risk claim in this research; explicitly NOT
  presented as verified, flagged for a mandatory Wave 0 fixture-based test.
- `PyJWKClient.jwk_set_cache` internal attribute settability for forced cache invalidation
  (Assumption A3) — inferred from general PyJWT familiarity, not confirmed against the exact
  installed 2.13.0 source in this session.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — every package version independently verified via `pip index versions`
  against the live PyPI registry this session; all match or exceed PY-01's pinned floors.
- Architecture: HIGH for patterns directly ported from the read-in-full Go/TS/Rust references
  (unified client, single-flight guard, error taxonomy, JWKS, AMQP consumer shape, middleware
  structure); MEDIUM for FastAPI/Django-specific idioms (verified via official docs search, not an
  existing in-repo Python reference to port from, since this is the first Python SDK phase).
- Pitfalls: HIGH for the four pitfalls grounded in direct source reads (gRPC import fixup is a
  widely-documented grpcio-tools limitation; org_id/refresh-cookie-path pitfalls are read directly
  from server source; buf-unavailability is a direct environment probe) — LOW/flagged for the AMQP
  HMAC canonical-ordering claim specifically (Pitfall 2/Assumption A2), which is the one item in
  this research that must NOT be treated as settled without a Wave 0 empirical test.

**Research date:** 2026-07-01
**Valid until:** 30 days (stable ecosystem; PyPI package versions may drift but the architectural
patterns and locked decisions are stable for the phase's execution window)
