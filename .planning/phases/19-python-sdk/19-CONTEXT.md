# Phase 19: Python SDK - Context

**Gathered:** 2026-07-01
**Updated:** 2026-07-01 (interactive discuss session — decisions confirmed + extended)
**Status:** Ready for planning

> **Discussion note:** An earlier session auto-adopted the *recommended* option for
> the four Python-specific gray areas because the interactive question channel
> closed mid-session (transport error). This session **re-opened the discussion
> and the user interactively confirmed all four** (sync/async architecture,
> packaging backend, FastAPI helper, Django helper) and locked **eleven
> additional decisions** (Python version floor, gRPC async coverage, examples
> breadth, package layout, logging, JWKS, HTTP resilience, CI matrix, client
> lifecycle, type/lint toolchain, `LoginResult` shape). Every choice is grounded
> in the Rust (Phase 16), TypeScript (Phase 17), and Go (Phase 18) reference SDKs
> and the binding `sdks/CONTRACT.md`. The four originally-flagged decisions are no
> longer `[recommended — revisable]` — they are **user-locked**. Remaining
> low-level items (module names, AMQP prefetch/QoS number, backoff constants,
> `__init__` exports, README structure, exact JWKS/cookie endpoint paths) are
> explicitly delegated to research/planner.

<domain>
## Phase Boundary

Phase 19 delivers `sdks/python/` — the publishable PyPI package **`axiam-sdk`** and
the **fourth SDK** (after Rust ref Phase 16, TypeScript Phase 17, Go Phase 18). It
implements the full client capability baseline against the frozen v1.0 APIs in
idiomatic Python, exposing **both sync and async** interfaces from a **single unified
client** in a **src-layout** package (`src/axiam_sdk/`), targeting **Python >=3.10**:

- **REST** (`httpx` 0.27, sync `httpx.Client` + async `httpx.AsyncClient`, `httpx.Cookies`
  jar) — auth flow (`login` → `verify_mfa`), `refresh`, `logout`, `check_access`/`can`,
  `batch_check`.
- **gRPC** (`grpcio` 1.78 — **both** sync stubs + `grpc.aio` async) — `CheckAccess`,
  `BatchCheckAccess`.
- **AMQP** (`aio-pika` 9.6, **async-only**) — event consumer with HMAC-SHA256
  verify-before-handler.
- Local JWKS verification via **PyJWT** (`PyJWKClient`, EdDSA/Ed25519) for proactive
  refresh; a **FastAPI dependency-injection helper** and a **Django middleware class** as
  first-class framework integrations.

It conforms to `sdks/CONTRACT.md` §1–§10 in full and **inherits the Rust/TS/Go reference
patterns** wherever a Python analog exists. Python is a **non-browser** SDK, so §3 CSRF =
capture `X-CSRF-Token` from the response header (not the browser cookie double-submit the TS
browser persona uses). The novel work this phase resolves is everything Python's
dual-interface (sync+async) surface and packaging toolchain force that the Rust/Go/TS
references never faced.

**In scope (PY-01):** the `sdks/python/` package + all three transports + FastAPI dependency
+ Django middleware + full per-capability examples + PyPI publish CI, with `asyncio.Lock`
(async) + `threading.Lock` (sync) single-flight refresh, HMAC verify, and the no-TLS-bypass
gate proven by test.

**Out of scope:** any change to the AXIAM server (v1.0 APIs are frozen; the SDK is a pure
external client and MUST NOT depend on server crates); the other remaining language SDKs
(Phases 20–22); the shared foundation already delivered in Phase 15 (`buf.gen.yaml`,
`CONTRACT.md`, FND-04 endpoint, scaffold).

</domain>

<decisions>
## Implementation Decisions

> **Note:** The SDK's *behavioral* surface is already locked by the binding
> `sdks/CONTRACT.md` §1–§10 and by `PY-01` (pinned deps: httpx 0.27 sync+async, grpcio 1.78,
> aio-pika 9.6, Pydantic v2, PyJWT for JWKS; `asyncio.Lock` single-flight; `httpx.Cookies`
> jar; `verify=True` hardcoded). The decisions below are the **HOW choices** — all
> **user-confirmed** in the 2026-07-01 discuss session. They do not restate the contract —
> downstream agents MUST read CONTRACT.md.

### Sync/Async Architecture
- **D-01 [LOCKED — user-confirmed]:** **Single `AxiamClient` exposing sync methods + `async_*`
  variants.** `client.login(email, password)` (sync via `httpx.Client`) and
  `await client.async_login(email, password)` (async via `httpx.AsyncClient`) both exist on the
  **same client object** and both return a typed `LoginResult` — chosen to satisfy **SC#1
  verbatim** (its literal test is `client.login` *and* `client.async_login`). The client holds
  one shared session (cookie jar, tenant context, JWKS cache) and lazily constructs the sync/async
  httpx clients. `threading.Lock` guards sync single-flight; **`asyncio.Lock` guards async
  single-flight** (SC#2 explicitly tests `asyncio.Lock` via pytest-asyncio). *Alternative
  considered and rejected:* the httpx-style two-class split (`AxiamClient` sync /
  `AsyncAxiamClient` async) — more idiomatic but breaks SC#1's literal `client.async_login`; kept
  in Deferred behind an SC#1 wording reconciliation.
- **D-02:** **AMQP is async-only via `aio-pika`** (locked by PY-01 acceptance "aio-pika 9.6").
  Closure-handler consumer, SDK owns the ack/nack loop, **HMAC-SHA256 verify-before-handler**
  (§8); handler returns `None` → ack, raises retryable error → nack WITH requeue, raises the
  exported drop sentinel → nack WITHOUT requeue, HMAC-fail → nack WITHOUT requeue + security log
  (handler never sees it). Direct Go D-07 analog.
- **D-12 [LOCKED — user-confirmed]:** **gRPC ships BOTH sync (`grpcio`) and async (`grpc.aio`)
  clients** for `CheckAccess`/`BatchCheckAccess` — one codegen emits both, mirroring the unified
  client's sync + `async_*` surface so the async authz transport is first-class (not thread-pool
  bridged). Sync-safe auth/tenant interceptor on both.
- **D-19 [LOCKED — user-confirmed]:** **Client lifecycle via context managers.** Support
  `with AxiamClient(...) as c:` (sync `__enter__`/`__exit__`) AND
  `async with AxiamClient(...) as c:` (async `__aenter__`/`__aexit__`), plus explicit
  `.close()`/`.aclose()`. These deterministically tear down the httpx clients, the gRPC channel,
  and the aio-pika connection — leak-safe and idiomatic.

### Packaging, Layout & Distribution
- **D-03 [LOCKED — user-confirmed]:** **`setuptools.build_meta` build backend.** Replaces the
  scaffold's invalid `setuptools.backends.legacy:build`; standard PEP 517, consistent with the
  scaffold's declared `setuptools>=68` toolchain and existing PEP 621 metadata. `python -m build
  && twine check dist/*` must pass (SC#5). (Hatchling considered; setuptools chosen for minimal
  correct fit.)
- **D-04:** **Commit gRPC stubs + CI drift-check + ship in wheel/sdist.** Commit the buf/protoc
  generated `*_pb2.py` / `*_pb2_grpc.py` (+ `*_pb2.pyi` type stubs) into `sdks/python/`, include
  them in the wheel **and** sdist (package-data), and add a CI job that regenerates with the pinned
  config and runs `git diff --exit-code` to block drift. **Direct Go D-01 analog** — `pip install`
  consumers cannot run buf/protoc, so the stubs MUST be present in the distributed artifact.
  Documented codegen-distribution exception to Phase 15 D-01's generate-on-build model.
- **D-05:** **Tag-triggered PyPI publish with Trusted Publishing (OIDC).** Publish `axiam-sdk`
  on tag `sdks/python/vX.Y.Z` (Phase 15 D-13 tag convention). Prefer PyPI **Trusted Publishing
  (OIDC)** over a stored API token; `python -m build` + `twine check` (and a `--repository testpypi`
  or dry-run) gate on PRs touching `sdks/python/**` (SC#5).
- **D-11 [LOCKED — user-confirmed]:** **`requires-python = ">=3.10"`** (raised from the scaffold's
  now-EOL `>=3.9`). 3.10 is the oldest non-EOL Python; enables `X | Y` union typing and `match`,
  still broad enterprise reach. Update the scaffold's `requires-python` accordingly.
- **D-14 [LOCKED — user-confirmed]:** **src-layout** (`src/axiam_sdk/`). Restructure the scaffold's
  current flat `axiam_sdk/`; src-layout prevents accidental import of the un-built source tree and
  surfaces missing package-data — important because the committed gRPC stubs are shipped as
  package-data (D-04).
- **D-18 [LOCKED — user-confirmed]:** **CI test matrix = Python 3.10/3.11/3.12/3.13 on
  `ubuntu-latest`.** Runs `pytest` (incl. the pytest-asyncio `asyncio.Lock` single-flight test,
  SC#2), the `verify=False` grep gate (SC#3), and the buf drift-check (D-04). Linux-only for cost;
  macOS/Windows not required.
- **D-20 [LOCKED — user-confirmed]:** **Ship PEP 561 `py.typed` marker; enforce `mypy --strict`
  and `ruff` (lint + format) in CI.** Consumers get inline types; strong quality bar fitting a
  Pydantic-v2 typed SDK.

### Token Safety & Models
- **D-06:** **Pydantic v2 typed models** (locked by PY-01). Typed `User`, authz result models, and
  `LoginResult` (shape pinned by D-21).
- **D-21 [LOCKED — user-confirmed]:** **`LoginResult` = a single Pydantic model with
  `mfa_required: bool`** (+ optional `mfa_token` and authenticated identity). Matches SC#1's literal
  "typed `LoginResult` with a `mfa_required` field"; caller checks the flag then calls
  `verify_mfa(mfa_token, code)`. Direct Go CF-04 / TS D-18 analog. *Discriminated-union alternative
  rejected* — SC#1's test targets the flat field.
- **D-07:** **`§7 Sensitive` = Pydantic `SecretStr` for token-bearing fields.** `SecretStr`
  redacts `repr`/`str`/`model_dump` and exposes the raw value only via `.get_secret_value()` —
  it *is* the Python §7 Sensitive type; no bespoke wrapper needed.
- **D-08:** **Exception taxonomy + redact-before-wrap (CR-04 carry-forward).** Three exception
  classes `AuthError` / `AuthzError` / `NetworkError` (§2), discriminated by type, from one central
  status→error mapper (HTTP §2 table + gRPC status codes → one source of truth). **`NetworkError`
  must redact `Set-Cookie`/`Authorization`/`Cookie` from any wrapped `httpx` request/response/error
  before storing it** — never let a raw session/refresh token enter the exception chain, `repr`, or
  logs. Add a regression test analogous to TS `errorRedaction.test.ts` (assert the raw
  `axiam_access`/`axiam_refresh` value never appears in `repr`/`str`/`json`/log of a raised error,
  with a non-vacuous control case).
- **D-16 [LOCKED — user-confirmed]:** **JWKS via PyJWT `PyJWKClient`** — built-in JWKS fetch +
  caching + rotation on unknown `kid`, pointed at the org-wide JWKS endpoint (exact path confirmed
  in research). Least custom crypto code; matches the "PyJWT for JWKS" PY-01 pin. Proactive refresh;
  reactive 401/`UNAUTHENTICATED` remains the fallback (CF-07).

### Runtime Behavior
- **D-15 [LOCKED — user-confirmed]:** **Observability = injectable stdlib `logging.Logger`, OFF by
  default.** The SDK attaches a `NullHandler` so it is silent unless the consuming app configures
  logging; an injectable `logging.Logger` integrates with users' existing config. Redaction
  guarantees no token values are ever logged (ties to D-07/D-08). No `structlog` dependency.
- **D-17 [LOCKED — user-confirmed]:** **Ship sane HTTP defaults, overridable.** Default
  connect/read timeouts + bounded exponential backoff **with jitter** on **idempotent ops only**
  for **429/503** (honoring `Retry-After`); all overridable at client construction. Matches Go
  CF-01/CF-03. aio-pika auto-reconnect with backoff+jitter. Concrete numeric constants =
  research/planner.

### Framework Integrations
- **D-09 [LOCKED — user-confirmed]:** **FastAPI = `Depends(...)` dependency-injection callable,
  dependency-only.** Verifies the session **locally** via PyJWT/`PyJWKClient` against the cached
  JWKS (no per-request server round-trip; §10 short-TTL cache) and **returns** the authenticated
  identity (`user_id`, `tenant_id`, `roles`); raises `HTTPException` 401 on `AuthError` / 403 on
  `AuthzError`. Async-native. **No ASGI-middleware variant** (dependency only). Mirrors Go D-06
  identity-injection intent.
- **D-10 [LOCKED — user-confirmed]:** **Django = middleware class attaching `request.axiam_user`,
  sync-WSGI-primary + ASGI-capable.** Primary target **sync WSGI** for broadest compatibility,
  declaring Django's `sync_capable`/`async_capable` flags so it also works under ASGI. Local JWKS
  verify via PyJWT; standardized 401/403 responses.
- **D-13 [LOCKED — user-confirmed]:** **Full per-capability examples set** (matches Rust/TS/Go
  siblings): runnable example scripts for **login+MFA**, **REST authz**, **gRPC**, **AMQP consumer**,
  **FastAPI dependency**, and **Django middleware**. SC#4 (FastAPI + Django both demonstrated) is a
  subset of this set; every transport is demonstrated runnable.

### Carried Forward from Rust/TS/Go references — apply unless research contradicts
- **CF-01:** **§3 CSRF** — Python = non-browser SDK → capture `X-CSRF-Token` from the response
  header and echo it on mutating requests (like Go, §3.1/3.4).
- **CF-02:** **§4 cookie jar** — SDK owns an `httpx.Cookies` jar (PY-01); server httpOnly cookies
  flow transparently for REST; for gRPC metadata + JWKS the SDK reads the access-token cookie by
  name (confirm exact cookie name + whether login/refresh also return tokens in the JSON body).
- **CF-03:** **§6 TLS** — httpx clients constructed with `verify=True` **hardcoded** (SC#3); the
  only escape hatch is an explicit custom-CA parameter (`verify=<ca-path/ssl.SSLContext>`); a CI
  grep gate confirms `verify=False` appears nowhere in SDK source or examples. Extend the lint to
  any TLS-bypass idiom.
- **CF-04:** **§5 tenant** — `tenant_slug` (or `tenant_id`) **required at client construction** and
  enforced at call time.
- **CF-05:** **§9 single-flight** — `asyncio.Lock` (async, SC#2) + `threading.Lock` (sync), shared
  across REST + gRPC on one session; 5 concurrent tasks on an expired token ⇒ **exactly 1 refresh**.
- **CF-06:** Retry = bounded backoff, **idempotent ops only** (Go CF-01, → D-17); observability =
  **injectable logger, OFF by default** (→ D-15), never emits token values; sane connect/request
  timeouts, aio-pika auto-reconnect w/ backoff+jitter, `base_url` required (Go CF-03).
- **CF-07:** Local JWKS via PyJWT (EdDSA/Ed25519), OIDC discovery + rotation on unknown `kid`,
  proactive refresh; reactive 401/`UNAUTHENTICATED` remains the fallback (Rust D-03/D-11, TS D-11)
  — implemented via `PyJWKClient` (D-16).

### Claude's Discretion (remaining after this session)
- Internal package/module layout **within** `src/axiam_sdk/` (`rest`/`grpc`/`amqp`/`auth`/
  `middleware`/generated stubs) and file names — planner's call within the locked contract and D-14
  src-layout.
- Concrete numeric timeout/backoff/retry values and default AMQP prefetch/QoS (D-02/D-17 set the
  *policy*; the *numbers* are the planner's).
- Exact `async_*` method naming and the precise `LoginResult` optional-field set beyond
  `mfa_required` (D-01/D-21).
- Exact `PyJWKClient` cache-TTL/lifespan and rotation API usage (D-16/CF-07).
- `__init__.py` public export surface and README structure.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Binding contract & phase definition (read FIRST)
- `sdks/CONTRACT.md` §1–§10 — **normative/binding** cross-language behavioral contract. The Python
  SDK *implements* this. Relevant §: §1 method map (`login`/`verify_mfa`/`refresh`/`logout`/
  `check_access`+`can`/`batch_check`), §2 error taxonomy + HTTP/gRPC status mapping (D-08), §3 CSRF
  (**Python = non-browser → capture `X-CSRF-Token` from response header**, CF-01), §4 cookie jar
  (`httpx.Cookies`, CF-02), §5 tenant context (CF-04), §6 TLS/`verify=True` (CF-03; SC#3 gate), §7
  `Sensitive` (D-07 = `SecretStr`), §8 AMQP HMAC protocol (D-02), §9 single-flight refresh
  (`asyncio.Lock`+`threading.Lock`, CF-05), §10 middleware interface (FastAPI/Django, D-09/D-10).
  C# `Grpc.Tools` exception in the closing notes is the precedent class for D-04's committed-stubs
  exception.
- `.planning/ROADMAP.md` — Phase 19 goal + 5 success criteria; the `sdks/<lang>/vX.Y.Z` tag
  convention (Phase 15 D-13) the publish CI follows.
- `.planning/REQUIREMENTS.md` §PY-01 — acceptance criteria + pinned deps (httpx 0.27, grpcio 1.78,
  aio-pika 9.6, Pydantic v2, PyJWT; `asyncio.Lock`; `httpx.Cookies`; `verify=True`; FastAPI + Django
  helpers; PyPI `axiam-sdk`).

### Prior-phase decisions this phase inherits
- `.planning/phases/18-go-sdk/18-CONTEXT.md` — the **freshest analog** (non-browser SDK). D-04
  (typed error + redact-before-wrap → Python D-08), D-07 (closure-handler AMQP → D-02), D-01
  (committed stubs + drift-check → D-04), D-06 (identity-injection middleware → D-09/D-10), CF-01/02/03
  (retry/observability/defaults → CF-06/D-15/D-17), CF-04 (discriminated LoginResult → D-06/D-21).
- `.planning/phases/17-typescript-sdk/17-CONTEXT.md` — sync/async-adjacent reference. D-16/D-17 (typed
  error classes + central status mapper → D-08), D-18 (discriminated login result → D-06/D-21), D-26
  (`Sensitive` multi-surface redaction → D-07), D-11 (local JWKS via jose → PyJWT, CF-07/D-16).
- `.planning/phases/17-typescript-sdk/17-REVIEW.md` §CR-04 + `17-VERIFICATION.md` — the
  **token-leak-via-error** finding and its `sanitizeAxiosError()` fix. **D-08's redact-before-wrap is
  the direct Python carry-forward.** Read CR-04 before implementing `NetworkError`.
- `.planning/phases/16-rust-sdk/16-CONTEXT.md` — first reference (local JWKS + OIDC discovery/rotation,
  shared-session single-flight, closure-handler AMQP, regenerate-and-bundle publish).
- `.planning/phases/15-sdk-foundation/15-CONTEXT.md` — D-01 (generate-on-build; **D-04 here is the
  documented Python exception**), D-02 (buf codegen pipeline), D-05 (FND-04 `/authz/check` + `/batch`),
  D-09/D-10 (binding contract + locked vocabulary), D-11/D-12/D-13 (package identities + monorepo tag
  scheme `sdks/python/vX.Y.Z`).

### SDK domain research (read for rationale)
- `.planning/research/ARCHITECTURE.md` — codegen source-of-truth, monorepo + path-filtered CI.
- `.planning/research/STACK.md` — buf toolchain + plugin set (protoc-gen-python / grpc plugin for Python).
- `.planning/research/PITFALLS.md` — cross-language divergence trap + the **TLS-bypass pitfall**
  (`verify=False` for httpx → SC#3 gate).
- `.planning/research/FEATURES.md` — per-SDK feature matrix.
- `.planning/research/SUMMARY.md` — consolidated research synthesis (TLS-disabled anti-pattern).

### Code the SDK consumes / mirrors (reuse semantics; do NOT depend on server crates)
- `crates/axiam-amqp/src/messages.rs` — **AMQP HMAC reference impl** (§8): canonical-JSON +
  hex-HMAC-SHA256 protocol the Python verify (D-02) must match byte-for-byte (use `hmac` +
  `hmac.compare_digest` for constant-time compare).
- `sdks/typescript/src/core/errorMapper.ts` (`sanitizeAxiosError`) + `core/sensitive.ts`, and the Go
  `sdks/go` error/sensitive packages — the redaction implementations D-07/D-08 mirror in Python.
- `sdks/rust/src/`, `sdks/go/` — reference trees (token/session, grpc interceptor, amqp consumer,
  middleware, sensitive) — structural analogs for the Python modules.
- `proto/axiam/v1/authorization.proto`, `user.proto`, `token.proto` — proto surface the Python stubs
  cover; `CheckAccess`/`BatchCheckAccess` request/response shapes for the gRPC client.
- `crates/axiam-api-grpc/src/services/authorization.rs` — gRPC `check_access`/`batch_check_access`
  semantics the Python gRPC client targets.
- REST `POST /api/v1/authz/check` + `/api/v1/authz/check/batch` (Phase 15 FND-04,
  `crates/axiam-api-rest/src/handlers/authz_check.rs`) — the endpoints `check_access`/`can`/`batch_check`
  call.
- `sdks/buf.gen.yaml` — buf codegen config; add/confirm the Python plugin entry driving D-04's committed
  stubs.
- `sdks/python/{pyproject.toml,README.md,LICENSE,axiam_sdk/__init__.py}` — existing scaffold (package
  `axiam-sdk`, `requires-python >=3.9`, README states CONTRACT.md conformance) — Phase 19 fills it in;
  **the broken build backend (D-03) is fixed, `requires-python` raised to >=3.10 (D-11), and the tree
  moves to src-layout (D-14) here.**
- OIDC JWKS endpoint (exact path to confirm in research) — JWKS source for CF-07/D-16 (`PyJWKClient`).

### Project-wide constraints
- License is **Apache-2.0** repo-wide — `sdks/python/LICENSE` already matches; keep it. See project
  memory `project_license_apache.md`.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `sdks/rust/` (16), `sdks/typescript/` (17), `sdks/go/` (18) — three complete reference
  implementations of the same contract; the Python SDK ports their structure (shared session +
  single-flight guard, gRPC interceptor/metadata, closure-handler AMQP consumer, JWKS cache,
  middleware) into idiomatic sync+async Python rather than reinventing.
- `sdks/typescript/src/core/errorMapper.ts` `sanitizeAxiosError()` + the Go `NetworkError`
  redaction — the exact behavior Python's `NetworkError` mirrors (D-08 / CR-04 carry-forward).
- `crates/axiam-amqp/src/messages.rs` — canonical HMAC sign/verify; the Python consumer reimplements
  *verification* (cannot depend on the crate) but the canonical-JSON + hex-HMAC-SHA256 protocol must
  be byte-identical (§8 / D-02); use `hmac` + `hmac.compare_digest`.
- `sdks/buf.gen.yaml` + `proto/axiam/v1/*.proto` — the codegen pipeline (Phase 15); D-04 commits the
  Python stubs generated from it into `sdks/python/` with a CI drift-check.
- `sdks/python/` scaffold (`pyproject.toml`, LICENSE, README, `axiam_sdk/__init__.py`) — Phase 19
  fills it in; the invalid `setuptools.backends.legacy:build` backend is corrected (D-03), the
  version floor raised to >=3.10 (D-11), and the flat layout moved to src-layout (D-14).

### Established Patterns
- **CONTRACT.md is binding (Phase 15 D-09):** "CONTRACT.md §1–§10 conformance verified" is a required
  acceptance checklist item for this phase.
- **No TLS bypass (§6 / SC#3):** the httpx client hardcodes `verify=True`; a CI
  `grep -rn 'verify=False' sdks/python/` (source + examples) gate MUST return empty.
- **Additive-only / allow-wins / default-deny RBAC** constrains how the SDK surfaces authz `reason`
  semantics (mirrors gRPC).
- **Monorepo tag release** (`sdks/python/vX.Y.Z`, Phase 15 D-13) — the publish CI follows it.
- **Codegen distribution differs by ecosystem:** pip consumers can't run buf/protoc, so D-04 commits
  the stubs + ships them in the wheel/sdist + drift-checks — the documented Python exception.

### Integration Points
- New `src/axiam_sdk/` package tree (REST core + `grpc`/`amqp`/`auth`/`middleware` modules +
  committed generated stubs) + `examples/` scripts (login+MFA, REST, gRPC, AMQP, FastAPI, Django — D-13).
- New per-SDK GitHub Actions workflow under `.github/workflows/` with `paths: sdks/python/**` filter:
  `pytest` (incl. the pytest-asyncio `asyncio.Lock` single-flight test SC#2) across Python 3.10–3.13
  (D-18) + the `verify=False` grep gate + `ruff` + `mypy --strict` (D-20) + the buf drift-check (D-04)
  + `python -m build`/`twine check` + tag-triggered PyPI publish (`sdks/python/vX.Y.Z`, SC#5).
- Committed Python stubs generated from `proto/axiam/v1/` via buf into `sdks/python/`.

</code_context>

<specifics>
## Specific Ideas

- The Python SDK is the **first dual-interface (sync+async) SDK** in the set — decisions favor a
  surface Python developers recognize instantly (`httpx.Client`/`AsyncClient`, `asyncio.Lock`,
  Pydantic v2, `Depends`, Django middleware, `with`/`async with`, `py.typed`) while staying
  byte-faithful to the shared contract.
- Success-criterion proof points to preserve as concrete tests: (#1) `pip install axiam-sdk`
  installs + `client.login()` **and** `await client.async_login()` both return `LoginResult` with
  `mfa_required` (D-01/D-21); (#2) 5 concurrent asyncio tasks on an expired token ⇒ **exactly 1
  refresh** (pytest-asyncio `asyncio.Lock` single-flight test, CF-05); (#3)
  `grep -rn 'verify=False' sdks/python/` → empty (CI gate, CF-03); (#4) FastAPI dependency + Django
  middleware both demonstrated in runnable example scripts (D-09/D-10/D-13); (#5)
  `python -m build && twine check dist/*` passes + tag `sdks/python/vX.Y.Z` publishes (D-05).
- **CR-04 must not recur in Python:** never wrap a raw `httpx` response/error carrying
  `Set-Cookie`/`Authorization` into `NetworkError` without redacting first (D-08). Add a Python
  regression test analogous to TS `errorRedaction.test.ts` (assert the raw `axiam_access`/
  `axiam_refresh` value never appears in `repr`/`str`/`json`/log of a raised error, with a control
  case proving the test is non-vacuous).
- **Quality bar:** `py.typed` shipped, `mypy --strict` + `ruff` gated in CI (D-20), matrix
  3.10–3.13 (D-11/D-18). Context-manager cleanup (`with`/`async with`, D-19) and injectable
  stdlib logging off-by-default (D-15) round out an SDK that "feels" native to Python developers.

</specifics>

<deferred>
## Deferred Ideas

- **SC#1 wording ↔ two-class idiom reconciliation** — SC#1 mandates both `client.login()` and
  `await client.async_login()` on **one** object, which is why D-01 (user-confirmed) chose the
  unified client. The httpx-native **two-class split** (`AxiamClient` sync / `AsyncAxiamClient`
  async, each with plain `.login()`) is arguably more idiomatic; adopting it would require first
  reconciling SC#1's literal wording. **Flag for the planner** — do not silently diverge from SC#1.
  **Do not lose.**
- **Sync AMQP (`pika`)** — considered; rejected because PY-01 pins `aio-pika` (async-only, D-02).
  Revisit only if a sync-only consumer becomes a real user request.
- **REQUIREMENTS PY-01 wording audit** — verify PY-01's package/tag/module identifiers match the
  scaffold (`axiam-sdk`, `sdks/python/vX.Y.Z`) the way GO-01 had a stale module path; reconcile in a
  scoped doc edit if drift is found.
- **Automated cross-language conformance harness** — inherited from Phase 15–18 deferred list; Phase
  19 verifies conformance via its own §1–§10 checklist, not a mechanical suite.
- **macOS/Windows CI matrix** — considered for D-18; deferred (Linux-only) for CI cost. Revisit if a
  platform-specific `grpcio`/`aio-pika` wheel issue is reported.

### Reviewed Todos (not folded)
None — no pending todos matched this phase.

</deferred>

---

*Phase: 19-python-sdk*
*Context gathered: 2026-07-01 · Updated 2026-07-01 (interactive discuss — 15 decisions locked)*
