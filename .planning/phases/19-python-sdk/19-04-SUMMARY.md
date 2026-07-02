---
phase: 19-python-sdk
plan: 04
subsystem: sdk
tags: [python, grpc, grpc.aio, tls, interceptor, asyncio]

# Dependency graph
requires:
  - phase: 19-python-sdk
    plan: "01"
    provides: "committed gRPC stubs (authorization_pb2.py/.pyi/_pb2_grpc.py)"
  - phase: 19-python-sdk
    plan: "02"
    provides: "AuthError/AuthzError/NetworkError taxonomy + error_from_grpc_status; RefreshGuard.cached_access_token() non-blocking accessor"
provides:
  - "grpc/_interceptor.py: SyncAuthInterceptor (grpcio) + AsyncAuthInterceptor (grpc.aio) injecting Bearer + x-tenant-id metadata from a non-blocking token_fn"
  - "grpc/_tls.py: build_channel_credentials() — strict TLS via grpc.ssl_channel_credentials, no insecure channel path"
  - "grpc/client.py: AuthzGrpcClient (sync) + AsyncAuthzGrpcClient (async) — CheckAccess/BatchCheckAccess with exactly-once UNAUTHENTICATED refresh-and-retry via a caller-supplied refresh_fn closure"
  - "grpc/__init__.py: public re-exports AuthzGrpcClient, AsyncAuthzGrpcClient"
affects: [19-05, 19-06, 19-07]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "grpc.aio interceptor's intercept_unary_unary is async def and awaits continuation; the sync grpcio interceptor calls continuation synchronously — two concrete classes sharing one _AuthMetadataMixin"
    - "refresh_fn is a caller-supplied closure (sync Callable[[], None] / async Callable[[], Awaitable[None]]) so grpc/client.py never imports _client.py — same decoupling as sdks/go/grpc/client.go's RefreshFunc"
    - "UNAUTHENTICATED retry-exactly-once: refresh_fn() then one RPC retry, no loop (§9.3); a second failure maps via the shared error_from_grpc_status"

key-files:
  created:
    - sdks/python/src/axiam_sdk/grpc/_interceptor.py
    - sdks/python/src/axiam_sdk/grpc/_tls.py
    - sdks/python/src/axiam_sdk/grpc/client.py
    - sdks/python/tests/test_grpc_interceptor.py
    - sdks/python/tests/test_grpc_client.py
  modified:
    - sdks/python/src/axiam_sdk/grpc/__init__.py
    - sdks/python/pyproject.toml

key-decisions:
  - "Added a [[tool.mypy.overrides]] exemption for axiam_sdk.grpc.gen.* — grpc_tools.protoc's generated authorization_pb2_grpc.py has no matching .pyi stub coverage (only the message types in authorization_pb2.pyi are typed), and this plan is the first to import the gRPC stub from a --strict-checked module; the generated code is out of every plan's file-modification scope (D-04, 'DO NOT EDIT!')"
  - "AuthzGrpcClient/AsyncAuthzGrpcClient accept a refresh_fn constructor closure instead of importing axiam_sdk._client — avoids the import cycle noted in 19-CONTEXT.md, mirrors sdks/go/grpc/client.go's RefreshFunc decoupling"
  - "Class names are SyncAuthInterceptor/AsyncAuthInterceptor (not UnaryXInterceptor) so no rename is needed if streaming RPCs are added post-v1.0-beta"

patterns-established:
  - "In-process self-signed-TLS grpc.server (grpc.ssl_server_credentials) is the test harness for gRPC transport plans — no external test infra needed, proves strict TLS end-to-end including the client's custom_ca escape hatch"

requirements-completed: [PY-01]

coverage:
  - id: D1
    description: "Sync (grpcio) and async (grpc.aio) auth/tenant metadata interceptors inject Bearer + x-tenant-id from a non-blocking token_fn; async variant correctly awaits its continuation"
    requirement: "PY-01"
    verification:
      - kind: unit
        ref: "sdks/python/tests/test_grpc_interceptor.py (9 tests)"
        status: pass
      - kind: other
        ref: "grep -c 'class SyncAuthInterceptor'=1, 'class AsyncAuthInterceptor'=1, 'grpc.aio.UnaryUnaryClientInterceptor'=1, 'acquire\\|Lock'=0 in _interceptor.py"
        status: pass
    human_judgment: false
  - id: D2
    description: "Sync + async AuthzGrpcClient perform CheckAccess/BatchCheckAccess over strict TLS, retry exactly once on UNAUTHENTICATED via a decoupled refresh closure, and map errors through the central taxonomy"
    requirement: "PY-01"
    verification:
      - kind: unit
        ref: "sdks/python/tests/test_grpc_client.py (9 tests, in-process self-signed-TLS server)"
        status: pass
      - kind: other
        ref: "grep -rEn 'insecure_channel|insecure\\(' sdks/python/src/axiam_sdk/grpc returns empty; mypy --strict sdks/python/src/axiam_sdk/grpc passes"
        status: pass
    human_judgment: false

# Metrics
duration: 9min
completed: 2026-07-01
status: complete
---

# Phase 19 Plan 04: gRPC Transport — Sync + Async Clients Summary

**Dual sync (grpcio) + async (grpc.aio) AuthzGrpcClient for CheckAccess/BatchCheckAccess, a non-blocking auth/tenant metadata interceptor, strict-TLS channel construction, and exactly-once UNAUTHENTICATED refresh-and-retry via a decoupled refresh closure.**

## Performance

- **Duration:** ~9 min
- **Started:** 2026-07-01T20:38:16Z
- **Completed:** 2026-07-01T20:46:38Z
- **Tasks:** 2
- **Files modified:** 7 (across 2 commits)

## Accomplishments

- `grpc/_interceptor.py`: `_AuthMetadataMixin._build_metadata()` shared by two concrete interceptor classes — `SyncAuthInterceptor(grpc.UnaryUnaryClientInterceptor)` with a synchronous `intercept_unary_unary`, and `AsyncAuthInterceptor(grpc.aio.UnaryUnaryClientInterceptor)` with `async def intercept_unary_unary` that awaits its continuation. The metadata-building `token_fn` is invoked as a plain synchronous callable — proven non-blocking by a test that holds a `threading.Lock` and confirms `_build_metadata` still returns immediately.
- `grpc/_tls.py`: `build_channel_credentials(custom_ca=None)` builds strict TLS credentials via `grpc.ssl_channel_credentials` — root certs from a caller-supplied CA PEM path when provided, else system trust roots. No insecure/plaintext channel construction anywhere in the `grpc/` package.
- `grpc/client.py`: `AuthzGrpcClient` (sync) and `AsyncAuthzGrpcClient` (async) both build a secure channel + the matching interceptor + the committed `AuthorizationServiceStub`, exposing `check_access`/`batch_check`. On `UNAUTHENTICATED`, each invokes the caller-supplied `refresh_fn` exactly once then retries the RPC exactly once (§9.3, no loop); `PERMISSION_DENIED` and all other terminal statuses route through the shared `error_from_grpc_status` mapper (no duplicate status table). `refresh_fn` is a constructor-supplied closure (not an import of `_client.py`), preserving the no-import-cycle invariant called out in 19-CONTEXT.md.
- Proved end-to-end against an in-process, self-signed-TLS `AuthorizationService` test server (`grpc.server` + `grpc.ssl_server_credentials`) — 9 tests covering sync/async allow/deny/batch results, exactly-one-refresh-and-retry on `UNAUTHENTICATED`, and `PERMISSION_DENIED → AuthzError` mapping, plus verifying the interceptor's injected metadata actually reaches the server.

## Task Commits

Each task was committed atomically:

1. **Task 1: Sync + async auth/tenant interceptors (non-blocking token func)** - `c1955e1` (feat)
2. **Task 2: Strict-TLS channel + sync/async AuthzGrpcClient with UNAUTHENTICATED retry-once** - `a322faa` (feat)

**Plan metadata:** committed alongside this SUMMARY (see final commit below)

## Files Created/Modified

- `sdks/python/src/axiam_sdk/grpc/_interceptor.py` - `_AuthMetadataMixin`, `SyncAuthInterceptor`, `AsyncAuthInterceptor`
- `sdks/python/src/axiam_sdk/grpc/_tls.py` - `build_channel_credentials(custom_ca=None)`
- `sdks/python/src/axiam_sdk/grpc/client.py` - `AuthzGrpcClient`, `AsyncAuthzGrpcClient`, `SyncRefreshFn`/`AsyncRefreshFn` type aliases
- `sdks/python/src/axiam_sdk/grpc/__init__.py` - re-exports `AuthzGrpcClient`, `AsyncAuthzGrpcClient` (was an empty placeholder from 19-01)
- `sdks/python/pyproject.toml` - added a `[[tool.mypy.overrides]]` exemption for `axiam_sdk.grpc.gen.*`
- `sdks/python/tests/test_grpc_interceptor.py` - 9 tests: metadata building, token_fn call-count/non-blocking invariant, sync-vs-async continuation dispatch
- `sdks/python/tests/test_grpc_client.py` - 9 tests: in-process self-signed-TLS test server, sync+async CheckAccess/BatchCheckAccess, exactly-once refresh+retry, PERMISSION_DENIED mapping

## Decisions Made

- Added a `[[tool.mypy.overrides]]` exemption for `axiam_sdk.grpc.gen.*` — `grpc_tools.protoc`'s generated `authorization_pb2_grpc.py` has no matching `.pyi` stub coverage (only the message types in `authorization_pb2.pyi` are typed via `--pyi_out`), and this plan is the first to import the gRPC service stub from a `--strict`-checked module (19-01/19-02 never touched it). The generated code carries a "DO NOT EDIT!" header and is out of every plan's `files_modified` scope, so exempting it from strict checking (rather than hand-annotating generated code) is the correct boundary.
- `AuthzGrpcClient`/`AsyncAuthzGrpcClient` accept `refresh_fn` as a constructor-supplied closure (`Callable[[], None]` sync / `Callable[[], Awaitable[None]]` async) rather than importing `axiam_sdk._client` — mirrors `sdks/go/grpc/client.go`'s `RefreshFunc` decoupling and satisfies the plan's explicit "MUST NOT import `_client.py` from `grpc/client.py`" prohibition.
- Interceptor classes named generically (`SyncAuthInterceptor`/`AsyncAuthInterceptor`, not `UnaryXInterceptor`) per the plan's guidance, so no rename is needed if streaming RPCs are added post-v1.0-beta.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `mypy --strict` on `grpc/` transitively failed against pre-existing generated-code gaps in `gen/`**
- **Found during:** Task 2, running the plan's `<verify>`-block `mypy --strict sdks/python/src/axiam_sdk/grpc` command after `client.py` first imported `authorization_pb2_grpc`.
- **Issue:** `authorization_pb2_grpc.py` (generated by `grpc_tools.protoc` in 19-01, "DO NOT EDIT!") has no typed counterpart to its message-stub `.pyi` file — its service-stub `__init__`/servicer methods are unannotated, and `grpc.experimental` isn't recognized by the installed `types-grpcio` stub version. This surfaced only now because 19-01/19-02 never imported the gRPC stub from any `--strict`-checked module; `client.py` is the first to do so.
- **Fix:** Added a `[[tool.mypy.overrides]]` block in `pyproject.toml` exempting `axiam_sdk.grpc.gen.*` (`ignore_errors = true`) — scoped precisely to the generated package, not a blanket relaxation. `grpc/_interceptor.py`, `grpc/_tls.py`, and `grpc/client.py` themselves remain fully `--strict`-clean with zero exemptions.
- **Files modified:** `sdks/python/pyproject.toml`
- **Verification:** `mypy --strict sdks/python/src/axiam_sdk/grpc` and `mypy --strict sdks/python/src` both report "Success: no issues found" (17 source files); full test suite (92 tests) still passes.
- **Committed in:** `a322faa` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 3 blocking, pre-existing generated-code typing gap).
**Impact on plan:** The fix unblocks the plan's own literal `mypy --strict` acceptance criterion without touching any generated file (which is explicitly out of scope per D-04's "DO NOT EDIT!" convention) and without relaxing strictness on any hand-authored module. No scope creep.

## Issues Encountered

None beyond the auto-fixed deviation above — no unresolved issues.

## User Setup Required

None — no external service configuration required. (The in-process TLS test server generates its own throwaway self-signed certificate via the already-installed `cryptography` package at test time; nothing is persisted or requires manual setup.)

## Next Phase Readiness

- The gRPC transport is complete and independently testable: `AuthzGrpcClient`/`AsyncAuthzGrpcClient` are ready to be wired into the unified `AxiamClient` (19-05/19-06) via the same `refresh_fn` closure pattern the REST transport (19-03) already established with `RefreshGuard.refresh_if_needed_sync`/`_async`.
- `token_fn` for the interceptor should be `RefreshGuard.cached_access_token()` (from 19-02) when wired into the unified client — this plan's tests exercise the interceptor/client with arbitrary token functions to keep `grpc/` independently testable, but the real integration point is already documented in the module docstrings.
- No blockers. The `[[tool.mypy.overrides]]` addition is a durable, narrowly-scoped fix that benefits every future plan importing the gRPC stubs (19-05 examples, 19-07 CI).

## Self-Check: PASSED

All claimed files verified present on disk (8/8); all claimed commit hashes (`c1955e1`, `a322faa`) verified present in `git log --oneline --all`.

---
*Phase: 19-python-sdk*
*Completed: 2026-07-01*
