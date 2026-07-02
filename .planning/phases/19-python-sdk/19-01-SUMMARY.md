---
phase: 19-python-sdk
plan: 01
subsystem: sdk
tags: [python, packaging, setuptools, grpc, protoc, amqp, hmac, pytest]

# Dependency graph
requires:
  - phase: 15-sdk-foundation
    provides: "sdks/buf.gen.yaml codegen config, CONTRACT.md binding cross-language contract, sdks/python scaffold"
  - phase: 18-go-sdk
    provides: "committed-stub + CI drift-check precedent (D-01), redact-before-wrap error taxonomy pattern"
provides:
  - "sdks/python/ restructured to src-layout with a working setuptools.build_meta build (python -m build && twine check dist/* passes)"
  - "Committed, drift-checkable Python gRPC stubs (authorization_pb2.py/.pyi/_pb2_grpc.py) with the mandatory relative-import fixup"
  - "verify_hmac() AMQP HMAC-SHA256 verifier proven byte-for-byte compatible with crates/axiam-amqp/src/messages.rs::sign_payload via a real, server-computed cross-language fixture"
affects: [19-02, 19-03, 19-04, 19-05, 19-06, 19-07]

# Tech tracking
tech-stack:
  added: [setuptools.build_meta, grpcio-tools==1.78.*, pytest, pytest-asyncio, respx]
  patterns:
    - "src-layout Python package with committed gRPC stubs shipped as package-data (D-04, Python's documented codegen-distribution exception alongside Go)"
    - "gen_grpc.sh: python -m grpc_tools.protoc codegen + targeted sed-equivalent import fixup, as the CI drift-check anchor"
    - "AMQP HMAC canonicalization preserves wire/insertion key order (no sort_keys) to match Rust declared-order struct serialization"

key-files:
  created:
    - sdks/python/src/axiam_sdk/__init__.py
    - sdks/python/src/axiam_sdk/py.typed
    - sdks/python/src/axiam_sdk/grpc/gen/authorization_pb2.py
    - sdks/python/src/axiam_sdk/grpc/gen/authorization_pb2.pyi
    - sdks/python/src/axiam_sdk/grpc/gen/authorization_pb2_grpc.py
    - sdks/python/src/axiam_sdk/amqp/_hmac.py
    - sdks/python/scripts/gen_grpc.sh
    - sdks/python/tests/fixtures/amqp_hmac_vectors.json
    - sdks/python/tests/test_amqp_hmac.py
    - sdks/python/tests/conftest.py
  modified:
    - sdks/python/pyproject.toml
    - sdks/python/README.md
    - .gitignore

key-decisions:
  - "AMQP HMAC canonicalization uses dict insertion order (json.dumps without alphabetizing keys), NOT sort_keys=True — proven against a real Rust-signed fixture where field order (tenant_id before subject_id, action before resource_id) is declared-struct order, not alphabetical"
  - "Pinned grpcio-tools==1.78.* (was unpinned) to match the PY-01 grpcio==1.78.* runtime pin — grpc_tools.protoc embeds its own version as a hard import-time floor check in generated _pb2_grpc.py files"
  - "Removed License :: OSI Approved :: Apache Software License classifier — redundant with (and now rejected alongside) the SPDX license = \"Apache-2.0\" expression under current setuptools"

patterns-established:
  - "gen_grpc.sh is the single source of truth for Python gRPC codegen + import fixup, reused as-is by the CI drift-check job in a later plan"
  - "AMQP HMAC fixture vectors are derived via a throwaway Rust #[test] emitting real sign_payload output, cross-verified independently in Python, then the throwaway test is removed — never hand-fabricated"

requirements-completed: [PY-01]

coverage:
  - id: D1
    description: "sdks/python restructured to src-layout with setuptools.build_meta backend; python -m build && twine check dist/* passes"
    requirement: "PY-01"
    verification:
      - kind: other
        ref: "cd sdks/python && python -m build && twine check dist/*"
        status: pass
    human_judgment: false
  - id: D2
    description: "Committed Python gRPC stubs import cleanly (relative-import fixup applied) and regenerate drift-free"
    requirement: "PY-01"
    verification:
      - kind: other
        ref: "bash sdks/python/scripts/gen_grpc.sh && git diff --exit-code sdks/python/src/axiam_sdk/grpc/gen"
        status: pass
      - kind: unit
        ref: "python -c \"from axiam_sdk.grpc.gen import authorization_pb2_grpc\""
        status: pass
    human_judgment: false
  - id: D3
    description: "AMQP HMAC verifier matches the Rust server's canonical protocol byte-for-byte, proven via a real server-signed fixture with a non-vacuous tampered control"
    requirement: "PY-01"
    verification:
      - kind: unit
        ref: "sdks/python/tests/test_amqp_hmac.py (12 tests, parametrized over fixtures/amqp_hmac_vectors.json)"
        status: pass
    human_judgment: false

# Metrics
duration: 12min
completed: 2026-07-01
status: complete
---

# Phase 19 Plan 01: Python SDK Foundation Summary

**Fixed the broken Python SDK scaffold to a buildable src-layout package, committed drift-checkable gRPC stubs, and proved the AMQP HMAC verifier is byte-for-byte compatible with the Rust server via a real cross-language fixture.**

## Performance

- **Duration:** ~12 min
- **Started:** 2026-07-01T19:54:00Z
- **Completed:** 2026-07-01T20:06:02Z
- **Tasks:** 3
- **Files modified:** 18 (across 3 commits)

## Accomplishments
- `sdks/python/` restructured from the broken flat scaffold (invalid `setuptools.backends.legacy:build`, EOL `>=3.9`) to a working src-layout package: `setuptools.build_meta`, `requires-python >=3.10`, PY-01-pinned runtime deps, `fastapi`/`django`/`dev` optional-dependency groups, `py.typed` (PEP 561), and package-data wiring for the committed gRPC stubs. `python -m build && twine check dist/*` passes.
- Generated and committed Python gRPC stubs (`authorization_pb2.py`/`.pyi`/`_pb2_grpc.py`) via `python -m grpc_tools.protoc` (no `buf` CLI locally, same gap Phase 18/Go hit), with the mandatory bare-import-to-relative-import fixup applied by a new `scripts/gen_grpc.sh`. Regenerating produces zero git diff — the drift-check anchor for a later plan's CI job.
- Implemented `verify_hmac()` and proved it matches `crates/axiam-amqp/src/messages.rs::sign_payload` byte-for-byte using a **real, server-computed fixture** (not fabricated): a throwaway Rust `#[test]` emitted genuine HMAC-SHA256 signatures over `AuthzRequest`/`AuditEventMessage` payloads, independently cross-verified in Python, then the throwaway test was removed (confirmed zero diff on `messages.rs`). This resolves the phase's single highest-risk unknown (Assumption A2 / Pitfall 2) before any other AMQP work builds on it.

## Task Commits

Each task was committed atomically:

1. **Task 1: Fix the scaffold — src-layout, build backend, tool config, package-data** - `ca790b3` (fix)
2. **Task 2: Generate + commit gRPC stubs with the import fixup (D-04)** - `8262eba` (feat)
3. **Task 3: AMQP HMAC verifier + real cross-language fixture test (Assumption A2 / Pitfall 2)** - `c83fa6e` (test)

**Plan metadata:** committed alongside this SUMMARY (see final commit below)

## Files Created/Modified
- `sdks/python/pyproject.toml` - Rewritten: `setuptools.build_meta`, `>=3.10`, PY-01 deps, optional-dependency groups, package-data, pytest/mypy/ruff config
- `sdks/python/src/axiam_sdk/__init__.py` - Minimal placeholder public surface, importable with runtime deps only
- `sdks/python/src/axiam_sdk/py.typed` - Empty PEP 561 marker
- `sdks/python/src/axiam_sdk/grpc/gen/authorization_pb2.py`, `.pyi`, `_pb2_grpc.py` - Committed generated gRPC stubs (D-04), import-fixed
- `sdks/python/src/axiam_sdk/amqp/_hmac.py` - `verify_hmac(signing_key, body) -> bool`
- `sdks/python/scripts/gen_grpc.sh` - Deterministic codegen + import-fixup script (drift-check anchor)
- `sdks/python/tests/fixtures/amqp_hmac_vectors.json` - Real cross-language HMAC vectors with documented derivation
- `sdks/python/tests/test_amqp_hmac.py` - Parametrized fixture test + non-raising negative-path tests
- `sdks/python/tests/conftest.py` - Shared fixtures (`signing_key`, `respx_mock`, `jwks_mock` placeholder) for this and later plans
- `sdks/python/README.md` - Fixed `AximClient` → `AxiamClient` typo
- `.gitignore` - Fixed stale `sdks/python/axiam_sdk/gen/` entry (wrong path, would have gitignored D-04-mandated committed stubs); added missing Python artifact rules (`__pycache__`, `*.egg-info`, caches)

## Decisions Made
- AMQP HMAC canonicalization preserves wire/insertion key order (`json.dumps` without alphabetizing) rather than `sort_keys=True` — confirmed correct against the real Rust-signed fixture, where field order is declared-struct order (not alphabetical): e.g. `AuthzRequest` emits `tenant_id` before `subject_id`, and `action` before `resource_id`.
- Pinned `grpcio-tools==1.78.*` in the `dev` extra to match the `grpcio==1.78.*` runtime pin — `grpc_tools.protoc` embeds its own version as a hard `GRPC_GENERATED_VERSION` floor in generated `_pb2_grpc.py` files, so an unpinned/newer `grpcio-tools` would generate stubs that raise `RuntimeError` at import time for every consumer running the pinned `grpcio`.
- Removed the redundant `License :: OSI Approved :: Apache Software License` classifier — current `setuptools` rejects it alongside the SPDX `license = "Apache-2.0"` expression (PEP 639); the SPDX expression alone is sufficient and is what the wheel's `METADATA` now carries.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Build failed due to conflicting license classifier + SPDX expression**
- **Found during:** Task 1 (`python -m build`)
- **Issue:** Current `setuptools` (82.0.1, pulled fresh into the PEP 517 build-isolation venv) raises `InvalidConfigError` when both `license = "Apache-2.0"` (SPDX expression) and `"License :: OSI Approved :: Apache Software License"` (classifier) are present — PEP 639 supersedes the classifier.
- **Fix:** Removed the classifier from `pyproject.toml`; kept the SPDX `license` field.
- **Files modified:** `sdks/python/pyproject.toml`
- **Verification:** `python -m build` succeeds.
- **Committed in:** `ca790b3` (Task 1 commit)

**2. [Rule 3 - Blocking] `twine check` failed on Metadata 2.4 SPDX fields**
- **Found during:** Task 1 (`twine check dist/*`)
- **Issue:** The locally-installed `packaging` library (24.0, bundled transitively with `twine` 6.2.0) predates PEP 639/Metadata 2.4 support and rejected the wheel's `License-Expression`/`License-File` fields as "unrecognized or malformed."
- **Fix:** Upgraded `packaging` to 26.2 (`pip install -U packaging`) — a tooling-environment fix, not a source-code change.
- **Verification:** `twine check dist/*` now reports PASSED for both the wheel and sdist.
- **Committed in:** N/A (local environment tooling upgrade only; no repo files changed)

**3. [Rule 1 - Bug] Stale `.gitignore` entry pointed at the old flat-scaffold gRPC-gen path**
- **Found during:** Task 1 (reviewing `.gitignore` for D-04 conflicts before committing)
- **Issue:** `.gitignore` had `sdks/python/axiam_sdk/gen/` (from the pre-Phase-19 flat scaffold), which no longer matches the new src-layout path (`src/axiam_sdk/grpc/gen/`) — but more critically, per D-04 the Python stubs must be **committed**, not gitignored, mirroring Go's exception. The stale entry documented the wrong (pre-D-04) policy for the wrong path.
- **Fix:** Removed the stale entry; documented Python alongside Go as a committed-stubs exception in the surrounding comment.
- **Files modified:** `.gitignore`
- **Verification:** `git add sdks/python/src/axiam_sdk/grpc/gen/*.py` stages cleanly (no silent gitignore swallow).
- **Committed in:** `ca790b3` (Task 1 commit)

**4. [Rule 2 - Missing Critical] No Python artifact `.gitignore` rules existed at all**
- **Found during:** Task 2 (noticed `__pycache__/` appearing as untracked after running the codegen script)
- **Issue:** The repo's `.gitignore` had zero Python-specific entries (`__pycache__/`, `*.egg-info/`, build/test caches) — every future Python SDK task risked accidentally staging bytecode caches or egg-info.
- **Fix:** Added `__pycache__/`, `*.py[cod]`, `*.egg-info/`, `.eggs/`, `.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/`, `sdks/python/dist/`, `sdks/python/build/`.
- **Files modified:** `.gitignore`
- **Verification:** `git status --short` shows no cache/build artifacts after running `pytest`/`python -m build`.
- **Committed in:** `8262eba` (Task 2 commit)

**5. [Rule 1 - Bug] `grpc_tools.protoc`-generated stub hardcoded an incompatible grpcio version floor**
- **Found during:** Task 2 (inspecting `authorization_pb2_grpc.py` after first codegen run)
- **Issue:** The locally-installed `grpcio-tools` (1.81.1, latest) generated `GRPC_GENERATED_VERSION = '1.81.1'` in `authorization_pb2_grpc.py`, which raises `RuntimeError` at import time unless the installed `grpcio` is `>=1.81.1` — but PY-01 pins the runtime dependency to `grpcio==1.78.*`. Every consumer installing `axiam-sdk` with the pinned runtime dep would hit an immediate import failure.
- **Fix:** Installed `grpcio-tools==1.78.0` (matching the pin) and regenerated; pinned `grpcio-tools==1.78.*` in `pyproject.toml`'s `dev` extra and documented the constraint in `gen_grpc.sh`'s header comment.
- **Files modified:** `sdks/python/pyproject.toml`, `sdks/python/scripts/gen_grpc.sh`, `sdks/python/src/axiam_sdk/grpc/gen/authorization_pb2_grpc.py`
- **Verification:** `python -c "from axiam_sdk.grpc.gen import authorization_pb2_grpc"` succeeds with `grpcio==1.78.0` installed; `GRPC_GENERATED_VERSION` now reads `'1.78.0'`.
- **Committed in:** `8262eba` (Task 2 commit)

**6. [Rule 1 - Bug] README.md `AximClient` typo**
- **Found during:** Task 1 (reviewing scaffold files)
- **Issue:** `README.md` imported `from axiam_sdk import AximClient` — a typo for `AxiamClient`, mirroring the identical bug already found and fixed in the TypeScript SDK's README (17-01).
- **Fix:** Corrected to `AxiamClient`.
- **Files modified:** `sdks/python/README.md`
- **Committed in:** `ca790b3` (Task 1 commit)

---

**Total deviations:** 6 auto-fixed (4 Rule 1 bug fixes, 1 Rule 2 missing-critical, 1 Rule 3 blocking/tooling)
**Impact on plan:** All auto-fixes were necessary for the build/import/security-correctness invariants the plan itself required (buildable package, importable stubs matching the pinned runtime, no accidental gitignore of D-04-mandated files). No scope creep — no new features were added beyond what the plan specified.

## Issues Encountered
None beyond the auto-fixed deviations above — no unresolved issues.

## User Setup Required
None - no external service configuration required. (Local dev-tooling installs — `build`, `twine`, `grpcio-tools`, `pytest`, `pytest-asyncio`, `respx`, and an upgraded `packaging` — were performed in this execution environment via `pip install`, matching the `dev` optional-dependency group already declared in `pyproject.toml`.)

## Next Phase Readiness
- The Wave-0 foundation is complete: `sdks/python/` builds, the gRPC stubs are committed and drift-checkable, and the AMQP HMAC protocol is proven cross-language-compatible. Later Phase 19 plans (client/session, REST transport, gRPC transport, AMQP consumer, FastAPI/Django integrations, examples, CI) can now build on a verified foundation instead of an unverified assumption.
- No blockers. The CI drift-check job and PyPI publish workflow referenced in this plan's `<verification>` block are explicitly out of scope for 19-01 (deferred to plan 19-07 per the phase's wave structure) — `scripts/gen_grpc.sh` is ready to be wired into that job as-is.

## Self-Check: PASSED

All claimed files verified present on disk; all claimed commit hashes verified present in `git log --oneline --all` (`ca790b3`, `8262eba`, `c83fa6e`, `ffe528f`).

---
*Phase: 19-python-sdk*
*Completed: 2026-07-01*
