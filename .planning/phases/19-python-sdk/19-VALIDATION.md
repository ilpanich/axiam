---
phase: 19
slug: python-sdk
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-01
---

# Phase 19 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `19-RESEARCH.md` § Validation Architecture. Per-task rows are
> finalized by the planner once PLAN.md task IDs exist.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `pytest` + `pytest-asyncio` (asyncio_mode = "auto"); `respx` for mocked httpx transport |
| **Config file** | none yet — Wave 0 adds `[tool.pytest.ini_options]` to `sdks/python/pyproject.toml` |
| **Quick run command** | `pytest sdks/python/tests -x -q` |
| **Full suite command** | `pytest sdks/python/tests -v --tb=short` |
| **Estimated runtime** | ~30–60 seconds (unit, mocked transport — no live server) |

---

## Sampling Rate

- **After every task commit:** Run `pytest sdks/python/tests -x -q` (fast subset relevant to the task)
- **After every plan wave:** Run `pytest sdks/python/tests -v --tb=short` + `mypy --strict sdks/python/src` + `ruff check sdks/python` + `verify=False` grep gate + gRPC stub drift-check
- **Before `/gsd-verify-work`:** Full suite green AND `cd sdks/python && python -m build && twine check dist/*` passing
- **Max feedback latency:** ~60 seconds

---

## Per-Task Verification Map

> Task IDs (`19-NN-MM`) are assigned by the planner. Rows below map each phase
> requirement / success-criterion to its automated verification; the planner
> binds each to the task that delivers it.

| Requirement / SC | Wave | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|------------------|------|-----------------|-----------|-------------------|-------------|--------|
| PY-01 SC#1 (sync+async login → typed `LoginResult.mfa_required`) | ≥1 | N/A | unit (respx mock) | `pytest sdks/python/tests/test_client_login.py -x` | ❌ W0 | ⬜ pending |
| PY-01 SC#2 (5 concurrent tasks ⇒ exactly 1 refresh) | ≥1 | prevents thundering-herd refresh | unit (pytest-asyncio) | `pytest sdks/python/tests/test_single_flight.py -x` | ❌ W0 | ⬜ pending |
| PY-01 SC#3 (`verify=False` absent) | ≥1 | no TLS bypass | static grep gate | `! grep -rn "verify=False" sdks/python/src sdks/python/examples sdks/python/tests` | ❌ W0 (CI) | ⬜ pending |
| PY-01 SC#4 (FastAPI dep + Django middleware runnable) | ≥2 | local JWKS verify + tenant check | integration + unit | `pytest sdks/python/tests/test_fastapi_dependency.py sdks/python/tests/test_django_middleware.py -x` | ❌ W0 | ⬜ pending |
| PY-01 SC#5 (`python -m build && twine check`) | last | N/A | build/packaging | `cd sdks/python && python -m build && twine check dist/*` | ❌ W0 (CI) | ⬜ pending |
| D-08 (`NetworkError` never leaks tokens/`Set-Cookie`) | ≥1 | info-disclosure mitigation | unit (non-vacuous regression) | `pytest sdks/python/tests/test_error_redaction.py -x` | ❌ W0 | ⬜ pending |
| §8 / A2 (AMQP HMAC byte-for-byte vs server) | **0** | tamper/replay mitigation | unit (cross-language fixture) | `pytest sdks/python/tests/test_amqp_hmac.py -x` | ❌ **W0 — real fixture required** | ⬜ pending |
| D-16 (JWKS: EdDSA-only allowlist, rotate on unknown kid) | ≥1 | alg-confusion mitigation | unit (mocked JWKS) | `pytest sdks/python/tests/test_jwks.py -x` | ❌ W0 | ⬜ pending |
| Cross-tenant token replay (middleware `tenant_id` check) | ≥2 | spoofing/EoP mitigation | unit | `pytest sdks/python/tests/test_middleware_tenant.py -x` | ❌ W0 | ⬜ pending |
| D-04 (committed gRPC stubs match regen) | ≥1 | supply-chain/drift | CI drift-check | `python -m grpc_tools.protoc … && git diff --exit-code sdks/python/src/axiam_sdk/grpc/gen` | ❌ W0 (CI) | ⬜ pending |
| D-20 (`mypy --strict` + `ruff`) | ≥1 | N/A | static analysis | `mypy --strict sdks/python/src && ruff check sdks/python && ruff format --check sdks/python` | ❌ W0 (CI) | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `sdks/python/pyproject.toml` — fix build-backend → `setuptools.build_meta` (D-03), raise `requires-python = ">=3.10"` (D-11), add `[tool.pytest.ini_options]` (`asyncio_mode="auto"`), `[tool.mypy]` (strict), `[tool.ruff]`, `[project.optional-dependencies]` (`fastapi`, `django`, `dev`), `[tool.setuptools.package-data]` for committed gRPC stubs (D-04)
- [ ] `sdks/python/src/axiam_sdk/` — src-layout restructure from the flat scaffold (D-14)
- [ ] `sdks/python/src/axiam_sdk/py.typed` — empty PEP 561 marker (D-20)
- [ ] `sdks/python/tests/conftest.py` — shared fixtures (respx mock httpx transport, JWKS mock, fake HMAC signing key)
- [ ] `sdks/python/tests/test_amqp_hmac.py` — **real cross-language HMAC fixture** captured from / cross-verified against `crates/axiam-amqp/src/messages.rs` (Assumption A2 / Pitfall 2) — **must resolve before other AMQP work**
- [ ] Dev/framework install: `grpcio-tools mypy ruff build twine pytest pytest-asyncio respx` (+ `fastapi`, `django` extras) via declared `pyproject.toml` groups
- [ ] `.github/workflows/` Python SDK workflow — matrix 3.10–3.13, `pytest`, `verify=False` grep gate, `mypy --strict`, `ruff`, gRPC drift-check, `python -m build`/`twine check`, tag-triggered PyPI Trusted-Publishing job (D-05/D-18)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| PyPI Trusted-Publishing (OIDC) actually publishes on a real release tag | PY-01 SC#5 / D-05 | Requires the live PyPI project + registered OIDC publisher; cannot run in unit CI | On first `sdks/python/vX.Y.Z` tag, confirm the GitHub Actions publish job succeeds and the version appears on PyPI |

*All other phase behaviors have automated verification (unit, static, build, or CI-gate).*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (incl. the AMQP HMAC cross-language fixture)
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
