# Phase 27: Performance & Load Hardening - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-05
**Phase:** 27-performance-load-hardening
**Areas discussed:** PERF-05 harness & profiling, PERF-01 HIBP breaker tuning, PERF-03 JWKS scope + approach, PERF-04 reconnect exhaustion & poison (all four selected), plus finer-grained defaults for PERF-02/PERF-01/PERF-04/PERF-05

---

## PERF-05 — Load-test & profiling harness

| Option | Description | Selected |
|--------|-------------|----------|
| criterion + manual + flamegraph | In-repo criterion micro-benches; run locally (not CI-gated); cargo-flamegraph; doc-only report | ✓ |
| criterion + k6, CI-gated | Add k6 HTTP load tests + a CI job | |
| k6 only, manual | HTTP-level load only | |

**User's choice:** criterion + manual + flamegraph
**Notes:** Greenfield (no benches/k6/perf-report existed). Non-CI-gated to avoid perf-in-CI variance; fits the Rust workspace.

## PERF-01 — HIBP circuit breaker

| Option | Description | Selected |
|--------|-------------|----------|
| Global, hand-rolled, config-tunable | One process-wide breaker; AXIAM__AUTH__ knobs; no new dep | ✓ |
| Global, via a breaker crate | Same semantics via failsafe/tower | |
| Per-tenant breaker | Isolate breaker state per tenant | |

**User's choice:** Global, hand-rolled, config-tunable
**Notes:** HIBP is a single shared upstream → global is correct. Fail-open `Ok(None)` + cooldown already locked by the requirement.

## PERF-03 — JWKS single-flight scope + approach

| Option | Description | Selected |
|--------|-------------|----------|
| 6 named + PHP; native-first | Named SDKs + PHP; prefer native coalescing | |
| Exactly the 6 named; PHP deferred | Literal requirement scope | |
| All SDKs, uniform hand-rolled | One identical hand-rolled single-flight everywhere | ✓ |

**User's choice:** All SDKs, uniform hand-rolled
**Notes:** PHP included (a JwksVerifier.php exists); java-bom excluded (Maven BOM, no verifier). One consistent pattern across all 7 code SDKs regardless of native primitives.

## PERF-04 — Reconnect exhaustion & pool poisoning

| Option | Description | Selected |
|--------|-------------|----------|
| Stay Unhealthy, keep probing at ceiling | health_check=Unhealthy + keep retrying at max_backoff; never exit | ✓ |
| Fail-fast: exit process on exhaustion | Surface Unhealthy then exit for orchestrator restart | |
| Stay Unhealthy, stop retrying | Surface Unhealthy and halt until external trigger | |

**User's choice:** Stay Unhealthy, keep probing at ceiling
**Notes:** Consistent with CORR-02 D-05 health semantics; k8s readiness sheds traffic; no crash-loop. Poisoned conn dropped, never recycled.

## Finer-grained defaults (second round)

| Decision | Options | Selected |
|----------|---------|----------|
| PERF-02 concurrency bound | Knob default 16 / Knob default 32 / Fixed 16 | Knob, default 16 (under ~30-conn pool) |
| PERF-01 breaker defaults | 5 fail/30s / 3 fail/60s / 10 fail/15s | 5 failures / 30s cooldown |
| PERF-04 backoff values | DB values (250ms/30s/10) shared convention / Reuse CORR-03 verbatim / Leave to research | DB values, shared naming convention |
| PERF-05 scenarios & gate | 3 scenarios doc-only / +manual regression threshold / broader set | 3 scenarios, doc-only report |

**Notes:** PERF-02 bound kept under the ~30-connection SurrealDB pool. PERF-04 backoff aligns naming/algorithm with the CORR-03 webhook backoff.

## Claude's Discretion

- Exact config-knob key names/sections (follow `AXIAM__SECTION__KEY` nesting; confirm against config module).
- Breaker half-open probe semantics.
- criterion sample-size/warm-up + cargo-flamegraph invocation.
- Per-SDK implementation primitive for the uniform single-flight pattern.
- PERF-04 numbers: DB-specific (D-13 default) vs CORR-03 verbatim — research validates.

## Deferred Ideas

- k6 HTTP-level load testing + CI-gated perf-regression job (future performance milestone).
- Native-primitive JWKS coalescing per SDK (rejected in favor of uniform hand-rolled).
- Breaker crate / per-tenant HIBP breaker (rejected).
