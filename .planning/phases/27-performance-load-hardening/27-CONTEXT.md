# Phase 27: Performance & Load Hardening - Context

**Gathered:** 2026-07-05
**Status:** Ready for planning

<domain>
## Phase Boundary

Make AXIAM's hot paths withstand load without adding new capabilities. Five
locked hardening items across auth, authz, the SDKs, and the DB layer:

- **PERF-01** — Circuit-break `check_hibp` (fail open, cooldown) + pre-size hot-path vectors
- **PERF-02** — Parallelize `BatchCheckAccess` with bounded concurrency, order preserved
- **PERF-03** — Single-flight the JWKS fetch across the SDKs (one network call per burst)
- **PERF-04** — Full-jitter reconnect backoff + poisoned-connection eviction in the DB layer
- **PERF-05** — Load-test/profiling harness for auth, authz-check, cert-validation with documented numbers

Requirements are **locked** by ROADMAP.md / REQUIREMENTS.md (PERF-01…PERF-05).
This discussion clarifies HOW to implement them, not WHAT to build. No new
capabilities.

**Dependency note:** PERF-04 builds directly on Phase 26 CORR-02, which built
`DbManager::reconnect` in `crates/axiam-db/src/connection.rs` as an explicit
*"forward-compatible extension seam"* for exactly this work (a full
jittered-backoff reconnect loop + poisoned-connection eviction). CORR-02 also
set the config precedent (`AXIAM__DB__TOKEN_REFRESH_FRACTION`, default 0.6).

</domain>

<decisions>
## Implementation Decisions

### PERF-01 — HIBP circuit breaker & hot-path pre-sizing
- **D-01:** **One global (process-wide) breaker** around `check_hibp`
  (`crates/axiam-auth/src/policy.rs`). The HIBP upstream is a single shared
  dependency, so breaker state is global — NOT per-tenant.
- **D-02:** **Hand-rolled** breaker (small closed/open + cooldown state
  machine). No new circuit-breaker crate dependency.
- **D-03:** **Fails open** — when tripped, `check_hibp` returns `Ok(None)`
  (breach lookup unavailable → do not block auth) for the cooldown window.
- **D-04:** Defaults: trip after **5** consecutive failures/timeouts; **30s**
  cooldown. Config knobs `AXIAM__AUTH__HIBP_BREAKER_THRESHOLD` (5) and
  `AXIAM__AUTH__HIBP_BREAKER_COOLDOWN_SECS` (30) — safe defaults, fully
  overridable (exact key/section confirmed against the config module in
  research).
- **D-05:** Hot-path pre-sizing with `Vec::with_capacity(n)` for the
  violation/segment vectors in the complexity checker, authz middleware, and
  SDK serialization maps (locked acceptance criterion).

### PERF-02 — Concurrent bounded BatchCheckAccess
- **D-06:** `BatchCheckAccess`
  (`crates/axiam-api-grpc/src/services/authorization.rs`; REST counterpart
  `crates/axiam-api-rest/src/handlers/authz_check.rs`) evaluates items
  concurrently via `buffer_unordered` / `FuturesUnordered`; **result order
  preserved**; a correctness test asserts batch results match per-item
  `CheckAccess`.
- **D-07:** Bounded concurrency via config knob
  `AXIAM__AUTHZ__BATCH_MAX_CONCURRENCY`, **default 16** — deliberately kept
  well under the ~30-connection SurrealDB pool so concurrent batches don't
  exhaust it (exact key/section confirmed in research).

### PERF-03 — JWKS single-flight across SDKs
- **D-08:** **Uniform hand-rolled single-flight** across all **7 code SDKs**:
  `csharp`, `go`, `java`, `php`, `python`, `rust`, `typescript`. **PHP is IN
  scope** — a `JwksVerifier` already exists (`sdks/php/src/Auth/JwksVerifier.php`)
  and applying the same hardening to it is consistency, not a new capability.
  `java-bom` is excluded (Maven BOM, no verifier). One consistent pattern per
  SDK rather than relying on each language's native coalescing primitive.
- **D-09:** N concurrent cache-misses (invalid-`kid` tokens) await **one**
  network fetch. Each SDK gets a test asserting exactly one JWKS fetch under a
  concurrent burst.

### PERF-04 — SurrealDB reconnect resilience
- **D-10:** Extend the existing `DbManager::reconnect` seam in
  `crates/axiam-db/src/connection.rs` (built forward-compatible by CORR-02).
  Reconnect loop uses **exponential backoff with full jitter**, a
  `max_backoff` ceiling, and a **bounded retry count**.
- **D-11:** On bounded-retry **exhaustion**: surface a critical error via
  `health_check` = **Unhealthy** (readiness alarm — consistent with CORR-02
  D-05) **and keep probing at the `max_backoff` ceiling interval**. **Never
  exit the process** (no crash-loop; k8s readiness sheds traffic while the loop
  keeps trying).
- **D-12:** **Poisoned connections** (handshake timeout / topology anomaly)
  are **dropped and regenerated, never recycled** into the healthy pool.
- **D-13:** Backoff values: base **250ms**, ceiling **30s**, **10** retries
  before critical; full jitter. Config knobs under `AXIAM__DB__` following the
  **same naming/algorithm convention as the CORR-03 webhook backoff**
  (candidate keys `AXIAM__DB__RECONNECT_BASE_MS`,
  `AXIAM__DB__RECONNECT_CEILING_MS`, `AXIAM__DB__RECONNECT_MAX_RETRIES` —
  exact names confirmed against the config module in research).

### PERF-05 — Load testing & critical-path profiling
- **D-14:** **Rust `criterion` micro-benches** (not k6) for the three paths,
  living under each owning crate's `benches/` dir. Scenarios:
  - **auth** = Argon2id password verify + EdDSA token mint
  - **authz** = single `CheckAccess` + `BatchCheckAccess`
  - **cert-validation** = X.509 chain verify
- **D-15:** Benches run **manually / locally — NOT a CI gate** (avoids
  perf-in-CI flakiness). `cargo-flamegraph` for hotspot profiling.
- **D-16:** Results documented in `claude_dev/performance-report.md` with
  **baseline-vs-optimized** numbers; **documentation-only, no regression gate**.
- **D-17:** Measurable optimizations applied where warranted (locked criterion).

### Claude's Discretion
- Exact config-knob key names/sections for all new knobs — follow the existing
  nested `AXIAM__SECTION__KEY` convention; confirm against the config module.
- Breaker half-open semantics (whether one probe request is tested before fully
  re-closing) — D-01..D-04 fix the observable behavior; the internal state shape
  is flexible.
- `criterion` harness details (sample size, warm-up) and `cargo-flamegraph`
  invocation specifics.
- The uniform single-flight (D-08) may be *implemented* with each language's
  ordinary concurrency primitives (mutex + in-flight map, promise cache) — the
  decision is "one consistent hand-rolled pattern," not a specific primitive.
- Whether PERF-04 numbers ultimately track the CORR-03 constants verbatim vs the
  DB-specific values in D-13 — D-13 is the default; research validates against
  existing backoff conventions.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & roadmap
- `.planning/REQUIREMENTS.md` §PERF-01…PERF-05 — locked acceptance criteria for every item.
- `.planning/ROADMAP.md` §"Phase 27: Performance & Load Hardening" — goal + 5 success criteria.

### PERF-04 dependency (Phase 26 handoff)
- `.planning/phases/26-correctness-resilience/26-CONTEXT.md` §CORR-02 (D-03/D-04/D-05) and §Deferred (the explicit PERF-04 handoff) — the reconnect seam + health semantics to stay consistent with.
- `crates/axiam-db/src/connection.rs` — `DbManager`, `spawn_proactive_resignin`, and the `reconnect` extension seam; `token_refresh_fraction` (0.6) config precedent.

### PERF-01 (HIBP breaker + pre-sizing)
- `crates/axiam-auth/src/policy.rs` — `check_hibp` (the call to wrap).

### PERF-02 (batch authz)
- `crates/axiam-api-grpc/src/services/authorization.rs` — `BatchCheckAccess` gRPC service.
- `crates/axiam-api-rest/src/handlers/authz_check.rs` — REST batch authz counterpart.

### PERF-03 (JWKS single-flight — per-SDK verifiers)
- `sdks/python/src/axiam_sdk/_jwks.py`
- `sdks/go/internal/jwks/verifier.go`, `sdks/go/jwks.go`
- `sdks/rust/src/token/jwks.rs`
- `sdks/java/src/main/java/io/axiam/sdk/internal/JwksVerifier.java`
- `sdks/csharp/Axiam.Sdk/Auth/JwksVerifier.cs`
- `sdks/typescript/src/node/jwks.ts`
- `sdks/php/src/Auth/JwksVerifier.php`

### Backoff / config conventions to mirror
- `crates/axiam-api-rest/src/webhook.rs` + 26-CONTEXT.md §CORR-03 (D-08/D-20) — webhook exponential-backoff knob naming/algorithm to align PERF-04 with.
- `crates/axiam-amqp/` (mail consumer, 25-08) — durable-consumer backoff precedent.

### PERF-05 (harness output)
- `claude_dev/performance-report.md` — to be CREATED; baseline-vs-optimized numbers for auth/authz/cert paths.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DbManager::reconnect` seam in `connection.rs` — CORR-02 built it explicitly for PERF-04; extend rather than rewrite.
- Existing per-SDK `JwksVerifier` implementations (all 7 code SDKs) — single-flight wraps the existing fetch, does not replace verification.
- CORR-03 webhook bounded-exponential-backoff knobs (`AXIAM__WEBHOOK__BACKOFF_*`) — naming/algorithm template for the new `AXIAM__DB__RECONNECT_*` knobs.
- Nested `AXIAM__SECTION__KEY` env-config with safe defaults — the precedent for every new PERF knob.

### Established Patterns
- `health_check` classifies auth/connection failures distinctly and surfaces Unhealthy (CORR-02 D-05) — PERF-04 exhaustion reuses this readiness-alarm semantics.
- Additive-only, fail-open safety posture (breaker returns `Ok(None)` rather than blocking auth) matches the project's default-deny-but-don't-self-DoS stance.

### Integration Points
- `check_hibp` breaker → password/breach-check auth flow (fail-open when tripped).
- `BatchCheckAccess` bounded concurrency → SurrealDB connection pool (~30) — bound must stay under it.
- `connection.rs` reconnect loop → `health_check` readiness → server health endpoint.
- criterion benches → `benches/` of `axiam-auth` (auth), `axiam-api-grpc`/`axiam-authz` (authz), `axiam-pki` (cert) → `claude_dev/performance-report.md`.

</code_context>

<specifics>
## Specific Ideas

- PERF-04 exhaustion behavior explicitly modeled as "stay Unhealthy + keep
  probing at the ceiling, never exit" — orchestrator readiness sheds traffic
  while the process self-heals.
- PERF-05 is deliberately a **developer/ops tool, not a build gate** — "documented
  numbers," not "green-or-red CI."
- JWKS single-flight is deliberately **uniform across all SDKs** (including PHP)
  for cross-SDK consistency, even where a native primitive exists.

</specifics>

<deferred>
## Deferred Ideas

- **k6 HTTP-level load testing** and a **CI-gated perf-regression job** — PERF-05
  chose criterion + manual + documentation-only. k6/end-to-end load and CI
  gating can be added in a later dedicated performance milestone.
- **Native-primitive JWKS coalescing per SDK** (e.g. Go `singleflight`, JS
  promise-cache) — considered and rejected in favor of one uniform hand-rolled
  pattern (D-08).
- **Breaker crate / per-tenant HIBP breaker** — considered and rejected (D-01/D-02).

None outside phase scope surfaced — discussion stayed within the five PERF items
and their direct config/backoff implications.

</deferred>

---

*Phase: 27-performance-load-hardening*
*Context gathered: 2026-07-05*
