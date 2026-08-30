# Phase 27: Performance & Load Hardening - Research

**Researched:** 2026-07-05
**Domain:** Rust hot-path hardening (circuit breaker, bounded concurrency, reconnect resilience) + cross-SDK JWKS single-flight + criterion micro-benchmarking
**Confidence:** HIGH (all claims below are code-grounded — this phase is closing a live-codebase gap, not adopting a new library)

## Summary

This phase closes five concrete gaps identified by direct source inspection, not by
choosing between competing libraries. Four of the five (PERF-01, PERF-02, PERF-04, PERF-05)
are pure Rust workspace changes with no new runtime dependency needed beyond one
already-resolved-but-not-yet-declared crate (`futures`/`futures-util`, already in
`Cargo.lock` transitively at 0.3.32). PERF-03 touches all 7 SDKs' existing JWKS
verifier files, each of which already has an unsynchronized (or partially-synchronized)
fetch-and-cache path with a demonstrable race under a concurrent invalid-`kid` burst.

**Key corrections to CONTEXT.md's locked-but-research-deferred assumptions:**
1. **PERF-01 pre-sizing target is `check_complexity`'s violation `Vec` (capacity 5), NOT
   an "authz middleware path-segment Vec"** — no such Vec exists in
   `middleware/authz.rs` (see Pitfall 1). The REST/gRPC batch handlers *already*
   `Vec::with_capacity(len)` their results — that pattern is done, PERF-02 is about
   concurrency, not sizing.
2. **`buffer_unordered`/`FuturesUnordered` requires adding the `futures` crate as an
   explicit dependency** to `axiam-api-grpc` and `axiam-api-rest` — the workspace's only
   futures-combinator dependency today is `futures-lite` (used by `axiam-amqp` for lapin),
   which does **not** provide `buffer_unordered` or `FuturesUnordered`. This is a
   zero-network-cost addition: `futures 0.3.32` / `futures-util 0.3.32` are already
   resolved in `Cargo.lock` as transitive deps (pulled in by tonic/reqwest/etc.), so
   declaring them directly needs no new download.
3. **There is no formal SurrealDB "connection pool" data structure** — AXIAM uses the
   stateless HTTP engine with exactly ONE `Arc<Surreal<Client>>` inside `DbManager`,
   plus ~30 independently-taken `.client().clone()` snapshots handed to repositories at
   server startup (`crates/axiam-server/src/main.rs`). "Poisoned-connection eviction...
   never recycled into the healthy pool" (ROADMAP wording) must be scoped to
   `DbManager`'s own internally-swappable handle — propagating a fresh handle to the
   ~30 already-cloned repository sessions is an orthogonal, larger refactor explicitly
   flagged as **out of this phase's reachable scope** by `26-RESEARCH.md` Pitfall 2 /
   `26-PATTERNS.md` (see Pitfall 2 below).
4. **PERF-03's "6 named SDKs" list in the roadmap wording undercounts** — CONTEXT.md
   D-08 already corrected this to all 7 code SDKs including PHP; confirmed here that
   PHP's `JwksVerifier.php` is fully hand-rolled (no PSR-6 cache), and that under
   classic sync PHP-FPM there is no intra-process concurrency at all — the
   single-flight guarantee is only observable under Guzzle's async promise interface
   or a long-running runtime (Swoole/RoadRunner). See Pitfall 6.
5. **Two of the 7 SDKs already delegate fetch/cache to a third-party library with its
   own internal coalescing** (TypeScript → `jose`'s `createRemoteJWKSet`; Go →
   `lestrrat-go/jwx/v3`'s `jwk.Cache`; Java → Nimbus's `RemoteJWKSet` +
   `DefaultJWKSetCache`). D-08 explicitly requires a uniform hand-rolled guard
   regardless — the concrete work item for these three is a **wrapper** in front of
   the existing library call, not a replacement of it.

**Primary recommendation:** Implement PERF-01/02/04/05 as targeted, additive changes to
the exact functions cited in CONTEXT.md's canonical refs (all confirmed to exist and
match the described shape); implement PERF-03 as one hand-rolled "double-checked-lock +
in-flight promise/future" guard per SDK, wrapping (not replacing) whatever the SDK
already uses internally, each proven by a test that counts actual HTTP calls under a
concurrent invalid-`kid` burst.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| HIBP circuit breaker | API/Backend (`axiam-auth`) | — | `check_hibp` is a library function called from the auth flow; breaker state is process-wide in-memory, no DB/cache tier involved |
| Batch authz concurrency | API/Backend (`axiam-api-grpc`, `axiam-api-rest`) | Database (SurrealDB pool sizing) | Concurrency bound must respect the DB tier's capacity even though the bound lives in the API tier |
| JWKS single-flight | SDK client (all 7 languages) — acts as its own "Backend" tier when embedded in a resource server | — | Each SDK is an independent process/library; there is no shared cache tier across SDK instances |
| DB reconnect resilience | Database/Storage (`axiam-db`) | API/Backend (readiness endpoint consumes `health_check`) | Reconnect/backoff logic belongs entirely inside the DB access layer; the API tier only reads the resulting health state |
| Load-test/profiling harness | Dev tooling (workspace-level `benches/`) | — | Not a runtime capability; local developer/CI-adjacent tooling only, explicitly non-CI-gated (D-15) |

## User Constraints (from CONTEXT.md)

<user_constraints>

### Locked Decisions

- **D-01:** One global (process-wide) breaker around `check_hibp`
  (`crates/axiam-auth/src/policy.rs`). NOT per-tenant.
- **D-02:** Hand-rolled breaker (small closed/open + cooldown state machine). No new
  circuit-breaker crate dependency.
- **D-03:** Fails open — when tripped, `check_hibp` returns `Ok(None)` for the cooldown
  window.
- **D-04:** Defaults: trip after 5 consecutive failures/timeouts; 30s cooldown. Config
  knobs `AXIAM__AUTH__HIBP_BREAKER_THRESHOLD` (5) and
  `AXIAM__AUTH__HIBP_BREAKER_COOLDOWN_SECS` (30).
- **D-05:** Hot-path pre-sizing with `Vec::with_capacity(n)` for the violation/segment
  vectors in the complexity checker, authz middleware, and SDK serialization maps.
- **D-06:** `BatchCheckAccess` (gRPC + REST) evaluates items concurrently via
  `buffer_unordered`/`FuturesUnordered`; result order preserved; a correctness test
  asserts batch results match per-item `CheckAccess`.
- **D-07:** Bounded concurrency via `AXIAM__AUTHZ__BATCH_MAX_CONCURRENCY`, default 16 —
  kept well under the ~30-connection SurrealDB pool.
- **D-08:** Uniform hand-rolled single-flight across all 7 code SDKs (csharp, go,
  java, php, python, rust, typescript). PHP is IN scope. `java-bom` excluded (no
  verifier).
- **D-09:** N concurrent cache-misses (invalid-`kid` tokens) await ONE network fetch.
  Each SDK gets a test asserting exactly one JWKS fetch under a concurrent burst.
- **D-10:** Extend the existing `DbManager::reconnect` seam in `connection.rs`.
  Reconnect loop uses exponential backoff with full jitter, a `max_backoff` ceiling,
  and a bounded retry count.
- **D-11:** On bounded-retry exhaustion: `health_check` = Unhealthy AND keep probing at
  the `max_backoff` ceiling interval. Never exit the process.
- **D-12:** Poisoned connections (handshake timeout / topology anomaly) are dropped and
  regenerated, never recycled into the healthy pool.
- **D-13:** Backoff values: base 250ms, ceiling 30s, 10 retries before critical; full
  jitter. Config knobs under `AXIAM__DB__` following the same naming/algorithm
  convention as CORR-03 webhook backoff.
- **D-14:** Rust `criterion` micro-benches (not k6) for auth (Argon2id verify + EdDSA
  mint), authz (single `CheckAccess` + `BatchCheckAccess`), cert-validation (X.509
  chain verify) — living under each owning crate's `benches/` dir.
- **D-15:** Benches run manually/locally — NOT a CI gate. `cargo-flamegraph` for
  hotspot profiling.
- **D-16:** Results documented in `claude_dev/performance-report.md` with
  baseline-vs-optimized numbers; documentation-only, no regression gate.
- **D-17:** Measurable optimizations applied where warranted.
- **D-20 (carried from Phase 26):** New config knobs follow `AXIAM__SECTION__KEY`,
  each with a safe default, fully overridable.

### Claude's Discretion

- Exact config-knob key names/sections (confirmed below against the real config module).
- Breaker half-open probe semantics (whether one probe request is tested before fully
  re-closing) — internal state shape is flexible.
- `criterion` harness details (sample size, warm-up) and `cargo-flamegraph` invocation.
- Per-SDK implementation primitive for the uniform single-flight pattern (mutex +
  in-flight map, promise cache, etc.).
- Whether PERF-04 numbers track CORR-03 constants verbatim vs. the DB-specific D-13
  values — resolved below: **use the D-13 DB-specific values**, but mirror CORR-03's
  algorithm *shape* and naming convention, adding full jitter (CORR-03 itself has no
  jitter — see Pitfall 5).

### Deferred Ideas (OUT OF SCOPE)

- k6 HTTP-level load testing and a CI-gated perf-regression job — future dedicated
  performance milestone.
- Native-primitive JWKS coalescing per SDK (Go `singleflight`, JS promise-cache as the
  *sole* mechanism) — rejected in favor of one uniform hand-rolled pattern (still
  applies even where jose/jwx/Nimbus already do some coalescing internally).
- Breaker crate / per-tenant HIBP breaker — rejected.

</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| PERF-01 | HIBP circuit breaker (fail-open, cooldown) + hot-path pre-sizing | §"PERF-01" below: exact `check_hibp` signature/behavior confirmed; correct pre-sizing target identified (`check_complexity`, capacity 5); config keys confirmed against `AuthConfig` |
| PERF-02 | Concurrent bounded `BatchCheckAccess`, order preserved | §"PERF-02" below: both gRPC and REST handlers read in full; `futures` crate dependency gap identified; new `AuthzConfig` section needed |
| PERF-03 | JWKS single-flight across SDKs | §"PERF-03" below: all 7 verifier files read; current race condition identified in each; per-language wrapper pattern specified |
| PERF-04 | SurrealDB reconnect resilience (full jitter, poisoned-connection eviction) | §"PERF-04" below: `connection.rs` read in full; the "no formal pool" architecture constraint documented; concrete swap-handle mechanism proposed |
| PERF-05 | Load-test/profiling harness, documented numbers | §"PERF-05" below: greenfield confirmed (no `criterion`/`benches/` anywhere); exact bench targets (pure-function, no DB) identified per path |

</phase_requirements>

## Project Constraints (from CLAUDE.md)

- Argon2id for passwords (OWASP params) — already implemented exactly as
  `crates/axiam-auth/src/password.rs` shows (m=19456, t=2, p=1); PERF-05's auth bench
  must use these real functions, not a synthetic stand-in.
- JWT: EdDSA (Ed25519), 15-min access tokens — matches `issue_access_token` read below.
- Config knobs use the nested `AXIAM__SECTION__KEY` convention (already a repo-wide
  norm, confirmed below).
- Build/disk hygiene: `cargo clean` between plan steps; scope `cargo test`/`clippy` to
  `-p <crate>`; the `SWAGGER_UI_DOWNLOAD_URL` file:// workaround applies to any
  build/test touching `axiam-api-rest` (which PERF-02's REST handler and PERF-04's
  DB-layer tests will touch transitively via workspace crates that depend on it).
- Signed commits per roadmap task (development-process note, not a code constraint for
  this phase's plans).

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `futures` (`futures-util` re-export) | 0.3.32 (already resolved in `Cargo.lock`, transitively) | `buffer_unordered`/`FuturesUnordered` bounded-concurrency stream combinators | The only crate in the Rust ecosystem providing this exact combinator; `futures-lite` (already a workspace dep) does NOT have it — confirmed by reading its `stream.rs` source in the local registry cache |
| `criterion` | latest 0.5.x (NOT currently a dependency anywhere — greenfield) | Statistical micro-benchmarking with baseline comparison, HTML reports | De facto standard Rust benchmarking crate; supports `criterion::black_box`, `Criterion::bench_function`, saved baselines for before/after comparison (needed for D-16's baseline-vs-optimized report) |
| `rand` | 0.9 (already a workspace dep) | Full-jitter backoff (`rand::random::<f64>()`) | Already used elsewhere in the workspace (TOTP secret gen, MFA); no new dependency |
| `tokio::sync::RwLock` | (part of `tokio = "1", features=["full"]`, already a dep) | Swappable DB connection handle for PERF-04's poisoned-connection eviction | Exact precedent already exists: `axiam-federation/src/jwks_cache.rs` wraps a `HashMap` in `Arc<tokio::sync::RwLock<_>>` for the same "shared, occasionally-replaced state" shape |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `cargo-flamegraph` | latest (external cargo subcommand, not a `Cargo.toml` dependency) | CPU hotspot profiling | Manual/local only per D-15; document invocation in `claude_dev/performance-report.md`, do not wire into CI |
| `rcgen` | 0.13 (already a workspace/axiam-pki dep) | Generate self-signed test CA + leaf cert fixtures for the cert-validation bench | Needed so the PERF-05 cert bench can construct realistic X.509 fixtures without touching the DB — `rcgen` is already used by axiam-pki's own tests for exactly this |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `futures::stream::buffer_unordered` | Hand-rolled `tokio::task::JoinSet` + `tokio::sync::Semaphore` | Avoids adding an explicit `futures` dependency, BUT requires `'static` bounds and cloning the engine/repos into each spawned task — `AuthorizationServiceImpl`'s generic repo type params are NOT currently `Clone`-bounded for this purpose, and REST's `AuthzData` is already `Arc`'d so cloning is cheap there but not on the gRPC side. `buffer_unordered` over `&self`-borrowing futures needs no `'static`/`Clone` bound at all — **recommended over JoinSet** for this reason. |
| `criterion` | `divan` | `divan` is newer/faster to compile but has a smaller ecosystem and no baseline-diff HTML report out of the box — criterion's baseline comparison directly satisfies D-16's "baseline-vs-optimized" requirement |
| Circuit breaker: hand-rolled (D-02, locked) | `failsafe`/`tower::limit` circuit-breaker layer | Explicitly rejected by CONTEXT.md D-02; not revisited |

**Installation:**
```bash
# axiam-api-grpc/Cargo.toml and axiam-api-rest/Cargo.toml
# (futures-util is already resolved transitively — this just promotes it to a direct dep)
cargo add futures --no-default-features --features std -p axiam-api-grpc
cargo add futures --no-default-features --features std -p axiam-api-rest

# New workspace dev-dependency for benches (axiam-auth, axiam-authz or axiam-api-grpc, axiam-pki)
cargo add criterion --dev --features html_reports -p axiam-auth
cargo add criterion --dev --features html_reports -p axiam-authz
cargo add criterion --dev --features html_reports -p axiam-pki
```

**Version verification:** `futures`/`futures-util` 0.3.32 confirmed present in
`Cargo.lock` today (`grep -n "^name = \"futures\"" -A2 Cargo.lock` → `version = "0.3.32"`).
`criterion` is not in the lockfile at all — `cargo add criterion --dev` will resolve
whatever the latest 0.5.x is at plan-execution time; **the planner should re-run
`cargo add --dry-run` (or check crates.io) at execution time** rather than hardcode a
patch version, since this research session did not have live registry-index access
confirmed beyond the local vendor cache. `[ASSUMED: criterion is 0.5.x — training
knowledge, not verified against crates.io this session]`

## Package Legitimacy Audit

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|--------------|---------|-------------|
| `futures` | crates.io | ~9 years (rust-lang org) | very high (top-50 crate) | github.com/rust-lang/futures-rs | OK | Approved — already transitively resolved, zero new supply-chain surface |
| `criterion` | crates.io | ~9 years | very high | github.com/bheisler/criterion.rs | OK | Approved |
| `cargo-flamegraph` | crates.io (cargo subcommand, dev-machine tool, not a `Cargo.toml` dep) | ~7 years | high | github.com/flamegraph-rs/flamegraph | OK | Approved — not a build dependency, developer-installed CLI only |

**Packages removed due to `[SLOP]` verdict:** none
**Packages flagged as suspicious `[SUS]`:** none

All three packages above are extremely well-established, rust-lang-adjacent or
long-standing community crates already familiar to this codebase's dependency graph
(criterion and flamegraph are the de facto standard pairing for Rust perf work). No
`gsd-tools query package-legitimacy check` seam was available in this execution
environment (network/tool constraints); this table is `[ASSUMED]` on reputation/training
knowledge for versions/age/downloads, but the packages themselves are not novel or
obscure — standard practice is to re-confirm exact current version via `cargo add
--dry-run` at plan-execution time, per the note above.

## Architecture Patterns

### System Architecture Diagram

```
                    ┌─────────────────────────────────────────┐
                    │  Credential-stuffing burst (PERF-01)     │
                    └───────────────┬───────────────────────────┘
                                    ▼
                     evaluate_password() [policy.rs]
                                    │
                     check_complexity() ──► Vec::with_capacity(5) violations
                                    │ (short-circuits if non-empty)
                                    ▼
                     check_history() [DB, spawn_blocking Argon2]
                                    │
                                    ▼
              ┌─────────────────────────────────────┐
              │  HibpBreaker (new, D-01/D-02)        │
              │  Closed ──5 fails──► Open             │
              │    ▲                   │ 30s cooldown │
              │    └────half-open probe┘              │
              └──────────────┬────────────────────────┘
                 Closed/HalfOpen│ Open → Ok(None) immediately, NO HTTP call
                                 ▼
                     check_hibp() ──HTTPS──► api.pwnedpasswords.com
                       (5s timeout, already fail-open on error)


          ┌─────────────────────────────────────────────────────┐
          │  BatchCheckAccessRequest (PERF-02)                    │
          └───────────────────────┬───────────────────────────────┘
                                  ▼
          gRPC: AuthorizationServiceImpl::batch_check_access
          REST: handlers::authz_check::batch_check_access
                                  │
              validate all UUIDs / tenant-mismatches UP FRONT (sync, cheap)
                                  │
              futures::stream::iter(indexed requests)
                     .map(|(i, req)| async { (i, engine.check_access(&req).await) })
                     .buffer_unordered(AXIAM__AUTHZ__BATCH_MAX_CONCURRENCY = 16)
                     .collect::<Vec<_>>().await
                                  │
                     sort_by_key(|&(i, _)| i)   ◄── restores input order
                                  │
                                  ▼
                     SurrealDB (~30 independently-cloned HTTP-engine handles,
                     concurrency bound (16) kept under this ceiling)


          ┌─────────────────────────────────────────────────────┐
          │  DbManager (PERF-04)                                  │
          └───────────────────────┬───────────────────────────────┘
              spawn_proactive_resignin()  (existing, CORR-02 — unchanged)
                                  │
              health_check() ──Unhealthy──► NEW: reconnect_loop task wakes
                                  │               │
                                  │      full-jitter backoff: rand() * min(ceiling, base*2^n)
                                  │               │
                                  │      DbManager::reconnect(config) ──fails──► retry (bounded)
                                  │               │                    ──succeeds──► swap handle
                                  │               │
                                  │      after 10 failed retries: stay Unhealthy,
                                  │      keep probing at ceiling interval forever (never exit)
                                  ▼
                     Arc<tokio::sync::RwLock<Surreal<Client>>>  (NEW — was plain Arc<Surreal<Client>>)
                     health_check() reads through the lock; client() returns current handle


          ┌─────────────────────────────────────────────────────┐
          │  N concurrent invalid-kid tokens (PERF-03)            │
          └───────────────────────┬───────────────────────────────┘
                                  ▼
          Per-SDK JwksVerifier.verify(token)
                                  │
              cache fresh? ──yes──► return cached decode
                                  │ no
              acquire fetch-guard lock (mutex/semaphore/asyncio.Lock/...)
                                  │
              re-check cache under lock (double-checked) ──fresh now──► release, use it
                                  │ still stale
              ONE HTTP GET {base_url}/oauth2/jwks
                                  │
              populate cache, release lock
                                  ▼
              all N callers now decode against the single freshly-fetched JWKS
```

### Recommended Project Structure

```
crates/
├── axiam-auth/
│   ├── src/
│   │   ├── policy.rs           # check_hibp wrapped by new hibp_breaker.rs
│   │   └── hibp_breaker.rs     # NEW — hand-rolled breaker state machine (D-02)
│   └── benches/
│       └── auth_bench.rs       # NEW — Argon2id verify + EdDSA mint (PERF-05)
├── axiam-authz/
│   ├── src/
│   │   └── config.rs           # NEW — AuthzConfig { batch_max_concurrency }
│   └── benches/
│       └── authz_bench.rs      # NEW — single CheckAccess + BatchCheckAccess (PERF-05)
├── axiam-pki/
│   └── benches/
│       └── cert_bench.rs       # NEW — X.509 chain verify_signature only (PERF-05)
├── axiam-db/
│   └── src/connection.rs       # MODIFIED — reconnect_loop, ArcSwap-style handle, DbConfig fields
├── axiam-api-grpc/
│   └── src/services/authorization.rs  # MODIFIED — buffer_unordered batch
└── axiam-api-rest/
    └── src/handlers/authz_check.rs    # MODIFIED — buffer_unordered batch

sdks/
├── rust/src/token/jwks.rs             # MODIFIED — tokio::sync::Mutex fetch-guard
├── go/internal/jwks/verifier.go       # MODIFIED — sync.Mutex + in-flight sentinel wrapping cache.Refresh
├── python/src/axiam_sdk/_jwks.py      # MODIFIED — threading.Lock wraps the WHOLE fetch, not just the decision
├── java/.../JwksVerifier.java         # MODIFIED — ReentrantLock/synchronized wrapping RemoteJWKSet call
├── csharp/Axiam.Sdk/Auth/JwksVerifier.cs  # MODIFIED — SemaphoreSlim(1,1), reuse existing SDK-wide pattern
├── typescript/src/node/jwks.ts        # MODIFIED — explicit in-flight Promise guard wrapping getJwks()/jwtVerify
└── php/src/Auth/JwksVerifier.php      # MODIFIED — Guzzle promise-based in-flight guard (see Pitfall 6)

claude_dev/
└── performance-report.md              # NEW — PERF-05 output (D-16)
```

### Pattern 1: Hand-rolled circuit breaker (PERF-01)

**What:** A tiny enum-based state machine: `Closed { consecutive_failures: u32 }`,
`Open { opened_at: Instant }`. No new dependency (D-02).
**When to use:** Wrapping `check_hibp`'s HTTP call specifically — global, in-process
(D-01), guarded by a `std::sync::Mutex` or `tokio::sync::Mutex` (this state is small
and contended briefly, either is fine; prefer `std::sync::Mutex` since the critical
section is a few field reads/writes with no `.await` inside it — matches
`crates/axiam-federation/src/jwks_cache.rs`'s general precedent of choosing the lock
type to match hold-duration/await-need).

```rust
// New file: crates/axiam-auth/src/hibp_breaker.rs
// Precedent for the "global singleton behind Arc<Mutex<...>>" shape:
// crates/axiam-federation/src/jwks_cache.rs's JwksCache(Arc<RwLock<...>>).

use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
enum BreakerState {
    Closed { consecutive_failures: u32 },
    Open { opened_at: Instant },
}

pub struct HibpBreaker {
    state: Mutex<BreakerState>,
    threshold: u32,   // AXIAM__AUTH__HIBP_BREAKER_THRESHOLD, default 5
    cooldown: Duration, // AXIAM__AUTH__HIBP_BREAKER_COOLDOWN_SECS, default 30s
}

impl HibpBreaker {
    /// Returns true if the call should proceed (Closed, or Open-but-cooldown-elapsed
    /// — a single "probe" request tests recovery, per Claude's Discretion on
    /// half-open semantics). Returns false if it should short-circuit to Ok(None)
    /// WITHOUT making the HTTP call at all (saves the 5s timeout under a burst).
    pub fn should_attempt(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        match *state {
            BreakerState::Closed { .. } => true,
            BreakerState::Open { opened_at } => {
                if opened_at.elapsed() >= self.cooldown {
                    // half-open probe: allow exactly this one through, stay
                    // "Open" until record_success() closes it.
                    true
                } else {
                    false
                }
            }
        }
    }

    pub fn record_success(&self) {
        *self.state.lock().unwrap() = BreakerState::Closed { consecutive_failures: 0 };
    }

    pub fn record_failure(&self) {
        let mut state = self.state.lock().unwrap();
        match *state {
            BreakerState::Closed { consecutive_failures } => {
                let n = consecutive_failures + 1;
                *state = if n >= self.threshold {
                    BreakerState::Open { opened_at: Instant::now() }
                } else {
                    BreakerState::Closed { consecutive_failures: n }
                };
            }
            BreakerState::Open { .. } => {
                // still failing during a half-open probe — re-open, reset cooldown clock.
                *state = BreakerState::Open { opened_at: Instant::now() };
            }
        }
    }
}
```

`check_hibp` becomes: check `breaker.should_attempt()` first; if false, `return
Ok(None)` immediately (no HTTP call, no 5s timeout wasted) with a `tracing::warn!` log
distinguishing "breaker open" from the existing "request failed"/"non-200" warn paths
already in the function. On success, call `breaker.record_success()`; on the two
existing failure branches (`Err(e)` from `.send()`, non-`is_success()` status), call
`breaker.record_failure()` before the existing `return Ok(None)`.

**The breaker instance must be constructed once and shared** (e.g. `Arc<HibpBreaker>`
threaded through wherever `check_hibp`/`evaluate_password` is called from, likely
alongside the existing `http_client: Option<&reqwest::Client>` parameter, or held as
`web::Data<Arc<HibpBreaker>>` in `axiam-server`/`axiam-api-rest` app state) — a
per-call-site breaker would defeat D-01's "global" requirement.

### Pattern 2: Bounded concurrent batch evaluation (PERF-02)

**What:** `futures::stream::iter` + `.map()` + `.buffer_unordered(n)` + re-sort by
index. Works directly against `&self`-borrowing async functions — no `'static` or
`Clone` bound needed on the engine/repos.
**When to use:** Both `AuthorizationServiceImpl::batch_check_access` (gRPC) and
`handlers::authz_check::batch_check_access` (REST).

```rust
// Source: this codebase — crates/axiam-api-grpc/src/services/authorization.rs
// (pattern to REPLACE the existing sequential `for check_req in req.requests` loop)
use futures::stream::{self, StreamExt};

// 1. Validate ALL cross-request identity checks synchronously, up front —
//    the current code returns Err on the FIRST mismatch inside the loop;
//    concurrent execution requires collecting all validation results before
//    firing any check_access() calls, so a mismatch anywhere still rejects
//    the whole batch with the same semantics as today.
let validated: Result<Vec<AccessRequest>, Status> = req.requests.iter().map(|check_req| {
    let body_tenant_id = parse_uuid(&check_req.tenant_id, "tenant_id")?;
    let body_subject_id = parse_uuid(&check_req.subject_id, "subject_id")?;
    if body_tenant_id != claims_tenant_id || body_subject_id != claims_subject_id {
        return Err(Status::permission_denied("tenant_id/subject_id mismatch: body does not match token claims"));
    }
    Ok(AccessRequest {
        tenant_id: claims_tenant_id,
        subject_id: claims_subject_id,
        action: check_req.action.clone(),
        resource_id: parse_uuid(&check_req.resource_id, "resource_id")?,
        scope: check_req.scope.clone(),
    })
}).collect();
let requests = validated?;

// 2. Concurrent, bounded, order-preserving evaluation.
let concurrency = self.authz_config.batch_max_concurrency; // AXIAM__AUTHZ__BATCH_MAX_CONCURRENCY, default 16
let mut indexed: Vec<(usize, AccessDecision)> = stream::iter(requests.into_iter().enumerate())
    .map(|(i, req)| {
        let engine = &self.engine; // shared &self reference, no clone/Arc needed
        async move {
            let decision = engine.check_access(&req).await
                .map_err(|e| Status::internal(e.to_string()))?;
            Ok::<_, Status>((i, decision))
        }
    })
    .buffer_unordered(concurrency)
    .collect::<Vec<Result<_, Status>>>()
    .await
    .into_iter()
    .collect::<Result<Vec<_>, Status>>()?;

indexed.sort_by_key(|&(i, _)| i); // restore input order (D-06)
let results = indexed.into_iter().map(|(_, d)| to_check_response(d)).collect();
Ok(Response::new(BatchCheckAccessResponse { results }))
```

The REST handler (`handlers::authz_check::batch_check_access`) follows the identical
shape, but must ALSO preserve the existing per-item `append_check_as_audit` call
(fire-and-forget, currently `.await`'d sequentially inside the loop) — since audit
writes are side effects independent of the decision, they can run concurrently inside
the same mapped future without affecting result ordering.

**Correctness test (D-06 acceptance criterion):** for a fixed set of N access requests,
assert `batch_check_access(requests)` produces byte-identical results, in the same
order, as calling `check_access` on each request individually and collecting into a
`Vec` — this proves both "order preserved" and "matches per-item `CheckAccess`" in one
test.

**Benchmark (D-06 acceptance criterion "faster than sequential"):** a criterion bench
(PERF-05, `axiam-authz/benches/authz_bench.rs` or an `axiam-api-grpc` bench) comparing
the old sequential-loop implementation (kept as a private test-only fn, or simply
`buffer_unordered(1)` as the "sequential" baseline) against `buffer_unordered(16)`
against a mock/kv-mem-backed repo set with artificial per-call latency (e.g. a test
repo that `tokio::time::sleep`s a few ms per `get_user_role_assignments` call) to make
the concurrency win observable — against a true in-memory kv-mem SurrealDB with near-zero
latency, the two may show no measurable difference, which would make the benchmark
pointless. **The plan must inject or simulate realistic per-call I/O latency in the
bench fixture for the comparison to mean anything.**

### Pattern 3: Full-jitter exponential backoff + swappable connection handle (PERF-04)

**What:** `DbManager`'s internal `db: Arc<Surreal<Client>>` field becomes
`db: Arc<tokio::sync::RwLock<Surreal<Client>>>` (precedent: `axiam-federation`'s
`JwksCache` already wraps shared, occasionally-replaced state the same way). A new
background task mirrors `spawn_proactive_resignin`'s shape but reacts to health-check
failure instead of running on a fixed timer.

```rust
// Source: this codebase — crates/axiam-db/src/connection.rs (extending, not
// replacing, the existing module).

use rand::Rng;

/// Full-jitter exponential backoff delay for reconnect attempt `n` (1-indexed).
/// Mirrors CORR-03 webhook backoff's `base * 2^(n-1)` SHAPE and naming
/// convention (backoff_base_ms/backoff_ceiling_ms), but ADDS full jitter —
/// CORR-03's webhook backoff has NO jitter (see Pitfall 5).
fn reconnect_backoff_delay(attempt: u32, base_ms: u64, ceiling_ms: u64) -> Duration {
    let exponent = attempt.saturating_sub(1) as i32;
    let capped = (base_ms as f64 * 2f64.powi(exponent)).min(ceiling_ms as f64);
    let jittered_ms = rand::rng().random::<f64>() * capped; // full jitter: uniform(0, capped)
    Duration::from_millis(jittered_ms as u64)
}

impl DbManager {
    /// Spawned once from `connect_with_ttl`, alongside `spawn_proactive_resignin`.
    /// Reacts to health-check failure (poll via the existing `health_check()`,
    /// or triggered from a failed query elsewhere — implementation detail left
    /// to the plan) by attempting `reconnect()` with full-jitter backoff, bounded
    /// to `reconnect_max_retries` (default 10) attempts. On exhaustion: stays in
    /// the failed state and keeps probing at the ceiling interval FOREVER (D-11)
    /// — never returns, never exits the process.
    fn spawn_reconnect_loop(
        db: Arc<tokio::sync::RwLock<Surreal<Client>>>,
        config: DbConfig,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                // Detect unhealthy: read-lock, run "RETURN 1", classify.
                let unhealthy = {
                    let guard = db.read().await;
                    guard.query("RETURN 1").await
                        .and_then(|r| r.check())
                        .map_err(Self::classify_query_error)
                        .is_err_and(|e| matches!(e, DbError::Unhealthy(_)))
                };
                if !unhealthy {
                    tokio::time::sleep(Duration::from_secs(5)).await; // poll interval when healthy
                    continue;
                }

                let mut attempt = 0u32;
                loop {
                    attempt += 1;
                    let delay = reconnect_backoff_delay(
                        attempt, config.reconnect_base_ms, config.reconnect_ceiling_ms,
                    );
                    tokio::time::sleep(delay).await;

                    match DbManager::reconnect(&config).await {
                        Ok(fresh) => {
                            // Poisoned-connection eviction (D-12): the OLD handle
                            // is simply dropped when the write-guard replaces it —
                            // never handed back out to any caller.
                            *db.write().await = fresh;
                            info!(attempt, "DB reconnect succeeded, handle replaced");
                            break; // back to health-poll loop
                        }
                        Err(e) if attempt >= config.reconnect_max_retries => {
                            warn!(error = %e, attempt, "DB reconnect exhausted retries — \
                                staying Unhealthy, continuing to probe at ceiling interval (D-11)");
                            // Keep looping at the ceiling interval — never break out
                            // to exit, never return from this task.
                            tokio::time::sleep(Duration::from_millis(config.reconnect_ceiling_ms)).await;
                        }
                        Err(e) => {
                            warn!(error = %e, attempt, "DB reconnect attempt failed, retrying");
                        }
                    }
                }
            }
        })
    }
}
```

**`client()`'s signature must change** from `pub fn client(&self) -> &Surreal<Client>`
to something that goes through the lock — e.g. `pub async fn client(&self) ->
tokio::sync::RwLockReadGuard<'_, Surreal<Client>>`, or (simpler, matching the ~40
existing `db.client().clone()` call sites in `main.rs` which all run inside `async fn
main()`) `pub async fn client_cloned(&self) -> Surreal<Client> { self.db.read().await.clone() }`. **This is an API-breaking
change** to every one of the ~40 call sites in `axiam-server/src/main.rs` — they must
become `.await`-ed. This is mechanical (add `.await`) but touches a lot of lines; the
plan should budget a dedicated task for it, separate from the reconnect-loop logic
itself.

**Test/simulation (per acceptance criterion):** spin up a `DbManager` against a
short-lived TTL (reusing `connect_with_ttl`'s existing test seam), force the
underlying connection into an unhealthy state, and assert: (a) `health_check()`
reports Unhealthy while retries are exhausted, (b) after exhaustion the loop keeps
running (task not finished/panicked) and keeps attempting at the ceiling interval, (c)
a subsequent successful `reconnect()` (e.g. bring the mock/live server back) causes
`health_check()` to become healthy again without a process restart, and (d) the OLD
poisoned handle is never returned by `client()`/`client_cloned()` after the swap (e.g.
assert the session id or a distinguishing marker differs pre/post swap).

### Pattern 4: Per-SDK JWKS single-flight (PERF-03)

**Rust** (`sdks/rust/src/token/jwks.rs`) — currently `cache: std::sync::RwLock<Option<CachedJwks>>`
with a TOCTOU race in `force_refetch_if_allowed` (check-then-fetch, not atomic).
Fix: add `fetch_lock: tokio::sync::Mutex<()>`; acquire it before any fetch (normal
miss or forced refetch), then re-check freshness under the lock before actually
calling `fetch_and_cache`:

```rust
// Source: this codebase — sdks/rust/src/token/jwks.rs (pattern to add)
async fn get_or_fetch(&self) -> Result<JwkSet, AxiamError> {
    if let Some(jwks) = self.cached_if_fresh() {
        return Ok(jwks);
    }
    let _guard = self.fetch_lock.lock().await; // NEW: serializes concurrent fetchers
    // Double-check: a concurrent caller may have already refreshed while we
    // waited for the lock.
    if let Some(jwks) = self.cached_if_fresh() {
        return Ok(jwks);
    }
    self.fetch_and_cache(false).await
}
```

The same double-checked-lock shape applies to `force_refetch_if_allowed`.

**Python** (`_jwks.py`) — the existing `threading.Lock` only guards the
"should-I-invalidate" *decision*, not the actual `get_signing_key_from_jwt` fetch that
happens after the lock is released. Fix: hold `self._refetch_lock` around the ENTIRE
forced-refetch-and-refetch sequence (not just the cache invalidation), so concurrent
callers block on the lock and, after acquiring it, re-check whether another caller
already repopulated the cache.

**Go** (`internal/jwks/verifier.go`) — wraps `lestrrat-go/jwx/v3`'s `jwk.Cache`, whose
`Refresh(ctx, url)` may already serialize internally per-URL (not confirmed from
source in this session — `httprc` internals weren't read). Per D-08, add an explicit
`sync.Mutex` (or `singleflight.Group` used purely as a mutual-exclusion primitive, NOT
relying on its native dedup semantics as the sole mechanism per the Deferred Ideas
note) around the `v.cache.Refresh(ctx, v.jwksURL)` call in the unknown-kid branch, so
the guarantee doesn't depend on unverified library internals.

**Java** (`JwksVerifier.java`) — wraps Nimbus's `RemoteJWKSet` + `DefaultJWKSetCache`.
Same treatment: add an explicit `ReentrantLock` (or `synchronized` block) around the
call path that triggers a refetch, matching D-08's "don't rely on the native
primitive" intent even though Nimbus's cache is likely already thread-safe internally.

**C#** (`JwksVerifier.cs`) — currently has **zero synchronization** at all
(`Dictionary<string, byte[]> _keysByKid` and `DateTimeOffset _fetchedAt` are plain
mutable fields, not thread-safe even for the dictionary mutation itself, independent
of the "extra fetch" concern). Fix: add a `SemaphoreSlim(1, 1)` — **reuse the exact
primitive REQUIREMENTS.md's CS-01 already specifies for the SDK's token-refresh
single-flight guard**, for consistency within the same codebase.

**TypeScript** (`node/jwks.ts`) — delegates entirely to `jose`'s
`createRemoteJWKSet`. The existing `jwksPromise` lazy-singleton pattern already
coalesces concurrent *construction* of the `createRemoteJWKSet` getter, but the actual
per-verification key lookup/refetch-on-unknown-kid happens INSIDE `jose`'s getter
function on every `jwtVerify` call — whether `jose` itself coalesces concurrent
in-flight fetches must be verified with a test (mock global `fetch`, fire N concurrent
`verifyAccessToken()` calls with an unknown `kid`, assert exactly 1 call). If it does
not, wrap the getter call itself with the same lazy-promise-singleton pattern already
used for `jwksPromise` (an `inFlightFetch: Promise<...> | null` guard reset after
resolution).

**PHP** (`Auth/JwksVerifier.php`) — fully hand-rolled, `$fetchedAt` int TTL, no shared
cache. See Pitfall 6 for the classic-FPM concurrency caveat; recommend wrapping the
refetch call (`ensureFresh`) in a Guzzle-promise-based in-flight guard so the
guarantee is meaningful under Guzzle's async interface / a long-running runtime,
and documenting explicitly that under classic sync PHP-FPM (single request per
process, no shared memory) there is no possible race to fix — the single-flight test
must exercise the async/coroutine path, not a plain sequential `verify()` call.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Bounded concurrent stream evaluation | A custom semaphore + spawn loop reimplementing what `buffer_unordered` already does | `futures::stream::StreamExt::buffer_unordered` | Already resolved in `Cargo.lock`; battle-tested; avoids `'static`/`Clone` bound headaches that a `tokio::spawn`-based approach would require |
| Full-jitter backoff math | A bespoke jitter formula diverging from the well-known "full jitter" algorithm (AWS's "Exponential Backoff And Jitter" post) | `rand::rng().random::<f64>() * min(ceiling, base * 2^n)` — the exact formula CORR-03's non-jittered version already approximates minus the jitter multiply | Full jitter is a specific, well-defined algorithm; deviating from `uniform(0, capped)` silently reintroduces the thundering-herd problem it exists to prevent |
| JWKS parsing/verification | Custom JWT/JWK parsing in any SDK | The SDK's already-chosen JWT library (`jsonwebtoken` Rust, `jose` TS, `jwx/v3` Go, `PyJWT` Python, Nimbus Java, BouncyCastle C#, `firebase/php-jwt` PHP) | PERF-03 only adds a coalescing WRAPPER around the existing fetch call — it must never touch the actual cryptographic verification logic in any of the 7 files |
| Criterion-style statistical benchmarking | A hand-rolled `Instant::now()`-diff loop | `criterion` | Handles warm-up, outlier rejection, statistical significance, and HTML baseline-diff reports — reimplementing this is exactly the kind of "deceptively complex" problem D-14 already resolved by picking criterion |

**Key insight:** every item in this phase is an *addition* around an existing,
already-correct core (the crypto verify, the DB query, the authz decision logic) — the
risk is in the wrapping logic (breaker state transitions, concurrency bound
correctness, backoff math, lock scope), not in reimplementing anything the codebase
already does well.

## Common Pitfalls

### Pitfall 1: CONTEXT.md's "authz middleware path-segment Vec" does not exist

**What goes wrong:** A planner takes D-05's wording literally and searches for/invents
a `Vec` of path segments to pre-size inside `crates/axiam-api-rest/src/middleware/authz.rs`.
**Why it happens:** `normalize_for_public_check` does use a pre-sized `String`
(`String::with_capacity(path.len())` — already done), and `matches_public_allowlist`
iterates `entries: &[&str]` (a slice, not something to size), but there is **no**
`.split('/').collect::<Vec<_>>()` anywhere in this file — `path.split('/').any(...)`
is used directly on the iterator, never collected.
**How to avoid:** The correct PERF-01 pre-sizing targets, confirmed by reading the
code, are: (1) `check_complexity`'s `let mut violations = Vec::new()` →
`Vec::with_capacity(5)` (exactly 5 possible complexity violations: TooShort,
MissingUppercase, MissingLowercase, MissingDigit, MissingSymbol); (2) the REST/gRPC
batch handlers' `results` vectors — **already** `Vec::with_capacity(len)` in both
files, nothing to change there; (3) "SDK serialization maps" — not investigated in
this session (out of the 7 JWKS files read; would require a broader SDK grep for
`HashMap::new()`/similar in hot serialization paths, e.g. auth response DTOs).
**Warning signs:** If a plan task says "pre-size the path-segment vector in
authz.rs," that task is based on a wording assumption, not code — flag for
correction before execution.

### Pitfall 2: There is no SurrealDB connection pool to evict from

**What goes wrong:** A plan assumes a `Vec<Surreal<Client>>` or similar pool exists
inside `axiam-db` that a "poisoned connection" can be removed from and regenerated
into.
**Why it happens:** The ROADMAP goal text says "dropped and never recycled into the
healthy pool" and PERF-02's CONTEXT.md references "the ~30-connection SurrealDB
pool" — but reading `connection.rs` shows AXIAM uses the **stateless HTTP engine**
with exactly ONE `Arc<Surreal<Client>>` inside `DbManager`. The "~30" figure refers to
~30 independent `db.client().clone()` calls taken ONCE at server startup in
`crates/axiam-server/src/main.rs`, each becoming its own repository's long-lived,
independently-expiring session snapshot — not a pool with add/remove semantics.
`26-RESEARCH.md` (Pitfall 2) and `26-PATTERNS.md` already documented this exact gap
and explicitly deferred fixing the ~30 already-cloned sessions to "Phase 27's
PERF-04," but the realistic, buildable scope for THIS phase is: (a) make
`DbManager`'s own internal handle swappable and evict/regenerate on poison, and (b)
document — again — that the ~30 pre-existing repository clones are not touched by
this fix (same residual-gap framing CORR-02 used).
**How to avoid:** Scope PERF-04's plan tasks to `DbManager`'s internal
`Arc<RwLock<Surreal<Client>>>` handle and the reconnect loop around it. Do NOT
attempt to thread a shared/swappable handle through the ~40 `db.client().clone()`
call sites in `main.rs` as part of this phase — that is a materially larger refactor
(changing every repository constructor's client-handle lifetime model) that was never
scoped or estimated by CONTEXT.md's discussion, and attempting it risks scope
creep/breaking ~40 call sites for a benefit (already-live repository sessions
recovering from THEIR OWN independent expiry) that is explicitly out of this phase's
locked acceptance criteria (which are about `DbManager`'s reconnect loop and
`health_check`, not about every repository's session lifetime).
**Warning signs:** A plan task titled "wire fresh connection into all repositories"
or "update the connection pool" — there is no pool struct to update; this phrasing
signals the plan drifted from the actual architecture.

### Pitfall 3: `futures-lite` cannot supply `buffer_unordered`

**What goes wrong:** A plan writes `use futures_lite::stream::StreamExt;` expecting
`buffer_unordered` to be available (since `futures-lite` is already a workspace
dependency used by `axiam-amqp`/`axiam-api-rest` for lapin), and the build fails.
**Why it happens:** `futures-lite` 2.6.1's `stream.rs` (read directly from the local
registry cache in this session) implements a large set of `Stream`/`StreamExt`
combinators but has NO `buffer_unordered`, NO `FuturesUnordered`. It is a
lighter-weight, single-future-at-a-time combinator library (smol-rs ecosystem);
concurrency-bounding combinators are a `futures`/`futures-util` (futures-rs, the
tokio-rs-adjacent ecosystem) feature.
**How to avoid:** Add `futures` (or `futures-util` directly, smaller) as an explicit
`[dependencies]` entry in `axiam-api-grpc/Cargo.toml` and
`axiam-api-rest/Cargo.toml`. Since `futures-util 0.3.32` is already resolved
transitively in `Cargo.lock` (pulled in by tonic and/or reqwest and/or surrealdb),
this requires no new network fetch — `cargo add` will pin to the already-resolved
version.
**Warning signs:** A compile error like `no method named 'buffer_unordered' found for
struct 'Iter'` — the fix is adding the dependency, not searching `futures-lite`
harder.

### Pitfall 4: `check_hibp` is already fail-open on network errors — the breaker is about avoiding wasted 5s timeouts, not adding fail-open behavior that doesn't exist

**What goes wrong:** A plan implements the breaker as if `check_hibp` currently
blocks/denies auth on HIBP failure and needs to be MADE fail-open.
**Why it happens:** Misreading D-03's "fails open" wording as describing new
behavior.
**How to avoid:** `check_hibp` (read in full this session) ALREADY returns `Ok(None)`
on every failure branch — connection error, non-200 status, unreadable body. This is
existing, correct behavior. The circuit breaker's actual value-add is: **under a
credential-stuffing burst, skip the HTTP call (and its up-to-5s timeout) entirely**
once the breaker trips, so a flood of concurrent logins don't each independently pay
the 5-second timeout cost against a downed/rate-limiting HIBP endpoint, which is the
actual "does not starve legitimate flows" acceptance criterion (PERF-01's third
bullet). The breaker's `should_attempt() == false` path must short-circuit BEFORE the
`http_client.get(&url)...send().await` call, not merely wrap the existing
already-fail-open error handling.
**Warning signs:** A plan task described as "make check_hibp fail open" (already
true) rather than "add a breaker that skips the network call under sustained
failure" (the actual gap).

### Pitfall 5: CORR-03's webhook backoff has NO jitter — do not copy it verbatim as "the jitter pattern"

**What goes wrong:** A plan reads CORR-03's `backoff_ttl_ms` function
(`crates/axiam-api-rest/src/webhook_consumer.rs`) as the reference implementation for
PERF-04's "full jitter" requirement and ports it as-is.
**Why it happens:** CONTEXT.md D-13 says "align PERF-04 with the CORR-03 webhook
backoff naming/algorithm convention," which is correct for the NAMING
(`backoff_base_ms`/`backoff_ceiling_ms`, exponential-with-multiplier-2.0 shape) but
the actual `backoff_ttl_ms` function reads: `let delay_ms = base_ms as f64 *
multiplier.powi(exponent); delay_ms.clamp(0.0, ceiling_ms)` — a pure deterministic
exponential backoff with **no random jitter term at all**.
**How to avoid:** Mirror the naming/shape (`base_ms`, `ceiling_ms`, `*2^n`,
clamped-to-ceiling) but ADD the jitter multiply that CORR-03 lacks:
`rand::rng().random::<f64>() * capped_delay` (full jitter — uniform between 0 and the
capped exponential value), matching D-13's explicit "full jitter" requirement, which
is stricter than CORR-03's plain exponential.
**Warning signs:** A reconnect-backoff test that asserts a fixed, non-random delay
value for a given attempt number — full jitter is inherently non-deterministic per
call; tests should assert the delay falls within `[0, capped]`, not an exact value.

### Pitfall 6: PHP's "concurrent burst" is not observable under classic sync PHP-FPM

**What goes wrong:** A plan writes a PHPUnit test that calls `$verifier->verify($jwt)`
in a plain sequential loop N times and asserts "exactly one fetch," expecting this to
exercise a race condition.
**Why it happens:** Classic PHP-FPM (the SDK's baseline runtime — gRPC support is
explicitly gated behind `extension_loaded('grpc')` with Swoole/RoadRunner as the
documented long-running-runtime path, per PHP-01/CONTRACT.md) processes ONE request
per worker PROCESS, synchronously, with no shared memory between concurrent workers
and no intra-process concurrency at all. A sequential PHPUnit test loop can never
reproduce a genuine race — there is no possible interleaving in a single-threaded,
single-request-at-a-time execution model.
**How to avoid:** Either (a) test the single-flight guarantee using Guzzle's async
promise interface (`sendAsync`, `Promise\Utils::settle`) to genuinely interleave
multiple in-flight `verify()`-triggered fetches within ONE PHP process/request (Guzzle
supports this via curl-multi even under classic FPM), or (b) explicitly scope the
PHP single-flight test/feature to the Swoole/RoadRunner coroutine runtime already
established as PHP-01's long-running-runtime story, and document in the SDK
README/CONTRACT that under classic sync FPM the guarantee is vacuous (each
request/process independently fetches, which is expected and cannot be
"fixed" without a cross-process shared cache — explicitly out of scope for this
phase, which is single-flight WITHIN one process, not cross-process caching).
**Warning signs:** A PHP test titled "concurrent burst" using a plain `for` loop with
no `sendAsync`/promise/coroutine construct — it is not actually testing concurrency.

## Code Examples

### HIBP breaker wiring into `evaluate_password`

```rust
// Source: this codebase — crates/axiam-auth/src/policy.rs (existing call site to modify)
// Current (existing code, line ~322):
if policy.hibp_check_enabled
    && let Some(client) = http_client
    && let Ok(Some(violation)) = check_hibp(password, client).await
{
    violations.push(violation);
}

// New: check_hibp gains a &HibpBreaker parameter; internally calls
// breaker.should_attempt() before the HTTP request and
// breaker.record_success()/record_failure() on each outcome branch.
// evaluate_password's call site is otherwise unchanged — the breaker
// short-circuit is entirely inside check_hibp, preserving the existing
// Result<Option<PolicyViolation>, AxiamError> signature.
```

### Config struct additions (confirmed against the real `config` crate wiring)

```rust
// Source: this codebase — crates/axiam-auth/src/config.rs (AuthConfig, existing
// pattern for max_failed_login_attempts/lockout_duration_secs — new fields follow
// the SAME container-level #[serde(default)] + custom Default impl shape, no
// per-field #[serde(default = "fn")] needed):
pub struct AuthConfig {
    // ... existing fields ...
    /// Consecutive check_hibp failures/timeouts before the breaker trips (D-04).
    /// AXIAM__AUTH__HIBP_BREAKER_THRESHOLD, default 5.
    pub hibp_breaker_threshold: u32,
    /// Cooldown (seconds) the breaker stays open before a half-open probe (D-04).
    /// AXIAM__AUTH__HIBP_BREAKER_COOLDOWN_SECS, default 30.
    pub hibp_breaker_cooldown_secs: u64,
}
// impl Default for AuthConfig { ... hibp_breaker_threshold: 5, hibp_breaker_cooldown_secs: 30, ... }

// Source: this codebase — NEW FILE crates/axiam-authz/src/config.rs (mirrors
// GrpcConfig's shape in crates/axiam-api-grpc/src/config.rs exactly):
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthzConfig {
    /// Max concurrent CheckAccess evaluations inside one BatchCheckAccess call (D-07).
    /// AXIAM__AUTHZ__BATCH_MAX_CONCURRENCY, default 16 (kept under the ~30-conn DB budget).
    pub batch_max_concurrency: usize,
}
impl Default for AuthzConfig {
    fn default() -> Self { Self { batch_max_concurrency: 16 } }
}

// Source: this codebase — crates/axiam-server/src/main.rs AppConfig (existing
// pattern — add ONE new field, mirroring how `grpc: GrpcConfig` was added):
struct AppConfig {
    // ... existing fields: server, db, auth, grpc, amqp, rate_limit ...
    #[serde(default)]
    authz: axiam_authz::AuthzConfig, // NEW
}

// Source: this codebase — crates/axiam-db/src/connection.rs DbConfig (existing
// pattern — token_refresh_fraction is the direct precedent; new fields follow
// identically, NO per-field serde(default) attribute, container-level
// #[serde(default)] + impl Default supplies the fallback):
pub struct DbConfig {
    // ... existing fields: url, namespace, database, username, password, token_refresh_fraction ...
    /// AXIAM__DB__RECONNECT_BASE_MS, default 250.
    pub reconnect_base_ms: u64,
    /// AXIAM__DB__RECONNECT_CEILING_MS, default 30_000.
    pub reconnect_ceiling_ms: u64,
    /// AXIAM__DB__RECONNECT_MAX_RETRIES, default 10.
    pub reconnect_max_retries: u32,
}
```

**Confirmed env-var mapping mechanism:** `crates/axiam-server/src/main.rs::load_config()`
uses `config::Config::builder().add_source(config::Environment::with_prefix("AXIAM").separator("__"))`
— so `AXIAM__DB__RECONNECT_BASE_MS` → `AppConfig.db.reconnect_base_ms` automatically via
serde's case-insensitive field-name matching against the `__`-split env var segments.
**This is the SAME mechanism `AXIAM__DB__TOKEN_REFRESH_FRACTION` already uses today** —
no new wiring code is needed beyond adding the struct fields themselves.

**Divergent pattern warning:** `crates/axiam-api-rest/src/webhook_consumer.rs`'s
`WebhookRetryConfig::from_env()` does NOT go through `AppConfig`/the `config` crate at
all — it manually calls `std::env::var("AXIAM__WEBHOOK__...").ok().and_then(|v|
v.parse().ok()).unwrap_or(default)` at the point of use. This is because
`WebhookRetryConfig` was never added as an `AppConfig` section. **Do not copy this
manual-parsing pattern for PERF-04's DB knobs** — `DbConfig` is ALREADY wired through
`AppConfig`'s serde tree, so the correct approach is adding plain struct fields (as
shown above), not a parallel manual-env-parsing function.

### PERF-05 bench targets (all pure-function, no DB/network required)

```rust
// auth bench — Source: crates/axiam-auth/src/password.rs + src/token.rs (both
// pure sync functions, no I/O):
//   hash_password(password: &str, pepper: Option<&str>) -> Result<String, AuthError>
//   verify_password(password: &str, hash: &str, pepper: Option<&str>) -> Result<bool, AuthError>
//   issue_access_token(user_id, tenant_id, org_id, scopes, config: &AuthConfig, jti, aud) -> Result<String, AuthError>
// Bench setup: call `AuthConfig::resolve_keys()` ONCE outside the criterion
// `bench_function` closure (it pre-parses the Ed25519 PEM into cached keys —
// exactly what production does at startup), so the bench measures steady-state
// signing cost, not PEM-parse cost on every iteration.

// authz bench — Source: crates/axiam-authz/src/engine.rs
//   AuthorizationEngine::check_access(&self, request: &AccessRequest) -> AxiamResult<AccessDecision>
// Setup: reuse the existing kv-mem SurrealDB dev-dependency pattern already used
// by axiam-authz's own tests (Cargo.toml dev-dependencies: `surrealdb = { features
// = ["kv-mem"] }`) to seed a realistic role/permission/resource graph, OR write
// simple fixed in-memory repo stubs implementing the five repository traits
// (RoleRepository/PermissionRepository/ResourceRepository/ScopeRepository/
// GroupRepository) for a lower-overhead, more isolated CPU-cost measurement.

// cert-validation bench — Source: crates/axiam-pki/src/mtls.rs's inner crypto
// step, NOT the full authenticate() (which requires DB repos):
//   client_x509.verify_signature(Some(ca_x509.public_key()))
// where client_x509/ca_x509 come from x509_parser::prelude::parse_x509_certificate.
// Bench fixture: use `rcgen` (already an axiam-pki dependency) to generate a
// self-signed CA + one leaf cert signed by it ONCE (outside the timed closure),
// then bench just the parse+verify_signature step — this isolates the pure
// cryptographic cost from the DB-repo lookups that `authenticate()` also performs.
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Sequential per-item `CheckAccess` loop in `BatchCheckAccess` | Bounded-concurrent `buffer_unordered` | This phase | I/O-bound DB round-trips overlap instead of serializing; latency for an N-item batch drops from ~N×RTT toward ~(N/concurrency)×RTT |
| Deterministic exponential backoff (CORR-03 webhook) | Full-jitter exponential backoff (PERF-04 DB reconnect) | This phase | Avoids synchronized retry storms when multiple server replicas lose DB connectivity simultaneously (e.g. a shared network blip) — full jitter is the AWS-documented standard fix for the "thundering herd on reconnect" failure mode |
| Per-request independent JWKS fetch on cache miss (all 7 SDKs, to varying degrees) | Single-flight coalesced fetch | This phase | Under a burst of invalid-`kid` tokens (e.g. a rotated signing key propagating slowly, or a probing attacker), N concurrent requests trigger 1 fetch instead of N, protecting the JWKS endpoint from self-inflicted load |

**Deprecated/outdated:** None — this phase hardens existing, currently-correct-but-not-yet-load-tested code; nothing here replaces a deprecated pattern.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `criterion` current version is 0.5.x | Standard Stack | Low — `cargo add criterion --dev` resolves the real current version at execution time regardless; only affects documentation accuracy in this research doc |
| A2 | Go's `lestrrat-go/jwx/v3` `jwk.Cache.Refresh` may already internally serialize concurrent refresh calls per-URL | Pattern 4 / PERF-03 Go section | Low-medium — if it does NOT already serialize, the recommended explicit `sync.Mutex` wrapper is still correct and sufficient; if it DOES already serialize, the wrapper is a harmless (if slightly redundant) belt-and-suspenders addition that still satisfies D-08's "don't rely on native primitives" intent |
| A3 | Nimbus's `DefaultJWKSetCache`/`RemoteJWKSet` (Java) has adequate but unverified internal thread-safety for concurrent refresh | Pattern 4 / PERF-03 Java section | Low — same reasoning as A2; the recommended explicit lock wrapper is correct regardless of the underlying library's actual internal behavior |
| A4 | The Package Legitimacy Audit table's download counts/ages for `futures`/`criterion`/`cargo-flamegraph` are approximate, based on training knowledge rather than a live registry query in this session | Package Legitimacy Audit | Very low — these are extremely well-established crates; the risk of a wrong exact number is negligible to the phase's actual risk profile (no slopsquatting concern) |

**If this table is empty:** N/A — see entries above; none of these affect the core architectural findings (all confirmed by direct source reading), only peripheral version/library-internals details.

## Open Questions

1. **Should the HIBP breaker instance be a `web::Data<Arc<HibpBreaker>>` app-state
   singleton, or threaded explicitly through `evaluate_password`'s call chain?**
   - What we know: `check_hibp`/`evaluate_password` are currently free functions in
     `axiam-auth`, called from wherever password policy evaluation happens
     (registration, password change, reset-confirm — not traced exhaustively in this
     session).
   - What's unclear: how many distinct call sites exist across `axiam-api-rest`
     handlers, and whether they already share a common app-state struct that a
     breaker could piggy-back on.
   - Recommendation: the plan should grep all `evaluate_password`/`check_hibp` call
     sites first, then decide between an `Arc<HibpBreaker>` in Actix app data
     (consistent with how `health_checker: Arc<dyn HealthChecker>` is already wired)
     vs. a lazily-initialized process-global (e.g. `std::sync::OnceLock`) if call
     sites are too scattered for app-data threading to be clean.

2. **Does the criterion authz bench need synthetic per-call I/O latency to make the
   concurrency win measurable, or is the kv-mem SurrealDB backend already slow enough
   relative to the buffer_unordered overhead to show a real difference?**
   - What we know: the kv-mem SurrealDB engine is in-memory and very fast; a batch of
     16 near-instant queries may not show a meaningful sequential-vs-concurrent
     difference just from Rust's async scheduling overhead alone.
   - What's unclear: actual measured latency-per-call in this specific engine/schema
     without running it.
   - Recommendation: the plan should include a fallback path — either bench against a
     real (containerized) SurrealDB instance where genuine network RTT exists, or
     inject a deliberate `tokio::time::sleep(Duration::from_millis(2))` in a
     bench-only mock repository to simulate realistic per-call I/O cost, whichever is
     simpler to set up in this sandboxed environment (containerized SurrealDB may not
     be available per the CLAUDE.md build-hygiene notes about sandbox constraints).

3. **What is the actual mechanism by which "a failed handshake does not leak a broken
   handle" (PERF-04's third acceptance criterion, "competing workers desynchronize")
   should be tested — is a real network-partition simulation feasible in this
   sandbox?**
   - What we know: `connection_resilience_test.rs` already has a `#[ignore]`d,
     live-SurrealDB-gated test pattern (`recovers_from_token_expiry_without_restart`)
     that the plan can extend.
   - What's unclear: how to deterministically force a "poisoned" (as opposed to
     merely expired-token) connection state in a test — e.g. simulating a handshake
     timeout specifically, versus the already-covered auth-expiry case.
   - Recommendation: the plan should treat "poisoned connection" testing primarily as
     a unit-level proof (assert the RwLock swap discards the old handle and no caller
     can observe it post-swap) rather than attempting to simulate a real SurrealDB
     handshake failure over the network, which would require either a proxy/fault
     injector or manipulating the live server mid-test — likely out of reach for a
     sandboxed CI-adjacent test.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain / cargo | All PERF-01/02/04/05 work | ✓ (per CLAUDE.md, standard project toolchain) | workspace `rust-version = "1.93"` | — |
| `futures`/`futures-util` crate | PERF-02 | ✓ — already resolved transitively in `Cargo.lock` at 0.3.32 | 0.3.32 | — |
| `criterion` crate | PERF-05 | Not yet a dependency anywhere — needs `cargo add --dev` | resolves at execution time | — |
| `cargo-flamegraph` CLI | PERF-05 profiling | Not verified installed in this sandbox | — | Document the invocation in the performance report even if flamegraph generation itself is deferred to a developer's local machine with perf/dtrace support — flamegraph generation typically requires OS-level profiling support (`perf` on Linux) that may not be available/permitted in a constrained sandbox |
| Live SurrealDB instance (`just dev-up`) | PERF-04's `#[ignore]`d live-reconnect tests; PERF-02's realistic authz bench (Open Question 2) | Not confirmed running in this research session (no `cargo test`/service checks were run per the task's "prefer reading over compiling" instruction) | — | kv-mem embedded SurrealDB (already a dev-dependency pattern) covers most test needs without a live server |
| Node/Python/Go/Java/.NET/PHP toolchains for the 7 SDKs | PERF-03 | Not verified in this session | — | Per-SDK CI already exists (FND-05) with path-filtered workflows; PERF-03's plan should rely on each SDK's existing test runner rather than assuming all 7 toolchains are present in one execution environment |

**Missing dependencies with no fallback:** none identified — `criterion` and
`futures` are both `cargo add`-able without network access to a fresh version (either
already resolved, or resolvable from the standard crates.io index which the project's
existing `Cargo.lock` already reaches).

**Missing dependencies with fallback:** `cargo-flamegraph`/OS-level profiling support
— if unavailable in the execution sandbox, the plan should still produce the
criterion benchmark numbers (which don't need flamegraph) and note flamegraph
generation as a manual step for a developer machine, satisfying D-15's "manual/local"
framing without blocking the phase on sandbox profiling support.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `cargo test` (workspace-standard, per-crate `-p <crate>`) for PERF-01/02/04; `criterion` (separate, non-`cargo test` harness) for PERF-05; per-SDK native test runners (`cargo test`, `vitest`/`jest`, `go test`, `pytest`, `mvn test`, `dotnet test`, `phpunit`) for PERF-03 |
| Config file | None new for Rust tests (standard `cargo test`); `Cargo.toml` `[[bench]]` stanzas with `harness = false` needed per crate adding criterion benches |
| Quick run command | `cargo test -p axiam-auth --lib` (breaker unit tests), `cargo test -p axiam-api-grpc --lib` / `-p axiam-api-rest --lib` (batch concurrency + ordering tests), `cargo test -p axiam-db --lib` (backoff-math unit tests, no live server) |
| Full suite command | `cargo test -p axiam-db --test connection_resilience_test -- --ignored` (live-SurrealDB-gated reconnect proof, requires `just dev-up`); per-SDK: `cargo test` / `npx vitest run` / `go test ./...` / `pytest` / `mvn test` / `dotnet test` / `vendor/bin/phpunit` for each SDK's new single-flight test |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PERF-01 | Breaker trips after N failures, fails open, cools down, resumes | unit | `cargo test -p axiam-auth --lib hibp_breaker` | ❌ Wave 0 — new file `hibp_breaker.rs` + tests |
| PERF-01 | Complexity-check `Vec` still produces identical violations after `with_capacity(5)` | unit | `cargo test -p axiam-auth --lib check_complexity` | ✅ existing tests in `policy.rs` cover current behavior; extend, don't replace |
| PERF-02 | Batch results match per-item `CheckAccess`, order preserved | integration | `cargo test -p axiam-api-grpc --lib` / `-p axiam-api-rest --lib batch_check_access` | ❌ Wave 0 — new correctness test |
| PERF-02 | Concurrent batch faster than sequential baseline | criterion bench | `cargo bench -p axiam-authz` (or `-p axiam-api-grpc`) | ❌ Wave 0 — new `benches/authz_bench.rs`, see Open Question 2 for fixture caveat |
| PERF-03 | Exactly one JWKS fetch under concurrent invalid-`kid` burst | integration, per SDK | `cargo test -p axiam-rust-sdk`, `npx vitest run jwks`, `go test ./internal/jwks/...`, `pytest sdks/python/tests/test_jwks.py`, `mvn test -Dtest=JwksVerifierTest`, `dotnet test --filter JwksVerifier`, `vendor/bin/phpunit tests/JwksVerifierTest.php` | ❌ Wave 0 — new test per SDK; each needs a mock/counting HTTP layer (see per-SDK notes in Pattern 4) |
| PERF-04 | Full-jitter backoff delay falls within `[0, capped]`, capped value follows exponential-to-ceiling shape | unit | `cargo test -p axiam-db --lib reconnect_backoff_delay` | ❌ Wave 0 — new unit tests, no live server needed |
| PERF-04 | Reconnect exhaustion → stays Unhealthy, keeps probing, never exits | integration (live-server-gated, `#[ignore]`) | `cargo test -p axiam-db --test connection_resilience_test -- --ignored` | 🟡 file exists (`connection_resilience_test.rs`), needs new test cases added |
| PERF-04 | Poisoned handle never recycled/returned post-swap | unit | `cargo test -p axiam-db --lib` (or extend the integration test file) | ❌ Wave 0 |
| PERF-05 | Baseline-vs-optimized numbers recorded | manual/doc-only | `cargo bench -p axiam-auth && cargo bench -p axiam-authz && cargo bench -p axiam-pki` (results pasted into `claude_dev/performance-report.md`) | ❌ Wave 0 — greenfield, no `benches/` anywhere in the workspace today |

### Sampling Rate

- **Per task commit:** the relevant `cargo test -p <crate> --lib` scoped to the
  touched crate only (per CLAUDE.md build-hygiene guidance — never unscoped `cargo
  test`/`cargo build` across the whole workspace).
- **Per wave merge:** the crate's full test suite (`cargo test -p <crate>`, still
  scoped) plus, for PERF-04, the `--ignored` live-server test if `just dev-up` is
  available in the environment.
- **Phase gate:** `criterion` benches run once manually at phase end to populate
  `claude_dev/performance-report.md` — explicitly NOT part of the automated green-gate
  (D-15/D-16), so it does not block `/gsd-verify-work`.

### Wave 0 Gaps

- [ ] `crates/axiam-auth/src/hibp_breaker.rs` + unit tests — new file, no existing coverage
- [ ] `crates/axiam-authz/src/config.rs` (`AuthzConfig`) — new file
- [ ] `crates/axiam-api-grpc/benches/authz_bench.rs`, `crates/axiam-auth/benches/auth_bench.rs`, `crates/axiam-pki/benches/cert_bench.rs` — greenfield, no `benches/` dir exists anywhere in the workspace
- [ ] `criterion` dev-dependency addition to at least `axiam-auth`, `axiam-authz`/`axiam-api-grpc`, `axiam-pki` `Cargo.toml`
- [ ] `futures` direct dependency addition to `axiam-api-grpc` and `axiam-api-rest` `Cargo.toml`
- [ ] Per-SDK JWKS single-flight test files (7 new/extended test files — see Test Map)
- [ ] `claude_dev/performance-report.md` — does not exist yet, to be created as PERF-05's deliverable

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | yes | HIBP breach-check remains a defense-in-depth password-policy control; the breaker must never turn a *genuine* breach-check bypass into a silent security regression — fail-open here is an explicit, pre-existing, documented tradeoff (network-error resilience over blocking legitimate logins), not new risk introduced by this phase |
| V4 Access Control | yes | `BatchCheckAccess`'s concurrent evaluation must not change authorization semantics — the correctness test (batch == per-item results) is the control that proves this; the up-front identity-mismatch validation (Pattern 2) must reject the WHOLE batch on any single mismatch, exactly matching today's sequential short-circuit-on-first-error behavior, so concurrency introduces no authorization bypass window |
| V6 Cryptography | yes (indirectly) | PERF-05's cert-validation bench and PERF-03's JWKS work must not touch the actual cryptographic verification logic (`verify_signature`, EdDSA decode/verify) in any file — only wrap/measure around it |
| V11 Business Logic | yes | The HIBP circuit breaker and DB reconnect backoff are both rate/flow-control business-logic additions; both must fail toward the SAFER state under ambiguity (breaker fails open = don't block auth on an unrelated outage; DB reconnect fails toward Unhealthy = readiness alarm, never toward silently serving stale/broken connections) |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| Credential-stuffing burst exhausting HIBP-check-induced timeouts, causing legitimate login requests to queue/time out (a self-inflicted DoS via an external dependency) | Denial of Service | The circuit breaker itself (PERF-01) — trip after N consecutive failures, skip the network call entirely during cooldown |
| Thundering-herd reconnect storm after a shared DB outage across multiple server replicas | Denial of Service | Full-jitter exponential backoff (PERF-04) — the specific mitigation this phase implements |
| JWKS-endpoint hammering from a rotating/forged `kid` attack (an attacker deliberately sending tokens with random/invalid `kid` values to force repeated refetches) | Denial of Service | Existing per-SDK forced-refetch cooldown (already implemented, e.g. Rust's `FORCED_REFETCH_MIN_INTERVAL`, Python's `_FORCED_REFETCH_MIN_INTERVAL_SECONDS`) PLUS the new single-flight guard (PERF-03) which additionally collapses concurrent legitimate cache-miss bursts (e.g. many users hitting an app instance at once right after a real key rotation) into one fetch |
| Authorization bypass via a concurrency-introduced ordering/mismatch bug in `BatchCheckAccess` | Tampering / Elevation of Privilege | The mandatory correctness test (batch results == sequential per-item results, same order) as an unconditional gate before considering PERF-02 done |
| Reconnect loop silently swallowing a genuinely revoked/invalid root credential as "just a transient network blip" and retrying forever without alarming | Repudiation / Denial of Service (masking a real incident) | `classify_query_error`'s existing `DbError::Unhealthy` distinction (CORR-02 D-05) must continue to be respected — PERF-04's reconnect loop reacts to `DbError::Unhealthy` specifically and surfaces it via `health_check`/`/ready`, it does not swallow the classification |

## Sources

### Primary (HIGH confidence — direct source reading in this session)

- `crates/axiam-db/src/connection.rs` (full file) — `DbManager`, `DbConfig`, `reconnect`, `health_check`, `classify_query_error`, module-doc architecture notes
- `crates/axiam-db/tests/connection_resilience_test.rs` (full file) — existing CORR-02 test patterns to extend
- `crates/axiam-db/src/error.rs` (full file) — `DbError` enum
- `crates/axiam-api-rest/src/health.rs` (full file) — `HealthChecker` trait, `/ready` endpoint
- `crates/axiam-auth/src/policy.rs` (lines 90-330) — `check_complexity`, `check_hibp`, `check_history`, `evaluate_password`
- `crates/axiam-authz/src/engine.rs` (lines 1-140) — `AuthorizationEngine::check_access`
- `crates/axiam-api-grpc/src/services/authorization.rs` (full file) — `AuthorizationServiceImpl`, existing sequential batch loop
- `crates/axiam-api-rest/src/handlers/authz_check.rs` (full file) — REST `check_access`/`batch_check_access` handlers
- `crates/axiam-api-rest/src/authz.rs` (lines 1-45) — `AuthzChecker` trait (confirms `&self` borrow shape)
- `crates/axiam-api-rest/src/middleware/authz.rs` (lines 1-140) — confirms NO path-segment `Vec` exists (Pitfall 1)
- `crates/axiam-api-rest/src/webhook_consumer.rs` (lines 1-120) — `WebhookRetryConfig`, `backoff_ttl_ms` (CORR-03 backoff precedent, confirmed no jitter)
- `crates/axiam-federation/src/jwks_cache.rs` (lines 1-80) — `tokio::sync::RwLock` precedent for shared/swappable state
- `crates/axiam-auth/src/config.rs` (full file) — `AuthConfig` struct/Default pattern
- `crates/axiam-api-grpc/src/config.rs` (full file) — `GrpcConfig` struct/Default pattern (new-section precedent)
- `crates/axiam-server/src/main.rs` (lines 74-102, 200-500, 790-830) — `AppConfig`, `load_config`, ~40 `db.client().clone()` call sites, `health_checker` wiring
- `crates/axiam-authz/Cargo.toml`, `crates/axiam-auth/Cargo.toml`, `crates/axiam-api-grpc/Cargo.toml`, `crates/axiam-pki/Cargo.toml` — dependency confirmation
- `Cargo.toml` (workspace root, full) — `[workspace.dependencies]`, confirms `futures-lite` present, `criterion` absent, `config = "0.15"`, `rcgen`, `rand`
- `Cargo.lock` — confirmed `futures`/`futures-util` 0.3.32 already resolved transitively; confirmed no `criterion` entry
- `/root/.cargo/registry/src/.../futures-lite-2.6.1/src/stream.rs` — confirmed absence of `buffer_unordered`/`FuturesUnordered`
- `crates/axiam-auth/src/password.rs` (lines 1-75) — `hash_password`, `verify_password` (pure sync, PERF-05 bench target)
- `crates/axiam-auth/src/token.rs` (lines 1-100) — `issue_access_token` (pure sync, PERF-05 bench target)
- `crates/axiam-pki/src/mtls.rs` (full file) — `DeviceAuthService::authenticate`, isolated `verify_signature` crypto step (PERF-05 bench target)
- `sdks/rust/src/token/jwks.rs` (full file) — `JwksVerifier`, TOCTOU race in `force_refetch_if_allowed`
- `sdks/typescript/src/node/jwks.ts` (full file) — `jose`'s `createRemoteJWKSet` delegation
- `sdks/go/internal/jwks/verifier.go` (full file) — `lestrrat-go/jwx/v3` `jwk.Cache` delegation
- `sdks/python/src/axiam_sdk/_jwks.py` (full file) — `PyJWKClient` + `threading.Lock` decision-only race
- `sdks/csharp/Axiam.Sdk/Auth/JwksVerifier.cs` (lines 1-80) — zero synchronization, `Dictionary`/`DateTimeOffset` mutable fields
- `sdks/php/src/Auth/JwksVerifier.php` (grep-level) — fully hand-rolled, no PSR cache
- `sdks/java/src/main/java/io/axiam/sdk/internal/JwksVerifier.java` (grep-level) — Nimbus `RemoteJWKSet`+`DefaultJWKSetCache`
- `.planning/phases/26-correctness-resilience/26-CONTEXT.md`, `26-PATTERNS.md` (grep excerpt) — CORR-02 handoff notes, "~30 repository clones" residual-gap framing
- `.planning/REQUIREMENTS.md` (PERF-01 through PERF-05 sections, lines 872-916) — locked acceptance criteria
- `.planning/phases/27-performance-load-hardening/27-CONTEXT.md`, `27-DISCUSSION-LOG.md` — locked decisions and discussion rationale

### Secondary (MEDIUM confidence)

- None — no external web/docs lookups were performed in this session; all findings are grounded directly in the local codebase. This is appropriate for a "close a known gap in code you already own" phase rather than a "adopt an unfamiliar library" phase.

### Tertiary (LOW confidence — flagged `[ASSUMED]`)

- `criterion`'s exact current version (Standard Stack, Assumption A1)
- `lestrrat-go/jwx/v3`'s `httprc`/`jwk.Cache` internal concurrency behavior (Assumption A2) — not read from source in this session
- Nimbus `DefaultJWKSetCache`/`RemoteJWKSet`'s internal thread-safety (Assumption A3) — not read from source in this session
- Package Legitimacy Audit's exact download/age figures (Assumption A4) — training-knowledge estimates, not a live registry query

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — every recommended dependency is either already resolved in `Cargo.lock` or is the unambiguous standard tool (criterion, flamegraph) for its purpose
- Architecture: HIGH — every architectural claim (no connection pool, no path-segment Vec, `futures-lite` gap, config-crate wiring mechanism) was confirmed by directly reading the actual source, not inferred from CONTEXT.md's wording
- Pitfalls: HIGH for Pitfalls 1-5 (all code-grounded); MEDIUM for Pitfall 6 (PHP-FPM concurrency model is architecturally well-known but this session did not read PHP-FPM's actual worker-pool config in this repo, e.g. `docker/`'s FPM pool settings, to confirm zero-shared-memory is the actual deployed model rather than assumed from PHP's general execution model)

**Research date:** 2026-07-05
**Valid until:** 30 days (stable, internally-owned codebase; the only fast-moving external factor is exact `criterion`/`futures` patch versions, which the plan re-resolves at execution time regardless)
