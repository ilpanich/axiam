# Phase 27: Performance & Load Hardening - Pattern Map

**Mapped:** 2026-07-05
**Files analyzed:** 15 (new + modified)
**Analogs found:** 15 / 15

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `crates/axiam-auth/src/hibp_breaker.rs` (NEW) | utility (state machine) | event-driven | `crates/axiam-federation/src/jwks_cache.rs` (shared-mutable-state shape) + `crates/axiam-auth/src/policy.rs::check_hibp` (call site) | role-match |
| `crates/axiam-authz/src/config.rs` (NEW) | config | request-response | `crates/axiam-api-grpc/src/config.rs` (`GrpcConfig`) | exact |
| `crates/axiam-api-grpc/src/services/authorization.rs` (MODIFY `batch_check_access`) | controller/service | request-response (batch) | itself — existing sequential loop, replace with `buffer_unordered` | exact (in-place refactor) |
| `crates/axiam-api-rest/src/handlers/authz_check.rs` (MODIFY `batch_check_access`) | controller | request-response (batch) | gRPC counterpart above (same pattern, REST shape) | exact |
| `crates/axiam-db/src/connection.rs` (MODIFY `DbManager`) | service/connection-manager | event-driven (health-triggered reconnect) | itself — CORR-02's `reconnect`/`spawn_proactive_resignin`/`health_check`; backoff naming from `crates/axiam-api-rest/src/webhook_consumer.rs::backoff_ttl_ms` | exact (extension seam) |
| `sdks/rust/src/token/jwks.rs` (MODIFY) | SDK client / cache | request-response + single-flight | itself — existing `RwLock<Option<CachedJwks>>` + `force_refetch_if_allowed` | exact |
| `sdks/go/internal/jwks/verifier.go` + `sdks/go/jwks.go` (MODIFY) | SDK client / cache | request-response + single-flight | itself — wraps `lestrrat-go/jwx/v3` `jwk.Cache` | exact |
| `sdks/python/src/axiam_sdk/_jwks.py` (MODIFY) | SDK client / cache | request-response + single-flight | itself — `PyJWKClient` + `threading.Lock` (decision-only today) | exact |
| `sdks/java/.../JwksVerifier.java` (MODIFY) | SDK client / cache | request-response + single-flight | itself — Nimbus `RemoteJWKSet` + `DefaultJWKSetCache` | exact |
| `sdks/csharp/Axiam.Sdk/Auth/JwksVerifier.cs` (MODIFY) | SDK client / cache | request-response + single-flight | itself (currently unsynchronized); SemaphoreSlim precedent = CS-01's SDK token-refresh guard | exact |
| `sdks/typescript/src/node/jwks.ts` (MODIFY) | SDK client / cache | request-response + single-flight | itself — existing `jwksPromise` lazy-singleton pattern | exact |
| `sdks/php/src/Auth/JwksVerifier.php` (MODIFY) | SDK client / cache | request-response + single-flight | itself — hand-rolled, no PSR cache | exact |
| `crates/axiam-auth/benches/auth_bench.rs` (NEW) | test (bench) | batch/transform | greenfield — idiomatic `criterion` `[[bench]] harness=false`; functions from `crates/axiam-auth/src/password.rs` + `src/token.rs` | no analog (greenfield tooling) |
| `crates/axiam-authz/benches/authz_bench.rs` (NEW, or under `axiam-api-grpc`) | test (bench) | batch/transform | greenfield — same criterion pattern; function from `crates/axiam-authz/src/engine.rs::check_access` | no analog (greenfield tooling) |
| `crates/axiam-pki/benches/cert_bench.rs` (NEW) | test (bench) | batch/transform | greenfield — same criterion pattern; function from `crates/axiam-pki/src/mtls.rs` (`verify_signature` step) | no analog (greenfield tooling) |
| `claude_dev/performance-report.md` (NEW) | doc | batch/transform | sibling docs in `claude_dev/` (e.g. `security-audit.md`) for format/tone only — content is greenfield | partial (format only) |

## Pattern Assignments

### `crates/axiam-auth/src/hibp_breaker.rs` (utility, event-driven)

**Analog:** `crates/axiam-federation/src/jwks_cache.rs` (shared-state-behind-a-lock shape) + `crates/axiam-auth/src/policy.rs::check_hibp` (integration call site)

**Shape to copy** — small enum state machine behind `std::sync::Mutex` (critical section has no `.await`, so `std::sync::Mutex` not `tokio::sync::Mutex`, matching `jwks_cache.rs`'s convention of choosing lock type by hold-duration/await-need):
```rust
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
enum BreakerState {
    Closed { consecutive_failures: u32 },
    Open { opened_at: Instant },
}

pub struct HibpBreaker {
    state: Mutex<BreakerState>,
    threshold: u32,    // AXIAM__AUTH__HIBP_BREAKER_THRESHOLD, default 5
    cooldown: Duration, // AXIAM__AUTH__HIBP_BREAKER_COOLDOWN_SECS, default 30
}

impl HibpBreaker {
    pub fn should_attempt(&self) -> bool { /* Closed -> true; Open -> true iff cooldown elapsed (half-open probe) */ }
    pub fn record_success(&self) { /* -> Closed { consecutive_failures: 0 } */ }
    pub fn record_failure(&self) { /* Closed: increment, trip to Open at threshold; Open: re-open, reset opened_at */ }
}
```

**Integration call site** (`crates/axiam-auth/src/policy.rs`, existing code ~line 322):
```rust
if policy.hibp_check_enabled
    && let Some(client) = http_client
    && let Ok(Some(violation)) = check_hibp(password, client).await
{
    violations.push(violation);
}
```
`check_hibp` gains a `&HibpBreaker` param; calls `breaker.should_attempt()` BEFORE the `http_client.get(...).send().await` call (short-circuit to `Ok(None)` with a distinguishing `tracing::warn!` if false — do not wait for the existing 5s timeout). On success path call `record_success()`; on the two existing failure branches (`Err(e)` from `.send()`, non-`is_success()` status) call `record_failure()` before the existing `return Ok(None)`.

**IMPORTANT — do not "add" fail-open behavior:** `check_hibp` already returns `Ok(None)` on every failure branch. The breaker's only job is skipping the network call under sustained failure, not making the function fail-open (already true).

**Pre-sizing (D-05), same file area, distinct target:** `crates/axiam-auth/src/policy.rs::check_complexity` — `let mut violations = Vec::new()` → `Vec::with_capacity(5)` (exactly 5 possible violations: TooShort/MissingUppercase/MissingLowercase/MissingDigit/MissingSymbol). Do NOT invent a path-segment `Vec` in `middleware/authz.rs` — none exists there.

**Wiring:** breaker must be constructed once and shared (`Arc<HibpBreaker>`), e.g. `web::Data<Arc<HibpBreaker>>` in Actix app state, consistent with how `health_checker: Arc<dyn HealthChecker>` is already wired in `crates/axiam-server/src/main.rs`. Grep all `evaluate_password`/`check_hibp` call sites first to decide between app-data threading vs. a `std::sync::OnceLock` process-global if call sites are scattered.

---

### `crates/axiam-authz/src/config.rs` (NEW — config)

**Analog:** `crates/axiam-api-grpc/src/config.rs` (`GrpcConfig`) — exact structural precedent for a new per-crate config section wired into `AppConfig`.

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthzConfig {
    /// AXIAM__AUTHZ__BATCH_MAX_CONCURRENCY, default 16 (kept under ~30-conn DB budget).
    pub batch_max_concurrency: usize,
}
impl Default for AuthzConfig {
    fn default() -> Self { Self { batch_max_concurrency: 16 } }
}
```

Wire into `crates/axiam-server/src/main.rs`'s `AppConfig` exactly as `grpc: GrpcConfig` was added:
```rust
struct AppConfig {
    // ... server, db, auth, grpc, amqp, rate_limit ...
    #[serde(default)]
    authz: axiam_authz::AuthzConfig, // NEW
}
```
Env mapping is automatic via `config::Config::builder().add_source(config::Environment::with_prefix("AXIAM").separator("__"))` — the same mechanism `AXIAM__DB__TOKEN_REFRESH_FRACTION` already uses; no new wiring code beyond struct fields.

**Divergent pattern — do NOT copy:** `crates/axiam-api-rest/src/webhook_consumer.rs::WebhookRetryConfig::from_env()` manually parses `std::env::var(...)` instead of going through the `config` crate/`AppConfig` tree. This is a legacy gap in that file, not the pattern to follow for `AuthzConfig` or the new `DbConfig` fields below.

---

### `crates/axiam-api-grpc/src/services/authorization.rs` (MODIFY `batch_check_access`) / `crates/axiam-api-rest/src/handlers/authz_check.rs` (MODIFY `batch_check_access`)

**Analog:** in-place refactor of the existing sequential `for check_req in req.requests` loop in the same file.

**New dependency required:** add `futures` (or `futures-util`) as a direct `[dependencies]` entry in both `axiam-api-grpc/Cargo.toml` and `axiam-api-rest/Cargo.toml` — `futures-lite` (already a workspace dep, used by `axiam-amqp`) does NOT provide `buffer_unordered`/`FuturesUnordered`. `futures-util 0.3.32` is already resolved transitively in `Cargo.lock`, so this is a zero-network `cargo add`.

**Core pattern** (gRPC — REST is structurally identical, see notes below):
```rust
use futures::stream::{self, StreamExt};

// 1. Validate ALL cross-request checks synchronously, up front (unchanged semantics:
//    any single mismatch rejects the whole batch, same as today's first-error loop).
let validated: Result<Vec<AccessRequest>, Status> = req.requests.iter().map(|check_req| {
    let body_tenant_id = parse_uuid(&check_req.tenant_id, "tenant_id")?;
    let body_subject_id = parse_uuid(&check_req.subject_id, "subject_id")?;
    if body_tenant_id != claims_tenant_id || body_subject_id != claims_subject_id {
        return Err(Status::permission_denied("tenant_id/subject_id mismatch: body does not match token claims"));
    }
    Ok(AccessRequest {
        tenant_id: claims_tenant_id, subject_id: claims_subject_id,
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
        let engine = &self.engine; // &self borrow — no clone/Arc/'static bound needed
        async move {
            let decision = engine.check_access(&req).await.map_err(|e| Status::internal(e.to_string()))?;
            Ok::<_, Status>((i, decision))
        }
    })
    .buffer_unordered(concurrency)
    .collect::<Vec<Result<_, Status>>>().await
    .into_iter().collect::<Result<Vec<_>, Status>>()?;

indexed.sort_by_key(|&(i, _)| i); // restore input order (D-06)
let results = indexed.into_iter().map(|(_, d)| to_check_response(d)).collect();
Ok(Response::new(BatchCheckAccessResponse { results }))
```

**REST-specific note:** the REST handler must ALSO preserve the existing per-item `append_check_as_audit` fire-and-forget call — run it concurrently inside the same mapped future (side effect independent of the decision, no impact on ordering).

**Why `buffer_unordered` over `tokio::task::JoinSet`+`Semaphore`:** the engine/repo generic type params aren't `Clone`-bounded on the gRPC side, and `buffer_unordered` works directly against `&self`-borrowing futures with no `'static`/`Clone` requirement — a hand-rolled `JoinSet` approach would need both.

**Correctness test (D-06 gate):** assert `batch_check_access(requests)` == per-item `check_access` calls collected into a `Vec`, same order, for a fixed request set — proves both ordering and semantic equivalence in one test.

**Bench caveat (PERF-05):** kv-mem SurrealDB is near-zero-latency; the sequential-vs-concurrent win may not show without injecting artificial per-call latency (e.g. `tokio::time::sleep` in a bench-only mock repo) — required for the comparison to be meaningful.

---

### `crates/axiam-db/src/connection.rs` (MODIFY — extend `DbManager::reconnect` seam)

**Analog:** itself — CORR-02's existing `reconnect`/`spawn_proactive_resignin`/`health_check`/`classify_query_error`; backoff naming/shape from `crates/axiam-api-rest/src/webhook_consumer.rs::backoff_ttl_ms` (CORR-03).

**Do NOT copy CORR-03's backoff verbatim — it has no jitter.** `backoff_ttl_ms` is `delay_ms = base_ms * multiplier.powi(exponent); delay_ms.clamp(0.0, ceiling_ms)` — pure deterministic exponential, no random term. PERF-04 must mirror the naming (`base_ms`/`ceiling_ms`, `*2^n`, clamp-to-ceiling) but ADD full jitter:

```rust
use rand::Rng;

/// Full-jitter exponential backoff delay for reconnect attempt `n` (1-indexed).
fn reconnect_backoff_delay(attempt: u32, base_ms: u64, ceiling_ms: u64) -> Duration {
    let exponent = attempt.saturating_sub(1) as i32;
    let capped = (base_ms as f64 * 2f64.powi(exponent)).min(ceiling_ms as f64);
    let jittered_ms = rand::rng().random::<f64>() * capped; // uniform(0, capped)
    Duration::from_millis(jittered_ms as u64)
}
```

**Swappable handle** — `DbManager`'s internal field changes from `Arc<Surreal<Client>>` to `Arc<tokio::sync::RwLock<Surreal<Client>>>`. Exact precedent: `crates/axiam-federation/src/jwks_cache.rs` already wraps shared, occasionally-replaced state in `Arc<RwLock<_>>` the same way.

**Reconnect loop shape** (new task alongside `spawn_proactive_resignin`, reacts to `health_check` failure instead of a fixed timer):
```rust
fn spawn_reconnect_loop(db: Arc<tokio::sync::RwLock<Surreal<Client>>>, config: DbConfig) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            // poll health via read-lock + "RETURN 1", classify via classify_query_error
            // if unhealthy: bounded retry loop with reconnect_backoff_delay(attempt, base_ms, ceiling_ms)
            //   success -> *db.write().await = fresh_handle (old handle dropped — D-12 eviction)
            //   exhausted (attempt >= reconnect_max_retries): stay Unhealthy, keep probing
            //     at ceiling interval FOREVER — never break/return/exit process (D-11)
        }
    })
}
```

**API-breaking change:** `client()` must go through the lock, e.g. `pub async fn client_cloned(&self) -> Surreal<Client> { self.db.read().await.clone() }` — touches ~40 `db.client().clone()) call sites in `crates/axiam-server/src/main.rs` (mechanical `.await` addition; budget as a dedicated task, separate from reconnect-loop logic).

**Config additions** (`DbConfig`, same container-level `#[serde(default)]` + `impl Default` shape as existing `token_refresh_fraction`):
```rust
pub struct DbConfig {
    // ... existing fields ...
    pub reconnect_base_ms: u64,     // AXIAM__DB__RECONNECT_BASE_MS, default 250
    pub reconnect_ceiling_ms: u64,  // AXIAM__DB__RECONNECT_CEILING_MS, default 30_000
    pub reconnect_max_retries: u32, // AXIAM__DB__RECONNECT_MAX_RETRIES, default 10
}
```

**Scope boundary (do not exceed):** there is no `Vec<Surreal<Client>>` connection pool anywhere — AXIAM uses one stateless-HTTP-engine handle inside `DbManager`, plus ~30 independent `.client().clone()` snapshots taken once at startup by repositories. "Poisoned-connection eviction" is scoped to `DbManager`'s own internal handle only; do NOT attempt to thread a shared/swappable handle through the ~30 pre-existing repository clones (out of phase scope, per `26-RESEARCH.md` Pitfall 2 / `26-PATTERNS.md`).

**Test seam to extend:** `crates/axiam-db/tests/connection_resilience_test.rs` (existing `#[ignore]`d live-SurrealDB-gated pattern, e.g. `recovers_from_token_expiry_without_restart`) — add new cases for exhaustion-stays-Unhealthy-but-keeps-probing and poisoned-handle-never-returned-post-swap. Full-jitter backoff unit tests must assert delay falls within `[0, capped]`, never an exact value (non-deterministic by design).

---

### SDK JWKS verifiers (7 files, MODIFY) — uniform hand-rolled single-flight (D-08/D-09)

Common shape across all: double-checked lock — check cache fresh, if not acquire a fetch-guard, re-check cache under the guard, then fetch once; all waiters see the result of the single fetch.

**Rust** (`sdks/rust/src/token/jwks.rs`) — existing `cache: std::sync::RwLock<Option<CachedJwks>>` has a TOCTOU race in `force_refetch_if_allowed` (check-then-fetch, not atomic). Add `fetch_lock: tokio::sync::Mutex<()>`:
```rust
async fn get_or_fetch(&self) -> Result<JwkSet, AxiamError> {
    if let Some(jwks) = self.cached_if_fresh() { return Ok(jwks); }
    let _guard = self.fetch_lock.lock().await; // serializes concurrent fetchers
    if let Some(jwks) = self.cached_if_fresh() { return Ok(jwks); } // re-check under lock
    self.fetch_and_cache(false).await
}
```
Same shape applies to `force_refetch_if_allowed`.

**Python** (`sdks/python/src/axiam_sdk/_jwks.py`) — `threading.Lock` currently guards only the "should-I-invalidate" decision, not the actual fetch. Fix: hold `self._refetch_lock` around the ENTIRE forced-refetch-and-refetch sequence, re-checking cache after acquiring.

**Go** (`sdks/go/internal/jwks/verifier.go`, `sdks/go/jwks.go`) — wraps `lestrrat-go/jwx/v3`'s `jwk.Cache`; add explicit `sync.Mutex` around `v.cache.Refresh(ctx, v.jwksURL)` in the unknown-kid branch — do not rely on unverified library internals.

**Java** (`sdks/java/.../JwksVerifier.java`) — wraps Nimbus `RemoteJWKSet`+`DefaultJWKSetCache`; add explicit `ReentrantLock`/`synchronized` around the refetch call path.

**C#** (`sdks/csharp/Axiam.Sdk/Auth/JwksVerifier.cs`) — currently ZERO synchronization (`Dictionary<string, byte[]>`/`DateTimeOffset` are plain mutable fields). Add `SemaphoreSlim(1, 1)` — reuse the exact primitive already used for the SDK's token-refresh single-flight guard (CS-01), for in-codebase consistency.

**TypeScript** (`sdks/typescript/src/node/jwks.ts`) — delegates to `jose`'s `createRemoteJWKSet`; existing `jwksPromise` lazy-singleton coalesces construction only. Verify with a test (mock global `fetch`, N concurrent `verifyAccessToken()` calls with unknown `kid`, assert exactly 1 call) whether `jose` already coalesces; if not, wrap with the same lazy-promise-singleton pattern (`inFlightFetch: Promise<...> | null`, reset after resolution) already used for `jwksPromise`.

**PHP** (`sdks/php/src/Auth/JwksVerifier.php`) — fully hand-rolled, `$fetchedAt` int TTL, no shared cache. Wrap `ensureFresh` in a Guzzle-promise-based in-flight guard (`sendAsync`/`Promise\Utils::settle`). **Caveat:** classic sync PHP-FPM has no intra-process concurrency (one request per worker process) — a sequential PHPUnit loop cannot exercise a real race. Test must use Guzzle's async interface or explicitly scope to the Swoole/RoadRunner coroutine runtime; document that under classic FPM the guarantee is vacuous by design (cannot be "fixed" without cross-process shared cache, out of scope).

**Do not touch:** the actual JWT/JWK cryptographic verification logic in any of the 7 files (`jsonwebtoken`/`jose`/`jwx/v3`/`PyJWT`/Nimbus/BouncyCastle/`firebase/php-jwt`) — single-flight is a coalescing wrapper only.

---

### Criterion benches (3 NEW files, greenfield)

**Analog:** none in this workspace (no `benches/` dir exists anywhere) — use idiomatic criterion setup:
```toml
# Cargo.toml
[[bench]]
name = "auth_bench"       # or authz_bench / cert_bench
harness = false

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
```
```rust
use criterion::{criterion_group, criterion_main, Criterion, black_box};
fn bench_x(c: &mut Criterion) { c.bench_function("name", |b| b.iter(|| /* call fn */)); }
criterion_group!(benches, bench_x);
criterion_main!(benches);
```

**auth_bench.rs** — target `crates/axiam-auth/src/password.rs::hash_password`/`verify_password` (pure sync) + `crates/axiam-auth/src/token.rs::issue_access_token`. Call `AuthConfig::resolve_keys()` ONCE outside the timed closure (pre-parses Ed25519 PEM) to measure steady-state signing cost only.

**authz_bench.rs** (under `axiam-authz` or `axiam-api-grpc`) — target `crates/axiam-authz/src/engine.rs::AuthorizationEngine::check_access`. Setup: reuse the kv-mem SurrealDB dev-dependency pattern already used by `axiam-authz`'s own tests, or simple fixed in-memory repo stubs for lower-overhead CPU-only measurement.

**cert_bench.rs** — target `crates/axiam-pki/src/mtls.rs`'s isolated `verify_signature` step (NOT full `authenticate()`, which needs DB repos), fixtures via `rcgen` (already an `axiam-pki` dependency) generating a self-signed CA + leaf cert once outside the timed closure.

**Not a CI gate (D-15):** run manually/locally; document `cargo-flamegraph` invocation as a manual step (may not be available in sandbox).

---

### `claude_dev/performance-report.md` (NEW doc)

**Analog:** sibling `claude_dev/*.md` docs (e.g. `security-audit.md`) for tone/format only — content (baseline-vs-optimized numbers per D-16) is greenfield, populated by running the three criterion benches once at phase end.

## Shared Patterns

### Config knob convention
**Source:** `crates/axiam-db/src/connection.rs::DbConfig` (existing `token_refresh_fraction` field), `crates/axiam-api-grpc/src/config.rs::GrpcConfig`
**Apply to:** `AuthzConfig`, new `AuthConfig` fields (hibp breaker), new `DbConfig` fields (reconnect)
- Container-level `#[serde(default)]` + custom `impl Default` — no per-field `#[serde(default = "fn")]` needed.
- Env mapping via `config::Environment::with_prefix("AXIAM").separator("__")` in `crates/axiam-server/src/main.rs::load_config()` — automatic, no new wiring code.
- **Do not** copy `crates/axiam-api-rest/src/webhook_consumer.rs::WebhookRetryConfig::from_env()`'s manual `std::env::var(...).parse()` pattern — that's a pre-existing gap (never added to `AppConfig`), not the convention to extend.

### Shared-mutable-state-behind-a-lock
**Source:** `crates/axiam-federation/src/jwks_cache.rs`
**Apply to:** `HibpBreaker` (std::sync::Mutex, no-await critical section), `DbManager`'s swappable connection handle (tokio::sync::RwLock, read/write across `.await` points)

### Fail-safe-toward-the-safer-state
**Source:** existing `check_hibp` (already fail-open) and CORR-02's `health_check`/`classify_query_error` (Unhealthy = readiness alarm)
**Apply to:** HIBP breaker (fails open — never blocks auth), DB reconnect exhaustion (fails toward Unhealthy — never silently serves a broken connection, never crashes the process)

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `crates/axiam-auth/benches/auth_bench.rs` | test (bench) | batch/transform | No `benches/` dir exists anywhere in the workspace — greenfield criterion tooling |
| `crates/axiam-authz/benches/authz_bench.rs` | test (bench) | batch/transform | Same — greenfield |
| `crates/axiam-pki/benches/cert_bench.rs` | test (bench) | batch/transform | Same — greenfield |
| `claude_dev/performance-report.md` | doc | batch/transform | New deliverable doc; only format precedent exists in sibling `claude_dev/*.md` files, no content analog |

## Metadata

**Analog search scope:** `crates/axiam-auth`, `crates/axiam-authz`, `crates/axiam-api-grpc`, `crates/axiam-api-rest`, `crates/axiam-db`, `crates/axiam-federation`, `crates/axiam-pki`, `sdks/{rust,go,python,java,csharp,typescript,php}`, `claude_dev/`
**Files scanned:** confirmed via 27-RESEARCH.md's direct source reads (primary sources list) plus targeted existence checks in this session (`jwks_cache.rs`, `webhook_consumer.rs`, `axiam-authz/src/*.rs`, `axiam-api-grpc/src/config.rs`)
**Pattern extraction date:** 2026-07-05

## PATTERN MAPPING COMPLETE
