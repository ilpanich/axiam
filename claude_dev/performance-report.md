# AXIAM — Performance Report (PERF-05)

- **Date**: 2026-07-05
- **Scope**: Three critical hot paths — authentication (Argon2id password hashing/verify + EdDSA access-token mint), authorization (RBAC `check_access` single-call cost, and the concurrent `BatchCheckAccess` optimization from PERF-02), and cert-validation (X.509 chain `verify_signature` used by mTLS device authentication).
- **Method**: Greenfield `criterion` (v0.8.2, `html_reports` feature) micro-benchmarks added under each owning crate's `benches/` directory — `crates/axiam-auth/benches/auth_bench.rs`, `crates/axiam-authz/benches/authz_bench.rs`, `crates/axiam-pki/benches/cert_bench.rs`. Each bench calls ONLY the existing, already-correct crypto/verification/decision function — no `src/` file in `axiam-auth`, `axiam-authz`, or `axiam-pki` was modified to produce these numbers. All three were run once, locally, in this sandbox and the numbers below are pasted directly from that run.
- **Environment**: 4 vCPU Intel(R) Xeon(R) Processor @ 2.10GHz, `rustc 1.94.1`, `cargo 1.94.1`, release (`bench`) profile.
- **Companion documents**: `claude_dev/security-review.md` / `security-review-postremediation.md` (sibling docs — format precedent only, no content relation).

**These benches are manual/local tooling only. They are NOT wired into CI and this report is NOT a CI regression gate (D-15).** `cargo bench -p <crate>` is a developer-run command; no pipeline currently fails a build based on these numbers, and none is planned for this milestone. The report exists purely as a documented, reproducible snapshot (D-16).

---

## Executive summary

All three PERF-05 bench targets exist, compile, and were run to completion:

| Path | Baseline | Optimized | Evidence of a real optimization? |
|---|---|---|---|
| Auth — Argon2id hash/verify | ~18.3 ms/op | — | No new optimization this phase; numbers confirm OWASP-recommended params (`m=19456`, `t=2`, `p=1`) keep per-request cost well under typical login-latency budgets |
| Auth — EdDSA token mint | ~22.2 µs/op (steady state, keys pre-parsed via `resolve_keys()`) | — | Confirms CQ-B14's parse-once key cache keeps signing cost to pure Ed25519 math, not PEM re-parsing |
| Authz — single `check_access` | ~1.45 ms/op (seeded kv-mem) | — | Baseline CPU cost of one RBAC decision; not itself optimized this phase |
| Authz — 20-item `BatchCheckAccess` | **95.9 ms** (sequential, ≈ 1×RTT-serialized) | **11.4 ms** (`buffer_unordered(16)`) | **Yes — ≈8.4× faster.** This is PERF-02's concurrent-batch win, made measurable by injecting a realistic 2 ms per-call latency (kv-mem itself is near-zero-latency; RESEARCH Open Question 2) |
| Cert-validation — X.509 chain `verify_signature` | ~49.3 µs/op | — | Confirms the mTLS device-auth crypto step (SEC-024) is cheap relative to the DB round-trips `authenticate()` also performs; not itself optimized this phase |

The only path with a genuine "baseline vs. optimized" comparison in this phase is authorization batch-checking (PERF-02); the other four numbers are steady-state baselines recorded for future regression comparison (criterion supports saved-baseline diffing via `cargo bench -- --save-baseline <name>` for that purpose, not exercised in this report).

---

## 1. Auth — password hashing (Argon2id)

**Bench:** `crates/axiam-auth/benches/auth_bench.rs` → `hash_password` / `verify_password`
**Target:** `crates/axiam-auth/src/password.rs::hash_password` / `verify_password` (OWASP params: `m=19456` KiB / 19 MiB, `t=2`, `p=1`)

| Function | Min | Median | Max |
|---|---|---|---|
| `hash_password` (fresh salt) | 18.289 ms | 18.364 ms | 18.439 ms |
| `verify_password` (steady state, hash built once outside the timed closure) | 18.237 ms | 18.305 ms | 18.370 ms |

Hash and verify cost are, as expected, nearly identical — both run the same Argon2id computation once. ~18.3 ms/op is well inside acceptable login-endpoint latency budgets (target <100 ms for the whole login round trip) and matches OWASP's guidance that these parameters trade a deliberately non-trivial CPU cost for brute-force resistance.

## 2. Auth — EdDSA access-token mint

**Bench:** `crates/axiam-auth/benches/auth_bench.rs` → `issue_access_token`
**Target:** `crates/axiam-auth/src/token.rs::issue_access_token`, with `AuthConfig::resolve_keys()` called ONCE outside the timed closure (steady-state signing cost — matches production, which pre-parses the Ed25519 PEM once at startup, CQ-B14).

| Function | Min | Median | Max |
|---|---|---|---|
| `issue_access_token` (steady state) | 22.125 µs | 22.188 µs | 22.248 µs |

Three orders of magnitude cheaper than password hashing, as expected for Ed25519 signing vs. Argon2id — token minting is not a hot-path bottleneck.

## 3. Authz — single `check_access`

**Bench:** `crates/axiam-authz/benches/authz_bench.rs` → `check_access (single, seeded kv-mem)`
**Target:** `crates/axiam-authz/src/engine.rs::AuthorizationEngine::check_access` against a seeded kv-mem SurrealDB graph (one org/tenant/user, a global role+permission grant) — this measures decision-engine overhead (role/permission/resource-hierarchy resolution + kv-mem round-trips), not the artificial latency used in the batch bench below.

| Function | Min | Median | Max |
|---|---|---|---|
| `check_access` (single) | 1.4314 ms | 1.4521 ms | 1.4747 ms |

## 4. Authz — `BatchCheckAccess` sequential vs. concurrent (PERF-02 evidence)

**Bench:** `crates/axiam-authz/benches/authz_bench.rs` → `authz_batch_check_access` group
**Target:** a 20-item batch of `check_access` calls, each wrapped (bench-only, `engine.rs` untouched) with an injected `tokio::time::sleep(2ms)` to simulate a realistic DB round-trip — kv-mem itself is near-zero-latency, so without this the sequential-vs-concurrent difference would not be meaningful (RESEARCH Open Question 2). "Sequential" awaits each call in order (equivalent to `buffer_unordered(1)`); "concurrent" uses `futures::stream::buffer_unordered(16)`, matching `AXIAM__AUTHZ__BATCH_MAX_CONCURRENCY`'s default of 16.

| Variant | Min | Median | Max |
|---|---|---|---|
| Sequential (baseline) | 95.562 ms | 95.921 ms | 96.299 ms |
| Concurrent `buffer_unordered(16)` (optimized) | 11.369 ms | 11.442 ms | 11.518 ms |

**Speedup: ≈8.4× (95.921 ms → 11.442 ms, median-to-median).** This is the concrete baseline-vs-optimized evidence for PERF-02's acceptance criterion ("concurrent batch faster than sequential baseline") — the 20-item batch drops from a fully-serialized ~20×2ms+overhead latency profile toward the expected ~⌈20/16⌉×2ms+overhead profile once requests are allowed to overlap.

**Caveat:** this uses an injected-latency simulation against embedded kv-mem SurrealDB, not a live SurrealDB instance (`just dev-up`) with real network RTT — no live SurrealDB was confirmed running in this sandbox session. The 2 ms injected value is a reasonable stand-in for a local-network DB round-trip; a live-DB run would be expected to show a similar or larger relative speedup (real RTT variance and connection-pool contention would only make the sequential case look worse, not better).

## 5. Cert-validation — X.509 chain verify

**Bench:** `crates/axiam-pki/benches/cert_bench.rs` → `cert_verify_signature (X.509 chain verify)`
**Target:** the isolated `client_x509.verify_signature(Some(ca_x509.public_key()))` step from `crates/axiam-pki/src/mtls.rs::DeviceAuthService::authenticate` (NOT the full `authenticate()` flow, which also requires DB repository round-trips). Fixtures — a self-signed CA + one Ed25519 leaf cert signed by it — are built once via `rcgen` outside the timed closure; each iteration parses both DER certs (`x509_parser::parse_x509_certificate`) fresh and then verifies, mirroring the per-request work `authenticate()` actually performs (only the DB lookups are excluded).

| Function | Min | Median | Max |
|---|---|---|---|
| `cert_verify_signature` (parse + verify) | 49.047 µs | 49.313 µs | 49.580 µs |

Sub-50-microsecond cost confirms the cryptographic chain-verify step is not the bottleneck in mTLS device authentication — the DB fingerprint lookup and CA-cert fetch in the full `authenticate()` flow dominate end-to-end latency, not this crypto step.

---

## 6. A2 post-mortem — `token_refresh` round-trip reduction (fix landed, measurement pending)

**The regression this addresses** (`improvement-after-run5-benchmark.md` §A2):
run 5 measured `token_refresh` at 545 req/s, p50 88.8 ms, against run 4's 839
req/s, p50 47.5 ms — a −35% throughput regression with tight medians in both
runs, the signature of added serialized per-request work rather than
contention or a slow tail. The suspect was the 53-commit post-run-4 security
series that added two datastore round trips to the refresh-rotation path.

**The fix** landed in `98a8b79` (`perf(auth): cut refresh rotation from five
datastore round trips to three (A2/J2)`), verified here via `git show --stat
98a8b79` and by reading the diff (`crates/axiam-auth/src/service.rs`,
`crates/axiam-api-rest/src/handlers/auth.rs`, `crates/axiam-api-rest/src/tenant_org_cache.rs`).
Two round trips were removed, neither by weakening a security property:

- `consume_by_token_hash` collapses the session read and the single-use
  consume into one statement (`DELETE ... WHERE token_hash = $h RETURN
  BEFORE`), closing a read-then-delete race window in the process rather than
  merely making it faster.
- The per-refresh tenant read (added post-run-4 so `org_id` comes from the
  server's own view of the tenant, not the client-supplied body) is now
  served from a small TTL cache. A tenant's owning organization is immutable,
  so re-reading it on every refresh bought nothing; the cache degrades to
  today's one-read-per-request behavior, never to unbounded growth.

Single-use rotation, the pre-mint user-status check, and consuming (rather
than stranding) an expired token are all unchanged and covered by existing
tests. A new round-trip budget test wraps the session repository in a
counting delegate and fails a rotation that makes more than two
session-repository calls, so a future regression on this path is caught
mechanically rather than only by benchmark.

**Measurement status: PENDING.** This section documents the fix and its
mechanism only — it does **not** report a re-measured throughput or latency
number, because no benchmark pass has been run against the fixed code. The
re-measurement is the `token_refresh` re-measure row of
`remediation-plan-2026-08-15.md` Wave R7 (source obligation: A2 §5),
blocked on the same one full benchmark session everything else in that wave
is blocked on. Until that pass runs and publishes a result, treat the A2
regression as **fixed in code, unverified in throughput** — do not infer or
imply a recovered req/s or p50 figure from the round-trip count alone.

---

## Profiling — `cargo-flamegraph` (documented, not run)

Per RESEARCH Environment Availability, flamegraph generation requires OS-level profiling support (`perf` on Linux) that is typically unavailable/unpermitted in a constrained sandbox. This was confirmed in this session:

```console
$ command -v perf
# (not found)
$ cargo flamegraph --version
error: no such command: `flamegraph`
```

Neither `perf` nor the `cargo-flamegraph` subcommand is installed in this sandbox. Flamegraph generation is deferred to a developer's local machine with `perf`/`dtrace` support. The invocation to run there, once installed (`cargo install flamegraph`):

```bash
# Auth hot path
cargo flamegraph --bench auth_bench -p axiam-auth -- --bench

# Authz hot path (single check + batch comparison)
cargo flamegraph --bench authz_bench -p axiam-authz -- --bench

# Cert-validation hot path
cargo flamegraph --bench cert_bench -p axiam-pki -- --bench
```

Each produces an interactive `flamegraph.svg` in the working directory, useful for drilling into where within `hash_password`/`check_access`/`verify_signature` time is actually spent (e.g. confirming Argon2id's memory-fill phase dominates `hash_password`, as expected).

---

## Reproducing these numbers

```bash
cd /home/user/axiam
cargo bench -p axiam-auth    # hash_password, verify_password, issue_access_token
cargo bench -p axiam-pki     # cert_verify_signature
cargo bench -p axiam-authz   # check_access (single) + sequential-vs-concurrent batch
```

Each command is scoped to a single crate (per CLAUDE.md build-hygiene guidance — never an unscoped workspace `cargo bench`). HTML reports (via the `html_reports` criterion feature) are written to `target/criterion/<bench-name>/report/index.html` per bench for local visual inspection; these HTML artifacts are not committed to the repository (`target/` is gitignored).

**Not a CI gate:** these commands are developer-run only. No GitHub Actions workflow invokes `cargo bench`, and none is planned as part of this milestone (D-15) — criterion's statistical sampling is well-suited to local before/after comparison during development, but wiring it into CI would introduce perf-flakiness from shared-runner noise (T-27-41, accepted risk, no CI gate).
