# Benchmark p0-plaintext Failure Analysis

**Date:** 2026-07-18
**Scope:** `benchmarks/results/axiam/p0-plaintext` (partial run — `userinfo` missing, `token_refresh` aborted at ~12s)
**Verdict:** Neither the server nor the benchmark logic is broken. **The benchmark is measuring AXIAM's own per-IP rate limiter, not the endpoints.** All k6 traffic originates from a single source IP, and the bench compose (`benchmarks/targets/axiam/docker-compose.yml`) does not override the production-default rate limits — so every scenario except JWKS is throttled to a trickle and the other ~400k requests/scenario are near-instant `429 Too Many Requests` rejections.

---

## 1. Evidence

### 1.1 Pass counts correlate exactly with the configured limits

Defaults from `crates/axiam-api-rest/src/config/rate_limit.rs` (env-overridable via `AXIAM__RATE_LIMIT__*`, **not overridden anywhere in the bench stack** — `grep RATE_LIMIT benchmarks/targets/axiam/docker-compose.yml` → 0 hits):

| Scenario | Passes | Fails | Governing limit (per IP) | Ratio check |
|---|---:|---:|---|---|
| `oauth2_password_login` | 72 | 407,060 | `login_per_min = 10` | baseline |
| `token_introspection` | 72 | 416,041 | `introspect_per_min = 10` | identical limit → **identical pass count (72 = 72)** |
| `oauth2_client_credentials` | 145 | 403,143 | `token_per_min = 20` | 2× limit → **~2× passes (145 ≈ 2×72)** |
| `authz_check_rest` | 2,189 | 409,478 | `authz_check_per_min = 300` | 30× limit → **~30× passes (2,189 ≈ 30×72)** |
| `authz_check_grpc` | 10,926 | 159,443 | `grpc_authz_per_sec = 100` (`AXIAM__GRPC__GRPC_AUTHZ_PER_SEC`, `crates/axiam-api-grpc/src/config.rs:16`) | 100/s × ~155s ≈ 15.5k budget → 10.9k under contention |
| `authz_batch_rest` | 2,184 | 4,451 | same authz bucket; batch iterations are slower → far fewer total requests → higher pass *ratio*, same pass *count* (2,184 ≈ 2,189) |
| `authz_batch_grpc` | 1,018 | 2,355 | same shape |
| `token_refresh` | 20 | 6 | see §2.2 — run aborted at ~12s | |
| `jwks_fetch` | 3,453,457 | **0** | **`/oauth2/jwks` has no rate-limit wrapper** (`crates/axiam-api-rest/src/server.rs:269`) | the one unthrottled endpoint → the one 100% scenario |

The linear scaling of pass counts with the configured per-minute limits (10 → 72, 20 → 145, 300 → 2,189, all over the same ~160s window) is conclusive: the ceiling is the limiter, not endpoint capacity.

Passes exceed the naive `limit × minutes` budget (e.g. 72 > 10/min × 2.7min ≈ 27) because two limiter layers cooperate and both leak a little under this load: the SurrealDB-backed shared pre-check (`rate_limit_shared.rs`) **fails open by design** (D-01b) when the shared store is slow/unreachable — and the DB was saturated by ~2,500 bucket-CAS round-trips/sec — plus the in-memory governor grants a burst allowance. Neither is a bug; both are documented behavior.

### 1.2 Failures are fast 429s, not server errors or timeouts

From `oauth2_password_login.k6.json`: 407,132 requests at **2,544 req/s** sustained, median latency **17 ms**, `http_req_failed = 99.98%`. A 2-CPU container cannot *fail* 2,500 Argon2id logins/sec — Argon2id verification alone costs ~100ms of CPU. It can, however, *reject* 2,500 req/s at the outermost middleware before any real work happens. The server container's own CPU stayed low during these scenarios (`*.res.csv`: ~0.02–0.8 cores) while **SurrealDB ran at ~1.0–1.1 cores — that's the shared rate-limit bucket CAS being hammered once per rejected request**, not authentication work.

### 1.3 `k6_exit_code: 99` in every failing meta.json

Exit 99 is k6's "thresholds crossed" code. The harness's validity gate (`checks rate > 0.99`, from `BENCH_MAX_ERROR=0.01` in `scenarios/lib/config.js`) correctly flagged every throttled run as invalid. The harness worked as designed — it told us the numbers are unusable; it just couldn't tell us why.

### 1.4 What this rules out

- **Wrong credentials / bad seeding** — then `jwks` wouldn't matter, but more decisively login would fail 100%, not succeed at exactly the limiter's rate.
- **Account lockout (`axiam-auth/src/lockout.rs`)** — lockout counts *failed password attempts*; the benchmark always sends the correct password. 429s never reach the credential check.
- **Server capacity collapse** — median rejection latency 17ms, flat; a collapsing server shows rising latencies and timeouts.
- **CSRF / cookie handling bugs in the scenarios** — `authz_check_rest` passes 2,189 times with the same session; a CSRF bug fails 100% of the time, not 99.5%.

---

## 2. Secondary findings

### 2.1 The comparison would be unfair even if it "worked"

Keycloak and Zitadel ship **without** per-IP request limits by default, so any head-to-head number taken with AXIAM's limiter active is apples-to-oranges. The bench design doc's own premise ("performance per resource meaningful and equal across targets") requires the limiter to be neutralized — or applied to all targets equally.

### 2.2 `token_refresh` scenario burns requests invisibly when minting fails

`token_refresh.js` mints a per-VU token via `mintToken()`, which hits `/oauth2/token` — itself limited to 20/min. With 50 VUs, ~49 of them can never mint; `mintToken()` **throws**, aborting the iteration *without recording `bench_ok`/`bench_failed`* (10,281 iterations, but only 26 logical ops recorded; 20,568 HTTP requests ≈ 2 doomed mint attempts per iteration). The k6 summary's headline error metrics under-report this scenario. The run was also interrupted after ~12s (10,281 iterations ÷ 858 it/s), and `userinfo` never ran — consistent with the "partial" run.

### 2.3 Even with raised limits, every limited endpoint pays a SurrealDB round-trip per request

The shared pre-check performs a windowed-CAS increment against the `rate_limit_bucket` table on **every** request to a limited endpoint, *even when allowed*. Raising the limits does not remove that cost — the benchmark will then honestly measure the product's real hot path (correct for AXIAM-only numbers), but note the bucket row (`"{endpoint}:{ip}"`) becomes a single-record write hotspot when all load comes from one IP. Expect this to be the dominant cost for `authz_check_rest` at p0. This is worth a deliberate product decision, not a silent bench hack (see Plan, step 3).

---

## 3. Fix plan

### Step 1 — Neutralize rate limits in the bench target (no product code changes)

Add env overrides to the `axiam-server` service in `benchmarks/targets/axiam/docker-compose.yml`, parameterized so the prod-posture run remains possible:

```yaml
# Rate limits: neutralized by default so benchmarks measure endpoint capacity,
# not the limiter. Set BENCH_RATE_LIMITS=prod to benchmark the production posture.
AXIAM__RATE_LIMIT__LOGIN_PER_MIN:        "${BENCH_RL:-1000000}"
AXIAM__RATE_LIMIT__TOKEN_PER_MIN:        "${BENCH_RL:-1000000}"
AXIAM__RATE_LIMIT__INTROSPECT_PER_MIN:   "${BENCH_RL:-1000000}"
AXIAM__RATE_LIMIT__REVOKE_PER_MIN:       "${BENCH_RL:-1000000}"
AXIAM__RATE_LIMIT__AUTHZ_CHECK_PER_MIN:  "${BENCH_RL:-1000000}"
AXIAM__RATE_LIMIT__MFA_PER_MIN:          "${BENCH_RL:-1000000}"
AXIAM__RATE_LIMIT__REGISTER_PER_MIN:     "${BENCH_RL:-1000000}"
AXIAM__RATE_LIMIT__PASSWORD_RESET_PER_MIN: "${BENCH_RL:-1000000}"
AXIAM__GRPC__GRPC_AUTHZ_PER_SEC:         "${BENCH_RL_GRPC:-1000000}"
```

Notes: all values are `u32` (1,000,000 fits); `RateLimitConfig::validate()` only requires ≥1; the gRPC quota math was already fixed to treat the value as tokens/sec (see the CORR-01 comment in `axiam-api-grpc/src/middleware/rate_limit.rs:167-179`), so a large value is safe there too. Verify the exact env-var casing against the config loader before committing (the REST doc comment says `AXIAM__RATE_LIMIT__LOGIN_PER_MIN`; gRPC says `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC`).

### Step 2 — Record the limiter posture in run metadata

Extend `runner/run-benchmark.sh` to write a `rate_limits: "neutralized" | "prod"` field into each `*.meta.json`, and have `runner/report.py` refuse to aggregate head-to-head comparisons across mixed postures. This prevents a silent repeat of this incident.

### Step 3 — Decide the shared-limiter story for single-replica benches (product decision, optional)

Even neutralized, every limited endpoint does one `rate_limit_bucket` CAS per request (§2.3). Options:
- **(a) Accept it** (recommended for the primary numbers): it is the real production hot path; publishing it is honest.
- **(b) Add `AXIAM__RATE_LIMIT__SHARED=false`** for explicitly single-replica deployments, skipping the DB pre-check and relying on the in-memory governor alone. Legitimate product feature (the shared store exists only to close the multi-replica HPA gap), but it is a server code change and a security-posture knob — route it through the normal roadmap/review process, and if added, benchmark both ways.

### Step 4 — Harden the `token_refresh` scenario

In `scenarios/token_refresh.js` / `lib/auth.js`: catch `mintToken()` failures inside the default function, record them as `bench_failed`, and back off (`sleep`) instead of throwing — so a misconfigured target produces honest error metrics instead of unrecorded burned iterations. With Step 1 in place the 50 VU mints will succeed anyway, but the harness should degrade legibly.

### Step 5 — Re-run and validate

1. `just bench-down && just target=axiam profile=p0-plaintext bench-up && just bench-seed`
2. Re-run **all** scenarios (this also fills in the missing `userinfo` and the truncated `token_refresh`).
3. Acceptance criteria per scenario:
   - `k6_exit_code: 0` and `checks rate ≥ 0.99`;
   - `oauth2_password_login` throughput in a plausible Argon2id range for 2 CPUs (order of 10–40 op/s, **not** 2,500/s of anything);
   - `bench-axiam-server` CPU near its 2-core cap during hot scenarios (it, not SurrealDB's limiter table, should be the bottleneck — SurrealDB doing real query work is fine);
   - `jwks_fetch` unchanged (sanity anchor).
4. Only then proceed to p1–p3 TLS profiles and competitor targets — with the same posture recorded in meta.

---

## 4. TL;DR

| Question | Answer |
|---|---|
| Is the server broken? | No — it enforced its documented per-IP limits perfectly. |
| Is the benchmark logic broken? | No — scenarios, sessions, CSRF, and per-VU refresh chains are correct; the validity gate even flagged the runs. |
| What's wrong? | The bench compose never overrides the production-default rate limits, and k6 is a single IP. Every scenario except the unthrottled JWKS endpoint benchmarked the 429 path. |
| Fix | Env-only override in the bench compose (Step 1), posture stamped into metadata (Step 2), scenario hardening (Step 4), full re-run (Step 5). |
