# Rate-limit fix verification (closes H2)

**Status: VERIFIED on this box.** The five commits on
`claude/g-benchmark-improvements-n5mjmj`
(`5212912`, `69109db`, `0fbbd5e`, `1f3da2f`, `7167c18`) remove the synchronous
per-request `UPSERT` that H2 root-caused
(`claude_dev/postseed-transient-investigation.md` §1, §2, §7). All six
previously-clamped endpoints — `POST /api/v1/authz/check`, `POST
/oauth2/token`, `POST /oauth2/introspect`, `POST /oauth2/revoke`, `GET
/api/v1/users` and (partially — see caveats) `POST /api/v1/auth/login` —
escape the 16–21 ops/s band. The H1 settle gate, which H2 §8.1 predicted
"can never pass in an environment like this one," **passed on the first
probe attempt** against this build.

> **Provenance.** Measured 2026-07-29/30, branch
> `claude/g-benchmark-improvements-n5mjmj` @ `7f3ea7d4b5fde83aa9b637320e7cb09db281a046`
> (the crates/ source at HEAD `7167c18` — the one later commit, `7f3ea7d`,
> is a docs-only change from a sibling agent and touches no crate source),
> local image `axiam/server:rl-fix-local` built from that source, server and
> datastore each capped at 2 CPU / 1 GiB (same envelope H2 used),
> `just target=axiam profile=p0-plaintext bench-up`. Shipped defaults:
> `AXIAM__RATE_LIMIT__SHARED=on`, `AXIAM__RATE_LIMIT__SHARED_SYNC_MS=1000`.

---

## 1. What was built

A local server image (`axiam/server:rl-fix-local`) from this branch's actual
source, via `docker buildx build` (not `just ... build=1`, to avoid touching
tracked compose/Dockerfile files). Two **sandbox-only, uncommitted** build
inputs were needed to reach crates.io/complete the build inside this
environment (neither touches a tracked file or the real Dockerfile —
`git status` is clean on this branch throughout):

- A trusted CA bundle (`/root/.ccr/ca-bundle.crt`) installed into the builder
  stage's trust store, via `docker buildx build --build-context
  cabundle=/root/.ccr` — without it, `cargo build`'s crates.io fetches fail
  TLS verification against this sandbox's egress proxy.
- The cached `swagger-ui-5.17.14.zip`
  (`/home/user/.axiam-build-cache/swagger-ui-5.17.14.zip`), copied into the
  image and pointed at via `SWAGGER_UI_DOWNLOAD_URL=file://...` — avoids the
  blocked `github.com` fetch `utoipa-swagger-ui`'s build script otherwise
  makes.

Same `CARGO_FEATURES=jemalloc` default as `docker/Dockerfile.server`. The
temporary Dockerfile lived under `/tmp/rlfix-build/` (never in the repo).
The compose target was pointed at the local image purely via environment —
`BENCH_AXIAM_IMAGE=axiam/server:rl-fix-local BENCH_AXIAM_PULL_POLICY=never`
— which makes `docker compose pull` a documented no-op ("Image ... Skipped")
instead of falling through to a source rebuild; no tracked file in
`benchmarks/` was touched.

## 2. How measured

`benchmarks/runner/h2-clamp-probe.sh`, run exactly as H2's own header
documents (`h2-clamp-probe.sh <op> 1 8` and `<op> 20 15`, one credential
mint outside the measured window, 25 requests per kept-alive curl
connection). No `AXIAM__RATE_LIMIT__SHARED=off` override — the headline
numbers below are the shipped write-behind path with its 1000 ms default
sync interval.

## 3. Before/after clamp map

H2's baseline is `claude_dev/postseed-transient-investigation.md` §2 (its
own provenance: `server:1.0.0-alpha19`, same 2 CPU / 1 GiB caps, rate
limits neutralized). "Escaped?" is judged against §7's success criterion:
land in the band the operation's unwrapped structural sibling occupies.

| operation | endpoint | H2 1 VU ops/s | H2 1 VU p50 | **now** 1 VU ops/s | **now** 1 VU p50 | H2 20 VU ops/s | H2 20 VU p50 | **now** 20 VU ops/s | **now** 20 VU p50 | escaped? |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|:--:|
| health | `GET /health` | 510 | 0.3 ms | **1134.4** | 0 ms | 4248 | 1 ms | **4313.3** | 1 ms | n/a (never clamped) |
| jwks | `GET /oauth2/jwks` | 493–504 | 0.3 ms | **1084.4** | 0 ms | 2992 | 1 ms | **3198.3** | 1 ms | n/a |
| userinfo | `GET /oauth2/userinfo` | 299–302 | 1 ms | **525.0** | 1 ms | 1681 | 9 ms | **1951.7** | 8 ms | n/a |
| resources | `GET /api/v1/resources` | 68–74 | 11–12 ms | **87.5** | 11 ms | 254–280 | 66–74 ms | **306.7** | 65 ms | n/a (the sibling) |
| roles | `GET /api/v1/roles` | 67–74 | 11–13 ms | **81.2** | 11 ms | 256 | 73 ms | **270.0** | 72 ms | n/a (the sibling) |
| **users (list)** | `GET /api/v1/users` | 14–16 | 60–65 ms | **84.4** | 11 ms | 17.9–20.0 | 967–1106 ms | **280.0** | 69 ms | **YES** — now indistinguishable from `resources`/`roles` |
| **authz check** | `POST /api/v1/authz/check` | 16–18 | 55–60 ms | **146.9** | 6 ms | 18.8–21.3 | 907–1061 ms | **583.3** | 30 ms | **YES** |
| **client credentials** | `POST /oauth2/token` | 16–18 | 51–55 ms | **306.2** | 2 ms | 20.0–21.7 | 897–1032 ms | **1231.7** | 14 ms | **YES** |
| **introspection** | `POST /oauth2/introspect` | 17–19 | 49–58 ms | **428.1** | 2 ms | 20.0 | 1002 ms | **1553.3** | 11 ms | **YES** |
| **revocation** | `POST /oauth2/revoke` | 17.3 | 53 ms | **300.0** | 3 ms | — (not recorded by H2) | — | **1266.7** | 13 ms | **YES** |
| **login** | `POST /api/v1/auth/login` | 8–11 | 95–116 ms | **19.4** | 51 ms | 19.2 | 1032 ms | **37.0** | 531 ms | **partial — see §5** |

`pct2xx=100` on every probe cell above (n ranges 175–64 700 requests per
cell); raw TSV: `/tmp/rlfix-build/clamp-after.tsv` (not committed — scratch
output, reproducible via `run_clamp_matrix.sh` pattern below).

Five of six previously-wrapped endpoints now land within noise of their
unwrapped structural siblings (compare `users` 84.4/280.0 to
`resources` 87.5/306.7 and `roles` 81.2/270.0 — the exact "cleanest natural
experiment" H2 §2.1 called out). `login` is the exception; see §5 — it is
**not** a residual instance of H2's clamp.

## 4. Mechanism confirmation

**(a) Startup log line.** Present on every boot, both listeners:

```
{"level":"INFO","fields":{"message":"shared rate-limit counter ACTIVE (write-behind); one datastore write per bucket per sync interval instead of one per request","sync_interval_ms":1000,"shards":16},"target":"axiam_db::rate_limit_counter"}
```
(logged twice per boot — once for the REST `AppState` counter, once for the
gRPC layer's own counter, per `7167c18`'s documented reason for the split.)

**(b) Batched writes, not per-request writes.** `rate_limit_bucket` cleared,
then 6500 `authz_check` requests fired over ~12 s (`h2-clamp-probe.sh authz
10 12`) while sampling `SELECT id, count, updated_at FROM rate_limit_bucket`
roughly once per second:

| sample time (UTC) | `authz_check` count | `updated_at` |
|---|---:|---|
| 00:02:51.593 | 472 | 00:02:51.258 |
| 00:02:53.102 | 1568 | 00:02:53.282 |
| 00:02:54.874 | 2048 | 00:02:54.292 |
| 00:02:56.301 | 3087 | 00:02:56.310 |
| 00:02:57.836 | 3651 | 00:02:57.317 |
| 00:02:59.243 | 4829 | 00:02:59.327 |
| 00:03:00.708 | 154 *(fixed-60s-window rollover at the minute boundary)* | 00:03:00.332 |
| 00:03:02.065 | 1304 | 00:03:02.359 |

6500 requests landed as **8 distinct `updated_at` values across 12 s** —
roughly one write per second, not one per request — while idle buckets
(`login`, `oauth2_token`, untouched after their one-off mint requests) never
moved at all. This is the write-behind flush behaving exactly as
`SharedRateLimitCounter`'s module docs describe.

**(c) Rate limiting still works end-to-end under production limits.**
Fresh stack, `just target=axiam profile=p0-plaintext rl=prod bench-up`
(`AXIAM__RATE_LIMIT__AUTHZ_CHECK_PER_MIN=300`), 20 concurrent curl workers
against `POST /api/v1/authz/check` for 15 s, authenticated user session:

```
total=3407  admitted_200=299  throttled_429=3108  other=0
```

299 admitted is within noise of the configured 300/min budget consumed by
the front of the burst; the remaining 3108 requests in the same 15 s window
were correctly rejected with 429. `other=0` — no unexpected status codes.
The fix moved the counting mechanism off the request path; it did not
change what gets enforced.

## 5. `login` did not fully escape — and that's expected, not a bug

`login` improved (~2×: 8–11→19.4 ops/s @1 VU, 19.2→37.0 ops/s @20 VU) but
stayed far below the other five endpoints' 15–80× jumps. This is **not** a
residual H2 clamp. `login` is the only wrapped endpoint whose handler also
does an Argon2id password verification — a deliberately expensive,
CPU-bound security control (`AXIAM__AUTH__MAX_CONCURRENT_HASHES`, B1 gate,
`crates/axiam-auth/src/config.rs`). Under this bench's 2-CPU server cap,
Argon2id's own cost dominates once the ~40 ms rate-limit write is removed:
observed numbers back-calculate to ~50 ms of real CPU time per hash
(1 VU: 1/0.050s ≈ 20 ops/s, matches 19.4; 20 VU: 2 cores / 0.050s ≈ 40 ops/s,
matches 37.0) — a **2-CPU-cap ceiling on Argon2id**, not a rate-limit
artifact. `login` has no unwrapped structural sibling in H2's map to compare
against (every other wrapped endpoint is a plain lookup/token-mint handler);
this is the honest result, reported as asked.

## 6. Settle gate: PASSED (a first for this environment)

`just target=axiam profile=p0-plaintext scenario=authz_check_rest.js
bench-run`, default thresholds (≥400 ops/s OR p50<150ms @ 20 VU burst,
`BENCH_SETTLE_TIMEOUT_SECS=600`):

```
[run] settle probe #1: 188.7 ops/s, p50 28.076ms, n=2666 samples (elapsed 15s)
[run] settle gate: PASSED (188.7 ops/s / p50 28.076ms) — proceeding after 15s
```

`meta.json`: `"settle_wait_secs": 15, "settle_timeout": false`. The gate
passed on its **first** probe (no retries needed) — H2 §8.1 said this gate
"can never pass in an environment like this one" while the clamp stood; it
now passes immediately.

The full `authz_check_rest` k6 cell (50 VUs, 30 s warmup + 120 s measured)
that followed:

```
bench_ok: 94368  589.570273/s
bench_op_latency_ms: avg=73.75ms p50=75.12ms p95=115.53ms p99=140.7ms
checks: 100.00% (94368/94368), bench_error_rate: 0.00%
```

**589.6 ops/s sustained**, 0% errors — this is the strong signal for the
user's upcoming run-4: authz throughput cells no longer need to be sourced
from a different host.

## 7. Caveat found on the way (not part of H2, reported for completeness)

During testing, ~7 minutes after one `bench-up` boot, **every** SurrealDB-
backed operation on the server started failing with 401 (not just the
rate-limit flusher — `POST /api/v1/auth/login` too, and audit-log writes).
Root cause, read from `crates/axiam-server/src/main.rs` and
`crates/axiam-db/src/pool.rs`: essentially every repository/service in
`main.rs` is built once at boot from `pool.handle_for_repo().await`, a
**one-time clone** of the pool's current `Surreal<C>` handle — not a live
reference. `DbManager`'s own proactive re-signin/reconnect loop (D-03/D-04)
does work, but it only benefits *future* `pool.handle_for_repo()` /
`pool.checkout()` callers; once *any* reconnect event swaps a fresh
connection object into the pool's internal slot, every handle captured at
boot (which is effectively the whole app — org/tenant/user/session/audit/
rate-limit repos, etc.) is left pointing at the old, now-unauthenticated
connection, permanently, until the process restarts. A plain `docker
restart bench-axiam-server` (no reseed needed — data is in the DB volume)
recovered instantly and reproducibly. This is **unrelated to the H2 rate-
limit fix** — it is a pre-existing architectural gap in how the DB pool's
reconnect safety net reaches long-lived consumers — and is being reported
here only because it interrupted this verification run twice and is worth
a follow-up issue on its own. It did not affect the correctness of any
number in §3/§4/§6 above (each was captured on a fresh boot before the
condition recurred).

> **Update — fixed.** `pool.handle_for_repo()` now returns a live `DbHandle`
> (the pool slot itself) instead of a one-time clone, so every repository
> resolves the current connection per query and follows a reconnect-loop swap.
> `AppState.db` and the gRPC handle held the same boot-time clone and were
> fixed the same way. See `db-pool-design.md` §11; regression test:
> `pool::tests::repository_bound_at_boot_follows_a_later_handle_swap`.

## 8. Verdict

**The clamp is gone on this host, for five of the six previously-wrapped
endpoints, without exception, and the sixth (`login`) is bounded by an
unrelated, deliberate Argon2id CPU cost rather than by the removed
rate-limit write.** `GET /api/v1/users` no longer inherits the registration
limiter. The write-behind mechanism is confirmed both structurally (log
line, batched datastore writes) and behaviorally (429s still fire correctly
under production limits). The H1 settle gate — previously guaranteed to
time out on any box with an expensive rate-limit write — passed on its
first attempt, and the `authz_check_rest` k6 cell it gates sustained
589.6 ops/s at 0% errors.
