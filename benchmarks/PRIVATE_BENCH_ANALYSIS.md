# PRIVATE — Benchmark Post-Mortem & Improvement Plan

> Internal working document. Companion to `PUBLIC_BENCH_ANALYSIS.md`; same
> dataset (single full-matrix run of 2026-07-19, AXIAM 1.0.0-alpha vs
> Keycloak 26.7.0 vs Zitadel v4.15.2, p0-plaintext + p2-tls13, 50 VUs,
> 2 CPU / 1024 MiB caps for servers and DBs). This file collects everything we
> should NOT publish as-is: harness bugs, unexplained anomalies, tuning
> hypotheses, and AXIAM work items derived from the raw data.

## 1. Harness bugs that invalidated cells (fix before the next run)

### 1.1 `userinfo` uses a client-credentials token → 100% errors on AXIAM and Keycloak

`scenarios/userinfo.js` calls `mintToken()` (`scenarios/lib/auth.js`), which
tries `clientCredentials` **first**. AXIAM and Keycloak correctly refuse a
service-account token at `/userinfo` (no user subject / missing `openid`
scope), so both targets fail every request — 1.66 M error responses for AXIAM
at ~10 k/s, which also means the "throughput" in `report.md` for those cells is
the error path. Zitadel passes only because its machine user is a first-class
user identity.

Fix: `userinfo.js` must use a *user* token — `loginSession()` for AXIAM,
ROPC for Keycloak — and the Keycloak adapter's `clientCredentials()` should
also request `scope=openid` so its tokens are userinfo/OIDC-capable when a
service-account comparison is intended. Bonus: after this fix userinfo becomes
a real 3-way comparison (Zitadel's 258–281 req/s at p95 ~270 ms looks very
beatable: its Postgres was pegged at 2.03 cores in that cell).

### 1.2 Keycloak ROPC (password login) → 100% errors

The seed *does* create the client with `directAccessGrantsEnabled: true` and
the user with a non-temporary password, but every `grant_type=password`
request failed in both profiles, and the seed script swallows provisioning
errors (`|| true` on the client and user `POST`s) — a 409/400 there would go
unnoticed and produce exactly this outcome. Actions:

- Remove the `|| true`s; assert HTTP 2xx on every seed call.
- Add a **post-seed smoke check** to `runner/seed.sh` for every target: one
  real request per scenario-critical flow (ROPC, CC, introspect, refresh,
  userinfo, authz) that hard-fails the run *before* burning 2 × 10 × 160 s of
  benchmark time on a mis-seeded target.
- Capture a sample response body for failed checks into the results dir —
  today the k6 summary only records pass/fail counts, so diagnosing "status
  is 200: 0 passes / 3824 fails" requires re-running by hand.

### 1.3 The password-login comparison is three different operations

- AXIAM: real Argon2id login (`/api/v1/auth/login`).
- Keycloak: real ROPC (currently failing per 1.2).
- Zitadel: adapter silently falls back to `client_credentials` → **no password
  hash at all**; its 393–405 req/s "login" is incomparable and flattering.

Options: (a) drive Zitadel's session/login API v2 (it is scriptable over
HTTP) for a true login; (b) mark the Zitadel login cell non-comparative in
`report.py` the way authz cells already are; at minimum (b) before the site
publishes anything. Also document each vendor's password hash + parameters
(AXIAM: Argon2id/OWASP; Keycloak 26: Argon2id default; Zitadel: bcrypt by
default) — hash choice dominates this scenario and readers must know.

### 1.4 `token_refresh` silently degrades on targets without CC refresh tokens

Zitadel issues no refresh token on client-credentials, so each iteration does
`mintToken()` (untimed) + a *fallback* `clientCredentials` op (timed) — hence
its "refresh" throughput is exactly half its CC throughput (201 vs 396). The
scenario should **tag the op actually measured** (e.g. a k6 tag / meta field
`measured_op: refresh|issuance_fallback`) so `report.py` can label or exclude
fallback cells instead of presenting them as refreshes. Real fix, same as 1.3:
obtain a user-grant refresh token for Zitadel via its login API.

### 1.5 meta.json is missing fields the methodology promises

`docs/methodology.md` §7 says every record embeds the *image digest* and
scenario file hash; `runner/run-benchmark.sh` currently records neither (no
`image`/`digest` key exists in any meta.json of this run — I checked). We
also don't record host kernel, docker version, CPU model/frequency, or the
`BENCH_BATCH_SIZE`. Add them — without the AXIAM image digest we cannot even
say precisely which alpha build produced these numbers.

## 2. Benchmark-coverage gaps (what the next rounds should add)

1. **Zitadel gRPC.** We benchmarked AXIAM's gRPC authz but no competitor gRPC
   at all. Keycloak has none — fine. **Zitadel's primary API surface is gRPC**
   (auth, management, session services): add a `zitadel` gRPC adapter and at
   least token-adjacent + session flows so AXIAM's Tonic stack is compared
   against Zitadel's Go gRPC stack, not only REST. k6 already does gRPC
   (we use it for AXIAM), so this is adapter + proto work only.
2. **gRPC over TLS.** The bench pins AXIAM gRPC to plaintext :50051 in every
   profile (`BENCH_GRPC_PLAINTEXT=true`, see `scenarios/lib/config.js`) — the
   p2 "gRPC" numbers are plaintext gRPC while REST pays TLS. Terminate TLS on
   the gRPC listener too (tonic/rustls) or the p2 matrix is internally
   inconsistent.
3. **p1-tls12 and p3-mtls were not run.** p3 especially matters — mTLS
   client-cert auth is a core AXIAM/IoT story (and see §4.4: today AXIAM
   can't even do p3 without nginx).
4. **Median of ≥3 runs** (methodology §7). Single-run deltas like Zitadel's
   "+32% under TLS" on jwks are obviously noise; the public doc had to
   hand-wave this. `report.py --repeat` support exists on paper — wire
   `bench-matrix` to actually do N passes and aggregate.
5. **Saturation studies / open-loop load.** Closed-loop 50 VUs measures
   "throughput at 50 concurrent users", conflating latency with capacity, and
   caps fast endpoints (AXIAM jwks at 27 k/s was generator/loop-limited:
   server CPU only 1.27/2 cores). Add a `constant-arrival-rate` executor
   variant and/or a VU sweep (50→100→200…) recording the knee point. Also
   assert and *record* k6 host CPU headroom per run (methodology promises
   this gate; the sampler currently samples only target containers).
6. **Prod-posture run.** All AXIAM numbers here have rate limits neutralized —
   correct for capacity comparison, but we should also publish one clearly
   labeled `rl=prod` AXIAM-only run so operators see the shipped defaults'
   throughput envelope (and competitors' *lack* of default per-IP limiting can
   be presented as an AXIAM security advantage rather than a benchmark
   asterisk).
7. **SDK client benches** (all 7 wired per `sdk/README.md`) and the deferred
   **AMQP async-authz harness** — both still unexercised; the AMQP one needs
   the custom (non-k6) publisher/consumer harness already sketched in
   `README.md`.
8. **Warm-up/steady-state validation.** Keycloak's JVM likely benefits from
   longer warm-up than 30 s (JIT); consider per-target warm-up override and a
   time-series sanity plot per cell (the res.csv already has 1 s resolution —
   plot it) to confirm steady state before trusting a 120 s window.
9. **Measure (don't just fear) thermal throttling.** The XPS 15 9570
   (i7-8750H) throttles under sustained all-core load — but this run's data
   shows no sign that *variable* throttling skewed comparisons: load was
   moderate (≤ ~4/12 threads) and CPU-bound cells repeated far apart in the
   2-hour session agree within noise (AXIAM introspection 2199 vs 2192 req/s
   ~27 min apart; CPU-pegged Keycloak CC 143 vs 138 ~17 min apart). What the
   data *cannot* exclude is a constant reduced sustained clock deflating all
   absolute numbers equally, because `docker stats` utilization is
   clock-blind. So: add CPU frequency + temperature columns to
   `resource/sampler.sh` (host-side) and publish them in the report, pin the
   CPU governor to `performance`, consider a no-turbo stability mode, and
   note that a desktop/server re-run is deferred until hardware is available
   (no VM budget at present) — the laptop remains the reference host for now.

## 3. Database bottleneck: findings + tuning plan

Per-container CPU averages (measure window) show three regimes — AXIAM
DB-bound, Keycloak server-bound, Zitadel DB-bound — detailed in the public
doc §3. Internal takeaways:

### 3.1 SurrealDB is AXIAM's ceiling in this envelope

SurrealDB pegged its 2-core cap on `authz_check_*` (2.02/1.88 avg) and ran
1.7+ cores on `oauth2_client_credentials`/`token_refresh` while `axiam-server`
never exceeded ~1.0 core on those flows. Actions:

- **Sensitivity run: uncap the DB** (`BENCH_DB_CPUS=4` or unlimited) for one
  AXIAM-only pass to measure how far the *server* scales when the DB isn't the
  wall. Cheap and hugely informative; do the same for Zitadel/Postgres for
  fairness if published.
- **Tune SurrealDB instead of just uncapping**: we run `surrealdb/surrealdb:v3`
  with stock flags + SurrealKV on a laptop NVMe. Investigate: in-memory vs
  surrealkv backend for the bench (durability parity question below),
  SurrealDB query/transaction cache settings, and AXIAM-side connection-pool
  sizing (is the pool large enough that the DB, not pool contention, is truly
  the limit? — server idle + DB pegged suggests yes, but verify).
- **Durability parity check (fairness):** Postgres 16 defaults to
  `synchronous_commit=on` (fsync per commit); confirm what SurrealKV's flush
  semantics are in v3 defaults. If the two sit at different durability points,
  either align them or disclose it — token_refresh/introspection are
  write-heavy enough for this to matter.
- **Postgres tuning for competitors** (fairness in the other direction):
  stock `postgres:16-alpine` has 128 MB `shared_buffers`, tiny
  `work_mem`. Zitadel is Postgres-bound in this envelope; a minimally tuned
  Postgres (shared_buffers ≈ 256 MB within the 1 GiB cap, appropriate
  max_connections) is the honest competitor configuration. Keycloak won't
  care (its DB is idle) but apply uniformly.
- **Report should attribute bottlenecks automatically**: `report.py` already
  has per-container samples; emit a `bottleneck: server|db|broker|none` tag
  per cell (container avg ≥ ~95% of its cap) so this analysis doesn't have to
  be redone by hand every run.

### 3.2 RabbitMQ shows periodic 1-core spikes

`bench-axiam-rabbitmq` averages 0.1–0.3 cores but p95 ≈ 1.0 core in nearly
every scenario — periodic bursts (audit/event publishing flushes) that
consume CPU inside AXIAM's measured footprint but deliver value competitors
aren't providing (signed audit trail). Options: sample the broker's queue
depths during runs to confirm audit ingestion keeps up; consider batching
audit publishes on the server side; and in the report, break the efficiency
metrics down per-container so the "AXIAM includes a broker" penalty is
visible instead of silently folded in.

## 4. AXIAM product work items (evidence-ranked)

### 4.1 [HIGH] Bound concurrent Argon2id verifications (perf + DoS hardening)

`oauth2_password_login`: server pegged at 2.0 cores, RSS climbing to
~970 MiB of the 1024 MiB cap, p95 2.1 s (gate breach) at only ~35 req/s.
The memory math is exact: 50 concurrent VUs × 19 MiB (OWASP Argon2id m=19456)
≈ 950 MiB — i.e. **login concurrency is unbounded** and each in-flight login
holds a full Argon2 arena. At 64+ concurrent logins this OOM-kills the
container (memory DoS reachable from an unauthenticated endpoint — the
per-IP limiter mitigates single-source floods, but distributed sources
bypass it). Fix: a semaphore sized ≈ number of cores around the Argon2
verify (fail fast / queue with timeout when saturated). Keeps params at
OWASP levels, converts the failure mode from OOM to bounded latency,
and should *raise* effective login throughput by eliminating memory
pressure + scheduler thrash. Consider `tokio::task::spawn_blocking` pool
sizing review at the same time.

Related observation: after the login scenario, server RSS never returned to
baseline (~93 MiB before, ~646 MiB for every subsequent scenario) — allocator
retention, not a leak per se, but worth a look (jemalloc/mimalloc with decay
tuning, or `malloc_trim`-style release) since it inflates AXIAM's reported
memory footprint in every scenario that runs after a login burst.

### 4.2 [HIGH] Fix the authz batch path (currently slower than N single checks)

Batch of 5 checks: REST 41 req/s (=205 checks/s) vs single-check REST
290 checks/s; gRPC batch 22 req/s (=110 checks/s) vs single gRPC 485/s —
**batching makes it worse**, with p95 1.5–2.6 s and p50 over 1.1 s while the
server sits at 0.07–0.11 cores and SurrealDB at only ~1.2 cores (neither
saturated!). A 5-item batch taking ~1.1 s median with both CPUs mostly idle
smells like serialized per-item DB round-trips *plus* some fixed per-item
stall (lock contention, per-check transaction, or an N+1 explosion in the
RBAC hierarchy walk). Investigate `axiam-authz` + the batch handlers:

- Execute batch items concurrently (join_all) or, better, coalesce into one
  DB query for the common same-subject case.
- Profile a single batch request server-side (tracing spans per check) to
  find the stall — the idle-CPU + high-latency signature suggests waiting,
  not computing.
- Same investigation covers the single-check gRPC p99 (850 ms vs p95 173 ms —
  a nasty tail, possibly SurrealKV compaction stalls or connection-pool
  exhaustion under burst).

### 4.3 [HIGH] Investigate the TLS 1.3 throughput halving on token endpoints

Native rustls p2 vs p0: client_credentials −55%, token_refresh −58%, yet
introspection −0.3% and jwks −13.9%. In the degraded cells *nothing is
saturated* (server 0.64 cores, DB 1.11) — latency simply doubles (26→58 ms
p50). That pattern (per-request fixed cost added, no CPU wall) points at
connection behavior, not record crypto: suspects are per-request handshakes
(keep-alive not effective on the rustls listener for POSTs?), missing TLS
session resumption (no session tickets configured in
`crates/axiam-server/src/tls.rs`?), Nagle/`TCP_NODELAY` on the TLS listener,
or actix worker/acceptor tuning differences between the plaintext and rustls
binds. Reproduce with a single curl/openssl session vs fresh-handshake loop;
enable rustls session tickets + verify keep-alive; do NOT enable 0-RTT (replay
risk on POST token endpoints — explicitly document that decision). Whatever
the cause, it's worth ~2× on our two most marketable numbers.

### 4.4 [MEDIUM] Native mTLS (and the TLS 1.2 decision)

Discovered during bench tuning: AXIAM's native rustls listener is TLS 1.3
server-auth only — **p3-mtls (and p1-tls12) require an nginx edge in front of
AXIAM**, while Keycloak and Zitadel terminate mTLS in-process. For an IAM
whose roadmap sells certificate-based auth for IoT (mTLS), client-cert
verification belongs in the server: implement rustls client-auth (verifier
against the tenant/org CA from axiam-pki, expose SAN/SPKI to the auth layer
for certificate-mapped identities). That also makes the p3 benchmark a fair
in-cap measurement. For TLS 1.2: either add it natively for p1 or take the
explicit stance "AXIAM is TLS 1.3-only, use an edge proxy for legacy
clients" — the security posture docs currently say TLS 1.3 minimum, so
consider simply documenting p1 as N/A-by-policy for native AXIAM.

### 4.5 [MEDIUM] Feed the DB-bound flows (after §3.1 tuning data)

If SurrealDB remains the wall after tuning: reduce per-op DB work in the hot
paths — candidates visible from this run: per-check RBAC reads
(cache the subject's effective-permission set with short TTL + event-driven
invalidation; the additive-only/allow-wins model of v1.0-beta makes a
decision cache tractable), token-issuance writes (client_credentials at
1743/s drove SurrealDB to 1.74 cores — check for redundant reads of
client/tenant per issuance; cache client credentials verification material),
and introspection lookups (opaque-token read path; 2199/s at 1.42 DB cores is
already good — low priority).

### 4.6 [LOW] Quick wins

- **JWKS caching headers**: we serve 27 k/s easily, but adding
  `Cache-Control`/`ETag` (per-tenant key rotation aware) cuts client refetch
  storms in real deployments; also consider whether `?tenant_id=` JWKS should
  be served from an in-process cache invalidated on rotation (it probably
  already is, given 0.062 cpu·ms/req — verify and document).
- **userinfo**: once the harness bug is fixed we'll get a real number; given
  every other AXIAM read path, expect a strong one — make sure the endpoint
  accepts (or cleanly 403s) service-account tokens per OIDC spec rather than
  whatever produced the current 100% failure shape, and document the choice.
- **gRPC TLS support in the bench image docs** (pairs with §2.2).

## 5. Security-hardening notes distilled from this exercise

1. **Unauthenticated memory-DoS via login** (§4.1) — the concrete numbers
   make this a real finding, not a theory: ~50 concurrent logins ≈ 950 MiB.
   Semaphore + optional per-tenant login concurrency quota. Track as a
   security work item, not only perf.
2. **Rate limiter posture**: the bench had to neutralize AXIAM's per-IP
   limits while competitors ship none by default — that's a *differentiator*
   to market (secure-by-default) and the `rl=prod` run (§2.6) turns it into
   published evidence. Also consider making limiter keys configurable
   (per-client-id / per-tenant, not only per-IP) so NAT'd fleets don't
   collide — a lesson directly from the "single source IP" bench constraint.
3. **mTLS in-process** (§4.4) — removes nginx from the trusted path; today
   client-cert identity would be asserted via proxy headers, which is a
   header-spoofing surface if the edge is misconfigured. Native verification
   closes it.
4. **TLS session tickets**: when implementing (§4.3), use rotating ticket
   keys (rustls default resumption with periodic key rotation), and skip
   0-RTT on state-changing endpoints.
5. **Bench secrets hygiene**: seed.env files with client secrets and
   passwords land in `results/` (gitignored, but they were just shared in an
   archive). They're throwaway bench creds, but the runner could redact
   secrets from anything under `results/` to make result archives shareable
   by construction.

## 6. Reporting/presentation improvements for the site

- Per-container CPU/mem breakdown per cell (bottleneck attribution tag,
  §3.1) — it's the single most explanatory piece of data we have and it's
  currently only in raw CSVs.
- Add p50 to `report.md` (it's already in the k6 summaries; the public doc
  had to be assembled by hand from both sources).
- Blank out throughput/latency columns for `error_rate=100%` cells in
  `report.md` — printing 10 358 req/s of 401s as "throughput" invites
  misquoting.
- Mark fallback-op cells (Zitadel login/refresh, §1.3–1.4) as
  non-comparative in the report the way authz cells already are.
- Charts for the site from the §5 public tables: grouped bars
  (throughput and thr/core per scenario × target, one group per profile),
  p95 latency dot plot, and a "TLS cost" delta chart — all derivable from
  the public doc's matrix without new data.

## 7. Suggested order of execution

1. Harness fixes §1.1–1.5 + smoke checks (unblocks a fully-valid matrix).
2. Argon2 semaphore (§4.1) and TLS investigation (§4.3) — biggest product
   wins, both likely small diffs.
3. Re-run matrix (median of 3) + DB-uncapped sensitivity pass (§3.1) on the
   laptop; publish updated draft.
4. Batch-authz fix (§4.2); Zitadel gRPC + login-API adapters (§2.1, §1.3);
   p3-mtls once native mTLS lands (§4.4).
5. Server-class hardware run → replace "draft" label on the site.
