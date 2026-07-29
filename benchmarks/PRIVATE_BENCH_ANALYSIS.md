# PRIVATE — Benchmark Post-Mortem & Improvement Plan

> Internal working document. Companion to `PUBLIC_BENCH_ANALYSIS.md`.
> **Updated 2026-07-26** for **run 3** — the first *serious* run: full
> median-of-3 capped matrix (AXIAM **1.0.0-alpha19** pulled ghcr image,
> digest-recorded, vs Keycloak 26.7.0 vs Zitadel v4.15.2; p0-plaintext +
> p2-tls13; 50 VUs; 2 CPU / 1024 MiB caps) **plus** the full labeled
> sensitivity set: B2 h1-isolation cell, batch-strategy A/B
> (`sens-batch-coalesced`), DB-pool A/B (`sens-pool-4`,
> `sens-pool-4-inflight-64`), native mTLS (`sens-p3-mtls`), prod rate-limit
> posture (`sens-rl-prod`), all-targets DB-uncapped (`sens-uncapped`),
> decision-cache ON (`sens-cache-on`), and the F3 expiry soak (cargo test —
> **PASS**, 10.53 s). Same Dell XPS 15 9570. Run-2 findings that are resolved
> are compressed; everything still open is carried forward. The executable
> follow-up plan derived from this document is
> [`claude_dev/improvement-after-serious-benchmark.md`](../claude_dev/improvement-after-serious-benchmark.md).

## 0. Run-3 executive summary

Median-of-3, capped p0, vs run 2 (single-run):

| Area | Run 2 | Run 3 (median-of-3) | Verdict |
|---|---|---|---|
| client_credentials | 1788 | **1823** (±0.1%) | ✅ stable; 5.2× KC, 4.3× Zitadel |
| introspection | 2229 | **2230** (±0.3%) | ✅ stable; KC closed to 1.17× (1908) |
| jwks | 27059 | **27784** | ✅ stable; generator-limited |
| userinfo | 5457 | **5008** | ✅ valid 3-way, AXIAM leads 1.3×/5.3× |
| login (B1) | 67.5, p95 907 | **69, p95 774** | ✅ best-in-field; KC p0 now *valid* (52/s, see §2.4) |
| token_refresh AXIAM | fallback | **still fallback-op (100%)** | ❌ A8 did NOT take effect for AXIAM (§2.1) |
| token_refresh KC | fallback | **REAL rotation: 379/s, 0 fallback** | ✅ A8 works for KC |
| Zitadel gRPC (D11) | 100% errors | **valid, 0% err — 183/s** | ✅ fixed; magnitude prediction was wrong (§2.5) |
| B2 TLS on CC | −49% | **−50.5%** (1823→903) | ❌ open; h1 conviction cell INVALID (§1) |
| authz batch | 46/23, "serialized DB" | **matrix cells INVALID — order artifact** (§1) | ⚠ verdict changes completely |
| authz single REST/gRPC | 745 / 722 | **737 / 603** | ✅ reproduced on pinned image (gRPC −16% vs REST, §3.6) |
| D3 native mTLS | not run | **parity with p2 across the board, no nginx** | ✅ D3 acceptance PASSED (§3.4) |
| D7 cache ON | not run | **check REST 2322 (+3.1×), gRPC 1822 (+3.0×)** | ✅ big, ship-decision pending (§3.2) |
| F2/F3 pool | not run | **pool 4: CC +7%, rest neutral; soak PASS** | ✅ CQ-B48 closed; default stays 1 (§3.3) |
| A9 provenance | digests unknown | **real digests everywhere, build_ref stamped** | ✅ closed |
| C1 median-of-3 | not used | **used; spreads ±0.1–2.8%** | ✅ machinery works, noise is small |

Note the runbook said alpha17; the run actually used the released
**1.0.0-alpha19** image (digest `4590…`, build_ref `678f601`) — fine, and now
provable thanks to A9.

## 1. ⚠ THE run-3 discovery: a post-seed serialized-DB transient invalidates every "first cell after seed"

**This is the most important finding of the run and rewrites two long-standing
conclusions (D1/D10 batch slowness, and the B2 h1 cell).**

> **UPDATE (H2, 2026-07-28): this was never post-seed, and "transient" is
> wrong too.** `claude_dev/postseed-transient-investigation.md` traced the
> effect to a permanent, product-relevant design property: six endpoints
> (`POST /api/v1/authz/check`, `POST /oauth2/token`, `POST /oauth2/introspect`,
> `POST /oauth2/revoke`, `POST /api/v1/auth/login`, and — as a bug —
> `GET /api/v1/users`) are wrapped with `RateLimitShared`, which performs one
> synchronous SurrealDB write (the shared rate-limit bucket) before the
> handler runs. That single round trip — not seeding, not compaction, not
> data volume — is the "~22 ms serialized unit": it survives idle time,
> server restarts, datastore restarts, `POOL_SIZE` changes, and even swapping
> the storage backend to pure in-memory. Structurally identical endpoints
> without the wrap are unaffected. §1.1–§1.4 below are kept as the *run-3*
> observation (accurate to what run 3 saw and how the harness was built in
> response — the settle gate + rotation in §2 of methodology.md are still
> exactly the right countermeasure), but read "post-seed window" throughout
> as "the window this particular host's write-cost happened to clear in
> during run 3", not a seeding effect. On the H2 investigation host the
> effect never clears at all (16–21 ops/s at any concurrency, indefinitely) —
> see that document §6 for the reconciliation with run 3's recovery cliff,
> which remains only partially explained. The G-box's "recovers after ~6 min"
> and this host's "never recovers" are two datastores paying a different
> price for the same synchronous write, not two different bugs.
>
> **UPDATE (2026-07-29, `claude/g-benchmark-improvements-n5mjmj`): both asks
> from `postseed-transient-investigation.md` §7.1 are now FIXED, not just
> root-caused.** `GET /api/v1/users`'s registration-bucket bug is fixed
> (method-guarded resource split). The synchronous per-request UPSERT is
> replaced by a write-behind design
> (`axiam_db::rate_limit_counter::SharedRateLimitCounter`, commits `5212912`,
> `0fbbd5e`, `1f3da2f`, `7167c18`): the request path decides synchronously
> in-memory and a background flusher coalesces one datastore write per
> bucket per `AXIAM__RATE_LIMIT__SHARED_SYNC_MS` (default 1000 ms) instead of
> one per request. What this buys and what it costs is written up in full in
> `claude_dev/rate-limit-posture-decision.md` §8 (chosen design, alternatives
> considered, and why) and quoted precisely in the
> `axiam_db::rate_limit_counter` module docs: cross-replica enforcement
> becomes eventual, bounded by `(replicas − 1) × arrival_rate_per_replica ×
> sync_interval` and zero on a single replica, instead of the old design's
> zero-overshoot-at-any-replica-count bound. **This has NOT yet been
> re-measured on the H2 investigation host or any other host** — no throughput
> number anywhere in this document has changed. The re-measurement is tracked
> as its own artifact, `claude_dev/rate-limit-fix-verification.md`, produced
> by a separate concurrent task; do not fold numbers from that file into this
> one without also updating the run/commit provenance this document is keyed
> on.

### 1.1 The signature

A window of roughly **5–7 minutes after `bench-up` + `bench-seed`** in which
the AXIAM stack serves requests with:

- SurrealDB pinned at almost exactly **~1.0–1.3 cores** (never its 2.0 cap),
- the AXIAM server nearly idle (0.05–0.11 cores),
- throughput clamped to **~45 req/s** with p50 ≈ `50 VUs × ~22 ms` ≈ 1.05–1.1 s
  — the classic closed-loop queue on a ~22 ms *serialized* unit of DB work.

### 1.2 The evidence (all from this archive)

1. **Scenario-independence.** In `sens-batch-coalesced` the cells ran in the
   order check_rest → batch_rest → check_grpc → batch_grpc. The first two
   cells clamp at **45.4 / 45.2 req/s** — including plain
   `authz_check_rest`, which the matrix measures at **737 req/s**. The last
   two cells are healthy (676.6 and — see below — **852.7**).
2. **Mid-cell recovery caught live.** In `run-1/axiam/p0`, cell 3
   (`authz_check_grpc`, ~7.4 min after seed) shows SurrealDB at 1.51 cores in
   the first quarter of the measure window and **2.01 in the last quarter** —
   the transient *ended during the cell*.
3. **The B2 h1 cell reproduces it on a different scenario.** The
   nginx-h1 `oauth2_client_credentials` cell (run first after its own seed)
   clamps at **44.7 req/s, p50 1105 ms** with nginx at 0.01 cores, server at
   0.05, SurrealDB at 1.03 — identical signature, nothing to do with TLS.
4. **The matrix ran scenarios alphabetically**, so `authz_batch_grpc` and
   `authz_batch_rest` were *always* cells 1–2 after seed — in run 1, run 2
   (single-run) and all three run-3 repeats. Their suspicious stability
   (22/41 req/s, ±0.5–0.9%) is the stability of the artifact, not of the
   batch path.

### 1.3 What it invalidates

- **All matrix batch cells, in every run so far.** The two-run-old
  "batch is serialized in the DB" narrative (D1 → D10) was measuring the
  transient. The only *clean* batch cell ever collected is
  `sens-batch-coalesced`'s cell 4: **authz_batch_grpc (coalesced) =
  852.7 batches/s = ~4 264 checks/s, p50 49 ms, p95 75 ms** — batch is
  **6.3× more efficient per check than single checks** once the DB is
  healthy. There is **no clean cell at all** for: batch REST (either
  strategy), batch gRPC with the `concurrent` default. D10's A/B is
  therefore still unfinished — but the prior is now inverted: nothing is
  wrong with batch; `coalesced` looks excellent.
- **The B2 h1-isolation cell.** It ran first-after-seed and measured the
  transient, not HTTP/1.1-over-TLS. ~~**B2 remains open**~~; the native p2 CC
  halving (1823→903, −50.5%) is confirmed real by the clean matrix cells.
  **UPDATE (H6, 2026-07-29): B2 is closed as framed — the −50.5% is real but
  is not a transport cost.** HTTP/2 is acquitted by direct measurement (the
  "all clients collapse onto one h2 connection" premise never held: 10/50/100
  concurrent clients open 10/50/100 connections over h2, and both actix
  workers stay balanced), and h1-vs-h2 over an otherwise identical TLS edge is
  a wash. TLS 1.3 itself is priced at −13%/−2% on jwks and −8%/−13% on
  userinfo depending on load. That leaves the CC penalty endpoint-specific,
  not transport-specific. Full evidence and the one remaining follow-up in
  `claude_dev/b2-tls-h2-investigation.md`. Note also that the G8 h1 cell's
  1 059 failed ops had a mundane cause found in H6: **none** of the nginx edge
  confs declared an `upstream ... keepalive`, so the edge opened and closed a
  fresh backend TCP connection per proxied request.
- Probably the low `authz_check_grpc` in `sens-pool-4*` (537 vs 603 —
  it was cell 3, the recovery window).

### 1.4 What it might be (to investigate, not assume)

Prime suspects, in order: SurrealDB/SurrealKV **post-ingest background work**
(compaction/index build after the seed's writes) holding a lock that
serializes foreground queries; the audit/AMQP ingestion backlog from seeding
draining through serialized DB writes (RabbitMQ shows 0.8–1.0-core spikes in
some affected cells); something in the server's DB session warm-up. Two facts
to hold onto: the unit cost is ~22 ms and constant; and recovery is
spontaneous after ~5–7 min. **If this is SurrealDB compaction, production
cold-starts and bulk-import windows will exhibit the same behavior — this is
potentially a product issue, not just a bench artifact.** Top-priority task
(G1) in the follow-up plan, together with harness countermeasures (settle
gate + cell-order rotation, G2).

## 2. Harness bugs & data-validity issues

### 2.1 ❌ A8 regression/failure — AXIAM `token_refresh` is STILL fallback-op

`bench_fallback` fired on **100% of iterations** in every AXIAM refresh cell
(e.g. run-1 p0: 9 774/9 774; 2 HTTP reqs per iteration — the CC-fallback
signature), while **Keycloak's cells show zero fallback and real rotation**
(379/367 req/s p0/p2, one request per iteration). So the A8 code path works
(KC proves it) but the AXIAM login-first mint is falling back — the
`axiam_refresh` cookie extraction presumably fails against alpha19 (or login
succeeded but the refresh grant rejected the cookie-sourced token). The AXIAM
refresh columns (62/61 req/s) measure the fallback op and are correctly
excluded from head-to-heads. **Follow-up task G4**; also note the AXIAM
refresh cells burn the highest server memory of the session (566–606 MiB —
double-issuance + retention, see §3.5).

### 2.2 ⚠ Sensitivity-pass knobs are not recorded in meta.json

`sens-pool-4`'s meta.json is indistinguishable from the baseline's — the
`AXIAM__DB__POOL_SIZE=4` / `BATCH_STRATEGY` / `DECISION_CACHE` exports that
defined the pass are nowhere in the metadata (only the results-dir name says
what it was). A5/A9 follow-up (G2): dump the `AXIAM__*` env the compose
actually received into each cell's meta.json so labeled passes are
self-describing.

### 2.3 Invalid cells, all explained

7/48 matrix cells invalid, every one for a known reason: 2× AXIAM batch_grpc
(p95 > 2 s — and now known-corrupted anyway, §1), 2× Zitadel login + 2×
Zitadel refresh (bcrypt cost / no offline_access flow — expected,
kept-with-labels), 1× KC p2 login (§2.4).

### 2.4 ⚠ Keycloak login anomaly: p0 now valid and 2.3× faster than run 2, p2 unchanged-slow

KC p0 login: **52 req/s, p50 919 ms, p95 1070** (2/3 valid runs, ±7.8% — the
widest spread in the matrix) vs run-2's 22.3/s, p50 2139. But KC **p2** login
stayed at 23 req/s, p95 2249 (0/3 valid). Same image digest for both
profiles. No explanation yet — possibly KC hashing-iteration warm-up
interacting with run order, possibly a real TLS interaction. Don't publish a
KC-login-got-faster claim; publish p0 as measured (valid) and p2 as
gate-invalid, and note the asymmetry. Worth one diagnostic run if time
permits; not AXIAM work.

#### 2.4.1 H7 diagnostic run (2026-07-29, `claude/g-benchmark-improvements-n5mjmj`) — fairness hygiene only, no KC fixes

One `oauth2_password_login.js` pass each way, per the written procedure in
`claude_dev/grpc-vs-rest-authz-analysis.md` §2 (single repro run each way,
per that section's own acceptance bar). `BENCH_MEM` raised from the target's
compose default (1024m) to **4096m** for this diagnostic only (env override,
no compose file change) — see why below; `docker stats` sampled every 3 s
throughout each measured window.

| profile | result | throughput | p50 | p95 | error | KC CPU (2-core cap) | KC mem peak |
|---|---|---:|---:|---:|---:|---|---|
| p0-plaintext | ✅ 100% valid | **27.93 req/s** | 1.63 s | 2.28 s | 0.00% | ~195–200% (saturated) | 3.28 GiB / 4 GiB (82%) |
| p2-tls13 | ✅ 100% valid | **13.55 req/s** (−51%) | 3.45 s | 4.00 s | 0.00% | ~197–202% (saturated) | 1.48 GiB / 4 GiB (37%) |

Both cells are clean 0%-error, 100%-`checks` passes — **not gate-invalid** —
answering procedure item 3 directly: on this box, with adequate memory
headroom, p2 is not failing the validity gate at all; it is legitimately
slower. That reframes the original matrix's "p0 52/s valid vs p2 23/s,
0/3 valid": **at the target's own compose default of `BENCH_MEM=1024m`, this
diagnostic reproduced an outright `OOMKilled: true` on `bench-keycloak` twice**
(once at 1024m, once again at 2560m) before a 4096m cap let the container
survive a full 50-VU sustained-login window — Keycloak 26 on Quarkus simply
needs more headroom than the shared 1 GiB per-container default under
sustained Argon2/PBKDF2-class hashing load. The original run's "0/3 valid"
for p2 is therefore plausibly **OOM-driven instability**, not a TLS-specific
gate failure — a harness sizing gap, not a Keycloak or TLS defect. (Not
re-verified against the original run's exact `BENCH_MEM`; flagged as the
most likely explanation, not confirmed root cause — the original run's
containers are gone.)

Procedure item 2 (isolate TLS overhead from KC's own request handling): KC's
CPU is pegged at the **same** ~195–202% (i.e., the full 2-core cap) in
**both** profiles, not "idle at p0, pegged at p2" — Argon2/PBKDF2 password
hashing already saturates the CPU budget at p0 by itself. p2's TLS
handshake/cipher cost is therefore not new, unused headroom being consumed;
it is **additional CPU work landing on an already-fully-booked budget**,
directly cannibalizing hashing throughput — consistent with the −51%
measured, and a cleaner mechanism than "TLS is expensive in the abstract."
Procedure item 1 (run-order/warm-up): only one order was run (p0 then p2,
per the "one diagnostic run each way is sufficient" bar) — not re-tested in
the opposite order; if the 30% budget affords it, a p2→p0 repeat would
further separate order effects from the CPU-contention mechanism above, but
was not required to close this item.

**Verdict:** fairness hygiene closed. No AXIAM or Keycloak code was touched.
Recommendation for any future publication of this pair: size the Keycloak
container's memory to at least ~3.5–4 GiB before trusting *any* sustained-load
login cell from it (current target compose default of `BENCH_MEM=1024m` is
too small and risks silently reporting an OOM-churn number as a TLS
penalty).

### 2.5 ✅ D11 Zitadel gRPC — fixed, but the run-2 magnitude prediction was wrong

Valid 0%-error cells at last: **183/187 req/s (p0/p2), p50 233 ms**,
`cc-token-setup` labeled. Run 2 predicted ~1.7–2 k/s from the error-path
resource profile — real `GetMyUser` calls are ~9× more expensive than the
auth-rejection path was. Lesson recorded: never extrapolate a valid-cell
magnitude from an error path. The protocol-efficiency pairing is now
publishable: Zitadel gRPC is **−80% vs its own REST userinfo** (both
cc-token-setup), while AXIAM's gRPC userinfo is −34% throughput but **−29%
cpu·ms/req** vs REST (closed-loop artifact: gRPC p50 14 ms vs REST 4.8 ms,
but gRPC is cheaper per request and its p95 is 2.3× better).

### 2.6 ✅ Closed this run

- **A9 provenance:** every container in every cell has a real digest; AXIAM
  cells carry `build_ref`; the pulled ghcr alpha19 image is what ran
  (first run on a non-locally-built, digest-pinned binary).
- **C1 median-of-3:** worked as designed; per-cell throughput spreads
  ±0.1–2.8% (login/KC cells widest). Single-run deltas ≥ ~5% are now
  resolvable signal on this laptop.
- **A7/bench-pack:** shared archive verified secret-free again.
- **F3 expiry soak:** `pooled_handles_survive_token_expiry_without_restart`
  **ok** in 10.53 s against a live DB — CQ-B48 stays closed under the pool.

## 3. Sensitivity passes — what each one taught

### 3.1 DB-uncapped (now all three targets — C2 complete)

| cell | capped → uncapped | limiter after uncapping |
|---|---|---|
| AXIAM authz_check_rest | 737 → **1013** (+37%) | nothing pegged; round-trip latency (DB 2.83/4) |
| AXIAM authz_check_grpc | 603 → **712** (+18%) | same |
| AXIAM userinfo | 5008 → **7457** (+49%) | **AXIAM server pegged (2.05/2)** — its ceiling found |
| AXIAM CC / introspection / jwks | ±1% | latency-structured / generator |
| Keycloak (all cells) | ±2% (e.g. CC 351→329) | **KC server pegged in every cell; DB CPU irrelevant to it** |
| Zitadel jwks | 2071 → **3510** (+70%) | PG at 3.83/4 |
| Zitadel userinfo | 943 → **1749** (+85%) | PG at 4.01/4 |
| Zitadel introspection | 910 → **1032** (+13%) | Zitadel server ~pegged |

Keycloak's flat uncapped pass completes the picture: KC is purely
server-bound, Zitadel purely Postgres-bound, AXIAM DB-bound on authz/userinfo
and latency-bound on tokens. The public "req/s per *server* core" framing is
fair to all three.

### 3.2 Decision cache ON (D7) — the single biggest lever measured

`AXIAM__AUTHZ__DECISION_CACHE_ENABLED=true`, TTL 5 s, single-tenant bench
key space:

- authz_check_rest **737 → 2322 (+215%)**, p50 68→19.6 ms; SurrealDB drops
  from pegged-2.0 to 1.30 cores.
- authz_check_grpc **603 → 1822 (+202%)**, p50 62→21 ms; DB 0.54 cores.
- Every non-authz cell within noise of the matrix (cache is scoped
  correctly). Batch cells corrupted by §1 (ran first), no conclusion.

Caveats for the ship-decision (G5): the bench's hit rate is optimistic
(50 VUs hammering one subject/resource set); the security bound (stale-allow
≤ TTL even if invalidation is missed) is already documented and
revocation-tested. Recommendation to take to the plan: **default ON for
v1.0-beta with TTL 5 s**, prominently documented, off-switch retained.

> **UPDATE (H5, 2026-07-29): decision recorded — stays opt-in (`false`).**
> `claude_dev/decision-cache-decision.md` walked the clean K-sweep (K=1
> 3.0–3.15×, K=10 000 +32%, K=100 now measured) against the seven pre-agreed
> criteria after fixing the three defects the run-3/G5 data had surfaced
> (unbounded `order` growth, O(shard) `invalidate_subject` under a global
> mutex, and documenting the process-local revocation bound). The flip is
> blocked on C1/C2/C4 — see that document for the full criteria table. The
> recommendation written here (default ON) is superseded.

### 3.3 DB pool A/B (F2/F3)

`pool_size=4`: CC **1823 → 1955 (+7.2%)**; `+ max_in_flight=64` changes
nothing further (the cap never binds at 50 VUs). Everything else within
noise or transient-affected (§1.3). Introspection −2.5% (noise-level),
userinfo/login/jwks flat. With the soak green, the honest F3 conclusion:
**keep `pool_size=1` as the shipped default** (the byte-identical safe
rollout), document `pool_size=4` as a token-issuance-heavy tuning
(it buys ~7% there and nothing else at this concurrency), revisit after G1
removes the transient and an open-loop harness exists (§5.3 of run-2 doc —
still true).

> **UPDATE (H9, 2026-07-29): closed negative — default stays `pool_size=1`.**
> The pre-agreed ≥5%-on-CC confirm cell turned out to be **unsatisfiable on
> this host**: H2 found `POST /oauth2/token` permanently clamped to
> 16–21 ops/s by the `RateLimitShared` write, so there is no settled CC cell
> to confirm against here. Two independent lines of evidence say the G-box
> G-run's "+7%" (1955 vs 1823) was noise rather than a `pool_size` effect
> anyway: `AXIAM__DB__POOL_SIZE` 1→8 changed authz throughput by 0 ops/s at
> both 1 and 20 VUs (H2 §5.2 — the shared-router mechanism means more pooled
> handles buy no DB concurrency), and the G-run CC cells were never proven
> to run outside the settle-gate-blind window in the first place. No code
> change needed — `pool_size=1` was already the default.
> `claude_dev/db-pool-design.md` §11 records the full verdict.

### 3.4 Native mTLS (D3) — acceptance PASSED

p3-mtls ran with **no nginx container** (meta: 3 containers, `client_auth:
x509`, scheme https): CC 903.6 (native p2: 903), check_rest 741 (747),
introspection 2201 (2225), userinfo 4826 (4822), jwks 24146 (24309),
login 68.1 (69), userinfo_grpc 3231 (3254). **Client-certificate
verification costs nothing measurable on top of TLS 1.3** — an excellent
IoT-story headline, and the proxy-header identity surface is gone from the
p3 path. (The CC cell still carries the TLS-vs-p0 halving, same as p2 —
B2 is orthogonal.)

### 3.5 Memory (B1/D9 watch)

Server container RSS across each session: ~75–127 MiB before the login cell;
**~490 MiB from the login burst onward** (login cell avg 489; every later
cell ~447–490); refresh cells push to 566–606. Retention confirmed on
alpha19: ~360 MiB of the burst never returns. The D9 A/B is now fully
scripted — `benchmarks/run-memory-experiment.sh` builds both images (default
vs `--features jemalloc`), runs baseline → burst → 10-min watch per variant,
and emits `results/d9-summary.md` with the ≥30%-gap-closure verdict. Run it
(G6); until then AXIAM's published mem column for post-login cells stays
inflated and the doc says so.

> **UPDATE (H4/G6, 2026-07-28/29): fixed — jemalloc is the release default.**
> The A/B ran: default malloc retained 376 MiB above baseline (peak 491);
> jemalloc retained 86 MiB (peak 126) — **94% of the gap closed**, no
> throughput or latency cost recorded. `crates/axiam-server` ships jemalloc
> as the release-container default allocator as of H4 (a
> `--no-default-features` escape hatch stays documented for musl/platform
> edge cases). The "stays inflated" line above is stale — see
> `claude_dev/memory-retention-experiment.md` §6 for the full numbers.

### 3.6 gRPC-vs-REST authz gap (new, now that both are clean)

Single check: gRPC 603 vs REST 737 (−18%, p0) with *lower* p50 (62 vs 68).
Not the transient (cells 3–4). Not TLS (identical at p2). Small, real,
unexplained — parked as a low-priority item (G8); suspect per-call
UUID-parse/validation or tonic service overhead. The p99 tail from run 1
(850 ms) remains gone (p99 112–217 ms).

### 3.7 Prod rate-limit posture (C4) — ran; framing matters

With shipped defaults (`token 20/min/IP`, `introspect 10/min/IP`,
`authz_check 300/min/IP`, `login 10/min/IP`…), a single-IP 50-VU generator
is — by design — throttled to ~zero on every limited endpoint (CC 0.9/s,
introspection 0.4/s, ~100% 429s; unlimited paths unaffected: jwks 27.7 k/s,
userinfo 5 994/s). report.py's posture-mixing guard worked (separate
subtree, never merged into head-to-heads). Two outputs: (a) the public
"AXIAM ships default abuse limits; competitors don't" evidence, now
measured; (b) **the maintainer's observation stands — the defaults are far
too strict for any M2M/NAT topology**, so the public doc now carries a
"recommended settings by deployment" section (§6 of the public doc) and G7
tracks revisiting the shipped defaults + docs.

## 4. Product work items (evidence-ranked, post-run-3)

Full task specs with models and acceptance criteria live in
[`claude_dev/improvement-after-serious-benchmark.md`](../claude_dev/improvement-after-serious-benchmark.md).
Ranked summary:

1. **G1 — Root-cause the post-seed serialized-DB transient** (§1). Biggest
   validity issue *and* a potential production cold-start defect. Everything
   batch- and B2-related is downstream of it. **Root-caused: DONE (H2).
   Fixed: DONE (`claude/g-benchmark-improvements-n5mjmj`, see the §1 UPDATE
   above and `claude_dev/rate-limit-posture-decision.md` §8) — not yet
   re-measured (`claude_dev/rate-limit-fix-verification.md`).**
2. **G2 — Harness countermeasures + self-describing meta**: settle gate
   before the first cell, cell-order rotation per run, record `AXIAM__*`
   knobs in meta.json, re-run the four batch cells clean (both strategies)
   and the B2 h1 cell mid-session.
3. ~~**G3 — B2**: still −50.5% on CC at p2. Clean h1 cell first; then h2
   stream/flow-control tuning on the actix listener or an accepted,
   documented position.~~ **DONE (H6) — documented position published, and it
   is not the position this line anticipated: the transport is exonerated
   entirely, so there is no listener tuning to do.** What replaces it is one
   narrow follow-up for the server-class re-run (E3): on a host where
   `/oauth2/token` is **not** clamped, sweep VUs at p0 and p2 on CC. A cost
   that scales with VU count is per-request; a throughput that stays pinned
   regardless of VU count is a serialization point (and `RateLimitShared`'s
   bucket write is the only one known on that path). See
   `claude_dev/b2-tls-h2-investigation.md` §6.
4. **G4 — A8 residual**: AXIAM refresh cookie extraction (harness) — last
   invalid AXIAM-controlled cell.
5. **G5 — D7 ship-decision**: default-ON proposal + combined cache+pool
   cell + realistic-hit-rate caveat work.
6. **G6 — D9**: run `run-memory-experiment.sh`, decide jemalloc.
7. **G7 — Rate-limit defaults & tuning guide** (from §3.7 / maintainer note).
8. **G8 — Small investigations**: gRPC −16% authz gap; KC p0/p2 login
   asymmetry (diagnostic only); Zitadel offline_access refresh.
9. **G9 — SDK benches (E1)**: still never run against a live target — the
   harness exists (7 code-bearing + 4 stubs implemented); wire them into the
   run-4 protocol so the SDK-overhead table finally exists.

## 5. Security-hardening notes (updated)

1. **B1 stands** (login p95 774 ms, RSS bounded, 0 errors at 50 VUs, OWASP
   params). D9 retention is the remaining memory item (script ready).
2. **mTLS native path measured at parity** — the p3 nginx/proxy-header
   surface is retired for real (§3.4).
3. **Rate limits**: shipped defaults are effective abuse-stoppers (measured:
   they flatten a 50-VU single-IP flood) and unsuitable as-is for M2M
   fleets — hence the public tuning guidance and G7. `key=client_id` mode
   (D8) is the right default candidate for token endpoints; login stays
   per-IP.
4. **Decision cache**: if G5 flips it on by default, the public docs must
   state the ≤TTL stale-allow bound next to the default, not in a footnote.
5. **TLS 0-RTT stays off**; resumption verified again at p2/p3.

## 6. Publishing guidance for the site (run-3 deliverables)

- Publish medians + spreads; headline multiples (p0): CC **5.2×/4.3×**,
  introspection **1.17×/2.45×**, jwks **7.4×/13.4×**, userinfo
  **1.34×/5.3×**, login: only valid cell at 50 VUs (KC p0 now also valid at
  52/s — say so; it strengthens rather than weakens the comparison).
- Publish the mTLS-parity table (§3.4) — it's the IoT differentiator.
- Publish cache-ON as a labeled sensitivity row with the TTL caveat, never
  in the default head-to-head.
- **Do NOT publish any batch number as a verdict** — publish the artifact
  discovery + the one clean 852-batches/s cell as "measurement corrected,
  full re-measurement in progress". This *retracts* the draft-1/2 "batch is
  slow" caveat in the honest direction.
  > **UPDATE (H3/G3, 2026-07-28): superseded — the re-measurement happened
  > and the verdict shipped.** On settled cells (G3 run 2–3), `coalesced`
  > batch REST measured **744 ops/s = 3 721 checks/s = 4.98× singles**;
  > gRPC coalesced **866–872 ops/s ≈ 4 330 checks/s**, p95 74 ms. `coalesced`
  > is now the shipped default (`crates/axiam-authz/src/config.rs`,
  > `concurrent` stays selectable). Publish the G3 table as the batch
  > verdict, not as "in progress" — see `claude_dev/authz-batch-investigation.md`
  > for the closing data. On *this* investigation host (H2/H10) batch cells
  > are still clamped by the `RateLimitShared` write and must be published as
  > refused, same as every other clamped cell — that is a host limitation,
  > not a reopening of the G3 decision.
  > **UPDATE (2026-07-29, `claude/g-benchmark-improvements-n5mjmj`): the
  > `RateLimitShared` write named above is fixed** (write-behind counter, §1
  > UPDATE). Any *new* H2-host pass run against this branch is no longer
  > expected to hit that specific clamp on these six endpoints, but this
  > document's own H2/H10 numbers above were captured pre-fix and are
  > unchanged — do not retroactively read them as un-clamped. Whether a
  > future pass on this host settles cleanly is an open question for
  > `claude_dev/rate-limit-fix-verification.md`, not asserted here.
- **Publish the shared rate-limit fix as a closed product item, not a
  performance number.** `claude_dev/postseed-transient-investigation.md`
  §7.1's two asks (the `GET /api/v1/users` bucket bug and the synchronous
  shared-store write) are both implemented on
  `claude/g-benchmark-improvements-n5mjmj` — see the §1 UPDATE above and
  `claude_dev/rate-limit-posture-decision.md` §8 for the design rationale.
  **Do NOT publish any post-fix throughput number yet** — none has been
  measured; it lands in `claude_dev/rate-limit-fix-verification.md` first,
  produced by a separate task, and only then flows into a future draft of
  the public matrix.
- Do NOT chart: AXIAM/Zitadel refresh (fallback), Zitadel/KC-p2 login
  (gate), any first-cell-after-seed number (§1), the B2 h1 cell.
- The new "recommended production settings" section (public §6) is the
  maintainer-requested addition; keep values in sync with code defaults.

## 7. Order of execution

G1 → G2 (they unblock clean batch/B2 data) → re-measure the 5 corrupted
cells → G3/G4/G5 in parallel → G6/G7 → run-4 full protocol (matrix +
sensitivity + SDK benches, G9) → E4 public refresh v4. Details, models and
acceptance criteria: `claude_dev/improvement-after-serious-benchmark.md`.
