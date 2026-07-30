# Run 4 — benchmark execution instructions

**Written 2026-07-30**, after the Phase H work plus the rate-limit fix landed on
`main`. This is the operator runbook for producing the **first publishable
benchmark matrix** — the one whose numbers can go into
`benchmarks/PUBLIC_BENCH_ANALYSIS.md` without caveats about contamination.

Read this **before** starting. The short answer to "do I just run the matrix?"
is **no** — the matrix is the main event, but there are four things to do
around it, and one known bug to watch for that can silently ruin a long run.

---

## §0 TL;DR — the five things to run

| # | What | Command (from `benchmarks/`) | Approx. wall time |
|---|---|---|---|
| 1 | **Preflight** (verify the fix is in the image) | see [§2](#2-preflight-do-not-skip-this) | 5 min |
| 2 | **The matrix** — median-of-3, all targets, p0+p2 | `just repeat=3 bench-matrix` | several hours |
| 3 | **Sensitivity passes** — one labeled pass per flipped default | see [§4](#4-sensitivity-passes-the-standing-list) | ~1–2 h |
| 4 | **SDK benches** — the E1.3 overhead table | `just sdk-bench-all` at p0 and p2 | ~30 min |
| 5 | **E4** — regenerate the public doc from run-4 medians | see [§6](#6-e4--regenerate-the-public-document) | manual |

Everything else in this document is *why*, *what to check*, and *what to do
when it goes wrong*.

---

## §1 What changed since the last run, and why run 4 is different

The previous runs' authz/token numbers were **not measuring AXIAM's
authorization engine**. They were measuring one synchronous
`rate_limit_bucket` UPSERT that `RateLimitShared` performed *before* the
handler, on six of the hottest endpoints — see
[`postseed-transient-investigation.md`](postseed-transient-investigation.md).
That write set a hard ceiling equal to the datastore's write latency (~20 ops/s
at ~40 ms), independent of concurrency, and it was originally misdiagnosed as a
"post-seed warm-up transient".

That is fixed. On the verification host the affected endpoints went from
16–21 ops/s to **147–1553 ops/s**, and — the headline for this run — **the H1
settle gate passed on its first probe for the first time**
([`rate-limit-fix-verification.md`](rate-limit-fix-verification.md)).

Also landed since the last matrix, all of which changes what you should expect
to see:

| Change | Effect on run 4 |
|---|---|
| Rate-limit write moved off the request path | authz/CC/introspect/login/revoke cells are finally real |
| **Batch default → `coalesced`** (H3) | `authz_batch_*` should be **~5× singles**, not ~1.4× |
| **jemalloc is the release-image default** (H4) | retained-memory caveat is gone; peak 491 → 126 MiB |
| Decision cache **stays opt-in** (H5) | cache is OFF by default — measure ON as a *sensitivity pass* |
| `pool_size` **stays 1** (H9) | do not set 4; the old "+7%" was noise |
| Settle gate v2 + `report.py` refusals (H1) | a contaminated cell is now *refused*, not silently published |
| `bench_http_proto` + protocol column (H6) | every cell records the negotiated protocol; `?` is no longer acceptable |
| `protocol-variant` label (H7) | AXIAM vs Keycloak refresh is labeled not-like-for-like |
| p0 `AXIAM__AUTH__COOKIE_SECURE=false` (H6) | login-based p0 cells work at all now — previously all died in `setup()` |
| SDK benches repaired (H8) | 6 languages emit valid records; C# stays honest `pending` |

---

## §2 Preflight (do not skip this)

Three of these have burned a previous run.

**2.1 — Confirm the image actually contains the rate-limit fix.** The bench
compose file pins a published tag. If it points at anything older than the tag
you cut *after* the rate-limit merge, you will re-measure the clamp and not
realise it. Start the stack and check the startup log:

```bash
just target=axiam profile=p0-plaintext bench-up
docker logs bench-axiam-server 2>&1 | grep -i "shared rate-limit counter"
```

You **must** see:

```
shared rate-limit counter ACTIVE (write-behind) … sync_interval_ms=1000 shards=16
```

If it says `DISABLED`, `AXIAM__RATE_LIMIT__SHARED=off` leaked into the
environment — unset it; the point of this run is to measure the shipped posture
with the shared layer **on**.
If the line is absent entirely, the image predates the fix. Stop and fix the tag.

**2.2 — Confirm jemalloc.** Same log, at startup:

```bash
docker logs bench-axiam-server 2>&1 | grep -i "allocator"
```

Expect `allocator=jemalloc`. The release Dockerfile defaults
`CARGO_FEATURES=jemalloc`, so a `system` value means someone passed
`--build-arg CARGO_FEATURES=` (that is the *control* build, only wanted for the
memory sensitivity pass).

**2.3 — Confirm the settle gate can pass.** This is the single best
five-minute signal that the run is worth starting. Seed, then let one cell run:

```bash
just target=axiam profile=p0-plaintext bench-seed
just target=axiam profile=p0-plaintext bench-run
```

In the resulting `*.meta.json`, you want `"settle_timeout": false` and
`settle_wait_secs` in the tens of seconds. If instead you get
`"settle_timeout": true` after the full `BENCH_SETTLE_TIMEOUT_SECS` (600 s
default), **do not proceed** — something is still clamping the authz path, and
every authz/token cell in the matrix will be refused by `report.py`. Diagnose
against `postseed-transient-investigation.md` §7 before burning hours.

Then tear down: `just target=axiam bench-down`.

---

## §3 The matrix (the main event)

```bash
cd benchmarks
just repeat=3 bench-matrix
```

Defaults are already what run 4 wants — `targets="axiam keycloak"`,
`profiles="p0-plaintext p2-tls13"`, `repeat=3`, `rl=neutralized`,
`dbcaps=capped`. Cell-order rotation is automatic via `BENCH_RUN_INDEX`, so no
scenario is systematically first (and therefore first-after-seed) across the
three repeats.

Add `zitadel` to `targets` if you want the third comparison target:
`just targets="axiam keycloak zitadel" repeat=3 bench-matrix`.

**Expect this to take several hours.** It is 3 repeats × targets × 2 profiles ×
~12 scenarios, each with warm-up + measured + cooldown, plus a settle gate per
invocation.

### 3.1 Keycloak needs more memory than the default

Keycloak 26/Quarkus **OOM-kills** under load at the harness's default
`BENCH_MEM=1024m` — confirmed twice during H7, and again more acutely on a
smaller box during H10. That produces a red herring: a "Keycloak is slow"
result that is really a dead JVM. Raise it for the Keycloak target only:

```bash
BENCH_MEM=4096m just repeat=3 bench-matrix
```

If you do this, **say so in the report notes** — it breaks the equal-caps
comparability rule that the matrix otherwise maintains, so it must be visible
rather than silent.

---

## §4 Sensitivity passes (the standing list)

Each of these is **one labeled pass**, not a median-of-3. The purpose is to
keep a *visible delta* for every default that changed, so a reader can see what
the flip bought — and to spot-check the postures the matrix doesn't cover.

Run each into its own results directory so the matrix report stays clean:

```bash
# 1. Batch OFF-pass — the default is now `coalesced`, so measure `concurrent`
#    to keep H3's 4.98× vs 1.37× delta visible.
AXIAM__AUTHZ__BATCH_STRATEGY=concurrent \
  BENCH_RESULTS_DIR=$PWD/results/sens-batch-concurrent \
  just target=axiam profile=p0-plaintext bench-up bench-seed bench-run

# 2. Allocator control — jemalloc is now the image default, so the
#    system-allocator build is the control for the memory claim.
#    (Build it with: docker build --build-arg CARGO_FEATURES= …)
#    Or use the dedicated harness: bash run-memory-experiment.sh

# 3. Decision cache ON — default is OFF (H5 kept it opt-in), so this pass is
#    the evidence for the "+x% with cache" claim. Sweep the keyspace.
AXIAM__AUTHZ__DECISION_CACHE_ENABLED=true BENCH_AUTHZ_KEYSPACE=10000 \
  BENCH_RESULTS_DIR=$PWD/results/sens-cache-on \
  just target=axiam profile=p0-plaintext bench-up bench-seed bench-run

# 4. Production rate-limit posture — the matrix runs rl=neutralized.
#    This pass shows the limiter actually limiting.
just rl=prod BENCH_RESULTS_DIR=$PWD/results/sens-rl-prod \
  target=axiam profile=p0-plaintext bench-up bench-seed bench-run

# 5. Uncapped datastore — removes the container CPU/mem caps.
just dbcaps=uncapped BENCH_RESULTS_DIR=$PWD/results/sens-db-uncapped \
  target=axiam profile=p0-plaintext bench-up bench-seed bench-run

# 6. p3-mtls spot check — one cell, just to confirm the profile still works.
just target=axiam profile=p3-mtls bench-up bench-seed bench-run
```

**Do not** run a `pool_size=4` pass expecting a win. H9 closed that as a
negative result (the SurrealDB Rust SDK multiplexes one connection, so the pool
buys no concurrency), and H2 measured `POOL_SIZE=8` as exactly 0 ops/s
difference. Run it only if you want to re-confirm the negative.

---

## §5 SDK benches (E1.3 overhead table)

```bash
just sdk-bench-all          # writes results/sdk/<profile>/<lang>.json, then collects
```

Run it at **both** p0 and p2 so the overhead-vs-wire-baseline table has both
columns. Expected status after H8: **rust, python, go, php, typescript, java**
emit `status:"ok"`; **csharp** stays an honest `pending` (no dotnet toolchain on
the bench host — its preflight prints the exact install commands if you want to
change that). TypeScript and Java are p0-only — both hit unrelated pre-existing
SDK bugs at p2 (an ESM `require()` issue and an OkHttp TLS-hostname issue
respectively), documented in their `TODO.md`s.

Note the wire baseline must be measured **on the same host, at matched VU
concurrency**, or the "overhead" column comes out negative and meaningless —
`sdk/collect.py` carries that methodology note.

---

## §6 E4 — regenerate the public document

Once the matrix and passes are in:

```bash
python3 runner/report.py --results results
```

**Before publishing anything, check the rendered report for all of these:**

- [ ] **No AXIAM cell refused for `settle_timeout`.** A refusal here means that
      cell measured a clamp, not the product. It must not be published.
- [ ] **`http` protocol column populated** on every valid cell (`1.1` / `2.0`),
      never `?`. A `mixed(1.1,2.0)` value means the cell is not
      single-protocol — treat any security-cost comparison across it as
      confounded (`report.py` prints a warning for this).
- [ ] **`authz_batch_rest` / `authz_batch_grpc` valid and ~5× singles.** These
      rows were pure contamination artifacts in every prior run; this is the
      first matrix where they mean anything.
- [ ] **AXIAM `token_refresh` valid, 0 `bench_fallback`, 1.00 req/iteration**,
      and carrying the `protocol-variant` label next to Keycloak's cell.
      AXIAM measures *session refresh*, Keycloak the *OAuth2 refresh grant* —
      they are **not** like-for-like and must not be published as a head-to-head.
- [ ] **No `fallback-op` rows for AXIAM.**
- [ ] **SDK section renders** from real records with the overhead table.

Then regenerate `benchmarks/PUBLIC_BENCH_ANALYSIS.md` from the run-4 medians.
The fourth draft's structure is already in place; what must change is the
*numbers* (they are currently G-box run-3 medians, explicitly labeled as
pre-fix) and these narrative points:

- The transient section: it was never a warm-up transient. Cite the fix, and
  note the published numbers are now post-fix.
- Batch: `coalesced` shipped as default; publish the real ~5× rows.
- Memory: retained-memory caveat is fixed (allocator), not outstanding.
- B2/TLS: h2 is acquitted; the remaining open item is the CC VU-sweep on a
  non-clamped host (see [`b2-tls-h2-investigation.md`](b2-tls-h2-investigation.md)).
- Keep the platform label honest, and keep E3 (server-class re-run) tracked.

---

## §7 Known hazard — read this before a long run

**A stale-DB-handle bug can silently kill a long run**, and it is **not fixed**.

Every repository is built once at boot from a one-time `pool.handle_for_repo()`
clone rather than a live reference. When the DB pool's proactive-reconnect loop
swaps in a fresh connection — observed **~7 minutes into a sustained load run**
— every long-lived handle goes stale and the affected paths **401 permanently
until the process restarts**. A plain `docker restart` of the server clears it
instantly.

This was found during the rate-limit verification and is filed as a follow-up
in the rate-limit PR; it is unrelated to rate limiting itself.

**What it looks like:** a cell that starts fine and then produces a wall of
401s / `bench_failed` for the rest of the run, with the server otherwise
healthy.

**Mitigations, cheapest first:**

1. **Watch for it.** If a cell's error rate jumps to ~100% mid-run, this is the
   first thing to suspect. Restart the server container and re-run that cell.
2. **Restart between repeats.** The matrix already does `bench-up` /
   `bench-down` per target/profile per repeat, which resets the process — so a
   *single cell* is the exposure window, not the whole run. That is why the
   matrix is relatively robust to this and a long single-cell soak is not.
3. **Fix it first** if you would rather not babysit. It is a contained change
   (hold a live pool reference in the repositories instead of a boot-time
   clone), and it would also remove the last reason to distrust a long soak.

---

## §8 If the settle gate times out

Do **not** relax the gate to make it pass. It is not flaky — a timeout is the
gate correctly reporting "this host cannot produce a settled authz cell", and
`report.py` correctly refuses those cells (H1 item 5).

Diagnose instead:

1. Re-check §2.1 — is the write-behind counter actually active? A missing
   `ACTIVE (write-behind)` line is the most likely cause.
2. Run `runner/h2-clamp-probe.sh` against the live stack. It reproduces the
   whole per-endpoint clamp map in a few minutes and will tell you immediately
   whether the wrapped endpoints are pinned again, and at what latency.
3. Compare against the before/after table in
   [`rate-limit-fix-verification.md`](rate-limit-fix-verification.md). If the
   wrapped endpoints are back in the 16–21 ops/s band, the fix is not in the
   image.

Relevant knobs, if you need to reason about the gate rather than change it:
`BENCH_SETTLE_BURST_VUS` (20), `BENCH_SETTLE_BURST_SECS` (15),
`BENCH_SETTLE_PROBE_THR` (400 ops/s), `BENCH_SETTLE_RETRY_SECS` (30),
`BENCH_SETTLE_TIMEOUT_SECS` (600), `BENCH_SETTLE_DRAIN_SECS` (5).

---

## §9 Cross-references

| Document | What it gives you |
|---|---|
| [`postseed-transient-investigation.md`](postseed-transient-investigation.md) | The root cause, the per-endpoint clamp map, the datastore exoneration |
| [`rate-limit-fix-verification.md`](rate-limit-fix-verification.md) | The before/after table and the three mechanism confirmations |
| [`improvement-after-g-benchmark.md`](improvement-after-g-benchmark.md) | The Phase H plan and its §6 execution record (H1–H10 outcomes) |
| [`../benchmarks/docs/methodology.md`](../benchmarks/docs/methodology.md) | Settle gate, cell rotation, metric definitions, comparability labels |
| [`decision-cache-decision.md`](decision-cache-decision.md) | Why the cache is still opt-in, and the seven criteria that would flip it |
| [`db-pool-design.md`](db-pool-design.md) | Why `pool_size` stays 1 (§11 verdict) |
| [`b2-tls-h2-investigation.md`](b2-tls-h2-investigation.md) | The closed h2 verdict and the one open follow-up |
