# PRIVATE — Benchmark Post-Mortem & Improvement Plan

> Internal working document. Companion to `PUBLIC_BENCH_ANALYSIS.md`.
> **Updated 2026-08-06 for run 5** — the first run executed against the
> **published release image** (`ghcr.io/ilpanich/axiam/server:1.0.0-alpha24`,
> digest-pinned `@sha256:a7d415bf…`, tag commit `a36ee3c`), per
> [`claude_dev/run5-runbook.md`](../claude_dev/run5-runbook.md). G-box
> (Dell XPS 15 9570, i7-8750H, 12 logical CPUs, ~31 GiB), Docker 29.6.2,
> k6 v2.1.0, kernel 7.1.5-arch1-2. Full median-of-3 capped matrix across
> **all three profiles for the first time** (p0-plaintext, p2-tls13, p3-mtls;
> AXIAM vs Keycloak 26.7.0 vs Zitadel v4.16.2), the §12.3–12.7 investigation
> passes (I5/I6/I7, KC-4GiB, rl-prod), and the first **median-of-3 SDK pass
> with a matched-VU wire baseline**. Run-4 findings that are resolved are
> compressed; everything still open is carried forward.
>
> **2026-08-06, second pass:** re-analyzed against the operator's *full*
> `results/` copy — the first `bench-pack` archive silently omitted every
> non-k6 artifact (`rl-prod-summary.md`, `h5-revocation.log`, the I5
> docker/nsenter logs, `sdk-report.md`). §1.1, §2.6, §3.1 and §3.2 are
> updated from those artifacts; `bench-pack`'s include patterns get a work
> item (J13).

## 0. Run-5 executive summary

**The headline: all three run-4 mysteries are closed, two of them fully
confirmed.** Run 5 was designed as "re-measure + collect the data I5/I6/I7
need" and it delivered exactly that:

- **I5 (TLS client-credentials plateau) — CONFIRMED as Nagle + delayed ACK,
  and fixed.** The A/B is textbook: `TCP_NODELAY=false` reproduces run-4's
  plateau (1 172/s, p50 42.8 / p95 44.1 ms — the 40 ms delayed-ACK timer in
  plain sight); the shipped default `true` gives 2 642/s at p50 9.5 ms. In
  the matrix, p2 CC is now **2 746/s, −2.0% vs p0** (run 4: −57%). The one
  remaining open sub-question (why CC and not refresh) is moot now that the
  fix ships on by default. §3.1.
- **I6 (REST/gRPC authz asymmetry) — CONFIRMED as the uncached session
  read.** The 2×2 cache matrix: REST check with decision cache only =
  5 597/s; with **both** caches = **11 647/s, matching gRPC's 11 172/s**.
  The runbook's decision rule is satisfied in the confirming direction.
  §3.2.
- **I7 (SurrealDB ceiling / table scans) — success metric met, ceiling
  reframed.** Capped, cache-off REST check hit **1 010/s** (goal ≥1 000;
  run-4 baseline 753). But the DB-uncapped delta narrowed only from ~+90%
  to **+75–79%** — the remaining ceiling is DB *concurrency*, not per-query
  scan cost. Read-replica work moves up the list. §3.3.

Median-of-3, capped, p0, run 4 → run 5 (comparability break: run 5 is a new
baseline — alpha24 image, revised defaults, scans removed, batch default
finally `coalesced`):

| Scenario | Run 4 | **Run 5** | Δ | Note |
|---|---|---|---|---|
| oauth2_client_credentials | 2 727 | **2 804** (±0.6%) | +3% | p2 now 2 746 (−2%), plateau gone |
| token_introspection | 4 387 | **4 504** (±0.5%) | +3% | |
| authz_check_rest | 753 | **1 032** (±0.3%) | **+37%** | I7 scan removal |
| authz_check_grpc | 887 | **1 268** (±1.1%) | **+43%** | 〃; gRPC leads REST +23% |
| authz_batch_rest | 199 (`concurrent`) | **1 026 ops/s = 5 130 checks/s** (±13%) | n/a | **first matrix measurement of the shipped `coalesced` default: 4.97× singles — G3's 4.98× confirmed at scale** |
| authz_batch_grpc | 175 (`concurrent`) | **928 ops/s = 4 640 checks/s** (±17%) | n/a | 3.7× singles |
| userinfo (REST) | 4 547 | 4 752 (±0.5%) | +4.5% | run-4 −9% watch item dismissed as env drift |
| userinfo_grpc | 12 665 | 12 307 (±1.9%) | −3% | noise |
| jwks_fetch | 26 371 | 26 680 (±0.9%) | +1% | generator-limited, unchanged |
| oauth2_password_login | 69 | 69 (±2.0%) | 0% | Argon2id-bound by design |
| token_refresh | 839 | **545** (±1.2%) | **−35%** | ⚠ REGRESSION — §1.2, top new work item |

Two new problems found, plus the formal verdicts from the recovered
investigation artifacts:

1. **The I19 limiter assertions ran — and FAILED on every measured
   endpoint except login.** gRPC under-admits ×20–33 under sustained
   flood despite the I1 ×60 units fix; the REST families **over**-admit
   +12–50% against the ±10% bar; three limiter families have no scenario
   coverage at all (§1.1).
2. **token_refresh lost a third of its throughput** since run 4 with no
   harness change on that path (§1.2).
3. The **revocation regression cell passed** (event-driven invalidation
   deny in 262 ms; out-of-band deletes TTL-bounded), unblocking the
   session-cache guidance (§3.2) — while the I5 stage-timing logs turned
   out to contain **zero perf events** because `RUST_LOG` never reached
   the container (§2.6); the arm-B socket capture supplies the missing
   proof instead (§3.1).

## 1. ⚠ Run-5 discoveries

### 1.1 The I19 limiter assertions ran, and the shipped posture fails them in both directions

`section-12_7/rl-prod-summary.md` (recovered in the full archive) is the
official verdict table — `rl_prod_check.py`, configured limits extracted
read-only from source at the alpha24-descendant checkout, ±10% tolerance
(I1's own acceptance bar), single-IP 50-VU flood:

| Endpoint | Configured (per min) | Admitted (per min) | Verdict |
|---|---|---|---|
| POST /api/v1/auth/login | 10 | 11 | **PASS** |
| POST /oauth2/token (CC) | 120 | 135 | **FAIL** (+12%) |
| POST /oauth2/introspect | 600 | 889 | **FAIL** (+48%) |
| POST /api/v1/authz/check (+ batch, shared bucket) | 1 800 | 2 699 | **FAIL** (+50%) |
| gRPC authz family | 6 000 | **181** | **FAIL** (~1/33) |
| gRPC identity family | 30 000 | **1 504** | **FAIL** (~1/20) |
| POST /oauth2/revoke | 60 | — | **no scenario — not checked** |
| gRPC admin family (SEC-079 absolute) | 600 | — | **no scenario — not checked** |
| gRPC infra family (fixed) | 6 000 | — | **no scenario — not checked** |

Three separate findings in one table:

1. **REST over-admission is a formal FAIL, not a footnote** — +12% on
   token (just outside the bar), +48–50% on introspect/authz_check.
   Shape-wise it's token-bucket burst-allowance bleeding into a sustained
   window; whether that's acceptable-and-documented (relax the assertion
   to model burst) or a bug (tighten the bucket) is a product decision —
   but today the code fails its own test.
2. **gRPC under-admission confirmed at ×20–33.** The ×60 *units* bug is
   fixed (we are no longer at exactly 1/60), but under a ~25 k attempts/s
   flood the admitted rate collapses to a few per second.
3. **Coverage gaps**: revoke, gRPC admin and gRPC infra families have no
   scenario at all — the SEC-079 ceilings that were specifically
   realigned for this run were never actually exercised (J1c).

**Working hypothesis for the gRPC starvation (from the two-layer design,
not yet verified):** the shared write-behind pre-check enforces its quota
over a 60 s window, so under flood it admits its entire 6 000-request
window allowance in the first ~fraction of a second of each window; the
in-memory governor behind it (per-second quota, small burst) then only
passes ~burst + rate×t of that front-loaded spike before the pre-check is
exhausted for the rest of the window. Two limiters, same nominal rate,
mismatched windows ⇒ multiplied rejection. If that's right, the fix is to
align the pre-check's window with the governor's (per-second) or drop one
layer for gRPC. **Task J1** (now covering both directions: the gRPC
starvation *and* the REST +48–50% overshoot). Note the starvation only
manifests under sustained overload — a compliant client under the limit is
unaffected — but "the abuse posture starves to ~3% of its advertised
ceiling under abuse" is exactly the situation the posture exists for, so
this blocks advertising gRPC prod-posture numbers, again.

### 1.2 token_refresh −35% (839 → 545/s, p50 47.5 → 88.8 ms) — real regression, cause unknown

Tight medians on both sides (±0.4% run 4, ±1.2% run 5), same scenario, same
50-VU envelope, DB pegged (bottleneck `bench-axiam-surrealdb`) in both runs
— this is not noise and not a harness change we know of. What changed
between the run-4 image and alpha24 on this path: the post-run-4 security
series (53 commits — session/audit work, OBS-1 keyed hashing, SEC-079),
plus SurrealDB moved to the digest-pinned v3 tag. Candidate mechanisms, in
order of plausibility:

1. extra per-refresh DB work added by the security series (session
   validation/rotation bookkeeping, audit emission on the rotate path);
2. SurrealDB version drift changing the cost of the session
   read-rotate-write transaction;
3. envelope/thermal drift (weak — every other DB-bound cell got faster or
   held).

p50 nearly doubled while p95 only grew from ~81 to ~111 ms — the whole
distribution shifted right, consistent with added serialized per-request
work rather than tail contention. **Task J2: bisect with stage timings on
the refresh handler (same treatment I5 got), then either fix or accept and
document.** Until then the public doc reports the regression openly with
"under investigation". Refresh still leads Keycloak's OAuth2 grant
(protocol-variant label as always: 545 vs 377), so the competitive story
survives; the trend is what's alarming.

### 1.3 The 4 GiB Keycloak login cells made things *worse* — new anomaly

§12.3 ran KC login alone at `BENCH_MEM=4096m` (single pass per profile,
recorded in meta): **20.7/s p0 and 20.8/s p2, p50 ≈ 2.25 s, p95 ≈ 2.53 s**
— stable (zero errors, no OOM kill, which was the point) but *half* the
throughput of the 2 GiB cells that survived (47–51/s) and failing the
p95 < 2 s validity gate outright. Meanwhile in the 2 GiB matrix KC login
finally produced a **valid p2 cell (2/3 runs, 51/s)** — its first ever —
while p0 stayed 1/3 and p3 went 0/3.

So H7's "KC needs ~3.5–4 GiB" prediction is refuted in the interesting
direction: more heap bought stability but cost half the throughput
(plausibly JVM heap-share sizing → bigger GC pauses, or Argon2id memory
interplay; not investigated). **Task J3: treat KC login as
memory-*sensitive*, not memory-starved; if we keep chasing a fair KC login
number, sweep KC's own heap knobs instead of the container cap — otherwise
declare the 2 GiB p2 cell (51/s) its best measured result and stop.**
Public doc publishes: AXIAM 69/s valid 3/3 at every profile; KC 51/s valid
at p2 only; the 4 GiB attempt reported honestly as a failed rescue.

### 1.4 refresh-under-prod errors doubled (I4 not fixed)

rl-prod refresh: 516/s with **4.4%** errors (run 4: 694/s, 2.4%). The I4
harness fix (budget re-logins inside the 10/min login bucket, or pre-mint
sessions) was specced but evidently not effective/not applied. Carry as
J4. The coupling note for product docs stands: short-session deployments'
refresh capacity is effectively gated by the login limit.

### 1.5 SDK pass: two of the four run-4 SDK defects are actually closed

The good: median-of-3 with a matched-VU wire baseline ran end to end
(first time), C# refresh now measures a real call (17.2 ms p50, the I9
guard held), client CPU/RSS telemetry is live for all 11 SDKs, C/PHP are
segregated as `conc=1` serial benches (I10). The bad:

- **Python's async rewrite did not close the gap** — check p50 40.2 ms /
  p95 116.8 ms (run 4 sync-over-threads: 30.3/76.1), throughput 311 vs 444
  rps, at +55–60 ms p95 over wire while go/java/rust sit at +3 ms. The
  Little's-Law analysis said the old number was a harness artifact; the new
  harness is clean and *slower* — so the residual is in the SDK or asyncio
  itself. Reprofile (J5). Until then Python is honestly the slow outlier.
- **C++ tail persists**: check p50 3.2 ms / p95 280 ms — identical
  signature to run 4 despite the MAXAGE_CONN/happy-eyeballs fix shipped in
  the C++ SDK. Its own acceptance criterion (p95 ≤ 3× p50) **fails**. The
  runbook's fallback suspects (server-side idle timeout, `Connection:
  close` on some path) are now the live hypotheses (J6).
- **TypeScript measures *negative* overhead** (−21 to −23 ms p95 vs wire on
  check/batch; its p95 34 ms vs wire 57 ms). A client can't beat the wire
  on the same box unless it's not doing the same thing as the k6 baseline —
  likely connection-reuse or pipelining asymmetry vs k6's model. Audit the
  baseline comparability before publishing any TS-vs-wire claim (J7);
  the TS row's absolute numbers look fine.
- **C# merged only 2/3 passes** (`median of 2`) and its refresh throughput
  reads 20 rps vs ~55 for everyone else — one dropped pass + a
  serialization quirk in the refresh loop; minor, but check (J8).
- cpp is now conc=16 (was effectively serial-ish tail behavior), c stays
  conc=1 **including for refresh** ("SDK_BENCH_CONCURRENCY was read but not
  applied" per its own notes) — fine, labeled.

Cross-language consistency otherwise excellent again: login p50 232–257 ms
(server Argon2 dominates), refresh 16.7–17.3 ms across ten SDKs, check p95
60–62 ms for every healthy conc-16 SDK — wire +3–5 ms. That last number is
the E1.3 deliverable: **SDK overhead on the hot op is single-digit ms at
p95 for 7 of 9 concurrent SDKs.**

The I13 client telemetry (first pass) adds the footprint axis: client CPU
over the bench ranges from **Go 3.3 s** to **Python 40 s**; peak RSS from
**C 13 / Rust 23 MiB** to JVM 306–458 MiB. One anomaly for the list:
**Rust's client CPU reads 23.4 s** — highest of the compiled SDKs and 7×
Go's — despite the best latency/throughput. Suspect the harness (CPU
counter possibly including build/spawn, or a busy-poll in the bench loop)
before the SDK; second look queued (J8b).

## 2. Data-validity notes

### 2.1 Validity: 64/72 matrix cells, all 8 exclusions explained, none AXIAM's

AXIAM: **36/36 valid** across all three profiles (first run with p3 in the
matrix proper). Exclusions: KC login p0 (1/3) and p3 (0/3) — §1.3; Zitadel
login all profiles (0/3, bcrypt-at-default ~22 s p50, known/tunable);
Zitadel refresh all profiles (0/3, fallback-op — no `offline_access`
harness flow; upstream `zitadel/zitadel#7900` still open, I17 carried).
KC login **p2 is valid for the first time** (2/3, 51/s).

### 2.2 Settle gate: clean

15 s first-probe clear on every session, zero timeouts, zero refused cells
— second consecutive clean run; the H1/H10 machinery remains vestigial
post-H2-fix. Good.

### 2.3 Provenance: image digest-pinned ✅, build_ref footnote

Every AXIAM cell records image
`ghcr.io/ilpanich/axiam/server@sha256:a7d415bf…` (digest-pinned per §12.1
step 3 — the runbook was followed) and SurrealDB digest-pinned
(`@sha256:51baed87…`). `build_ref` is `1df1a83`, which is **on main** (I18
preflight passes) but is main's HEAD of Aug 5 — the operator ran the
harness from main, not from the `v1.0.0-alpha24` tag (`a36ee3c`) the
runbook specified. Checked: `a36ee3c` is an ancestor of `1df1a83` and the
five intervening commits touch only `benchmarks/`, docs and website — the
binary under test is the released image regardless (that's what digest
pinning is for). Verdict: provenance is sound; note the tag/HEAD mismatch
so nobody bisects against the wrong checkout later. One consequence: the
§12.7 harness (rl_prod_check, justfile posture) at `1df1a83` includes the
SEC-079 realignments — which is the *correct* harness for the alpha24
image, so this mismatch is harmless here.

### 2.4 Run-4 watch items: both dismissed

- userinfo REST −9% (run 4): recovered to 4 752 (+4.5%); env drift,
  closed.
- cache-pass introspection −21% (run 4): this run's matrix introspection is
  +2.7% and the §12.5 pass didn't touch introspection; nothing reproduced,
  closed.

### 2.5 Thermals

Unchanged posture: hot cells at 95–100 °C, mhz_avg 3.12–3.89 GHz across
cells, `clock_variance` host-flag on most KC and Zitadel login/CC cells
(they run cooler-clocked because they're slower — the flag marks variance,
not unfairness in AXIAM's favor; AXIAM's own hot cells are the
thermally-worst ones). Median-of-3 spreads: ≤±2% on almost all AXIAM
cells, except batch gRPC/REST at ±12–17% (coalescing makes throughput
sensitive to arrival phasing — worth a note, not a gate). Server-class
re-run remains the standing caveat.

### 2.6 Artifacts: all recovered in the full archive — with two harness findings

The first `bench-pack` tarball contained only the k6/meta/CSV files; the
operator's full `results/` copy adds `rl-prod-summary.md` (§1.1),
`section-12_5-h5/h5-revocation.log` (§3.2), the I5 docker-log captures
plus `nsenter.log` socket snapshots (§3.1), and `sdk-report.md`
(identical to report.md's SDK section). Two findings from the recovery:

- **`bench-pack` silently drops every non-k6 artifact** — exactly the
  `.md`/`.log` files that carry the investigation verdicts. Fix the
  include patterns (J13).
- **The I5 stage-timing instrumentation produced nothing**: both arm logs
  contain zero `axiam::perf` DEBUG events, and `RUST_LOG` is absent from
  every cell's recorded `axiam_env` — the variable never reached the
  container (the §12.0 allow-list failure mode the runbook itself warned
  about, biting the one variable the runbook forgot to verify). The I5
  *conclusion* is unaffected — the A/B + VU sweep + socket capture are
  decisive (§3.1) — but the handler-stage breakdown planned in §4.3 of
  the runbook still doesn't exist. Add `RUST_LOG` to the compose
  allow-list check and to the §12.5-style `docker inspect` verification
  (J9, repurposed).

## 3. What the investigation passes taught

### 3.1 I5 closed: it was Nagle all along

| Cell (p2 CC unless noted) | thr | p50 / p95 |
|---|---|---|
| Arm B — `TCP_NODELAY=false` (pre-I5) | 1 172 | 42.8 / 44.1 ms |
| Arm A — `TCP_NODELAY=true` (shipped) | 2 642 | 9.5 / 57.5 ms |
| p0 control | 2 757 | 8.9 / 57.6 ms |
| Matrix p2 (default) | 2 746 | 9.1 / 57.3 ms |

Arm B reproduces run-4's 1 180/s @ ~43 ms flat to three significant
figures; arm A collapses to the p0 shape. That is the §4.4 decision rule's
"confirms" row almost verbatim. The VU sweep (1→100, p0 and p2) adds the
missing dynamics: p2 tracks p0 within 2–6% at *every* VU count
(533→2 737/s p0; 501→2 683/s p2), saturating ~2.7 k/s from 20 VUs — a
constant small per-request TLS cost plus the DB ceiling, no serialization
point anywhere.

The full archive adds the wire-level smoking gun: arm B's `ss -ti`
snapshot (`section-12_4-B1/nsenter.log`) shows **18 of 20 established
connections frozen with `Send-Q 707`, `unacked:1`, `notsent:31` and
`ato:40`** — 707 bytes sitting in the send queue, 31 more held back
behind one unacked segment, waiting out the peer's 40 ms delayed-ACK
timer. The p0 control snapshot shows zero `notsent` connections and
Send-Q 0 on 15/20. That is Nagle photographed in the act. (The planned
in-handler stage timings do *not* exist — `RUST_LOG` never reached the
container, §2.6 — but they're no longer needed for the verdict.)
B2/H6/G8-TLS is closed.

### 3.2 I6 closed: the 2×2 says it was the session read

p0, authz_check, 50 VUs (§12.5):

| | session cache OFF | session cache ON (TTL 5 s) |
|---|---|---|
| decision cache OFF | REST 1 013 / gRPC 1 248 | REST **1 177** (+16%) / gRPC 1 244 (0%) |
| decision cache ON | REST 5 597 / gRPC 11 122 | REST **11 647** / gRPC 11 172 |

Reading: session cache alone buys REST +16% and gRPC exactly nothing
(gRPC never did the session read — as diagnosed); with both caches REST
*passes* gRPC. The run-4 prediction "decision-only stays ~791" was wrong
in level (5 597 — because I7's scan removal cheapened the remaining
session read massively) but the asymmetry mechanism is confirmed in full.
Ship-decision consequences:

- **The §5.4 revocation cell ran and passed** (`h5-revocation.log`,
  cache=on, TTL 5 s): (A) event-driven invalidation — REST role unassign
  → deny served **262 ms** later, the invalidation hook fires end to end;
  (B) suppressed invalidation — an out-of-band `has_role` edge delete
  directly in SurrealDB produced 22 stale allows, first deny at entry age
  5 179 ms, **bounded by TTL + slack as the contract promises**. So the
  cache guidance can ship, contract stated: event-path revocation is
  immediate; only writes that bypass the API entirely wait out the TTL.
- The session-validation cache is worth ~2× on cached REST checks and
  ~16% uncached; it stays **default-off** (same stays-opt-in reasoning as
  the decision cache, H5, and the K=1 ceiling caveat applies to the
  11.6 k number verbatim) — but with the revocation cell green it can now
  be *documented and recommended* for measured workloads.
- The security note is unchanged and now measured: gRPC's speed advantage
  partly *is* the absence of the per-request revocation check
  (`middleware/auth.rs:42` validates the token and stops). That tradeoff
  should be documented as a posture choice, not discovered by users (J10 —
  docs task; consider an opt-in strict-revocation gRPC mode post-beta).

### 3.3 I7: fix confirmed, ceiling reframed as concurrency

§12.6, both caches off, p0:

| cell | capped (2c DB) | uncapped (4c) | Δ |
|---|---|---|---|
| authz_check_rest | 1 010 | 1 804 | +79% |
| authz_check_grpc | 1 238 | 2 162 | +75% |
| authz_batch_rest | 1 006 ops/s | 1 776 ops/s | +77% |

Success metric met (≥1 000 capped, cache-off; run 4: 753). The uncapped
delta narrowed (+90% → ~+77%) but not to the "scan cost was the ceiling"
level — per §6.2's decision rule, the remaining ceiling is **DB
concurrency**, so the priority order flips: read-replica design work (with
its stale-allow staleness problem stated) moves ahead of further per-query
tuning; CP-3 (DB container tuning) is worth one measured pass now that its
premise is clean (J11). Seed-size sensitivity still blocked on bulk-seed
tooling (harness gap, carried as J12).

### 3.4 Batch: the shipped default finally measured, G3 vindicated

Matrix `coalesced` (the default, at last): REST 1 026 ops/s = 5 130
checks/s = **4.97× singles** — G3's settled 4.98× reproduced at matrix
scale, case closed. gRPC batch 928 ops/s = 4 640 checks/s = 3.66× its
singles. Batch REST slightly out-throughputs batch gRPC on checks/s (the
gRPC batch pays more per-op overhead at this shape); fine to publish with
the ±13–17% spread noted. The run-4 `concurrent` numbers are historical
footnotes now.

### 3.5 mTLS at matrix scale: parity holds for AXIAM, costs Keycloak

First full-matrix p3: AXIAM p3-vs-p0 deltas are −0.3% to −3.8% everywhere
except jwks (−10.2%, same as plain TLS — it's the h1→h2 protocol change +
handshake cost on the generator-limited cell, not mTLS). p2→p3
specifically is ≤1.2% on every AXIAM cell — client-cert verification
remains free on top of TLS 1.3. Keycloak pays −17.2% on jwks at p3 and its
login collapses to 22/s (0/3 valid); Zitadel is flat (−2 to −4%). The IoT
headline survives its third re-measurement, now in the run of record
rather than a sensitivity pass.

## 4. Memory & CPU (run 5)

Server-container averages across the p0 matrix (per-container appendix):

| target | server avg RSS | server avg CPU | whole-stack mem (range) |
|---|---|---|---|
| **AXIAM** | 86–120 MiB | 0.46–1.82 cores | 375–533 MiB (incl. SurrealDB + RabbitMQ) |
| Keycloak | 674–853 MiB | pegged 1.99–2.00 | 816–973 MiB |
| Zitadel | 135–169 MiB | 0.43–1.87 | 281–457 MiB |

Whole-stack cpu·ms/req p0: CC **1.23** / 5.85 / 8.21 (AX/KC/Zit);
introspection **0.79** / 1.25 / 3.98; jwks **0.06** / 0.44 / 1.43;
userinfo 0.70 / **0.54** / 2.89 (KC still wins that one whole-stack;
server-only AXIAM 0.25 vs 0.53 — publish both, same as run 4). thr/GiB
p0: jwks 66 270 / 5 022 / 7 351; CC 6 528 / 416 / 1 239; introspection
9 312 / 2 134 / 2 228; userinfo 11 522 / 4 319 / 2 319. The story is
stable across two runs now — publishable with confidence. Honesty notes
carry over verbatim (RabbitMQ+SurrealDB ride in AXIAM's stack figures;
Zitadel's server is the smallest of the three at idle-ish loads; publish
per-container bars).

## 5. Work items (evidence-ranked, post-run-5)

1. **J1 — limiter enforcement fails I19 in both directions** (§1.1):
   gRPC flood starvation (verify the two-layer window-mismatch
   hypothesis; align windows or drop a layer) *and* REST +48–50%
   over-admission (decide: model burst in the assertion, or tighten the
   bucket). Keep the assertion running *under sustained flood*. Blocks
   advertising gRPC prod posture. **J1c**: add scenarios for the three
   unchecked families (revoke, gRPC admin, gRPC infra — the SEC-079
   ceilings were realigned for this run and then never exercised).
2. **J2 — token_refresh −35% regression** (§1.2): stage-time the refresh
   handler, bisect security-series commits vs SurrealDB drift.
3. **J9 — RUST_LOG never reaches the container** (§2.6): add it to the
   compose allow-list + a `docker inspect` preflight check, so the I5/J2
   stage-timing instrumentation can actually emit. **J13 — fix
   `bench-pack`** to include `*.md`/`*.log` investigation artifacts (this
   run's verdict files were all silently dropped).
4. **J5/J6/J7/J8 — SDK**: Python async residual; C++ tail (now suspect
   server-side idle timeout); TS negative-overhead baseline audit; C#
   2/3-pass + refresh-throughput quirk.
5. **J10 — document the gRPC no-revocation-check posture** (§3.2); design
   opt-in strict mode. Also ship the session-cache docs with the measured
   revocation contract (262 ms event-path / TTL-bounded out-of-band).
6. **J11 — DB concurrency ceiling**: one measured CP-3 pass; read-replica
   design doc to review (staleness contract).
7. **J12 — bulk-seed tooling** for the 10× seed-size cell (carried).
8. **J3 — KC login**: stop raising the container cap; either sweep KC heap
   knobs once or freeze the story at "51/s, p2, 2 GiB, 2/3".
9. **J4 — refresh-under-prod re-login budget** (carried I4, worse now).
10. **Server-class hardware re-run** (perennial; unblocked whenever budget
    allows — every laptop caveat in §2.5 goes away with it).

## 6. Publishing guidance for the site (run-5 deliverables)

- Publish run 5 as **the new headline matrix** (release image, all three
  profiles, 64/72): CC 7.9×/6.5× (and now ~8× under TLS too — the plateau
  is gone), introspection 2.4×/4.8×, jwks 5.8×/12.8×, userinfo REST
  1.3×/4.8× + 12.3 k/s gRPC, checks 1 032/1 268 with **batch 5 130
  checks/s at the shipped default**, login only-target-valid-everywhere.
- Publish the **three closed mysteries as a narrative** (Nagle A/B, cache
  2×2, index scans) — "the benchmark found it, the code fixed it, the
  re-run proved it" is the project's best credibility asset, better than
  any single ratio.
- Publish the **refresh regression openly** (545, −35%, under
  investigation) — same honesty pattern as the H2 write and the ×60 bug.
- Publish mTLS parity from the run of record.
- Publish the revocation-cell result alongside the cache numbers (262 ms
  event-path deny; TTL-bounded out-of-band window) — it is the honest
  answer to "does the cache break revocation" and we now have it.
- Publish the I19 verdict table honestly (login PASS, everything else
  measured FAIL) — "our own assertion script fails our shipped posture"
  is the same credibility pattern as the ×60 bug, and it's what makes
  the eventual fix verifiable.
- Do NOT publish: gRPC prod-posture *throughput* numbers (J1 open),
  TS-vs-wire overhead (J7), any KC-login number other than "51/s at p2
  (2/3 valid); 4 GiB attempt made it stable but slower and still
  invalid".
- Keep verbatim: protocol-variant refresh label, cc-token-setup label,
  h1→h2 protocol-confound note, D8 client_id-keying caveat, the corrected
  "25–2 700×, authz tightest" capacity-margin range (never "≥500×").
