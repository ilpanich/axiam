# D9 — Memory-Retention Allocator Experiment

Status: **DONE — measured (G6, 2026-07-28), PASS, shipped as the release
container default (H4).** jemalloc closed 94% of the observed retention gap
(threshold ≥30%) with no throughput caveat; see §6 for the numbers and the
action taken. This note still documents the original hypothesis,
reproduction procedure, A/B method, and decay-tuning rationale (§1–5) for
reference.

Related: [`benchmark-improvement-plan.md`](benchmark-improvement-plan.md) §D9.
Depends conceptually on B1 (`crates/axiam-auth` Argon2 concurrency semaphore,
already landed) — B1 caps the concurrent-hashing **peak**; this task is about
the **retention** after the peak subsides.

## 1. Hypothesis

Evidence from the first benchmark run: server RSS never returns to baseline
after a login burst.

- Baseline (idle, post-boot): ~93 MiB RSS
- Post-burst steady state (observed, did not decay over the observation
  window): ~646 MiB RSS

This is consistent with a well-known glibc `malloc` behavior: freed large
allocations from a burst of concurrent work (here, Argon2id hashing arenas —
~19 MiB each, per B1's analysis) get returned to glibc's internal free lists
per-arena, but the **arenas themselves are not unmapped / `madvise`d back to
the OS** unless a full arena happens to be entirely free and glibc's trimming
heuristics decide to release it. Under bursty, multi-threaded load (many
threads each getting their own arena via `spawn_blocking`'s blocking pool),
this is a known pathological case for glibc's allocator — high peak
concurrency permanently inflates the number of live arenas even after load
drops back to near-zero.

**Hypothesis:** replacing the global allocator with jemalloc — which
purges freed "dirty" pages back to the OS on a decay timer rather than
relying on glibc's arena-trim heuristics — will make retained RSS after a
burst converge back toward baseline within the decay window, with no
material throughput cost.

**Null hypothesis / alternative explanation to rule out:** the retention
could instead (or additionally) be caused by growth in long-lived
server-owned structures that scale with request volume (e.g. the D7 authz
decision cache if enabled, the B3 JWKS response cache, connection pool
buffers, or SurrealDB client-side buffering) rather than allocator
fragmentation. The A/B test below is designed to distinguish these: if
retained RSS is nearly identical between the default allocator and jemalloc,
the leak/growth is in-process (a real bug to chase, not an allocator
artifact); if jemalloc's retained RSS is materially lower, the glibc-arena
hypothesis is confirmed and the fix is legitimate.

## 2. What's implemented (this task's deliverable)

Because this sandbox cannot run the server or the bench stack (no live
process, and the full `axiam-server` release binary link risks OOMing the
container), the actual RSS measurement is **not done here**. What ships
instead:

1. **`crates/axiam-server/Cargo.toml`** — `tikv-jemallocator = { version =
   "0.7", optional = true }` as an optional dependency, plus a `jemalloc`
   Cargo feature (`jemalloc = ["dep:tikv-jemallocator"]`). **Not** part of
   `default = ["saml"]` — a default build (`cargo build -p axiam-server`,
   and therefore every existing CI/Docker build) pulls in and links exactly
   what it did before this change. `tikv-jemallocator` 0.7.0 was the current
   crates.io release at the time of writing and resolved cleanly against the
   workspace's `edition = "2024"` / `rust-version = "1.93"` toolchain
   (verified via `cargo check`, see §5).
2. **`crates/axiam-server/src/main.rs`** — behind `#[cfg(feature =
   "jemalloc")]`:
   ```rust
   #[global_allocator]
   static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
   ```
   With the feature off (default), this line does not exist in the compiled
   binary at all — zero behavior change, zero new transitive dependency in
   the default dependency graph or lockfile resolution used by a default
   build.
3. This note.

No changes were made to `docker/Dockerfile.server` or the bench compose
files **at the time this section was written**: the plan explicitly allowed
documenting the invocation instead of wiring a build variant "only if it's
clean," and doing so untested (this sandbox could not build/link the release
binary at the time) would have risked landing an unverified Docker/compose
change. The exact commands to build and run the jemalloc variant were
documented below (§4) instead — wiring them into `docker/Dockerfile.server`
as the default was explicitly deferred to "a small follow-up once the laptop
measurement confirms the allocator is worth shipping."

**That follow-up is done.** §6 records the laptop measurement (G6, PASS),
and H4 landed the `docker/Dockerfile.server` change: the image now builds
with `--features jemalloc` by default via a `CARGO_FEATURES` build ARG. See
§6 for the numbers and the exact mechanism.

## 3. Reproduction procedure (to run on the laptop)

Uses the existing bench harness; no new tooling needed.

```bash
just target=axiam bench-up bench-seed      # bring up + seed the AXIAM target
source benchmarks/.seed/axiam.seed.env      # or wherever A7 relocated it
```

1. **Record baseline RSS.** Let the server sit idle ~30s post-seed, then:
   ```bash
   docker stats --no-stream bench-axiam-server --format '{{.MemUsage}}'
   ```
   Expect ~90-100 MiB (matches the ~93 MiB baseline from the original run).
2. **Drive the login burst.** Run the existing password-login scenario at the
   same concurrency used in the original benchmark (50 VUs):
   ```bash
   k6 run benchmarks/scenarios/oauth2_password_login.js
   ```
3. **Watch RSS for 10 minutes post-burst.** Sample every 10-15s for at least
   10 minutes after the k6 run exits:
   ```bash
   for i in $(seq 1 60); do
     docker stats --no-stream bench-axiam-server --format '{{.MemUsage}}'
     sleep 10
   done
   ```
   Record the RSS trajectory: peak-during-burst, immediately-post-burst, and
   the value at each subsequent minute out to 10 minutes. The original
   evidence is that this value plateaus around ~646 MiB and does not
   decay further — confirm this reproduces before attributing anything to
   the allocator.

## 4. A/B method

Run the reproduction procedure (§3) twice — **same load, same seed data,
same host state** (governor, AC power, background apps quiesced per the C3
runbook) — once per binary variant:

### Variant A — default (control)

```bash
just target=axiam build=1 bench-up   # forces a local image build
# (or, without docker): 
cargo build --release -p axiam-server
```
No feature flags. This is today's shipped behavior.

### Variant B — jemalloc

```bash
cargo build --release -p axiam-server --features jemalloc
```
For a containerized A/B, add a temporary build-arg override to
`docker/Dockerfile.server`'s final `cargo build --release -p axiam-server`
line (`--features jemalloc`) or build the binary locally and mount it over
the image's `/usr/local/bin/axiam-server` — either is fine for a one-off
laptop comparison; don't commit either hack without re-verifying it against
a real Docker build first.

### What to compare

- **Retained RSS**: steady-state `docker stats` RSS at the 10-minute mark
  post-burst, variant B vs variant A. This is the primary metric — jemalloc
  is "worth it" only if this drops materially (propose a threshold of ≥30%
  reduction toward baseline, i.e. closing at least 30% of the ~550 MiB gap
  between the ~93 MiB baseline and the ~646 MiB plateau).
- **Throughput / latency, no regression check**: rerun
  `oauth2_password_login`'s req/s and p50/p95 under variant B and confirm it
  is within noise (~±5%, consistent with the plan's other A/B acceptance
  bars) of variant A. jemalloc swapping the global allocator can move
  allocation-heavy hot-path latency in either direction; a retention win that
  costs throughput is not an unambiguous win and should be reported as a
  trade-off, not a straightforward fix.
- Record both variants' `meta.json`/`res.csv` under separate result dirs
  (e.g. `results/d9-jemalloc-off/`, `results/d9-jemalloc-on/`) so the
  comparison is reproducible and reviewable, mirroring the existing bench
  result layout.

## 5. Decay tuning

jemalloc's default behavior already purges freed "dirty" pages back to the
OS via `madvise(MADV_DONTNEED)`/`MADV_FREE` on a **decay timer** (default:
dirty pages decay over ~10s, "muzzy" pages — a middle state between dirty and
fully purged — over another ~10s), rather than glibc's arena-trim
heuristics. This alone should improve on the retention baseline. Whether to
tune the decay times *more aggressively* than the default is an orthogonal
knob, controlled entirely at **runtime via environment variable** — not
hardcoded in `main.rs` — so it can be tuned per-deployment without a
rebuild:

```bash
# tikv-jemallocator reads _RJEM_MALLOC_CONF first, falling back to
# MALLOC_CONF if unset (the "_RJEM_" prefix avoids colliding with a
# system glibc/other-jemalloc build that also honors MALLOC_CONF).
export _RJEM_MALLOC_CONF="dirty_decay_ms:1000,muzzy_decay_ms:0"
# or, if only one jemalloc is in play on the host:
export MALLOC_CONF="dirty_decay_ms:1000,muzzy_decay_ms:0"
```

Rationale for the specific example values (not committed as a default —
illustrative only, to be validated against the A/B data):

- `dirty_decay_ms:1000` — purge freed-but-still-mapped ("dirty") pages back
  to the OS ~1s after they go idle, instead of jemalloc's default ~10s. For
  a bursty workload (login spikes, then quiet), a short decay converts idle
  memory back into free OS pages quickly, which is exactly the behavior the
  retention bug needs.
- `muzzy_decay_ms:0` — skip the intermediate "muzzy" state entirely (pages
  go straight from dirty to fully purged); muzzy exists as a cheaper
  halfway point for allocator-churn-heavy workloads that will likely reuse
  the memory soon, which is not this workload's profile during the 10-minute
  post-burst observation window.

**Caution:** more aggressive decay trades retained-RSS improvement for more
frequent `madvise` syscalls and potential page-fault cost on the *next*
burst (pages have to be faulted back in / re-zeroed). This is exactly what
the throughput side of the A/B comparison (§4) is meant to catch — if p95
regresses under variant B with aggressive decay, try the jemalloc defaults
(no `MALLOC_CONF` override) before concluding jemalloc doesn't help.

`tikv-jemallocator` also exposes a `stats` Cargo feature (not enabled here)
that adds `jemalloc_ctl`-based introspection (`stats.resident`,
`stats.retained`, arena counts) if finer-grained diagnosis is needed beyond
`docker stats`' whole-process RSS — worth enabling temporarily during the
laptop investigation if the plain RSS numbers are ambiguous, but not proposed
as a permanent addition.

## 6. Conclusion — G6 measurement (PASS)

**Status: measured, decided, shipped.** The A/B in §4 was run as part of the
G-task benchmark pass (G6, 2026-07-28) on the laptop/bench stack, same load
(`oauth2_password_login`, 50 VUs), same seed data, same host state for both
variants:

| Variant | Baseline RSS | Peak RSS (during burst) | Retained RSS (post-burst plateau) | Retained above baseline |
|---|---|---|---|---|
| A — default allocator (glibc malloc) | 68 MiB | 491 MiB | 376 MiB | +309 MiB |
| B — jemalloc | 69 MiB | 126 MiB | 86 MiB | +17 MiB |

- **Retention gap under default malloc:** 376 − 68 = **309 MiB**.
- **jemalloc closes 309 − 17 = 292 MiB of that gap ⇒ 94%** (309 → 17 MiB
  retained above baseline), well past the §4 ship threshold of ≥30%.
- **Peak RSS during the burst also dropped ~74%** (491 → 126 MiB) — jemalloc
  is not just decaying faster after the fact, it never inflates as much in
  the first place, consistent with the glibc-per-thread-arena hypothesis in
  §1 (arenas are the thing jemalloc doesn't multiply the same way under
  `spawn_blocking`'s blocking-pool concurrency).
- **Throughput/latency: no regression recorded.** The login-burst k6 numbers
  for variant B were within noise of variant A — no throughput caveat to
  report. This is an unambiguous win, not a trade-off.
- **Decay tuning was not needed to get these numbers.** Both variants ran
  with jemalloc's out-of-the-box decay settings (no `MALLOC_CONF`/
  `_RJEM_MALLOC_CONF` override) — see §5's example values, which remain
  documented as an available (not required) knob for workloads with a
  different retention profile.

**Verdict:** PASS — the glibc-arena hypothesis from §1 is confirmed (an
allocator swap alone accounts for the vast majority of the retention), and
the null hypothesis (in-process growth: decision cache, JWKS cache, pool
buffers) is *not* what's driving this number, since an allocator-only change
closes 94% of it.

**Action taken (H4, `claude/g-benchmark-improvements-n5mjmj`):** jemalloc is
now the **release container default**. The crate's `jemalloc` Cargo feature
in `crates/axiam-server/Cargo.toml` stays opt-in at the crate level (a plain
`cargo build -p axiam-server` is unaffected, exactly as before) — the change
is in `docker/Dockerfile.server`, which now builds with
`--features jemalloc` by default via its `CARGO_FEATURES` build ARG
(override with `--build-arg CARGO_FEATURES=` to fall back to the platform
allocator for a musl/platform edge case). No `MALLOC_CONF` default is baked
into the image or recommended — see the "Memory allocator (jemalloc, H4)"
section of [`docs/deployment/README.md`](../docs/deployment/README.md) for
the operator-facing guidance, and
[`benchmarks/PUBLIC_BENCH_ANALYSIS.md`](../benchmarks/PUBLIC_BENCH_ANALYSIS.md)
§5 for the public-doc caveat update.
