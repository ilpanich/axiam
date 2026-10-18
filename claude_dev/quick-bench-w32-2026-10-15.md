# AXIAM 1.1.0 — W3.8(e) quick-bench: cost of 7be5e8094

**Question.** What does commit `7be5e8094` ("a tombstoned tenant's clients no longer
authenticate", R1W1-03: one extra indexed tenant read per client-authenticated token
call) cost on `just bench-quick` Cell 1 (p3-mtls, 20 VUs, 45 s window per sub-arm,
`oauth2_client_credentials.js`)?

**Answer: no cost visible at this sample size. The result is within noise, and the
measured deltas point the "wrong" way.** Arm B (the commit itself) was not slower than
arm A (its parent) on any throughput or p50 figure. This run's own noise floor is
about 7–15%: arm A's two sub-arms ran against the same binary and differ by 7.2% in
req/s and 12.4% at p50. The B-vs-A deltas are the same size or smaller, so they are
not attributable to the commit in either direction.

> **This is a single, unrepeated 45 s window per sub-arm. The numbers are
> indicative, not a matrix result.** No repeats were run, and nothing has error bars.

---

## 0. Machine

| | |
|---|---|
| OS | Arch Linux, kernel `7.2.9-arch1-1` x86_64 |
| CPU | Intel Core i7-8750H @ 2.20 GHz: 6 cores / 12 threads, 1 socket. Governor **`powersave`** (not `performance`) |
| RAM | 30 GiB (swap 4 GiB, unused) |
| Docker | client/server 29.9.0, overlay2, Compose 5.6.0 |
| k6 | v2.3.0 (commit e088784614, go1.26.8) |
| just | 1.58.0 |
| jq | 1.8.2 |
| Date / time (UTC) | 2026-10-15. Session start 18:52:19Z; arm A measured 19:15:43–19:17:43Z; arm B 19:36:09–19:38:09Z; arm C 19:58:48–20:00:49Z |

**Other load.** This is a laptop running a desktop session: GNOME, Firefox, two
Electron apps, the Claude Code CLI and `sage-gui` were open the whole time. They were
light (Firefox peaked at about 28% of one core). Two non-bench Docker stacks were
running at the start: `domo-*`, 7 containers, whose `domo-axiam-server-1` was
crash-looping (`Restarting (101)`), and the AXIAM dev dependencies (`axiam-surrealdb`,
`axiam-rabbitmq`). With the maintainer's approval all 9 were stopped with `docker stop`
(no `down`, volumes untouched) before the first build, then restarted with
`docker start` after the last arm.

The machine had booted about 10 minutes before the session started. Load average and
iowait fell steadily through the session. The 1-minute load average at the start of
each measured run was: A 2.28, B 1.70, C 1.28. **Later arms therefore ran on a slightly
quieter host.** If that biases anything, it biases toward B and C. It is one more
reason not to read B's small advantage as a speed-up.

## 1. Commands and exit codes

Every exit code below was taken from the tool itself (`cmd > log 2>&1; echo $?`), not
from a pipeline. Logs are in `~/axiam-bench-log/`. For every arm, `BENCH_TLS_PORT=18443`
was exported (see §3, item 1).

| # | Command (cwd) | Exit |
|---|---|---:|
| 1 | `git fetch origin` (repo) | 0 |
| 2 | `docker stop <9 containers>` (list in `stopped-containers.txt`) | 0 |
| 3 | `git worktree add ~/axiam-bench-A 7f5330cf4` | 0 |
| 4 | `just build=1 profile=p3-mtls bench-up` (`~/axiam-bench-A/benchmarks`), 18:52:41Z→19:14:43Z | 0 |
| 5 | `just profile=p3-mtls bench-seed` (A) | 0 |
| 6 | `BENCH_RESULTS_DIR=$PWD/results/w32-A just profile=p3-mtls bench-quick` (A), attempt 1 | **1** (see §3, item 3) |
| 7 | `BENCH_CERTS_DIR=$PWD/profiles/certs BENCH_RESULTS_DIR=$PWD/results/w32-A just profile=p3-mtls bench-quick` (A), attempt 2 | 0 |
| 8 | `just profile=p3-mtls bench-down` (A) | 0 |
| 9 | `git worktree add ~/axiam-bench-B 7be5e8094` | 0 |
| 10 | `just build=1 profile=p3-mtls bench-up` (B), 19:18:11Z→~19:36Z | 0 |
| 11 | `BENCH_CERTS_DIR=… just profile=p3-mtls bench-seed` (B) | 0 |
| 12 | `BENCH_CERTS_DIR=… BENCH_RESULTS_DIR=$PWD/results/w32-B just profile=p3-mtls bench-quick` (B) | 0 |
| 13 | `just profile=p3-mtls bench-down` (B) | 0 |
| 14 | `git fetch origin` (repo, before arm C) | **128** (see §3, item 6) |
| 15 | `git ls-remote https://github.com/ilpanich/axiam refs/heads/claude/release-1.1.0-w3` → `b40b33a67…` | 0 |
| 16 | `git worktree add ~/axiam-bench-C b40b33a67` | 0 |
| 17 | `just build=1 profile=p3-mtls bench-up` (C), 19:40:05Z→~19:58Z | 0 |
| 18 | `BENCH_CERTS_DIR=… just profile=p3-mtls bench-seed` (C) | 0 |
| 19 | `BENCH_CERTS_DIR=… BENCH_RESULTS_DIR=$PWD/results/w32-C just profile=p3-mtls bench-quick` (C) | 0 |
| 20 | `just profile=p3-mtls bench-down` (C) | 0 |
| 21 | `docker start <the same 9 containers>` | 0 |
| 22 | `git worktree remove ~/axiam-bench-A` / `-B` / `-C` | 0 / 0 / 0 |
| 23 | `docker builder prune -f` (disk hygiene, reclaimed 8.0 GB) | 0 |

Nothing was committed, pushed, tagged or merged, and no tracked file was edited.

## 2. Results

### Provenance

`bench-quick` writes no `meta.json` (see §3, item 4). The values below were captured
from the running `bench-axiam-server` container the same way `run-benchmark.sh` fills
`meta.json`: `build_ref` is `git rev-parse HEAD` of the worktree, and `image_digest` is
`RepoDigests[0]`, falling back to the image ID. All three images are **local source
builds** (`build=1`), so none has a registry digest. The digest column is therefore the
image ID.

| Arm | build_ref | image ref (as launched) | image digest (= image ID; RepoDigests empty) | built (local time) |
|---|---|---|---|---|
| A (parent) | `7f5330cf47acab961c8c5987e538ce572fe37a07` | `ghcr.io/ilpanich/axiam/server:1.0.0` | `sha256:7ede5a9d4751cb61839fef4200a723eb193ef32e66740c782eda03ee860d18f0` | 2026-10-15 21:14:24 +02:00 |
| B (7be5e8094) | `7be5e80947a297c18146447b7e04a76de6bb5dd2` | `ghcr.io/ilpanich/axiam/server:1.0.0` | `sha256:7e3079288689838c3d3a5d4ec9a3f0e1abc67dc8c3f9d5d8aa59890a837f9393` | 2026-10-15 21:35:29 +02:00 |
| C (W3 head, informative) | `b40b33a672ad7321906be462eb47bcad00d05e7d` | `ghcr.io/ilpanich/axiam/server:1.0.1` | `sha256:285fb9a51a8a72bc841fdf72657597fd28a8ec82853d5fa1cf88c288161fa0ff` | 2026-10-15 21:58:16 +02:00 |

**The published image was not measured.** The `server:1.0.0` / `server:1.0.1` refs
are only the tag `bench-up` derives from `Cargo.toml`. The image behind each ref is a
local build of the commit in `build_ref`. A and B carry the same ref but have different
image IDs.

### Cell 1, per arm

Throughput is `iterations.rate` from the k6 summary, the recipe's own req/s figure.
Latency is `bench_op_latency_ms`. Error rate is `bench_error_rate` (the validity
gate); `http_req_failed` and `checks` agree with it in every case.

| Arm | Sub-arm | req/s | p50 ms | p95 ms | p99 ms | error rate | iterations |
|---|---|---:|---:|---:|---:|---:|---:|
| A (7f5330cf4) | unbound | 2149.2 | 4.50 | 47.13 | 51.72 | 0.00% (0 / 128 958) | 128 958 |
| A (7f5330cf4) | certificate-bound | 1993.8 | 5.06 | 44.46 | 50.59 | 0.00% (0 / 119 633) | 119 633 |
| B (7be5e8094) | unbound | 2188.8 | 4.28 | 49.29 | 53.02 | 0.00% (0 / 131 334) | 131 334 |
| B (7be5e8094) | certificate-bound | 2183.6 | 4.32 | 48.97 | 52.80 | 0.00% (0 / 131 022) | 131 022 |

### B against A (Δ% = (B − A) / A)

For req/s, positive means B is faster. For latency, positive means B is slower.

| Sub-arm | req/s | p50 | p95 | p99 | error rate |
|---|---:|---:|---:|---:|---:|
| unbound | **+1.84%** | **−4.91%** | +4.56% | +2.52% | 0 → 0 (Δ undefined; no errors in either arm) |
| certificate-bound | **+9.52%** | **−14.71%** | +10.14% | +4.37% | 0 → 0 (Δ undefined; no errors in either arm) |

**How to read this.**

- **Where the cost should show, B is not worse.** A per-call indexed read adds a
  small, constant amount to every request. That would lower req/s and raise p50. In
  both sub-arms B is the opposite: higher req/s and lower p50.
- **B's p95/p99 are higher by 2.5–10%, but that is inside the noise.** The p95/p99 band is a separate
  ~45–53 ms mode: p50 is about 4.5 ms and p95 about 47 ms, with nothing in between.
  That is a periodic stall, not a per-request cost. A sub-millisecond read cannot
  produce a 40 ms mode.
- **The noise floor, measured inside this run:** in arm A, the two sub-arms used the
  same binary, the same stack and back-to-back windows. They differ by −7.2% req/s,
  +12.4% p50 and −5.7% p95. Arm A's bound sub-arm looks like the outlier in the whole
  run. In B and C the two sub-arms agree within 2%. That outlier is why the bound
  row's B-vs-A deltas (+9.5% / −14.7%) are larger than the unbound row's.
- **Conclusion: within noise.** This run cannot tell A and B apart. It does rule out
  a regression large enough to beat roughly 10% single-window variance, and it shows
  that the tombstone check does not break the client-credentials path. B ran 262 356
  token calls with 0 errors.

### The recipe's own closing caveat, verbatim

The caveat text in `results/w32-A/quick/SUMMARY.md` and `results/w32-B/quick/SUMMARY.md`
is byte-identical (checked with `diff`). Here it is verbatim:

```
## What this run establishes

- The **direction and rough size** of the binding overhead on this machine,
  for this scenario, under this profile.
- That the bound arm works at all end to end — a smoke check the unit tests
  cannot give you, because they never open a TLS connection.

## What this run does NOT establish

- **Anything with error bars.** One window per arm, no repeats. A delta
  inside single-digit percent is not distinguishable from run-to-run noise
  at this sample size; `bench-matrix`'s median-of-3 exists for exactly this
  reason (methodology §8).
- **A comparison against any other product.** No competitor ran.
- **Behaviour under any other profile, scenario, or fixture size.** One cell
  of a matrix is not the matrix.
- **A publishable headline number.** If a claim in the plan or the README
  rests on this figure, the claim must say it rests on an indicative
  single-window measurement, or `bench-matrix` must be run.

Artifacts: `results/quick/binding-*.k6.json`, `results/quick/binding-*.log`.
These are NOT collected by `bench-report` or `bench-pack` — they are not
matrix cells and must not be aggregated as though they were.
```

Cell 2 (reactor hook) printed its "Not run — but no longer for the original reason"
text in every arm, as designed. No hook number was produced.

### Arm C: 1.1.0 W3 head, informative

**Not part of the W3.2 comparison.** This is `origin/claude/release-1.1.0-w3` at
`b40b33a67`, the head both at the first fetch and at the later `ls-remote`. It was
measured on the same machine, right after B.

| Sub-arm | req/s | p50 ms | p95 ms | p99 ms | error rate | iterations |
|---|---:|---:|---:|---:|---:|---:|
| unbound | 2210.8 | 4.29 | 48.28 | 52.50 | 0.00% (0 / 132 653) | 132 653 |
| certificate-bound | 2168.9 | 4.37 | 48.22 | 52.66 | 0.00% (0 / 130 137) | 130 137 |

C is indistinguishable from B: every figure is within about 1%. This is also a rough
read on repeatability. When the only change between two arms (B→C) is a different
build, consecutive windows land within about 1%. Arm A's bound sub-arm, at −7%, is the
anomaly, and the earlier, noisier host state is the most likely cause (§0).

## 3. What did not go as written, and what I did instead

1. **`BENCH_TLS_PORT=18443` for every arm.** On this machine `sage-gui` holds
   `127.0.0.1:8443`, which is `bench-up`'s default TLS port. I exported
   `BENCH_TLS_PORT=18443` for every recipe call. This is a host-port mapping only and
   has no effect on the container or the server configuration. `bench-up`'s own
   pre-flight message suggests the same override.
2. **Stopped other stacks.** Nine non-bench containers were stopped for the whole run
   and restarted afterwards, with the maintainer's approval (§0).
   `domo-axiam-server-1` went back into the crash loop it was already in before the
   bench. That loop is not a bench artefact.
3. **`bench-quick` fails at k6 init on p3-mtls when run as the brief wrote it (a
   recipe bug).** Attempt 1 (command 6) failed before any request was sent:
   `GoError: stat …/benchmarks/scenarios/profiles/certs/client.crt: no such file or directory`
   (log kept as `A-attempt1-binding-unbound.log`). The cause:
   `profiles/p3-mtls.env` sets
   `BENCH_CLIENT_CERT=${BENCH_CERTS_DIR:-profiles/certs}/client.crt`, a *relative*
   path, and k6's `open()` resolves it against the script directory (`scenarios/`).
   Every other recipe does what `run-benchmark.sh:118` does and exports
   `BENCH_CERTS_DIR` as an absolute path first (`justfile:904/959/969`). `bench-quick`
   does not. **Workaround:** I exported `BENCH_CERTS_DIR=$PWD/profiles/certs` before
   calling `bench-quick`. That is the same value those recipes set. It is a k6-side
   path, not a container knob, and no tracked file was edited. All three measured runs
   (A attempt 2, B, C) used it identically. **Suggested fix for 1.1.0:** add
   `export BENCH_CERTS_DIR="${BENCH_CERTS_DIR:-$PWD/profiles/certs}"` near the top of
   the `bench-quick` recipe.
   - Side effect: attempt 1 had already registered its `quick-unbound` / `quick-bound`
     client pair before k6 failed. Arm A's measured run therefore ran with 4 OAuth2
     clients in the tenant (2 unused) where B and C had 2. A token call looks up only
     its own client, so I expect no effect. I'm noting it so nothing is hidden.
   - In arm A, `bench-seed` ran without `BENCH_CERTS_DIR`. In B and C it ran with it.
     `seed.sh` runs `curl` from `benchmarks/`, so the relative path resolves either way
     (A's seed and smoke checks passed).
4. **No `meta.json` exists for a quick run.** `bench-quick` does not go through
   `run-benchmark.sh`, which is the only thing that writes `meta.json`. I recorded image
   ref, digest/ID and `build_ref` with the same `docker inspect` / `git rev-parse` logic
   `run-benchmark.sh` uses, at the moment each stack was up (§2 Provenance).
5. **Local builds wear release tags.** `bench-up` tags its local build
   `ghcr.io/ilpanich/axiam/server:<Cargo.toml version>`. On this machine the local tag
   `server:1.0.0` therefore now points at the **B build of 7be5e8094**, not the
   published 1.0.0, and `server:1.0.1` points at the C build. To keep each arm's image
   addressable I added the tags `axiam-ab:A-7f5330cf4`, `axiam-ab:B-7be5e8094` and
   `axiam-ab:C-b40b33a67`. A later `build=0` run on this machine that fails to pull
   would silently reuse these local images. Remove the tags or re-pull before relying
   on them.
6. **The pre-C `git fetch origin` exited 128.** The error was `Permission denied
   (publickey)`: the SSH agent had no key at that point. The first fetch (command 1)
   had succeeded and already had `origin/claude/release-1.1.0-w3` = `b40b33a67`. I
   re-verified the live head over anonymous HTTPS with `git ls-remote` (command 15),
   which also returned `b40b33a67`, and built that commit.
7. **`bench-pack` was not used.** The recipe states that quick artifacts are not
   collected by `bench-pack`, so I attached the JSON summaries directly (§4).
8. **Seed.** The runbook says `bench-quick` "needs a live p3 stack + seed", and the
   recipe exits without a seed. I followed the brief's sequence of `bench-up`, then
   `bench-seed`, then `bench-quick`. `bench-quick` does not bring up its own stack.

## 4. Attached files

Next to this report, in `~/axiam-bench-report/`:

- `results/w32-A/quick/`, `results/w32-B/quick/`, `results/w32-C/quick/`: for each arm,
  `binding-{unbound,bound}.k6.json` (k6 `--summary-export`),
  `binding-{unbound,bound}.log` (k6 stdout) and `SUMMARY.md` (the recipe's report).
  There is no `.seed/`, no `docker/.secrets`, and no client secrets; a grep for
  `secret`/`password` found nothing.
- `results/cell1-extract.json`: the A and B figures and the B-vs-A deltas, produced
  from the k6 JSON by a small script.

The three worktrees have been removed. Raw recipe logs stay in `~/axiam-bench-log/`
on this machine; they are not attached.
