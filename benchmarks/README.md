# AXIAM Benchmark Framework

A vendor-neutral, protocol-driven benchmark harness for comparing **AXIAM** against
other open-source IAM systems (Keycloak, Zitadel, Authentik, Ory, …) across three
dimensions:

1. **Performance** — throughput (req/s) and latency (p50/p95/p99) under load.
2. **Resource efficiency** — CPU and memory consumed to deliver that performance,
   so we can answer *"can AXIAM match the competition with a smaller footprint?"*
3. **Security posture** — the same workload is replayed across a matrix of
   **security profiles** (from plaintext HTTP up to mTLS with client-certificate
   authentication and TLS 1.3-only), measuring the cost of stronger security.

It also includes **per-SDK client-side benchmarks**, so the client overhead of each
official AXIAM SDK can be measured against the raw protocol baseline. There are
**eleven** — Rust, TypeScript, Python, Java, Kotlin, C#, PHP, Go, Swift, C and C++,
each published from its own `ilpanich/axiam-<lang>-sdk` repository — and **all eleven
bench harnesses are wired to their SDKs** (see `sdk/README.md`). Seven of them
(Rust, TypeScript, Python, Java, C#, PHP, Go) implement the full CONTRACT §1–§11
surface including gRPC and AMQP; Kotlin, Swift, C and C++ cover the REST surface,
which is the whole of what the four contractual bench ops need.

Each bench builds against the sibling SDK checkout via a local
path/replace/project reference until the package lands on the public registry,
and **reports the version of that checkout** rather than a literal frozen into
the harness (`sdk/_sdkversion.sh`) — so a record always names the SDK release it
actually measured.

## Why a custom framework?

There is **no vendor-neutral standard benchmark** for IAM systems. The de-facto
reference is [`keycloak-benchmark`](https://github.com/keycloak/keycloak-benchmark)
(Gatling-based), but it is Keycloak-specific in its provisioning, dataset add-on,
and endpoint assumptions.

AXIAM and every serious competitor speak the **same wire standards** — OAuth2
(RFC 6749), OIDC, token introspection (RFC 7662), JWKS (RFC 7517). So instead of
re-implementing a vendor-coupled tool, this framework drives those *standard flows*
through a thin per-target **adapter layer** (`scenarios/lib/targets.js`). Every
target is hit with the identical logical workload; only the endpoint paths and
request encodings differ. That keeps the comparison apples-to-apples.

The load generator is [**k6**](https://k6.io): a single static binary, scriptable
in JavaScript, with native HTTP + gRPC support, built-in latency/throughput
metrics, threshold gating, and machine-readable JSON output. It is deliberately
lighter than a JVM-based generator (Gatling) so the load tool does not starve the
system-under-test of the CPU we are trying to measure.

## Directory layout

```
benchmarks/
├── README.md                 # this file
├── justfile                  # convenience commands (bench-up, bench-run, bench-report…)
├── run-improvement-tasks.sh  # per-task data collection for the pre-MVP plan (see below)
├── run-memory-experiment.sh  # B1/D9 allocator A/B (default malloc vs jemalloc)
├── docs/
│   ├── methodology.md        # how a fair run is defined; metric definitions
│   ├── security-profiles.md  # the TLS/cert profile matrix
│   └── interpreting-results.md
├── targets/                  # each system-under-test as a resource-capped compose file
│   ├── axiam/docker-compose.yml
│   ├── axiam/docker-compose.minimal.yml   # overlay: AXIAM without the broker (`deploy=minimal`)
│   ├── authentik/docker-compose.yml   # server + worker + PostgreSQL, no Redis (see "The authentik target")
│   ├── keycloak/docker-compose.yml
│   └── zitadel/docker-compose.yml
├── profiles/                 # security profiles (env files + registry)
│   ├── profiles.yaml
│   ├── p0-plaintext.env
│   ├── p1-tls12.env
│   ├── p2-tls13.env
│   └── p3-mtls.env
├── scenarios/                # k6 load scenarios (vendor-neutral)
│   ├── lib/{config,targets,metrics,auth}.js
│   ├── oauth2_password_login.js
│   ├── opaque_login_start.js
│   ├── opaque_register_start.js
│   ├── oauth2_client_credentials.js
│   ├── token_introspection.js
│   ├── token_refresh.js
│   ├── jwks_fetch.js
│   ├── userinfo.js
│   ├── authz_check_rest.js     # AXIAM-only; SDK check_access wire baseline
│   ├── authz_batch_rest.js     # AXIAM-only; SDK batch_check wire baseline
│   ├── authz_check_grpc.js
│   └── authz_batch_grpc.js
├── resource/                 # resource-consumption sampling
│   ├── sampler.sh            # docker stats → CSV
│   └── cadvisor-compose.yml  # optional richer telemetry
├── runner/
│   ├── run-benchmark.sh      # orchestrator: target × profile × scenario matrix
│   ├── seed.sh               # provision org/tenant/user/client per target
│   ├── bench-creds.sh        # per-run credentials for every target (generated, never literals)
│   ├── pull-pinned-images.sh # pull every image of a run, record + pin its digest
│   ├── resting-sample.sh     # memory of a running stack at rest, no load
│   ├── *-selftest.sh         # hermetic guards, run in CI (credentials, rl=prod pinning, deploy profile, …)
│   └── report.py             # aggregate raw results → comparative report
├── sdk/                      # per-language SDK client-side benchmarks
│   ├── HARNESS-SPEC.md       # the JSON contract every SDK bench must emit
│   ├── _sdkversion.sh        # resolves each bench's SDK version from its checkout
│   ├── run-all.sh
│   └── {rust,typescript,python,go,java,kotlin,csharp,php,swift,c,cpp}/
└── results/                  # run outputs (gitignored)
```

## Quick start

```bash
# 0. Prerequisites: docker, docker compose, k6, python3, jq, openssl, bash.
cd benchmarks

# The AXIAM target needs a JWT keypair + DB/RabbitMQ creds. `bench-up` bootstraps
# throwaway local-only ones automatically: the keys under docker/.secrets/ (or reuse
# docker/.secrets/env if you provide real ones) and every password per stack under
# .seed/ (see "Credentials: generated per run" below) — none is a literal.
# A full release round (the four targets, the minimal profile, the SDK pass) follows
# claude_dev/run6-runbook.md. By default it pulls the prebuilt
# server image ghcr.io/ilpanich/axiam/server:<version>; GHCR packages are private
# by default, so run `docker login ghcr.io` first (PAT with read:packages), set
# BENCH_AXIAM_IMAGE to an image you can pull, or build from source with build=1.

# NOTE: `just` variable overrides (target=…, profile=…) must come BEFORE the
# recipe name — placed after, `just` reads them as another recipe and errors
# with "justfile does not contain recipe `target=…`".

# 1. Bring up a target under a chosen security profile and seed it.
#    AXIAM uses the published ghcr image by default (no source build); pin a
#    different tag with BENCH_AXIAM_IMAGE, or force a local build with build=1.
just target=axiam profile=p2-tls13 bench-up            # prebuilt image
# just target=axiam profile=p2-tls13 build=1 bench-up  # local source build
just target=axiam bench-seed

# 2. Run the full scenario suite (load + resource sampling) for that target/profile.
just target=axiam profile=p2-tls13 bench-run

# 3. Repeat for a competitor.
just target=keycloak profile=p2-tls13 bench-up
just target=keycloak bench-seed
just target=keycloak profile=p2-tls13 bench-run

#    ...or for authentik (2026.8.3; its per-run credentials are generated by
#    bench-up — see "The authentik target" below). Its first start takes minutes.
just target=authentik profile=p0-plaintext bench-up
just target=authentik bench-seed
just target=authentik profile=p0-plaintext bench-run

# 4. Generate a comparative report across everything in results/.
just bench-report

# 5. Tear down.
just target=axiam bench-down
just target=keycloak bench-down

# Compose logs of a running target (no secrets needed in the environment).
just target=axiam bench-logs 200 axiam-server
```

Or run the entire matrix (all targets × all profiles × all scenarios) unattended.
By default this repeats the whole matrix 3× (`repeat := "3"`) into
`results/run-1/`, `results/run-2/`, `results/run-3/`, and `report.py` medians
each cell across the valid runs (see
[methodology §8](docs/methodology.md#8-multiple-runs--median-of-n-c1)); pass
`repeat=1` for a single quick pass instead:

```bash
just targets="axiam keycloak" profiles="p0-plaintext p2-tls13 p3-mtls" bench-matrix
# just repeat=1 targets="axiam keycloak" profiles="p0-plaintext p2-tls13 p3-mtls" bench-matrix
```

### One question in minutes (`bench-quick`)

`bench-matrix` is hours. `bench-quick` is one A/B, and the two are not
interchangeable — use it when you need the **direction and rough size** of a
single effect, not a publishable cell:

```bash
just target=axiam profile=p3-mtls bench-up
just target=axiam bench-seed
just bench-quick
```

| Use | When |
|---|---|
| `bench-matrix` | a number that goes in a comparison table, a README, a plan's claim, or the public archive. Median-of-3, full cross-product, competitors included. |
| `bench-dry-run` | rehearsing the matrix — does every cell's client actually connect and get the answer it expects? Never a measurement. |
| `bench-quick` | "did this change cost anything, roughly?" One target, one profile, one short window per arm, no repeats. |
| `bench-nested` | "what does depth cost?" A labelled depth ladder for nested-resource authorization across all three targets — see [Nested-resource authorization](#nested-resource-authorization-depth-bench-nested) below. |

It measures the per-request cost of RFC 8705 certificate-bound access tokens
(X5.1) as an A/B between two AXIAM clients that differ in exactly one registered
field, on the same server over the same mTLS connections — so the delta is
attributable to the binding rather than to mTLS. `quickdur=` (default `45s`) and
`quickvus=` (default `20`) are the only knobs; everything else is fixed so that
two people running it run the same thing.

Its second cell — the X1 reactor hook cost — is **conditional and currently does
not run**: X1's dispatcher exists in `crates/axiam-amqp` but nothing invokes it
from a request path, so there is no hook on the token path to measure. The
recipe says so in its output rather than reporting the cost of code that never
executes.

**`bench-quick` output is not a matrix result and must not be presented as one.**
The recipe prints what it establishes and what it does not — one unrepeated
window per arm cannot separate a single-digit delta from run-to-run noise — and
writes the same text to `results/quick/SUMMARY.md`. Its artifacts are
deliberately excluded from `bench-report` and `bench-pack`. If a claim anywhere
rests on a `bench-quick` figure, the claim has to say so, or the matrix has to
be run.

### Rehearse the matrix first (`bench-dry-run`)

A full matrix is hours long, and a break in the k6 client contract — a seeded
client the target rejects, a p3-mtls cert k6 cannot load, a gRPC dial into a
TLS listener, an OAuth2 cell that gets silently skipped — does not announce
itself until that cell's turn comes round. `bench-dry-run` walks the **same**
target × profile grid with the **same** bring-up → seed → run → tear-down path
and the **same** scenarios, but collapses each measured window to a few
seconds and grades every cell on whether the k6 client could connect, send its
request and get back the answer the scenario expects:

```bash
just targets="axiam keycloak zitadel" profiles="p0-plaintext p2-tls13 p3-mtls" bench-dry-run
```

It does **not** stop at the first broken cell — a failing bring-up, seed or
scenario is recorded and the sweep carries on, so one pass gives you the whole
fix list. Verdicts are `PASS` / `WARN` (ran, but the cell would not measure
what it claims — e.g. a fallback op, or a sampler writing no rows) / `SKIP`
(filtered out, with the reason) / `FAIL`. The exit status is non-zero if
anything failed, and a table lands in `results/dry-run/SUMMARY.md` alongside
per-cell `*.dryrun.log` files holding k6's own check breakdown.

Because it deliberately skips the post-seed settle gate, a dry run measures
inside the transient window — so it relaxes the p95 latency gate to 30s while
keeping correctness strict (a single failed check fails the cell). **A dry run
is never a measurement.** Its artifacts carry `"dry_run": true`, live under
`results/dry-run/`, and are excluded from both `bench-report` and `bench-pack`.

`dry=1` applies the same treatment to a single cell:

```bash
just target=axiam profile=p3-mtls dry=1 bench-run
```

See [`docs/methodology.md`](docs/methodology.md) for the rules that make a run
comparable, and [`docs/security-profiles.md`](docs/security-profiles.md) for the
profile definitions.

Running the matrix on a laptop rather than dedicated hardware? See
[**"Running on a laptop"**](docs/methodology.md#10-running-on-a-laptop-c3) in
the methodology doc for the variance-control runbook (AC power, CPU governor,
turbo-boost mode, cooldown pauses between cells) before trusting absolute
numbers.

For a repeatable, noise-resistant run, use `repeat=N` (default 3) so
`bench-matrix` runs the whole matrix N times and `report.py` medians each
cell — see [§8 "Multiple runs — median-of-N"](docs/methodology.md#8-multiple-runs--median-of-n-c1):

```bash
just repeat=3 targets="axiam keycloak" profiles="p0-plaintext p2-tls13" bench-matrix
```

### Sharing a run (`bench-pack`) — what the archive contains

`just bench-pack` writes `results-<date>.tar.xz`. Its manifest is produced by
[`runner/pack-filelist.sh`](runner/pack-filelist.sh) — one script, so the
archive and its regression test can never disagree:

| Included (by extension, anywhere under `results/`) | Why |
|---|---|
| `*.json` | k6 summaries (`*.k6.json`) and per-cell run metadata (`*.meta.json`) |
| `*.csv` / `*.tsv` | container resource samples (`*.res.csv`) and host telemetry (`*.host.csv`) |
| `*.md` | the generated `report.md`, plus every investigation verdict — `rl-prod-summary.md`, `sdk-report.md`, targeted-run write-ups |
| `*.log` / `*.txt` | investigation captures — `nsenter.log` socket snapshots, `h5-revocation.log`, docker-log excerpts |

Excluded by construction (pruned, not filtered afterwards):

- `results/dry-run/**` — a dry run writes real-*looking* artifacts for
  five-second unsettled windows. They are diagnostics, never measurements.
- anything matching `*seed*` — client secrets and the bench user's password.
  These normally live in `.seed/` (outside `results/` entirely); the prune also
  covers the legacy `results/<target>.seed.env` path `run-benchmark.sh` still
  honours.

The include list is by extension on purpose. Run 5 shipped an archive that
dropped every investigation artifact because the list named five exact
filenames and could not anticipate the sixth (J13). Matching extensions means
the *next* investigation's artifact is packed by default rather than found
missing after the fact.

```bash
just bench-pack-selftest   # hermetic; no docker, no k6. Asserts both directions.
```

The self-test builds a fixture tree carrying one of every run-5 artifact shape,
runs the real selection script over it, and fails if an investigation artifact
is missing *or* if a dry-run/seed path survives. After packing, `bench-pack`
additionally re-scans the finished archive for `SECRET`/`PASSWORD` content
(ignoring the `"<redacted>"` key names `axiam_env` legitimately records).

### Credentials: generated per run, never literals

No benchmark credential is a literal anywhere in this repository (the CodeQL
hard-coded-credentials rule; `just bench-credential-selftest`, run in CI, fails on
the next one). For every target `bench-up` generates the credentials the stack needs
with `openssl rand` into a **mode-600** file under the gitignored `.seed/`
(`<target>.stack.env`, by `runner/bench-creds.sh`) and exports them for compose,
where each is a **required** variable (`${VAR:?…}`) — a raw `docker compose up`
fails closed instead of starting with a password from the repository.

| Target | Generated by `bench-up` | Written into the seed env by `bench-seed` |
|---|---|---|
| axiam | `AXIAM__DB__PASSWORD`, `RABBITMQ_DEFAULT_PASS`, the bootstrap admin's `BENCH_ADMIN_PASSWORD`, the bench user's `BENCH_PASSWORD` (plus the keys under `docker/.secrets/`, as before) | `BENCH_PASSWORD`, `BENCH_ADMIN_PASSWORD`, `BENCH_CLIENT_SECRET` |
| keycloak | `KC_ADMIN_PASSWORD`, `BENCH_KC_DB_PASSWORD`, `BENCH_PASSWORD` | `BENCH_PASSWORD`, `KC_ADMIN_PASSWORD`, `BENCH_CLIENT_SECRET` |
| zitadel | `BENCH_ZITADEL_MASTERKEY` (exactly 32 characters), `BENCH_ZITADEL_DB_USER_PASSWORD`, `BENCH_ZITADEL_DB_ADMIN_PASSWORD`, `BENCH_PASSWORD` | `BENCH_PASSWORD`, `BENCH_CLIENT_SECRET`, the introspection client's secret |
| authentik | its secret key, PostgreSQL password, bootstrap admin password and token (see "The authentik target") | `BENCH_PASSWORD` (generated by the seed), `BENCH_CLIENT_SECRET` |

* **A value you export wins.** The FAPI conformance workflow exports
  `BENCH_ADMIN_PASSWORD` before `bench-up`; that still works, and the stack file
  records your value.
* **`bench-down` removes the stack file** with the volumes it belongs to (the seed
  env is left: the scenarios and the SDK benches read it).
* **Running a k6 scenario by hand** needs the seed env in the environment — the
  scenarios no longer fall back to a default (a missing password reads as a
  visible failure, and `lib/config.js` says why once):

  ```bash
  cd benchmarks
  set -a; . profiles/p0-plaintext.env; . .seed/keycloak.seed.env; set +a
  k6 run scenarios/oauth2_client_credentials.js
  ```
* Nothing prints a credential: the recipes, `seed.sh` and the self-tests never echo
  one, and under GitHub Actions every generated value is registered with
  `::add-mask::` as it is loaded.

### AXIAM's minimal profile (`deploy=minimal`)

`just deploy=minimal target=axiam profile=p0-plaintext bench-up` layers
[`targets/axiam/docker-compose.minimal.yml`](targets/axiam/docker-compose.minimal.yml)
over the AXIAM target: `AXIAM__AMQP__ENABLED=false`, SurrealDB and the server, no
RabbitMQ, no broker URL, no AMQP signing key — the harness's form of
`docker/docker-compose.minimal.yml` (T23.8.3), under the same caps as every other
AXIAM cell. It needs Docker Compose >= 2.24 (`!reset` / `!override`).

* **Single instance, always.** The profile holds a singleton lease in SurrealDB, and
  the fixed container name makes Compose refuse `--scale`.
* **State it wherever a number is quoted:** the minimal profile's outbound deliveries
  (webhooks, SSF push, outbound SCIM, CIBA ping) and its mail run on in-process queues
  and are **lost on restart** (T-445), so its footprint is the footprint of a profile
  that gives up that durability — never the full profile's.
* **Outbound SCIM targets stay disabled** (none is registered): a target on a dead
  host reproduces P23W5-07 (#550), it does not measure the server.
* **Its cells go in their own results tree** (`BENCH_RESULTS_DIR=…/results/minimal-profile`),
  never medianed with full-profile cells. `meta.json` records `axiam_deploy_profile`,
  `report.py` banner-labels a minimal cell, and `bench-matrix`/`bench-dry-run` forward
  `deploy=` and set `BENCH_EXPECT_DEPLOY`, so a stack that is not the profile the pass
  says fails the cell in seconds (`just bench-deploy-profile-selftest`).
* `BENCH_SCENARIO_ONLY="a.js b.js"` (the inverse of `BENCH_SCENARIO_EXCLUDE`) runs a
  chosen set of cells behind one settle gate; an unknown name is a hard error.

### Memory at rest (`runner/resting-sample.sh`)

The per-cell sampler only runs under load. `runner/resting-sample.sh <target> <stage>`
samples a **running** stack with no load — every container the target has — and writes
`results/resting/<target>[-minimal]/<stage>-{samples.csv,summary.txt,meta.json}`:

```bash
just target=keycloak profile=p0-plaintext bench-up
bash runner/resting-sample.sh keycloak fresh      # freshly migrated, empty datastore
just target=keycloak bench-seed
bash runner/resting-sample.sh keycloak fixture    # the benchmark fixture in place, no load
```

Per container it records `rss_kib` (sum of `VmRSS` of every process in it, from the
host's `/proc`; Linux hosts only), `rss_anon_kib` and `cgroup_working_set_kib` (what
`docker stats` reports), takes the **median** over `DURATION` seconds after a `SETTLE`
period (defaults 90 / 60 s, every 5 s), and records each container's image digest, cap and
start time. Name the stage `fresh` / `fixture`, **not** `seeded`: `bench-pack` prunes every
file name containing `seed`, and the script refuses such a label. These are figures
**at rest, not under load**, in the harness's own caps and with the released image; they
are not comparable with `resting-footprint/` (a native binary beside containers).

**Keycloak 26.8's "reduced memory usage".** What the 26.8.0 release notes (and their
upgrade guide, read at tag `26.8.0` of the keycloak repository) verifiably say: the
highlight reads "Simpler administration with automatic index creation, reduced memory
usage, and enhanced HTTP performance", with no figure and no new memory flag. The two
mechanisms they name are (1) **login failures are stored in the database by default**
(`login-failures:v2`; "reduces memory consumption from accumulated login failure
entries", at the price of more database connections and database CPU), and (2) caching of
persistent user sessions **can be disabled** (`--spi-user-sessions--infinispan--use-caches=false`)
— **opt-in, not a default**, so it is not part of run 6. Quarkus moved from 3.33 to 3.40,
and the JVM heap is still sized as a percentage of the container limit (so `BENCH_MEM`
moves it). The harness therefore measures the claim **as Keycloak ships it**: the
at-rest sample above and the under-load figures in every cell's `res.csv`, both at the
run-5 caps and with no Keycloak tuning. Mechanism (1) only has entries to save in a
workload that fails logins; the benchmark's logins succeed, so a reduction seen in run 6
must not be attributed to it without evidence (an inference, not a finding).

### Pinned images (`runner/pull-pinned-images.sh`)

`bash runner/pull-pinned-images.sh` pulls every image of a run (the AXIAM server,
SurrealDB, RabbitMQ, Keycloak, Zitadel, authentik and PostgreSQL), reading each
reference from the `${BENCH_*_IMAGE:-default}` line of the compose file that owns it
(anything you already exported wins), and writes `results/provenance/images.txt` and a
`pinned-images.sh` of `export BENCH_*_IMAGE=<repo>@sha256:…` lines to source. A failed pull is
a hard error: `bench-up` otherwise falls back to a local source build when the AXIAM image
cannot be pulled, and the run silently stops measuring the release.

## Status of components

| Component                         | State                                                        |
|-----------------------------------|--------------------------------------------------------------|
| k6 protocol scenarios             | Implemented (HTTP); authz check + batch scenarios over both REST and gRPC |
| AXIAM target + seeding            | Implemented (prebuilt ghcr image by default, local build fallback); seeds org/tenant/admin via the gated bootstrap flow plus a resource/role/grant for authz checks |
| Keycloak / Zitadel targets        | Implemented (Keycloak **26.8.0**, Zitadel **v4.19.4** — the pins in `targets/*/docker-compose.yml`, each overridable: `BENCH_KEYCLOAK_IMAGE`, `BENCH_ZITADEL_IMAGE`) |
| authentik target                  | Implemented (authentik 2026.8.3, server + worker + PostgreSQL, no Redis; p0 and p2 only — see [The authentik target](#the-authentik-target)) |
| Security profile matrix           | Implemented (p0–p3); mTLS requires per-target cert wiring; SDK benches cover p0–p2 (no SDK client-cert option yet) |
| Resource sampler + report         | Implemented (stdlib python, no external deps)                 |
| SDK client benchmarks             | All 11 wired to their SDKs, each reporting its checkout's own version (see `sdk/README.md`) |
| AMQP async-authz benchmarking     | Out of scope for v1.0-beta (see below)                        |

> Every SDK bench builds against its sibling `ilpanich/axiam-<lang>-sdk` checkout
> via a local path/replace/project reference until the package is published —
> see each language's `sdk/<lang>/TODO.md`. `sdk/HARNESS-SPEC.md` documents the
> shared result contract every bench emits. G10 is closed: seven benches have
> produced validated `status: "ok"` records against a live target, and
> `sdk/README.md`'s H8 table says which, at which profile, and what still blocks
> the rest.

## The authentik target

`targets/authentik/` is the fourth benchmark target (T23.10.1, G-10), in the
same shape as `keycloak/` and `zitadel/`: a resource-capped compose file, a seed
in `runner/seed.sh`, an adapter in `scenarios/lib/targets.js`, and the same k6
scenarios for the endpoints the products share. It exists so that the authentik
comparison can make a performance statement; nothing here has been published as
one yet.

### What runs

| | |
|---|---|
| Version | **authentik 2026.8.3**, `ghcr.io/goauthentik/server:2026.8.3`. The identical Docker Hub mirror is `authentik/server:2026.8.3`; point `BENCH_AUTHENTIK_IMAGE` at it where ghcr.io is unreachable (the same way `BENCH_PG_IMAGE` and `BENCH_AXIAM_IMAGE` work). |
| Stack | `server` + `worker` + PostgreSQL. **No Redis**: authentik dropped it in 2025.10 (cache, channels and the task queue moved into PostgreSQL), and this is exactly the shape authentik's own compose ships. |
| Database | `${BENCH_PG_IMAGE:-postgres:16-alpine}` with the same three tuning flags and the same 2 CPU / 1 GiB cap as Keycloak's and Zitadel's. |
| Ports | the plaintext listener (container `:9000`) on `BENCH_APP_PORT` (8090), the built-in HTTPS listener (`:9443`) on `BENCH_TLS_PORT` (8443) |

**Resource caps and the memory accounting.** The run-5 caps apply per
container, exactly as for the other targets: server **2 CPU / 2 048 MiB**
(`BENCH_CPUS` / `BENCH_MEM`), database **2 CPU / 1 024 MiB** (`BENCH_DB_CPUS` /
`BENCH_DB_MEM`) — and the **worker carries the same server cap**
(`BENCH_AUTHENTIK_WORKER_CPUS` / `BENCH_AUTHENTIK_WORKER_MEM`, defaulting to
`BENCH_CPUS` / `BENCH_MEM`). The stack's configured ceiling is therefore 6 CPU /
5 GiB against Keycloak's 4 CPU / 3 GiB; the worker is close to idle while a cell
runs, so the ceiling is not what the efficiency figures divide by — they divide
by *measured* cores and memory, like every other target.

* The sampler matches `bench-authentik`, so **all three containers are in the
  whole-stack figure** (cores and resident memory), and `meta.json` records each
  container's role (`server`, `worker`, `db`), image, digest and cap.
* `report.py`'s "server only" efficiency variant for authentik is **server +
  worker**, because authentik cannot be deployed without both (the worker
  applies the bootstrap blueprint and runs every background task). Leaving the
  worker out would make its server-only memory look ~300 MiB smaller than what a
  deployer has to run. The per-container appendix still shows them separately.
* The worker is idle for JWKS, introspection and userinfo cells (~0.0–0.1 cores)
  but **not** for client_credentials and password login, where it consumes the
  background tasks each request enqueues (~0.6–0.7 cores in the smoke runs) —
  which is why it belongs in the stack's footprint. Order of magnitude seen in
  the smoke runs on the small development host (not a measurement): server
  ≈ 0.7 GiB, worker ≈ 0.3 GiB, database 0.1–0.35 GiB resident, ≈ 1.3 GiB in all.
* `shm_size` is 512 MiB (authentik's own value; it keeps scratch state in
  `/dev/shm`, and tmpfs pages count against the container's memory limit).
* The image's `ak healthcheck` is not free (a process start and a deep request,
  ~0.2 s CPU) and runs inside the measured container, so its steady-state
  interval is left at the image's 30 s; only the start-up interval is shortened.
* authentik's stock `web.workers=2` / `threads=4` is left as shipped — no tuning
  in either direction, the same stance as Keycloak's and Zitadel's.

### Running it

```bash
just target=authentik profile=p0-plaintext bench-up     # first start: minutes (migrations under the CPU cap)
just target=authentik bench-seed                        # waits for the default blueprints, then seeds + smoke-checks
just target=authentik profile=p0-plaintext bench-run
just target=authentik bench-down                        # also removes the per-run credentials
```

or in the matrix: `just targets="axiam keycloak zitadel authentik" profiles="p0-plaintext p2-tls13" bench-matrix`.
`bench-matrix` and `bench-dry-run` skip an `authentik` × `p3-mtls` pair (the
dry run records it as `SKIP`) and `bench-up` refuses it — see Profiles below.

| Variable | Default | Effect |
|---|---|---|
| `BENCH_AUTHENTIK_IMAGE` | `ghcr.io/goauthentik/server:2026.8.3` | server and worker image |
| `BENCH_AUTHENTIK_WORKER_CPUS` / `_MEM` | `BENCH_CPUS` / `BENCH_MEM` | the worker's cap |
| `BENCH_AUTHENTIK_LISTEN_HTTP` / `_HTTPS` / `_METRICS` | `0.0.0.0:9000` / `:9443` / `:9300` | authentik binds `[::]` by default and **exits at start-up on a host whose kernel has no IPv6** ("Address family not supported by protocol" — the sandbox this target was written in is one). IPv4 wildcards work everywhere; set these to `[::]:<port>` to get the shipped binding back. |
| `BENCH_AUTHENTIK_SEED_TIMEOUT` | `900` | seconds `bench-seed` waits for the default blueprints |
| `BENCH_AUTHENTIK_USER_PASSWORD` | generated | pin the bench user's password instead of generating one |

**Credentials are generated per run and never written down in the repo** (the same
mechanism now serves every target — see "Credentials" above).
`bench-up` creates authentik's secret key, the PostgreSQL password, the
bootstrap admin password and the bootstrap API token with `openssl rand`, into a
mode-600 file under the gitignored `.seed/` (`authentik.stack.env`), and exports
them for compose, where each is a *required* variable
(`${BENCH_AUTHENTIK_PG_PASSWORD:?…}` and so on — a stack cannot start without
them and no default exists to leak). The file exists so that a second `bench-up`
against a running stack hands compose the same values (a new PostgreSQL password
against the old data volume would lock authentik out of its own database);
`bench-down` removes it together with the volumes. `bench-seed` generates the
bench user's password, the client secret comes from authentik itself, and the
admin token is read back out of the running container's environment (the way
`seed_zitadel` reads its PAT). Nothing prints a credential: failure paths print
status codes and short error summaries, and under GitHub Actions every generated
value is registered with the log scrubber (`::add-mask::`) first. Like the other
targets' seed files, `.seed/authentik.seed.env` (mode 600, gitignored) holds the
generated client secret and password for the k6 run; it lives outside `results/`,
the tree `bench-pack` archives.

### How it is seeded, and why through the API

`seed_authentik` drives authentik's REST API (`/api/v3`) with the bootstrap
token rather than applying a blueprint. A blueprint is the declarative option
and was considered: it is applied *asynchronously* by the worker, so the seed
would have to poll for it anyway; it can inject a secret only through an `!Env`
tag, i.e. one more variable in the container's environment; and it cannot hand
the generated client secret back to the script. The API returns each object's id
and the generated secret in its response and lets every fixture be created-or-
found and verified, which is the shape the Keycloak and Zitadel seeds work in.

It provisions an OAuth2/OpenID provider `bench-provider` (confidential client
`bench-client`; grant types `authorization_code`, `refresh_token`,
`client_credentials`, `password`; the `openid`/`profile`/`email` scopes; a
signing key so tokens are RS256 and the JWKS is not empty), an application
`bench-app` bound to it, the bench user (a generated password) and an
app-password token for that user (see "Password login" below). Re-seeding an
existing stack converges instead of duplicating. Two things it had to learn:

* authentik 2026.x **refuses every grant on a provider whose `grant_types` list
  is empty** (`invalid_grant`), so the list is set explicitly and verified;
* the first start applies the default blueprints (the flows and the OAuth2 scope
  mappings) in the worker **minutes after the server already answers**, so the
  readiness gate in `bench-up` passes long before the seed can run. The seed
  polls for the objects it needs instead of for a fixed time.

The smoke checks that gate `results/authentik.seed.ok` assert more than a
status, because two authentik answers are **HTTP 200 on failure**: an
introspection call it cannot authenticate (`{"active": false}`) and a flow-
executor password stage handed a wrong password (`response_errors` in the
challenge). They check that the token is `active`, that the JWKS carries a key,
that userinfo returns the bench user's own `preferred_username`, that a **wrong
password is rejected** by the flow executor and the right one completes it into
an authenticated session, and that the ROPC grant does *not* accept the real
password (see below; if a future release changes that, the check says so).

### How authentik serves the five shared endpoints — and the equivalence verdict

Determined against a running 2026.8.3 container (status codes and bodies in the
T23.10.1 smoke run; every non-obvious row was checked by hand with `curl`).

| Operation | authentik's endpoint | How it differs from the other targets | Verdict |
|---|---|---|---|
| **Client credentials** | `POST /application/o/token/` (a **global** endpoint, not per application) with `client_id` + `client_secret` in the form body, `grant_type=client_credentials`. Needs `client_credentials` in the provider's `grant_types`. | The token's subject is a generated service-account user. Same grant, same wire shape as Keycloak's. | **Equivalent** |
| **Introspection** (RFC 7662) | `POST /application/o/introspect/`, authenticated with the **provider's own client credentials** (form body or HTTP Basic). | Same as Keycloak (the token's own client introspects it). **A failed client authentication is not an HTTP error: it is `200 {"active": false}`**, so the request carries a `require` predicate on `active === true`; without it a mis-seeded client would be counted as 100 % successful. It reads the stored access token from PostgreSQL (≈ 70 transactions per request, measured with `pg_stat_database` deltas — cache and sessions live in the database too). | **Equivalent**, with the extra check |
| **JWKS** | `GET /application/o/<app-slug>/jwks/` — **per application**. | One RSA signing key (RS256). Unlike the other targets' JWKS, it is **not a cheap static read**: with the cache in PostgreSQL even this request costs roughly a dozen transactions. That is a product property, left as shipped. | **Equivalent** (same operation); read its cost as authentik's |
| **Userinfo** | `GET /application/o/userinfo/` with a bearer token. | The claims follow the scopes the token was minted with, so every authentik token the harness mints asks for `openid profile email`; without them it returns only `sub` and the cell would measure less than the others' identity read. The user token is a **real user-subject token** minted in `setup()` through the ROPC grant redeemed with the user's app-password token (a setup-only path, never measured). It reads the token and the user from PostgreSQL on every call (≈ 20 transactions). | **Equivalent** |
| **Password login** | **Not the token endpoint — the flow executor** (`/api/v3/flows/executor/default-authentication-flow/`): GET the identification challenge, POST the username, POST the password. About six server requests (the executor answers each POST with a 302), three client calls, measured as **one** operation. | See below. A session login like AXIAM's `/api/v1/auth/login` and Zitadel's session API, not a single-request op, and its hash is **PBKDF2-SHA256 at 1 000 000 iterations** (read off the stored hash), not Argon2id or bcrypt. | **Verifies the real password; not like-for-like on the wire.** The report labels the cell `protocol-variant` |

**Password login.** authentik does have `grant_type=password` (ROPC) on its
token endpoint — and benchmarking it would have been the wrong call. Its backend
is authentik's `TokenBackend`: the `password` field takes an **app-password
token**, and **the user's real password is rejected with `invalid_grant`**
(checked: real password → 400; the app-password token → 200 with a user token).
A token comparison involves no password hash, so a cell built on it would be a
cheap lookup under a "password login" label, which is exactly the misreading the
"all targets hash for real" claim in `PUBLIC_BENCH_ANALYSIS.md` exists to
exclude. What does verify the real password with the real hash is the flow
executor every browser login goes through, so that is what
`authentik.login()` drives. The negative control is part of the seed: a wrong
password comes back as HTTP 200 with `response_errors`, so each step carries a
`require` on the executor's `component` (`ak-stage-identification` →
`ak-stage-password` → `xak-flow-redirect`) and a bad credential is a failed
operation, not a green one. `doSteps()` in `scenarios/lib/metrics.js` runs the
three calls as one operation with a **fresh cookie jar per iteration** (a flow
session is the state being carried and must not leak into the next login) and
records the wall clock of the whole sequence. Side effects a deployer would also
pay, and which are therefore part of the measurement: a created session, a login
event, and the worker consuming the resulting background tasks (its CPU is in the
sampler's per-container rows).

Two consequences to carry into any published number. The latency of this cell
includes three client round trips that the other targets' single-request login
does not, and PBKDF2-1M is as dominant here as bcrypt is on Zitadel — expect the
`p95 < 2 s` validity gate to fail at 50 VUs for the same reason Zitadel's does,
and say so rather than tuning the hash.

**Refresh.** authentik issues refresh tokens only from the authorization-code
and device grants (its token view), **not from ROPC or client_credentials**, so
`token_refresh.js` has nothing to refresh on this target non-interactively and
measures its client_credentials fallback, tagged `fallback-op` and excluded from
the head-to-head — the same treatment Zitadel's cell gets. Reaching a real
refresh would take a scripted authorization-code exchange per VU; that is not
needed for the five shared endpoints and is not attempted.

### Scenarios, profiles, and what authentik is not part of

* **Scenarios.** `--scenario all` runs the five shared scenarios plus
  `token_refresh` (as above) — exactly Keycloak's set. Every AXIAM-only and
  Zitadel-only scenario is excluded by the runner's "every target except X"
  filters, and `runner/scenario-filter-selftest.sh` pins both the exclusions and
  the exact survivor set per competitor (`BENCH_LIST_SCENARIOS=1` prints it
  without k6 or a stack).
* **`bench-nested`** is three-target by design; authentik has no per-resource
  authorization-decision endpoint and is not in `nestedtargets`.
* **Profiles.** `p0-plaintext` is the clean one. `p1-tls12`/`p2-tls13` run
  against authentik's built-in HTTPS listener, which serves **its own
  self-signed certificate, accepts TLS 1.2 and 1.3 (k6 negotiates 1.3) and speaks
  HTTP/1.1 only** — it cannot be pinned to TLS 1.3 or switched to HTTP/2, so a
  p2 number is not the same transport as AXIAM's or Keycloak's p2 and must be
  quoted with that sentence. **`p3-mtls` is not run:** the listener has no
  client-certificate mode (client certificates belong to authentik's outposts
  and flow stages), and measuring plain TLS under an mTLS label is the thing this
  harness does not do. `bench-up` refuses it, `bench-matrix` skips it.
* **Rate limits.** No limiter acted on any measured endpoint in the smoke runs
  (zero 429s anywhere, none in the server log): authentik's stock `throttle`
  settings cover the device-code grant and the API's per-request default
  (1 000/s), and the default authentication flow has no policy — in particular no
  reputation policy — bound to it or to any of its stages. So the rate-limit
  posture is `n/a`, like Keycloak's and Zitadel's. (A deployment that binds a
  reputation policy to the identification stage would throttle the password-login
  cell; this target does not.) Nothing the authentik target adds to the runner
  raises any AXIAM limit for any cell.

### Gotchas for a run

* **Time to first request.** The first start applies every migration under the
  2-CPU cap (about 2–3 minutes on the sandbox this was written on) and the
  default blueprints land after that; `bench-seed` waits for them and prints it
  is doing so.
* **The post-seed settle gate is calibrated on AXIAM.** Its burst probe wants
  400 ops/s or a 150 ms p50 under 20 workers, which authentik cannot reach at any
  time (a slow endpoint, not a clamp), so with the default the gate would wait out
  its whole timeout and stamp `settle_timeout: true` on every cell — which
  `report.py` turns into refused cells. For authentik `run-benchmark.sh` therefore
  defaults `BENCH_SETTLE_PROBE_THR` to **10 ops/s**: a does-it-answer-under-
  concurrency check and nothing more. **No post-seed transient has been
  characterised for authentik**, so the gate cannot vouch for "settled"; leave a
  quiet minute or two between `bench-seed` and `bench-run`, and raise the
  threshold once run 6 shows the settled rate (the value used is recorded in every
  cell's `meta.json` as `settle_probe_thr`).
* **The cheap endpoints are database-bound.** Because the cache and the task queue
  live in PostgreSQL, the 2-CPU database container saturates first on JWKS,
  introspection and userinfo (the report's `bottleneck` column names it); each of
  those costs ~10–70 database transactions per request (`pg_stat_database`
  deltas). That is a result about authentik 2026.8, not a harness defect — and it
  makes the database cap part of what is being measured for this target.
* **client_credentials queues on a row lock.** With 50 VUs against one client,
  `pg_stat_activity` shows tens of backends in `Lock/tuple` and `Lock/transactionid`
  waits while no container is at its CPU cap, and throughput sits at roughly the
  reciprocal of one request's latency. The same single seeded client is used for
  every target, so this is not a harness artifact, but it means the cell measures
  authentik's behaviour *per client*, and a figure from it should say so.
* **Password login at 50 VUs will time out.** One login costs about 0.8 s of CPU
  in PBKDF2 alone and the executor adds five more requests, so at the closed-loop
  load the other cells use, requests queue past k6's 60 s timeout and the cell
  reads a large error rate — an overload artifact, the same shape as Zitadel's
  bcrypt login, not a failing check. Its validity verdict (`p95 < 2 s`, error rate
  < 1 %) will say so; a lower-VU label is the way to get a figure out of it.
* **No `docker.sock` mount.** authentik's own compose gives the worker the
  Docker socket for managed outposts; none are used here, so it is not mounted.

### Not verified

* The target was built and smoke-tested on a small sandbox host, so **no
  throughput or latency figure from it is a measurement** — only correctness
  (status codes, check counts, error rates) is established. Run 6 is the
  measurement.
* `ghcr.io/goauthentik/server:2026.8.3` itself could not be pulled in the sandbox
  (blob downloads are blocked); the Docker Hub mirror `authentik/server:2026.8.3`
  was used. They are published as the same release.
* `p2-tls13` was exercised as a **dry run** (the five real cells passed the client
  contract over `https://localhost:8443`, `HTTP/1.1` recorded; `token_refresh`
  warned `fallback-op`, as documented), and the TLS facts above come from
  `openssl s_client` and `curl`; there is no measured p2 cell.
* The seed's per-run credentials were exercised end to end on a fresh stack, a
  re-seed of a running one, and `bench-down`. `bench-dry-run` ran for authentik
  start to finish (bring-up, seed, six cells, teardown, 4 min 11 s, with the
  `p3-mtls` pair recorded as `SKIP`); `bench-matrix` was not run — its `p3-mtls`
  skip is only pinned by `runner/authentik-selftest.sh`.
* The settle gate's authentik threshold (10 ops/s) is a placeholder chosen so the
  gate checks liveness; it is not derived from a measured settled rate.

## Targeted investigation runs

Two standalone scripts sit alongside the matrix for the open questions from
run 3. They are separate from `bench-matrix` on purpose: each answers ONE
question, writes its own verdict, and can be run in isolation.

| Script | Use it for |
|---|---|
| `./run-improvement-tasks.sh <task>` | One subcommand per task in [`claude_dev/improvement-after-serious-benchmark.md`](../claude_dev/improvement-after-serious-benchmark.md) that needs a live run. `./run-improvement-tasks.sh list` prints the tasks with time estimates. |
| `./run-memory-experiment.sh [a\|b\|both]` | The B1/D9 memory-retention A/B: builds a default-allocator and a jemalloc image, drives a login burst, watches RSS for 10 minutes per variant, and writes `results/d9-summary.md`. |

Each `run-improvement-tasks.sh` task writes `results/tasks/<task>/SUMMARY.md`
containing the measured numbers **and** the plan's acceptance criterion, so a
task can be closed (or a follow-up opened) from its summary alone. Start with
`g1-timeline`: run 3 found that for ~5–7 minutes after seeding, the AXIAM stack
serves everything at ~45 req/s with the datastore pinned at ~1 core, which
silently corrupted every cell that ran first after a seed — see
[`PRIVATE_BENCH_ANALYSIS.md`](PRIVATE_BENCH_ANALYSIS.md) §1.

### Seed-size sensitivity (`bench-bulk-seed`)

Every published AXIAM number so far was measured against a fixture of one
tenant, two users, one resource and the ~100 built-in registry permissions. The
obvious reader question — *does the check path hold at 100 000 users and a
four-deep resource tree?* — had no answer in the archive (J12). It does now:

```bash
just target=axiam profile=p2-tls13 bench-up
just target=axiam bench-seed          # the functional fixture, via the REST API
just scale=10 bench-bulk-seed         # 10 000 users, 2 000 resources, depth 4
just target=axiam profile=p2-tls13 bench-run
```

`runner/bulk-seed.sh` writes SurrealQL directly into the datastore in batched
transactions (`--batch`, default 1 000 statements per `BEGIN`/`COMMIT`) —
provisioning 100 000 users through the REST API would mean 100 000 Argon2id
hashes and is not a thing anyone waits for. Three properties make the resulting
cell comparable:

- **The functional fixture is untouched.** `benchuser`, `bench-resource` and
  `bench-reader` keep their ids, so the scenario runs the *same logical query*
  against a bigger index. That is the only comparison worth making.
- **The tree is deep, not just wide.** `--depth` (default 4) and `--fanout`
  (6) build a balanced hierarchy, because a flat 10 000-resource fixture
  exercises the ancestor-walk code exactly as hard as a 1-resource one.
- **Some grants are denies.** `--deny-ratio` (default 0.05) writes a fraction
  of grants as `effect: deny`, so the cell measures B1's deny-override path
  rather than only its no-denies short-circuit. Set `0` to measure the cheap
  path exclusively.

Bulk users **cannot authenticate by construction** — their `password_hash` is a
sentinel string that is not an Argon2id encoded hash at all, so verification
fails to parse. The fixture adds volume; it does not add usable credentials.

The resulting scale is recorded in `.seed/axiam.bulk.env` and lands in every
cell's `meta.json` as `seed_scale` / `seed_fixture`, so a 10× measurement can
never be mistaken for a base-fixture one. Absent file means scale 1.

`just bench-bulk-verify` prints the row counts without writing anything.

### Nested-resource authorization depth (`bench-nested`)

`bench-bulk-seed` above makes the *fixture* deep. This makes the **question**
deep: what does it cost to authorize a resource that sits N levels below the one
carrying the grant, and how does that cost move as N grows — for AXIAM, Keycloak
and Zitadel, over REST and (where the capability exists at all) gRPC.

```bash
just bench-nested                                   # depths 0 1 2 4 8 16, all three targets
just nestedtargets="axiam" nesteddepths="0 4 16" bench-nested
just profile=p2-tls13 bench-nested                  # the same ladder over TLS 1.3
just bench-nested-report                            # re-render the summary, no containers
```

Each rung is a real measured cell through the same runner as every matrix cell
(settle gate, samplers, `meta.json`), written to
`results/nested/d<N>/<target>/<profile>/authz_nested_{rest,grpc}.*` — one level
deeper than `report.py`'s walk reaches, so `bench-report` never sees it, the same
way it never sees `results/dry-run/`. **A depth ladder is not a matrix**: its
cells differ in a knob, not in a target/profile coordinate, so medianing or
ranking them against matrix cells would be meaningless.
`runner/nested_report.py` is the tree's own reader and writes
`results/nested/SUMMARY.md` at the end of the sweep.

The three arms **do not run the same product mechanism**, because only one of the
three has the mechanism — `scenarios/lib/nested.js` carries the full reasoning and
the summary repeats the caveat on every table:

| target | its arm | depth meaningful? |
|---|---|---|
| **axiam** | A real hierarchy walk: one role assignment on the chain root cascades to the leaf, and the engine resolves the ancestor chain before it can decide. | yes |
| **keycloak** | No parent/child relation exists. Nesting is URI paths over a flat resource set: one `/<root>/*` resource + one scope-based permission covers the subtree, and the decision request names the full leaf path (`permission_resource_format=uri`). Same administrative shape, different resolution mechanism. Set `BENCH_KC_NESTED_MODE=per-node` for the one-resource-per-level control. | yes |
| **zitadel** | **No per-resource decision endpoint exists at all** — project roles ride in the token and the application decides locally. The arm measures the role-claim round trip a resource server makes first, and is depth-invariant *by construction*; `nested_report.py` refuses to compute a slope for it and prints why. | no — capability gap |

So the publishable artifact is **per-target depth sensitivity** (each product
against itself); the absolute cross-target table is printed too, never without
its model caveat. Every arm's `setup()` is fail-closed — the decision at the
requested depth must return the expected verdict before the measured window
opens, because a misprovisioned fixture takes the SHORT deny path, which is
*cheaper* than the walk the cell exists to measure.

Depth is capped at 40: `crates/axiam-db/src/repository/resource.rs` sets
`MAX_ANCESTOR_DEPTH = 50` and `get_ancestors` returns an **error** — not a
truncated walk — at that many ancestors, so a rung near 50 would measure the
depth-overflow path instead of the authorization path. `just
bench-nested-selftest` is the hermetic guard (no docker, no k6) that keeps the
sweep cells out of the default matrix, keeps the gRPC arm AXIAM-only, and keeps
the capability-gap arm from being handed a slope; CI runs it on every PR.

Run procedure for a release round:
[`claude_dev/quick-bench-runbook-2026-08-16.md`](../claude_dev/quick-bench-runbook-2026-08-16.md) §6b.

## Out of scope (v1.0-beta)

**AMQP async-authz benchmarking** (server `axiam-amqp` + the Go/Python/TypeScript
SDKs' AMQP modules) is deliberately deferred. k6 has no AMQP executor/protocol
plugin, so measuring the async-authz-over-AMQP flow needs a custom load harness
(publish decision requests, consume results, measure end-to-end latency and
consumer throughput) rather than a k6 scenario. This is planned as a follow-up,
not part of the current `scenarios/`/`sdk/` frameworks.
