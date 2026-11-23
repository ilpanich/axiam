# Benchmark VM runbook — Infomaniak Public Cloud

- **Date written**: 2026-11-07; §1–§8 scripted on 2026-11-08 ([`infra/bench-vm/`](../infra/bench-vm/README.md))
- **Purpose**: provision one dedicated cloud VM and run on it the **cross-system comparison**
  (AXIAM vs Keycloak vs Zitadel vs authentik) and the **SDK pass**, in place of the
  maintainer's laptop (the "G-box" every draft so far used).
- **Scope, by decision of the maintainer**: only the benchmarks needed to *compare systems*.
  The AXIAM-only improvement passes (the NEW cells, `rl=prod`, the minimal profile, the
  §12.11 investigations of the run-6 runbook) are deferred to a later session on the same VM;
  §11 lists them so nothing is silently dropped.
- **Run 6b** (§13, added 2026-11-21): the same comparison with every server and database cap raised
  from 2 to 4 CPUs, on AXIAM 1.3.1 with the competitors and SurrealDB 4.0.1 pinned to run 6's digests.
- **Run 6c** (§14, added 2026-11-23): AXIAM 1.3.1 against a SurrealDB **3.3.5** server, at both
  run-6b cap settings — how much of AXIAM's database cost is the 4.x server. Benchmark-only, unsupported.
- **Relationship to the run-6 runbook**: this file covers *the machine*.
  [`run6-runbook.md`](run6-runbook.md) remains the reference for *the run* — what each cell
  measures, the labels, the reporting rules. Where this file says "run6 §12.x", the commands
  are the ones there, unchanged unless this file says otherwise.
- **Relationship to `infra/bench-vm/`**: the OpenTofu module and the scripts *do* §1–§8;
  this file says why, in what order, and what to check. The run itself (§9) stays by hand.

---

## 0. Is a VM a good starting point? Yes — but not the `a8_ram32_disk20_perf1` flavor

### 0.1 Why a dedicated VM is better than the laptop

| Laptop problem (documented in `benchmarks/docs/methodology.md` §10 and run 4/5) | On a cloud VM |
|---|---|
| Thermal throttling (run 4's hot cells reached 96–100 °C), turbo ramp-up/back-off, AC vs battery | Gone. No thermals, no turbo you can see or that drifts cell to cell. |
| Background load (browser, IDE indexers, sync clients) | A single-purpose machine with nothing else on it. |
| A 17-hour matrix ties up the developer's own machine for days | Runs unattended in `tmux`; the PC stays free. |
| "Laptop" is not a platform a reader can reproduce | A named flavor anyone can rent and re-run on. |
| The methodology already says the laptop "is not the intended long-term benchmark environment" and keeps a **server-class re-run** open (E3 / R8.6, blocked on budget) | This is a cheap way to close that gap. |

### 0.2 What a VM introduces instead — and how this runbook handles it

1. **Shared vCPUs (noisy neighbours).** Third-party listings mark Infomaniak's standard
   flavors as *shared*, not dedicated, CPUs. Another tenant's load shows up as **steal time**,
   and the harness does **not** record steal (its host sampler reads frequency, temperature,
   utilisation and k6's own CPU). Steal is to a VM what throttling is to a laptop: invisible
   unless measured. §7 qualifies the VM before the run and §9 logs steal for its whole length.
2. **The harness's throttling telemetry goes blind.** A guest usually exposes no `cpufreq`
   and no thermal zones, so `cpu_governor` reads `unknown`, the MHz columns read 0 and the
   `clock_variance` flag can never fire. That is expected, not a fault; the steal log replaces it.
3. **A new box is a new baseline.** VM numbers are not comparable with G-box numbers (run 5
   or any earlier draft), and the two must **never be mixed** in one dataset or one median.
   Run 6 was already a new baseline (run6 §0.4); the box change is one more reason, and it
   must be stated in the report next to the comparability warning.

### 0.3 Why `a8_ram32_disk20_perf1` is undersized — two concrete reasons

**CPU: 8 vCPUs leave the load generator too little room.** k6 runs on the same host as the
stacks (methodology principle 6), and the per-container caps are CFS *quotas*, not reserved
cores, so k6 and the capped containers compete for the same vCPUs. In run 5, **k6 alone
burned about 5 cores on AXIAM's fast cells** (JWKS at ~26 700 req/s, and even there the run
was "still limited by the load generator", `PUBLIC_BENCH_ANALYSIS.md`). `report.py` flags a
cell `generator_saturated` when k6 uses more than `0.8 × (host_cpus − stack_cap_cpus)`:

| Stack (configured ceiling, run6 §2.3) | k6 headroom on 8 vCPU | flagged above | on 12 (G-box) | on 16 vCPU |
|---|---|---|---|---|
| AXIAM full — 5 CPU | 3 | **2.4 cores** | 7 (5.6) | 11 (8.8) |
| Keycloak / Zitadel — 4 CPU | 4 | 3.2 cores | 8 (6.4) | 12 (9.6) |
| authentik — 6 CPU | 2 | **1.6 cores** | 6 (4.8) | 10 (8.0) |

On 8 vCPUs, AXIAM's highest-throughput cells would be both **generator-bound and flagged**,
and the bias runs in one direction: the faster a target is, the more k6 is the bottleneck,
so the 8-vCPU box would *understate the leader* — the opposite of a fair comparison.

**Disk: 20 GB does not hold the toolchains.** The server is not built (the run uses the
published image), but the eleven SDK benches need eleven toolchains. Rough estimates (orders
of magnitude, not measurements): OS ~3 GB; images for the four stacks ~3–4 GB; Swift 6.x
toolchain + build ~4–5 GB; Rust + the fat-LTO bench build ~3 GB; .NET 10 SDK + NuGet ~1.5 GB;
JDK + Maven + Gradle caches ~2 GB; Node, Python, Go, PHP and C/C++ together ~2 GB; the twelve
checkouts ~1–2 GB. That is **20–25 GB before the first result**.

### 0.4 Recommendation

| Resource | Minimum | Recommended | Why |
|---|---|---|---|
| vCPU | 12 (matches the G-box's logical count) | **16** | §0.3: k6 headroom on every target |
| RAM | 16 GB | **32 GB** (64 GB if that is what the 16-vCPU flavor offers) | largest stack ceiling is 5 GiB; builds (Swift, Rust LTO) are memory-hungry |
| Disk | 60 GB | **80–100 GB** | §0.3 |
| OS | Ubuntu 24.04 LTS | Ubuntu 24.04 LTS | every toolchain below supports it; the resting sampler needs Linux `/proc` |

Two equivalent ways to get the disk on Infomaniak (OpenStack), pick one and **record which** —
it is fair either way because every target shares it:

- a 16-vCPU flavor with a **local disk** (`a16-…-disk80-perf1` or similar, if listed); or
- a **`-disk0`** flavor (e.g. `a16-ram64-disk0`, which exists) **booted from a 100 GB volume**.
  Volumes are network storage: database fsync latency differs from a local SSD.

Cost is hourly; a whole comparison round is about one day of uptime (§10), i.e. a few euros
at the listed rates (a8-ram32-disk80-perf1 was listed at €0.049/h). Check the console for the
16-vCPU price.

---

## 1. Provision the instance — `infra/bench-vm/run.sh`

§1–§7 are scripted in [`infra/bench-vm/`](../infra/bench-vm/README.md): an OpenTofu module
for the instance, and five numbered scripts for the host, each idempotent and safe to re-run.
Their headers say what they do and why; this section says when to run them and what to look at.
Every version they install is pinned in
[`infra/bench-vm/scripts/versions.env`](../infra/bench-vm/scripts/versions.env).

On your PC, with OpenTofu ≥ 1.6 (or Terraform ≥ 1.7), `rsync`, `ssh`, and the OpenStack CLI
if you want the snapshot of §11:

```bash
source ~/Downloads/<project>-openrc.sh          # the Infomaniak manager's OpenStack RC file
```

```bash
cd axiam/infra/bench-vm && cp tofu/example.tfvars tofu/bench-vm.auto.tfvars && $EDITOR tofu/bench-vm.auto.tfvars
```

Set `flavor_name` (16 vCPU; `openstack flavor list --sort-column VCPUs`), `boot_volume_size`
(100 for a `-disk0` flavor, 0 for one with a large local disk) and `ssh_allowed_cidrs` (your
address, `curl -fsS https://ifconfig.me`). The plan refuses fewer than 12 vCPUs, less than
60 GB of disk, and SSH from anywhere — the sizing of §0.3 as preconditions, so the
`a8_ram32_disk20_perf1` flavor fails before anything is created.

```bash
./run.sh plan
```

```bash
./run.sh apply
```

```bash
./run.sh output host_for_run_notes        # flavor, vCPUs, RAM, disk kind: goes in the run notes
```

```bash
./run.sh push && ./run.sh ssh
```

The state is kept outside the repository (`~/axiam-infra/state/bench-vm/`) and holds no
secret; the OpenStack credentials stay in your shell's environment. `./run.sh test` runs the
module's offline tests (no cloud needed).

---

## 2. Base system — `00-host-prepare.sh`

On the VM:

```bash
~/bench-vm/scripts/00-host-prepare.sh
```

It checks the OS and the box's size, upgrades, disables the background jobs that burst CPU
or disk at random (unattended upgrades, the apt and man-db timers, snap refreshes), sets UTC
and installs the base packages. **No kernel or network tuning**: the G-box had none, and a
sysctl that helps one target changes the comparison. If it ends asking for a reboot:

```bash
sudo reboot
```

---

## 3. Docker, Compose and k6 — `01-docker-k6.sh`

```bash
~/bench-vm/scripts/01-docker-k6.sh
```

Docker Engine and the Compose plugin from Docker's own repository (≥ 25 and ≥ 2.24, checked),
container log rotation so a 20-hour run cannot fill the disk, and k6 and `just` at the pinned
versions. **`just` is deliberately not Ubuntu's package**: 24.04 ships 1.21.0, which refuses
`benchmarks/justfile` (`Non-default parameter \`services\` follows default parameter`, at
`bench-logs`); the script removes it and installs release 1.59.0, checked against the SHA-256
pinned in `versions.env`.
Log out and back in afterwards (the docker group).

---

## 4. Registry logins (by hand — never scripted)

Anonymous Docker Hub pulls are rate-limited per IP (run 6's sandbox got `429` on the third
pull), and cloud IPs are shared, so log in to both registries (run6 §1.2). These are the only
credentials the round needs on the VM, and they are typed, not scripted: anything put in
cloud-init or a Tofu variable is readable through the metadata service and lands in the state.

```bash
docker login ghcr.io      # GitHub handle + a PAT with read:packages only
```

```bash
docker login              # Docker Hub
```

If the repositories are private, set up read access for §6 the same way (`gh auth login`, or
a fine-grained PAT with Contents: read on the twelve repositories).

---

## 5. The eleven SDK toolchains — `02-sdk-toolchains.sh`

```bash
~/bench-vm/scripts/02-sdk-toolchains.sh && exec bash -l
```

What each bench needs, read off `benchmarks/sdk/<lang>/run.sh` and the SDK manifests:

| Bench | Needs | Source of the requirement |
|---|---|---|
| rust | `cargo`, Rust ≥ 1.89, edition 2024 (REST feature only — no `protoc`) | `axiam-rust-sdk/Cargo.toml`, `sdk/rust/Cargo.toml` |
| typescript | Node ≥ 22, npm | `axiam-typescript-sdk/package.json` `engines` |
| python | Python ≥ 3.11, `venv` | `axiam-python-sdk/pyproject.toml` |
| java | **JDK 21** (the SDK compiles with `release 21`), Maven | `axiam-java-sdk/pom.xml` |
| kotlin | a JDK (17+); Gradle comes from the wrapper | `sdk/kotlin/build.gradle.kts` |
| csharp | **.NET SDK 10** — see §5.1 | `axiam-csharp-sdk/*.csproj` (`net10.0`) |
| php | PHP ≥ 8.2 with `sodium`, `sockets`; Composer | `axiam-php-sdk/composer.json` |
| go | Go ≥ 1.26 | `axiam-go-sdk/go.mod`, `sdk/go/go.mod` |
| swift | **Swift ≥ 6.2** (tools-version 6.2) | `axiam-swift-sdk/Package.swift` |
| c | CMake ≥ 3.16, a C11 compiler, libcurl, OpenSSL | `axiam-c-sdk/CMakeLists.txt` |
| cpp | CMake ≥ 3.16, a C++17 compiler, libcurl, OpenSSL | `axiam-cplusplus-sdk/CMakeLists.txt` |

The script installs each at the version pinned in `versions.env` (Rust via rustup, Node via
NodeSource, Go from go.dev or, when go.dev fails, from the Go module proxy verified against
sum.golang.org, .NET via `dotnet-install.sh` into `/opt/dotnet`, Swift via
`swiftly`; Maven at the Java SDK's own pinned 3.9.16, checksum-verified, not Ubuntu's 3.8.7;
JDK 21, PHP 8.3, Composer, CMake and the C/C++ libraries from Ubuntu). `go`, `dotnet` and `mvn`
are linked into `/usr/local/bin`, so every shell finds them; `cargo` and `swift` come from one
marked PATH block in `~/.bashrc` (`exec bash -l` once). `04-verify.sh` checks the shell's real
`PATH`, which is the one the SDK benches see. It installs them in that order and **stops
at the first step that fails**, printing `STOPPED … at line N` with the failing command; Go,
.NET and Swift come last, so if `04-verify.sh` finds all three missing, the script stopped at
Go. Its full output is in `~/bench/logs/02-sdk-toolchains.log`; re-running it skips what is
already installed.

### 5.1 Known blocker: the C# bench targets `net8.0`, the SDK `net10.0`

`benchmarks/sdk/csharp/axiam-sdk-bench.csproj` declares `<TargetFramework>net8.0</TargetFramework>`
and a `ProjectReference` to the sibling `Axiam.Sdk.csproj`, which now targets **`net10.0`**.
NuGet refuses that reference (a `net8.0` project cannot consume a `net10.0` one), so the C#
bench will fail to build whatever SDK is installed; its `run.sh` also still prints .NET 8
install hints. Until the harness is fixed upstream, retarget the bench **only for the SDK
pass**, and restore it afterwards so the checkout is clean for everything else:

```bash
sed -i 's#<TargetFramework>net8.0</TargetFramework>#<TargetFramework>net10.0</TargetFramework>#' ~/bench/axiam/benchmarks/sdk/csharp/axiam-sdk-bench.csproj
```

```bash
git -C ~/bench/axiam checkout -- benchmarks/sdk/csharp/axiam-sdk-bench.csproj      # after the SDK pass
```

Write it in the run notes (§9.7). `04-verify.sh` flags the mismatch as a `WARN` while it lasts. This was found by reading the files and has **not** been
compiled here (no .NET on the machine that wrote this runbook).

---

## 6. The checkouts — `03-checkouts.sh`

```bash
~/bench-vm/scripts/03-checkouts.sh
```

It clones `axiam` and the eleven SDKs side by side under `~/bench` (every SDK bench resolves
its SDK at `../../../../axiam-<lang>-sdk`), with `--filter=blob:none` so the full history is
there for the provenance check without every old file. It **refuses an unpublished tag**,
checks out the tag, and verifies that it is on `origin/main`, that `Cargo.toml` carries the
same version, and that the tree is clean; it prints the harness's SurrealDB default and writes
every checkout's ref to `~/bench/logs/checkouts.txt`.

### 6.1 Which AXIAM release to measure — `v1.3.0`

The round measures **`v1.3.0`**, the first release on **SurrealDB 4.0**
([ilpanich/axiam#853](https://github.com/ilpanich/axiam/pull/853)); the run-6 runbook's
`v1.1.1` pin is superseded for this round, its procedure unchanged. On 2026-11-08 both the tag
and `ghcr.io/ilpanich/axiam/server:1.3.0` were published, and every SDK repository carried a
`v1.3.0` tag too. The harness at the tag already pins the datastore
(`surrealdb/surrealdb:v4.0.0` in `benchmarks/targets/axiam/docker-compose.yml`), so no override
is needed; `pull-pinned-images.sh` still resolves and records its digest. The image matters
because `bench-up` falls back to a local source build when it cannot pull (run6 §1.0), and a
build is not the release — `04-verify.sh` fails if the image is not pullable.

`AXIAM_TAG=<tag>` before the script measures another release; `SDK_REF=v1.3.0` checks every SDK
out at its matching release instead of its default branch (each SDK record carries the version
it built either way, `benchmarks/sdk/_sdkversion.sh`).

**What SurrealDB 4.0 means for the numbers.** It is a major version of AXIAM's datastore, so
AXIAM's figures from this round are not comparable with any earlier run for **two**
independent reasons — the box (§0.2) and the database engine — and the report must name both.
The competitors are unaffected by the second. The PR also changes one query on the
rate-limit sweep (now index-served on 4.0) and adds write-conflict retries; none of the
comparison cells targets those paths directly, but they are part of the product being measured.
The dry run (§9.3) is the first time the harness meets 4.0 under load: a `FAIL` there is a
finding for the harness or the release, not a reason to pin SurrealDB back (a 3.x datastore
refuses the 1.3.0 client).

---

## 7. Verify and qualify — `04-verify.sh`, `05-qualify.sh`

```bash
~/bench-vm/scripts/04-verify.sh
```

A read-only table of `PASS` / `WARN` / `FAIL` over the box, the standard-benchmark tooling,
the eleven toolchains, the checkouts and the registries; its exit status is the number of
`FAIL`s, so **0 means ready**. It writes the table to `~/bench/logs/verify.txt` and every exact
version to `~/bench/logs/toolchains.txt` (for the run notes). Expect one `WARN` today: the C#
bench target (§5.1).

```bash
~/bench-vm/scripts/05-qualify.sh
```

About five minutes, no containers: three identical `sysbench` CPU runs on every vCPU (their
spread) and a fourth with `vmstat` beside it (the mean steal). The thresholds are **operator
heuristics** chosen for this runbook, not values from the methodology:

| Result | Verdict |
|---|---|
| spread ≤ 5 % and steal ≤ 2 % | proceed |
| spread ≤ 10 % and steal ≤ 5 % | proceed, and watch the steal log during the run (§9.1) |
| anything worse | exit 3: delete the instance and create a new one (it usually lands on another hypervisor), or ask Infomaniak about a dedicated-CPU option |

The result is in `~/bench/logs/qualify.txt`; quote it in the run notes.

---

## 8. Later rounds — boot the snapshot

After the first round, §11 images the provisioned VM. The next round (the improvement
benchmarks) starts from it: set `image_name = "axiam-bench-provisioned"` in
`tofu/bench-vm.auto.tfvars`, `./run.sh apply`, then `04-verify.sh` and `05-qualify.sh` — a new
instance may land on a different hypervisor, so qualify it again. Re-run `03-checkouts.sh`
with the new `AXIAM_TAG` if the release changed.

---

## 9. The comparison round

Run everything inside `tmux` so a dropped SSH session does not stop it:

```bash
tmux new -s bench
```

```bash
cd ~/bench/axiam/benchmarks
```

### 9.1 Start the steal log (and leave it running until §9.7)

This is the VM's substitute for the laptop's thermal telemetry. The file name avoids the
word `seed` so that `bench-pack`'s prune keeps it (run6 §0.3); the directory is created by
run6 §12.4, so create it now:

```bash
mkdir -p results/provenance && vmstat -n -t 10 > results/provenance/vmstat-steal.txt &
```

### 9.2 Preflight, image pins, provenance — run6 §12.1 to §12.4, unchanged

That is: the version checks, `just bench-certs`, the later-patch re-check for the competitors,
`bash runner/pull-pinned-images.sh`, **`source results/provenance/pinned-images.sh`** (in the
`tmux` shell that runs the matrix — and again in any new shell), and
`bash runner/record-provenance.sh`. Never pass `build=1`.

### 9.3 Dry run — restricted to the comparison cells

run6 §12.5 dry-runs all 26 AXIAM scenarios; only the CORE set is needed here.
`BENCH_SCENARIO_ONLY` is honoured by the dry run (the rest are recorded as `SKIP`):

```bash
export BENCH_SCENARIO_ONLY="jwks_fetch.js oauth2_client_credentials.js oauth2_password_login.js token_introspection.js token_refresh.js userinfo.js zitadel_userinfo_grpc.js userinfo_grpc.js authz_check_rest.js authz_check_grpc.js authz_batch_rest.js authz_batch_grpc.js"
```

```bash
just targets="axiam keycloak zitadel authentik" profiles="p0-plaintext p2-tls13 p3-mtls" bench-dry-run 2>&1 | tee ~/bench/logs/dry-run.log
```

```bash
cat results/dry-run/SUMMARY.md
```

Every cell must be `PASS` (`SKIP` is expected for AXIAM-only scenarios on competitors and for
authentik × p3-mtls). On a `FAIL`, stop and follow run6 §8.

**Then rehearse the SDK pass now**, not after the matrix: it compiles all eleven benches, so
a missing toolchain or a build failure surfaces on day one instead of after twenty hours
(remember §5.1 for C#):

```bash
just target=axiam profile=p0-plaintext bench-up && just target=axiam bench-seed
```

```bash
just target=axiam profile=p0-plaintext sdk-dry-run 2>&1 | tee ~/bench/logs/sdk-dry-run.log
```

```bash
just target=axiam bench-down
```

### 9.4 Resting footprint — the four comparison stacks

run6 §12.6 with the AXIAM loop reduced to the **full** profile (the minimal profile is
AXIAM-only and deferred, §11). Two stages per stack: `fresh` (empty datastore) and `fixture`
(seeded, still no load):

```bash
for T in keycloak zitadel authentik; do
  just target=$T profile=p0-plaintext bench-up
  case $T in authentik) S=300 ;; *) S=120 ;; esac
  SETTLE=$S bash runner/resting-sample.sh $T fresh
  just target=$T profile=p0-plaintext bench-seed
  SETTLE=60 bash runner/resting-sample.sh $T fixture
  just target=$T bench-down
done
```

```bash
just deploy=full target=axiam profile=p0-plaintext bench-up && SETTLE=90 bash runner/resting-sample.sh axiam fresh && just target=axiam profile=p0-plaintext bench-seed && SETTLE=60 bash runner/resting-sample.sh axiam fixture; just target=axiam bench-down
```

### 9.5 The core matrix — run6 §12.7, unchanged (the long step)

```bash
export BENCH_SCENARIO_ONLY="jwks_fetch.js oauth2_client_credentials.js oauth2_password_login.js token_introspection.js token_refresh.js userinfo.js zitadel_userinfo_grpc.js userinfo_grpc.js authz_check_rest.js authz_check_grpc.js authz_batch_rest.js authz_batch_grpc.js"
```

```bash
just targets="axiam keycloak zitadel authentik" profiles="p0-plaintext p2-tls13 p3-mtls" repeat=3 bench-matrix 2>&1 | tee ~/bench/logs/core-matrix.log
```

```bash
unset BENCH_SCENARIO_ONLY
```

Detach with `Ctrl-b d`, reattach later with `tmux attach -t bench`. If it is interrupted,
resume per pass with run6 §12.15. Keep the caps at their defaults (run6 §2.3): the box is
bigger than the G-box, but the caps — not the box — define the comparison.

### 9.6 The SDK pass — run6 §12.13, unchanged (with §5.1 applied)

At p0, `repeat=3`, `SDK_BENCH_CONCURRENCY=16`, with the stack up and seeded (run6 §12.13).
`SDK_BENCH_CONCURRENCY` is an **environment** variable, so it goes before `just`; `repeat` is a
justfile variable and goes after it. Placed after `just`, the first is refused (`variable
\`SDK_BENCH_CONCURRENCY\` overridden on the command line but not present in justfile`):

```bash
SDK_BENCH_CONCURRENCY=16 just target=axiam profile=p0-plaintext repeat=3 sdk-bench-all
```

Restore the C# project file afterwards (§5.1).

### 9.7 Report and pack

```bash
pkill -f 'vmstat -n -t 10'; bash runner/record-provenance.sh -after
```

```bash
just bench-report && just bench-pack
```

Average steal over the whole run, to quote in the notes:

```bash
awk 'NR==2 {for (i=1;i<=NF;i++) if ($i=="st") c=i; next} c && $1 ~ /^[0-9]+$/ {s+=$c; n++; if ($c>5) hi++} END {printf "mean steal %.2f %% over %d samples; %d samples above 5 %%\n", s/n, n, hi}' results/provenance/vmstat-steal.txt
```

**Run notes** — write `results/RUN-NOTES.md` from run6 §10's template, **adding**:

```text
- Host:                Infomaniak Public Cloud; ./run.sh output host_for_run_notes; CPU model from ~/bench/logs/verify.txt
- Region / created:    <region>, instance created <date>
- Qualification (§7):  ~/bench/logs/qualify.txt (sysbench spread, steal under load, verdict)
- Toolchains:          ~/bench/logs/toolchains.txt; checkouts: ~/bench/logs/checkouts.txt
- Steal during run:    mean <x> %; any period above 5 %: <when, which cells>
- Box change:          first run on this VM; NOT comparable with G-box runs (run 5 and earlier)
- AXIAM tag measured:  v1.3.0 @ <commit>; SurrealDB v4.0.0 @ <digest from images.txt>
- Engine change:       first round on SurrealDB 4.0; AXIAM figures NOT comparable with any 3.x run
- Scope:               comparison only (dry run CORE, resting x4, core matrix, SDK pass); deferred: NEW cells, rl=prod, minimal profile, investigations
- Local change:        C# SDK bench retargeted net8.0 -> net10.0 for the SDK pass only (§5.1)
```

---

## 10. Order and duration

| Step | Wall clock (estimate) |
|---|---|
| §1–§6 `run.sh apply` and scripts 00–03 | 1–1.5 h (mostly downloads; Swift is the largest) |
| §7 `04-verify.sh`, `05-qualify.sh` | 10 min |
| §9.2 preflight, pulls | 30 min |
| §9.3 dry run (CORE) + SDK rehearsal | 1.5 h |
| §9.4 resting footprint, four stacks | 50 min |
| §9.5 core matrix, median-of-3 (84 cells per repeat) | **~17 h** (run6 §5's G-box estimate; the cell timing is fixed by the load model, so the VM will be close) |
| §9.6 SDK pass | 1.5 h |
| §9.7 report, pack | 10 min |
| **Total** | **about 24 h of uptime** |

---

## 11. After the run — retrieve, clean up, keep the machine for later

From your PC — the packed results and `~/bench/logs`:

```bash
./run.sh fetch ~/axiam-results
```

On the VM, drop every credential **before** the snapshot, which would otherwise carry them
into every VM booted from it:

```bash
docker logout ghcr.io; docker logout; gh auth logout 2>/dev/null; rm -f ~/.git-credentials
```

Revoke the PATs on GitHub too. Then, **to stop paying while keeping the work**, image the
provisioned VM (everything §2–§6 installed is in it; §8 boots it) and delete the instance:

```bash
./run.sh snapshot
```

```bash
./run.sh destroy
```

The snapshot of a running VM is crash-consistent, which is enough for an image of
toolchains. For a volume-booted instance the image references a volume snapshot; both are
billed by size, so check the rate in the manager. `destroy` asks for confirmation and deletes
the boot volume with the instance (`delete_on_termination`).

**Deferred to the improvement session, on the same flavor** (each in its own results tree, as
run6 specifies): the 15 NEW AXIAM cells (run6 §12.8), the `rl=prod` pass and `rl-prod-check`
(§12.9), the minimal profile with its full control and its resting sample (§12.6 `minimal`,
§12.10), and the investigations (§12.11).

---

## 12. Security notes for a VM on the public internet

- The security group opens **only port 22, from your address**.
- Every published port of every stack binds `127.0.0.1` (`BENCH_BIND_ADDR`, run6 §1.2). The
  benchmark posture raises AXIAM's limiters and lockout to 1 000 000, so **never** export
  `BENCH_BIND_ADDR=0.0.0.0` on this machine: Docker publishes past host firewalls, and the
  security group would then be the only thing in front of four identity servers with their
  limits off.
- All benchmark credentials are generated per stack under the gitignored `.seed/` (mode 600);
  none needs to be typed. The only secrets you bring are the two registry logins and the
  GitHub read token — scope them minimally and revoke them after (§11).
- Membership of the `docker` group is root-equivalent; acceptable on a single-purpose VM, not
  on a shared one.

---

## 13. Run 6b — the comparison with raised caps, on AXIAM 1.3.1

Written 2026-11-21 from the run-6 archive (`results-2026-11-21.tar.xz`, VM `a16-ram64-disk80-perf1`,
16 vCPU AMD EPYC-Genoa, steal 0 %). **Same scope as run 6** — the cross-system comparison only; the
improvement passes of §11 stay deferred.

### 13.1 Why: run 6 measured the 2-CPU caps, not the products

In run 6 nearly every comparison cell stopped at a **2-CPU cap of one container** while the host had
more than half its CPU free. Per-container CPU, p0-plaintext, median of the three repeats
(`res.csv`):

| Target | The container at its 2.0-core cap | The rest of the stack |
|---|---|---|
| AXIAM 1.3.0 | **SurrealDB, 2.02–2.04 cores in 9 of 11 cells** (every cell that touches the datastore) | server 0.27–0.82 (1.81 in password login, 1.31 in JWKS); RabbitMQ ~0.2 |
| Keycloak 26.8.1 | **server, 2.01 in 6 of 6** | PostgreSQL 0.01–0.51 |
| Zitadel v4.19.5 | **server ~2.0** (client credentials, login, refresh, introspection) **or PostgreSQL ~2.0** (JWKS, introspection, userinfo) | the other one |
| authentik 2026.8.5 | **PostgreSQL 2.0** (JWKS, introspection, userinfo; 1.8–1.9 elsewhere) | server ≤ 1.85, worker ≤ 0.64 |

The two exceptions were not cap-bound at all: AXIAM's JWKS (43 640 req/s, closed loop at 0.8 ms p50,
k6 at 7.5 cores) and AXIAM's password login (Argon2id, server 1.81). The load generator was nowhere
near its limit elsewhere (k6 ≤ 1.8 cores outside AXIAM's JWKS).

So the run-6 table answers "what does each product do with 2 cores in its busiest container?" — a
fair question, but not the capacity of the products. Run 6b asks the next one, under the same rules.

### 13.2 The rule: raise every role by the same amount — never "uncap"

Comparable resources means **the same cap per role for every target**, which is the rule run 6 already
used (run6 §2.3). Run 6b moves both roles together:

| Role | Run 6 | **Run 6b** | Variable |
|---|---|---|---|
| every server container (AXIAM, Keycloak, Zitadel, authentik server) | 2 CPU / 2 048 MiB | **4 CPU** / 2 048 MiB | `BENCH_CPUS` |
| authentik worker | = server cap | **= server cap (4 CPU)**, as run 6 (D-79) | `BENCH_AUTHENTIK_WORKER_CPUS` defaults to `BENCH_CPUS` |
| every database (SurrealDB, PostgreSQL ×3) | 2 CPU / 1 024 MiB | **4 CPU** / 1 024 MiB | `BENCH_DB_CPUS` |
| RabbitMQ (AXIAM only, off the request path: ~0.2 cores) | 1 CPU / 512 MiB | unchanged | `BENCH_MQ_CPUS` |

Why this and not something else:

- **Not `dbcaps=uncapped`.** That switch raises the database role only (4 CPU / 2 GiB). It would lift
  the DB-bound products (AXIAM, Zitadel's reads, authentik) and leave Keycloak — server-bound in every
  cell — exactly where it was: an asymmetric change dressed as a fair one.
- **Not "no caps".** Uncapped, a stack takes whatever the host gives it, so a product with more
  containers gets more of the machine, and the stacks compete with k6 for the same 16 vCPUs.
  Neither is a comparable resource.
- **Why 4 and not 8.** 8/8 would put AXIAM's configured ceiling at 17 CPUs on a 16-vCPU host. At 4/4
  the ceilings are Keycloak and Zitadel **8**, AXIAM **9** (with RabbitMQ), authentik **12** (server +
  worker + database), and k6 keeps headroom on every stack (§13.3). It doubles the cap that bound
  run 6, which is the step that answers "was it the cap?".
- **Memory unchanged — one variable at a time.** No container came near its memory cap in run 6
  (largest: Keycloak's server at about 1.1 GiB of 2 GiB). Raising memory would also change
  Keycloak's configuration (its JVM heap is sized as 70 % of the container limit), so a throughput
  change could no longer be attributed to CPU. If a run-6b cell does reach its memory cap, that is a
  finding, and memory is the next, separate pass.
- **Efficiency is still per measured core.** `thr/core` and `cpu_ms/req` divide by the cores each
  stack actually used, not by its ceiling, so the differing ceilings (8 / 9 / 12) do not favour anyone;
  the report must still state them.

### 13.3 The load generator still fits

`report.py` flags a cell `generator_saturated` when k6 uses more than `0.8 × (16 − stack ceiling)`:

| Stack ceiling at 4/4 | k6 headroom | flagged above | k6 in run 6 (busiest cell) |
|---|---|---|---|
| Keycloak, Zitadel — 8 | 8 | 6.4 cores | 1.8 (Keycloak JWKS) |
| AXIAM — 9 | 7 | 5.6 cores | **7.5 (JWKS)**; 1.2 otherwise |
| authentik — 12 | 4 | 3.2 cores | 0.03 |

Even at twice run 6's throughput, every cell but one stays under its threshold. **AXIAM's JWKS cell
will be flagged**, and correctly so: it was not cap-bound in run 6 (no container near 95 %), so a
raised cap cannot speed it up — it only shrinks k6's share of the box. Quote AXIAM's JWKS from run 6,
and read its run-6b cell as a generator-bound control.

### 13.4 Two variables for AXIAM — so one control pass

AXIAM changes **release** (1.3.0 → 1.3.1) *and* caps; the competitors change caps only (the same
images, by digest). Without a control, an AXIAM delta could not be split between the two. 1.3.1 is
dependency bumps and test fixes (`CHANGELOG.md` `[1.3.1]`: webauthn-rs 0.5 → 0.6, minor-patch groups,
base images; no performance change is listed), and **nothing under `benchmarks/` changed between the
tags**, so the expected version delta is near zero — the control is what shows it rather than
assumes it.

| Pass | Targets | Caps | Tree | Answers |
|---|---|---|---|---|
| **A — control** | AXIAM 1.3.1 | run 6's 2/2 | `results/run6b/axiam-1.3.1-caps-2x2` | 1.3.0 → 1.3.1 at equal caps (against run 6) |
| **B — raised caps** | all four | 4/4 | `results/run6b/caps-4x4` | each product's gain from the caps (against run 6; AXIAM against pass A), and the head-to-head at 4/4 |

Both at **p0-plaintext** (run 6 already measured the TLS cost, which was small and is a separate
question), the **CORE** scenario set, `repeat=3`. Every non-AXIAM image — **SurrealDB 4.0.1**,
RabbitMQ, Keycloak, Zitadel, authentik, PostgreSQL — is pinned to the **digest run 6 recorded**, so
the competitors and the datastore are byte-for-byte what run 6 measured.

**Same VM, or a control for everyone.** Run 6's numbers are the competitors' control only on the
**same instance** (the same hypervisor host). If the VM was destroyed and recreated since, run pass A
for all four targets (`targets="axiam keycloak zitadel authentik"`) — about 5.5 h more — and re-run
`05-qualify.sh` first; otherwise a host difference reads as a cap effect.

### 13.5 Duration

From run 6 on this VM (15.6 h for 252 cells, ≈ 3.7 min per cell including bring-ups):

| Pass | Cells per repeat | × 3 | Wall clock |
|---|---|---|---|
| A — AXIAM 1.3.1 at 2/2 | 11 | 33 | ≈ 2 h |
| B — four targets at 4/4 | 30 (AXIAM 11, Keycloak 6, Zitadel 7, authentik 6) | 90 | ≈ 5.5 h |
| **Total** | | | **≈ 7.5 h** |

### 13.6 Commands

From your PC, push the updated scripts (they include `pin-images-from-run.py`):

```bash
git pull && ./run.sh push
```

On the VM, in `tmux`. First the checkout: restore the C# bench file (§5.1) so the tree is clean, then
move to the 1.3.1 tag (the SDK checkouts are only fetched, not moved; `versions.env` now defaults to
`v1.3.1`, the variable just makes the choice visible):

```bash
git -C ~/bench/axiam checkout -- benchmarks/sdk/csharp/axiam-sdk-bench.csproj
```

```bash
AXIAM_TAG=v1.3.1 ~/bench-vm/scripts/03-checkouts.sh
```

```bash
AXIAM_TAG=v1.3.1 ~/bench-vm/scripts/04-verify.sh
```

`04-verify.sh` must show `axiam checkout v1.3.1` and `AXIAM image ghcr.io/ilpanich/axiam/server:1.3.1`.

```bash
cd ~/bench/axiam/benchmarks && mkdir -p results/run6b/provenance
```

Pin every image except AXIAM's to run 6's digests, add the 1.3.1 server, pull and record them all:

```bash
eval "$(python3 -I ~/bench-vm/scripts/pin-images-from-run.py results/run-1 --except BENCH_AXIAM_IMAGE)" && export BENCH_AXIAM_IMAGE=ghcr.io/ilpanich/axiam/server:1.3.1
```

```bash
bash runner/pull-pinned-images.sh results/run6b/provenance && source results/run6b/provenance/pinned-images.sh
```

```bash
grep -E 'SURREALDB|AXIAM' results/run6b/provenance/images.txt      # SurrealDB = run 6's 4.0.1 digest; AXIAM = 1.3.1
```

```bash
bash runner/record-provenance.sh -run6b
```

The steal log for the whole round:

```bash
vmstat -n -t 10 > results/run6b/provenance/vmstat-steal.txt &
```

The CORE set, for both passes:

```bash
export BENCH_SCENARIO_ONLY="jwks_fetch.js oauth2_client_credentials.js oauth2_password_login.js token_introspection.js token_refresh.js userinfo.js zitadel_userinfo_grpc.js userinfo_grpc.js authz_check_rest.js authz_check_grpc.js authz_batch_rest.js authz_batch_grpc.js"
```

**Pass A** — AXIAM 1.3.1 at run 6's caps (the defaults; make sure no cap variable is set):

```bash
unset BENCH_CPUS BENCH_MEM BENCH_DB_CPUS BENCH_DB_MEM BENCH_AUTHENTIK_WORKER_CPUS BENCH_AUTHENTIK_WORKER_MEM
```

```bash
BENCH_RESULTS_DIR="$PWD/results/run6b/axiam-1.3.1-caps-2x2" just targets="axiam" profiles="p0-plaintext" repeat=3 bench-matrix 2>&1 | tee ~/bench/logs/run6b-pass-a.log
```

**Pass B** — all four targets at 4/4 (environment variables before `just`, §9.6):

```bash
BENCH_CPUS=4 BENCH_DB_CPUS=4 BENCH_RESULTS_DIR="$PWD/results/run6b/caps-4x4" just targets="axiam keycloak zitadel authentik" profiles="p0-plaintext" repeat=3 bench-matrix 2>&1 | tee ~/bench/logs/run6b-pass-b.log
```

While pass B runs, check in another pane that the caps took — server and database `4000000000`
nano-CPUs, RabbitMQ `1000000000`, memory unchanged (`2147483648` server, `1073741824` database):

```bash
docker inspect -f '{{.Name}} cpus={{.HostConfig.NanoCpus}} mem={{.HostConfig.Memory}}' $(docker ps -q)
```

Afterwards, the same from the records (every cell's `containers[].cpu_cap`, read off the running
container):

```bash
jq -r '[.target, .scenario, (.containers | map("\(.role)=\(.cpu_cap)") | join(" "))] | @tsv' results/run6b/caps-4x4/run-1/*/p0-plaintext/*.meta.json | sort -u
```

Close the round:

```bash
pkill -f 'vmstat -n -t 10'; unset BENCH_SCENARIO_ONLY; bash runner/record-provenance.sh -run6b-after
```

`bench-matrix` writes `report.md` into each pass's tree; `just bench-report` (run 6's tree) is not
affected, because `report.py` does not walk into `results/run6b/`. Then pack and fetch as in §9.7 and
§11 — `bench-pack` includes `results/run6b/**`:

```bash
just bench-pack
```

```bash
./run.sh fetch ~/axiam-results-run6b        # on your PC
```

### 13.7 Reading run 6b — what the report must say

1. **The caps, per role, and the ceilings** (§13.2), in the opening: 4 CPU per server and per
   database for every target; memory as run 6; ceilings 8 / 9 / 12; authentik's worker carries the
   server cap.
2. **Run 6b cells are never medianed with run 6 cells.** They are a labelled sensitivity pass — the
   same matrix with one variable moved — not a fourth repeat.
3. **Per target, the scaling factor** `thr(4/4) ÷ thr(2/2)` cell by cell, and **where the bottleneck
   moved** (the `bottleneck` column). A target that doubles and stays bound in the same container was
   simply cap-limited; one that gains little while no container is at 95 % has a limit that is not
   CPU (a lock, a pool, a serial path) — that is the finding the pass exists for.
4. **AXIAM's version delta** first (pass A against run 6), then its cap delta (pass B against pass A).
   A version delta outside run-to-run noise (run 6's `±thr%` column) is reported, not absorbed.
5. **SurrealDB 4.0.1's per-statement cost.** surrealdb/surrealdb#7667 (open; "every write statement
   costs ~350 µs of CPU in `exec::ir`, 10–17× slower than 3.3.5", unchanged in 4.0.1) and #7716 (open;
   `DEFINE EVENT` bodies re-planned on every write) both describe CPU spent per statement on the
   executing path, not lock contention. Neither issue measures whether more cores help — an inference,
   not a finding: if SurrealDB runs statements in parallel, AXIAM's throughput should rise with the
   database cap while each request's latency does not fall. Run 6b measures which; say that the
   datastore build is a known-regressed one wherever AXIAM's numbers appear. Run 6c (§14) measures how much of AXIAM's database
   cost that regression accounts for (#7716 does not apply to AXIAM's schema, §14.1).
6. **The labels of run 6 still apply**: authentik's login is `protocol-variant`, authentik's and
   Zitadel's refresh are `fallback-op`, Zitadel's userinfo uses a client-credentials token, and the
   cells run 6 marked invalid (authentik's six, Zitadel's login and refresh) are reported as such
   again unless they become valid.
7. **AXIAM's JWKS at 4/4 is generator-bound** (§13.3); the head-to-head quotes run 6's.

### 13.8 What to send back

The archive from `just bench-pack` (it carries `results/run6b/**` next to run 6), and these lines added
to `results/RUN-NOTES.md`:

```text
## Run 6b
- Same VM instance as run 6?  yes / no (if no: pass A ran for all four targets, 05-qualify.sh re-run)
- AXIAM:              v1.3.1 @ <commit>; image digest from results/run6b/provenance/images.txt
- Pinned from run 6:  SurrealDB 4.0.1, RabbitMQ, Keycloak 26.8.1, Zitadel v4.19.5, authentik 2026.8.5, PostgreSQL 16 (digests in images.txt)
- Caps:               pass A 2/2 (run 6); pass B BENCH_CPUS=4 BENCH_DB_CPUS=4, memory unchanged
- docker inspect:     caps confirmed 4/4 during pass B (yes / what differed)
- Steal during run:   mean <x> %; periods above 5 %: <when>
- Start / end, interruptions, anything re-run:
```

I will then write the scaling comparison (run 6 → pass A → pass B, per target and cell) from it.

---

## 14. Run 6c — AXIAM on a SurrealDB 3.3.5 server

Written 2026-11-23. **A benchmark-only setup, not a supported deployment**: AXIAM 1.3.1 requires
SurrealDB 4.0 (`docs/deployment/README.md`: "If you override the image, stay on 4.0.x"), and nothing
here changes that. Same scope as runs 6 and 6b: the comparison stays run 6b's; run 6c explains one of
its numbers.

### 14.1 Why: how much of AXIAM's database cost is the 4.x server?

In runs 6 and 6b AXIAM's busiest container is SurrealDB (§13.1: 2.02–2.04 cores, at its cap, in 9 of
11 cells). The 4.0 server has a known per-statement CPU regression, so part of that cost may be the
server version rather than AXIAM:

- **surrealdb/surrealdb#7667** (open): "every write statement costs ~350 µs of CPU in `exec::ir`,
  10–17× slower than 3.3.5"; the reporter measured it CPU-bound, a fixed cost per write statement,
  with reads and empty transactions barely changed; a later comment found it unchanged in 4.0.1.
- **surrealdb/surrealdb#7716** (open): every write that fires a `DEFINE EVENT` re-plans the event
  body. **It does not apply to AXIAM**: AXIAM's schema defines no events (`git grep 'DEFINE EVENT'
  v1.3.1 -- crates/` finds two, both in test code: a `#[cfg(test)]` helper in
  `axiam-db/src/repository/session.rs` and a test string in `axiam-db/src/schema.rs`). Run 6c
  therefore measures #7667, not #7716.

Run 6c runs **the same AXIAM 1.3.1 image** against a **SurrealDB 3.3.5 server** — the last release
before 4.0 — and changes nothing else.

### 14.2 Why it can run at all — the facts, each with its evidence

Re-checked on 2026-11-23 against the sources named.

1. **The client accepts a 3.x server.** AXIAM 1.3.1 locks the `surrealdb` SDK at **4.0.0**
   (`Cargo.lock` at `v1.3.1`; 4.0.1 reached `main` only after the tag). Both 4.0.0 and 4.0.1 declare,
   at `src/lib.rs:92`, `const SUPPORTED_VERSIONS: &str = ">=3.0.0-alpha.1, <5.0.0";`, and
   `check_server_version` refuses a server outside that range on connect (`src/lib.rs:370–377`). The
   refusal in 68b6d4d's message ("A 3.x client refuses a 4.0 server") is the other direction: an old
   client, a new server. **Limit:** the range check says the client will not *refuse* 3.3.5; it does not
   prove that every query and every serialized value round-trips across the major version. That is
   what the dry run (§14.6) establishes.
2. **AXIAM's queries need nothing new from 4.x.** 68b6d4d (the 4.0 migration) added no migration:
   `axiam-db/src/schema.rs` has the same 1 313 `DEFINE` statements before and after it; its
   `schema.rs` change wraps the application of a migration in `retry_on_write_conflict`. Its query
   changes are a write-conflict retry on the CIBA redemption and a bound `$cutoff` (a datetime computed
   in Rust) in the rate-limit sweep, replacing `time::now() - duration::from_secs($retention)` — plain
   SurrealQL that 3.3.x also runs. 9e55515 and 5ccd0d7, also in 1.3.1, change retry budgets
   (`helpers.rs`, `role.rs`, `notification_window.rs`). **8a78041 is not in 1.3.1** (2026-11-13, after
   the 2026-11-11 tag) and does not matter here; it only changes how the lost migration lease parks.
   AXIAM ran on 3.3.x until 68b6d4d with this same schema.
3. **The single-winner guarantee holds on 3.3.5.** `tools/surreal-race-probe/RESULTS.md`, section
   "surrealdb 3.3.5 / surrealdb-core 3.3.5 / surrealkv 0.21.4": 5 000 rounds × 8 racers in both
   mechanisms, **0 rounds with more than one winner**, 0 burned. The same file records 4.0's slower
   commit path (on 4 cores the `tx` abort rate goes from 37 % on 3.3.5 to 87 % on 4.0.0, and `nonce`,
   which never aborts, takes 4–5× as long) — which is the reason for this pass. **Caveat:** the probe ran
   the *embedded* 3.3.5 engine; this exact pairing (a 4.0.0 client, a 3.3.5 server over the network)
   was never probed. Serialization is the engine's property, so the result should carry over —
   an inference, not a measurement.
4. **The datastore must be fresh.** Upgrading a 3.x datastore to 4.0 is one-way
   (`docs/deployment/README.md`, "Upgrading a SurrealDB 3 datastore": "After that the data cannot be
   opened by 3.x"), so a volume a 4.x server has written cannot be opened by 3.3.5. `bench-matrix` and
   `bench-dry-run` run `bench-up → bench-seed → bench-run → bench-down` per target, profile and repeat,
   and `bench-down` runs `docker compose … down -v`, so every block starts on an empty
   `bench-axiam_surrealdb-data` — **provided the previous teardown happened**. A stack left running
   from run 6b, or a failed teardown, leaves a 4.x volume, and `bench-up` against a running stack
   reuses it. §14.6 therefore tears down and checks that the volume is gone before anything else.
5. **Nothing else tests this pairing.** At `v1.3.1`, CI (`ci.yml`, `coverage.yml`), every shipped
   Compose file under `docker/`, `k8s/surrealdb/statefulset.yml` and the benchmark harness all pin
   `surrealdb/surrealdb:v4.0.0`. The dry runs of §14.6 are therefore **mandatory gates**: if either
   fails, stop and send the logs. **Do not adapt code, schema or harness** to make it pass — a failure
   is the finding "AXIAM 1.3.1 does not run on a 3.3.5 server", and the pass ends there.
6. **Security.** 3.3.5 carries two advisories that 4.0 fixed (`CHANGELOG.md` `[1.3.0]`, "SurrealDB 4.0
   clears …"): **RUSTSEC-2026-0452** (`surrealkv` < 1.2.0, out-of-bounds read from a crafted SSTable;
   the trigger needs write access to the database volume) and **RUSTSEC-2026-0454** (`surrealdb-core`
   < 4.0.0, unsound `Send`/`Sync`; no query or network trigger named) — the triage notes are in
   `deny.toml` before 68b6d4d. On this internet-facing VM (§12) the database port **is not published at
   all**: the `surrealdb` service has no `ports:` entry and is reachable only on the compose network
   `bench`. (`BENCH_BIND_ADDR` governs the ports that *are* published — the AXIAM server's 8090/50051,
   loopback — and `runner/bind-addr-selftest.sh` pins every `ports:` entry to it.) Leave it that way,
   and tear the stack down when the pass ends.

### 14.3 The rule: one variable

| | Run 6b (the control) | **Run 6c** |
|---|---|---|
| AXIAM | `ghcr.io/ilpanich/axiam/server:1.3.1` | the same image |
| SurrealDB server | 4.0.1 (run 6's digest) | **3.3.5, by digest** |
| RabbitMQ, PostgreSQL, competitors | run 6's digests | run 6's digests (only RabbitMQ is in AXIAM's stack) |
| caps, memory, scenarios, profile, repeats | §13.2, §13.6 | the same |

Two passes, each compared with its run-6b twin at **equal caps**:

| Pass | Caps | Tree | Compared with |
|---|---|---|---|
| **A** | 2/2 (run 6's) | `results/run6c/axiam-1.3.1-surreal-3.3.5-caps-2x2` | run 6b pass A (`results/run6b/axiam-1.3.1-caps-2x2`) |
| **B** | 4/4 (`BENCH_CPUS=4 BENCH_DB_CPUS=4`) | `results/run6c/axiam-1.3.1-surreal-3.3.5-caps-4x4` | AXIAM's cells in run 6b pass B (`results/run6b/caps-4x4`) |

AXIAM only, **p0-plaintext**, the CORE `BENCH_SCENARIO_ONLY` set of §13.6, `repeat=3`.

**Same VM, or the control is gone.** As in §13.4: run 6b is the control only on the **same instance**.
If the VM was destroyed and recreated since run 6b, re-run `05-qualify.sh`, and know that **neither
run-6b pass is a valid control any more**: re-run run 6b's AXIAM cells at both caps on the new instance
first (§13.6 pass A, and pass B with `targets="axiam"`), or the server-version delta and the host delta
cannot be told apart.

### 14.4 Duration

At §13.5's ≈ 3.7 min per cell:

| Step | Cells | Wall clock |
|---|---|---|
| dry runs at 2/2 and 4/4 (gates) | 2 × 11, short windows | ≈ 20 min |
| pass A — 11 cells × 3 | 33 | ≈ 2 h |
| pass B — 11 cells × 3 | 33 | ≈ 2 h |
| **Total** | | **≈ 4.5 h** |

### 14.5 Before you start

Everything below runs on the VM, in `tmux`, after run 6b (so the `v1.3.1` checkout and run 6's
results are in place). Re-run the checkout script to be sure the tree is the tag, clean (it refuses
local changes — restore the C# project first if §5.1 was applied):

```bash
AXIAM_TAG=v1.3.1 ~/bench-vm/scripts/03-checkouts.sh
```

```bash
cd ~/bench/axiam/benchmarks && mkdir -p results/run6c/provenance
```

### 14.6 Commands

**1 — A fresh datastore volume (§14.2 point 4).** Tear down whatever AXIAM stack exists, then check
that the volume is gone; the second command must print nothing:

```bash
just target=axiam bench-down
```

```bash
docker volume ls -q --filter name=bench-axiam_surrealdb-data
```

**2 — The images.** Everything except AXIAM and SurrealDB from run 6's digests, then AXIAM 1.3.1:

```bash
eval "$(python3 -I ~/bench-vm/scripts/pin-images-from-run.py results/run-1 --except BENCH_AXIAM_IMAGE --except BENCH_SURREALDB_IMAGE)" && export BENCH_AXIAM_IMAGE=ghcr.io/ilpanich/axiam/server:1.3.1
```

SurrealDB 3.3.5 by its digest, never the tag (the method in the comment above `image:` in
`targets/axiam/docker-compose.yml`):

```bash
docker pull surrealdb/surrealdb:v3.3.5
```

```bash
export BENCH_SURREALDB_IMAGE="surrealdb/surrealdb@$(docker inspect --format '{{index .RepoDigests 0}}' surrealdb/surrealdb:v3.3.5 | cut -d@ -f2)" && echo "$BENCH_SURREALDB_IMAGE"
```

That digest must really be 3.3.5 — the server says so itself:

```bash
docker run --rm "$BENCH_SURREALDB_IMAGE" version
```

Pull and record every image, then pin the shell to the record:

```bash
bash runner/pull-pinned-images.sh results/run6c/provenance && source results/run6c/provenance/pinned-images.sh
```

```bash
grep -E 'SURREALDB|AXIAM' results/run6c/provenance/images.txt
```

`BENCH_SURREALDB_IMAGE` must show the digest printed above (3.3.5), and `BENCH_AXIAM_IMAGE` the same
1.3.1 digest as `results/run6b/provenance/images.txt`:

```bash
grep AXIAM results/run6b/provenance/images.txt
```

```bash
bash runner/record-provenance.sh -run6c
```

The steal log for the round:

```bash
vmstat -n -t 10 > results/run6c/provenance/vmstat-steal.txt &
```

The CORE set (non-AXIAM names in it are ignored for AXIAM, as in run 6b):

```bash
export BENCH_SCENARIO_ONLY="jwks_fetch.js oauth2_client_credentials.js oauth2_password_login.js token_introspection.js token_refresh.js userinfo.js zitadel_userinfo_grpc.js userinfo_grpc.js authz_check_rest.js authz_check_grpc.js authz_batch_rest.js authz_batch_grpc.js"
```

**3 — The gates: a dry run at each cap setting.** Under `results/dry-run/`, which `bench-pack`
excludes like every dry run. First at 2/2 (no cap variable set):

```bash
unset BENCH_CPUS BENCH_MEM BENCH_DB_CPUS BENCH_DB_MEM BENCH_AUTHENTIK_WORKER_CPUS BENCH_AUTHENTIK_WORKER_MEM
```

```bash
BENCH_RESULTS_DIR="$PWD/results/dry-run/run6c-caps-2x2" just targets="axiam" profiles="p0-plaintext" bench-dry-run 2>&1 | tee ~/bench/logs/run6c-dry-run-2x2.log
```

```bash
cat results/dry-run/run6c-caps-2x2/SUMMARY.md
```

Then at 4/4:

```bash
BENCH_CPUS=4 BENCH_DB_CPUS=4 BENCH_RESULTS_DIR="$PWD/results/dry-run/run6c-caps-4x4" just targets="axiam" profiles="p0-plaintext" bench-dry-run 2>&1 | tee ~/bench/logs/run6c-dry-run-4x4.log
```

```bash
cat results/dry-run/run6c-caps-4x4/SUMMARY.md
```

**Both must be all-PASS** for AXIAM's 11 cells (`SKIP` only for scenarios not in the set). Where it
would show first if the 3.3.5 server is the problem: a `FAIL` at `(bench-up)` — the server never became
healthy; its log is dumped above the summary (a version refusal reads `server version … does not match
the range supported by the client`; a migration or query error names the statement) — or at
`(bench-seed)`, or a cell's `.dryrun.log`. **On any FAIL: stop here, run step 6 (teardown), and send the
two logs. Do not change code, schema or harness to get past it** (§14.2 point 5).

**4 — Pass A**, at run 6's caps:

```bash
BENCH_RESULTS_DIR="$PWD/results/run6c/axiam-1.3.1-surreal-3.3.5-caps-2x2" just targets="axiam" profiles="p0-plaintext" repeat=3 bench-matrix 2>&1 | tee ~/bench/logs/run6c-pass-a.log
```

**5 — Pass B**, at 4/4:

```bash
BENCH_CPUS=4 BENCH_DB_CPUS=4 BENCH_RESULTS_DIR="$PWD/results/run6c/axiam-1.3.1-surreal-3.3.5-caps-4x4" just targets="axiam" profiles="p0-plaintext" repeat=3 bench-matrix 2>&1 | tee ~/bench/logs/run6c-pass-b.log
```

Every cell must have run against the 3.3.5 digest and the intended caps — one line per pass, each with
the single 3.3.5 digest:

```bash
jq -r '.containers[] | select(.role=="db") | "\(.image_digest) cpu_cap=\(.cpu_cap)"' results/run6c/*/run-*/axiam/p0-plaintext/*.meta.json | sort | uniq -c
```

**6 — Close the round**, and leave no 3.3.5 volume behind (a later 4.x run could not open it either
without the experimental upgrade flag):

```bash
pkill -f 'vmstat -n -t 10'; unset BENCH_SCENARIO_ONLY BENCH_SURREALDB_IMAGE; bash runner/record-provenance.sh -run6c-after
```

```bash
just target=axiam bench-down
```

```bash
docker volume ls -q --filter name=bench-axiam_surrealdb-data
```

`bench-matrix` wrote `report.md` into each pass's tree. Pack and fetch as in §13.6:

```bash
just bench-pack
```

```bash
./run.sh fetch ~/axiam-results-run6c        # on your PC
```

### 14.7 Reading run 6c — what the report must say

1. **The label, on every number:** "SurrealDB 3.3.5 server, unsupported, benchmark-only". The
   comparison with the competitors keeps **run 6b's figures** as the official ones; run 6c never
   enters a head-to-head table.
2. **Run 6c cells are a labelled sensitivity pass.** They are never medianed with run 6 or run 6b.
3. **Per cell, at equal caps** (pass A against run 6b pass A, pass B against run 6b pass B): the
   throughput ratio `thr(3.3.5) ÷ thr(4.0.1)`, p50 and p99, the SurrealDB container's CPU and its
   cores per 1 000 requests, and the `bottleneck` column.
4. **The prediction, stated before the numbers.** #7667 puts a fixed CPU cost on every *write
   statement* and leaves reads almost unchanged. So 3.3.5 should show **less database CPU per request
   and higher throughput on the write path** — `token_refresh`, `oauth2_client_credentials`,
   `oauth2_password_login` (where Argon2id on the server may cap the gain: in run 6 the server, not the
   database, was its busiest container) — and **little movement on read-mostly cells** — `jwks_fetch`,
   `userinfo`, `authz_check_*`. A result that departs from this is **reported as found, not explained
   away**: for instance, a large gain on a "read-mostly" cell says that cell writes more per request
   than its label suggests, which is itself worth knowing.
5. **Where the bottleneck goes.** If SurrealDB stops being the container at its cap, name the next one;
   if it stays at its cap with a higher throughput, the per-request database cost fell.
6. **The caveats**: the client/server pairing is unsupported and untested outside this pass (§14.2
   points 1, 3, 5); 3.3.5 carries RUSTSEC-2026-0452 and RUSTSEC-2026-0454 (point 6); #7716 does not
   apply to AXIAM's schema (§14.1).

### 14.8 What to send back

The archive from `just bench-pack` (it now carries `results/run6c/**`), and these lines added to
`results/RUN-NOTES.md`:

```text
## Run 6c
- Same VM instance as run 6b?  yes / no (if no: 05-qualify.sh re-run; which run-6b AXIAM cells were re-run as the control)
- SurrealDB:          3.3.5 @ <digest from results/run6c/provenance/images.txt>; `docker run … version` printed: <output>
- AXIAM:              1.3.1 @ <digest>, identical to run 6b's (yes / no)
- Volume reset:       `docker volume ls` empty before the dry runs (yes / no) and after the round (yes / no)
- Dry runs:           2/2 <all PASS / which FAIL>; 4/4 <all PASS / which FAIL>
- Caps check (jq):    pass A db cpu_cap=2 only (yes / no); pass B cpu_cap=4 only (yes / no)
- Steal during run:   mean <x> %; periods above 5 %: <when>
- Start / end, interruptions, anything re-run:
```

I will then write the per-cell comparison of §14.7 from it.
