# Benchmark VM runbook — Infomaniak Public Cloud

- **Date written**: 2026-11-07; §1–§8 scripted on 2026-11-08 ([`infra/bench-vm/`](../infra/bench-vm/README.md))
- **Purpose**: provision one dedicated cloud VM and run on it the **cross-system comparison**
  (AXIAM vs Keycloak vs Zitadel vs authentik) and the **SDK pass**, in place of the
  maintainer's laptop (the "G-box" every draft so far used).
- **Scope, by decision of the maintainer**: only the benchmarks needed to *compare systems*.
  The AXIAM-only improvement passes (the NEW cells, `rl=prod`, the minimal profile, the
  §12.11 investigations of the run-6 runbook) are deferred to a later session on the same VM;
  §11 lists them so nothing is silently dropped.
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
container log rotation so a 20-hour run cannot fill the disk, and k6 at the pinned version.
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
NodeSource, Go from go.dev, .NET via `dotnet-install.sh` into `/opt/dotnet`, Swift via
`swiftly`; JDK 21, Maven, PHP 8.3, Composer, CMake and the C/C++ libraries from Ubuntu) and
writes one marked PATH block into `~/.bashrc`.

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

At p0, `repeat=3`, `SDK_BENCH_CONCURRENCY=16`. Restore the C# project file afterwards.

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
