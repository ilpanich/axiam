# Benchmark VM runbook — Infomaniak Public Cloud

- **Date written**: 2026-11-07
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

## 1. Provision the instance

With the OpenStack CLI (download the project's `openrc` from the Infomaniak manager), from
your PC:

```bash
source ~/Downloads/PCP-XXXX-openrc.sh
```

```bash
openstack flavor list --sort-column VCPUs | grep -E '\| a(12|16|24)-'
```

```bash
openstack image list | grep -i 'ubuntu 24.04'
```

```bash
openstack network list        # the public network is usually ext-net1
```

```bash
openstack keypair create --public-key ~/.ssh/id_ed25519.pub axiam-bench
```

SSH from your own address only (the stacks bind loopback, but nothing else needs to be open):

```bash
openstack security group create axiam-bench-ssh
```

```bash
openstack security group rule create --protocol tcp --dst-port 22 --remote-ip "$(curl -fsS https://ifconfig.me)/32" axiam-bench-ssh
```

Variant A — flavor with a local disk:

```bash
openstack server create --flavor <a16-flavor-with-disk> --image "<Ubuntu 24.04 image>" --network ext-net1 --key-name axiam-bench --security-group axiam-bench-ssh axiam-bench
```

Variant B — `disk0` flavor booted from a 100 GB volume:

```bash
openstack server create --flavor a16-ram64-disk0 --image "<Ubuntu 24.04 image>" --boot-from-volume 100 --network ext-net1 --key-name axiam-bench --security-group axiam-bench-ssh axiam-bench
```

```bash
openstack server show axiam-bench -c addresses -c status
```

```bash
ssh ubuntu@<VM_IP>
```

The Horizon web console does the same: Compute → Instances → Launch, with the same flavor,
image, key pair and security group.

---

## 2. Base system — update, then remove sources of noise

Everything from here on runs **on the VM**.

```bash
sudo apt-get update && sudo apt-get -y full-upgrade && sudo reboot
```

After the reboot, stop the background jobs that burst CPU or disk at random times. They are
the VM's equivalent of the laptop's browser and indexers:

```bash
sudo systemctl disable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer motd-news.timer man-db.timer fwupd-refresh.timer 2>/dev/null; true
```

```bash
command -v snap >/dev/null && sudo snap refresh --hold
```

```bash
sudo timedatectl set-timezone UTC
```

Base packages the harness and the builds need:

```bash
sudo apt-get install -y git curl ca-certificates gnupg jq openssl python3 python3-venv python3-pip just tmux xz-utils unzip rsync sysstat sysbench build-essential cmake pkg-config libcurl4-openssl-dev libssl-dev
```

> **No kernel or network tuning** beyond this. The G-box had none, and a sysctl that helps
> one target changes the comparison. Removing noise is allowed; adding speed is not.

---

## 3. Docker Engine (≥ 25) and Compose (≥ 2.24)

From Docker's own repository (Ubuntu's `docker.io` package lags behind):

```bash
sudo install -m 0755 -d /etc/apt/keyrings && sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
```

```bash
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list
```

```bash
sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Bound the container logs so a 20-hour run cannot fill the disk (rotation does not affect
what is measured):

```bash
echo '{ "log-driver": "json-file", "log-opts": { "max-size": "50m", "max-file": "3" } }' | sudo tee /etc/docker/daemon.json && sudo systemctl restart docker
```

```bash
sudo usermod -aG docker "$USER" && exit      # log in again so the group applies
```

```bash
docker version --format 'docker {{.Server.Version}}' && docker compose version --short
```

---

## 4. k6

Pin the version, and record it (run 5 used 2.1.0; the sandbox that wrote run 6 had 2.3.0).
If you have been running k6 on your PC, use the same version for continuity:

```bash
K6_VERSION=2.3.0
```

```bash
curl -fsSL "https://github.com/grafana/k6/releases/download/v${K6_VERSION}/k6-v${K6_VERSION}-linux-amd64.tar.gz" | sudo tar -xz -C /usr/local/bin --strip-components=1 "k6-v${K6_VERSION}-linux-amd64/k6"
```

```bash
k6 version
```

That completes the tooling of the **standard benchmarks** (run6 §1.2: Docker, Compose, k6,
`just`, `jq`, `openssl`, `python3`, `curl`, `git`).

---

## 5. The eleven SDK toolchains

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

C and C++ are already covered by §2's `build-essential cmake libcurl4-openssl-dev libssl-dev`.

**Rust**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal && . "$HOME/.cargo/env"
```

**Node 22**

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt-get install -y nodejs
```

**Java 21, Maven** (Kotlin uses the same JDK)

```bash
sudo apt-get install -y openjdk-21-jdk-headless maven
```

**PHP 8.3, Composer**

```bash
sudo apt-get install -y php8.3-cli php8.3-curl php8.3-mbstring php8.3-xml composer
```

```bash
php -m | grep -iE '^(sodium|sockets|curl|ffi)$'      # sodium and sockets must be listed
```

**Go** (the latest stable release satisfies `go 1.26`)

```bash
GO_VER="$(curl -fsS 'https://go.dev/VERSION?m=text' | head -1)" && curl -fsSL "https://go.dev/dl/${GO_VER}.linux-amd64.tar.gz" | sudo tar -xz -C /usr/local
```

**.NET 10**

```bash
sudo apt-get install -y libicu74 && curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh && sudo bash /tmp/dotnet-install.sh --channel 10.0 --install-dir /opt/dotnet
```

**Swift** (via `swiftly`, the official installer; it installs the latest stable toolchain)

```bash
sudo apt-get install -y binutils gnupg2 libc6-dev libedit2 libgcc-13-dev libncurses-dev libpython3-dev libsqlite3-0 libstdc++-13-dev libxml2-dev libz3-dev tzdata zlib1g-dev
```

```bash
cd /tmp && curl -fsSLO "https://download.swift.org/swiftly/linux/swiftly-$(uname -m).tar.gz" && tar -xzf "swiftly-$(uname -m).tar.gz" && ./swiftly init --assume-yes --quiet-shell-followup
```

**PATH for every new shell**

```bash
cat >> ~/.bashrc <<'EOF'
export PATH="/usr/local/go/bin:$HOME/go/bin:/opt/dotnet:$HOME/.cargo/bin:$PATH"
export DOTNET_ROOT=/opt/dotnet DOTNET_CLI_TELEMETRY_OPTOUT=1
[ -f "$HOME/.local/share/swiftly/env.sh" ] && . "$HOME/.local/share/swiftly/env.sh"
EOF
```

```bash
exec bash -l
```

```bash
cargo --version; node --version; python3 --version; java -version 2>&1 | head -1; mvn -v | head -1; php --version | head -1; go version; dotnet --version; swift --version 2>&1 | head -1; cmake --version | head -1
```

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

Write it in the run notes (§9.4). This was found by reading the files and has **not** been
compiled here (no .NET on the machine that wrote this runbook).

---

## 6. The checkouts — AXIAM at a release tag, the SDKs as siblings

Every SDK bench resolves its SDK at `../../../../axiam-<lang>-sdk` from
`benchmarks/sdk/<lang>/`, i.e. **beside** the `axiam` checkout. If the repositories are
private, authenticate first with a fine-grained PAT (Contents: read-only, these twelve
repositories only) or `gh auth login`.

```bash
mkdir -p ~/bench ~/bench/logs && cd ~/bench
```

```bash
git clone --filter=blob:none https://github.com/ilpanich/axiam.git
```

```bash
for L in rust typescript python java kotlin csharp php go swift c cplusplus; do git clone --filter=blob:none "https://github.com/ilpanich/axiam-$L-sdk.git"; done
```

`--filter=blob:none` keeps the full history (the provenance check needs `origin/main`) without
downloading every old file.

### 6.1 Which AXIAM release to measure — your decision

The run-6 runbook is pinned to **`v1.1.1`**; the workspace is now at **`1.2.5`**. Both
are measurable with the same procedure; the harness at the checked-out tag is the one that
runs. **My recommendation is the latest release (`v1.2.5`)**: the VM is a new baseline in any
case (§0.2), so there is nothing to keep comparable with 1.1.1, and a comparison published
now should describe the product as it ships now. Whichever you pick:

```bash
AXIAM_TAG=v1.2.5
```

```bash
cd ~/bench/axiam && git fetch origin main --tags && git checkout "$AXIAM_TAG"
```

```bash
git merge-base --is-ancestor HEAD origin/main && echo "OK: on main" || echo "STOP: not on main"
```

```bash
grep -m1 '^version' Cargo.toml && git rev-parse HEAD      # both go in the run notes
```

For the SDKs, check out the release tag of each that you intend to publish against (or leave
the default branch); either way every SDK record carries the version it built
(`sdk/_sdkversion.sh`), so the choice is recorded automatically:

```bash
for L in rust typescript python java kotlin csharp php go swift c cplusplus; do printf '%-11s %s\n' "$L" "$(git -C ~/bench/axiam-$L-sdk describe --tags --always)"; done | tee ~/bench/logs/sdk-checkouts.txt
```

---

## 7. Qualify the VM before trusting it (about 15 minutes)

Two cheap checks that the vCPUs deliver steady capacity. The thresholds are **operator
heuristics** chosen for this runbook, not values from the methodology.

**CPU consistency** — three identical runs on every vCPU:

```bash
for i in 1 2 3; do sysbench cpu --threads="$(nproc)" --time=60 run | grep 'events per second'; done | tee ~/bench/logs/sysbench.txt
```

**Steal under load** — start a fourth `sysbench cpu --threads="$(nproc)" --time=60 run` in one
`tmux` pane and, at the same time, this in another (`st` = % of time the hypervisor gave the
vCPUs to someone else):

```bash
vmstat -t 5 13 | tee ~/bench/logs/steal-qualify.txt
```

| Result | Action |
|---|---|
| spread of the three runs ≤ 5 % and average `st` ≤ 2 % | proceed |
| spread 5–10 % or `st` 2–5 % | proceed, and watch the steal log during the run (§9.1) |
| spread > 10 % or `st` > 5 % | delete the instance and create a new one (it usually lands on another hypervisor), or ask Infomaniak about a dedicated-CPU option |

Record `nproc`, `lscpu | grep 'Model name'` and the results in the run notes.

---

## 8. Registry logins

Anonymous Docker Hub pulls are rate-limited per IP (run 6's sandbox got `429` on the third
pull), and cloud IPs are shared, so log in to both registries (run6 §1.2):

```bash
docker login ghcr.io      # GitHub handle + a PAT with read:packages only
```

```bash
docker login              # Docker Hub
```

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
- Host:                Infomaniak Public Cloud, flavor <name>, <n> vCPU <model>, <RAM>, disk <local|volume, size>
- Region / created:    <region>, instance created <date>
- Qualification (§7):  sysbench e/s <r1> <r2> <r3>; steal under load <x> %
- Steal during run:    mean <x> %; any period above 5 %: <when, which cells>
- Box change:          first run on this VM; NOT comparable with G-box runs (run 5 and earlier)
- AXIAM tag measured:  <tag> @ <commit>   (run6 runbook pins v1.1.1 — say why if different)
- Scope:               comparison only (dry run CORE, resting x4, core matrix, SDK pass); deferred: NEW cells, rl=prod, minimal profile, investigations
- Local change:        C# SDK bench retargeted net8.0 -> net10.0 for the SDK pass only (§5.1)
```

---

## 10. Order and duration

| Step | Wall clock (estimate) |
|---|---|
| §1–§6 provisioning and toolchains | 1–1.5 h (mostly downloads) |
| §7 qualification | 15 min |
| §9.2 preflight, pulls | 30 min |
| §9.3 dry run (CORE) + SDK rehearsal | 1.5 h |
| §9.4 resting footprint, four stacks | 50 min |
| §9.5 core matrix, median-of-3 (84 cells per repeat) | **~17 h** (run6 §5's G-box estimate; the cell timing is fixed by the load model, so the VM will be close) |
| §9.6 SDK pass | 1.5 h |
| §9.7 report, pack | 10 min |
| **Total** | **about 24 h of uptime** |

---

## 11. After the run — retrieve, clean up, keep the machine for later

From your PC:

```bash
scp ubuntu@<VM_IP>:~/bench/axiam/benchmarks/results-*.tar.xz .
```

On the VM, drop the registry credentials:

```bash
docker logout ghcr.io; docker logout
```

Revoke the GitHub PATs used on the VM. Then, **to stop paying while keeping the work**, take a
snapshot of the provisioned instance (everything in §2–§6 is in it) and delete the instance;
the improvement benchmarks start from that snapshot later:

```bash
openstack server image create --name axiam-bench-provisioned axiam-bench
```

```bash
openstack server delete axiam-bench
```

(Variant B: snapshot the boot volume instead, `openstack volume snapshot create`.) Snapshots
are billed by size; check the current rate in the manager.

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
