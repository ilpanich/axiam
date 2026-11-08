#!/usr/bin/env bash
# Static checks: is everything the comparison round needs installed, at the
# version it must be, and is the box shaped the way the round assumes?
# Read-only. Run it after 03-checkouts.sh and the registry logins, and again on
# any VM booted from the snapshot.
#
# Each line is PASS, WARN or FAIL; the exit status is the number of FAILs
# (0 = ready, capped at 100). The table is also written to ~/bench/logs/verify.txt, and every
# exact version to ~/bench/logs/toolchains.txt for the run notes.
#
# Usage:  ./04-verify.sh              Then: ./05-qualify.sh
#
# `test && row PASS || row FAIL` is used as if-then-else throughout: row always
# returns 0, so the FAIL branch runs only when the test failed.
# shellcheck disable=SC2015
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"
# shellcheck source=versions.env
source "$HERE/versions.env"
bench_path

mkdir -p "$BENCH_DIR/logs"
REPORT="$BENCH_DIR/logs/verify.txt"
TOOLS="$BENCH_DIR/logs/toolchains.txt"
: > "$REPORT"
FAILS=0

row() {  # row LEVEL "what" "detail"
    local level="$1" what="$2" detail="${3:-}"
    [[ "$level" == FAIL ]] && FAILS=$((FAILS + 1))
    printf '%-4s  %-34s %s\n' "$level" "$what" "$detail" | tee -a "$REPORT"
}
# at_least NAME FOUND MIN
at_least() {
    if [[ -z "$2" ]]; then row FAIL "$1" "not found"
    elif version_ge "$2" "$3"; then row PASS "$1" "$2 (>= $3)"
    else row FAIL "$1" "$2 (needs >= $3)"
    fi
}
# exactly NAME FOUND WANT
exactly() {
    if [[ "$2" == "$3" ]]; then row PASS "$1" "$2"; else row FAIL "$1" "${2:-not found} (versions.env pins $3)"; fi
}
first_version() { grep -oE '[0-9]+(\.[0-9]+)+' | head -1; }

echo "# bench-vm verify — $(date -u +%FT%TZ) — $(hostname)" | tee -a "$REPORT"

# --- the box ---------------------------------------------------------------
cpus="$(nproc)"
if (( cpus >= 16 )); then row PASS "vCPUs" "$cpus"
elif (( cpus >= 12 )); then row WARN "vCPUs" "$cpus (12 is the minimum, 16 recommended)"
else row FAIL "vCPUs" "$cpus (k6 needs headroom beside the stacks: >= 12)"; fi
mem_gib=$(( $(awk '/^MemTotal:/ {print $2}' /proc/meminfo) / 1024 / 1024 ))
(( mem_gib >= 15 )) && row PASS "memory" "${mem_gib} GiB" || row FAIL "memory" "${mem_gib} GiB (>= 16)"
free_gib=$(( $(df --output=avail -k / | tail -1) / 1024 / 1024 ))
(( free_gib >= 20 )) && row PASS "free disk on /" "${free_gib} GiB" || row FAIL "free disk on /" "${free_gib} GiB (keep >= 20 for images, volumes and results)"
row PASS "CPU model" "$(lscpu | sed -n 's/^Model name: *//p' | head -1)"
for unit in unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then row WARN "background job" "$unit is active (00-host-prepare.sh disables it)"; fi
done
[[ -f /var/run/reboot-required ]] && row WARN "reboot pending" "reboot before the run, not during it"

# --- the standard benchmarks -------------------------------------------------
at_least "Docker Engine" "$(docker version --format '{{.Server.Version}}' 2>/dev/null)" 25
cv="$(docker compose version --short 2>/dev/null)"; at_least "Docker Compose" "${cv#v}" 2.24
docker info >/dev/null 2>&1 && row PASS "docker without sudo" "" || row FAIL "docker without sudo" "log out and in after 01-docker-k6.sh (docker group)"
jq -e '."log-opts"."max-size"' /etc/docker/daemon.json >/dev/null 2>&1 \
    && row PASS "container log rotation" "" || row WARN "container log rotation" "not configured (01-docker-k6.sh)"
exactly "k6" "$(k6 version 2>/dev/null | first_version)" "$K6_VERSION"
for t in just jq openssl python3 curl git xz tmux vmstat sysbench; do
    command -v "$t" >/dev/null 2>&1 && row PASS "$t" "" || row FAIL "$t" "not found (00-host-prepare.sh)"
done
case "${BENCH_BIND_ADDR:-127.0.0.1}" in
    127.0.0.1 | localhost) row PASS "BENCH_BIND_ADDR" "loopback" ;;
    *) row FAIL "BENCH_BIND_ADDR" "${BENCH_BIND_ADDR} — the stacks would listen beyond loopback with their limits off (runbook §12)" ;;
esac

# --- the SDK toolchains ------------------------------------------------------
exactly "rust" "$(rustc --version 2>/dev/null | first_version)" "$RUST_VERSION"
nv="$(node --version 2>/dev/null | first_version)"
[[ "${nv%%.*}" == "$NODE_MAJOR" ]] && row PASS "node" "$nv" || row FAIL "node" "${nv:-not found} (versions.env pins $NODE_MAJOR.x)"
at_least "python3" "$(python3 --version 2>/dev/null | first_version)" 3.11
jv="$(java -version 2>&1 | sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -1)"
[[ "${jv%%.*}" == 21 ]] && row PASS "java" "$jv" || row FAIL "java" "${jv:-not found} (the Java SDK compiles with release 21)"
at_least "maven" "$(mvn -v 2>/dev/null | first_version)" 3.6
at_least "php" "$(php -r 'echo PHP_VERSION;' 2>/dev/null)" 8.2
for ext in sodium sockets; do
    php -m 2>/dev/null | grep -qix "$ext" && row PASS "php ext-$ext" "" || row FAIL "php ext-$ext" "missing"
done
at_least "composer" "$(composer --version 2>/dev/null | first_version)" 2.0
exactly "go" "$(go version 2>/dev/null | first_version)" "$GO_VERSION"
dn="$(dotnet --list-sdks 2>/dev/null | awk '{print $1}' | grep "^${DOTNET_CHANNEL}\." | tail -1)"
[[ -n "$dn" ]] && row PASS ".NET SDK" "$dn" || row FAIL ".NET SDK" "no $DOTNET_CHANNEL.x SDK (02-sdk-toolchains.sh)"
exactly "swift" "$(swift --version 2>&1 | grep -m1 'Swift version' | first_version)" "$SWIFT_VERSION"
at_least "cmake" "$(cmake --version 2>/dev/null | first_version)" 3.16
for t in cc c++ pkg-config; do command -v "$t" >/dev/null 2>&1 && row PASS "$t" "" || row FAIL "$t" "not found"; done
for pc in libcurl openssl; do pkg-config --exists "$pc" 2>/dev/null && row PASS "dev: $pc" "" || row FAIL "dev: $pc" "headers missing"; done

# --- the checkouts -----------------------------------------------------------
AX="$BENCH_DIR/axiam"
if [[ -d "$AX/.git" ]]; then
    # By commit, not by `git describe`: the release commit carries other tags too
    # (axiam-opaque-v1.3.0), and describe may name any of them.
    want="$(git -C "$AX" rev-parse -q --verify "refs/tags/$AXIAM_TAG^{commit}" 2>/dev/null)"
    if [[ -n "$want" && "$(git -C "$AX" rev-parse HEAD)" == "$want" ]]; then
        row PASS "axiam checkout" "$AXIAM_TAG @ $(git -C "$AX" rev-parse --short=12 HEAD)"
    else
        row FAIL "axiam checkout" "HEAD is not $AXIAM_TAG (03-checkouts.sh)"
    fi
    git -C "$AX" diff --quiet && row PASS "axiam tree clean" "" || row WARN "axiam tree clean" "local changes: build_ref no longer describes the tag alone (fine only for runbook §5.1, during the SDK pass)"
    csproj="$AX/benchmarks/sdk/csharp/axiam-sdk-bench.csproj"
    if grep -q '<TargetFramework>net8.0</TargetFramework>' "$csproj" 2>/dev/null \
       && grep -rqs '<TargetFramework>net10.0</TargetFramework>' "$BENCH_DIR/axiam-csharp-sdk" --include=*.csproj; then
        row WARN "C# bench target" "net8.0 bench vs net10.0 SDK: apply runbook §5.1 for the SDK pass"
    fi
else
    row FAIL "axiam checkout" "missing at $AX (03-checkouts.sh)"
fi
for lang in $SDK_REPOS; do
    [[ -d "$BENCH_DIR/axiam-$lang-sdk/.git" ]] && row PASS "axiam-$lang-sdk" "$(git -C "$BENCH_DIR/axiam-$lang-sdk" describe --tags --always 2>/dev/null)" \
        || row FAIL "axiam-$lang-sdk" "missing beside axiam (03-checkouts.sh)"
done

# --- the registries ------------------------------------------------------------
IMG="ghcr.io/ilpanich/axiam/server:${AXIAM_TAG#v}"
if docker manifest inspect "$IMG" >/dev/null 2>&1; then
    row PASS "AXIAM image" "$IMG"
else
    row FAIL "AXIAM image" "$IMG not pullable (not published, or no 'docker login ghcr.io'). bench-up would fall back to a source build."
fi
if jq -e '.auths | has("https://index.docker.io/v1/")' "$HOME/.docker/config.json" >/dev/null 2>&1 \
   || jq -e '.credsStore' "$HOME/.docker/config.json" >/dev/null 2>&1; then
    row PASS "Docker Hub login" ""
else
    row WARN "Docker Hub login" "anonymous pulls are rate-limited (HTTP 429): docker login"
fi

# --- exact versions, for the run notes --------------------------------------
{
    echo "# toolchains — $(date -u +%FT%TZ) — $(hostname)"
    echo "kernel:   $(uname -r)"
    echo "docker:   $(docker version --format '{{.Server.Version}}' 2>/dev/null); compose $(docker compose version --short 2>/dev/null)"
    echo "k6:       $(k6 version 2>/dev/null | head -1)"
    echo "rust:     $(rustc --version 2>/dev/null)"
    echo "node:     $(node --version 2>/dev/null)"
    echo "python:   $(python3 --version 2>/dev/null)"
    echo "java:     $(java -version 2>&1 | grep -m1 ' version ')"
    echo "maven:    $(mvn -v 2>/dev/null | head -1)"
    echo "php:      $(php --version 2>/dev/null | head -1)"
    echo "composer: $(composer --version 2>/dev/null | head -1)"
    echo "go:       $(go version 2>/dev/null)"
    echo "dotnet:   $(dotnet --list-sdks 2>/dev/null | tr '\n' ' ')"
    echo "swift:    $(swift --version 2>&1 | grep -m1 'Swift version')"
    echo "cmake:    $(cmake --version 2>/dev/null | head -1)"
    echo "gcc:      $(gcc --version 2>/dev/null | head -1)"
} > "$TOOLS"

echo
if (( FAILS == 0 )); then ok "Ready. Versions recorded in $TOOLS. Next: ./05-qualify.sh"
else warn "$FAILS check(s) failed; see $REPORT."; fi
exit "$(( FAILS > 100 ? 100 : FAILS ))"
