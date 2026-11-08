#!/usr/bin/env bash
# Prepare a fresh Ubuntu 24.04 VM for the benchmarks. Idempotent; safe to re-run.
#
# Runbook: claude_dev/bench-vm-runbook.md §2. It
#   1. checks the OS and the size of the box (vCPUs, memory, disk) — the same
#      rules the OpenTofu stage enforces, re-checked here because the scripts
#      also run on a VM nobody provisioned with it;
#   2. upgrades the system, and stops if a reboot is needed (a kernel upgrade
#      taking effect halfway through a matrix is a confounder);
#   3. disables the background jobs that burst CPU or disk at random moments —
#      the VM's equivalent of the laptop's browser and indexers;
#   4. installs the base packages the harness needs.
#
# No kernel or network tuning: the G-box had none, and a sysctl that helps one
# target changes the comparison. Removing noise is allowed; adding speed is not.
#
# Usage:  ./00-host-prepare.sh        Then: ./01-docker-k6.sh (after a reboot, if asked)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

MIN_VCPUS="${BENCH_VM_MIN_VCPUS:-12}"

# ---------------------------------------------------------------------------
# 1. OS and size
# ---------------------------------------------------------------------------
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] \
    || die "This is ${PRETTY_NAME:-an unknown OS}. The scripts are written for Ubuntu 24.04 LTS (package names, the Swift and .NET builds)."
[[ "$(uname -m)" == "x86_64" ]] || die "This is $(uname -m). The k6 and Go downloads pinned in versions.env are x86_64."
ok "$PRETTY_NAME, $(uname -m)"

cpus="$(nproc)"
(( cpus >= MIN_VCPUS )) || die "$cpus vCPUs; at least $MIN_VCPUS are needed (bench-vm-runbook.md §0.3: k6 runs beside the stacks). Set BENCH_VM_MIN_VCPUS to override for a smoke test only."
if (( cpus >= 16 )); then ok "$cpus vCPUs"; else warn "$cpus vCPUs: enough, but 16 is recommended."; fi

mem_gib=$(( $(awk '/^MemTotal:/ {print $2}' /proc/meminfo) / 1024 / 1024 ))
(( mem_gib >= 15 )) || die "${mem_gib} GiB of memory; at least 16 are needed (the largest stack ceiling is 5 GiB, and the Swift and Rust builds are memory-hungry)."
ok "${mem_gib} GiB memory"

disk_gib=$(( $(df --output=size -k / | tail -1) / 1024 / 1024 ))
(( disk_gib >= 55 )) || die "${disk_gib} GiB root filesystem; at least 60 are needed (the eleven SDK toolchains alone take 20-25 GB)."
ok "${disk_gib} GiB root filesystem"

# ---------------------------------------------------------------------------
# 2. Upgrade, and stop on a pending reboot
# ---------------------------------------------------------------------------
say "Upgrading the system"
$SUDO apt-get update -q
$SUDO apt-get -y -q full-upgrade

# ---------------------------------------------------------------------------
# 3. Background noise
# ---------------------------------------------------------------------------
say "Disabling background jobs that compete with a measurement"
for unit in unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer \
            motd-news.timer man-db.timer fwupd-refresh.timer; do
    if systemctl cat "$unit" >/dev/null 2>&1; then
        $SUDO systemctl disable --now "$unit" >/dev/null 2>&1 || true
        ok "disabled $unit"
    fi
done
if command -v snap >/dev/null 2>&1; then
    $SUDO snap refresh --hold >/dev/null && ok "snap refreshes held"
fi
$SUDO timedatectl set-timezone UTC && ok "timezone UTC"

# ---------------------------------------------------------------------------
# 4. Base packages (the harness: run6-runbook.md §1.2; the samplers; tmux)
# ---------------------------------------------------------------------------
say "Installing base packages"
apt_install git curl ca-certificates gnupg jq openssl python3 python3-venv python3-pip \
            just tmux xz-utils unzip rsync procps sysstat sysbench
ok "base packages"

if [[ -f /var/run/reboot-required ]]; then
    warn "A reboot is required (the upgrade replaced the kernel or a core library)."
    echo
    echo "    sudo reboot"
    echo
    echo "  then reconnect and run ./01-docker-k6.sh"
    exit 0
fi
ok "Host prepared. Next: ./01-docker-k6.sh"
