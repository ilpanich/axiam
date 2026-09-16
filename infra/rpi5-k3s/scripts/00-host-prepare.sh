#!/usr/bin/env bash
# Prepare a Raspberry Pi 5 to run k3s. Idempotent; safe to re-run.
#
# Two things Raspberry Pi OS does not do for you, and k3s will not do for
# itself:
#
#   1. MEMORY CGROUPS. The Pi's kernel ships with the memory controller
#      compiled in but DISABLED at boot. Without `cgroup_memory=1
#      cgroup_enable=memory` on the kernel command line the kubelet refuses to
#      start, with a message about the memory cgroup not being available that
#      reads like a k3s bug. This needs a REBOOT, which is why this script
#      stops rather than continuing.
#
#   2. SWAP. Raspberry Pi OS enables a 200 MB dphys-swapfile by default. The
#      kubelet fails to start with swap enabled unless told to tolerate it, and
#      telling it to tolerate it on an 8 GB node running a datastore, a broker
#      and Vault is the wrong trade: the thing that gets swapped is whatever is
#      holding decrypted secrets.
#
# It also checks the things that are cheaper to know now than after the stack is
# up: architecture, memory, free disk, and whether the root filesystem is on an
# SD card.
#
# Usage:  sudo -v && ./00-host-prepare.sh
# Then:   ./01-install-k3s.sh   (after the reboot, if one is required)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

REBOOT_REQUIRED=0

# ---------------------------------------------------------------------------
# 1. Architecture and OS
# ---------------------------------------------------------------------------
arch="$(uname -m)"
case "$arch" in
    aarch64 | arm64) ok "64-bit ARM ($arch)" ;;
    *)
        die "This is $arch. AXIAM publishes linux/amd64 and linux/arm64 only, and
  the Pi guide's hardware target is a 64-bit Raspberry Pi OS or Ubuntu Server
  arm64. A 32-bit Raspberry Pi OS install cannot run these images at all — the
  fix is a 64-bit OS, not a flag."
        ;;
esac

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    say "OS: ${PRETTY_NAME:-unknown}"
fi

# ---------------------------------------------------------------------------
# 2. Memory and disk — advisory, but the numbers are the Pi guide's
# ---------------------------------------------------------------------------
mem_mb=$(( $(awk '/^MemTotal:/ {print $2}' /proc/meminfo) / 1024 ))
if (( mem_mb < 7000 )); then
    warn "This node has ${mem_mb} MB of RAM. The k3s control plane alone takes
  500-700 MB before ingress-nginx (~150 MB), cert-manager (~120 MB across three
  pods), Vault, RabbitMQ, SurrealDB and axiam-server. 8 GB is the requirement,
  not the recommendation. Continuing, but expect OOM kills."
else
    ok "RAM: ${mem_mb} MB"
fi

free_gb=$(( $(df --output=avail -k / | tail -1) / 1024 / 1024 ))
if (( free_gb < 20 )); then
    warn "Only ${free_gb} GB free on /. Container images alone are several GB, and
  the local-path PVCs for SurrealDB (10Gi), RabbitMQ (5Gi) and Vault (1Gi) are
  all carved out of this filesystem."
else
    ok "Free disk on /: ${free_gb} GB"
fi

# Is / on an SD card? mmcblk* is the SD/eMMC controller; nvme*/sd* are not.
root_src="$(findmnt -no SOURCE / 2>/dev/null || echo unknown)"
if [[ "$root_src" == /dev/mmcblk* ]]; then
    warn "Root filesystem is on an SD card ($root_src).
  SurrealDB's surrealkv engine on an SD card is miserable, and now RabbitMQ's
  and Vault's local-path PVCs share the same device. Boot from NVMe or SSD if
  you can. This is a strong recommendation, not a hard requirement — continuing."
else
    ok "Root filesystem: $root_src"
fi

# ---------------------------------------------------------------------------
# 3. Packages
# ---------------------------------------------------------------------------
say "Installing host packages"
sudo apt-get update -qq
# curl/ca-certificates for every download; python3 for the AXIAM scripts this
# tree reuses (vault-seed.sh drives vault_seed_payload.py); jq for reading API
# responses in 03/05; openssl for inspecting certificates when something is
# wrong. No Rust toolchain: this deployment pulls released images.
sudo apt-get install -y -qq curl ca-certificates jq python3 openssl unzip git
ok "Packages installed"

# ---------------------------------------------------------------------------
# 4. Swap off, permanently
# ---------------------------------------------------------------------------
if swapon --show --noheadings 2>/dev/null | grep -q .; then
    say "Disabling swap"
    if systemctl list-unit-files 2>/dev/null | grep -q '^dphys-swapfile'; then
        sudo systemctl disable --now dphys-swapfile
        # `swapoff` alone is undone by the next boot; `uninstall` removes the
        # file dphys-swapfile would re-enable.
        sudo dphys-swapfile swapoff || true
        sudo dphys-swapfile uninstall || true
    fi
    sudo swapoff -a
    # Anything left in /etc/fstab would come back on reboot.
    if grep -qE '^[^#].*\bswap\b' /etc/fstab; then
        sudo sed -i.axiam-bak -E 's@^([^#].*\bswap\b.*)$@# disabled for k3s (AXIAM 00-host-prepare.sh): \1@' /etc/fstab
        say "Commented swap entries in /etc/fstab (backup: /etc/fstab.axiam-bak)"
    fi
    ok "Swap disabled"
else
    ok "Swap already off"
fi

# ---------------------------------------------------------------------------
# 5. Memory cgroups on the kernel command line
# ---------------------------------------------------------------------------
# Bookworm and later use /boot/firmware/cmdline.txt; older images use
# /boot/cmdline.txt. Ubuntu Server arm64 uses /boot/firmware/cmdline.txt too.
CMDLINE=""
for candidate in /boot/firmware/cmdline.txt /boot/cmdline.txt; do
    [[ -f "$candidate" ]] && { CMDLINE="$candidate"; break; }
done

if [[ -z "$CMDLINE" ]]; then
    warn "No cmdline.txt found (looked in /boot/firmware/ and /boot/).
  This is not a Raspberry Pi OS layout. Make sure the memory cgroup controller
  is enabled by whatever means your OS uses, then re-run. Check with:
      grep -w memory /proc/cgroups          # 'enabled' column must be 1
      cat /sys/fs/cgroup/cgroup.controllers # must list 'memory'"
elif grep -q 'cgroup_enable=memory' "$CMDLINE"; then
    ok "Memory cgroups already enabled in $CMDLINE"
else
    say "Enabling memory cgroups in $CMDLINE"
    # cmdline.txt is ONE line and must stay one line — a newline in it is an
    # unbootable Pi, recoverable only by putting the card in another machine.
    sudo cp "$CMDLINE" "${CMDLINE}.axiam-bak"
    sudo sed -i '1s/[[:space:]]*$/ cgroup_memory=1 cgroup_enable=memory/' "$CMDLINE"
    if [[ $(wc -l < "$CMDLINE") -gt 1 ]]; then
        sudo cp "${CMDLINE}.axiam-bak" "$CMDLINE"
        die "Editing $CMDLINE produced more than one line; restored the backup.
  Edit it by hand: append ' cgroup_memory=1 cgroup_enable=memory' to the END of
  the single existing line, with no newline."
    fi
    ok "Edited $CMDLINE (backup: ${CMDLINE}.axiam-bak)"
    REBOOT_REQUIRED=1
fi

# Believe /proc, not the file: an operator may have edited cmdline.txt already
# without rebooting, and the kubelet cares about the running kernel.
if [[ "$(awk '$1=="memory" {print $4}' /proc/cgroups 2>/dev/null)" != "1" ]] \
   && ! grep -qw memory /sys/fs/cgroup/cgroup.controllers 2>/dev/null; then
    REBOOT_REQUIRED=1
fi

# ---------------------------------------------------------------------------
# 6. The reboot gate
# ---------------------------------------------------------------------------
if (( REBOOT_REQUIRED )); then
    cat <<'MSG'

  ────────────────────────────────────────────────────────────────────────
  REBOOT REQUIRED before k3s can start.

  The memory cgroup controller is not active in the running kernel. Installing
  k3s now would leave you with a k3s.service that starts, fails, and restarts
  forever, and an error about the memory cgroup that reads like a k3s bug.

      sudo reboot

  Then run 01-install-k3s.sh. Re-running THIS script after the reboot is also
  fine and will simply confirm.
  ────────────────────────────────────────────────────────────────────────

MSG
    exit 10
fi

ok "Memory cgroup controller is active in the running kernel"
echo
ok "Host is ready. Next: ./01-install-k3s.sh"
