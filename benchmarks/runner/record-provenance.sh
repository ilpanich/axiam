#!/usr/bin/env bash
# record-provenance.sh — write down what machine and what checkout a run happened on.
#
# T23.10.2(a). Per-cell meta.json already carries the host kernel, CPU model, governor,
# Docker and k6 versions, and each container's image, digest and caps; what it cannot
# carry is facts about the RUN: which tag the harness checkout was, whether it is
# clean, what the thermal/power state of the host was, and which tool versions drove it.
# Run it once before the matrix and once after (`-after` suffix, to see drift), and send
# results/provenance/ back with the archive.
#
# Writes results/provenance/run<SUFFIX>.txt. No credential is read or printed.
# Usage: record-provenance.sh [suffix]      e.g.  record-provenance.sh -after
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$BENCH/.." && pwd)"
OUT="$BENCH/results/provenance"
mkdir -p "$OUT"
F="$OUT/run${1:-}.txt"
{
  echo "recorded:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "checkout HEAD:   $(git -C "$REPO" rev-parse HEAD)"
  echo "describe:        $(git -C "$REPO" describe --tags --always 2>/dev/null || echo unknown)"
  echo "workspace ver:   $(grep -m1 '^version' "$REPO/Cargo.toml" | cut -d'"' -f2)"
  echo "on origin/main:  $(git -C "$REPO" merge-base --is-ancestor HEAD origin/main 2>/dev/null && echo yes || echo 'NO (or origin/main not fetched)')"
  echo "tree clean:      $([ -z "$(git -C "$REPO" status --porcelain --untracked-files=no)" ] && echo yes || echo 'NO — uncommitted changes:')"
  git -C "$REPO" status --porcelain --untracked-files=no | sed 's/^/                 /'
  echo "kernel:          $(uname -sr)"
  echo "cpu:             $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ //' || echo unknown)"
  echo "logical cpus:    $(nproc)"
  echo "memory:          $(awk '/MemTotal/ {printf "%.1f GiB", $2/1048576}' /proc/meminfo 2>/dev/null || echo unknown)"
  echo "cpu governor:    $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
  echo "power:           $(cat /sys/class/power_supply/AC*/online 2>/dev/null | head -1 | sed 's/^1$/AC online/; s/^0$/ON BATTERY/' || true)"
  echo "docker:          $(docker version --format '{{.Server.Version}} (client {{.Client.Version}})' 2>/dev/null || echo unknown)"
  echo "compose:         $(docker compose version --short 2>/dev/null || echo unknown)"
  echo "k6:              $(k6 version 2>/dev/null | head -1 || echo unknown)"
  echo "just:            $(just --version 2>/dev/null || echo unknown)"
  echo "jq / openssl:    $(jq --version 2>/dev/null || echo '?') / $(openssl version 2>/dev/null | cut -d' ' -f1-2 || echo '?')"
  echo "python3:         $(python3 --version 2>/dev/null || echo unknown)"
  echo "variables set:   $(env | grep -E '^BENCH_[A-Z_]*=' | grep -vE 'PASSWORD|SECRET|TOKEN|MASTERKEY|BENCH_.*_IMAGE=' | sed 's/=.*//' | sort | tr '\n' ' ')"
  if [ -s "$OUT/images.txt" ]; then echo; echo "pinned images:"; sed 's/^/  /' "$OUT/images.txt"; fi
} > "$F"
echo "[provenance] wrote ${F#"$BENCH"/}"
