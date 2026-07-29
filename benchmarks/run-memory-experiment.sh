#!/usr/bin/env bash
# run-memory-experiment.sh — B1/D9 memory-retention allocator A/B.
#
# Automates the full procedure in claude_dev/memory-retention-experiment.md:
#   1. builds two local server images from the current tree —
#        variant A (control):  default allocator (glibc malloc)
#        variant B (jemalloc): --features jemalloc (tikv-jemallocator)
#   2. for each variant: bench-up + bench-seed, record idle baseline RSS,
#      drive the login burst (oauth2_password_login, 50 VUs — the same cell
#      that exposed the retention), then watch server RSS for 10 minutes
#      post-burst at 10 s cadence,
#   3. writes per-variant RSS timelines + a combined d9-summary.md with the
#      baseline / burst-peak / post-burst-plateau numbers, the ≥30%-of-gap
#      decision threshold from the experiment note, and the throughput/p95
#      no-regression check (from the k6 summaries bench-run already saves).
#
# Run from benchmarks/ on the laptop (needs docker, just, k6, python3):
#   ./run-memory-experiment.sh            # both variants, A then B
#   ./run-memory-experiment.sh a          # control only
#   ./run-memory-experiment.sh b          # jemalloc only
#
# Knobs (env):
#   D9_WATCH_MINUTES  post-burst observation window (default 10)
#   D9_SAMPLE_SECS    RSS sample cadence in seconds (default 10)
#   D9_MALLOC_CONF    optional jemalloc decay tuning for variant B, e.g.
#                     "dirty_decay_ms:1000,muzzy_decay_ms:0" — baked into the
#                     variant-B image as _RJEM_MALLOC_CONF (see the experiment
#                     note §5; leave unset for jemalloc defaults first)
#   D9_SKIP_BUILD=1   reuse already-built axiam-server:d9-* images
#
# Results land under results/d9-jemalloc-off/ and results/d9-jemalloc-on/
# (k6 + res.csv via the normal bench-run path, plus rss.csv / phases.csv /
# variant.meta from this script) and results/d9-summary.md. Nothing tracked
# by git is modified: the jemalloc build patches a *temp copy* of
# docker/Dockerfile.server.
set -euo pipefail
cd "$(dirname "$0")"
REPO_ROOT=$(cd .. && pwd)

WHICH=${1:-both}
case "$WHICH" in a|b|both) ;; *) echo "usage: $0 [a|b|both]" >&2; exit 2 ;; esac

WATCH_MIN=${D9_WATCH_MINUTES:-10}
SAMPLE_SECS=${D9_SAMPLE_SECS:-10}
SERVER_CONTAINER=bench-axiam-server
RESULTS_ROOT=$PWD/results

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v just   >/dev/null || { echo "just is required"   >&2; exit 1; }
command -v k6     >/dev/null || { echo "k6 is required"     >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

# --- helpers ----------------------------------------------------------------

# Current server RSS in MiB (normalizes docker's "489.5MiB / 1GiB" formats).
rss_mib() {
  docker stats --no-stream "$SERVER_CONTAINER" --format '{{.MemUsage}}' 2>/dev/null \
    | awk -F'/' '{print $1}' | tr -d ' ' \
    | awk '/GiB$/{printf "%.1f\n", $1*1024; next}
           /MiB$/{printf "%.1f\n", $1+0;   next}
           /KiB$/{printf "%.1f\n", $1/1024; next}
           {print 0}' \
    | sed 's/GiB//;s/MiB//;s/KiB//'
}

# Background sampler: appends "epoch_s,mem_mib" until the stopfile appears.
#
# The PID comes back in the global SAMPLER_PID, never on stdout: called as
# `pid=$(start_sampler ...)` the backgrounded subshell inherits the command
# substitution's pipe as fd 1 and — with the stopfile not yet created — holds it
# open indefinitely, so the caller blocks in read() waiting for an EOF that
# cannot arrive. Ctrl-C does not recover it either, because an async command in
# a non-interactive shell has SIGINT set to ignore. Same defect as the G1
# telemetry sampler in run-improvement-tasks.sh.
SAMPLER_PID=""
start_sampler() { # $1=csv $2=stopfile  -> sets SAMPLER_PID
  ( while [ ! -e "$2" ]; do
      printf '%s,%s\n' "$(date +%s)" "$(rss_mib)" >> "$1"
      sleep "$SAMPLE_SECS"
    done ) >/dev/null 2>&1 &
  SAMPLER_PID=$!
}

# Interrupt safety: a variant run holds a bench stack up for 10+ minutes, so
# Ctrl-C must stop the sampler and tear the stack down rather than orphan both.
STOPFILE=""
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [ -n "$STOPFILE" ]; then touch "$STOPFILE" 2>/dev/null || true; STOPFILE=""; fi
  if [ -n "${SAMPLER_PID:-}" ]; then
    kill "$SAMPLER_PID" 2>/dev/null || true
    pkill -P "$SAMPLER_PID" 2>/dev/null || true
    wait "$SAMPLER_PID" 2>/dev/null || true
    SAMPLER_PID=""
  fi
  # Only reached when a variant did NOT finish normally (the clean path disarms
  # first), so announce the teardown — bench-down is silenced here.
  echo "[d9] interrupted — tearing down the bench stack" >&2
  just target=axiam bench-down >/dev/null 2>&1 || true
  return $rc
}
arm_cleanup() { # $1=stopfile
  STOPFILE=$1
  trap 'cleanup || true; exit 130' INT TERM
  trap 'cleanup || true' EXIT
}
disarm_cleanup() { trap - EXIT INT TERM; STOPFILE=""; }

mark_phase() { # $1=phases.csv $2=phase-name
  printf '%s,%s\n' "$(date +%s)" "$2" >> "$1"
}

build_image() { # $1=variant(a|b) $2=tag
  local variant=$1 tag=$2
  if [ "${D9_SKIP_BUILD:-0}" = 1 ] && docker image inspect "$tag" >/dev/null 2>&1; then
    echo "[d9] reusing image $tag (D9_SKIP_BUILD=1)"; return
  fi
  local tmpdir; tmpdir=$(mktemp -d)
  cp "$REPO_ROOT/docker/Dockerfile.server" "$tmpdir/Dockerfile.server"
  # H4 flagged fix: docker/Dockerfile.server now defaults `ARG CARGO_FEATURES`
  # to `jemalloc` (H4 made jemalloc the release default), so variant A
  # (the "default allocator" control) is no longer a true control if built
  # with no override — it would silently inherit jemalloc too, and the whole
  # A-vs-B comparison this experiment exists to run would measure jemalloc vs
  # jemalloc. Force the system allocator back for variant A specifically via
  # the same --build-arg the Dockerfile documents at its own top (line ~53).
  local build_args=()
  if [ "$variant" = a ]; then
    build_args+=(--build-arg "CARGO_FEATURES=")
  elif [ "$variant" = b ]; then
    # Patch BOTH cargo build lines (dep pre-build + real build) so the feature
    # is consistent across layers. Temp copy only — the tracked file is untouched.
    sed -i 's/cargo build --release -p axiam-server/cargo build --release -p axiam-server --features jemalloc/g' \
      "$tmpdir/Dockerfile.server"
    if [ -n "${D9_MALLOC_CONF:-}" ]; then
      printf '\nENV _RJEM_MALLOC_CONF=%s\n' "$D9_MALLOC_CONF" >> "$tmpdir/Dockerfile.server"
      echo "[d9] variant B will run with _RJEM_MALLOC_CONF=$D9_MALLOC_CONF"
    fi
  fi
  echo "[d9] building $tag (variant $variant) — this is a full release build, be patient"
  docker build "${build_args[@]}" -f "$tmpdir/Dockerfile.server" -t "$tag" "$REPO_ROOT"
  rm -rf "$tmpdir"
}

run_variant() { # $1=variant(a|b) $2=tag $3=resultsdir
  local variant=$1 tag=$2 outdir=$3
  mkdir -p "$outdir"
  local rss_csv=$outdir/rss.csv phases=$outdir/phases.csv stopfile=$outdir/.sampler-stop
  : > "$rss_csv"; : > "$phases"; rm -f "$stopfile"
  {
    echo "variant=$variant"
    echo "image=$tag"
    echo "malloc_conf=${D9_MALLOC_CONF:-}"
    echo "watch_minutes=$WATCH_MIN"
    echo "started=$(date -Iseconds)"
  } > "$outdir/variant.meta"

  echo "[d9] === variant $variant ($tag) → $outdir ==="
  export BENCH_AXIAM_IMAGE=$tag
  export BENCH_RESULTS_DIR=$outdir
  arm_cleanup "$stopfile"
  just target=axiam bench-up
  just target=axiam bench-seed

  start_sampler "$rss_csv" "$stopfile"

  # 1. idle baseline (~60 s post-seed; the note expects ~90–130 MiB)
  mark_phase "$phases" baseline
  echo "[d9] sampling idle baseline for 60s"
  sleep 60

  # 2. login burst — same scenario/VUs as the benchmark; bench-run also saves
  #    the k6 summary + res.csv used for the throughput no-regression check.
  mark_phase "$phases" burst
  echo "[d9] driving the login burst (oauth2_password_login)"
  just target=axiam scenario=oauth2_password_login.js bench-run

  # 3. post-burst retention watch
  mark_phase "$phases" post_burst
  echo "[d9] watching RSS for $WATCH_MIN minutes post-burst"
  sleep $(( WATCH_MIN * 60 ))
  mark_phase "$phases" end

  touch "$stopfile"; wait "$SAMPLER_PID" 2>/dev/null || true; SAMPLER_PID=""
  disarm_cleanup
  just target=axiam bench-down
  unset BENCH_AXIAM_IMAGE BENCH_RESULTS_DIR
  echo "[d9] variant $variant done"
}

# --- run --------------------------------------------------------------------

TAG_A=axiam-server:d9-default
TAG_B=axiam-server:d9-jemalloc
DIR_A=$RESULTS_ROOT/d9-jemalloc-off
DIR_B=$RESULTS_ROOT/d9-jemalloc-on

if [ "$WHICH" = a ] || [ "$WHICH" = both ]; then
  build_image a "$TAG_A"
  run_variant a "$TAG_A" "$DIR_A"
fi
if [ "$WHICH" = b ] || [ "$WHICH" = both ]; then
  build_image b "$TAG_B"
  run_variant b "$TAG_B" "$DIR_B"
fi

# --- summarize --------------------------------------------------------------

python3 - "$DIR_A" "$DIR_B" "$RESULTS_ROOT/d9-summary.md" <<'PY'
import csv, json, os, statistics, sys

dir_a, dir_b, out = sys.argv[1], sys.argv[2], sys.argv[3]

def load(d):
    if not os.path.exists(os.path.join(d, "rss.csv")):
        return None
    rss = [(int(t), float(m)) for t, m in csv.reader(open(os.path.join(d, "rss.csv"))) if m]
    phases = [(int(t), p) for t, p in csv.reader(open(os.path.join(d, "phases.csv")))]
    bounds = {}
    for i, (t, p) in enumerate(phases):
        end = phases[i + 1][0] if i + 1 < len(phases) else None
        bounds[p] = (t, end)
    def window(p):
        s, e = bounds[p]
        return [m for t, m in rss if t >= s and (e is None or t < e)]
    base = window("baseline"); burst = window("burst"); post = window("post_burst")
    r = {
        "baseline": statistics.median(base) if base else None,
        "peak": max(burst + post[:3]) if (burst or post) else None,
        "plateau": statistics.median(post[-6:]) if len(post) >= 3 else None,
        "post_trajectory": post,
    }
    k6 = os.path.join(d, "oauth2_password_login.k6.json")
    if os.path.exists(k6):
        m = json.load(open(k6))["metrics"]
        r["thr"] = m["bench_ok"]["rate"]
        r["p95"] = m["bench_op_latency_ms"]["p(95)"]
    meta = os.path.join(d, "variant.meta")
    if os.path.exists(meta):
        r["meta"] = open(meta).read().strip()
    return r

A, B = load(dir_a), load(dir_b)
lines = ["# D9 memory-retention experiment — results", ""]
for name, r in (("A (default malloc)", A), ("B (jemalloc)", B)):
    lines.append(f"## Variant {name}")
    if r is None:
        lines.append("_not run_"); lines.append(""); continue
    lines.append(f"- baseline RSS: **{r['baseline']:.0f} MiB**")
    lines.append(f"- burst peak RSS: **{r['peak']:.0f} MiB**")
    if r.get("plateau") is not None:
        lines.append(f"- post-burst plateau (last minute of watch): **{r['plateau']:.0f} MiB**")
        lines.append(f"- retained above baseline: **{r['plateau'] - r['baseline']:.0f} MiB**")
    if "thr" in r:
        lines.append(f"- login throughput / p95 during burst: {r['thr']:.1f} req/s / {r['p95']:.0f} ms")
    if "meta" in r:
        lines.append("```\n" + r["meta"] + "\n```")
    lines.append("")
if A and B and A.get("plateau") and B.get("plateau"):
    gap = A["plateau"] - A["baseline"]
    closed = A["plateau"] - B["plateau"]
    pct = 100.0 * closed / gap if gap > 0 else 0.0
    verdict = "PASS — propose jemalloc" if pct >= 30 else "FAIL — document the negative result"
    lines += ["## Verdict",
              f"- retention gap under default malloc: {gap:.0f} MiB",
              f"- jemalloc closes {closed:.0f} MiB (**{pct:.0f}%** of the gap; threshold ≥30%)",
              f"- **{verdict}** (see claude_dev/memory-retention-experiment.md §4)"]
    if "thr" in A and "thr" in B and A["thr"] > 0:
        dthr = 100.0 * (B["thr"] - A["thr"]) / A["thr"]
        lines.append(f"- throughput delta B vs A: {dthr:+.1f}% (no-regression bar: within ±5%)")
lines.append("")
open(out, "w").write("\n".join(lines))
print(f"[d9] summary written to {out}")
PY

echo "[d9] all done — see $RESULTS_ROOT/d9-summary.md"
