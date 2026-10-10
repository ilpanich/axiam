#!/usr/bin/env bash
# Every port a benchmark stack publishes is bound to ${BENCH_BIND_ADDR:-127.0.0.1}
# (P23W6-06, #567).
#
# The targets' compose files used to publish `"${BENCH_APP_PORT:-8090}:8090"`, which
# Docker binds on 0.0.0.0 — past `ufw` — while AXIAM's benchmark posture raises its
# limiters and lockout threshold to 1 000 000. On a benchmark host on a LAN that is
# four identity servers with their limits off, reachable for the length of a run.
# The variable defaults to loopback; the FAPI conformance workflow sets it to
# 0.0.0.0 because the rig reaches AXIAM through the Docker bridge.
#
# This pins the invariant instead of the list: EVERY `ports:` entry of EVERY compose
# file under benchmarks/ (the targets, their overlays, the cAdvisor stack) names the
# variable first, so a stack added next year cannot publish on every interface by
# copying a neighbour's older line. The files are read as text — the minimal overlay
# uses `!override`/`!reset` tags that a plain YAML loader refuses — and the scan is
# run over fixtures first, so it cannot be a tautology.
#
# Hermetic: no docker, no k6. Usage: bind-addr-selftest.sh   (from benchmarks/)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"

python3 -I - "$BENCH" <<'PY'
import glob, os, re, sys

bench = sys.argv[1]
PREFIX = "${BENCH_BIND_ADDR:-127.0.0.1}:"


def published_ports(path):
    """(line number, entry) for every item under a `ports:` key, comments and the
    `!override`/`!reset` tag ignored. Short syntax only: a long-syntax mapping
    entry (`- target: 80`) comes back as its text and fails the prefix test, which
    is the right answer — it has no place to carry the variable."""
    entries, base = [], None
    with open(path) as f:
        for n, raw in enumerate(f, start=1):
            line = raw.split(" #", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            if base is not None and (indent <= base and not line.lstrip().startswith("- ")):
                base = None
            m = re.match(r"^(\s*)ports:\s*(?:!\w+\s*)?(\[\s*\])?\s*$", line)
            if m:
                base = len(m.group(1))
                continue
            if base is not None and line.lstrip().startswith("- ") and indent >= base:
                entries.append((n, line.lstrip()[2:].strip().strip("\"'")))
    return entries


def violations(path):
    return [(n, e) for n, e in published_ports(path) if not e.startswith(PREFIX)]


problems = []

# 1. The scan itself: a fixture with one bound and two unbound entries (one under an
# `!override` tag, one after a comment) must yield exactly the two unbound ones.
import tempfile
fixture = """\
services:
  a:
    ports:
      # a comment between the key and the entries
      - "${BENCH_BIND_ADDR:-127.0.0.1}:${BENCH_APP_PORT:-8090}:8090"
      - "${BENCH_APP_PORT:-8090}:8090"
    environment:
      X: "1"
  b:
    ports: !override
      - "8443:8443"
"""
with tempfile.NamedTemporaryFile("w", suffix=".yml") as t:
    t.write(fixture)
    t.flush()
    got = [e for _, e in violations(t.name)]
if got != ["${BENCH_APP_PORT:-8090}:8090", "8443:8443"]:
    problems.append(f"the scan misreads its own fixture: {got}")

# 2. Every compose file the harness can bring up.
files = sorted(set(glob.glob(os.path.join(bench, "**", "*compose*.yml"), recursive=True)
                   + glob.glob(os.path.join(bench, "**", "*compose*.yaml"), recursive=True)))
files = [f for f in files if "/node_modules/" not in f and "/results/" not in f]
total = 0
for path in files:
    total += len(published_ports(path))
    for n, entry in violations(path):
        problems.append(f"{os.path.relpath(path, bench)}:{n}: published port {entry!r} does "
                        f"not start with {PREFIX}")
if total < 10:
    problems.append(f"found only {total} published ports under benchmarks/ — the scan has "
                    "drifted from the files (there are a dozen)")

if problems:
    print("[bind-addr-selftest] FAILED", file=sys.stderr)
    for p in problems:
        print("  " + p, file=sys.stderr)
    sys.exit(1)
print(f"[bind-addr-selftest] OK — all {total} published ports in {len(files)} compose files "
      f"are bound to {PREFIX[:-1]}.")
PY
