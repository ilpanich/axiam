#!/usr/bin/env bash
# authentik target wiring (T23.10.1) — three silent failure modes, all caught here.
#
#  1. A credential literal in the compose file. Every credential the authentik
#     stack needs is a REQUIRED variable (`${VAR:?…}`) generated per run by
#     `just target=authentik bench-up`; a later edit that gives one a default,
#     "just to make `docker compose up` work", puts a password in the repo and
#     in every container started from it. Nothing else would notice.
#  2. Container names that drift apart. The compose file, run-benchmark.sh's
#     container list (what `meta.json` records and what the per-container caps
#     are read for) and report.py's SERVER_CONTAINER (what the "server only"
#     efficiency variant sums) each spell the names; a mismatch does not fail
#     anything, it makes authentik's server-only figure silently 0.0 or drops the
#     worker from it.
#  3. The report's authentik arithmetic and label: "server only" must be server +
#     worker, and only authentik's password-login cell is `protocol-variant`
#     (labelling the other targets' login cells would relabel published ones).
#
# It also pins that the p3-mtls refusal is still in the justfile: authentik's
# listener has no client-certificate mode, and the failure mode of losing the
# guard is a plain-TLS number published under an mTLS label.
#
# Hermetic: no docker, no k6, no stack. Runs in CI on every PR.
# Usage: authentik-selftest.sh          (from benchmarks/)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
COMPOSE="$BENCH/targets/authentik/docker-compose.yml"
fail=0
say() { echo "[authentik-selftest] $*" >&2; fail=1; }

# --- 1. no credential literal ---------------------------------------------
# Strip comments, then every line that assigns a password / secret key /
# bootstrap token must take it from a required variable.
bad="$(sed 's/^[[:space:]]*#.*$//' "$COMPOSE" \
        | grep -nE '(PASSWORD|SECRET_KEY|BOOTSTRAP_TOKEN)[A-Z_]*:' \
        | grep -vE '\$\{[A-Z_]+:\?' || true)"
if [ -n "$bad" ]; then
  say "a credential in $COMPOSE is not a required (\${VAR:?…}) variable:"
  printf '%s\n' "$bad" >&2
fi
required="$(grep -cE '\$\{BENCH_AUTHENTIK_(SECRET_KEY|PG_PASSWORD|ADMIN_PASSWORD|ADMIN_TOKEN):\?' "$COMPOSE" || true)"
# The shared env anchor carries the secret key and the PG password once each (the
# server and worker both take it from there); the server adds the admin password and
# token; the database takes the PG password. Five in all.
if [ "${required:-0}" -lt 5 ]; then
  say "expected the four generated credentials to be required variables in at least 5 places (found ${required:-0}) — did one lose its \`:?\`?"
fi

# --- 2. container names agree ---------------------------------------------
want="bench-authentik bench-authentik-postgres bench-authentik-worker"
in_compose="$(sed -n 's/^[[:space:]]*container_name:[[:space:]]*//p' "$COMPOSE" | sort | tr '\n' ' ' | sed 's/ $//')"
in_runner="$(awk '/^container_specs_for_target\(\)/,/^}/' "$HERE/run-benchmark.sh" \
              | grep -oE 'bench-authentik[a-z-]*' | sort -u | tr '\n' ' ' | sed 's/ $//')"
[ "$in_compose" = "$want" ] || say "compose container_names are '$in_compose', expected '$want'"
[ "$in_runner" = "$want" ]  || say "run-benchmark.sh container_specs_for_target lists '$in_runner', expected '$want'"

# --- 3. the report's authentik arithmetic and label ------------------------
py_out="$(python3 -I - "$HERE/report.py" <<'PY'
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("report", sys.argv[1])
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)

problems = []
want = {"bench-authentik", "bench-authentik-worker"}
if set(report.SERVER_CONTAINER.get("authentik", ())) != want:
    problems.append("SERVER_CONTAINER['authentik'] is %r, expected server + worker %r"
                    % (report.SERVER_CONTAINER.get("authentik"), sorted(want)))

res = {"containers": {
    "bench-authentik": {"cpu_avg": 1.0, "mem_avg": 600.0},
    "bench-authentik-worker": {"cpu_avg": 0.1, "mem_avg": 300.0},
    "bench-authentik-postgres": {"cpu_avg": 1.5, "mem_avg": 100.0},
}}
d = report.derive_server_only({"throughput": 110.0}, res, "authentik")
# 110 req/s over (1.0 + 0.1) cores, and 110 req/s over 900 MiB — the database is out.
if abs(d["throughput_per_core"] - 100.0) > 0.01:
    problems.append("server-only throughput/core is %.3f, expected 100 (server + worker, no database)"
                    % d["throughput_per_core"])
if abs(d["throughput_per_gib"] - 110.0 / (900.0 / 1024.0)) > 0.01:
    problems.append("server-only throughput/GiB is %.3f, expected the server + worker memory only"
                    % d["throughput_per_gib"])

for sc, tgt, expect in [
    ("oauth2_password_login", "authentik", True),   # the three-call flow-executor login
    ("oauth2_password_login", "keycloak", False),   # the others' single-request logins are not variants
    ("oauth2_password_login", "zitadel", False),
    ("oauth2_password_login", "axiam", False),
    ("token_refresh", "axiam", True),                # the pre-existing per-scenario label is unchanged
    ("token_refresh", "authentik", True),
    ("oauth2_client_credentials", "authentik", False),
]:
    if report.is_protocol_variant(sc, tgt) != expect:
        problems.append("is_protocol_variant(%r, %r) is not %r" % (sc, tgt, expect))

for p in problems:
    print(p)
PY
)" || py_out="could not evaluate report.py: python3 failed"
if [ -n "$py_out" ]; then
  while IFS= read -r line; do say "$line"; done <<<"$py_out"
fi

# --- the p3-mtls guards -----------------------------------------------------
grep -q 'authentik cannot run p3-mtls' "$BENCH/justfile" \
  || say "justfile: bench-up no longer refuses authentik x p3-mtls"
skips="$(grep -cE '"\$t" = "authentik" \] && \[ "\$p" = "p3-mtls"' "$BENCH/justfile" || true)"
[ "${skips:-0}" -ge 2 ] \
  || say "justfile: bench-matrix and bench-dry-run must both skip authentik x p3-mtls (found ${skips:-0} guard(s))"

[ "$fail" -eq 0 ] || { echo "[authentik-selftest] FAILED" >&2; exit 1; }
echo "[authentik-selftest] OK — compose credentials are required variables, the three container-name lists agree, the report sums server + worker, and p3-mtls stays refused."
