#!/usr/bin/env bash
# No benchmark credential is a literal (T23.10.2(a); the CodeQL "hard-coded
# credentials" rule; the generalisation of authentik-selftest.sh's compose check to
# every target).
#
# The failure it guards is silent by nature: a compose file, a seed script, a k6
# config or an SDK bench that gains a `:-somepassword` default "to make it work on a
# laptop" works, passes review as a one-line convenience, and publishes a credential
# in the repository and in every container started from it. Nothing else would
# notice. This test makes the next one red.
#
# What it asserts, all hermetic (no docker, no k6, no stack):
#   1. Every credential-shaped assignment in every targets/*/docker-compose*.yml
#      takes its value from a REQUIRED variable (`${VAR:?…}`), a `--pass` /
#      `--masterkey` command-line value included.
#   2. No script, justfile, k6 scenario or SDK bench gives a credential-named
#      variable a non-empty literal default (`${X_PASSWORD:-hunter2}`,
#      `str('BENCH_CLIENT_SECRET', 'bench-secret')`, `env("BENCH_PASSWORD", "…")`),
#      and none of the five literals this repository once carried is back anywhere
#      under benchmarks/.
#   3. The scanner itself is not a tautology: it is run over known-bad fixtures and
#      must flag every one, and over known-good fixtures and must flag none.
#   4. runner/bench-creds.sh does what the compose files rely on, for all four
#      targets: a 40-character-class password, a mode-600 stack file, the same
#      values on a second load, an exported value winning over a generated one, the
#      CI scrubber told about every value, and bench-down's removal.
#   5. The credential names the helper generates for a target are exactly the ones
#      its compose file REQUIRES (a name the helper forgot, or one the compose file
#      renamed, would leave a stack that cannot start — or worse, one that starts
#      with an empty password).
#
# Usage: credential-selftest.sh          (from benchmarks/)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
fail=0
say() { echo "[credential-selftest] $*" >&2; fail=1; }

# --- 1-3: the scanner ---------------------------------------------------------
py_out="$(python3 -I - "$BENCH" <<'PY'
import os, re, sys

BENCH = sys.argv[1]
problems = []

# --- compose ------------------------------------------------------------------
SECRET_KEY = re.compile(r"(PASSWORD|_PASS$|SECRET|TOKEN|MASTERKEY|SIGNING_KEY|ENCRYPTION_KEY|PEPPER|PRIVATE_KEY|_PEM$)")
NOT_A_SECRET = re.compile(r"(PER_MIN|PER_SEC|HASHER|KEYPATH|KEY_FILE|CERT|REQUIRE_CLIENT|TTL|EXPIRATION)")
# `!reset null` (the minimal overlay REMOVING a credential the base file requires) is
# the absence of a credential, not a literal.
REQUIRED = re.compile(r'^("?\$\{[A-Za-z0-9_]+:\?|!reset null$)')

def scan_compose(text):
    """Return the credential-shaped lines of a compose file that are not required variables."""
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = re.sub(r"(^|\s)#.*$", "", raw).rstrip()
        if not line.strip():
            continue
        m = re.match(r"^\s*-?\s*([A-Za-z0-9_.]+):\s*(.*)$", line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if SECRET_KEY.search(key) and not NOT_A_SECRET.search(key) and val and not REQUIRED.match(val):
                out.append((n, raw.strip()))
        # command-line credentials: --pass X, --password X, --masterkey X
        for flag in re.finditer(r"--(?:pass|password|masterkey)\s+(\S+)", line):
            if not REQUIRED.match(flag.group(1).lstrip("'\"")):
                out.append((n, raw.strip()))
    return out

# --- scripts / js / sdk ----------------------------------------------------------
CRED_NAME = r"[A-Za-z0-9_]*(?:PASSWORD|PASS|SECRET|TOKEN|MASTERKEY)[A-Za-z0-9_]*"
SH_DEFAULT = re.compile(r"\$\{(" + CRED_NAME + r"):-([^}]*)\}")
JS_DEFAULT = re.compile(r"str\(\s*'(" + CRED_NAME + r")'\s*,\s*'([^']+)'\s*\)")
SDK_DEFAULT = re.compile(r"""(BENCH_(?:PASSWORD|CLIENT_SECRET|ADMIN_PASSWORD))["']\s*,\s*["']([^"']+)["']""")

def scan_source(text):
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for m in SH_DEFAULT.finditer(line):
            default = m.group(2)
            # empty is fine; a generated default (`$(openssl rand …)`) is fine; a
            # reference to another variable is fine; a literal is not.
            if default and "$(openssl " not in default and not default.startswith("$"):
                out.append((n, line.strip()))
        for rx in (JS_DEFAULT, SDK_DEFAULT):
            for m in rx.finditer(line):
                out.append((n, line.strip()))
    return out

# the literals this repository once carried; built from pieces so this file does not match itself
OLD = ["Bench@" + "User123!", "Bench@" + "Admin123!", "bench-" + "secret", "bench-local-" + "only-pw",
       "Masterkey" + "NeedsToHave32Characters"]

# --- witnesses: the scanner must flag every bad fixture and no good one -------------
BAD_COMPOSE = [
    '      KC_BOOTSTRAP_ADMIN_PASSWORD: "admin"',
    '      POSTGRES_PASSWORD: zitadel',
    '      RABBITMQ_DEFAULT_PASS: "${RABBITMQ_DEFAULT_PASS:-guest}"',
    "    command: 'start-from-init --masterkey \"abcdefghijklmnopqrstuvwxyz012345\"'",
    "    command: start --user ${U:?x} --pass literalpw --log warn surrealkv:/data/axiam.db",
    '      AUTHENTIK_BOOTSTRAP_TOKEN: "${BENCH_AUTHENTIK_ADMIN_TOKEN:-abc}"',
]
GOOD_COMPOSE = [
    '      KC_BOOTSTRAP_ADMIN_PASSWORD: "${KC_ADMIN_PASSWORD:?generated per run}"',
    '      POSTGRES_PASSWORD: "${BENCH_X:?generated}"',
    "    command: start --user ${U:?x} --pass ${P:?y} --log warn surrealkv:/data/axiam.db",
    '      AXIAM__RATE_LIMIT__PASSWORD_RESET_PER_MIN: "${AXIAM__RATE_LIMIT__PASSWORD_RESET_PER_MIN:-1000000}"',
    '      ZITADEL_SYSTEMDEFAULTS_PASSWORDHASHER_HASHER_COST: "${BENCH_ZITADEL_HASHER_COST:-14}"',
    '      ZITADEL_TLS_KEYPATH: "${BENCH_ZITADEL_TLS_KEYPATH:-}"',
    '      # KC_DB_PASSWORD: literal in a comment is not a credential',
]
BAD_SRC = [
    'PW="${KC_ADMIN_PASSWORD:-admin}"',
    'export X="${BENCH_ADMIN_PASSWORD:-hunter2}"',
    "  password: str('BENCH_PASSWORD', 'hunter2'),",
    "  clientSecret: str('BENCH_CLIENT_SECRET', 'bench-s3cret'),",
    'password: env("BENCH_PASSWORD", "hunter2"),',
    "'password' => $env('BENCH_PASSWORD', 'hunter2'),",
]
GOOD_SRC = [
    'PW="${KC_ADMIN_PASSWORD:?no password}"',
    'BENCH_PASSWORD="${BENCH_PASSWORD:-}"',
    'P="${BENCH_AUTHENTIK_USER_PASSWORD:-Bn-$(openssl rand -hex 16)-Aa1}"',
    "  password: str('BENCH_PASSWORD', ''),",
    'password: env("BENCH_PASSWORD", ""),',
    '# PW="${KC_ADMIN_PASSWORD:-admin}"  (a comment)',
]
for fx in BAD_COMPOSE:
    if not scan_compose(fx):
        problems.append("witness: the compose scanner did NOT flag a credential literal: %s" % fx.strip())
for fx in GOOD_COMPOSE:
    if scan_compose(fx):
        problems.append("witness: the compose scanner flagged an innocent line: %s" % fx.strip())
for fx in BAD_SRC:
    if not scan_source(fx):
        problems.append("witness: the source scanner did NOT flag a credential default: %s" % fx.strip())
for fx in GOOD_SRC:
    if scan_source(fx):
        problems.append("witness: the source scanner flagged an innocent line: %s" % fx.strip())

# --- the real tree -----------------------------------------------------------------
n_compose = 0
for tdir in sorted(os.listdir(os.path.join(BENCH, "targets"))):
    d = os.path.join(BENCH, "targets", tdir)
    if not os.path.isdir(d):
        continue
    for fn in sorted(os.listdir(d)):
        if fn.startswith("docker-compose") and fn.endswith(".yml"):
            n_compose += 1
            for n, line in scan_compose(open(os.path.join(d, fn)).read()):
                problems.append("targets/%s/%s:%d is a credential that is not a required ${VAR:?…}: %s" % (tdir, fn, n, line))
if n_compose < 6:
    problems.append("expected to scan at least six compose files under targets/, found %d" % n_compose)

SKIP_DIRS = {"results", ".seed", "node_modules", "target", ".git", "vendor", "__pycache__", "profiles"}
n_src = 0
for root, dirs, files in os.walk(BENCH):
    dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not x.startswith(".")]
    for fn in files:
        path = os.path.join(root, fn)
        rel = os.path.relpath(path, BENCH)
        if fn == "credential-selftest.sh":
            continue
        # historical literals: anywhere, in any text file
        try:
            text = open(path, encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        for lit in OLD:
            if lit in text:
                problems.append("%s still contains the literal %r" % (rel, lit))
        if fn.endswith((".sh", ".js", ".mjs", ".py", ".go", ".rs", ".java", ".kt", ".cs", ".php", ".swift", ".c", ".cpp")) or fn == "justfile":
            n_src += 1
            for n, line in scan_source(text):
                problems.append("%s:%d gives a credential a non-empty literal default: %s" % (rel, n, line))
if n_src < 40:
    problems.append("expected to scan at least 40 source files, found %d — did the walk break?" % n_src)

for p in problems:
    print(p)
PY
)" || py_out="could not run the credential scanner: python3 failed"
if [ -n "$py_out" ]; then
  while IFS= read -r line; do say "$line"; done <<<"$py_out"
fi

# --- 4: bench-creds.sh, functionally -------------------------------------------------
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
command -v openssl >/dev/null || { say "openssl is required"; exit 1; }
(
  set -euo pipefail
  export BENCH_SEED_DIR="$T/seed"
  # shellcheck source=bench-creds.sh
  . "$HERE/bench-creds.sh"
  for tgt in axiam keycloak zitadel authentik; do
    ( # a clean environment per target: nothing the caller exported may leak in
      for name in $(bench_creds_spec "$tgt" | awk '{print $1}'); do unset "$name"; done
      bench_creds_load "$tgt" 2>/dev/null
      f="$(bench_creds_file "$tgt")"
      [ "$(stat -c %a "$f")" = "600" ] || { echo "stack file for $tgt is mode $(stat -c %a "$f"), not 600"; exit 1; }
      first=""
      while read -r name kind; do
        [ -n "$name" ] || continue
        v="${!name:-}"
        [ -n "$v" ] || { echo "$tgt: $name is empty after bench_creds_load"; exit 1; }
        case "$kind" in
          pw) [[ "$v" =~ ^Bn-[0-9a-f]{32}-Aa1$ ]] || { echo "$tgt: $name does not have the generated password shape"; exit 1; } ;;
          hex16) [ "${#v}" -eq 32 ] || { echo "$tgt: $name must be exactly 32 characters (Zitadel's masterkey), is ${#v}"; exit 1; } ;;
          hex64) [ "${#v}" -eq 64 ] || { echo "$tgt: $name must be 64 hex characters, is ${#v}"; exit 1; } ;;
        esac
        first="$first$name=$v;"
      done < <(bench_creds_spec "$tgt")
      # a second load yields the same values (a still-running stack keeps its credentials)
      for name in $(bench_creds_spec "$tgt" | awk '{print $1}'); do unset "$name"; done
      bench_creds_load "$tgt" 2>/dev/null
      second=""
      while read -r name kind; do [ -n "$name" ] && second="$second$name=${!name};"; done < <(bench_creds_spec "$tgt")
      [ "$first" = "$second" ] || { echo "$tgt: a second bench_creds_load changed the credentials"; exit 1; }
      # an exported value wins, and is what the file records
      for name in $(bench_creds_spec "$tgt" | awk '{print $1}'); do unset "$name"; done
      rm -f "$f"
      one="$(bench_creds_spec "$tgt" | awk 'NR==1{print $1}')"
      export "$one=operator'chose \$this"
      bench_creds_load "$tgt" 2>/dev/null
      [ "${!one}" = "operator'chose \$this" ] || { echo "$tgt: an exported $one did not win over the generated value"; exit 1; }
      unset "$one"; . "$f"
      [ "${!one}" = "operator'chose \$this" ] || { echo "$tgt: the stack file did not record the exported $one verbatim"; exit 1; }
      # under GitHub Actions every value is registered with the scrubber
      for name in $(bench_creds_spec "$tgt" | awk '{print $1}'); do unset "$name"; done
      masked="$(GITHUB_ACTIONS=true bench_creds_load "$tgt" 2>/dev/null | grep -c '^::add-mask::' || true)"
      want="$(bench_creds_spec "$tgt" | wc -l)"
      [ "$masked" -eq "$want" ] || { echo "$tgt: $masked of $want credentials were registered with ::add-mask::"; exit 1; }
      bench_creds_remove "$tgt"
      [ ! -e "$f" ] || { echo "$tgt: bench_creds_remove left the stack file"; exit 1; }
    ) || exit 1
  done
) > "$T/creds.out" 2>&1 || { say "runner/bench-creds.sh misbehaves:"; sed 's/^/    /' "$T/creds.out" >&2; }

# --- 5: the generated names are the required names ---------------------------------
# shellcheck source=bench-creds.sh
( . "$HERE/bench-creds.sh"
  for tgt in axiam keycloak zitadel authentik; do
    compose="$BENCH/targets/$tgt/docker-compose.yml"
    while read -r name kind; do
      [ -n "$name" ] || continue
      # BENCH_PASSWORD and BENCH_ADMIN_PASSWORD are provisioned by the seed, not read
      # by a compose file.
      case "$name" in BENCH_PASSWORD|BENCH_ADMIN_PASSWORD) continue ;; esac
      grep -qE "\\$\{$name:\?" "$compose" \
        || echo "targets/$tgt/docker-compose.yml does not require \${$name:?…}, which runner/bench-creds.sh generates for it"
    done < <(bench_creds_spec "$tgt")
  done
) > "$T/names.out" 2>&1 || true
if [ -s "$T/names.out" ]; then while IFS= read -r line; do say "$line"; done < "$T/names.out"; fi

# bench-down removes what belongs to the volumes it removes: the per-run credentials AND the
# bulk-seed record (a stale axiam.bulk.env mislabels every later cell as a scaled fixture)
down="$(awk '/^bench-down:/{f=1} f&&/^# Dump a target/{exit} f' "$BENCH/justfile")"
grep -q 'bench_creds_remove' <<<"$down" || say "bench-down no longer removes the per-run credentials (.seed/<target>.stack.env)"
grep -q 'bulk.env' <<<"$down" || say "bench-down no longer removes .seed/<target>.bulk.env — a scaled-fixture record would outlive its datastore and mislabel later cells"

[ "$fail" -eq 0 ] || { echo "[credential-selftest] FAILED" >&2; exit 1; }
echo "[credential-selftest] OK — every compose credential is a required variable, no script/scenario/SDK bench carries a credential default, the scanner flags its witnesses, and bench-creds.sh generates, persists, masks and removes per-run credentials for all four targets."
