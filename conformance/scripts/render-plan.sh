#!/usr/bin/env bash
# render-plan.sh — substitute suite.env values (and PEM file contents) into a
# committed test-plan template, producing the JSON the suite actually reads.
#
# Why templates rather than committed configs: a usable conformance config
# carries client ids, certificate PEMs and an issuer URL, i.e. deployment
# identity. Committing one means either publishing it or keeping the real one
# out of tree, and the second is how a harness rots — the committed copy stops
# matching what anybody actually runs. Templating keeps the SHAPE in git, where
# review can see it, and the values on the machine.
#
# Usage: render-plan.sh <plan.json> [output.json]
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
PLAN="${1:?usage: render-plan.sh <plan.json> [output.json]}"
OUT="${2:-$HERE/.run/$(basename "$PLAN")}"

[ -f "$PLAN" ] || { echo "[render-plan] no such plan: $PLAN" >&2; exit 1; }

# shellcheck disable=SC1091
set -a; . "$HERE/suite.env"; set +a

mkdir -p "$(dirname "$OUT")"

# PEM files become PEM *strings* in the JSON. Read them here rather than making
# the template reference paths: the suite runs in a container that cannot see
# the host's filesystem, so a path in the config would resolve to nothing and
# the failure would surface as an unexplained TLS error twelve tests in.
read_pem() {
  local path="$1" label="$2"
  # Relative paths resolve against conformance/, so suite.env can say
  # `certs/client-mtls.crt` without knowing where the repo lives.
  case "$path" in /*) : ;; *) path="$HERE/$path" ;; esac
  if [ ! -f "$path" ]; then
    echo "[render-plan] $label: no such file: $path" >&2
    echo "[render-plan] run 'just conformance-certs' first, or point suite.env at real ones" >&2
    exit 1
  fi
  # JSON-encode: the PEM is multi-line, and an unescaped newline is a syntax
  # error in the rendered config.
  python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read()))' "$path"
}

CLIENT_MTLS_CERT_PEM=$(read_pem "$CLIENT_MTLS_CERT" CLIENT_MTLS_CERT)
CLIENT_MTLS_KEY_PEM=$(read_pem "$CLIENT_MTLS_KEY" CLIENT_MTLS_KEY)
CLIENT_SELF_SIGNED_CERT_PEM=$(read_pem "$CLIENT_SELF_SIGNED_CERT" CLIENT_SELF_SIGNED_CERT)
CLIENT_SELF_SIGNED_KEY_PEM=$(read_pem "$CLIENT_SELF_SIGNED_KEY" CLIENT_SELF_SIGNED_KEY)
AXIAM_CA_PEM=$(read_pem "${AXIAM_CA:-certs/ca.crt}" AXIAM_CA)

for required in AXIAM_ISSUER CLIENT_MTLS_ID CLIENT_SELF_SIGNED_ID; do
  if [ -z "${!required:-}" ]; then
    echo "[render-plan] $required is empty in suite.env." >&2
    echo "[render-plan] run 'just conformance-register' to provision the two FAPI clients," >&2
    echo "[render-plan] or fill it in by hand if they already exist." >&2
    exit 1
  fi
done

# The PEM variables are already JSON string literals (quotes included), so they
# substitute into a template position that is NOT itself quoted. The templates
# are written with that in mind: "cert": "${...}" would double-quote, so they
# use bare ${...} where a PEM goes. Check that assumption rather than trusting
# it, because the failure mode is invalid JSON forty lines deep.
python3 - "$PLAN" "$OUT" <<'PY'
import json, os, re, sys

src, dst = sys.argv[1], sys.argv[2]
raw = open(src).read()

# Placeholders holding a JSON-encoded PEM must not sit inside quotes; every
# other placeholder must.
pem_vars = {
    "CLIENT_MTLS_CERT_PEM", "CLIENT_MTLS_KEY_PEM",
    "CLIENT_SELF_SIGNED_CERT_PEM", "CLIENT_SELF_SIGNED_KEY_PEM",
    "AXIAM_CA_PEM",
}

def substitute(match):
    name = match.group(1)
    value = os.environ.get(name, "")
    return value

# Strip the quotes around PEM placeholders so the JSON-encoded value lands
# cleanly, then substitute everything.
for v in pem_vars:
    raw = raw.replace('"${%s}"' % v, "${%s}" % v)

rendered = re.sub(r"\$\{([A-Z_][A-Z0-9_]*)\}", substitute, raw)

try:
    parsed = json.loads(rendered)
except json.JSONDecodeError as e:
    sys.stderr.write("[render-plan] rendered config is not valid JSON: %s\n" % e)
    sys.stderr.write("[render-plan] this is a bug in the template, not in your setup\n")
    sys.exit(1)

# The suite ignores unknown keys, but `_comment` is ours and there is no reason
# to ship an essay to the test runner.
parsed.pop("_comment", None)

with open(dst, "w") as f:
    json.dump(parsed, f, indent=2)
    f.write("\n")
PY

chmod 600 "$OUT"
echo "[render-plan] wrote $OUT (mode 600 — it carries private keys)"
