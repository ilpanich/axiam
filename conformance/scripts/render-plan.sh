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
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPTS_DIR/lib-env.sh"
conf_load

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

# W9. Which values a plan needs is a property of THAT PLAN, not of the harness.
#
# This block used to read five PEM files and demand three client ids for every
# template, because every template was a FAPI one. The Basic OP plan has no
# certificates at all and different client ids, so an unconditional list makes
# it unrenderable — and the error it produced ("run 'just conformance-certs'")
# pointed at a step that would not have helped.
#
# So: scan the template for the placeholders it actually contains, and require
# only those. A plan that needs a PEM still fails loudly when the PEM is
# missing; a plan that does not, no longer fails for a file it never mentions.
# `_comment` is stripped BEFORE scanning. Every template opens with an essay
# that contains the words "Placeholders of the form ${NAME}", and a naive scan
# of the raw file dutifully demands a variable called NAME — a requirement
# invented by the documentation describing the requirements.
# `_comment` is stripped BEFORE scanning, and stripped TEXTUALLY.
#
# Two reasons, both learned the hard way. Every template opens with an essay
# containing the words "Placeholders of the form ${NAME}", and a naive scan of
# the raw file dutifully demands a variable called NAME — a requirement
# invented by the documentation describing the requirements. And the strip
# cannot go through a JSON parser, because a template is not valid JSON until
# it is rendered: the private_key_jwt one substitutes an entire JWKS object
# through an unquoted placeholder.
NEEDED=$(python3 -c '
import re, sys
raw = open(sys.argv[1]).read()
raw = re.sub(r"\"_comment\"\s*:\s*\[.*?\]\s*,", "", raw, flags=re.S)
print("\n".join(sorted(set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*)\}", raw)))))
' "$PLAN")

needs() { printf '%s\n' "$NEEDED" | grep -qx "$1"; }

# PEM placeholders are named <VAR>_PEM and are filled from the file named by
# <VAR> in the config, so the template says what it wants and suite.env says
# where it lives.
PEM_VARS=""
for v in $NEEDED; do
  case "$v" in
    *_PEM)
      src_var="${v%_PEM}"
      # AXIAM_CA_PEM comes from AXIAM_CA, whose default is the harness CA.
      path="${!src_var:-}"
      if [ -z "$path" ] && [ "$src_var" = "AXIAM_CA" ]; then path="certs/ca.crt"; fi
      if [ -z "$path" ]; then
        echo "[render-plan] $PLAN wants \${$v}, but $src_var is empty in suite.env" >&2
        exit 1
      fi
      printf -v "$v" '%s' "$(read_pem "$path" "$src_var")"
      export "${v?}"
      PEM_VARS="$PEM_VARS $v"
      ;;
  esac
done

for required in $NEEDED; do
  case "$required" in *_PEM) continue ;; esac
  if [ -z "${!required:-}" ]; then
    echo "[render-plan] $required is empty in suite.env / suite.local.env (needed by $(basename "$PLAN"))." >&2
    echo "[render-plan] run the matching registrar — 'just conformance-register' for the" >&2
    echo "[render-plan] FAPI plans, 'just conformance-register-basic' for the Basic OP plan —" >&2
    echo "[render-plan] or fill it in by hand if the client already exists." >&2
    exit 1
  fi
done

export CONFORMANCE_PEM_VARS="$PEM_VARS"

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
# W9: discovered from the template rather than hard-coded, for the same reason
# the shell half was — a new plan with a new PEM would otherwise render its
# certificate as a double-quoted string and fail as invalid JSON forty lines
# deep, which is a bad way to learn about a missing entry in a set literal.
pem_vars = set(os.environ.get("CONFORMANCE_PEM_VARS", "").split())

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
