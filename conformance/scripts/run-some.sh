#!/usr/bin/env bash
# run-some.sh — create one plan and run only the modules named on the command
# line.
#
# `run-plan.sh` runs every module of a plan, which is the right tool for
# producing evidence and the wrong one for iterating: a FAPI 2.0 plan is dozens
# of modules and the better part of an hour, and several of them deliberately
# sleep out a 60-second window. When the question is "did this change fix the
# two modules it was meant to, and break none of the four it could have", that
# is six modules and about ten minutes.
#
# The suite's API takes a module name per run, so the plan is created once and
# only the named modules are started in it. Everything else — the plan
# templating, the variant, the credentials — is `run-plan.sh`'s, unchanged, so a
# targeted run and a full sweep cannot disagree about what was under test.
#
# The browser driver must already be running (`just conformance-drive`), exactly
# as for a full sweep.
#
# Usage:
#   conformance/scripts/run-some.sh <plan-template.json> <plan-name> <module>...
#
# Example:
#   conformance/scripts/run-some.sh \
#     conformance/plans/fapi2-security-profile-final-mtls.json \
#     fapi2-security-profile-final-test-plan \
#     fapi2-security-profile-final-happy-flow \
#     fapi2-security-profile-final-par-attempt-reuse-request_uri
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS="$(cd "$(dirname "$0")" && pwd)"
PLAN_TEMPLATE="${1:?usage: run-some.sh <plan-template.json> <plan-name> <module>...}"
PLAN_NAME="${2:?plan name, e.g. fapi2-security-profile-final-test-plan}"
shift 2
[ "$#" -gt 0 ] || { echo "[run-some] name at least one module" >&2; exit 1; }

# shellcheck source=conformance/scripts/lib-env.sh
# shellcheck disable=SC1091
. "$SCRIPTS/lib-env.sh"
conf_load

BASE="${SUITE_BASE_URL:-https://localhost.emobix.co.uk:8442}"
OUT="${RUN_SOME_OUT:-$HERE/.run/some}"
mkdir -p "$OUT"

# `-k` is scoped to the harness's own loopback conversation with the suite, for
# the reason run-plan.sh gives: the suite's certificate is upstream's, and the
# TLS under test is the suite verifying AXIAM, which is a different process.
CURL=(curl -sS -k)

RENDERED="$HERE/.run/$(basename "$PLAN_TEMPLATE")"
bash "$SCRIPTS/render-plan.sh" "$PLAN_TEMPLATE" "$RENDERED" >/dev/null

VARIANT=$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])).get("variant", {})))' "$RENDERED")
PLAN_RESP=$("${CURL[@]}" -X POST \
  "$BASE/api/plan?planName=$PLAN_NAME&variant=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$VARIANT")" \
  -H "Content-Type: application/json" --data-binary "@$RENDERED")
PLAN_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("id",""))' <<<"$PLAN_RESP" 2>/dev/null || true)
if [ -z "$PLAN_ID" ]; then
  echo "[run-some] the suite would not create the plan. Response:" >&2
  echo "$PLAN_RESP" >&2
  exit 1
fi
echo "[run-some] plan $PLAN_ID ($PLAN_NAME)"
echo "[run-some] follow along at $BASE/plan-detail.html?plan=$PLAN_ID"

FAILED=0
for module in "$@"; do
  printf '[run-some] %s ... ' "$module"
  TEST_ID=$("${CURL[@]}" -X POST "$BASE/api/runner?test=$module&plan=$PLAN_ID" \
    -H 'Content-Type: application/json' \
    | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("id",""))' 2>/dev/null || true)
  if [ -z "$TEST_ID" ]; then
    echo "COULD NOT START"
    FAILED=1
    continue
  fi

  # The same generous cap run-plan.sh uses, and for the same two reasons: an
  # interactive module sits in WAITING until the browser driver acts, and
  # several modules deliberately wait out the 60-second PAR window.
  deadline=$(( $(date +%s) + ${CONFORMANCE_MODULE_TIMEOUT:-300} ))
  status=""; result=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    INFO=$("${CURL[@]}" "$BASE/api/info/$TEST_ID" 2>/dev/null || echo '{}')
    read -r status result <<<"$(python3 -c 'import json,sys
d = json.loads(sys.stdin.read() or "{}")
print(d.get("status", ""), d.get("result", ""))' <<<"$INFO" 2>/dev/null || echo " ")"
    case "$status" in FINISHED|INTERRUPTED) break ;; esac
    sleep 2
  done

  echo "${status:-TIMED_OUT} / ${result:-<none>}   (testId=$TEST_ID)"
  # The full log, because the UI truncates a condition's text and the full text
  # is where a REVIEW says what evidence it actually wants.
  "${CURL[@]}" "$BASE/api/log/$TEST_ID" > "$OUT/$module.$TEST_ID.log.json" || true
  case "$result" in PASSED) ;; *) FAILED=1 ;; esac
done

echo "[run-some] logs under $OUT"
exit "$FAILED"
