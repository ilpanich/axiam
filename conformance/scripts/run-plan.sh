#!/usr/bin/env bash
# run-plan.sh — drive one FAPI 2.0 test plan through the OIDF suite's API and
# collect its result (X5.2).
#
# The suite is normally driven from its web UI. This script uses the same HTTP
# API the UI does, because a run that can only be reproduced by clicking is not
# evidence anybody else can regenerate — and regenerating it is the entire
# argument of §X5.3's digest-pinned submission.
#
# What it does NOT do is decide whether the result is good. It records what the
# suite said, including failures, and exits non-zero when any test did not pass.
# Interpreting a failure is `conformance-report`'s job and the runbook's.
#
# Usage: run-plan.sh <rendered-plan.json> <plan-name> [output-dir]
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
PLAN_CONFIG="${1:?usage: run-plan.sh <rendered-plan.json> <plan-name> [output-dir]}"
PLAN_NAME="${2:?plan name, e.g. fapi2-security-profile-final-test-plan}"
OUT_DIR="${3:-$HERE/.run/results}"

# shellcheck disable=SC1091
set -a; . "$HERE/suite.env"; set +a

BASE="${SUITE_BASE_URL:-https://localhost.emobix.co.uk:8442}"
mkdir -p "$OUT_DIR"

# The suite serves a certificate for localhost.emobix.co.uk that a normal trust
# store does accept, but a local build or a mirrored image may not — and the
# thing under test is AXIAM, not the suite's own TLS. `-k` here is scoped to the
# harness's loopback conversation with the suite and never to AXIAM: the suite's
# own connections to AXIAM verify normally, which is what the tests are for.
CURL=(curl -sS -k)

echo "[run-plan] suite: $BASE"
echo "[run-plan] plan:  $PLAN_NAME"
echo "[run-plan] config: $PLAN_CONFIG"

if ! "${CURL[@]}" --max-time 10 "$BASE/api/runner/available" >/dev/null 2>&1; then
  echo "[run-plan] the suite is not answering at $BASE" >&2
  echo "[run-plan] run 'just conformance-up' first (it takes ~60s to become ready)" >&2
  exit 1
fi

# --- create the plan ------------------------------------------------------
#
# The variant lives INSIDE the config file (its "variant" object), and the
# suite also accepts it as a query parameter. Sending it in one place only —
# the file — means the committed template is the single source of truth for
# which variant a given plan config represents, so a plan cannot be run under a
# variant its own comments contradict.
VARIANT=$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])).get("variant", {})))' "$PLAN_CONFIG")

PLAN_RESP=$("${CURL[@]}" -X POST \
  "$BASE/api/plan?planName=$PLAN_NAME&variant=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$VARIANT")" \
  -H "Content-Type: application/json" \
  --data-binary "@$PLAN_CONFIG")

PLAN_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("id",""))' <<<"$PLAN_RESP" 2>/dev/null || true)
if [ -z "$PLAN_ID" ]; then
  echo "[run-plan] the suite would not create the plan. Response:" >&2
  echo "$PLAN_RESP" >&2
  exit 1
fi
echo "[run-plan] plan id: $PLAN_ID"
echo "[run-plan] follow along at $BASE/plan-detail.html?plan=$PLAN_ID"

# --- run every module in the plan ----------------------------------------
#
# A FAPI 2.0 OP plan is dozens of modules. Several are interactive by
# construction (they need a browser to complete an authorization), and those
# CANNOT be driven from here — the suite marks them WARNING/REVIEW and a human
# finishes them in the UI. That is a property of the profile, not a gap in this
# script, and the runbook explains which ones and why.
MODULES=$("${CURL[@]}" "$BASE/api/plan/$PLAN_ID" \
  | python3 -c 'import json,sys; print("\n".join(m["testModule"] for m in json.load(sys.stdin).get("modules", [])))')

MODULE_COUNT=$(printf '%s\n' "$MODULES" | grep -c . || true)
echo "[run-plan] $MODULE_COUNT modules in this plan"

RESULTS_JSON="$OUT_DIR/$(basename "$PLAN_CONFIG" .json).results.json"
: > "$RESULTS_JSON.tmp"

i=0
while IFS= read -r module; do
  [ -n "$module" ] || continue
  i=$((i + 1))
  printf '[run-plan] (%d/%d) %s ... ' "$i" "$MODULE_COUNT" "$module"

  TEST_RESP=$("${CURL[@]}" -X POST \
    "$BASE/api/runner?test=$module&plan=$PLAN_ID" -H "Content-Type: application/json")
  TEST_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("id",""))' <<<"$TEST_RESP" 2>/dev/null || true)
  if [ -z "$TEST_ID" ]; then
    echo "COULD NOT START"
    printf '{"module":"%s","status":"COULD_NOT_START"}\n' "$module" >> "$RESULTS_JSON.tmp"
    continue
  fi

  # Poll to completion. The cap is generous because an interactive module sits
  # in WAITING until a human acts; `conformance-report` reports what was still
  # waiting rather than this loop pretending it finished.
  deadline=$(( $(date +%s) + ${CONFORMANCE_MODULE_TIMEOUT:-180} ))
  status=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    INFO=$("${CURL[@]}" "$BASE/api/info/$TEST_ID" 2>/dev/null || echo '{}')
    status=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read() or "{}").get("status",""))' <<<"$INFO" 2>/dev/null || true)
    case "$status" in
      FINISHED|INTERRUPTED) break ;;
    esac
    sleep 2
  done

  RESULT=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read() or "{}").get("result",""))' <<<"$INFO" 2>/dev/null || true)
  echo "${RESULT:-${status:-TIMEOUT}}"
  python3 - "$module" "$TEST_ID" "${status:-TIMEOUT}" "${RESULT:-}" >> "$RESULTS_JSON.tmp" <<'PY'
import json, sys
print(json.dumps({
    "module": sys.argv[1],
    "testId": sys.argv[2],
    "status": sys.argv[3],
    "result": sys.argv[4],
}))
PY
done <<<"$MODULES"

python3 - "$RESULTS_JSON.tmp" "$RESULTS_JSON" "$PLAN_ID" "$PLAN_NAME" <<'PY'
import json, sys
src, dst, plan_id, plan_name = sys.argv[1:5]
modules = [json.loads(line) for line in open(src) if line.strip()]
json.dump({"planId": plan_id, "planName": plan_name, "modules": modules},
          open(dst, "w"), indent=2)
PY
rm -f "$RESULTS_JSON.tmp"
echo "[run-plan] wrote $RESULTS_JSON"

# Exit non-zero if anything did not pass. A harness that exits 0 on a red plan
# is a harness that gets wired into CI and then silently stops meaning anything.
FAILED=$(python3 -c '
import json,sys
d = json.load(open(sys.argv[1]))
bad = [m for m in d["modules"] if m.get("result") not in ("PASSED", "SKIPPED")]
print(len(bad))
' "$RESULTS_JSON")
if [ "$FAILED" != "0" ]; then
  echo "[run-plan] $FAILED module(s) did not pass — see 'just conformance-report'" >&2
  exit 2
fi
echo "[run-plan] all modules passed"
