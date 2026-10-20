#!/usr/bin/env bash
# validate_inputs_test.sh — the numeric knobs of the conformance scripts are
# refused, not evaluated, when they are not digits (R101W4-02).
#
# Run:  bash conformance/scripts/tests/validate_inputs_test.sh
#
# The class under test: `$(( $(date +%s) + ${CONFORMANCE_MODULE_TIMEOUT} ))`
# parses the value as an arithmetic expression, and an array subscript in one is
# expanded first, so `a[$(cmd)]` runs `cmd`. `module_timeout` is a workflow
# dispatch input, so that was command execution for anyone who may dispatch.
#
# Two things are asserted for every bad value, because "it was refused" alone
# does not show the payload did not run first:
#   1. the exit status is 2 and stderr is exactly ONE line, the refusal;
#   2. the payload had no effect: a canary file it would create does not exist,
#      and no stderr line is the bare word INJECTED that `echo INJECTED >&2`
#      would print. (The refusal itself quotes the offending value with %q, so
#      the word INJECTED appears INSIDE that line, escaped and inert. What must
#      never appear is a line that is only the word.)
#
# The helper is exercised directly, and so are the two real scripts, so a script
# that stopped calling the helper (or called it after the arithmetic) fails here.
# SC2015: `[ ... ] && ok || fail` is deliberate; ok() cannot fail. SC2119/2120: run_plan
# forwards nothing on purpose. SC2016: the payloads are single-quoted so they stay inert.
# shellcheck disable=SC2015,SC2016,SC2119,SC2120
set -u

HERE_TEST="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE_TEST/.." && pwd)"
CONF_DIR="$(cd "$SCRIPTS/.." && pwd)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
CANARY="$WORK/canary"

fails=0
checks=0
fail() { fails=$((fails + 1)); printf 'FAIL: %s\n' "$*"; }
ok()   { checks=$((checks + 1)); }

# Values that must be refused. Each of the command-bearing ones would create the
# canary (or print INJECTED) if it were ever evaluated.
bad_values=(
  'a[$(echo INJECTED >&2)]'
  "a[\$(touch $CANARY)]"
  "\$(touch $CANARY)"
  "\`touch $CANARY\`"
  "1;touch $CANARY"
  '1+1'
  '-5'
  '5 '
  ' 5'
  '0x10'
  '1e3'
  '1.5'
  '123456'
  'abc'
  $'5\nBASH_ENV=/x'
  $'5\n::error::forged'
)

# --- the helper -------------------------------------------------------------
HERE="$CONF_DIR"
# shellcheck source=conformance/scripts/lib-env.sh
. "$SCRIPTS/lib-env.sh"

for v in "${bad_values[@]}"; do
  rm -f "$CANARY"
  err="$(conf_require_uint TEST_KNOB "$v" 2>&1 >/dev/null)"; rc=$?
  label="helper refuses $(printf '%q' "$v")"
  [ "$rc" -eq 2 ] && ok || fail "$label: exit status $rc, want 2"
  [ -e "$CANARY" ] && fail "$label: the payload ran (canary created)" || ok
  if printf '%s\n' "$err" | grep -qx 'INJECTED'; then fail "$label: INJECTED printed by the payload"; else ok; fi
  [ "$(printf '%s\n' "$err" | wc -l)" -eq 1 ] && ok || fail "$label: stderr is not exactly one line: $err"
done

# An empty value is refused by the helper (the scripts pass their default for an
# unset one, so this is the helper's own contract).
conf_require_uint TEST_KNOB '' 2>/dev/null; rc=$?
[ "$rc" -eq 2 ] && ok || fail "helper refuses the empty string: exit status $rc"

for v in 1 5 30 180 300 00180 99999; do
  err="$(conf_require_uint TEST_KNOB "$v" 2>&1)"; rc=$?
  [ "$rc" -eq 0 ] && [ -z "$err" ] && ok || fail "helper accepts $v: exit $rc, stderr '$err'"
done

# --- the real scripts -------------------------------------------------------
# Neither gets as far as the network when the value is bad, which is the point:
# the check comes before everything else. run-plan.sh needs its two positional
# arguments to get past `${1:?}`; run-some.sh needs three.
run_plan()  { bash "$SCRIPTS/run-plan.sh" "$WORK/plan.json" some-plan-name "$WORK/out" "$@"; }
run_some()  { bash "$SCRIPTS/run-some.sh" "$WORK/plan.json" some-plan-name some-module; }

for v in "${bad_values[@]}"; do
  for script in run_plan run_some; do
    rm -f "$CANARY"
    err="$(CONFORMANCE_MODULE_TIMEOUT="$v" "$script" 2>&1 >/dev/null)"; rc=$?
    label="$script refuses CONFORMANCE_MODULE_TIMEOUT=$(printf '%q' "$v")"
    [ "$rc" -eq 2 ] && ok || fail "$label: exit status $rc, want 2"
    [ -e "$CANARY" ] && fail "$label: the payload ran (canary created)" || ok
    if printf '%s\n' "$err" | grep -qx 'INJECTED'; then fail "$label: INJECTED printed by the payload"; else ok; fi
    [ "$(printf '%s\n' "$err" | wc -l)" -eq 1 ] && ok || fail "$label: stderr is not exactly one line: $err"
  done
done

# run-plan.sh has a second knob that reaches the same arithmetic.
for v in "${bad_values[@]}"; do
  rm -f "$CANARY"
  err="$(CONFORMANCE_SUITE_WAIT="$v" run_plan 2>&1 >/dev/null)"; rc=$?
  label="run_plan refuses CONFORMANCE_SUITE_WAIT=$(printf '%q' "$v")"
  [ "$rc" -eq 2 ] && ok || fail "$label: exit status $rc, want 2"
  [ -e "$CANARY" ] && fail "$label: the payload ran (canary created)" || ok
  if printf '%s\n' "$err" | grep -qx 'INJECTED'; then fail "$label: INJECTED printed by the payload"; else ok; fi
  [ "$(printf '%s\n' "$err" | wc -l)" -eq 1 ] && ok || fail "$label: stderr is not exactly one line: $err"
done

# Good values get PAST the check. They go on to fail for other reasons (there is
# no suite here), so what is asserted is that the refusal is absent and, for
# run-plan.sh, that it reached the suite-wait and gave up there with status 1.
for v in 1 30 180 00180; do
  err="$(CONFORMANCE_MODULE_TIMEOUT="$v" CONFORMANCE_SUITE_WAIT=0 \
         SUITE_BASE_URL=https://127.0.0.1:1 run_plan 2>&1 >/dev/null)"; rc=$?
  label="run_plan accepts CONFORMANCE_MODULE_TIMEOUT=$v"
  [ "$rc" -eq 1 ] && ok || fail "$label: exit status $rc, want 1 (suite not answering)"
  case "$err" in *"must be a whole number"*) fail "$label: refused: $err" ;; *) ok ;; esac
  case "$err" in *"is not answering"*) ok ;; *) fail "$label: did not reach the suite wait: $err" ;; esac

  err="$(CONFORMANCE_MODULE_TIMEOUT="$v" SUITE_BASE_URL=https://127.0.0.1:1 \
         run_some 2>&1 >/dev/null)"
  label="run_some accepts CONFORMANCE_MODULE_TIMEOUT=$v"
  case "$err" in *"must be a whole number"*) fail "$label: refused: $err" ;; *) ok ;; esac
done

# Unset means the default, and the default is a number.
err="$(env -u CONFORMANCE_MODULE_TIMEOUT -u CONFORMANCE_SUITE_WAIT \
       CONFORMANCE_SUITE_WAIT=0 SUITE_BASE_URL=https://127.0.0.1:1 \
       bash "$SCRIPTS/run-plan.sh" "$WORK/plan.json" some-plan-name "$WORK/out" 2>&1 >/dev/null)"; rc=$?
[ "$rc" -eq 1 ] && ok || fail "run_plan with the knob unset: exit status $rc, want 1"

# --- the workflow's own patterns (R110W4-05) ----------------------------------
# The dispatch step carries its own copies of the two patterns; grep the YAML so
# they cannot drift from the helper's, and check that a refused input stops the
# steps that need the workspace (otherwise they run on an empty one and the gate
# step goes red beside the refusal).
WF="$(cd "$CONF_DIR/.." && pwd)/.github/workflows/fapi-conformance.yml"
if [ -f "$WF" ]; then
  grep -qxF "          plan_re='^[a-z0-9-]{1,128}\$'" "$WF" && ok || fail "workflow plan_re is not ^[a-z0-9-]{1,128}\$"
  grep -qxF "          timeout_re='^[0-9]{1,5}\$'" "$WF" && ok || fail "workflow timeout_re is not ^[0-9]{1,5}\$"
  grep -qF "local re='^[0-9]{1,5}\$'" "$SCRIPTS/lib-env.sh" && ok || fail "lib-env.sh no longer uses ^[0-9]{1,5}\$ (workflow copy would drift)"
  grep -qxF "        id: inputs" "$WF" && ok || fail "the validation step has no 'id: inputs'"
  guarded="$(grep -cF "steps.inputs.outcome == 'success'" "$WF")"
  [ "$guarded" -eq 5 ] && ok || fail "want 5 steps guarded by steps.inputs.outcome == 'success', found $guarded"
  bare="$(grep -cx '        if: always()' "$WF")"
  [ "$bare" -eq 0 ] && ok || fail "$bare step(s) still use a bare 'if: always()'"
else
  fail "workflow file not found: $WF"
fi

printf '%d checks, %d failed\n' "$((checks + fails))" "$fails"
[ "$fails" -eq 0 ]
