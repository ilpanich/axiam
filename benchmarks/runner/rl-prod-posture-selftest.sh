#!/usr/bin/env bash
# `rl=prod` must pin EVERY rate-limit family the compose file neutralizes
# (T23.10.2(a)).
#
# targets/axiam/docker-compose.yml raises each REST family to 1 000 000 by default
# (the `rl=neutralized` posture), and `just rl=prod bench-up` is supposed to put the
# shipped values back. It pins nine by hand; the seven REST families added after
# alpha24 (device_authorization, token_exchange, uma_perm, uma_ticket, par,
# end_session, scim) are pinned from the Rust source by `rl_prod_check.py
# --print-exports`. A family that is in the compose file and in neither list keeps
# its 1 000 000 under `rl=prod`, while `rl-prod-check` compares what it admitted
# against the SHIPPED limit — a FAIL for a posture the harness never applied, which
# reads as a limiter bug. The same hole existed once before (the "seventeenth
# family" note in the compose file). This pins the invariant instead of the list:
#
#   every AXIAM__RATE_LIMIT__*_PER_MIN the compose file neutralizes is exported by
#   the rl=prod branch of the justfile or printed by `--print-exports`; and nothing
#   is exported that the compose file does not forward (a typo would pin nothing).
#
# Hermetic: no docker, no k6. Usage: rl-prod-posture-selftest.sh   (from benchmarks/)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
fail=0
say() { echo "[rl-prod-posture-selftest] $*" >&2; fail=1; }

compose="$(sed 's/^[[:space:]]*#.*$//' "$BENCH/targets/axiam/docker-compose.yml" \
            | grep -oE '^[[:space:]]+AXIAM__RATE_LIMIT__[A-Z_]+_PER_MIN:' | grep -oE 'AXIAM__RATE_LIMIT__[A-Z_]+_PER_MIN' | sort -u)"
# the rl=prod branch of bench-up: from `if [ "{{rl}}" = "prod" ]` to its `elif`
branch="$(awk '/if \[ "\{\{rl\}\}" = "prod" \]; then/{f=1} /elif \[ "\{\{rl\}\}" != "neutralized" \]/{f=0} f' "$BENCH/justfile")"
by_hand="$(printf '%s\n' "$branch" | grep -oE '^\s*export (AXIAM__RATE_LIMIT__[A-Z_]+_PER_MIN)=' | grep -oE 'AXIAM__RATE_LIMIT__[A-Z_]+_PER_MIN' | sort -u)"
printed="$(python3 -I "$HERE/rl_prod_check.py" --print-exports | grep -oE 'AXIAM__RATE_LIMIT__[A-Z_]+_PER_MIN' | sort -u)"
echo "$branch" | grep -q 'rl_prod_check.py --print-exports' \
  || say "the rl=prod branch of the justfile no longer evals rl_prod_check.py --print-exports"
pinned="$(printf '%s\n%s\n' "$by_hand" "$printed" | sort -u)"

[ -n "$compose" ] && [ -n "$by_hand" ] && [ -n "$printed" ] \
  || say "could not extract one of the three lists (compose: $(echo "$compose" | wc -l), by hand: $(echo "$by_hand" | wc -l), printed: $(echo "$printed" | wc -l))"

missed="$(comm -23 <(echo "$compose") <(echo "$pinned"))"
if [ -n "$missed" ]; then
  say "rl=prod does not pin these neutralized families (they would keep 1 000 000 under the 'shipped' posture):"
  printf '    %s\n' $missed >&2
fi
typo="$(comm -13 <(echo "$compose") <(echo "$pinned"))"
if [ -n "$typo" ]; then
  say "rl=prod exports these, but the compose file does not forward them (they pin nothing):"
  printf '    %s\n' $typo >&2
fi
# every printed value is a positive integer
while read -r line; do
  [[ "$line" =~ ^export\ AXIAM__RATE_LIMIT__[A-Z_]+_PER_MIN=[1-9][0-9]*$ ]] || say "malformed --print-exports line: $line"
done < <(python3 -I "$HERE/rl_prod_check.py" --print-exports)

# P23W6-02: the pin fails CLOSED. rl_prod_check.py raises when the Rust source moves,
# but `eval "$(python3 … --print-exports)"` discards the substitution's status, so
# bench-up carried on with the seven families still neutralized under a pass labelled
# `rl=prod` — the very posture the pin exists to make true. Run the justfile's own pin
# code (between its `rl-prod-pin` markers, or the line naming --print-exports) under
# bench-up's `set -euo pipefail`, against a python3 that fails and one that prints
# nothing: each must stop the shell.
pin="$(printf '%s\n' "$branch" | awk '/# rl-prod-pin: begin/{f=1;next} /# rl-prod-pin: end/{f=0} f')"
[ -n "$pin" ] || pin="$(printf '%s\n' "$branch" | grep -F -- '--print-exports')"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/fail" "$T/empty"
printf '#!/usr/bin/env bash\necho "Traceback: could not find scim_per_min" >&2\nexit 1\n' > "$T/fail/python3"
printf '#!/usr/bin/env bash\nexit 0\n' > "$T/empty/python3"
chmod +x "$T/fail/python3" "$T/empty/python3"
for stub in fail empty; do
  if PATH="$T/$stub:$PATH" bash -c "set -euo pipefail; cd '$BENCH'; $pin
echo REACHED" 2>/dev/null | grep -q REACHED; then
    say "rl=prod's source pin fails OPEN: with a python3 that $([ "$stub" = fail ] && echo exits non-zero || echo prints no export), bench-up carries on with the families unpinned"
  fi
done
# ... and with the real script it pins exactly what --print-exports prints
got="$(bash -c "set -euo pipefail; cd '$BENCH'; $pin
env" | grep -oE '^AXIAM__RATE_LIMIT__[A-Z_]+_PER_MIN' | sort -u)"
[ "$got" = "$printed" ] || say "the justfile's pin code does not export what --print-exports prints"

[ "$fail" -eq 0 ] || { echo "[rl-prod-posture-selftest] FAILED" >&2; exit 1; }
echo "[rl-prod-posture-selftest] OK — every rate-limit family the compose file neutralizes is pinned by rl=prod ($(echo "$compose" | wc -l) families: $(echo "$by_hand" | wc -l) by hand, $(echo "$printed" | wc -l) from source)."
