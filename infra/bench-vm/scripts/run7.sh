#!/usr/bin/env bash
# shellcheck disable=SC2030,SC2031  # pass bodies run in subshells on purpose: caps, cache posture and results dir must not leak between passes
# run7.sh — benchmark run 7, end to end and unattended, on a VM booted from the
# provisioned snapshot. Start it in tmux and leave it:
#
#     tmux new -s bench
#     ~/bench-vm/scripts/run7.sh
#
# What run 7 measures (claude_dev/bench-vm-runbook.md §15): AXIAM 1.4.0 — the
# query optimisations (one round trip per authorization check, merged token and
# userinfo reads, batched audit writes), the read caches now on by default, and
# the 1.4.0 fixes — against the SAME competitor and SurrealDB images runs 6–6c
# measured, pinned by digest (run7-pins.env).
#
# The passes, in order (each writes its own results tree; none is medianed with
# another):
#
#   setup        archive any older results, check out (03), verify (04), qualify (05)
#   preflight    certificates, pinned image pulls, provenance, the steal log
#   dryrun       gate: the CORE comparison cells at p0/p2/p3, all four targets;
#                then oauth2_refresh_grant on its own (dropped, not fatal, on FAIL);
#                then the SDK rehearsal (the SDK pass is skipped, not fatal, on FAIL)
#   resting      memory at rest, four stacks, fresh and with the fixture
#   matrix       THE RUN OF RECORD: 4 targets x p0/p2/p3, caps 2/2, shipped caches,
#                median of REPEAT                                   -> results/run-*
#   strict-2x2   AXIAM with its read caches OFF (caches=strict), p0, 2/2
#                                       -> results/run7/axiam-strict-caps-2x2
#   caps-4x4     4 targets, p0, every server and database at 4 CPU, shipped caches
#                                       -> results/run7/caps-4x4
#   strict-4x4   AXIAM caches=strict, p0, 4/4
#                                       -> results/run7/axiam-strict-caps-4x4
#   sdk          the eleven SDKs, p0, median of REPEAT, shipped caches -> results/sdk
#   ws-2x2       AXIAM on the opt-in WebSocket datastore engine, p0, 2/2
#                                       -> results/run7/axiam-ws-caps-2x2
#   zitadel-on   Zitadel with its optional object caches ON (caches=on), p0, 2/2
#                                       -> results/run7/zitadel-caches-on-caps-2x2
#   surreal335   AXIAM 1.4.0 on a SurrealDB 3.3.5 server (unsupported,
#                benchmark-only), p0, 2/2 and 4/4, gated by its own dry run
#                                       -> results/run7/axiam-surreal-3.3.5-caps-{2x2,4x4}
#   close        stop the steal log, provenance, report, pack, RUN-NOTES.md
#
# Every pass leaves results-<date>.tar.xz up to date, so `./run.sh fetch` from your
# PC returns everything finished so far at any moment.
#
# Restart-safe: a finished pass is recorded in ~/bench/run7/state and skipped on the
# next start; a pass interrupted half-way is moved aside (results/run7/_aborted/)
# and run again from its start. Optional passes whose own dry run fails are
# SKIPPED with the reason recorded, and the run carries on. Only the setup checks
# and the CORE dry run stop the whole run: without them there is no comparison.
#
# Usage:
#   run7.sh                 every pass not yet done
#   run7.sh --list          the passes, their state and a duration estimate; no run
#   run7.sh --redo PASS     forget PASS's state and run it again (and what follows)
#
# Environment:
#   PASSES="matrix sdk ..."  run only these (setup, preflight and close always run)
#   REPEAT=3                 median-of-N for the matrix and SDK passes
#   AXIAM_TAG=v1.4.0         the release; AXIAM_REF=origin/main the harness checkout
#   RUN7_ALLOW_NO_TMUX=1     run outside tmux (not recommended: an SSH drop kills it)
#
# Before starting, by hand and only once per VM (never scripted, runbook §4):
#   docker login ghcr.io; docker login        and, if the repositories are private,
#   gh auth login                             (read access for 03-checkouts.sh)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"
export AXIAM_TAG="${AXIAM_TAG:-v1.4.0}"
export AXIAM_REF="${AXIAM_REF:-origin/main}"
# shellcheck source=versions.env
source "$HERE/versions.env"

AX="$BENCH_DIR/axiam"
BM="$AX/benchmarks"
ROUND="$BENCH_DIR/run7"
STATE="$ROUND/state"
LOGS="$BENCH_DIR/logs/run7"
REPEAT="${REPEAT:-3}"
mkdir -p "$STATE" "$LOGS"

ALL_PASSES="setup preflight dryrun resting matrix strict-2x2 caps-4x4 strict-4x4 sdk ws-2x2 zitadel-on surreal335 close"
OPTIONAL_PASSES="strict-2x2 caps-4x4 strict-4x4 sdk ws-2x2 zitadel-on surreal335"

# The CORE comparison set of runs 6–6c, plus the like-for-like OAuth2 refresh
# grant (added after run 6c; dropped from every pass if its own dry run fails).
CORE="jwks_fetch.js oauth2_client_credentials.js oauth2_password_login.js token_introspection.js token_refresh.js userinfo.js zitadel_userinfo_grpc.js userinfo_grpc.js authz_check_rest.js authz_check_grpc.js authz_batch_rest.js authz_batch_grpc.js"
NEW_CELL="oauth2_refresh_grant.js"
TARGETS_ALL="axiam keycloak zitadel authentik"
PROFILES_ALL="p0-plaintext p2-tls13 p3-mtls"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
ts() { date -u +%FT%TZ; }
log_main="$LOGS/run7.log"
note() { printf '[%s] %s\n' "$(ts)" "$*" | tee -a "$log_main"; }
done_mark() { printf '%s\n' "$(ts)" > "$STATE/$1.done"; rm -f "$STATE/$1.running"; note "PASS $1: done"; }
skip_mark() { printf '%s %s\n' "$(ts)" "$2" > "$STATE/$1.skipped"; rm -f "$STATE/$1.running"; note "PASS $1: SKIPPED — $2"; }
is_settled() { [[ -f "$STATE/$1.done" || -f "$STATE/$1.skipped" ]]; }
fatal() { note "FATAL: $*"; note "Fix the cause, then start run7.sh again: finished passes are kept."; exit 1; }

# run_logged NAME cmd... — the command's own exit status, never tee's.
run_logged() {
    local name="$1"; shift
    note "  \$ $*"
    { "$@"; } 2>&1 | tee -a "$LOGS/$name.log"
    return "${PIPESTATUS[0]}"
}

core_set() {
    if [[ -f "$STATE/new-cell.dropped" ]]; then echo "$CORE"; else echo "$CORE $NEW_CELL"; fi
}

# The pinned images: always re-sourced, so a restart pins the shell again.
load_pins() {
    # shellcheck source=run7-pins.env
    source "$HERE/run7-pins.env"
    if [[ -f "$BM/results/provenance/pinned-images.sh" ]]; then
        # shellcheck disable=SC1091
        source "$BM/results/provenance/pinned-images.sh"
    fi
}

steal_log_on() {
    mkdir -p "$BM/results/provenance"
    if ! pgrep -f 'vmstat -n -t 10' >/dev/null; then
        nohup vmstat -n -t 10 >> "$BM/results/provenance/vmstat-steal.txt" 2>/dev/null &
        note "steal log running (results/provenance/vmstat-steal.txt)"
    fi
}

no_caps() { unset BENCH_CPUS BENCH_MEM BENCH_DB_CPUS BENCH_DB_MEM BENCH_AUTHENTIK_WORKER_CPUS BENCH_AUTHENTIK_WORKER_MEM AXIAM__DB__ENGINE; }

# A pass that died half-way leaves a partial tree; never median into it.
fresh_tree() {
    local dir="$1"
    if [[ -e "$dir" ]]; then
        mkdir -p "$BM/results/run7/_aborted"
        local dest
        dest="$BM/results/run7/_aborted/$(basename "$dir")-$(date -u +%Y%m%dT%H%M%SZ)"
        mv "$dir" "$dest"
        note "  moved the partial tree aside: ${dest#"$BM"/}"
    fi
    mkdir -p "$dir"
}

pack() {
    (cd "$BM" && run_logged pack just bench-pack) || note "  (bench-pack failed; the results stay on disk)"
}

# dry NAME TARGETS PROFILES SCENARIOS [env assignments...] — a dry run into
# results/dry-run/run7-NAME; the summary is copied into the logs (dry runs are
# never packed). Returns the dry run's own status.
dry() {
    local name="$1" targets="$2" profiles="$3" scen="$4"; shift 4
    local out="$BM/results/dry-run/run7-$name" rc
    rm -rf "$out"; mkdir -p "$out"
    (
        cd "$BM" || exit 1
        no_caps
        for kv in "$@"; do export "${kv?}"; done
        export BENCH_SCENARIO_ONLY="$scen" BENCH_RESULTS_DIR="$out"
        run_logged "dryrun-$name" just targets="$targets" profiles="$profiles" \
            caches="${CACHES:-default}" bench-dry-run
    )
    rc=$?
    [[ -f "$out/SUMMARY.md" ]] && cp "$out/SUMMARY.md" "$LOGS/dryrun-$name-SUMMARY.md"
    return "$rc"
}

# matrix NAME RESULTS_DIR TARGETS PROFILES CACHES [env assignments...]
matrix() {
    local name="$1" dir="$2" targets="$3" profiles="$4" caches="$5"; shift 5
    # The run of record writes run-1..N into the results ROOT, beside provenance
    # and resting: clear only its own repeats there, never the root itself.
    if [[ "$dir" == "$BM/results" ]]; then
        local d
        for d in "$BM"/results/run-[0-9]*; do [[ -e "$d" ]] && fresh_tree "$d"; done
        rm -rf "$BM"/results/run-[0-9]*
    else
        fresh_tree "$dir"
    fi
    (
        cd "$BM" || exit 1
        no_caps
        for kv in "$@"; do export "${kv?}"; done
        BENCH_SCENARIO_ONLY="$(core_set)"
        export BENCH_SCENARIO_ONLY BENCH_RESULTS_DIR="$dir"
        run_logged "$name" just targets="$targets" profiles="$profiles" caches="$caches" \
            repeat="$REPEAT" bench-matrix
    )
}

# ---------------------------------------------------------------------------
# the passes
# ---------------------------------------------------------------------------
pass_setup() {
    # A snapshot carries the previous round's trees. Never mix them with this one.
    if [[ ! -f "$STATE/archived" && -d "$BM/results" ]] \
       && [[ -n "$(ls -A "$BM/results" 2>/dev/null)" ]]; then
        local dest
        dest="$BENCH_DIR/archive/results-before-run7-$(date -u +%Y%m%dT%H%M%SZ)"
        mkdir -p "$BENCH_DIR/archive"
        mv "$BM/results" "$dest"
        note "older results moved to ${dest} (untouched; fetch them separately if needed)"
    fi
    for f in "$BM"/results-*.tar.xz; do
        [[ -e "$f" && ! -f "$STATE/archived" ]] && mv "$f" "$BENCH_DIR/archive/"
    done
    touch "$STATE/archived"

    # Local edits left by an earlier SDK pass (go.sum, Package.resolved, the
    # retargeted csproj) would make 03-checkouts refuse; they are harness noise.
    if [[ -d "$AX/.git" ]] && ! git -C "$AX" diff --quiet; then
        git -C "$AX" diff --stat > "$LOGS/setup-discarded-local-changes.txt"
        git -C "$AX" checkout -- .
        note "discarded local edits in the axiam checkout (list: logs/run7/setup-discarded-local-changes.txt)"
    fi

    run_logged setup-checkouts "$HERE/03-checkouts.sh" || fatal "03-checkouts.sh failed (see logs/run7/setup-checkouts.log)"
    run_logged setup-verify "$HERE/04-verify.sh"
    local fails=$?
    (( fails == 0 )) || fatal "04-verify.sh reported $fails FAIL line(s): ~/bench/logs/verify.txt"
    run_logged setup-qualify "$HERE/05-qualify.sh"
    local q=$?
    case "$q" in
        0) note "qualification: PROCEED" ;;
        3) fatal "05-qualify.sh says RECREATE the VM (noisy host): ~/bench/logs/qualify.txt" ;;
        *) note "qualification: exit $q (WATCH) — continuing; read ~/bench/logs/qualify.txt into the notes" ;;
    esac
    done_mark setup
}

pass_preflight() {
    cd "$BM" || fatal "no $BM"
    run_logged preflight just bench-certs || fatal "bench-certs failed"
    # shellcheck source=run7-pins.env
    source "$HERE/run7-pins.env"
    unset BENCH_AXIAM_IMAGE
    run_logged preflight bash runner/pull-pinned-images.sh results/provenance \
        || fatal "an image could not be pulled (docker login ghcr.io / docker login?)"
    load_pins
    grep -q "server:${AXIAM_TAG#v} " results/provenance/images.txt \
        || fatal "images.txt does not show ghcr.io/ilpanich/axiam/server:${AXIAM_TAG#v}"
    grep -q "408eb8e5c9436670525e2bc2634b1e50ba74ce1b447eaf0094c35f73b67f9cb6" results/provenance/images.txt \
        || fatal "SurrealDB is not the pinned 4.0.1 digest (run7-pins.env)"
    cp results/provenance/images.txt "$LOGS/images.txt"
    run_logged preflight bash runner/record-provenance.sh || fatal "record-provenance.sh failed"
    steal_log_on
    done_mark preflight
}

pass_dryrun() {
    # 1. The gate: everything the run of record needs.
    if ! dry core "$TARGETS_ALL" "$PROFILES_ALL" "$CORE"; then
        fatal "the CORE dry run has FAILs: logs/run7/dryrun-core-SUMMARY.md. Nothing has been measured."
    fi
    # 2. The new like-for-like refresh cell: never allowed to block the round.
    if ! dry refresh-grant "axiam keycloak" "p0-plaintext" "$NEW_CELL"; then
        touch "$STATE/new-cell.dropped"
        note "oauth2_refresh_grant FAILED its dry run — dropped from every pass (logs/run7/dryrun-refresh-grant-SUMMARY.md)"
    fi
    # 3. The SDK rehearsal: builds all eleven benches now, not after a day.
    local rc=0
    (
        cd "$BM" || exit 1
        no_caps
        just target=axiam profile=p0-plaintext bench-up && just target=axiam bench-seed \
            && run_logged sdk-dryrun just target=axiam profile=p0-plaintext sdk-dry-run
        r=$?
        just target=axiam bench-down
        exit "$r"
    ) >>"$LOGS/sdk-dryrun.log" 2>&1 || rc=$?
    if (( rc != 0 )); then
        touch "$STATE/sdk.rehearsal-failed"
        note "SDK rehearsal FAILED (logs/run7/sdk-dryrun.log) — the sdk pass will be skipped"
    fi
    done_mark dryrun
}

pass_resting() {
    cd "$BM" || return 1
    (
        no_caps
        for t in keycloak zitadel authentik; do
            local s=120; [[ "$t" == authentik ]] && s=300
            just target=$t profile=p0-plaintext bench-up || exit 1
            SETTLE=$s bash runner/resting-sample.sh "$t" fresh || exit 1
            just target=$t profile=p0-plaintext bench-seed || exit 1
            SETTLE=60 bash runner/resting-sample.sh "$t" fixture || exit 1
            just target=$t bench-down
        done
        just deploy=full target=axiam profile=p0-plaintext bench-up || exit 1
        SETTLE=90 bash runner/resting-sample.sh axiam fresh || exit 1
        just target=axiam profile=p0-plaintext bench-seed || exit 1
        SETTLE=60 bash runner/resting-sample.sh axiam fixture || exit 1
        just target=axiam bench-down
    ) 2>&1 | tee -a "$LOGS/resting.log"
    local rc=${PIPESTATUS[0]}
    if (( rc != 0 )); then
        (cd "$BM" && for t in $TARGETS_ALL; do just target="$t" bench-down >/dev/null 2>&1; done)
        skip_mark resting "a stack failed during the resting samples (logs/run7/resting.log)"
        return 0
    fi
    done_mark resting
}

pass_matrix() {
    # The run of record uses the standard tree (results/run-1..N), like run 6.
    if matrix matrix "$BM/results" "$TARGETS_ALL" "$PROFILES_ALL" default; then
        (cd "$BM" && run_logged matrix just bench-report)
        done_mark matrix
    else
        fatal "the run-of-record matrix stopped (logs/run7/matrix.log). Restarting run7.sh re-runs it from repeat 1."
    fi
    pack
}

# An optional AXIAM-only pass with its own dry-run gate.
optional_axiam() {
    local pass="$1" dir="$2" caches="$3"; shift 3
    if ! CACHES="$caches" dry "$pass" axiam p0-plaintext "$(core_set)" "$@"; then
        skip_mark "$pass" "its dry run failed (logs/run7/dryrun-$pass-SUMMARY.md)"
        return 0
    fi
    if matrix "$pass" "$dir" axiam p0-plaintext "$caches" "$@"; then
        done_mark "$pass"
    else
        skip_mark "$pass" "the pass stopped (logs/run7/$pass.log); its partial tree is moved aside on a restart"
    fi
    pack
}

pass_strict_2x2() { optional_axiam strict-2x2 "$BM/results/run7/axiam-strict-caps-2x2" strict; }
pass_strict_4x4() { optional_axiam strict-4x4 "$BM/results/run7/axiam-strict-caps-4x4" strict BENCH_CPUS=4 BENCH_DB_CPUS=4; }
pass_ws_2x2()     { optional_axiam ws-2x2 "$BM/results/run7/axiam-ws-caps-2x2" default AXIAM__DB__ENGINE=ws; }

pass_caps_4x4() {
    if matrix caps-4x4 "$BM/results/run7/caps-4x4" "$TARGETS_ALL" p0-plaintext default BENCH_CPUS=4 BENCH_DB_CPUS=4; then
        done_mark caps-4x4
    else
        skip_mark caps-4x4 "the pass stopped (logs/run7/caps-4x4.log)"
    fi
    pack
}

pass_zitadel_on() {
    if ! CACHES=on dry zitadel-on zitadel p0-plaintext "$(core_set)"; then
        skip_mark zitadel-on "its dry run failed (logs/run7/dryrun-zitadel-on-SUMMARY.md)"; return 0
    fi
    if matrix zitadel-on "$BM/results/run7/zitadel-caches-on-caps-2x2" zitadel p0-plaintext on; then
        done_mark zitadel-on
    else
        skip_mark zitadel-on "the pass stopped (logs/run7/zitadel-on.log)"
    fi
    pack
}

pass_sdk() {
    if [[ -f "$STATE/sdk.rehearsal-failed" ]]; then
        skip_mark sdk "the SDK rehearsal failed in the dry-run pass (logs/run7/sdk-dryrun.log)"; return 0
    fi
    rm -rf "$BM/results/sdk" "$BM"/results/sdk-run-*
    local rc=0
    (
        cd "$BM" || exit 1
        no_caps
        just target=axiam profile=p0-plaintext bench-up && just target=axiam bench-seed || exit 1
        SDK_BENCH_CONCURRENCY=16 just target=axiam profile=p0-plaintext repeat="$REPEAT" sdk-bench-all
        r=$?
        just target=axiam bench-down
        exit "$r"
    ) 2>&1 | tee -a "$LOGS/sdk.log" || rc=$?
    # The SDK builds touch go.sum, Package.resolved and friends; keep the tree clean.
    if ! git -C "$AX" diff --quiet; then
        git -C "$AX" diff --stat > "$LOGS/sdk-local-changes.txt"
        git -C "$AX" checkout -- .
    fi
    if (( rc == 0 )); then done_mark sdk
    else skip_mark sdk "sdk-bench-all exited $rc (logs/run7/sdk.log); partial records may still be in results/sdk"
    fi
    pack
}

pass_surreal335() {
    # A 3.3.5 server cannot open a volume a 4.x server wrote: start from nothing.
    (cd "$BM" && just target=axiam bench-down >/dev/null 2>&1)
    if [[ -n "$(docker volume ls -q --filter name=bench-axiam_surrealdb-data)" ]]; then
        skip_mark surreal335 "a SurrealDB volume survived bench-down"; return 0
    fi
    local img="$RUN7_SURREALDB_335"
    docker pull "$img" >>"$LOGS/surreal335.log" 2>&1 || { skip_mark surreal335 "cannot pull $img"; return 0; }
    docker run --rm "$img" version 2>&1 | tee -a "$LOGS/surreal335.log" | grep -q '^3\.3\.5 ' \
        || { skip_mark surreal335 "the pinned image does not report 3.3.5"; return 0; }
    if ! dry surreal335 axiam p0-plaintext "$(core_set)" BENCH_SURREALDB_IMAGE="$img"; then
        skip_mark surreal335 "AXIAM 1.4.0 does not pass its dry run on SurrealDB 3.3.5 (logs/run7/dryrun-surreal335-SUMMARY.md) — a finding, not a fault"
        (cd "$BM" && just target=axiam bench-down >/dev/null 2>&1)
        return 0
    fi
    local ok=1
    matrix surreal335-2x2 "$BM/results/run7/axiam-surreal-3.3.5-caps-2x2" axiam p0-plaintext default \
        BENCH_SURREALDB_IMAGE="$img" || ok=0
    matrix surreal335-4x4 "$BM/results/run7/axiam-surreal-3.3.5-caps-4x4" axiam p0-plaintext default \
        BENCH_SURREALDB_IMAGE="$img" BENCH_CPUS=4 BENCH_DB_CPUS=4 || ok=0
    (cd "$BM" && just target=axiam bench-down >/dev/null 2>&1)
    if (( ok )); then done_mark surreal335
    else skip_mark surreal335 "a 3.3.5 pass stopped (logs/run7/surreal335-*.log)"
    fi
    pack
}

pass_close() {
    cd "$BM" || return 1
    pkill -f 'vmstat -n -t 10' 2>/dev/null || true
    run_logged close bash runner/record-provenance.sh -after || true
    run_logged close just bench-report || true
    local steal
    steal="$(awk 'NR==2 {for (i=1;i<=NF;i++) if ($i=="st") c=i; next} c && $1 ~ /^[0-9]+$/ {s+=$c; n++; if ($c>5) hi++} END {if (n) printf "mean %.2f %% over %d samples; %d samples above 5 %%", s/n, n, hi; else print "no samples"}' results/provenance/vmstat-steal.txt 2>/dev/null)"
    {
        echo "# Run 7 notes (written by run7.sh; add what the files cannot say)"
        echo
        echo "- Generated:          $(ts)"
        echo "- Host:               $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //'), $(nproc) vCPUs, $(awk '/MemTotal/ {printf "%.0f GiB", $2/1048576}' /proc/meminfo)"
        echo "- Qualification:      $(tr '\n' ' ' < "$BENCH_DIR/logs/qualify.txt" 2>/dev/null | cut -c1-300)"
        echo "- Steal during run:   $steal"
        echo "- AXIAM:              $AXIAM_TAG (image by digest, results/provenance/images.txt); harness $AXIAM_REF @ $(git -C "$AX" rev-parse --short=12 HEAD)"
        echo "- Pinned from run 6:  Keycloak 26.8.1, Zitadel v4.19.5, authentik 2026.8.5, PostgreSQL 16, RabbitMQ 4, SurrealDB 4.0.1 (run7-pins.env)"
        echo "- SurrealDB issues:   surrealdb/surrealdb#7667 and #7716 open at the time of the run"
        echo "- Caps:               2/2 unless the tree name says 4x4"
        echo "- Cache posture:      shipped defaults unless the tree name says strict (AXIAM caches off) or caches-on (Zitadel)"
        echo "- oauth2_refresh_grant: $([[ -f "$STATE/new-cell.dropped" ]] && echo 'DROPPED (failed its dry run)' || echo 'measured in every pass')"
        echo "- Passes:"
        for p in $ALL_PASSES; do
            if [[ -f "$STATE/$p.done" ]]; then echo "    $p: done $(cat "$STATE/$p.done")"
            elif [[ -f "$STATE/$p.skipped" ]]; then echo "    $p: SKIPPED $(cat "$STATE/$p.skipped")"
            elif [[ "$p" == close ]]; then echo "    close: this file"
            else echo "    $p: not run"; fi
        done
        echo "- Start / end, interruptions, anything re-run: (fill in)"
    } > results/RUN-NOTES.md
    cp results/RUN-NOTES.md "$LOGS/RUN-NOTES.md"
    pack
    done_mark close
    note "Run 7 complete. From your PC: ./run.sh fetch ~/axiam-results-run7"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
estimate() {  # minutes, from run 6 (~3.7 min per cell including bring-ups)
    case "$1" in
        setup) echo 25 ;; preflight) echo 30 ;; dryrun) echo 120 ;; resting) echo 50 ;;
        # cells per repeat: AXIAM 12, Keycloak 7, Zitadel 8, authentik 7 per profile
        # (authentik has no p3), with oauth2_refresh_grant counted.
        matrix) echo $(( (36 + 21 + 24 + 14) * REPEAT * 37 / 10 )) ;;
        strict-2x2|strict-4x4|ws-2x2) echo $(( 12 * REPEAT * 37 / 10 + 10 )) ;;
        caps-4x4) echo $(( (12 + 7 + 8 + 7) * REPEAT * 37 / 10 )) ;;
        zitadel-on) echo $(( 8 * REPEAT * 37 / 10 + 10 )) ;;
        sdk) echo 90 ;; surreal335) echo $(( 2 * 12 * REPEAT * 37 / 10 + 15 )) ;; close) echo 10 ;;
    esac
}

list() {
    local total=0 m
    printf '%-12s %-9s %s\n' pass state "estimate"
    for p in $ALL_PASSES; do
        m="$(estimate "$p")"
        local st="todo"
        [[ -f "$STATE/$p.done" ]] && st="done"
        [[ -f "$STATE/$p.skipped" ]] && st=skipped
        [[ "$st" == todo ]] && total=$((total + m))
        printf '%-12s %-9s %dh%02d\n' "$p" "$st" $((m / 60)) $((m % 60))
    done
    printf 'remaining, about %dh%02d (REPEAT=%s)\n' $((total / 60)) $((total % 60)) "$REPEAT"
}

case "${1:-}" in
    --list) list; exit 0 ;;
    --redo)
        [[ -n "${2:-}" ]] || die "--redo needs a pass name"
        [[ " $ALL_PASSES " == *" $2 "* ]] || die "unknown pass '$2' (one of: $ALL_PASSES)"
        rm -f "$STATE/$2.done" "$STATE/$2.skipped" "$STATE/close.done"
        note "forgot pass $2"; shift 2 ;;
    -h|--help) sed -n '3,/^set -uo/p' "${BASH_SOURCE[0]}" | grep '^#' | sed 's/^# \{0,1\}//'; exit 0 ;;
    "") ;;
    *) die "unknown argument '$1' (try --help)" ;;
esac

if [[ -z "${TMUX:-}" && "${RUN7_ALLOW_NO_TMUX:-0}" != "1" ]]; then
    die "Run this inside tmux (tmux new -s bench), so an SSH drop cannot stop a day-long run. RUN7_ALLOW_NO_TMUX=1 overrides."
fi
need just; need docker; need k6; need jq; need git

wanted="${PASSES:-$ALL_PASSES}"
note "run 7 starting — $AXIAM_TAG, harness $AXIAM_REF, REPEAT=$REPEAT"
list | tee -a "$log_main"

for p in $ALL_PASSES; do
    if is_settled "$p"; then continue; fi
    # setup, preflight and close always run; the rest only when PASSES names them.
    if [[ " setup preflight close " != *" $p "* && " $wanted " != *" $p "* ]]; then
        note "PASS $p: not in PASSES, left for later"; continue
    fi
    # Mandatory passes must be done before anything else runs.
    for need_done in setup preflight dryrun; do
        [[ "$p" == "$need_done" ]] && break
        [[ -f "$STATE/$need_done.done" ]] || fatal "$need_done is not done; it must pass before $p"
    done
    [[ "$p" == close ]] || load_pins
    [[ "$p" == setup || "$p" == close ]] || steal_log_on
    note "PASS $p: starting (estimate $(estimate "$p") min)"
    touch "$STATE/$p.running"
    "pass_${p//-/_}"
done
# OPTIONAL_PASSES is the documented list of passes allowed to be skipped.
: "$OPTIONAL_PASSES"
