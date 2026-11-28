#!/usr/bin/env bash
# Shared helpers. Sourced, never executed. The five of
# infra/rpi5-k3s/scripts/_lib.sh, plus the few this host needs.

# shellcheck shell=bash

_c() { [[ -t 1 ]] && printf '\033[%sm' "$1" || true; }
say()  { printf '%s→%s %s\n' "$(_c 36)" "$(_c 0)" "$*"; }
ok()   { printf '%s✓%s %s\n' "$(_c 32)" "$(_c 0)" "$*"; }
warn() { printf '%s!%s %s\n' "$(_c 33)" "$(_c 0)" "$*" >&2; }
die()  { printf '%s✗%s %s\n' "$(_c 31)" "$(_c 0)" "$*" >&2; exit 1; }

# Ask before doing something that cannot be undone. Refuses in a non-interactive
# shell rather than assuming yes.
confirm() {
    local prompt="$1" reply
    [[ -t 0 ]] || die "$prompt — refusing to assume an answer on a non-interactive shell."
    read -r -p "$prompt [type YES to continue] " reply
    [[ "$reply" == "YES" ]] || die "Aborted."
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "\`$1\` is not on PATH. ${2:-Run the earlier scripts first.}"
}

# Download to a temp file and move into place only on success, so an interrupted
# transfer never leaves a half-written file that looks installed.
fetch_to() {
    local url="$1" dest="$2" mode="${3:-0644}" tmp
    tmp="$(mktemp)"
    curl --fail --location --silent --show-error --retry 3 --retry-delay 2 \
         --output "$tmp" "$url" || { rm -f "$tmp"; return 1; }
    $SUDO install -m "$mode" "$tmp" "$dest"
    rm -f "$tmp"
}

# Root needs no sudo; everybody else does (the Ubuntu cloud user has it
# without a password).
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then SUDO=""; else SUDO="sudo"; fi

# Non-interactive apt: no debconf prompts, and needrestart restarts services
# itself instead of opening a dialog in the middle of a script.
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
apt_install() { $SUDO apt-get install -y --no-install-recommends "$@"; }

# version_ge A B: true when version A >= version B (dotted, any length).
version_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }

# The toolchains' PATH, for a script that runs before the new ~/.bashrc block
# has been read by a login shell.
# swiftly's home is not the same everywhere: ~/.local/share/swiftly on Linux
# by default, ~/.swiftly in some releases, or wherever SWIFTLY_HOME_DIR points.
# A hard-coded path made an installed Swift look absent.
swiftly_env() {
    local f
    for f in "${SWIFTLY_HOME_DIR:+$SWIFTLY_HOME_DIR/env.sh}" \
             "$HOME/.local/share/swiftly/env.sh" "$HOME/.swiftly/env.sh"; do
        [[ -n "$f" && -f "$f" ]] && { printf '%s' "$f"; return 0; }
    done
    return 1
}

bench_path() {
    export PATH="/usr/local/go/bin:$HOME/go/bin:/opt/dotnet:$HOME/.cargo/bin:$PATH"
    export DOTNET_ROOT=/opt/dotnet DOTNET_CLI_TELEMETRY_OPTOUT=1
    local env_sh
    # shellcheck disable=SC1090
    if env_sh="$(swiftly_env)"; then . "$env_sh"; fi
    return 0
}

# For the installing scripts (set -e): keep a log of the whole run, and when a
# step fails, say WHICH one instead of exiting on a bare curl or tar message
# that scrolls past. A re-run skips the steps already done.
#   log: ${BENCH_DIR:-~/bench}/logs/<script>.log
stop_loudly() {
    local name log_dir
    name="$(basename "$0" .sh)"
    log_dir="${BENCH_DIR:-$HOME/bench}/logs"
    mkdir -p "$log_dir"
    BENCH_SCRIPT_LOG="$log_dir/$name.log"
    printf '\n===== %s %s =====\n' "$name" "$(date -u +%FT%TZ)" >> "$BENCH_SCRIPT_LOG"
    exec > >(tee -a "$BENCH_SCRIPT_LOG") 2>&1
    set -E
    trap '_stopped $? $LINENO "$BASH_COMMAND"' ERR
}
_stopped() {
    trap - ERR
    printf '✗ %s STOPPED (exit %s) at line %s: %s\n' "$(basename "$0")" "$1" "$2" "$3" >&2
    printf '  The steps after this one did not run. Fix the cause shown above and run it again:\n' >&2
    printf '  what is already installed is skipped. Full output: %s\n' "$BENCH_SCRIPT_LOG" >&2
}
