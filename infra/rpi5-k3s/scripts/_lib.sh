#!/usr/bin/env bash
# Shared helpers. Sourced, never executed.
#
# Kept deliberately small: five functions and no framework. A bring-up script an
# operator has to debug at 2am should be readable top to bottom.

# shellcheck shell=bash

_c() { [[ -t 1 ]] && printf '\033[%sm' "$1" || true; }
say()  { printf '%s→%s %s\n' "$(_c 36)" "$(_c 0)" "$*"; }
ok()   { printf '%s✓%s %s\n' "$(_c 32)" "$(_c 0)" "$*"; }
warn() { printf '%s!%s %s\n' "$(_c 33)" "$(_c 0)" "$*" >&2; }
die()  { printf '%s✗%s %s\n' "$(_c 31)" "$(_c 0)" "$*" >&2; exit 1; }

# Ask before doing something that cannot be undone. Refuses in a non-interactive
# shell rather than assuming yes: an unattended run of a destructive step is the
# thing this exists to prevent.
confirm() {
    local prompt="$1" reply
    [[ -t 0 ]] || die "$prompt — refusing to assume an answer on a non-interactive shell."
    read -r -p "$prompt [type YES to continue] " reply
    [[ "$reply" == "YES" ]] || die "Aborted."
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "\`$1\` is not on PATH. Run 01-install-k3s.sh first."
}

# Download to a temp file and move into place only on success, so an interrupted
# transfer never leaves a half-written binary that looks installed.
fetch_to() {
    local url="$1" dest="$2" mode="${3:-0755}" tmp
    tmp="$(mktemp)"
    curl --fail --location --silent --show-error --retry 3 --retry-delay 2 \
         --output "$tmp" "$url" || { rm -f "$tmp"; return 1; }
    sudo install -m "$mode" "$tmp" "$dest"
    rm -f "$tmp"
}

# The repository root, from any script in this directory.
repo_root() { git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel; }
