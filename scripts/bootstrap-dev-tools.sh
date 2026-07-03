#!/usr/bin/env bash
#
# bootstrap-dev-tools.sh
#
# Idempotently provisions the Claude Code development tooling this repo's
# workflow relies on, so a fresh (ephemeral) environment has them available:
#
#   1. GSD   — @opengsd/gsd-core: the spec-driven dev workflow that drives the
#              .planning/ directory (gsd-* skills / commands). Installed globally
#              to ~/.claude.
#   2. ruflo — ruvnet/ruflo multi-agent swarm. Agents/commands/skills are
#              scaffolded into the project .claude/ (Claude-only, runtime light).
#   3. RTK   — rtk-ai (Rust Token Killer): a PreToolUse hook that compresses
#              command output before it hits the context window. Wired globally.
#
# Safe to re-run: each step is skipped when already present. Network access to
# the npm registry is required for GSD and ruflo; RTK must already be on PATH.
#
# Usage:  bash scripts/bootstrap-dev-tools.sh
#
set -uo pipefail

CLAUDE_HOME="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

log()  { printf '\033[36m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[bootstrap] WARN:\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[32m[bootstrap] ✓\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------------------
# 1. GSD (get-shit-done / gsd-core)
# ---------------------------------------------------------------------------
install_gsd() {
  if [ -f "$CLAUDE_HOME/gsd-core/VERSION" ]; then
    ok "GSD already installed ($(cat "$CLAUDE_HOME/gsd-core/VERSION" 2>/dev/null))"
    return 0
  fi
  if ! command -v npx >/dev/null 2>&1; then
    warn "npx not found — skipping GSD install"
    return 1
  fi
  log "Installing GSD (gsd-core) for Claude Code (global)…"
  if npx -y @opengsd/gsd-core@latest --claude --global; then
    ok "GSD installed"
  else
    warn "GSD install failed"
  fi
}

# ---------------------------------------------------------------------------
# 2. ruflo (ruvnet/ruflo) — Claude integration only
#    ruflo init --force overwrites the project CLAUDE.md, so preserve ours.
# ---------------------------------------------------------------------------
install_ruflo() {
  if [ -d "$REPO_ROOT/.claude-flow" ] && [ -d "$REPO_ROOT/.claude/agents" ]; then
    ok "ruflo already initialized (.claude-flow present)"
    return 0
  fi
  if ! command -v npx >/dev/null 2>&1; then
    warn "npx not found — skipping ruflo init"
    return 1
  fi
  log "Initializing ruflo (Claude integration)…"
  local saved=""
  if [ -f "$REPO_ROOT/CLAUDE.md" ]; then
    saved="$(mktemp)"
    cp "$REPO_ROOT/CLAUDE.md" "$saved"
  fi
  npx -y ruflo@latest init --only-claude --no-global --force || warn "ruflo init reported errors"
  # Restore the project's own CLAUDE.md (ruflo overwrites it).
  if [ -n "$saved" ]; then
    cp "$saved" "$REPO_ROOT/CLAUDE.md"
    rm -f "$saved" "$REPO_ROOT/CLAUDE.md.pre-ruflo"
    log "Restored project CLAUDE.md (ruflo had overwritten it)"
  fi
  ok "ruflo initialized"
}

# ---------------------------------------------------------------------------
# 3. RTK (rtk-ai / Rust Token Killer) — wire the global hook
# ---------------------------------------------------------------------------
install_rtk() {
  if ! command -v rtk >/dev/null 2>&1; then
    warn "rtk not on PATH — install from https://github.com/rtk-ai/rtk, then re-run"
    return 1
  fi
  if [ -f "$CLAUDE_HOME/RTK.md" ] && grep -q "rtk hook" "$CLAUDE_HOME/settings.json" 2>/dev/null; then
    ok "RTK hook already wired ($(rtk --version 2>/dev/null))"
    return 0
  fi
  log "Wiring RTK hook (global)…"
  if rtk init --global --auto-patch; then
    ok "RTK hook wired"
  else
    warn "RTK init failed"
  fi
}

log "Provisioning Claude Code dev tools into $CLAUDE_HOME and $REPO_ROOT"
install_gsd
install_ruflo
install_rtk
log "Done. Restart Claude Code so newly installed skills/hooks load."
