#!/usr/bin/env bash
#
# provision-agent-tooling.sh — idempotent provisioner for the AXIAM agent toolchain.
#
# Installs / builds three external agent-tooling projects used to develop AXIAM
# in Claude Code (web or local), and wires them into this checkout:
#
#   * GSD Core (open-gsd/gsd-core) — spec-driven development skills/commands/agents
#   * RTK      (rtk-ai/rtk)        — "Rust Token Killer" CLI, cuts LLM token usage
#   * RuFlo    (ruvnet/ruflo)      — Claude-Flow agent-orchestration MCP server + skills
#
# Remote Claude Code containers are ephemeral: anything outside the git repo is
# lost when the container is reclaimed. Run this once per fresh container (or via
# the SessionStart hook / your environment setup script) to rebuild the toolchain
# and (re)generate the local, gitignored .mcp.json so the RuFlo + GSD MCP servers
# attach on the next session start.
#
# Safe to re-run: every step checks for existing state before doing work.

set -euo pipefail

# --- config -----------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# External repos are cloned as siblings of this checkout (repo parent dir).
TOOLS_DIR="${AXIAM_TOOLS_DIR:-$(dirname "$REPO_ROOT")}"
GSD_DIR="$TOOLS_DIR/gsd-core"
RTK_DIR="$TOOLS_DIR/rtk"
RUFLO_DIR="$TOOLS_DIR/ruflo"
BIN_DIR="${AXIAM_BIN_DIR:-$HOME/.local/bin}"

log()  { printf '\033[36m[provision]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[provision]\033[0m %s\n' "$*" >&2; }

mkdir -p "$BIN_DIR"

# --- clone ------------------------------------------------------------------
clone() { # <dir> <url>
  local dir="$1" url="$2"
  if [ -d "$dir/.git" ]; then
    log "$(basename "$dir") already cloned — skipping"
  else
    log "cloning $(basename "$dir") ..."
    git clone --depth 1 "$url" "$dir"
  fi
}

clone "$GSD_DIR"   "https://github.com/open-gsd/gsd-core.git"
clone "$RTK_DIR"   "https://github.com/rtk-ai/rtk.git"
clone "$RUFLO_DIR" "https://github.com/ruvnet/ruflo.git"

# --- RTK: build the token-reduction CLI -------------------------------------
if [ -x "$RTK_DIR/target/release/rtk" ]; then
  log "rtk already built — skipping"
else
  log "building rtk (release) ..."
  ( cd "$RTK_DIR" && cargo build --release )
fi
ln -sf "$RTK_DIR/target/release/rtk" "$BIN_DIR/rtk"
log "rtk -> $BIN_DIR/rtk"

# --- GSD: install skills/commands/agents/hooks into ~/.claude ---------------
if [ -d "$GSD_DIR/node_modules" ]; then
  log "gsd deps already installed — skipping npm install"
else
  log "installing gsd deps ..."
  ( cd "$GSD_DIR" && npm install --no-audit --no-fund )
fi
log "installing GSD for Claude Code (global) ..."
( cd "$GSD_DIR" && node bin/install.js --claude --global ) || warn "GSD install reported warnings (non-fatal)"

# --- RuFlo: install deps + build the v3 CLI (drives the MCP server) ---------
if [ -d "$RUFLO_DIR/node_modules" ]; then
  log "ruflo deps already installed — skipping npm install"
else
  log "installing ruflo deps ..."
  ( cd "$RUFLO_DIR" && npm install --no-audit --no-fund )
fi
if [ -f "$RUFLO_DIR/v3/@claude-flow/cli/dist/src/index.js" ]; then
  log "ruflo v3 cli already built — skipping"
else
  log "building ruflo v3 cli ..."
  # build:ts is tolerant (|| true) of the optional ruvector ML module that has no
  # published wasm dep; the core CLI + MCP server build fine without it.
  ( cd "$RUFLO_DIR" && npm run build:ts ) || warn "ruflo build reported warnings (non-fatal)"
fi

# --- generate the local (gitignored) .mcp.json ------------------------------
# Registers the RuFlo + GSD MCP servers so they attach on the next session start.
# .mcp.json is gitignored on purpose: paths are container-local.
MCP_JSON="$REPO_ROOT/.mcp.json"
log "writing $MCP_JSON"
cat > "$MCP_JSON" <<JSON
{
  "mcpServers": {
    "ruflo": {
      "command": "node",
      "args": ["$RUFLO_DIR/bin/cli.js", "mcp", "start"],
      "env": { "NODE_NO_WARNINGS": "1" }
    },
    "gsd": {
      "command": "node",
      "args": ["$GSD_DIR/bin/gsd-mcp-server.js"]
    }
  }
}
JSON

log "done. Restart the Claude Code session so the RuFlo + GSD MCP servers attach."
log "  GSD skills:   gsd-new-milestone, gsd-plan-phase, gsd-execute-phase, ..."
log "  RuFlo skills: swarm-orchestration, hive-mind-advanced, sparc-methodology, ..."
log "  RTK:          rtk read|grep|git|tree  (token-optimized proxies)"
