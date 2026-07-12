#!/usr/bin/env bash
#
# session-start-tooling.sh — fast SessionStart wiring for the agent toolchain.
#
# Runs on every Claude Code session start (see .claude/settings.json). It is
# intentionally cheap: it NEVER clones or builds. It only re-wires tooling that
# a previous provisioning run already produced, so that:
#
#   * rtk is on PATH, and
#   * .mcp.json (gitignored, container-local) points at the RuFlo + GSD MCP
#     servers so they attach on this session start.
#
# Heavy setup lives in scripts/provision-agent-tooling.sh. If the tools are
# missing (fresh container), this prints one line telling you to run it.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# External repos are cloned as siblings of this checkout (repo parent dir).
TOOLS_DIR="${AXIAM_TOOLS_DIR:-$(dirname "$REPO_ROOT")}"
BIN_DIR="${AXIAM_BIN_DIR:-$HOME/.local/bin}"
GSD_DIR="$TOOLS_DIR/gsd-core"
RTK_DIR="$TOOLS_DIR/rtk"
RUFLO_DIR="$TOOLS_DIR/ruflo"

# rtk on PATH (only if already built)
if [ -x "$RTK_DIR/target/release/rtk" ]; then
  mkdir -p "$BIN_DIR"
  ln -sf "$RTK_DIR/target/release/rtk" "$BIN_DIR/rtk"
fi

# regenerate local .mcp.json if the MCP servers are present but the config is gone
if [ -f "$RUFLO_DIR/bin/cli.js" ] || [ -f "$GSD_DIR/bin/gsd-mcp-server.js" ]; then
  if [ ! -f "$REPO_ROOT/.mcp.json" ]; then
    cat > "$REPO_ROOT/.mcp.json" <<JSON
{
  "mcpServers": {
    "ruflo": { "command": "node", "args": ["$RUFLO_DIR/bin/cli.js", "mcp", "start"], "env": { "NODE_NO_WARNINGS": "1" } },
    "gsd":   { "command": "node", "args": ["$GSD_DIR/bin/gsd-mcp-server.js"] }
  }
}
JSON
  fi
else
  echo "[agent-tooling] GSD/RTK/RuFlo not provisioned in this container — run: bash scripts/provision-agent-tooling.sh"
fi

exit 0
