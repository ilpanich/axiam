# Development Environment — Claude Code Tooling

This repo's workflow relies on three Claude Code tools. Because web/cloud
sessions run in **ephemeral containers**, these are not committed into the repo
(they install into `~/.claude` and generate large `.claude/` trees that are
git-ignored). Instead they are reprovisioned by a single idempotent script.

## Bootstrap

```bash
bash scripts/bootstrap-dev-tools.sh
```

Safe to re-run; each step is skipped when already present. Restart Claude Code
afterwards so the new skills and hooks load.

For automatic provisioning in Claude Code on the web, point the environment's
**setup script** (configured in the web UI) at the command above, or add it as a
`SessionStart` hook in your user `~/.claude/settings.json`.

## What it installs

| Tool | Source | Scope | What it gives you |
|------|--------|-------|-------------------|
| **GSD** | [`@opengsd/gsd-core`](https://github.com/open-gsd/gsd-core) | global (`~/.claude`) | Spec-driven dev workflow — the `gsd-*` skills/commands that drive `.planning/` (e.g. `gsd-plan-phase`, `gsd-execute-phase`, `gsd-progress`, `gsd-ship`). |
| **ruflo** | [`ruvnet/ruflo`](https://github.com/ruvnet/ruflo) | project (`.claude/`) | Multi-agent swarm — agent definitions (`.claude/agents/`), slash commands, skills, and the `claude-flow` MCP server (`.mcp.json`). |
| **RTK** | [`rtk-ai/rtk`](https://github.com/rtk-ai/rtk) | global (`~/.claude`) | Rust Token Killer — a `PreToolUse` hook that compresses command output before it reaches the context window (60–90% fewer tokens). |

## Notes

- **GSD** is the workflow already in use across `.planning/` (PROJECT.md,
  ROADMAP.md, phase plans). The installer is non-interactive via
  `--claude --global`.
- **ruflo**'s `init --force` overwrites the project `CLAUDE.md`; the bootstrap
  script preserves and restores ours automatically. To install the full
  ~89-agent set instead of the default substrate set, re-run with
  `npx -y ruflo@latest init --only-claude --no-global --force --all-agents`.
  The optional V3 runtime (daemon/memory/swarm) and cloud MCP servers are not
  enabled by default — see `ruflo --help`.
- **RTK** must already be on `PATH` (binary install). The script only wires the
  hook via `rtk init --global --auto-patch`.
- Generated/ephemeral artifacts (`.claude/`, `.claude-flow/`, `.mcp.json`,
  `.swarm/`) are git-ignored on purpose — they are reproducible from the script.
