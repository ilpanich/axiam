# Agent Tooling — GSD, RTK, RuFlo

AXIAM is developed with three external agent-tooling projects. This document
records how they are provisioned into a Claude Code environment (web or local)
and how to use them.

| Tool | Repo | Role |
|------|------|------|
| **GSD Core** | [`open-gsd/gsd-core`](https://github.com/open-gsd/gsd-core) | Spec-driven development workflow — skills, commands, agents, hooks (`gsd-new-milestone`, `gsd-plan-phase`, `gsd-execute-phase`, `gsd-code-review`, `gsd-secure-phase`, …) |
| **RTK** | [`rtk-ai/rtk`](https://github.com/rtk-ai/rtk) | "Rust Token Killer" CLI — token-optimized proxies for `read`, `grep`, `git`, `tree`, `diff`, … to cut LLM context cost |
| **RuFlo** | [`ruvnet/ruflo`](https://github.com/ruvnet/ruflo) | Claude-Flow agent orchestration — swarm/hive-mind MCP server + skills (`swarm-orchestration`, `hive-mind-advanced`, `sparc-methodology`, …) |

## Provisioning

Remote Claude Code containers are **ephemeral** — anything outside the git repo
(cloned repos, built binaries, `~/.claude` installs) is lost when the container
is reclaimed. `.mcp.json` and `.claude/` are gitignored, so they cannot be
committed; they are regenerated per container.

Run the idempotent provisioner once per fresh container:

```bash
bash scripts/provision-agent-tooling.sh
```

It clones the three repos as siblings of this checkout, builds RTK (`cargo`),
installs GSD into `~/.claude`, builds the RuFlo v3 CLI, and (re)generates the
local, gitignored `.mcp.json` registering the RuFlo + GSD MCP servers.

**Recommended:** set this script as the environment's **setup script** in the
Claude Code web UI so every session/restart auto-provisions. See
<https://code.claude.com/docs/en/claude-code-on-the-web>.

`scripts/session-start-tooling.sh` is a fast, no-build re-wiring step (rtk on
PATH, regenerate `.mcp.json`) suitable for a local `.claude/settings.json`
SessionStart hook when the container persists across restarts.

## What needs a session restart

- **GSD/RuFlo skills** hot-load into the running session (invoke via the Skill tool).
- **RTK** works immediately once built (`rtk` on `PATH`).
- **MCP servers** (`mcp__ruflo__*`, `mcp__gsd__*`) and **GSD slash commands / hooks**
  bind only at **session start** — restart after provisioning to activate them.

## RTK usage

```bash
rtk read <file>      # intelligent, token-reduced file read
rtk grep <pattern>   # compact grep grouped by file
rtk git <args>       # compact git output
rtk tree | rtk ls    # token-optimized directory listing
rtk init -g          # (optional) install a hook for automatic passive savings
```
