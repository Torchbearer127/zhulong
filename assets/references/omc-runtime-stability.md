# OMC Runtime Stability

Use this note when deciding whether the current Claude Code session can safely run `ulw` or `/team`.

## Core Rule

- `/ultrawork` and `/team` are in-session OMC workflows.
- Avoid leading a prompt with a bare `ulw ...` string. In some environments that token can be misinterpreted and routed into Bash instead of an in-session workflow.
- `omc team ...` is a tmux-backed CLI runtime and should not be the default path for interactive local audits.
- If Claude Code native teams are not enabled, prefer a single-agent audit over a pseudo-parallel fallback.

## Required Gate

Run this before starting a new multi-agent audit:

```bash
bash <audit-workspace>/bin/check_omc_runtime.sh
```

If your current working directory is already the current audit workspace, the compatibility alias is:

```bash
bash scripts/check_omc_runtime.sh
```

Interpret the result as:

- `recommended_mode=native_team_ready`
  Use `/team` first. Escalate to `/ultrawork` only when broader parallel sweep is truly needed.
  If `live_swarm_sockets` is non-empty, that means Claude already has an active live teammate session. Do not run cleanup in that same active session.
- `recommended_mode=cleanup_needed`
  Treat this as a manual-review state first.
  The runtime helper no longer auto-cleans teammate-mode processes because that can kill an unrelated active Claude Code session.
  If only stale sockets are present, run `bash <audit-workspace>/bin/check_omc_runtime.sh --cleanup-stale`, then re-check.
  If teammate-mode PIDs are also reported, inspect those processes manually before terminating anything.
  If `ignored_current_session_teammate_pids` is non-empty, those PIDs belong to the current Claude session itself and must never be killed as stale residue.
- `recommended_mode=single_agent_only`
  Do not force `/team` or `ulw`; continue single-agent.

## Native Team Requirement

Claude Code native teams should be enabled in `~/.claude/settings.json`:

```json
{
  "env": {
    "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"
  }
}
```

Without this flag, OMC may fall back away from native team execution.

## Common Failure Signatures

- UI shows `View teammates: tmux -L claude-swarm-... a` but no new work appears.
- A `claude --teammate-mode tmux` process exists, but there is no corresponding live `claude-swarm-*` tmux socket.
- The todo list says a task is still `in progress`, but elapsed time stops changing in a meaningful way.

Treat these as broken orchestration, not as proof that useful work is still happening.

## Local Config Pitfalls

- Do not whitelist `Bash(ulw:*)`. `ulw` is not a shell command.
- Do not instruct the model to run `oh-my-claudecode:ultrawork(...)` as an agent type.
- Avoid starting a second audit while stale teammate/tmux residue from the previous audit still exists.

## Minimal Recovery

```bash
bash <audit-workspace>/bin/check_omc_runtime.sh --cleanup-stale
bash <audit-workspace>/bin/check_omc_runtime.sh
```

Or from inside the current audit workspace:

```bash
bash scripts/check_omc_runtime.sh --cleanup-stale
bash scripts/check_omc_runtime.sh
```

If the second command still reports `single_agent_only`, continue without OMC multi-agent mode.

Important:

- Do not run `--cleanup-stale` blindly in the middle of an active `/team` session.
- `--cleanup-stale` removes stale `claude-swarm-*` sockets only; it does not kill teammate-mode processes unless you do that yourself after inspection.
- If `live_swarm_sockets` is present, finish or cancel the current team session first, then clean up afterward only if a later re-check still reports `cleanup_needed`.
- If `suspect_teammate_pids` is present without a live socket, assume the state is ambiguous and inspect with `ps -fp <pid>` before any manual cleanup.
- If `ignored_current_session_teammate_pids` is present, treat that as a self-protection hint from the runtime helper and do not kill those PIDs.
