# Install

This guide assumes your shell is in the `zhulong` package root: the
directory that contains `README.md`, `scripts/`, `docs/`, `assets/`,
`.claude-plugin/`, and `.codex-plugin/`.

If you are working from a parent dogfood repository that contains
`plugins/zhulong/`, first run:

```bash
cd plugins/zhulong
```

All commands below are written for the standalone plugin package layout.

## What This Package Is

Zhulong is distributed as a lightweight local-agent package:

```text
zhulong/
├── .claude-plugin/plugin.json
├── .codex-plugin/plugin.json
├── skills/zhulong/SKILL.md
├── scripts/
├── assets/
└── docs/
```

The Claude plugin manifest is metadata-only. The stable runtime remains the
installed Skill plus the package scripts and assets; it does not introduce
hooks, MCP servers, apps, agents, commands, background services, dashboards,
databases, vector stores, or hosted services.

## Platform Support

Zhulong is designed around Bash, Python helper scripts, and Docker-first
verification. Use it from a Unix-like shell.

| Platform | Recommended path | Notes |
| --- | --- | --- |
| macOS | Supported and dogfooded | Install Python 3.11+, Docker Desktop or another Docker Engine, and run the sync commands below. |
| Linux | Supported target path | Install Python 3.11+, Docker Engine, Docker Compose, Bash, and run the same commands below. |
| Windows | Use WSL2 | Run Zhulong inside WSL2 with Docker Desktop WSL integration enabled. Keep working repositories on the WSL filesystem when possible. Native PowerShell/CMD execution is not a first-class supported path yet. |

If your local agent uses a non-default Skill directory, set
`CLAUDE_SKILLS_DIR` or pass `--claude-skills-dir` to the sync script.

## Install Into Claude Code

### Option A: Sync The Claude Skill

From the package root:

```bash
python3 scripts/selftest_plugin.py
bash scripts/sync_to_claude_skill.sh
python3 ~/.claude/skills/zhulong/scripts/selftest_plugin.py
```

The default target is:

```text
~/.claude/skills/zhulong/
```

If a Skill already exists there, the script backs it up automatically before
replacing it.

This is the most stable runtime path today because Claude Code loads the
`SKILL.md` instructions and helper scripts directly from the installed Skill.

### Option B: Use The Plugin-Style Package

For packaging or discovery workflows that understand Claude plugin-style
packages, point them at this package root:

```text
zhulong/
```

The manifest points to `./skills`, `./scripts`, and `./assets` with relative
paths. Use `skills/zhulong/SKILL.md` as the human/runtime entrypoint and
`scripts/asr_start.sh` as the one-command launcher when you need a manual
fallback. Do not manually chain many helpers unless you are debugging a specific
stage.

## One Command Manual Fallback

If you want to bootstrap or refresh a repository manually, use the one-shot
launcher:

```bash
bash scripts/asr_start.sh --source https://github.com/owner/repo
```

Or for an existing local repository:

```bash
bash scripts/asr_start.sh --repo-root /path/to/repo
```

By default, OMC suspect teammate PIDs are recorded in workspace status and
handoff documents without an interactive pause. Add
`--prompt-runtime-pid-review` only when you want an explicit terminal review
block:

```bash
bash scripts/asr_start.sh --repo-root /path/to/repo --prompt-runtime-pid-review
```

This option prints review-only process information. It does not enable PID
cleanup or process termination.

After bootstrap, the preferred first-pass scan runner is:

```bash
bash /path/to/repo/<audit-workspace>/bin/run-initial-probes.sh --repo-root /path/to/repo
```

Before any PoC or exploit verification, enforce the Docker-only gate:

```bash
bash /path/to/repo/<audit-workspace>/bin/check-docker-gate.sh --repo-root /path/to/repo
```

If this gate fails, do not continue on the host. Keep the current progress under
`/path/to/repo/<audit-workspace>/`, inspect `<audit-workspace>/audit-log.md`,
fix Docker, and then resume the task from the same repository workspace.

## Prompt Template

The canonical short prompt template lives at:

```text
assets/references/claude-code-invocation-template.md
```

The sync script no longer writes a prompt template outside the package by
default. If you want a convenience copy, opt in explicitly:

```bash
bash scripts/sync_to_claude_skill.sh --prompt-template-output ./claude-code-zhulong-prompt-template.md
```

Maintainers working from the historical parent dogfood repository can also use:

```bash
bash scripts/sync_to_claude_skill.sh --sync-root-prompt-template
```

For standalone clones, prefer `--prompt-template-output PATH`.

## Refresh Existing Bootstrapped Repositories

If a repository already has an older audit workspace, refresh its helpers after
updating the Claude Skill:

```bash
bash scripts/refresh_workspace_helpers.sh --repo-root /path/to/repo
```

## Quick Local Verification

Run:

```bash
python3 scripts/selftest_plugin.py
```

This self-test checks that the package can be installed into a
Claude-compatible Skill layout. It also validates `.claude-plugin/plugin.json`
without requiring that manifest inside the installed Skill copy.

After syncing into Claude Code, verify the installed runtime copy too:

```bash
python3 ~/.claude/skills/zhulong/scripts/selftest_plugin.py
```

## Optional Tooling Installation

Install the first-tier recommended tools on macOS with Homebrew:

```bash
bash scripts/install_recommended_tooling.sh --tier first-tier
```

On Linux or WSL2, install optional security tools through your distribution
package manager, language ecosystem package managers, or the upstream project
instructions listed in `assets/tool-registry.json`.

## Use The Plugin Scripts Directly

Prepare a repository and run the stable first-pass helpers:

```bash
bash scripts/asr_start.sh --source https://github.com/owner/repo
bash repo/<audit-workspace>/bin/check-docker-gate.sh --repo-root repo
bash repo/<audit-workspace>/bin/run-initial-probes.sh --repo-root repo
python3 repo/<audit-workspace>/bin/validate-all-report-bundles.py --confirmed-dir repo/<audit-workspace>/confirmed
```

For GitHub targets, prefer `gh` for repository clone, advisories, issues, pull
requests, commits, and release inspection. Avoid browser-style GitHub fetches
unless `gh` is unavailable.

## Open-Source Packaging Checklist

Before publishing:

1. Verify publisher, author, developer, homepage, and repository metadata in `.claude-plugin/plugin.json` and `.codex-plugin/plugin.json`.
2. Review `README.md`, `README.zh-CN.md`, `docs/INSTALL.md`, `docs/USAGE.md`, and `CONTRIBUTING.md`.
3. Run the self-test script.
4. Verify that no local absolute paths remain in plugin docs or assets.
5. Keep the Claude plugin manifest metadata-only unless a future release intentionally adds and tests a real runtime component.
6. Run `docs/RELEASE_CHECKLIST.md` and record any release-blocking High/Medium defect before publishing.
