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

The plugin source tree is the source of truth. Installed Claude and Codex skill
directories are generated runtime copies. See
[`docs/CODEX_SKILL_ADAPTATION.md`](CODEX_SKILL_ADAPTATION.md) for the source,
Claude installed, and Codex installed layout contract.

## Platform Support

Zhulong is designed around Bash, Python helper scripts, and Docker-first
verification. Use it from a Unix-like shell.

| Platform | Recommended path | Notes |
| --- | --- | --- |
| macOS | Supported and dogfooded | Install Python 3.11+, Docker Desktop or another Docker Engine, and run the sync commands below. |
| Linux | Supported target path | Install Python 3.11+, Docker Engine, Docker Compose, Bash, and run the same commands below. |
| Windows | Use WSL2 | Run Zhulong inside WSL2 with Docker Desktop WSL integration enabled. Keep working repositories on the WSL filesystem when possible. Native PowerShell/CMD execution is not a first-class supported path yet. |

If your local agent uses a non-default skill directory, set
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

If a skill already exists there, the script backs it up automatically before
replacing it.

This is a stable runtime path for Claude Code because it loads the `SKILL.md`
instructions and helper scripts directly from the installed skill.

## Install Into Codex

From the package root:

```bash
python3 scripts/selftest_plugin.py
bash scripts/sync_to_codex_skill.sh
python3 ~/.agents/skills/zhulong/scripts/selftest_plugin.py
```

The default target is:

```text
~/.agents/skills/zhulong/
```

Codex user-level skills are supported through this installed layout.

If a skill already exists there, the script moves it to a hidden sibling backup
directory under:

```text
~/.agents/skills/.zhulong-backups/
```

Use `--codex-skills-dir DIR` when testing a repo-scoped or temporary Codex
skills root. For a repo-scoped install, point it at that repository's Codex
skills root:

```bash
bash scripts/sync_to_codex_skill.sh --codex-skills-dir /path/to/repo/.agents/skills
```

Do not hand-edit installed Codex skill directories as source. Edit this plugin
source tree, keep `skills/zhulong/SKILL.md` and
`templates/claude-skill/SKILL.md` identical, then resync.

When working from this source checkout, repo-root `AGENTS.md` may point Codex to
`$zhulong`; installed skill behavior is still owned by `SKILL.md`.

### Option B: Use The Plugin-Style Package

For packaging or discovery workflows that understand Claude plugin-style
packages, point them at this package root:

```text
zhulong/
```

The manifest points to `./skills`, `./scripts`, and `./assets` with relative
paths. Use `skills/zhulong/SKILL.md` as the human/runtime entrypoint and
`scripts/zhulong_audit.sh` as the platform-neutral launcher when you need a
manual fallback. Do not manually chain many helpers unless you are debugging a
specific stage.

## One Command Manual Fallback

If you want to bootstrap or refresh a repository manually, use the one-shot
launcher:

```bash
bash scripts/zhulong_audit.sh --source https://github.com/owner/repo
```

Or for an existing local repository:

```bash
bash scripts/zhulong_audit.sh --repo-root /path/to/repo
```

By default, OMC suspect teammate PIDs are recorded in workspace status and
handoff documents without an interactive pause. Add
`--prompt-runtime-pid-review` only when you want an explicit terminal review
block:

```bash
bash scripts/zhulong_audit.sh --repo-root /path/to/repo --prompt-runtime-pid-review
```

This option prints review-only process information. It does not enable PID
cleanup or process termination.

To inspect which source or installed skill copy the wrapper will use, run:

```bash
bash scripts/zhulong_audit.sh --print-skill-root
```

From an installed skill, use the same relative form under that skill root:

```bash
bash <skill-root>/scripts/zhulong_audit.sh --source https://github.com/owner/repo
```

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

This self-test checks that the package can be installed into Claude-compatible
and Codex-compatible skill layouts. It also validates plugin manifests without
requiring those manifests inside installed skill copies.

After syncing into Claude Code, verify the installed runtime copy too:

```bash
python3 ~/.claude/skills/zhulong/scripts/selftest_plugin.py
```

After syncing into Codex, verify that installed runtime copy too:

```bash
python3 ~/.agents/skills/zhulong/scripts/selftest_plugin.py
```

Installed selftests validate layout without Docker, network access, PoC
execution, package registry calls, GitHub search, LLM calls, or Codex execution.

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
bash scripts/zhulong_audit.sh --source https://github.com/owner/repo
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
2. Review `README.md`, `README.zh-CN.md`, `docs/INSTALL.md`, `docs/USAGE.md`, `docs/CODEX_SKILL_ADAPTATION.md`, and `CONTRIBUTING.md`.
3. Run the self-test script.
4. Verify that no local absolute paths remain in plugin docs or assets.
5. Keep the Claude plugin manifest metadata-only unless a future release intentionally adds and tests a real runtime component.
6. Run `docs/RELEASE_CHECKLIST.md` and record any release-blocking High/Medium defect before publishing.
