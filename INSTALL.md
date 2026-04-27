# Install

## What This Directory Is

This repository already contains the plugin package in:

```text
plugins/zhulong-plugin/
```

The local marketplace entry lives in:

```text
.agents/plugins/marketplace.json
```

That marketplace metadata is useful for packaging and future distribution, but Claude Code itself still loads skills from `~/.claude/skills/`.

## Install Into Claude Code

Sync the package into Claude's native skill directory:

```bash
bash plugins/zhulong-plugin/scripts/sync_to_claude_skill.sh
```

The default target is:

```text
~/.claude/skills/zhulong/
```

If a skill already exists there, the script backs it up automatically before replacing it.

## One Command Manual Fallback

If you want to bootstrap or refresh a repository manually, use the one-shot launcher:

```bash
bash plugins/zhulong-plugin/scripts/asr_start.sh --source https://github.com/owner/repo
```

Or for an existing local repository:

```bash
bash plugins/zhulong-plugin/scripts/asr_start.sh --repo-root /path/to/repo
```

After bootstrap, the preferred first-pass scan runner is:

```bash
bash /path/to/repo/<audit-workspace>/bin/run-initial-probes.sh --repo-root /path/to/repo
```

Before any PoC or exploit verification, enforce the Docker-only gate:

```bash
bash /path/to/repo/<audit-workspace>/bin/check-docker-gate.sh --repo-root /path/to/repo
```

If this gate fails, do not continue on the host. Keep the current progress under `/path/to/repo/<audit-workspace>/`, inspect `<audit-workspace>/audit-log.md`, fix Docker, and then resume the task from the same repository workspace.

## Refresh Existing Bootstrapped Repositories

If a repository already has an older audit workspace, refresh its helpers after updating the Claude skill:

```bash
bash plugins/zhulong-plugin/scripts/refresh_workspace_helpers.sh --repo-root /path/to/repo
```

## Quick Local Verification

Run:

```bash
python3 plugins/zhulong-plugin/scripts/selftest_plugin.py
```

This self-test now also checks that the package can be installed into a Claude-compatible skill layout.

## Optional Tooling Installation

Install the first-tier recommended tools on macOS with Homebrew:

```bash
bash plugins/zhulong-plugin/scripts/install_recommended_tooling.sh --tier first-tier
```

## Use The Plugin Scripts Directly

Prepare a repository and run the stable first-pass helpers:

```bash
bash plugins/zhulong-plugin/scripts/asr_start.sh --source https://github.com/owner/repo
bash repo/<audit-workspace>/bin/check-docker-gate.sh --repo-root repo
bash repo/<audit-workspace>/bin/run-initial-probes.sh --repo-root repo
python3 repo/<audit-workspace>/bin/validate-all-report-bundles.py --confirmed-dir repo/<audit-workspace>/confirmed
```

For GitHub targets, prefer `gh` for repository clone, advisories, issues, pull requests, commits, and release inspection. Avoid browser-style GitHub fetches unless `gh` is unavailable.

## Open-Source Packaging Checklist

Before publishing:

1. Replace placeholder URLs and maintainer metadata in `.codex-plugin/plugin.json`.
2. Review `README.md`, `INSTALL.md`, and `CONTRIBUTING.md`.
3. Run the self-test script.
4. Verify that no local absolute paths remain in plugin docs or assets.
