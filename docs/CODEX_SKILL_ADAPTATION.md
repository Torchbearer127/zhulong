# Codex Skill Support Contract

This document describes Zhulong's tested Codex skill support. It defines the
layout and synchronization rules for source, Claude installed, and Codex
installed skill copies. The current Codex support path does not add a hook, MCP
server, daemon, background service, or new confirmed-bundle format.

## Scope

Zhulong remains a lightweight local-agent workflow with Docker-first
verification, confirmed-only vulnerability deliverables, deterministic bundle
validation, and no required hosted platform.

This contract covers only:

- the canonical source tree
- Claude installed skill layout
- Codex installed skill layout and user-level sync
- platform-neutral launcher and skill-root resolver behavior
- sync inclusion and exclusion boundaries
- selftest expectations
- maintenance expectations

It does not change the confirmed bundle directory structure, weaken the
`confirmed/` contract, or permit host-side PoC execution.

## Codex Facts Used

This contract relies on these Codex facts, checked against the Codex manual on
2026-06-15:

- A Codex skill is a directory containing `SKILL.md` plus optional
  `scripts/`, `references/`, `assets/`, or similar support files.
- `SKILL.md` must include `name` and `description`.
- Codex supports explicit skill invocation with `/skills` or `$skill-name`, and
  implicit invocation through the skill `description`.
- Codex reads repository skills from `.agents/skills` in each directory from
  the current working directory up to the repository root.
- Codex reads user skills from `$HOME/.agents/skills`.
- Codex reads admin skills from `/etc/codex/skills`.
- Codex supports symlinked skill folders.
- Plugins are a distribution unit for reusable skills, apps, and MCP, but local
  skills are the tested path for Zhulong's current Codex support.
- `AGENTS.md` is a project/global instruction surface, not a replacement for
  the reusable Zhulong skill contract.

If any of these facts are suspected to have changed, verify only against
official OpenAI Codex documentation before changing this contract.

## Source Of Truth

The plugin source tree is canonical:

```text
zhulong/
├── skills/zhulong/
├── templates/claude-skill/
├── scripts/
├── assets/
└── docs/
```

Installed skill directories are generated copies or symlink targets. They are
runtime layouts, not source. Do not edit an installed Claude or Codex skill and
treat that edit as a product change. Change the plugin source tree first, then
sync or reinstall.

The two source skill entrypoints must stay identical until a future phase
deliberately splits platform-specific wording:

```bash
diff -u skills/zhulong/SKILL.md templates/claude-skill/SKILL.md
```

## Supported Layout Targets

Zhulong supports these layouts:

| Layout | Path | Status |
| --- | --- | --- |
| Source skill | `skills/zhulong/` | Canonical source. |
| Claude installed skill | `~/.claude/skills/zhulong/` | Current stable installed runtime. |
| Codex user skill | `~/.agents/skills/zhulong/` | Tested user-level sync target. |
| Codex repo-scoped skill | `<target-repo>/.agents/skills/zhulong/` | Optional target for repository-specific testing. |

The Codex repo-scoped target is for a target repository that should carry the
skill locally. It must not be confused with generated
`security-research-*` audit workspaces.

Codex also supports admin skills under `/etc/codex/skills`, but Zhulong does not
make an admin install path part of the current MVP.

## Repo-Root AGENTS Shim

The plugin source root includes `AGENTS.md` as a short source-checkout
instruction shim. Its job is to point maintainers to `docs/AGENTS.md` and point
security-audit requests toward `$zhulong`; installed Claude and Codex skill
behavior remains owned by `SKILL.md`.

Do not copy repo-root `AGENTS.md` into installed skill directories as a source
of truth. Sync scripts should continue to copy the skill runtime materials
documented below.

## Platform-Neutral Launcher

The package includes these scripts in the source tree and in installed
Claude/Codex skill copies:

- `scripts/resolve_skill_root.sh`
- `scripts/zhulong_audit.sh`

The resolver derives the package or installed skill root from its own script
location. It does not require Git, network access, Docker, Codex, Claude Code,
or parent-directory probing beyond the script's parent root.

Use the wrapper as the user-facing terminal entrypoint:

```bash
bash <skill-root>/scripts/zhulong_audit.sh --source <local-path-or-repo-url>
bash <skill-root>/scripts/zhulong_audit.sh --repo-root <repo-root>
```

From an already-open source checkout, this is equivalent to:

```bash
bash scripts/zhulong_audit.sh --source <local-path-or-repo-url>
```

The wrapper delegates to `<skill-root>/scripts/asr_start.sh` and preserves all
user arguments. The diagnostic command is safe and must not start an audit,
clone repositories, run Docker, run Codex, or execute PoCs:

```bash
bash <skill-root>/scripts/zhulong_audit.sh --print-skill-root
```

## Sync Inclusion Boundary

Sync implementations must copy or link only the skill runtime materials needed
for source, Claude installed, and Codex installed selftests:

- `SKILL.md`
- `scripts/`
- `assets/`
- required reference docs used by the skill, including relevant files under
  `docs/`
- package README or install notes when selftest or operator handoff relies on
  them

Repo-root `AGENTS.md` is intentionally outside this installed skill runtime
boundary.

Installed copies must include the scripts and assets required by
`scripts/selftest_plugin.py`, `scripts/resolve_skill_root.sh`,
`scripts/zhulong_audit.sh`, bundle validation, Docker gates, workspace
finalization, report rendering, and seeded variant helper validation.

## Sync Exclusion Boundary

Sync implementations must not copy:

- outer workspace `prompts/`
- real dogfood target repositories or workspaces
- generated `security-research-*` audit workspaces
- confirmed real vulnerability bundles
- historical `已提交/` materials
- `.codex`, `.claude`, `.omc`, agent logs, chat exports, caches, credentials,
  secrets, or tokens
- machine-local absolute paths or private target details
- source-control internals from target repositories

This exclusion boundary applies equally to Claude installed and Codex installed
layouts.

## Selftest Contract

The source selftest remains mandatory:

```bash
python3 scripts/selftest_plugin.py
```

The Claude installed selftest remains mandatory after syncing:

```bash
bash scripts/sync_to_claude_skill.sh
python3 ~/.claude/skills/zhulong/scripts/selftest_plugin.py
```

The Codex installed selftest is mandatory after syncing:

```bash
bash scripts/sync_to_codex_skill.sh
python3 ~/.agents/skills/zhulong/scripts/selftest_plugin.py
```

The Codex installed selftest validates layout without requiring Docker, PoC
execution, network access, package registry calls, GitHub search, LLM calls, or
running Codex itself. The Codex installed selftest verifies:

- installed `SKILL.md` exists and has the required frontmatter
- required `scripts/` and `assets/` files are present
- `scripts/resolve_skill_root.sh` prints the installed skill root
- `scripts/zhulong_audit.sh --print-skill-root` prints the installed skill root
- required reference docs are present
- excluded workspace material is absent
- no machine-local absolute paths or stale private target names are present
- no broad Docker prune guidance or PID kill behavior is introduced
- repo-root `AGENTS.md` remains a source-checkout shim and is not copied into
  installed skill directories

Selftests should remain deterministic, local, and fast. They validate packaging
and layout; they do not validate real vulnerability discovery.

## Current Support Status

Current Codex support status:

1. Layout contract is implemented.
2. Codex sync and Codex installed selftest are implemented.
3. Platform-neutral launcher and skill-root resolver are implemented so
   docs and prompts do not need to hardcode a Claude-only path.
4. Repository-root `AGENTS.md` points Codex toward
   `$zhulong` without copying the full skill contract into project rules.
5. Source, Claude installed, and Codex installed regression checks are part of
   release validation.

Do not introduce a required Codex plugin, hook, rule, MCP server, marketplace
workflow, daemon, scheduler, queue, database, dashboard, or Docker socket
profile as part of this MVP.
