# Zhulong (烛龙) Plugin Package

This repository directory is a distribution package for the Zhulong (烛龙) workflow.

It includes a Codex-style plugin manifest because the package was scaffolded with a cross-agent plugin layout, but Claude Code does not directly load `.codex-plugin/plugin.json` from this repo path.

For Claude Code, the actual usable form is a skill installed under `~/.claude/skills/...`.

## Design Goals

- keep the primary audit workflow deterministic and scriptable
- keep verification Docker-only
- keep report generation and validation deterministic
- separate runtime checks, tool planning, reporting, and references into stable plugin components
- make the package easier to open-source and easier for other users to deploy

## Claude Code Compatibility

- `.codex-plugin/plugin.json` is packaging metadata, not Claude Code's native skill loading path
- Claude Code will not automatically use this repo package just because it exists under `plugins/`
- the supported Claude path is `~/.claude/skills/zhulong/`
- use the sync script below to install or refresh the Claude-native skill

```bash
bash scripts/sync_to_claude_skill.sh
```

After that, restart Claude Code or open a new Claude Code session.

## Claude Code Quick Use

After syncing, invoke it in Claude Code by explicitly asking for the `zhulong` skill.

Operational defaults to keep:

- for GitHub repository access and GitHub-side intelligence, prefer `gh` first
- for PoC execution and exploit verification, use Docker or Docker Compose only
- if Docker is unavailable, log progress to `<repo>/<audit-workspace>/audit-log.md` and pause instead of falling back to the host
- keep all audit output under `<repo>/<audit-workspace>/`, where each audit gets its own workspace such as `security-research-YYYYMMDD-HHMMSS/`
- each confirmed vulnerability bundle should include one bundle-root reproduction helper shell script for macOS and Linux
- keep `render_confirmed_vuln_docx.py` as the canonical first-pass renderer, but use Claude Code's built-in `Documents` skill for any in-place `.docx` correction or final polish
- when reviewers may ask for practical harm, exploitation path, attack success, or DoS proof, include that material explicitly in the report or bundled supplement note

Prompt template:

- `claude-code-zhulong-prompt-template.md` in the parent OSS research workspace

The prompt template is intentionally short. Durable audit rules belong in the
skill, reference contracts, renderer, and validators. A normal launch prompt only
needs the target repository and output language, for example:

```text
Please use the zhulong skill to perform end-to-end autonomous vulnerability research on this repository:
https://github.com/owner/repo

Output language: zh-CN.
```

If a rule should apply to every future audit, update
`templates/claude-skill/SKILL.md`, `assets/references/*.md`, or the relevant
validator instead of making this prompt longer.

## One-Shot Entry

If you want a manual fallback, use one command instead of multiple helper commands:

```bash
bash plugins/zhulong-plugin/scripts/asr_start.sh --source https://github.com/owner/repo
```

For an already cloned repository:

```bash
bash plugins/zhulong-plugin/scripts/asr_start.sh --repo-root /path/to/repo
```

For a stable first-pass scan pass:

```bash
bash /path/to/repo/<audit-workspace>/bin/run-initial-probes.sh --repo-root /path/to/repo
```

Before any PoC verification:

```bash
bash /path/to/repo/<audit-workspace>/bin/check-docker-gate.sh --repo-root /path/to/repo
```

## Layout

```text
zhulong-plugin/
├── .codex-plugin/plugin.json
├── README.md
├── assets/
│   ├── attacker-container/
│   ├── confirmed-vuln-report-template.docx
│   ├── examples/
│   ├── references/
│   └── tool-registry.json
├── scripts/
│   ├── bootstrap_verification_workspace.sh
│   ├── prepare_target_repo.sh
│   ├── check_omc_runtime.sh
│   ├── check_security_tooling.sh
│   ├── plan_security_toolchain.py
│   ├── render_confirmed_vuln_docx.py
│   ├── scaffold_bilingual_findings.py
│   ├── validate_report_bundle.py
│   └── validate_all_report_bundles.py
└── skills/
    └── zhulong/
        └── SKILL.md
```

## Component Boundaries

- Runtime layer:
  - `check_omc_runtime.sh`
  - `check_security_tooling.sh`
  - `asr_exec.sh`
- Planning layer:
  - `plan_security_toolchain.py`
  - `assets/tool-registry.json`
- Workspace/bootstrap layer:
  - `prepare_target_repo.sh`
  - `bootstrap_verification_workspace.sh`
- Reporting layer:
  - `render_confirmed_vuln_docx.py`
  - `scaffold_bilingual_findings.py`
  - `validate_report_bundle.py`
  - `validate_all_report_bundles.py`
- Reference layer:
  - `assets/references/*.md`

## Recommended Flow

1. Prepare or clone the target repository.
2. If it is a GitHub target, use `gh` as the default GitHub access path.
3. Do not run `web_search`, `Search(...)`, `Fetch(...)`, or `WebFetch(...)` as shell commands. Use native agent tools when available, `gh` for GitHub, or explicit HTTP tools such as `curl` for ordinary URL fallback.
4. Check OMC/runtime health.
5. Check installed security tooling.
6. Plan the repository-specific toolchain based on stack and available tools.
7. Run the Docker gate before any verification attempt.
8. Run scanning and verification only inside Docker.
9. Render confirmed vulnerability bundles.
10. Validate every final bundle.

## Before Real Project Testing

Run the plugin self-test first:

```bash
python3 plugins/zhulong-plugin/scripts/selftest_plugin.py
```

Then sync the package into Claude Code:

```bash
bash plugins/zhulong-plugin/scripts/sync_to_claude_skill.sh
```

If you already have older bootstrapped repositories, refresh their helper scripts too:

```bash
bash plugins/zhulong-plugin/scripts/refresh_workspace_helpers.sh --repo-root /path/to/repo
```

If you want the recommended first-tier optional tools:

```bash
bash plugins/zhulong-plugin/scripts/install_recommended_tooling.sh --tier first-tier
```

For the first real-world dogfood runs, do not start with broad unsupervised
scanning across many repositories. Use a staged pilot:

1. Small Docker-ready repository: validate workspace setup, attack-surface
   inventory, candidate routing, Docker gate behavior, and handoff quality.
2. Known-vulnerable benchmark or historical vulnerable revision: validate that a
   real issue can move from hypothesis to Docker evidence and then to one valid
   confirmed bundle.
3. Medium-sized OSS repository: stress-test context slimming, raw-log avoidance,
   playbook usefulness, false-positive handling, and multi-session handoff.

Dogfood success is not measured by forcing a vulnerability report. A clean "no
confirmed vulnerabilities" run is acceptable when Docker evidence does not
support any candidate. Playbooks and checklists are starting maps, not fences;
expand `attack-surface.md` whenever repository-specific code reveals frameworks,
data flows, sinks, or deployment assumptions not covered by the references.

## Minimal Commands

```bash
bash plugins/zhulong-plugin/scripts/asr_start.sh \
  --source https://github.com/owner/repo

bash repo/<audit-workspace>/bin/check-docker-gate.sh --repo-root repo
bash repo/<audit-workspace>/bin/run-initial-probes.sh --repo-root repo
python3 repo/<audit-workspace>/bin/validate-all-report-bundles.py --confirmed-dir repo/<audit-workspace>/confirmed
```

See also:

- `INSTALL.md`
- `CONTRIBUTING.md`
- `CHANGELOG.md`

## Notes For Open-Sourcing

- keep the plugin self-contained
- avoid hardcoding home-directory paths
- avoid making external MCP servers a required dependency
- treat security tools as optional capabilities discovered at runtime
- keep report generation deterministic and validate bundles before shipping
