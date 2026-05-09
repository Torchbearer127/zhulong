# Agent Maintenance Guide

This file is for Codex, Claude Code, Cursor, Gemini CLI, and other local AI
coding agents that are asked to maintain Zhulong.

If you are an agent working on this repository, read this file before editing
source code, prompts, scripts, templates, validators, or release docs.

## Source Of Truth

- The canonical source tree is this repository root: `zhulong/`.
- The installed Claude-compatible skill at `~/.claude/skills/zhulong/` is a
  synced runtime copy, not the source of truth.
- `.claude-plugin/plugin.json` and `.codex-plugin/plugin.json` are package
  metadata. They must not introduce required hooks, MCP servers, apps, agents,
  commands, daemons, dashboards, databases, or platform services.
- Generated `security-research-*` workspaces inside audited target repositories
  are outputs. Do not patch only a generated workspace and call the product bug
  fixed.

## Product Positioning

Describe Zhulong as a lightweight, Docker-first, security-focused code audit
workflow for local agents.

Do not describe it as only a vulnerability scanner, a hosted platform, a RAG
system, a dashboard product, an exploit automation framework, or a guaranteed
0-day finder.

Zhulong may track confirmed vulnerabilities, candidates, false positives,
non-security defects, hardening-only observations, blocked verification, and
unverified leads. Only Docker-reproduced and bundle-validated vulnerabilities
enter `confirmed/`.

## Ownership Model

- `skills/zhulong/SKILL.md` owns the agent-facing entry point.
- `templates/claude-skill/SKILL.md` owns the installed skill template.
- `assets/references/*.md` owns detailed behavior contracts and playbooks.
- `scripts/*.py` and `scripts/*.sh` own deterministic checks, helpers, gates,
  validators, rendering, cleanup, and finalization.
- `scripts/validate_report_bundle.py` owns confirmed bundle validation.
- `scripts/audit_disposition.py` owns disposition ledger validation.
- `scripts/manage_docker_resources.py` owns Docker baseline, cleanup planning,
  exact adoption, and strict hygiene.
- `scripts/check_omc_runtime.sh` owns OMC/runtime hygiene. Teammate PIDs are
  review-only.

Do not solve recurring behavior problems by expanding launch prompts. If a rule
must apply to every audit, encode it in the skill, reference docs, scripts,
validators, or selftests.

## Non-Negotiable Invariants

- PoC and exploit verification must stay Docker-only.
- Docker unavailable means pause and preserve artifacts, not host fallback.
- Scanner-only, dependency-only, static-only, LLM-only, blocked, timed-out,
  rejected unsafe sandbox, or dirty-Docker results must not enter `confirmed/`.
- Docker-applicable confirmed findings require Docker reproduction.
- `rejected_unsafe_sandbox` is a safety blocker, not vulnerability evidence.
- Confirmed bundles must preserve the existing one-folder-per-vulnerability
  contract, including DOCX report, reproduction supplement, attachment index,
  `verification-evidence.json`, attachments, and bundle-root reproduction
  helper script.
- Confirmed reports must include attacker condition, server condition, and
  concrete CIA or equivalent security impact.
- Docker residue and OMC/runtime residue must stay separate.
- OMC teammate PID handling is review-only. Do not add PID signaling, broad
  teammate process cleanup, automatic hard-kill escalation, or Docker cleanup
  coupling.
- Docker cleanup must be label-aware, baseline-aware, and exact-adoption only.
  Do not add wildcard, prefix, regex, label-selector, or "all" adoption.
- Do not add broad Docker-wide cleanup commands such as `docker system pr[u]ne`,
  `docker builder pr[u]ne`, or `docker buildx pr[u]ne` as normal cleanup
  guidance.
- Late Docker baseline overwrite must not hide post-baseline residue.
- Finalization must recompute strict Docker cleanliness and must not trust stale
  cleanliness status files.
- Do not introduce required backend services, dashboards, databases, vector DBs,
  RAG platforms, Discord/Notion integrations, MCP servers, hooks, or long-lived
  orchestration services.
- Do not hardcode machine-local paths, user-specific usernames, or stale package
  names in public source, docs, templates, or generated outputs.

If a requested change conflicts with these invariants, stop and redesign the
change.

## Safe Development Loop

Run from the repository root:

```bash
python3 scripts/selftest_plugin.py
```

If skill-facing files changed, sync and test the installed layout:

```bash
bash scripts/sync_to_claude_skill.sh
python3 ~/.claude/skills/zhulong/scripts/selftest_plugin.py
```

If report rendering or confirmed bundle logic changed, validate affected
bundles:

```bash
python3 scripts/validate_report_bundle.py --bundle-dir <bundle-dir>
python3 scripts/validate_all_report_bundles.py --confirmed-dir <confirmed-dir>
```

Before a release, run through:

- `../CONTRIBUTING.md`
- [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md)

## Common Change Areas

When fixing a product bug, patch the canonical source area:

- Workspace creation or path bugs: `scripts/asr_start.sh`,
  `scripts/prepare_target_repo.sh`, workspace helper scripts.
- Docker cleanup or residue bugs: `scripts/manage_docker_resources.py`,
  finalization/assertion scripts, Docker hygiene references.
- Unsafe verification container bugs: `scripts/check_sandbox_preflight.py`,
  `scripts/run_verification_case.sh`.
- Ledger/finalization bugs: `scripts/audit_disposition.py`,
  `scripts/finalize_audit_workspace.py`,
  `scripts/assert_finalized_workspace.py`.
- Report or bundle bugs: `scripts/render_confirmed_vuln_docx.py`,
  `scripts/validate_report_bundle.py`,
  `assets/references/confirmed-vuln-docx-format.md`.
- Agent behavior or prompt contract bugs: `skills/zhulong/SKILL.md`,
  `templates/claude-skill/SKILL.md`, `assets/references/*.md`.
- Packaging docs or manifests: `.claude-plugin/plugin.json`,
  `.codex-plugin/plugin.json`, `README.md`, `README.zh-CN.md`, `docs/INSTALL.md`.

## Recommended Agent Prompt

Use a prompt like this when asking an AI coding agent to modify Zhulong:

```text
You are maintaining Zhulong.
Read docs/AGENTS.md, CONTRIBUTING.md, and docs/RELEASE_CHECKLIST.md first.
Keep the change narrow.
Do not weaken confirmed-only, Docker-first, Docker hygiene, OMC PID safety,
sandbox preflight, finalization, or confirmed bundle contracts.
After editing, run the relevant selftests and report exactly what changed.
```
