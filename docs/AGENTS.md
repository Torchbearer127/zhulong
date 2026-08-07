# Agent Maintenance Guide

This file is for Codex, Claude Code, Cursor, Gemini CLI, and other local AI
coding agents that are asked to maintain Zhulong.

The repo-root `AGENTS.md` is only a quick instruction shim. This document remains
the maintainer guide and source-maintenance rule set.

If you are an agent working on this repository, read this file before editing
source code, prompts, scripts, templates, validators, or release docs.

## Source Of Truth

- The canonical source tree is this repository root: `zhulong/`.
- The installed Claude-compatible skill at `~/.claude/skills/zhulong/` is a
  synced runtime copy, not the source of truth.
- The installed Codex user skill at `~/.agents/skills/zhulong/` and any optional
  repo-scoped Codex skill at `<target-repo>/.agents/skills/zhulong/` are also
  generated/synced runtime copies, not source.
- `scripts/zhulong_audit.sh` is the platform-neutral terminal launcher. It
  resolves its skill/package root through `scripts/resolve_skill_root.sh` and
  delegates to `scripts/asr_start.sh`.
- The Codex adaptation contract lives in
  [`CODEX_SKILL_ADAPTATION.md`](CODEX_SKILL_ADAPTATION.md). Keep source,
  Claude installed, and Codex installed layout changes aligned with that
  contract.
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
unverified leads. A Docker-applicable vulnerability enters `confirmed/` only
after attacker-entrypoint reproduction, source-bound validity and severity
checks, and final bundle validation all pass.

## Ownership Model

- `skills/zhulong/SKILL.md` owns the agent-facing entry point.
- `templates/claude-skill/SKILL.md` owns the installed skill template.
- `assets/references/*.md` owns detailed behavior contracts and playbooks.
- `scripts/*.py` and `scripts/*.sh` own deterministic checks, helpers, gates,
  validators, rendering, cleanup, and finalization.
- `scripts/validate_report_bundle.py` owns confirmed bundle validation.
- `scripts/validate_bundle_contract.py` owns generation-contract preflight;
  `scripts/build_confirmed_bundle.py` owns validated staging and atomic
  promotion into `confirmed/`.
- `scripts/validate_candidate.py`, `scripts/verify_candidate.py`, and
  `scripts/validate_verifier_verdict.py` own the candidate and independent
  verifier evidence-level contracts. They do not replace Docker execution.
- `scripts/candidate_identity.py`, the explicit upgrade helper, and candidate
  dedup plan builder/validator own Candidate R2 identity, provenance, and
  candidate-only duplicate advice. They have no verifier or promotion authority.
- `scripts/audit_disposition.py` owns disposition ledger validation.
- `scripts/finalize_audit_workspace.py` and
  `scripts/assert_finalized_workspace.py` own final workspace and handoff/status
  consistency checks.
- `scripts/extract_variant_seed.py`, `scripts/find_variant_candidates.py`, and
  their validators own confirmed-seed-based same-repository candidate analysis.
- `scripts/recording_identity.py`, `scripts/auto_record_bundle.py`, and
  `scripts/validate_recording_evidence.py` own the optional final recording
  path. Recording readiness is separate from ordinary confirmed status.
- `scripts/manage_docker_resources.py` owns Docker baseline, cleanup planning,
  exact adoption, and strict hygiene.
- `scripts/check_omc_runtime.sh` owns OMC/runtime hygiene. Teammate PIDs are
  review-only.
- `assets/tool-registry.json`, its strict schema, and
  `scripts/validate_tool_registry.py` own the local tool-effects contract for
  the planner and named controlled wrappers. They do not sandbox native Agent
  tools or replace candidate, verifier, disposition, or bundle gates.

Do not solve recurring behavior problems by expanding launch prompts. If a rule
must apply to every audit, encode it in the skill, reference docs, scripts,
validators, or selftests.

## Non-Negotiable Invariants

- PoC and exploit verification must stay Docker-only.
- Docker unavailable means pause and preserve artifacts, not host fallback.
- Scanner-only, dependency-only, static-only, LLM-only, blocked, timed-out,
  rejected unsafe sandbox, or dirty-Docker results must not enter `confirmed/`.
- Docker-applicable confirmed findings require Docker reproduction.
- Code-level reproduction, blocked entrypoint verification, candidate ranking,
  and finder wording are supporting material only. They cannot promote a
  finding or create a confirmed bundle.
- Confirmation requires source-bound attacker entrypoint, path and token
  fidelity, validity, evidence-bounded classification and severity, and a
  deterministic impact oracle. Synthetic fixture properties cannot support
  stronger real-world impact claims.
- `rejected_unsafe_sandbox` is a safety blocker, not vulnerability evidence.
- Confirmed bundles must preserve the existing one-folder-per-vulnerability
  contract, including DOCX report, reproduction supplement, attachment index,
  `verification-evidence.json`, attachments, and bundle-root reproduction
  helper script.
- Confirmed reports must include attacker condition, server condition, and
  concrete CIA or equivalent security impact.
- New confirmed bundles must be rendered under `confirmed/.staging/`, pass
  final validation there, and be atomically promoted. Failed staging output is
  not a confirmed deliverable.
- Handoff and status claims must be derived from validated artifacts. A
  directory count, Docker evidence alone, or code-level reproduction must not
  be described as confirmed-bundle completion.
- Formal same-repository variant analysis starts only from a validated
  confirmed bundle. Every resulting lead remains a candidate until it completes
  its own Docker reproduction and confirmed-bundle validation.
- Final screen recording is opt-in. Recording identity, final-video-derived
  screenshots, archive integrity, and transactional promotion are required only
  when recording-ready or submission-ready delivery is requested; they do not
  redefine ordinary confirmed status.
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
bash scripts/sync_to_codex_skill.sh
python3 ~/.agents/skills/zhulong/scripts/selftest_plugin.py
```

If report rendering or confirmed bundle logic changed, validate affected
bundles:

```bash
python3 scripts/validate_report_bundle.py --bundle-dir <bundle-dir>
python3 scripts/validate_all_report_bundles.py --confirmed-dir <confirmed-dir>
```

For new bundle generation, validate the contract against the real target
repository and use the staging builder rather than writing a final directory by
hand:

```bash
python3 scripts/validate_bundle_contract.py \
  --repo-root <target-repository> \
  --workspace-dir <audit-workspace> \
  --contract <bundle-contract>
python3 scripts/build_confirmed_bundle.py \
  --repo-root <target-repository> \
  --workspace-dir <audit-workspace> \
  --contract <bundle-contract> \
  --language <zh-CN|en-US>
```

If optional final recording behavior changed, run the recording evidence tests
and validate a sanitized recording fixture. Do not operate OBS, Terminal, a real
PoC, Docker, or the network from deterministic selftests.

Before a release, run through:

- `../CONTRIBUTING.md`
- [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md)

## Common Change Areas

When fixing a product bug, patch the canonical source area:

- Workspace creation or path bugs: `scripts/asr_start.sh`,
  `scripts/zhulong_audit.sh`, `scripts/resolve_skill_root.sh`,
  `scripts/prepare_target_repo.sh`, workspace helper scripts.
- Docker cleanup or residue bugs: `scripts/manage_docker_resources.py`,
  finalization/assertion scripts, Docker hygiene references.
- Unsafe verification container bugs: `scripts/check_sandbox_preflight.py`,
  `scripts/run_verification_case.sh`.
- Ledger/finalization bugs: `scripts/audit_disposition.py`,
  `scripts/finalize_audit_workspace.py`,
  `scripts/assert_finalized_workspace.py`.
- Candidate/verifier evidence-level bugs: `scripts/validate_candidate.py`,
  `scripts/verify_candidate.py`, `scripts/validate_verifier_verdict.py`,
  finding-contract schemas and examples.
- Report, contract, or bundle promotion bugs:
  `scripts/validate_bundle_contract.py`,
  `scripts/build_confirmed_bundle.py`,
  `scripts/render_confirmed_vuln_docx.py`,
  `scripts/validate_report_bundle.py`,
  `assets/references/confirmed-vuln-docx-format.md`.
- Same-repository variant-analysis bugs: `scripts/extract_variant_seed.py`,
  `scripts/find_variant_candidates.py`, their validators and schemas.
- Final recording bugs: `scripts/recording_identity.py`,
  `scripts/auto_record_bundle.py`, `scripts/validate_recording_evidence.py`,
  the recording schema and sanitized fixtures.
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
sandbox preflight, source binding, evidence levels, staging promotion,
finalization, handoff consistency, or confirmed bundle contracts.
After editing, run the relevant selftests and report exactly what changed.
```
