---
name: zhulong
description: Zhulong (烛龙), a Docker-first security-focused code audit workflow with runtime checks, deterministic confirmed vulnerability bundles, and final workspace validation.
---

# Zhulong (烛龙)

Use this local-agent skill when performing repository-level security audits that preserve
candidate, verification, confirmation, packaging, and finalization boundaries.
Zhulong is a lightweight local Skill: it does not own an Agent runtime, runner,
scheduler, service, database, RAG system, MCP server, hooks, or rules engine.

## Layout and launcher

The source of truth is `skills/zhulong/` in the plugin repository. Installed
Claude and Codex directories are generated runtime copies; do not edit them as
source.

- Claude: `~/.claude/skills/zhulong/`
- Codex: `~/.agents/skills/zhulong/`
- Optional repo-scoped Codex copy: `<target-repo>/.agents/skills/zhulong/`

Use the platform-neutral launcher:

```bash
bash <skill-root>/scripts/zhulong_audit.sh --source <local-path-or-repo-url>
```

Normal use prepares the repository and timestamped
`security-research-YYYYMMDD-HHMMSS/` workspace automatically. Do not ask the
user to execute a long chain of helper commands. Use `--print-skill-root` for a
read-only layout check.

## Core Safety Invariants

These invariants apply even when no phase reference has been loaded:

1. PoCs, exploit payloads, and verification traffic run only inside Docker or
   Docker Compose. If Docker is unavailable, preserve artifacts, record the
   blocker, print a resume path, and stop verification; no host fallback is
   allowed.
2. Scanner, static, dependency, checklist, playbook, and LLM results are
   candidate-only. They never become confirmed findings without independent
   Docker reproduction.
3. Confirmed requires a real attacker-controlled entrypoint, accepted input
   shape, entrypoint-to-sink path, deterministic Docker oracle, independent
   verifier verdict, confirmed disposition, and a validated final bundle.
4. Blocked verification is not `completed_no_confirmed_findings`. Material
   Docker/runtime/entrypoint blockers remain blocked or unverified.
5. Bind every claim to the exact tested source ref. Source-bound validity and
   fixture provenance cap impact: synthetic identity, privilege, secrets,
   sensitive objects, ownership, or deployment properties do not prove the same
   upstream property.
6. `rejected_unsafe_sandbox` never enters `confirmed/`; rewrite the case and
   rerun the sandbox and Docker gates.
7. Never use broad Docker prune, rewrite a Docker baseline to hide residue, or
   automatically signal/kill teammate PIDs. Clean only exact audit-owned,
   labeled resources after review. Teammate PID cleanup is review-only.
8. Severity escalation and seeded variant discovery are separate required
   passes after the first confirmation; neither substitutes for the other.
9. Each variant remains a candidate until its own Docker reproduction,
   independent verdict/disposition, and separate validated confirmed bundle.
10. Final bundles use contract-first staging under
    `confirmed/.staging/<slug>`, final validation, batch validation, and atomic
    promotion. Do not hand-create final `confirmed/<slug>/` directories.
11. Only the canonical finalization gate and event establish completion.
    Editing `SUMMARY.md`, handoff text, checkpoints, next-actions, or state views
    cannot create a final result.
12. Recording is an opt-in post-bundle gate. Recording failure must roll back
    recording-only staging without damaging the original validated bundle.
13. Context plans, handoffs, checkpoints, and next-actions are advisory. They
    provide no read, execution, evidence, candidate, verdict, disposition,
    bundle, recording, promotion, completion, or gate-bypass authority.
14. Confirmed bundles must not leak local absolute paths, `file://` URLs,
    workspace names, private material, credentials, or unpublished public-issue
    details. Reviewer-facing paths stay bundle-relative.

False positives, non-security defects, hardening observations, and unverified
leads stay in workspace notes outside `confirmed/`. Partial bundles, Docker
evidence without a valid bundle, and blocked work must be described
conservatively and never as completed confirmed deliverables.

## Lifecycle and phase boundaries

Zhulong records evidence and decisions; the local Agent remains responsible for
choosing and executing work. The compact lifecycle is:

1. **Intake and Recon** — prepare the repository, bind the exact target identity,
   map entrypoints/trust boundaries/sinks, and validate `recon-result.json`.
2. **Candidate and triage** — record candidate-only leads, stable R2 identity and
   provenance, advisory deduplication, and a bounded triage batch.
3. **Verification and severity** — pass runtime and sandbox gates, reproduce the
   real entrypoint in Docker, obtain an independent verdict, then run a distinct
   Docker severity-escalation pass.
4. **Seeded variant discovery** — derive a valid seed from a validated bundle,
   find same-repository candidates offline, and verify every candidate
   independently.
5. **Packaging and finalization** — validate the bundle contract, build in
   staging, validate/promote/batch-check bundles, clean exact audit-owned Docker
   resources, and emit the canonical finalization event.
6. **Recording** — only when requested, validate identity-bound replay, visual,
   checkpoint, and archive evidence without mutating the source bundle.

Candidate → verifier verdict → disposition → confirmed bundle validation →
workspace finalization remains the authority chain. A stage result, context
plan, handoff, or summary never replaces it.

## Context planning and phase references

Generate a deterministic advisory context plan with:

```bash
python3 <skill-root>/scripts/plan_audit_context.py \
  --skill-root <skill-root> \
  --repo-root <repo-root> \
  --phase <phase> \
  --output <audit-workspace>/context-plan.json
```

Validate it with `scripts/validate_context_plan.py`. `mandatory` means planned
reading priority only; it does not prove an Agent read, understood, used, or
completed a reference. The catalog is advisory and cannot grant execution or
confirmation authority.

Stable phase entrypoints:

- `assets/references/audit-phase-intake-recon.md`
- `assets/references/audit-phase-candidate-triage.md`
- `assets/references/audit-phase-verification.md`
- `assets/references/audit-phase-variant-discovery.md`
- `assets/references/audit-phase-packaging-finalization.md`
- `assets/references/audit-phase-recording.md`
- `assets/references/audit-continuation-state.md`

Use catalog-selected language playbooks and vulnerability checklists only as
starting maps. They are not exhaustive and cannot narrow repository-specific
exploration or confirm a vulnerability.

## Confirmed bundle path

Before creating `confirmed/<slug>`, validate
`confirmed/.contracts/<slug>.bundle-contract.json` with the real target
repository:

```bash
python3 <skill-root>/scripts/validate_bundle_contract.py \
  --repo-root <repo-root> \
  --workspace-dir <audit-workspace> \
  --contract <audit-workspace>/confirmed/.contracts/<slug>.bundle-contract.json \
  --all-errors

python3 <skill-root>/scripts/build_confirmed_bundle.py \
  --repo-root <repo-root> \
  --workspace-dir <audit-workspace> \
  --contract <audit-workspace>/confirmed/.contracts/<slug>.bundle-contract.json \
  --language <zh-CN|en-US>
```

The builder renders into `confirmed/.staging/<slug>`, applies the final
validator, promotes only valid output, and runs
`validate_all_report_bundles.py`. Contract preflight and
`validate_report_bundle.py --all-errors` are diagnostics/workflow gates only;
Docker evidence and final bundle validation remain required.

Each final directory contains exactly one confirmed vulnerability and its
portable DOCX, attachment index, reproduction supplement,
`verification-evidence.json`, `attachments/`, and bundle-root replay helper.
Recording and seeded-variant candidates are never substitutes for this path.

## Finalization and continuation

The append-only `audit-events.jsonl` is authoritative;
`stage-status.json`, `handoff-state.json`, checkpoints, handoff summaries, and
next-actions are derived views. Diagnose or explicitly rebuild a stale state view
through `scripts/recover_audit_state.py`; never rewrite the journal.
For offline review, `render_audit_timeline.py` and `validate_audit_timeline.py`
produce and check a static, derived-only timeline with no execution authority.

Before finalization:

- run `validate_all_report_bundles.py`;
- complete seeded variant discovery when valid confirmed bundles exist;
- review and strictly verify audit-owned Docker resource cleanup;
- keep blocked verification distinct from a clean no-confirmed result.

Finalize with `scripts/finalize_audit_workspace.py` and verify integrity with
`scripts/assert_finalized_workspace.py`. A failed or absent canonical event
means the workspace is not finalized.

## Recording boundary

Recording begins only from a validated confirmed bundle and only when requested.
Validate `recording-evidence.json` through
`scripts/validate_recording_evidence.py`. Replay logs must be real
command/output/oracle transcripts; visual pause variables are not readiness
timers. Failure preserves the original bundle and remains a recording failure,
not a vulnerability or bundle failure.

## Output and maintenance

Use `zh-CN` when the user communicates primarily in Chinese; use `en-US`
otherwise. Keep CLI, schema fields, issue codes, filenames, and functional
scripts in concise ASCII English.

The machine-auditable carrier map is
`assets/root-skill-rule-inventory.json`; validate it with
`scripts/validate_root_skill_rule_inventory.py`. Detailed contracts live under
`docs/runner-contracts/`. Update source and template Skills together and keep
them byte-identical through the sync and three-layout selftests.
