# Zhulong Agent Shim

This root file is a lightweight instruction shim for Codex and other local
agents working inside the Zhulong plugin source tree.

## Maintaining Zhulong

Before editing Zhulong itself, read `docs/AGENTS.md`, `CONTRIBUTING.md`, and
`docs/RELEASE_CHECKLIST.md`.

Treat this plugin source tree as canonical. Installed Claude and Codex skill
directories are generated runtime copies; do not edit installed copies as source.

## When To Use `$zhulong`

When the user asks for repository-level security audit, vulnerability
verification, Docker-based PoC reproduction, confirmed vulnerability bundles,
seeded variant discovery, or the Zhulong workflow, use `$zhulong`.

Do not duplicate the full `$zhulong` skill contract here.

## Safety Boundaries

Scanner, static-analysis, LLM, and dependency findings remain candidates until
attacker-entrypoint Docker reproduction, source-bound validity checks, and
confirmed-bundle validation support them.

Do not execute PoC or exploit verification directly on the host. For applicable
PoC work, use Zhulong's Docker / Docker Compose verification flow.

Confirmed findings must live only in validated Zhulong confirmed bundles.

Final recording is optional and has its own identity, screenshot, archive, and
promotion gates; ordinary confirmed status does not imply recording readiness.

Do not use broad Docker prune or PID kill behavior.

## Durable Rules

Detailed behavior lives in `skills/zhulong/SKILL.md`, `assets/references/`,
`docs/WORKFLOW_DETAILS.md`, `docs/WORKFLOW_DETAILS.zh-CN.md`,
`docs/CODEX_SKILL_ADAPTATION.md`, and deterministic validators/selftests.
