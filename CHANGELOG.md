# Changelog

## 0.3.0

- added seeded variant discovery for same-repository follow-up candidates from validated confirmed bundles
- added Variant Seed Card validation, offline seed extraction, candidate ranking, and candidate-only guardrails
- added historical findings compatibility so older confirmed bundles can produce useful variant seeds without weakening confirmation gates
- dogfooded the variant flow on real confirmed bundles while preserving Docker-first and confirmed-only semantics
- hardened confirmed bundle replay helpers with reviewer-facing identity, code context, code-level analysis, realistic impact, and final evidence summary screens
- required DOCX vulnerability analysis to include reviewer-usable key code context
- added cross-artifact consistency gates for raw structured-object cleanup, direct-impact marker synchronization, replay log registration, mutable version identity, marker drift, and readiness alignment
- updated workflow documentation for variant discovery and confirmed-bundle quality gates

## 0.2.0

- added metadata-only Claude plugin package manifest at `.claude-plugin/plugin.json`
- documented Claude skill sync versus Claude plugin-style package discovery paths
- extended self-test coverage for Claude plugin manifest shape, relative paths, and absence of required hooks/MCP/apps/agents/commands/background services
- added P5 audit disposition ledger support with workspace-level `audit-disposition.json`
- added OMC runtime hygiene status with teammate PIDs treated as review-only
- removed plugin-owned teammate PID signaling; the suspect-PID review path no longer terminates teammate processes
- added Docker / sandbox preflight rejection for unsafe verification configurations
- added confirmed report quality gates for attacker condition, server condition, and security impact
- strengthened candidate/unverified guidance around official security policy, default config, expected behavior, administrator trust, and project security boundary
- added report-quality consistency gates for auth/title/CVSS mismatch, unconditional PoC success output, `0/N` recording labels, zh-CN natural-language consistency, and optional target/command consistency fields
- hardened Docker resource hygiene against late baseline overwrite, stale cleanliness status reuse, legacy `com.zhulong.workspace` labels, unsafe adoption, and broad cleanup drift
- added exact post-baseline adoption for reviewed image refs, network names, volume names, and BuildKit cache IDs
- preserved confirmed-only, Docker-first, Docker cleanup, finalization, and confirmed bundle contracts
- completed release-candidate real-world dogfood across five-plus repositories and documented the results before open-source publication
- added release checklist guidance for future tagged releases

## 0.1.1

- clarified that `.codex-plugin` is package metadata rather than Claude Code's native loading format
- added `scripts/sync_to_claude_skill.sh` to install the package into `~/.claude/skills`
- added `scripts/refresh_workspace_helpers.sh` to update existing bootstrapped repositories
- added `scripts/asr_start.sh` as a one-shot launcher so users do not need to run many helper commands manually
- added a Claude-native installed skill template at `templates/claude-skill/SKILL.md`
- extended self-test coverage to validate Claude skill sync

## 0.1.0

- Created the initial plugin scaffold.
- Packaged runtime checks, workspace bootstrap, dynamic toolchain planning, reporting, and bundle validation into a plugin-friendly structure.
- Added first-tier security tooling detection and optional installer support.
- Added deterministic DOCX report generation and validation helpers.
