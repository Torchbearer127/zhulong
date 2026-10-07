# Changelog

## Unreleased

## 0.7.0

### English

- Preserve the original replay failure and historical audit logs. Validate declared replay entrypoints and delivery files, inspect bundle-local Compose/build inputs without Docker, and stop replay when startup or a bounded health wait fails. Static packaging checks do not prove runtime replay.
- Support declared movable package inputs and qualify original materials; bind quoted source excerpts to their cited code and keep reviewer prose separate from source evidence.
- Keep disposition IDs stable and make triage feedback idempotent. Do not replace a Docker baseline recorded as unavailable with a later observation.
- Add limited DeepSeek Harness support through the shared skill directory. This does not establish a complete Docker-backed DSH audit workflow.
- Add an opt-in fresh verifier that runs the PoC with isolated Python (`python3 -I`). Default diagnostics stay separate from canonical fresh verdicts; failed or interrupted source snapshots are excluded from named-file discovery, read-only snapshots preserve executable bits, and rollback cleanup requires verified ownership. Reviewer-provided text does not verify identity, attacker reachability, or claimed impact.

### 简体中文

- 复现失败时保留原始失败结果和历史审计日志。发布前校验已声明的复现入口和交付文件，也可在不启动 docker 的情况下检查漏洞包内的 Compose、build context 和 Dockerfile；启动或有时限的健康检查等待失败时会停止复现。静态打包校验通过不代表运行时复现成功。
- 支持在声明中标注可迁移的软件包输入并校验原始材料；源码引文绑定到对应代码，复核说明与源码证据分开处理。
- 保持处置记录 ID 稳定，并使分诊反馈可幂等处理。docker 初始基线若记录为不可用，后续观察不得覆盖该记录。
- 通过共享 skill 目录有限接入 DeepSeek Harness；这不表示完整的 docker 审计闭环已经通过。
- 增加显式启用的独立核验器，通过隔离 Python 执行 PoC（`python3 -I`）。默认诊断输出与正式核验结论分开；运行失败或中断后，源码快照仍会排除在按文件名查找的项目材料之外；只读快照保留可执行权限，回滚清理前须核实占位文件归属于本次调用。复核者提供的文字不能核实其身份、证明攻击者能否访问相关入口，也不能自动验证所声称的影响。

## 0.6.0

- added recoverable file-backed audit state with an append-only event history, derived workspace views, revision-checked writes, and explicit recovery
- added structured handoff, immutable checkpoints, next actions, and context planning for reliable continuation across sessions
- added an offline audit timeline in JSON and HTML with built-in sensitive-data protection
- added candidate identity, fingerprinting, deduplication, and bounded triage so repeat findings remain traceable
- added strict validation across reconnaissance, triage, candidates, verdicts, disposition, handoff, checkpoints, next actions, timelines, and finalization
- added safe authority-file persistence and ordered finalization so incomplete or uncertain work cannot be presented as complete
- added isolated Docker and Compose execution with bounded resources, pinned inputs, host-observed results, and exact cleanup
- made host-observed exit, timeout, and signal outcomes authoritative; bounded stdout/stderr capture and historical-only container output prevent text from overriding execution facts
- added source, Claude installed, and Codex installed layout synchronization and selftests, with release-candidate validation for real Docker execution and sensitive-data handling

## 0.5.0

- added a contract layer for target, candidate, verifier, and disposition data with strict schemas and validation
- added verification workspace bootstrap and independent candidate verification helpers
- required variant discovery before a workspace can be finalized as complete
- added reviewer-readiness checks for report structure, evidence quality, and cross-artifact consistency
- hardened confirmed-bundle generation, validation, replay metadata, and historical bundle compatibility
- separated readiness waits from reviewer pauses so incomplete review work is not mistaken for a completed result

## 0.4.0

- added tested Codex user-level skill support at `~/.agents/skills/zhulong/`
- added Codex sync, installed selftest, and a platform-neutral `zhulong_audit.sh` launcher
- added repo-root `AGENTS.md` guidance for Codex and other local agents while keeping installed skill behavior owned by `SKILL.md`
- documented source, Claude installed, and Codex installed layout boundaries
- updated English and Chinese README/usage/install docs for Claude Code and Codex installation paths
- tightened portability checks to avoid machine-local paths and parent workspace names in plugin source and confirmed deliverables
- dogfooded the Codex installed skill on a real repository with no confirmed-finding overclaim

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
- added an audit disposition ledger with workspace-level `audit-disposition.json`
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
