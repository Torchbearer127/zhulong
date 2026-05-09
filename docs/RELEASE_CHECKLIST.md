# Zhulong Release Checklist

Use this checklist before publishing a tagged open-source release of Zhulong
(烛龙).

## 1. Positioning

- [ ] Public wording describes Zhulong as a Docker-first, security-focused code
  audit workflow, not merely a vulnerability scanner.
- [ ] `SECURITY.md` and `DISCLAIMER.md` are present, linked from README, and use
  the current maintainer contact information.
- [ ] Documentation clearly separates confirmed vulnerabilities, candidates,
  false positives, non-security defects, hardening-only observations, and
  unverified leads.
- [ ] Documentation says scanner-only, dependency-only, static-only, LLM-only,
  blocked, timed-out, rejected unsafe sandbox, or dirty-Docker results cannot
  enter `confirmed/`.

## 2. Packaging

- [ ] `.claude-plugin/plugin.json` is valid JSON and metadata-only.
- [ ] `.codex-plugin/plugin.json` is valid JSON and uses the same release
  version.
- [ ] Publisher, author, developer, copyright, homepage, and repository metadata
  are under `Torchbearer127`.
- [ ] Manifest paths are relative and point to existing package content.
- [ ] If releasing from the parent dogfood workspace, package only the canonical
  plugin source and approved top-level docs. Do not include target repository
  snapshots, `security-research-*` workspaces, confirmed vulnerability bundles,
  disclosure drafts, exported conversation logs, OMC state, or local Claude
  runtime files.
- [ ] No hooks, MCP servers, apps, agents, commands, background services,
  dashboards, databases, vector DBs, RAG services, Discord/Notion integrations,
  or platform dependencies are required for normal use.
- [ ] No maintainer metadata placeholders remain in public release manifests.

## 3. Safety Contracts

- [ ] Docker-only PoC and verification remains mandatory.
- [ ] Docker unavailable means pause and preserve artifacts, not host fallback.
- [ ] Docker sandbox preflight rejects privileged containers, host networking,
  host PID, docker socket mounts, host root mounts, and unsafe Docker run flags.
- [ ] OMC teammate PIDs are review-only inside Zhulong; no production path
  signals `claude --teammate-mode tmux` processes.
- [ ] Docker residue is separate from OMC runtime residue.
- [ ] Docker cleanup uses labels, baseline checks, exact Compose project/image
  ref/network name/volume name adoption, or exact BuildKit cache ID adoption.
- [ ] No broad Docker prune appears as normal cleanup guidance.
- [ ] Late `--force-overwrite-baseline` cannot hide post-baseline owned or
  unattributed Docker residue.
- [ ] Finalization recomputes strict Docker cleanliness and does not trust stale
  `docker-cleanliness-status.json`.

## 4. Confirmed Bundle Contract

- [ ] One confirmed bundle represents exactly one vulnerability.
- [ ] Each bundle contains a finding-specific DOCX report, attachment index,
  reproduction supplement, `verification-evidence.json`, `attachments/`, and a
  reviewer-friendly bundle-root reproduction helper script.
- [ ] Confirmed reports include attacker condition, server condition, and
  concrete CIA or equivalent security impact.
- [ ] Report wording, CVSS, reproduction scripts, evidence JSON, and
  reviewer-facing artifacts do not contradict each other.
- [ ] Bundle validation passes on all bundled confirmed findings.

## 5. Validation Commands

Run from the plugin root:

```bash
python3 scripts/selftest_plugin.py
bash scripts/sync_to_claude_skill.sh
python3 ~/.claude/skills/zhulong/scripts/selftest_plugin.py
python3 -m json.tool .claude-plugin/plugin.json >/dev/null
python3 -m json.tool .codex-plugin/plugin.json >/dev/null
rg -n "/Users/torchbear[e]r" . --glob '*.md' --glob '*.py' --glob '*.sh' --glob '*.json'
rg -n "autonomous-security[-]researcher" . --glob '*.md' --glob '*.py' --glob '*.sh' --glob '*.json'
rg -n "docker (system|builder|buildx) prune|builder pr[u]ne|system pr[u]ne|buildx pr[u]ne" . --glob '*.md' --glob '*.py' --glob '*.sh' --glob '*.json'
rg -n "kill -[T]ERM|kill -[9]|SIG[K]ILL|kill -[K]ILL|cleanup-suspect-pid .*--appl[y]" . --glob '*.md' --glob '*.py' --glob '*.sh' --glob '*.json'
```

Run confirmed bundle validation for release-candidate dogfood workspaces that
contain confirmed findings:

```bash
python3 scripts/validate_all_report_bundles.py --confirmed-dir <repo>/<audit-workspace>/confirmed --language zh-CN
```

## 6. Release-Candidate Dogfood

- [ ] At least five real-world pilot logs or workspace summaries are archived.
- [ ] The pilot set covers a Docker-ready Web/API target, a medium/large
  monorepo, a Python or Node library/framework target, a realistic Docker
  Compose stack, and an expected no-confirmed control.
- [ ] Each pilot records finalization, `audit-disposition.json`, runtime
  hygiene, sandbox preflight, Docker strict clean, and bundle validation status
  where applicable.
- [ ] No unresolved High/Medium workflow defect remains.
- [ ] Low-only wording, alias, or ergonomics issues are recorded as follow-up
  issues instead of restarting the hardening loop.

## 7. Publish Decision

Publish only when:

- [ ] Selftests pass in both plugin source and installed Claude skill layouts.
- [ ] Confirmed bundles validate.
- [ ] No local absolute paths or stale package names remain in public docs.
- [ ] No broad Docker prune or PID signaling path is present.
- [ ] Release notes summarize the P5 gates and real-world dogfood status.
