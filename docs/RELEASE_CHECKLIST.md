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
- [ ] `docs/CODEX_SKILL_ADAPTATION.md` reflects the current source,
  Claude installed, and Codex installed layout contract.
- [ ] Repo-root `AGENTS.md` exists, remains a short shim, points to
  `$zhulong` and `docs/AGENTS.md`, and is not copied as an installed skill
  contract.
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
- [ ] Installed Claude and Codex skill directories are treated as generated
  runtime copies. The plugin source tree remains the source of truth.
- [ ] `scripts/zhulong_audit.sh --print-skill-root` resolves the source,
  installed Claude, and installed Codex skill roots without starting an audit.
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
- [ ] bundle contract generation runs `validate_bundle_contract.py` on a
  `confirmed/.contracts/<slug>.bundle-contract.json` preflight document before
  final `confirmed/<slug>/` artifacts are created.
- [ ] `assets/references/bundle-rule-mapping.md` exists, represents all
  required contract fields, and maps each field to renderer output, a final
  validator or batch gate, and a bundle evidence artifact.
- [ ] New bundle contract fields are added to
  `assets/references/bundle-rule-mapping.md` in the same change; fields that
  cannot be mapped are not added to the contract.
- [ ] Mapping and release wording do not describe contract preflight as
  vulnerability confirmation. It remains a ready-to-render workflow gate.
- [ ] `finding.severity` uses the stable contract enum
  `Critical`/`High`/`Medium`/`Low`/`Informational`, while report renderers may
  localize display labels.
- [ ] `finding.bug_class` and `impact_tier.bug_class` remain documented free
  text with recommended bug_class values rather than a strict schema enum.
- [ ] `assets/references/bundle-contract-template.json` omits redundant empty
  optional fields for full-app fixture provenance and callback-only SSRF oracle
  material.
- [ ] Confirmed bundles are built through `build_confirmed_bundle.py`, with
  render output validated under `confirmed/.staging/<slug>` before atomic
  promote into `confirmed/<slug>/`.
- [ ] Failed staging builds stay under `confirmed/.staging/` and are not
  described as confirmed deliverables.
- [ ] Each bundle contains a finding-specific DOCX report, attachment index,
  reproduction supplement, `verification-evidence.json`, `attachments/`, and a
  reviewer-friendly bundle-root reproduction helper script.
- [ ] Confirmed reports include attacker condition, server condition, and
  concrete CIA or equivalent security impact.
- [ ] DOCX key code context includes project-relative paths, line metadata or an
  explicit unavailable-line reason, vulnerable-chain snippets, compact
  monospace formatting, and code-level analysis tied to the snippet.
- [ ] Bundle-root replay helpers expose reviewer pause overrides and preserve
  readable pauses around identity, code context, analysis, impact boundary,
  proof command/output transitions, and final evidence summary screens.
- [ ] Bundle-root replay helpers keep reviewer pauses visual-only: service
  readiness, health polling, startup retries, and backoff use independent
  readiness/backoff variables, and reviewer-facing evidence path messages are
  bundle-relative.
- [ ] `assets/references/reviewer-readiness-validator-gates.md` exists and
  classifies reviewer-readiness gate classification scope for SSRF impact
  overclaim, code context minimum quality, and replay helper pause contract.
- [ ] Each reviewer-readiness gate family has deterministic local-only positive
  and negative fixture coverage in `scripts/selftest_plugin.py`.
- [ ] New reviewer-readiness gates add classification, selftest fixture
  coverage, and a release checklist entry in the same change.
- [ ] Registered replay logs are real transcripts with command/output/oracle
  signals, not placeholders or marker-only files; copied successful transcripts
  carry portable provenance and direct-impact markers are not appended manually.
- [ ] The replay transcript corpus under
  `assets/fixtures/replay-transcript-corpus/` covers positive and negative
  examples, and docs state that replay trust does not require a single rigid log format.
- [ ] `validate_report_bundle.py --all-errors --json --output-errors` remains an
  explicit diagnostic mode only; default final bundle validation stays
  fail-fast and all-errors output does not repair bundles or confirm
  vulnerabilities.
- [ ] Formal seeded variant discovery accepts only seed cards backed by a
  validated `confirmed/<bundle>/`; candidate/manual/evidence-only pointers fail
  closed and remain outside `evidence/variant-analysis/seeds.jsonl`.
- [ ] Report wording, CVSS, reproduction scripts, evidence JSON, and
  reviewer-facing artifacts do not contradict each other.
- [ ] SSRF reports keep callback/reachability, response-content exposure,
  configuration leakage, and sensitive-data exposure in separate evidence tiers.
- [ ] Bundle validation passes on all bundled confirmed findings.

## 5. P8 Bundle Builder Closure

- [ ] Source layout selftest passes: `python3 scripts/selftest_plugin.py`.
- [ ] Claude installed layout selftest passes after `bash scripts/sync_to_claude_skill.sh`.
- [ ] Codex installed layout selftest passes after `bash scripts/sync_to_codex_skill.sh`.
- [ ] `skills/zhulong/SKILL.md` and `templates/claude-skill/SKILL.md` are byte-identical.
- [ ] `assets/schemas/bundle-contract.schema.json` and
  `assets/references/bundle-contract-template.json` are valid JSON.
- [ ] `assets/references/bundle-rule-mapping.md` is present in source and
  installed layouts, covers required contract fields, and preserves the
  ready-to-render boundary.
- [ ] Staging wrapper selftest covers contract preflight, staging validation,
  `confirmed/.staging/<slug>`, promote, batch validation, and failed-staging
  non-promotion.
- [ ] Replay log trust selftest rejects placeholder, marker-only, and thin
  transcripts.
- [ ] Replay transcript corpus selftest passes for trusted positives,
  marker-only, placeholder-only, thin explanatory, oracle-missing, and copied
  transcript provenance-boundary samples without Docker, replay, network, or
  package-manager execution.
- [ ] All-errors selftest covers diagnostic JSON output without treating
  all-errors as confirmation.
- [ ] reviewer-readiness gate classification exists in source and installed
  layouts, and the three gate families retain positive and negative fixture coverage.
- [ ] No local path leak appears in public Markdown, Python, shell, or JSON
  files.
- [ ] No broad Docker prune appears as normal cleanup guidance.
- [ ] No PID kill behavior is introduced for OMC teammate cleanup.

## 6. Validation Commands

Run from the plugin root:

```bash
python3 scripts/selftest_plugin.py
bash scripts/sync_to_claude_skill.sh
python3 ~/.claude/skills/zhulong/scripts/selftest_plugin.py
bash scripts/sync_to_codex_skill.sh
python3 ~/.agents/skills/zhulong/scripts/selftest_plugin.py
python3 -m json.tool .claude-plugin/plugin.json >/dev/null
python3 -m json.tool .codex-plugin/plugin.json >/dev/null
bash scripts/resolve_skill_root.sh
bash scripts/zhulong_audit.sh --print-skill-root
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

## 7. Release-Candidate Dogfood

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

## 8. Publish Decision

Publish only when:

- [ ] Selftests pass in plugin source, installed Claude skill, and installed
  Codex skill layouts.
- [ ] Confirmed bundles validate.
- [ ] No local absolute paths or stale package names remain in public docs.
- [ ] No broad Docker prune or PID signaling path is present.
- [ ] Release notes summarize the P5 gates and real-world dogfood status.
