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
- [ ] Repo-root `AGENTS.md` exists, remains a short shim, and points to
  `$zhulong` and `docs/AGENTS.md`; neither source-only `AGENTS.md` file is
  copied as an installed skill contract.
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
- [ ] `assets/tool-registry.json` conforms to its strict R2 schema; tool names
  are globally unique, unknown fields are rejected, and prohibited entries have
  only the prohibited boundary, no active effects/wrapper, and no authority.
- [ ] `scripts/validate_tool_registry.py` remains offline, deterministic, and
  read-only; its stable JSON issue codes reject unsafe wrapper/evidence paths,
  missing wrapper contracts, scanner/DAST over-authority, and raw Docker oracle
  authority without executing a tool.
- [ ] Planner metadata has no raw Docker, DAST, live-target, or external-command
  hint. First-pass probes are wrapper-required candidate material; only the
  controlled Docker verification wrapper emits oracle material, which still
  requires verifier verdict, disposition, and bundle validation.
- [ ] New and refreshed workspaces carry the same registry, schema, validator,
  planner, and controlled-wrapper markers as the installed source snapshot.
- [ ] Docker sandbox preflight rejects privileged containers, host networking,
  host PID, docker socket mounts, host root mounts, and unsafe Docker run flags.
- [ ] Compose preflight requires literal `privileged: false`, rejects YAML
  anchors/aliases/interpolation and non-static namespace values, and rejects
  writable binds overlapping workspace/evidence control paths. Unknown or
  value-less extra Docker arguments fail before any evidence or Docker side
  effect; documented resource limits remain allowed.
- [ ] Verification control files are host-owned. Evidence is read-only inside
  Docker, writable container output is isolated under `/workspace/output`, and
  stdout/stderr oracle bytes come from host-held descriptors. Symlink,
  hardlink, FIFO, directory, ancestor drift, and running pathname replacement
  attacks fail closed without changing candidate/verdict/disposition authority.
- [ ] Bootstrap workspace names are validated as one direct-child ASCII
  component before mkdir, copy, latest-workspace publication, or event writes.
- [ ] The R2 verification wrapper validates synchronized canonical journal/state
  before every Docker CLI call; wrong, missing, stale, corrupt, symlinked, or
  protocol-mismatched R2 state fails with zero Docker calls and zero authority
  mutation.
- [ ] Only `verification/running` or an explicit `verification/blocked` retry
  reaches R2 verification prerequisites. A revision-bound same-stage start
  event commits before the PoC container command; drift or writer failure
  prevents that command.
- [ ] Confirmed and not-reproduced Docker results use same-stage observations,
  blocked results use `running -> blocked`, and result-event commit failure is
  reported nonzero without promoting Docker evidence into a verdict,
  disposition, bundle, or finalization fact.
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
- [ ] Strict Docker evidence is a current, owned, regular JSON object with
  `clean=true`, `strict=true`, workspace binding, checked timestamp, counts and
  note; `finalization_succeeded` binds its relative path, SHA-256, workspace and
  timestamp. Missing, stale, malformed, symlinked or manually paired status
  evidence fails the assertion.
- [ ] `blocked_verification.py` consumes structured verification-result,
  verdict, disposition and event facts before conservative historical text
  fallback; only a later structured result for the same identity resolves an
  unresolved Docker/runtime blocker.
- [ ] Handoff/status consistency is mechanically checked: zero validated
  confirmed bundles cannot be described as confirmed-bundle completion, formal
  seeded variant completion/readiness, or bundle-ready Docker/code-level
  evidence.
- [ ] `handoff-state.json` is generated only from the shared
  `workspace_state.py` aggregation layer; its schema is strict, path-redacted,
  deterministic, and its generator never writes journal/state/verdict/ledger/
  bundle/recording/finalization authority.
- [ ] `validate_handoff_state.py` rejects stale revision, tested-ref, artifact
  digest, and count/ID drift; the human summary is gated on current derived
  state and keeps `agent-notes.md` advisory.
- [ ] Handoff calls Recon and triage validators with their declared input
  contracts. Triage receives only its workspace-relative `--triage-batch` and
  validates a digest/ID-bound `recon_binding` internally; digest, ID, path,
  symlink, and target/candidate-to-Recon swap regressions fail closed.
- [ ] Checkpoints are immutable snapshot indexes with stable numeric filenames,
  same-revision idempotence, atomic publication, safe fixed resume entrypoints,
  and a read-only distinction between current, legal historical, and
  tampered/unverifiable snapshots.
- [ ] `next-actions.json` remains a deterministic, advisory-only derived index:
  it is regenerated from current authority by a read-only validator, writes only
  itself atomically, and has no candidate/verdict/disposition/bundle/finalization
  authority or automatic execution path.
- [ ] Next-action entrypoints and parameter names remain a closed allowlist;
  arbitrary shell, raw Docker, scanner/DAST, absolute paths, URI/traversal,
  notes/chat inference, and zero-bundle variant suggestions fail closed.
- [ ] `audit-timeline.json` and its script-free static HTML remain deterministic,
  offline, derived-only review views: production validators bind every displayed
  authority fact, unsafe links/content fail closed, and generation writes no
  journal/state/candidate/verdict/disposition/Docker/bundle/finalization input.
- [ ] Static timeline HTML has a strict CSP, no script/event handler/external
  resource/CSS URL, and escapes all displayed text; confirmed flows require the
  existing candidate R2, verdict, disposition, Docker, and bundle validation chain.
- [ ] New R2 writer events, static timeline JSON/HTML, and diagnostics use one
  portability/sensitive-value classifier. It rejects documented common
  credential/private-key shapes and local Unix/macOS, Windows, UNC, and `file:`
  paths without echoing values; rejection before append leaves journal/state
  bytes unchanged and retains SHA/ref/path/ordinary-word near-miss controls.
- [ ] Timeline confirmed bundle links are emitted only for a uniquely proven
  single flow; ambiguous, orphan, duplicate, or count-mismatched validated
  bundles fail closed without slug/title/order heuristics.
- [ ] Timeline URI validation is attribute-scoped: escaped URL text remains
  visible, while active/external/protocol-relative/fragment/traversal links,
  duplicate attributes, and parser bypasses fail closed.
- [ ] `audit-events.jsonl` remains the authoritative journal; `stage-status.json`
  is only a derived view and is never treated as confirmation or finalization evidence.
- [ ] R2 writes use a persistent workspace advisory lock, explicit CAS or
  current-revision intent, journal fsync before atomic state replacement, and
  fail closed on unsafe paths, stale views, or partial commits.
- [ ] New R2 writes include one complete P9.3 transition metadata set and pass
  the authoritative `scripts/audit_transition_policy.py` check inside the same
  workspace lock before journal append; rejected transitions change neither journal
  nor state view.
- [ ] The central R2 commit boundary covers CLI writers, direct `commit_event()`
  callers, and stage finalizers. A portable-text rejection exposes no matched
  value and changes no journal/state bytes; Docker-gate blocked events retain an
  actionable placeholder-based resume step without host paths.
- [ ] `resume`, `skip`, `return`, and `reopen` include a non-default reason,
  reason detail, portable subject, workspace-relative evidence reference, and
  structured next action; `observe` never changes state.
- [ ] Pre-P9.3 R2 journals remain visibly classified as `pre_policy_r2` and R1
  remains legacy-compatible without invented transition facts or silent migration.
- [ ] Workflow transition events are never treated as candidate, verdict,
  disposition, bundle, recording, or finalization authority; the existing
  artifact validators and finalization gates remain mandatory.
- [ ] Existing R1 workspaces remain legacy-compatible without silent migration;
  no release path appends R2 records to an R1 journal or claims R1 CAS support.
- [ ] All new R2 writer events carry `plugin_version`; historical missing metadata
  is used only from a schema-valid state cryptographically anchored to an exact
  valid journal prefix, otherwise rebuild fails with a stable provenance error.
- [ ] `recover_audit_state.py` defaults to read-only diagnostics, distinguishes
  incomplete tail, missing final newline, and middle corruption, and never repairs,
  truncates, appends, or rewrites `audit-events.jsonl`.
- [ ] State rebuild requires explicit `--apply`, journal digest CAS, and state digest
  CAS or an explicit missing-state expectation; consumers never auto-apply rebuild.
- [ ] Conflicting state-CAS intents return `STATE_CAS_INTENT_CONFLICT` in JSON before
  lock acquisition or writes; LF/CRLF journal acceptance preserves exact-byte digests.
- [ ] The dedicated P9.5 state-protocol runner passes its manifest, concurrency,
  hard-exit, immutability, and source/Claude/Codex deterministic-layout checks without
  Docker, PoC, replay, network, or package-manager execution.
- [ ] R1 migration preflight reports source digests and redacted/local-field
  classifications without producing R2 records or changing source bytes.
- [ ] `assets/schemas/recon-result.schema.json` is strict Draft 2020-12 JSON,
  and every Recon object rejects unknown properties.
- [ ] `scripts/validate_recon_result.py` binds `tested_ref`, target-contract
  digest, and `attack-surface.md` digest; rejects unsafe paths, missing or
  escaped symlink references, dangling IDs, thin coverage, and unjustified
  `not_applicable` records.
- [ ] Recon `complete` is documented and tested as coverage-contract
  completeness only; it is not vulnerability confirmation, candidate readiness,
  bundle readiness, or audit finalization. Candidate/verdict/disposition/
  severity/bundle permission fields remain outside the result contract.
- [ ] Recon `partial` and `blocked` fixtures require structured gaps/blockers,
  evidence, and executable next/resume actions; absence-only prose does not
  count as coverage.
- [ ] The Recon validator is offline and read-only. Its source, Claude, and
  Codex selftests run the positive service/library cases plus the manifest-driven
  negative status, binding, path, symlink, reference, and permission matrix
  without Docker, network, PoC, replay, package-manager, or LLM execution.
- [ ] `assets/references/recon-result-template.json`, the Recon runner contract,
  and the fixture manifest are included in all three supported package layouts;
  the source skill and Claude template remain byte-identical.
- [ ] `assets/schemas/triage-batch.schema.json` is strict Draft 2020-12 JSON and
  every object rejects unknown fields. Its explicit candidate inventory binds
  path, digest, ID, target contract, and tested ref without creating a verdict,
  disposition, confirmation, severity, bundle, or audit-completion authority.
- [ ] `validate_triage_batch.py` is offline and read-only, invokes the production
  candidate validator for every inventory item, rejects digest/ID/ref/path and
  duplicate-graph drift, and enforces advisory completeness for complete,
  partial, and blocked batches.
- [ ] `finalize_stage.py` accepts only existing R2 recon/triage running stages,
  explicit result-digest and state-revision CAS, and appends one same-stage
  complete/pause/block event through the canonical writer. Its lock-held
  revalidation failure leaves journal/state bytes unchanged; a documented
  journal-committed/state-view-failed outcome is directed to R2 recovery.
- [ ] Source, Claude, and Codex selftests execute the triage/finalizer fixture
  matrix without Docker, PoC, replay, network, package-manager, or LLM activity.
- [ ] Candidate R1 remains visibly readable as `legacy_r1`; Candidate R2 uses a
  recomputable versioned fingerprint, canonical non-empty provenance, strict
  relationships, and explicit non-overwriting upgrade.
- [ ] Candidate deduplication reads only an explicit digest-bound inventory;
  exact duplicates require every identity component, partial matches remain
  `review_required`, and canonical selection is deterministic.
- [ ] Candidate identity and deduplication tooling is offline and candidate-only;
  it cannot write verdict, disposition, journal/state, confirmed bundle,
  recording, evidence, severity, or finalization authority.
- [ ] R2 verifier/disposition bindings reject candidate digest or fingerprint
  drift without treating fingerprint equality as confirmation.

## 4. Confirmed Bundle Contract

- [ ] One confirmed bundle represents exactly one vulnerability.
- [ ] bundle contract generation runs `validate_bundle_contract.py` on a
  `confirmed/.contracts/<slug>.bundle-contract.json` preflight document before
  final `confirmed/<slug>/` artifacts are created.
- [ ] Contract preflight and builder require the real `--repo-root`, verify the
  checked-out tested ref against target/verifier material, and reject source
  path, symlink, line-range, token, or SHA-256 drift.
- [ ] Exact/composed attacker entrypoints are derived from real source tokens;
  unprovable dynamic routes remain blocked or conditional.
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
- [ ] Fixture security properties distinguish upstream-backed from synthetic;
  synthetic privilege, identity, session, secret, ownership, or sensitivity
  never supports stronger real-world impact, while oracle-only markers disclose
  their non-support boundary.
- [ ] Generic impact claims bind deterministic oracle, source/config
  prerequisites, property dependencies, bug-class support, severity ceiling,
  deployment prerequisites, and unsupported stronger impacts.
- [ ] `not_valid` and `withdrawn` never promote; conditional findings retain
  source-bound conditions and narrowed severity in all reviewer-facing material.
- [ ] `validity-review.json`, bundle-local `findings.json`,
  `verification-evidence.json`, reviewer index, DOCX, and build-manifest hashes
  agree on validity, classification, severity, tested ref, and conditions.
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
- [ ] Evidence-level gates reject code-level-only or blocked-entrypoint material
  as bundle-ready; `confirmed_in_docker` requires attacker-entrypoint evidence,
  input shape, entrypoint-to-sink path, and deterministic impact oracle.
- [ ] Report wording, CVSS, reproduction scripts, evidence JSON, and
  reviewer-facing artifacts do not contradict each other.
- [ ] SSRF reports keep callback/reachability, response-content exposure,
  configuration leakage, and sensitive-data exposure in separate evidence tiers.
- [ ] Bundle validation passes on all bundled confirmed findings.

## 5. Bundle Contract And Builder Closure

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
- [ ] `assets/context-catalog.json`, its strict schema, the strict context-plan schema, and both offline validators pass in source, Claude, and Codex layouts.
- [ ] Catalog paths are regular non-symlink files below `assets/references/`; duplicate IDs/paths, unsafe paths, unknown selectors, and authority drift fail closed.
- [ ] Context planning remains deterministic across repeated locale/timezone runs and does not grant reading, execution, confirmation, promotion, or gate authority.
- [ ] `assets/root-skill-rule-inventory.json` and its strict schema pass the read-only inventory validator.
- [ ] All 14 kernel invariants remain in both byte-identical source Skills; moved hard rules retain a real production carrier.
- [ ] Every phase reference is a safe catalog baseline module and no phase reference triggers dogfood/template/example scope rejection.
- [ ] Context fixture goldens and source/Claude/Codex plans include the new phase baseline references byte-for-byte.
- [ ] Root Skill measurements report actual lines, bytes, Unicode characters, and whitespace-split words; phase-reference lines are reported separately.

## 6. Optional Final Recording Gate

- [ ] Final recording is explicitly requested; ordinary confirmed status is not treated as recording-ready.
- [ ] The public source files exist: `scripts/recording_identity.py`, `scripts/auto_record_bundle.py`, `scripts/validate_recording_evidence.py`, the strict recording schema, and sanitized fixtures.
- [ ] `skills/zhulong/SKILL.md` and `templates/claude-skill/SKILL.md` are byte-identical, and neither delegates authority to the old local recording skill.
- [ ] The generated helper has identity/context/impact checkpoint events and fails closed when the recorder-owned protocol is incomplete.
- [ ] Checkpoint acknowledgements use exact JSON semantics (ordinary recorder-owned file, protocol version, status, stage, integer sequence, and marker), not serialization-dependent text matching.
- [ ] Final encoded video frames are non-black, correctly timed, source/window-bound, and identity/oracle/direct-impact observations are present.
- [ ] `recording_time_observations` are documented and emitted only as non-authoritative consistency claims; `--finalize` requires live checkpoints for full validation, while later no-checkpoint revalidation reports artifact-only consistency.
- [ ] The three canonical screenshots are derived from the final encoded video, hashed, non-duplicate, and registered in all three evidence/inventory targets.
- [ ] `recording-evidence.json` passes `scripts/validate_recording_evidence.py` only after finalization; the ordinary report validator also passes.
- [ ] Temporary ZIP passes UTF-8/readability, `testzip()`, required-entry, and manifest-hash checks before atomic promotion.
- [ ] Optional diagnostic archive retention uses `--keep-unpromoted-archive DIR` only after a verified staged archive and a later promotion failure; it stays external, diagnostic-named, and non-overwriting. Deprecated `--zip-on-fail` creates no archive.
- [ ] A forced replay/archive/promotion failure leaves the original bundle, video, screenshots, and ZIP byte-identical; failed raw output remains outside the final path with an owned staging marker.

## 6.5 Authority-Boundary Repair

- [ ] Completion uses the shared read-only candidate -> verifier -> disposition -> bundle chain; a standalone bundle validator, state count, or self-authored result cannot authorize completion.
- [ ] Confirmed bundles, confirmed legacy disposition items, and confirmed candidate dispositions are one-to-one; duplicate, orphan, unsafe, or mismatched target/verifier references fail closed.
- [ ] Candidate R2 disposition records preserve and validate candidate SHA-256 and fingerprint; verifier status, candidate ID, target ref, evidence, and `confirmed_in_docker` agree exactly.
- [ ] R2 no-confirmed completion rejects candidate/unverified/blocked/missing records and accepts only terminal `false_positive` candidate dispositions; a no-candidate workspace has a production-valid Recon coverage proof with no gaps or blockers.
- [ ] The same substantive predicate is consumed by finalization, handoff derivation, workspace validation, and the finalization assertion; R1 compatibility is explicit and is not described as R2 completion.
- [ ] Automatic R1 state writing rejects R2-only intent before journal append; explicit `legacy-r1` writes report ignored fields and compatibility diagnostics without migration or fabricated sequence/revision history.
- [ ] Verification case IDs and evidence directories are validated before evidence creation, state reads, Docker, or PoC execution; missing journal/state returns `AUTHORITATIVE_STATE_MISSING` without execution.
- [ ] No production success bypass or legacy test-only skip variable exists for Docker cleanliness, and selftests use only deterministic temporary helpers.

## 7. Validation Commands

Run from the plugin root:

```bash
python3 scripts/selftest_plugin.py
bash scripts/sync_to_claude_skill.sh
python3 ~/.claude/skills/zhulong/scripts/selftest_plugin.py
bash scripts/sync_to_codex_skill.sh
python3 ~/.agents/skills/zhulong/scripts/selftest_plugin.py
python3 -m json.tool assets/schemas/handoff-state.schema.json >/dev/null
python3 -m json.tool assets/schemas/workspace-checkpoint.schema.json >/dev/null
python3 -m json.tool assets/root-skill-rule-inventory.json >/dev/null
python3 -m json.tool assets/schemas/root-skill-rule-inventory.schema.json >/dev/null
python3 scripts/validate_root_skill_rule_inventory.py --skill-root . --inventory assets/root-skill-rule-inventory.json --json
cmp -s skills/zhulong/SKILL.md templates/claude-skill/SKILL.md
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

## 8. Release-Candidate Dogfood

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

## 9. Publish Decision

Publish only when:

- [ ] Selftests pass in plugin source, installed Claude skill, and installed
  Codex skill layouts.
- [ ] Confirmed bundles validate.
- [ ] No local absolute paths or stale package names remain in public docs.
- [ ] No broad Docker prune or PID signaling path is present.
- [ ] Release notes summarize the core safety gates and real-world dogfood status.
