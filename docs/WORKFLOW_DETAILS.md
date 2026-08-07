# Zhulong Workflow Details

This document collects the detailed operational notes that are useful after a
reader already understands the README-level positioning.

For Simplified Chinese, see [`WORKFLOW_DETAILS.zh-CN.md`](WORKFLOW_DETAILS.zh-CN.md).

## Human-Agent Collaboration

Zhulong treats the audit workspace as a shared working surface between agents
and humans. The important state is written to small, named files instead of
being trapped in a long chat transcript or raw scanner output.

- Agents can resume from `handoff-summary.md`, `stage-status.json`, and
  `audit-disposition.json`.
- Humans can review `attack-surface.md`, `candidate-findings.md`,
  `false-positives.md`, `unverified-leads.md`, and `SUMMARY.md` without reading
  every raw log.
- Maintainers can evolve behavior by editing scripts, reference contracts, and
  validators rather than inflating launch prompts.
- Reviewers can inspect confirmed bundles without reconstructing which
  evidence, command, payload, and report claim belong together.

## Audit State Protocol R2

The R2 protocol defines audit-events.jsonl as the authoritative append-only
journal and stage-status.json as a derived materialized current-state view.
Shape-valid records do not prove a vulnerability, Docker confirmation, bundle
validity, or workspace completion. New R2 writes use a locked writer with
explicit CAS/current-revision intent and an explicit transition intent.
The authoritative P9.3 policy records source stage, controls local state changes,
conservative forward/return/optional-stage relationships, and evidence-bearing
resume/skip/return/reopen actions. Old R2 records remain visibly classified as
pre-policy history, while valid R1 workspaces remain read/write compatible without
silent migration. P9.4 adds a byte-aware shared inspector, field-level drift
diagnostics, read-only R1 migration preflight, and an explicit double-digest-CAS
command that can atomically rebuild only stage-status.json. Consumers never
auto-repair, and audit-events.jsonl is never truncated, rewritten, or synthesized. See
[audit-state-protocol-r2.md](runner-contracts/audit-state-protocol-r2.md).
Before any new R2 journal append, the canonical locked writer also screens its
published event text for local host paths, `file:` URIs, and common credential
or private-key shapes. Rejection reports only a stable category and leaves both
journal and state bytes unchanged; direct writers and stage finalizers share
this boundary. Historical journal bytes are never sanitized in place.
The recovery CLI reports `STATE_CAS_INTENT_CONFLICT` in JSON before taking a lock
when both state-CAS intents are supplied. LF and CRLF journals are accepted as
distinct exact-byte inputs; recovery never normalizes their line endings. Historical
anchored plugin-version metadata is explicitly identified as prefix provenance, not
as the latest plugin version. The offline protocol closure fixtures exercise these
rules without Docker, PoC, replay, network, or package-manager execution.

## Recon Coverage Result

Recon coverage is carried in a separate, portable JSON contract. Read
[`recon-result-contract-r1.md`](runner-contracts/recon-result-contract-r1.md)
before creating or reviewing `recon-result.json`.

Candidate triage is a separate advisory batch contract. Read
[`triage-batch-contract-r1.md`](runner-contracts/triage-batch-contract-r1.md)
before creating `triage-batch.json` or recording a Recon/triage terminal state.
Triage cannot update a disposition or claim confirmation. The narrow stage
finalizer uses exact result and revision CAS to append only a same-stage R2
complete/pause/block event; it never advances work or executes next actions.

Candidate Contract R2 adds deterministic identity, structured provenance, and
candidate-only duplicate relationships. Read
[`candidate-identity-dedupe-r1.md`](runner-contracts/candidate-identity-dedupe-r1.md)
before upgrading or deduplicating candidates. R1 remains readable as
`legacy_r1`; upgrade is explicit and non-overwriting. Exact fingerprint matches
and advisory dedup plans never replace independent verification, disposition,
Docker evidence, confirmed-bundle validation, or finalization.

The result binds to the exact `zhulong-target.yaml` digest, `tested_ref`, and
workspace-root `attack-surface.md` digest. Its structured observations use
stable IDs and repository/workspace-relative source and evidence references.
`complete` means only that all Recon coverage categories are structurally
covered or evidence-backed `not_applicable`; it does not mean no vulnerability,
audit completion, candidate readiness, or confirmed deliverable. `partial` and
`blocked` must carry explicit gaps/blockers and executable recovery actions.

Validate it without changing the repository or workspace:

```bash
python3 scripts/validate_recon_result.py \
  --repo-root <repo-root> \
  --workspace-dir <audit-workspace> \
  --recon-result <audit-workspace>/recon-result.json \
  --json
```

The validator is offline and read-only. Recon output may expose stable
`focus_refs` for later review planning, but it cannot create candidates,
verdicts, dispositions, bundles, or finalization state. A separate, later
stage-finalization entrypoint is solely responsible for registering Recon-stage
termination.

## Tool Effects and Execution Boundaries

The strict R2 Tool Registry is shared by the dynamic planner, the offline
validator, and Zhulong's narrow controlled wrappers. Read
[`tool-effects-execution-boundaries-r1.md`](runner-contracts/tool-effects-execution-boundaries-r1.md)
before changing tool metadata or interpreting a plan.

The registry is local to Zhulong: it cannot intercept a human's or another
Agent's native tools. A successful registry check is metadata-only and never
creates a candidate, verdict, disposition, or confirmation. First-pass scanner
output is candidate material only; the initial-probe wrapper records its start
in the canonical `recon` stage. Raw Docker and uncontrolled DAST/live-target
tools have no direct planner command hint. Only the fixed Docker verification
wrapper can emit Docker oracle material, and that material still must pass the
existing verifier-verdict, disposition, and confirmed-bundle gates.

In an R2 workspace, the verification wrapper validates the canonical
journal/state pair and requires `verification/running` or an explicit retry
from `verification/blocked` before any Docker CLI call. It never advances
triage or rewrites workflow state to make a result event fit. Docker
daemon/image checks are non-PoC prerequisites; the actual PoC container command
starts only after a revision-bound same-stage start event commits. Result-event
failure is a nonzero wrapper result even when Docker evidence exists. R1
remains legacy-compatible, and a workspace with no state files is not silently
upgraded to R2.

## Advisory Context Planning

`assets/context-catalog.json` declares stable local references that may be recommended for a phase. Run `plan_audit_context.py` with an explicit target directory and phase to create a deterministic `context-plan.json`; optional bug classes are closed explicit inputs. The planner reuses the toolchain planner's stack and attack-surface detection only. It does not parse notes, candidates, handoff text, or references.

`mandatory` means a phase-baseline reading recommendation, not a security gate. `optional` records exact matching selector facts, and `deferred` records a phase-relevant module without a selector match. The plan is advisory only: it does not prove an Agent read, understood, or used a module; execute tools or references; create evidence; confirm findings; or replace existing validators, gates, or root Skill constraints. See [`context-planning-r1.md`](runner-contracts/context-planning-r1.md).

## Handoff Status Consistency

`handoff-summary.md` is an operational continuation packet. It must describe the
mechanical workspace state, not the most optimistic interpretation of notes or
partial evidence.

The renderer and completion checks use `scripts/workspace_state.py` as the
shared inspection layer:

- `confirmed_bundle_dirs_total` counts non-hidden directories under
  `confirmed/`.
- `validated_confirmed_bundle_count` counts only directories that pass the
  existing confirmed-bundle validator through
  `validate_all_report_bundles.py`.
- `invalid_or_partial_confirmed_bundle_count` counts bundle-like directories
  classified as partial or validation-failed by that validator.
- `docker_evidence_only_count` counts Docker or verification evidence under
  workspace evidence paths that is not a validated confirmed bundle.
- `formal_variant_analysis_status` is `completed` only when at least one
  validated confirmed bundle exists and both
  `evidence/variant-analysis/seeds.jsonl` and
  `variant-candidates.jsonl` pass their validators.

When no validated confirmed bundle exists, the handoff must say
`Confirmed bundles: 0`. If Docker evidence exists without a validated bundle,
the conservative state is `docker_evidence_collected_but_no_bundle`. In that
state, Docker evidence may be useful verification material, but it is not a
confirmed deliverable, does not make the workspace bundle-ready, and cannot make
formal seeded variant discovery completed or ready.

Manual same-pattern notes, draft seed notes, candidate rows, code-level evidence,
partial bundles, and validation-failed directories remain manual or unverified
workspace material until a real `confirmed/<bundle>/` passes final validation.
`validate_workspace_state.py`, `assert_finalized_workspace.py`, and the
finalization gate reject stale handoff/status text that claims otherwise.

### Structured Handoff And Checkpoints

`handoff-state.json` is the machine-readable continuation index. It is derived
by `scripts/workspace_state.py` from the committed journal/state view and the
existing candidate, verifier, disposition, bundle, Docker, runtime, recording,
and finalization validators. It records revision/digest, tested-ref
verifiability, stable IDs and counts, formal seeded-variant status, blocker/
resume context, and relative artifact digests. It never writes back to those
authoritative artifacts and it never turns Docker evidence, recording manifests,
or notes into a confirmed finding.

For Recon and triage, this aggregation uses each production validator's
declared input contract. In particular, triage receives only its
workspace-relative `--triage-batch` input; its digest-bound `recon_binding` is
validated internally by the triage contract rather than supplied as an invented
second CLI flag.

`render_handoff_state.py` publishes only that one file with a same-directory
temporary file, fsync, and atomic replacement. `validate_handoff_state.py` is
read-only and reports stale revision, tested-ref, digest, and count/ID drift.
The human renderer refreshes or validates this state before writing
`handoff-summary.md`; `agent-notes.md`, when present, is explicitly advisory.

`checkpoints/<revision>.json` is an immutable, lightweight snapshot index, not a
copy of logs, prompts, chat, credentials, or evidence. Creation requires a
current handoff state, uses a stable numeric filename, and is idempotent for
identical bytes; conflicting same-revision bytes fail closed. Checkpoint resume
metadata uses fixed safe entrypoints and workspace-relative parameters only. A
validator may classify a structurally sound older checkpoint as
`valid_historical`; changed inputs or an unsafe/tampered index are
`historical_unverifiable` or `tampered`, not silently current.

### Derived Next Actions

`next-actions.json` is a deterministic, advisory-only index derived from a
current `handoff-state.json` and its existing structured authority inputs.
`render_next_actions.py` writes only this derived file atomically;
`validate_next_actions.py` is read-only and rederives every field. Suggestions
use a fixed entrypoint allowlist and structured relative parameters, and are
never shell commands or automatic execution. The index is not evidence and has
no candidate, verdict, disposition, bundle, recording, finalization, or audit
completion authority. Missing or conflicting authority fails closed rather than
being inferred from notes, summaries, chat, or directory names.

### Static Audit Timeline

`render_audit_timeline.py --workspace-dir <audit-workspace> --repo-root <repo-root>`
creates `audit-timeline.json` and `audit-timeline.html` as one deterministic,
offline review projection. The JSON is derived from the canonical journal/state
reader and the existing target, candidate, verdict, disposition, Docker, bundle,
handoff, next-action, and finalization validators; the HTML is rendered only
from that validated JSON. Run `validate_audit_timeline.py --timeline
<audit-workspace>/audit-timeline.json --html
<audit-workspace>/audit-timeline.html --workspace-dir <audit-workspace> --repo-root
<repo-root>` before opening the HTML locally.

The timeline does not run an audit, Docker, a PoC, replay, a scanner, a network
request, a model, or an Agent. It contains no hidden reasoning or chat content,
and it has no confirmation, disposition, bundle, execution, or finalization
authority. A confirmed flow still requires the existing Docker evidence,
independent verdict, disposition, and validated bundle. Zhulong intentionally
uses a static file instead of a server-side dashboard so review adds no service,
database, daemon, telemetry, network, or new authority surface.

Common credential and private-key shapes make timeline generation fail closed
without echoing the matched value. The same classifier also rejects local host
paths and is shared with the new-R2 write boundary; historical unsafe journal
text remains a read-only fail-closed condition. A confirmed bundle is displayed only when
the existing authority files prove one unique candidate-to-bundle relationship;
ambiguous multi-confirmed workspaces are rejected rather than paired by names or
ordering. Escaped URLs may appear as visible review text, while clickable
resources remain limited to canonical workspace-relative links.

## Runtime Residue And Cleanup

Zhulong separates Docker residue from OMC/PID runtime residue. Both are surfaced
in workspace artifacts and handoff summaries, but they use different safety
policies:

| Type | Where To Review | Default Behavior | What The User Or Agent May Do |
| --- | --- | --- | --- |
| Docker containers, images, networks, volumes, BuildKit cache | `docker/docker-cleanup-plan.json`, `docker/docker-cleanliness-status.json`, `handoff-summary.md` | Generate a cleanup plan first; dry-run by default; only remove resources proven to belong to the current audit. | After human review, the user may authorize the agent to clean exact resources with `--apply`. |
| OMC stale sockets | `runtime/runtime-hygiene-status.json`, `handoff-summary.md` | Remove only stale `claude-swarm-*` sockets when no live swarm socket exists. | Run `--cleanup-stale`, then re-check. |
| Suspect `claude --teammate-mode tmux` PIDs | `runtime/runtime-hygiene-status.json`, `handoff-summary.md` | Review-only; Zhulong does not send termination signals or force-kill commands. | Inspect `pid/ppid/pgid/sess/tty/stat/command`; if a PID is confirmed stale, handle it manually outside Zhulong. |

The recommended Docker cleanup flow is to inspect the plan first:

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py \
  --workspace-dir <audit-workspace> \
  --cleanup-created
```

After confirming the listed resources belong to the current audit, authorize
precise cleanup:

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py \
  --workspace-dir <audit-workspace> \
  --cleanup-created \
  --apply
```

If the plan lists unlabeled resources that are proven to belong to this audit,
use exact adoption flags such as `--adopt-compose-project`, `--adopt-image-ref`,
`--adopt-network-name`, `--adopt-volume-name`, or `--adopt-build-cache-id`.
Do not use wildcard, prefix, regex, or "clean every project" semantics.

After cleanup, verify strict cleanliness:

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py \
  --workspace-dir <audit-workspace> \
  --verify-clean \
  --strict
```

If `clean=false`, the workspace should remain blocked and the summary should
record the residue plus safe resume steps. Zhulong must not hide residue by
recapturing the Docker baseline, and it must not trust a stale
`docker-cleanliness-status.json` as a completion signal.

OMC/PID review is only a safety gate for multi-agent usage:

```bash
bash <audit-workspace>/bin/check_omc_runtime.sh --json
```

If only stale sockets exist and no live swarm socket exists, clean sockets and
re-check:

```bash
bash <audit-workspace>/bin/check_omc_runtime.sh --cleanup-stale --json
bash <audit-workspace>/bin/check_omc_runtime.sh --json
```

If suspect teammate PIDs are reported, Zhulong only shows review metadata. Even
when PID review or cleanup flags are supplied, current Zhulong does not signal
teammate PIDs. If the user confirms that a PID is stale, terminate it manually
outside Zhulong or explicitly authorize an agent to use normal system process
tools with full awareness of the risk. Do not merge PID cleanup into Docker
cleanup, and do not use broad process cleanup.

For details, see
[`../assets/references/docker-resource-hygiene.md`](../assets/references/docker-resource-hygiene.md)
and
[`../assets/references/omc-runtime-stability.md`](../assets/references/omc-runtime-stability.md).

## Confirmed Bundle Short Path

Zhulong standardizes confirmed bundle generation as a short, repeatable path:

```text
bundle contract preflight
-> staging build wrapper
-> staging final validation
-> promote
-> validate all
-> seeded variant discovery
-> finalization
```

The bundle contract preflight checks that one selected finding has the minimum
portable, Docker-confirmed, reviewer-facing inputs needed for generation. It is
a generation gate only; it does not prove a vulnerability and does not replace
Docker evidence.

Source-bound confirmation is stricter than structural completeness. Preflight
receives the real target `--repo-root`, verifies the checked-out Git ref, reads
the target contract and verifier verdict, and hashes exact repository-relative
source ranges for the attacker entrypoint and sink or missing guard. Exact and
composed entrypoints are accepted only when their normalized replay value is
mechanically derived from those source tokens; unresolved dynamic routes remain
blocked or conditional.

Fixture-created roles, sessions, secrets, sensitive objects, ownership, or
deployment boundaries cannot support stronger real-world impact claims. An
ordinary synthetic marker may serve only as a deterministic oracle and must
state which impact claims it cannot support. Conditional findings retain every
source-bound deployment prerequisite, use an evidence-bounded severity, and
repeat the conditions in `validity-review.json`, bundle-local `findings.json`,
`verification-evidence.json`, the reviewer index, and the DOCX.

Contract fields must map to renderer output, a final validator or batch gate,
and a bundle evidence artifact. Fields that cannot be mapped should not be
added to the contract.

`finding.severity` in the contract uses the stable enum `Critical`, `High`,
`Medium`, `Low`, or `Informational`; final reviewer materials may localize that
label. `finding.bug_class` and `impact_tier.bug_class` stay free text with
recommended values in the checklist because project-specific vulnerability
classes are open-ended.

The staging build wrapper renders into `confirmed/.staging/<slug>` and runs the
same final bundle validator there before promotion. A failed staging directory
is debugging material only, not a confirmed deliverable. After promotion,
`validate_all_report_bundles.py` checks the full `confirmed/` directory before
seeded variant discovery and finalization.

Default final validation remains fail-fast. `validate_report_bundle.py
--all-errors` is a diagnostic mode for staging or final validation failures; it
collects actionable errors but does not repair bundles, relax the validator, or
confirm vulnerabilities.

Replay logs must be real command/output/oracle transcripts. Marker-only replay
logs and logs with manually appended direct-impact markers are invalid. Copied
successful transcripts need portable provenance, such as
`bundle-build-manifest.json` or reviewer-facing evidence.

The replay transcript corpus in `assets/fixtures/replay-transcript-corpus/`
anchors this trust boundary with positive and negative static samples. The
validator does not require a single rigid log format: different real transcript
shapes are acceptable when they contain command, raw output, oracle, exit/pass,
and direct-impact evidence, while marker-only, placeholder-only, thin
explanatory logs, oracle-missing logs, and copied transcripts without provenance
remain rejected.

Seeded variant discovery stays candidate-only. `seeds.jsonl` and
`variant-candidates.jsonl` are required closure artifacts for confirmed-bundle
audits, but candidate ranking and seed similarity must not be cited as
confirmation evidence.

## Report Quality Gates

Confirmed reports must state:

- attacker condition
- server condition
- concrete security impact
- real-world exploitability: practical scenario, attacker-controlled input,
  trigger/call chain, direct business or security consequence, and the
  verified-vs-not-claimed impact boundary

The validator also checks for common contradiction patterns, including:

- title or wording claiming no-auth reachability while CVSS or reproduction
  evidence requires privileges
- unconditional success banners in PoC scripts without concrete success oracles
- fail-open success-oracle lines such as `grep ... || echo ...`,
  `grep ... || true`, `jq ... || true`, `curl ... || true`, or
  `docker logs ... | grep ... || echo ...` before final confirmation banners
- stale or malformed recording step labels
- bundle-root recording helper shell syntax and executable bit
- attachment Docker Compose consistency, including missing relative `env_file`
  entries, missing relative bind-mount sources, and forbidden absolute host paths
- long natural-language output in the wrong report language
- optional target/command consistency fields when structured evidence is present
- root/attachment scripts that escape the downloaded bundle through deep
  `../../..` traversal or parent-repository mounts
- PoC label drift between report materials and the root recording helper
- stale recording videos that are older than the current report, supplement,
  evidence JSON, or root reproduction script
- package manager install commands that may trigger lifecycle-script or network
  noise in the shortest reviewer path
- replay helpers that display PoC/Docker commands but never execute them
- replay helpers that do not show `Tested Software` and
  `Tested Version / Branch` as separate opening-screen fields, or that skip the
  opening/final reviewer pauses needed for screen recording
- replay helpers that lack overrideable `REVIEWER_PAUSE_SHORT` /
  `REVIEWER_PAUSE_LONG`, replace quick-mode pauses with fixed short sleeps, or
  skip pauses after code context, code-level analysis, impact-boundary, proof
  command/output, or final summary screens
- replay helpers that reuse reviewer pause variables for service readiness,
  health polling, startup retries, or backoff; reviewer pauses are visual only,
  and functional waits must use independent readiness/backoff variables
- reproduction supplements or evidence indexes that reference missing
  bundle-local helper scripts
- missing direct-impact replay evidence, such as `DIRECT_IMPACT_CONFIRMED`,
  `DIRECT_AVAILABILITY_IMPACT_CONFIRMED`, or an equivalent programmatic oracle
- raw Python/JSON-like dict/list/object text leaking into DOCX reviewer prose
- mutable-only runtime identity such as `latest`, floating image tags, `main`,
  `master`, or vague "current version" wording without a stable version, commit,
  digest, or tested date
- direct-impact marker drift between DOCX, supplement, replay helper,
  `verification-evidence.json`, reviewer evidence index, and registered replay
  `.log` files
- registered replay `.log` files that are empty, placeholders, marker-only, or
  lack command/output/oracle transcript signals; direct-impact markers must not
  be manually appended to make a thin log pass validation
- copied or historical successful replay transcripts without portable
  provenance in `bundle-build-manifest.json` or reviewer-facing evidence
- SSRF impact-tier drift, such as proving only callback/reachability while
  claiming response content, configuration leakage, credentials, or sensitive
  data exposure without an artifact-backed oracle
- readiness or health checks in root replay helpers that target an unrelated
  host/path instead of the runtime path exercised by proof commands
- optional `reviewer-evidence-and-impact.md` files that are placeholder-only or
  missing attacker boundary, impact, success-oracle, and replay-command wording
- optional `attachments/reviewer-evidence-index.json` files with invalid JSON,
  missing artifacts, package-external paths, non-bundle-local replay commands,
  or success-oracle tokens that do not appear in reviewer sources
- fixture-based or vendored-source replay without source-grounded provenance,
  and library/package reports that omit the consuming-application boundary
- severity and claim contradictions, such as High CVSS with Medium report
  wording, webshell/HTTP command-execution claims without matching oracles, or
  container-escape/host-RCE/public-unauthenticated claims without an explicit
  non-claim boundary

These checks are intentionally conservative. They are meant to reduce false
positives without changing the confirmed bundle contract.

Reviewer-readiness gates such as SSRF impact overclaim detection, code context
minimum quality, and replay helper pause checks are classified in
[`../assets/references/reviewer-readiness-validator-gates.md`](../assets/references/reviewer-readiness-validator-gates.md).
That reference records their purpose, false-positive boundary, accepted and
rejected examples, stable issue-code expectations where applicable, and the rule
that these gates only reject weak reviewer material rather than prove
vulnerabilities or replace Docker evidence.

Evidence-level terms such as `code_level_reproduced`,
`entrypoint_reproduced`, `blocked_entrypoint_verification`, and
`confirmed_in_docker` are defined in
[`runner-contracts/finding-contract-r1.md`](runner-contracts/finding-contract-r1.md).
Code-level or function-level reproduction is supporting evidence only; bundle
readiness requires attacker-entrypoint reproduction with an input shape,
entrypoint-to-sink path, and deterministic impact oracle.

## Confirmed-Seed Variant Discovery

- A confirmed seed is a confirmed finding that already has a valid confirmed
  bundle, reproducible Docker evidence, and a completed severity-escalation pass.
- A variant candidate is a separate candidate derived from a confirmed seed as a
  similarity/ranking target and must be tracked as candidate material.
- A confirmed variant is a candidate that passes its own Docker reproduction and
  has a valid `verification_status=confirmed_in_docker` bundle; similarity alone
  is not enough.
- Route variant candidates as one of:
  `candidate`, `blocked`, `false_positive`, `unverified`, `confirmed_in_docker`.
- A variant candidate must not be reported as confirmed in a confirmed package,
  supplement, note, or reviewer-facing summary before Docker reproduction and
  independent bundle validation are complete.
- `scripts/extract_variant_seed.py` is an offline helper that reads one existing
  confirmed bundle and extracts a Variant Seed Card. It does not execute PoCs,
  run Docker, search the repository, rank candidates, or confirm variants.
- Final Variant Seed Cards are accepted only when `confirmed_bundle_path`
  resolves to a real `confirmed/<bundle>/` directory in the current audit
  workspace and that bundle passes `validate_report_bundle.py`. Candidate ids,
  markdown rows, ad hoc notes, Docker evidence directories, partial bundles, and
  validation-failed bundles fail closed; manual same-pattern notes must stay
  outside formal `evidence/variant-analysis/seeds.jsonl`.
- `scripts/find_variant_candidates.py` reads one final Variant Seed Card and
  ranks same-repository candidates offline. It uses local Python filesystem
  traversal only; it does not call scanners, `rg`, `grep`, `git`, network APIs,
  LLMs, Docker, PoCs, DOCX rendering, or confirmed bundle generation.
- Candidate output lives in `variant-candidates.jsonl`. Each record stays
  `status=candidate`, uses repo-relative file paths, includes deterministic
  score/rank evidence, and must require independent Docker or Docker Compose
  verification before any confirmation decision.
- `validate_report_bundle.py --variant-candidates` validates candidate-only
  JSONL or JSON arrays. This is separate from confirmed bundle validation:
  candidate output can guide follow-up verification, but it cannot prove a
  vulnerability.
- Confirmed bundles must not include `variant-candidates.jsonl` as primary
  evidence or cite candidate ranking, seed similarity, or candidate-only records
  as confirmation evidence.
- A Variant Seed Card is auxiliary evidence for variant discovery, not a
  replacement for `verification-evidence.json`, findings JSON, DOCX reports,
  reproduction supplements, attachment indexes, replay logs, Docker evidence, or
  confirmed bundle validation.
- Seed-card artifacts live under
  `<audit-workspace>/evidence/variant-analysis/`:
  `seeds.jsonl`, `variant-candidates.jsonl`,
  `variant-expansion-summary.json`, and optional `seed-<slug>.md` notes. Existing
  workspaces and old confirmed bundles are not required to contain these files.
- For new audits finalized as `completed_with_confirmed_bundles`, the completion
  gate requires `evidence/variant-analysis/seeds.jsonl` and
  `evidence/variant-analysis/variant-candidates.jsonl` to exist and pass their
  variant validators. This makes the same-repository variant pass part of the
  normal confirmed-bundle workflow instead of an after-chat reminder.
- Seed cards use `schema_version=1` and include: `seed_id`,
  `confirmed_bundle_path`, `bug_class`, `root_cause`, `source_pattern`,
  `propagation_pattern`, `sink_pattern`, `missing_constraint_pattern`,
  `trigger_condition`, `docker_success_oracle`, `search_scope`, and
  `negative_filters`.
- Final seed cards must be rooted in a bundle-relative or workspace-relative
  confirmed bundle path and a Docker success oracle. `root_cause`,
  `source_pattern`, `sink_pattern`, and `docker_success_oracle` must be non-empty
  and must not be `unknown` in a final card.
- Extractor final output must pass
  `validate_report_bundle.py --variant-seed-card`. Incomplete extraction becomes
  a draft note or optional draft seed card, not a final seed.
- `source_pattern` describes attacker control, `sink_pattern` describes a sink
  family/API or dangerous behavior, `search_scope` stays bounded to the same
  target repository, and `negative_filters` records directories, patterns,
  mitigations, or contexts to exclude or downgrade.
- Candidate finding must fail closed when the seed scope is not the structured
  same target repository scope, when the workspace is outside the scanned repo,
  or when the seed's confirmed bundle path does not resolve under the current
  workspace `confirmed/` directory.
- A seed card can generate variant candidates only. Every variant still requires
  independent Docker or Docker Compose reproduction and confirmed-bundle
  validation before it can be called confirmed.
- A later confirmed variant must look like a normal confirmed bundle, with its
  own Docker reproduction, replay/direct-impact evidence,
  `verification-evidence.json`, and confirmed-bundle validation.

Reviewer-facing recording helpers should derive their own bundle directory,
refer to `attachments/` relative to that directory, and either bootstrap the
Docker environment from bundle-local attachments or fail early with the exact
bundle-local command the reviewer must run first. They should check required
containers before `docker exec`, run readiness checks when practical, and print
captured command errors instead of hiding critical failures with naked
`2>/dev/null`. Harmless `../` paths are acceptable inside nested attachment
directories only when they still resolve inside the per-vulnerability bundle;
scripts must not depend on the submitter's full local repository layout.

## Example Finding Shape

```text
State: confirmed
Title: SSRF through file import URL fetch
Severity: High
Evidence: Docker reproduction observed attacker-controlled callback
Attacker condition: authenticated low-privilege user with import permission
Server condition: default import endpoint enabled, outbound network reachable
Security impact: confidentiality risk through internal service probing or metadata access
Real-world exploitability: the authenticated attacker controls the import URL;
the default server-side deny list allows private ranges; the effect is visible
as stored response content or callback traffic; Docker evidence verifies SSRF
reachability but does not claim code execution.
Bundle: confirmed/<vulnerability-slug>/
```

This is the shape of a confirmed record, not a promise that every audit will
produce one.

## Validation

Run the plugin selftest:

```bash
python3 scripts/selftest_plugin.py
```

Sync and test the installed Claude skill layout:

```bash
bash scripts/sync_to_claude_skill.sh
python3 ~/.claude/skills/zhulong/scripts/selftest_plugin.py
```

Codex user-level skill support is also available. It uses the same layout
contract, installed selftest, platform-neutral launcher, and repository-root
`AGENTS.md` guidance documented in
[`CODEX_SKILL_ADAPTATION.md`](CODEX_SKILL_ADAPTATION.md). The Codex installed
skill at `~/.agents/skills/zhulong/` is supported after syncing:

```bash
bash scripts/sync_to_codex_skill.sh
python3 ~/.agents/skills/zhulong/scripts/selftest_plugin.py
```

Validate one confirmed bundle:

```bash
python3 scripts/validate_report_bundle.py --bundle-dir <bundle-dir>
```

Default final bundle validation is fail-fast. When staging or final validation
fails and you need a diagnosis pass, explicitly opt in to the focused
all-errors collector:

```bash
python3 scripts/validate_report_bundle.py \
  --bundle-dir <bundle-dir> \
  --all-errors \
  --json \
  --output-errors <bundle-dir>/bundle-validation-errors.json
```

All-errors reports are diagnostics only. They do not repair bundles or confirm
vulnerabilities; fix the upstream contract, evidence, or reviewer materials,
then rerun validation.

Before creating final `confirmed/<slug>/` artifacts, fill
`<audit-workspace>/confirmed/.contracts/<slug>.bundle-contract.json` from
`assets/references/bundle-contract-template.json`, point its `render` section at
the selected source finding, and run:

```bash
python3 scripts/validate_bundle_contract.py \
  --repo-root <target-repository> \
  --workspace-dir <audit-workspace> \
  --contract <contract> \
  --all-errors
```

If preflight fails, fix the contract or upstream Docker evidence. Do not create
marker-only replay logs or patch direct-impact markers reactively. This
preflight is only a generation guard; final bundle validation remains
mandatory.

Then build through staging:

```bash
python3 scripts/build_confirmed_bundle.py \
  --repo-root <target-repository> \
  --workspace-dir <audit-workspace> \
  --contract <contract> \
  --language <zh-CN|en-US>
```

Do not hand-create final confirmed bundle directories. The wrapper renders a
single selected finding under `confirmed/.staging/<slug>`, runs final bundle
validation, promotes only after validation passes, and then runs batch
validation. Failed builds stay under `confirmed/.staging/` and must not be
called confirmed deliverables. Final audit finalization and the seeded variant
discovery gates remain mandatory.
The wrapper does not execute replay by default. It records replay-log provenance
for bundled evidence when available, and final validation decides whether the
registered replay log is a trusted transcript.

Validate all bundles in a workspace:

```bash
python3 scripts/validate_all_report_bundles.py --confirmed-dir <repo>/<audit-workspace>/confirmed
```

Before publishing a release, run:

```bash
cat docs/RELEASE_CHECKLIST.md
```

## Limitations

- Zhulong does not guarantee vulnerability discovery.
- Zhulong does not replace expert review or responsible disclosure judgment.
- Zhulong does not automatically log in to registries or silently substitute
  non-equivalent Docker images.
- Zhulong does not clean uncertain Docker resources or OMC teammate PIDs.
- Zhulong does not run a hosted backend, dashboard, database, vector store, or
  RAG service.

## Optional Final Recording Workflow

The ordinary confirmed-bundle path ends at Docker/report validation. Final
screen recording is a separate opt-in path and does not turn an ordinary
confirmed finding into a recording-ready or submission-ready artifact.

Use the public repository implementation:

```bash
python3 scripts/auto_record_bundle.py confirmed/<slug> \
  --repo-root . \
  --mode record \
  --engine docker
```

The recorder resolves canonical identity from bundle-local `findings.json`,
`validity-review.json`, `verification-evidence.json`, and source-bound contract
material. It requires the generated root helper's
`identity`, `code_or_trigger_context`, and `final_impact` checkpoint protocol.
The helper writes events only into a recorder-owned temporary directory; the
adapter verifies the OBS source/window, captures live checkpoint images outside
the bundle, and acknowledges each event. A helper without this protocol fails
closed in recording mode. When recording variables are absent, ordinary replay
does not wait for an acknowledgement. Acknowledgements are parsed as JSON
semantics, not compact-text fragments: the helper requires an ordinary,
recorder-owned ack file whose object has the exact protocol version, `ack`
status, stage, integer sequence, and expected marker. Pretty or compact JSON,
whitespace, and key order do not change that protocol.

The recording validator extracts frames from the final encoded video, checks
non-black content, timestamps/holds, and conservative similarity to the live
source images. Each stage's `recording_time_observations` is a recorder-supplied
consistency claim that can fail closed or improve an error diagnosis, but is not
independent visual proof of encoded content. It creates exactly:

```text
attachments/evidence/screenshots/01-target-identity.png
attachments/evidence/screenshots/02-code-or-trigger-context.png
attachments/evidence/screenshots/03-final-impact.png
```

It recomputes screenshot hashes/dimensions and requires registration in
`verification-evidence.json`, `attachments/reviewer-evidence-index.json`, and
the attachment inventory. The final `recording-evidence.json` is strict and
records identity, media, replay, OBS/window, checkpoint, registration, and
archive-readiness fields.

`--finalize` requires `--checkpoint-dir` and performs full recording-time
validation: it recomputes the live-checkpoint/final-frame relationship before
recording promotion authority. A later invocation without the checkpoint
directory is deliberately `artifact_only` revalidation; it can recheck hashes,
inventory, screenshots, and archive consistency, but cannot establish a new
recording-time content proof.

Promotion is transactional. OBS output and staging remain outside the final
bundle; the staged bundle is checked by `validate_report_bundle.py` and
`validate_recording_evidence.py`; a temporary UTF-8 ZIP passes `testzip()` and
required-entry checks; only then are the bundle directory and ZIP atomically
promoted. Replay, frame, archive, or promotion failure leaves the original
bundle/video/screenshots/ZIP byte-identical and retains a labelled unpromoted
recorder session. The older local recording skill is compatibility-only and is
not the source of truth.

`--keep-unpromoted-archive DIR` is optional and never writes a final-named ZIP.
Only if a later promotion failure occurs after the staged ZIP has fully passed
validation does it copy that unpromoted diagnostic archive to the explicit
bundle-external directory; it never overwrites an existing diagnostic copy.
The legacy `--zip-on-fail` flag emits a deprecation warning and creates no
failure archive.

## Root Skill kernel and phase references

The root `SKILL.md` is intentionally limited to product boundaries, core safety
invariants, lifecycle authority, phase-reference loading, the confirmed bundle
path, canonical finalization, and opt-in recording. Detailed phase operations
live in the baseline `audit-phase-*.md` references and
`audit-continuation-state.md`.

`assets/root-skill-rule-inventory.json` records why each former root rule is
retained or moved and binds it to production schema, validators, gates, fixed
wrappers, the kernel, references, and selftests. Validate the relationship with:

```bash
python3 scripts/validate_root_skill_rule_inventory.py \
  --skill-root . \
  --inventory assets/root-skill-rule-inventory.json \
  --json
```

A moved hard constraint requires a real production carrier; documentation,
references, inventory, and selftests are not production authority. Phase
references are catalog baseline modules, but `mandatory` remains planned reading
priority only. It does not prove an Agent read, understood, applied, or completed
a reference and grants no execution, confirmation, promotion, recording, or
finalization authority. See
`docs/runner-contracts/root-skill-kernel-r1.md`.

## Authority-bound completion and verification-wrapper boundary

Completion is a substantive evidence-chain decision, not a count of state fields,
validated bundle directories, or self-authored Markdown. For a confirmed result,
the read-only completion helper requires a one-to-one chain:

```text
candidate.json -> verifier-verdict.json -> candidate disposition -> confirmed bundle
```

The candidate and verifier are revalidated by their production validators. Their
candidate IDs, target references, verdict/status, Docker-confirmed status, and
evidence fields must agree; Candidate R2 records also bind the candidate file
SHA-256 and fingerprint. A bundle's
`validity-review.json.source_binding.materials.verifier_verdict` must be a safe,
workspace-relative regular file and must point to exactly one passed disposition.
The standalone bundle validator remains necessary but is not sufficient.

For `completed_no_confirmed_findings`, every discovered candidate must have one
production-valid terminal verifier disposition and only `false_positive` may
permit nonconfirmation. Candidate, unverified, blocked, missing, duplicate, or
orphaned records remain blocking. When there are no candidate files, R2 requires
an existing production-valid Recon coverage result (with no gaps or blockers)
that proves the reviewed surface; an arbitrary boolean or hand-written “no
findings” note is not a substitute. The same read-only predicate is consumed by
the finalizer, handoff derivation, workspace validator, and finalization assertion.

Legacy R1 workspaces remain readable and their historical completion fields are
not silently migrated. New R2-only transition intent is rejected by automatic
R1 writing; a real R1 producer must pass `--protocol-mode legacy-r1`, and the
write result reports compatibility/ignored-field diagnostics. This compatibility
does not describe the workspace as R2 verification-complete.

The verification wrapper validates the case identifier and evidence directory
before it creates evidence, reads authority, invokes Docker, or runs a PoC. Case
IDs must start with an ASCII letter or digit and contain only ASCII letters,
digits, `.`, `_`, and `-`; dot components, separators, whitespace, control
characters, and leading-dot IDs are rejected. The evidence path must normalize
exactly to `<workspace>/evidence/<case-id>` and cannot traverse symlink or
non-directory ancestors. A workspace with neither journal nor state view is
blocked with `AUTHORITATIVE_STATE_MISSING` before execution. Docker cleanliness
checks have no production success bypass; the former test-only skip variable is
unsupported.

### Closure security boundary rules

The verification wrapper owns control evidence. `verification-result.json`,
`command.json`, sandbox status, `stdout.log`, `stderr.log`, and authority
references are created or replaced with host-owned, identity-checked file
descriptors and same-directory atomic publication. `/workspace/evidence` is
read-only when it is mounted into a Docker-run case; a separate
`/workspace/output` mount is the only default writable container-output area,
and output files are review-only attachments. The oracle reads bytes held by
the host capture descriptors, never reopens a container-replaceable pathname.
Symlink, hardlink, FIFO, directory, ancestor drift, and running pathname
replacement therefore fail closed and cannot write `stage-status.json` or
turn a case into `confirmed_in_docker`. Compose cases receive the same host
capture treatment; writable binds overlapping workspace control paths are
rejected.

Sandbox preflight is a proof obligation before any evidence or Docker side
effect. Compose services must declare literal `privileged: false`; anchors,
aliases, interpolation and non-static namespace values are rejected. Unknown
or value-less extra Docker arguments are rejected; only documented resource
limits and `--read-only` are allowed. Bootstrap workspace names are one safe
ASCII directory component and the destination must be a direct child of a
real target directory.

`blocked_verification.py` first consumes structured verification results,
verdicts, dispositions and normalized events. An unresolved identity-specific
`blocked_*`, timeout, unsafe-sandbox, missing-image/runtime, or authority-event
failure blocks completion. Only a later structured result for the same case or
candidate identity can resolve it; text scanning is a conservative fallback
for historical R1 workspaces and skips examples/resolved sentences.

Publishable R1 text, `tested_ref`, handoff and checkpoint fields share the
portable classifier. Local absolute paths, credentials, private keys, tokens
and control characters are rejected before append/publication; the raw value
is never returned. Normal SHA-1/SHA-256 refs, tags, branches, URLs without
embedded credentials and workspace-relative evidence paths remain valid. New
R1 state uses logical workspace/repository labels rather than parsed host
paths.

The Tool Registry treats `prohibited` as an exclusive boundary: effects,
wrappers, authority, active network and planner capabilities must all be
empty/prohibited. Finalization requires a safe current
`docker/docker-cleanliness-status.json` with `clean=true` and `strict=true`.
The `finalization_succeeded` event must bind its relative path, SHA-256,
workspace and `checked_at`; missing, stale, symlinked, mismatched or manually
paired status evidence fails the assertion.
