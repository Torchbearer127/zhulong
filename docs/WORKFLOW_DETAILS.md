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

## Seeded Variant Discovery (P6)

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
- P6.1 established the seeded-variant workflow boundary. P6.2 defines the Variant Seed Card fields without implementing automatic seed extraction or candidate finding.
- P6.3 adds `scripts/extract_variant_seed.py`, an offline helper that reads one
  existing confirmed bundle and extracts a Variant Seed Card. It does not
  execute PoCs, run Docker, search the repository, rank candidates, or confirm
  variants.
- P6.4 adds `scripts/find_variant_candidates.py`, an offline helper that reads
  one final Variant Seed Card and ranks same-repository candidates. It uses
  local Python filesystem traversal only; it does not call scanners, `rg`,
  `grep`, `git`, network APIs, LLMs, Docker, PoCs, DOCX rendering, or confirmed
  bundle generation.
- P6.4 candidate output lives in `variant-candidates.jsonl`. Each record stays
  `status=candidate`, uses repo-relative file paths, includes deterministic
  score/rank evidence, and must require independent Docker or Docker Compose
  verification before any confirmation decision.
- P6.5 adds `validate_report_bundle.py --variant-candidates` for candidate-only
  JSONL/JSON-array validation. This is separate from confirmed bundle
  validation: candidate JSONL can guide follow-up verification, but it cannot
  prove a vulnerability.
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

Validate one confirmed bundle:

```bash
python3 scripts/validate_report_bundle.py --bundle-dir <bundle-dir>
```

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
