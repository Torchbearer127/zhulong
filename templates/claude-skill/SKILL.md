---
name: zhulong
description: Zhulong (烛龙), a Docker-first security-focused code audit workflow with runtime checks, dynamic toolchain planning, deterministic confirmed vulnerability bundles, and final workspace validation.
---

# Zhulong (烛龙)

Use this Claude Code skill when you want a repository-level security-focused code audit workflow that is:

- Docker-first for PoC execution and verification
- broader than vulnerability scanning: it records confirmed vulnerabilities, candidates, false positives, non-security defects, hardening-only observations, and unverified leads separately
- dynamic in tool selection based on stack and installed capabilities
- deterministic in report generation
- packaged from the open-source plugin repository into a Claude-native skill layout

## Installed Claude Skill Layout

- runtime checks:
  - [check_docker_gate.sh](./scripts/check_docker_gate.sh)
  - [check_omc_runtime.sh](./scripts/check_omc_runtime.sh)
  - [check_sandbox_preflight.py](./scripts/check_sandbox_preflight.py)
  - [check_security_tooling.sh](./scripts/check_security_tooling.sh)
  - [asr_exec.sh](./scripts/asr_exec.sh)
- Docker verification runner:
  - [run_verification_case.sh](./scripts/run_verification_case.sh)
- Docker resource hygiene:
  - [manage_docker_resources.py](./scripts/manage_docker_resources.py)
  - [docker-resource-hygiene.md](./assets/references/docker-resource-hygiene.md)
- handoff summary:
  - [render_handoff_summary.py](./scripts/render_handoff_summary.py)
- dynamic planning:
  - [plan_security_toolchain.py](./scripts/plan_security_toolchain.py)
  - [tool-registry.json](./assets/tool-registry.json)
- language-specific source-to-sink playbooks:
  - [java-web-audit-playbook.md](./assets/references/java-web-audit-playbook.md)
  - [go-web-audit-playbook.md](./assets/references/go-web-audit-playbook.md)
  - [nodejs-library-audit-playbook.md](./assets/references/nodejs-library-audit-playbook.md)
  - [nodejs-web-audit-playbook.md](./assets/references/nodejs-web-audit-playbook.md)
  - [php-swoole-audit-playbook.md](./assets/references/php-swoole-audit-playbook.md)
  - [python-library-audit-playbook.md](./assets/references/python-library-audit-playbook.md)
  - [python-web-audit-playbook.md](./assets/references/python-web-audit-playbook.md)
- optional vulnerability-type checklists:
  - [ssrf-checklist.md](./assets/references/ssrf-checklist.md)
  - [path-traversal-checklist.md](./assets/references/path-traversal-checklist.md)
  - [prototype-pollution-checklist.md](./assets/references/prototype-pollution-checklist.md)
- seeded variant discovery:
  - [extract_variant_seed.py](./scripts/extract_variant_seed.py)
  - [find_variant_candidates.py](./scripts/find_variant_candidates.py)
  - [variant-seed-template.md](./assets/references/variant-seed-template.md)
  - [variant-seed.schema.json](./assets/schemas/variant-seed.schema.json)
- workspace setup:
  - [prepare_target_repo.sh](./scripts/prepare_target_repo.sh)
  - [bootstrap_verification_workspace.sh](./scripts/bootstrap_verification_workspace.sh)
- reporting:
  - [render_confirmed_vuln_docx.py](./scripts/render_confirmed_vuln_docx.py)
  - [scaffold_bilingual_findings.py](./scripts/scaffold_bilingual_findings.py)
  - [validate_report_bundle.py](./scripts/validate_report_bundle.py)
  - [validate_all_report_bundles.py](./scripts/validate_all_report_bundles.py)
- completion gate:
  - [finalize_audit_workspace.py](./scripts/finalize_audit_workspace.py)
  - [assert_finalized_workspace.py](./scripts/assert_finalized_workspace.py)
  - [audit_disposition.py](./scripts/audit_disposition.py)

## Plugin-Owned Hard Constraints

The user's launch prompt should stay short. Treat the rules below as the skill's
default contract even when the user does not restate them:

- Prepare the target repository and per-audit workspace autonomously. Do not ask
  the user to run a chain of helper Bash commands during normal use.
- Keep all final audit output under the target repository in a timestamped
  workspace such as `security-research-YYYYMMDD-HHMMSS/`; never use a bare
  workspace-root `security-research/` for new remote-repository audits.
- Run all PoCs, exploit payloads, and verification traffic only inside Docker or
  Docker Compose. If Docker is unavailable, update `<audit-workspace>/audit-log.md`,
  preserve collected artifacts, print a visible pause summary, and stop
  verification instead of falling back to host execution.
- When Docker images are needed, prefer suitable local images or already-cached
  base images first. Pull from the network only when no suitable local image is
  available.
- Track Docker resource ownership per audit workspace. Prefer
  `<audit-workspace>/bin/manage-docker-resources.py --cleanup-created` dry-run
  before finishing, and only use `--apply` after confirming the listed images,
  volumes, networks, or stopped containers carry this workspace's Zhulong
  ownership labels and were created by this audit. New unlabeled resources may
  belong to another parallel audit, target Compose stack, or unrelated Docker
  application and must be reviewed manually, not auto-deleted. Finish with
  `--verify-clean --strict`; if it fails, report or resolve the exact residual
  resources instead of calling the environment clean. For Compose stacks this
  audit explicitly started, use exact `--adopt-compose-project` and, when
  needed, exact `--adopt-image-ref`, `--adopt-network-name`, or
  `--adopt-volume-name` cleanup flags rather than broad matching. Never
  overwrite the Docker baseline to make residue disappear; `--force-overwrite-baseline`
  is not a cleanup mechanism. Never use broad Docker prune commands as the
  cleanup path.
- For individual PoC checks, prefer `run_verification_case.sh` or an equivalent
  Docker-only wrapper with a mandatory timeout, explicit network setting,
  resource limits, and structured evidence. The stable verification case labels
  are `blocked_docker_unavailable`, `blocked_missing_image`, `failed_timeout`,
  `failed_resource_limit`, `rejected_unsafe_sandbox`,
  `rejected_not_reproducible`, and
  `confirmed_in_docker`.
- Docker / sandbox preflight is a verification safety guard, not vulnerability
  confirmation. If `rejected_unsafe_sandbox` appears, keep the case in
  candidate/blocked/unverified notes only, manually rewrite the verification
  container or script, and never place that result under `confirmed/`.
- Prefer `gh` for GitHub repositories, advisories, issues, pull requests,
  commits, and releases. Do not execute `web_search`, `Search(...)`,
  `Fetch(...)`, or `WebFetch(...)` as Bash commands.
- If `git clone` fails and a GitHub archive or `gh api` fallback is used,
  record the exact source commit SHA and archive source in `fingerprint.md`.
  Archive fallback without an exact commit identity is not acceptable for final
  source/runtime claims.
- Before multi-agent execution, run the OMC runtime gate. If it reports
  `single_agent_only`, continue single-agent. If it reports `cleanup_needed`,
  show `suspect_teammate_pids`, `stale_swarm_sockets`, `live_swarm_sockets`,
  `ignored_current_session_teammate_pids`, and `unresolved_review_only` from
  `runtime/runtime-hygiene-status.json`; never auto-kill teammate processes.
  Teammate PID cleanup is review-only inside Zhulong, even when `--apply` is
  supplied; inspect with `ps -fp <pid>` and the owning terminal/session, and
  terminate stale teammate PIDs manually outside Zhulong only after operator
  confirmation.
- Confirm vulnerabilities only with Docker evidence. After the first
  confirmation, run one explicit severity-escalation pass in Docker before final
  scoring, and only upgrade severity when stronger impact is verified.
- After a confirmed seed is available, run one explicit seeded variant-discovery
  pass in the same repository using the confirmed seed only when it already has
  a valid confirmed bundle and Docker success oracle.
- A confirmed seed must document the root-cause chain, attacker-controlled source,
  propagation path, sink family, missing constraint, trigger condition, and a
  deterministic success oracle.
- A Variant Seed Card is auxiliary evidence for seeded variant discovery, not a
  confirmed vulnerability and not a replacement for `verification-evidence.json`,
  findings JSON, DOCX reports, reproduction supplements, attachment indexes,
  replay logs, Docker evidence, or confirmed bundle validation.
- Write future seed-card artifacts under
  `<audit-workspace>/evidence/variant-analysis/` as `seeds.jsonl`,
  `variant-candidates.jsonl`, `variant-expansion-summary.json`, and optional
  `seed-<slug>.md` notes. Do not require existing workspaces or old confirmed
  bundles to contain these files.
- Final seed cards use schema version `1`, are rooted in a confirmed bundle path
  that is bundle-relative or workspace-relative, keep search scope bounded to the
  same target repository, and must not use `unknown` for root cause, source,
  sink, or Docker success oracle.
- To bridge an existing confirmed bundle into the seed-card contract, use
  `scripts/extract_variant_seed.py` offline. It reads existing bundle evidence
  only; it does not execute PoCs, run Docker, search the repository, rank
  candidates, or confirm variants.
- Extractor final output must pass
  `validate_report_bundle.py --variant-seed-card`. Incomplete extraction is a
  draft note or optional draft seed card, not a final seed.
- To rank candidates from one final seed card, use
  `scripts/find_variant_candidates.py` offline. It reads local same-repository
  source text only; it must not call scanners, `rg`/`grep`/`git`, network APIs,
  LLMs, Docker, PoCs, DOCX rendering, or confirmed-bundle generation.
- Candidate finder output is auxiliary `variant-candidates.jsonl` material only:
  every record must stay `status=candidate`, use repo-relative file paths, and
  require independent Docker or Docker Compose verification before any
  confirmation decision.
- Validate candidate output with
  `scripts/validate_report_bundle.py --variant-candidates <path>`. This
  candidate validation is separate from confirmed bundle validation.
- Candidate JSONL can guide follow-up verification, but it cannot prove a
  vulnerability. Confirmed bundles must not cite candidate ranking, seed
  similarity, or `variant-candidates.jsonl` as confirmation evidence.
- Variant candidates are candidate material by default. Route them as one of:
  `candidate`, `blocked`, `false_positive`, `unverified`, `confirmed_in_docker`.
- Do not mark a variant candidate as confirmed based on resemblance to a seed.
  It must complete its own Docker reproduction and confirmed-bundle validation
  before `confirmed_in_docker`.
- The seeded variant pass must not replace the severity-escalation pass. Both are
  required in a normal confirmed discovery flow.
- Static scanning, source-to-sink reasoning, pattern matching, dependency alerts,
  and LLM analysis can only create candidates. They must not be written as
  confirmed findings unless Docker reproduction succeeds.
- Blocked Docker/runtime verification is not the same as
  `completed_no_confirmed_findings`. If material candidates or unverified leads
  say `BLOCKED`, `Docker rate limit`, `pull access denied`, `authentication
  required`, `missing image`, `runtime not started`, or equivalent Docker
  verification blocker language, keep the workspace blocked and rerun Docker
  verification after recovery. Do not finalize as no-confirmed.
- If a high-confidence unverified lead still has blocked/no-Docker verification,
  record `Material blocker?`, `Default runtime scope?`, and `Why completion is
  still safe?`. Without that materiality rationale, do not finalize as
  `completed_no_confirmed_findings`.
- Initial probe results are classification evidence only. Read
  `<audit-workspace>/evidence/initial-probes/initial-probes-summary.json` before
  interpreting raw scanner logs. Statuses such as `ran_ok`,
  `skipped_tool_missing`, `skipped_no_package_sources`, `failed_nonfatal`, and
  `failed_fatal` must not be reported as confirmed vulnerabilities or copied
  into `confirmed/`.
- Use `<audit-workspace>/handoff-summary.md` as the first-read continuation
  packet for new agent sessions. It is a context-slimming index over lightweight
  files, not a report, not raw scanner output, and not a source for DOCX
  generation or confirmed findings.
- False positives, non-security defects, unverified leads, and
  high-confidence-but-not-Docker-confirmed leads are workspace records only.
  Keep them in `candidate-findings.md`, `false-positives.md`,
  `unverified-leads.md`, or equivalent workspace notes. Never write them under
  `confirmed/`, never generate confirmed DOCX reports for them, and never list
  them as confirmed vulnerabilities.
- Fill `<audit-workspace>/attack-surface.md` as a concise handoff artifact for
  entry points, trust boundaries, high-risk sinks, and source-to-sink
  hypotheses. It is not a vulnerability report, not raw scanner output, and not
  a replacement for `candidate-findings.md`, `false-positives.md`,
  `unverified-leads.md`, or confirmed bundles. Hypotheses in it remain
  unverified until Docker confirmation succeeds.
- Use local vulnerability-type checklists only as optional first-read aids for
  relevant candidates. Checklist matches, source-to-sink hypotheses, and pattern
  matches cannot confirm a vulnerability by themselves and must stay out of
  `confirmed/` until Docker evidence exists.
- Language playbooks are starting maps, not fences. They are not exhaustive and
  must not be used to stop exploring repository-specific frameworks, data flows,
  sinks, or deployment patterns that are not listed in the playbook.
- Write final confirmed bundles only to
  `<audit-workspace>/confirmed/<one-folder-per-vulnerability>/`, with exactly one
  confirmed vulnerability per bundle.
- Every final bundle must be self-contained and portable: one finding-specific
  `.docx`, one finding-specific attachment index markdown, one finding-specific
  reproduction supplement markdown, `verification-evidence.json`, `attachments/`,
  and one reviewer-friendly bundle-root reproduction helper script.
- Confirmed bundles must not embed submitter-local absolute paths, `file://`
  URLs, parent workspace names, template paths, external checkout paths, or
  package-root shortcuts such as `/pkg/index.js`; keep reviewer-facing paths
  relative to the delivered bundle.
- Bundle-root replay helpers must derive their root from the script path
  (`SCRIPT_DIR`, `BUNDLE_ROOT`, or equivalent), mount/read only bundle-local
  files, honor `REVIEWER_PAUSE_SHORT` and `REVIEWER_PAUSE_LONG`, and support
  quick automation with `REVIEWER_PAUSE_SHORT=0 REVIEWER_PAUSE_LONG=0 ./run-*.sh quick docker`.
- Bundle-root replay helpers are reviewer-facing recording artifacts: they must
  print concrete commands before execution, capture raw stdout/stderr into a
  bundle-local `attachments/evidence/*.log`, and check a deterministic success
  marker programmatically before final confirmation.
- Bundle-root replay helpers must be helper-closed: helper-like calls such as
  `run_*`, `verify_*`, `assert_*`, `show_*`, `print_*`, or `require_*` must be
  defined in the same script unless they are normal shell/system commands.
- Bundle-root replay helpers must not recursively call themselves from the proof
  path. They should invoke the underlying Docker or Docker Compose proof command
  directly.
- For time-based availability or performance proofs, exact timing values belong
  in fresh logs. DOCX, Markdown, JSON, and evidence summaries should use
  thresholds, ranges, order-of-magnitude wording, or references to the latest
  log instead of stale exact seconds.
- Public issue text must be sanitized: do not disclose unpublished package names,
  vulnerability titles, bundle paths, attachment filenames, PoC commands,
  payloads, or local filesystem paths.
- Validate every final bundle before finishing. A bare `findings.json`, generic
  filenames such as `report.docx` or `attachments.md`, final `evidence/`
  directories, runtime state, source-control directories, dependency trees, or
  cache directories inside a final bundle are incomplete output.
- A finding may be called a confirmed deliverable only after both Docker
  evidence and successful bundle validation exist. Docker-confirmed evidence in
  an incomplete bundle must be described as `Docker-confirmed but bundle incomplete`,
  not as a completed confirmed deliverable.
- Keep the DOCX, attachment note, reproduction supplement, findings JSON, and
  recording script semantically aligned with the same project, vulnerability
  identity, severity rationale, and verified oracle.

## Standard Execution Order

1. Prepare the target repository automatically through the skill.

For GitHub repositories, advisories, issues, pull requests, commits, and releases, prefer the `gh` CLI first. Do not rely on browser-style GitHub fetches when equivalent `gh` commands are available.

Do not execute `web_search`, `Search(...)`, `Fetch(...)`, or `WebFetch(...)` as Bash commands. They are agent/tool affordances, not shell binaries. If external intelligence is needed:

- use `gh` first for GitHub repositories, advisories, issues, pull requests, commits, and releases
- use the agent's native web/fetch tool when the runtime exposes one
- use explicit shell tools such as `curl` only for ordinary HTTP fallback, and record the source URL in the audit notes
- if no external lookup path is available, keep the lead as unverified external intelligence instead of failing with `command not found`

If a manual fallback is truly needed, do not call `./scripts/prepare_target_repo.sh` from an arbitrary current working directory. Use the installed one-shot launcher instead. By default it creates a new per-audit workspace such as `security-research-YYYYMMDD-HHMMSS/` under the repository root:

```bash
bash "$HOME/.claude/skills/zhulong/scripts/asr_start.sh" --source <local-path-or-repo-url>
```

By default this launcher writes OMC suspect teammate PIDs to workspace status and
handoff artifacts without interrupting the run. Add
`--prompt-runtime-pid-review` only when the operator wants an explicit terminal
review block. This option never enables automatic teammate PID cleanup.

If `git clone` fails, a `gh api` or source-archive fallback is acceptable only
when the exact commit SHA is recorded. Update `fingerprint.md` with the archive
URL/source, resolved commit SHA, and any runtime/source alignment caveat before
verification continues.

2. Check Docker gate, runtime, and tooling capability:

```bash
bash <audit-workspace>/bin/check-docker-gate.sh --repo-root <repo-root> --note "pre-verification gate"
bash <audit-workspace>/bin/check_omc_runtime.sh --json
bash <audit-workspace>/bin/check_security_tooling.sh
```

If the Docker gate blocks verification, stop immediately. Keep all collected artifacts under `<repo>/<audit-workspace>/`, update `<audit-workspace>/audit-log.md`, and do not execute PoCs on the host.
If an image pull blocks verification because of Docker Hub rate limits,
`toomanyrequests`, `pull access denied`, `authentication required`, DNS/network
timeout, `missing image`, or no cached images, record blocked verification in
candidate/unverified records. The resume step should be operator action such as
`docker login`, pre-pulling the required images, or configuring an approved
equivalent registry mirror; then rerun Docker verification, not finalization.
Never auto-login, store credentials, or silently swap to a non-equivalent image.

If Docker gate or OMC runtime gate pauses the workflow, do not fail silently. Print a clear terminal pause block that includes:

- the exact blocker and why it was triggered
- the relevant log or evidence path
- confirmation that collected artifacts were preserved
- the precise resume step
- a pointer to `<audit-workspace>/handoff-summary.md` or the command to render it:
  `python3 <audit-workspace>/bin/render-handoff-summary.py --workspace-dir <audit-workspace>`

If `check_omc_runtime.sh` reports `cleanup_needed`, treat it as a manual-review
state first. Do not auto-kill teammate-mode processes and do not use deprecated
`--force-kill-suspect-teammates`. If `suspect_teammate_pids` or
`stale_swarm_sockets` are reported, show them explicitly with the exact
`resume_step` from `runtime/runtime-hygiene-status.json`. Stale socket cleanup
uses `--cleanup-stale` only when no live socket exists. Suspect PID cleanup is
always review-only in Zhulong, records process metadata and
`unresolved_review_only`, and must not signal teammate PIDs. A missing live
swarm socket does not prove the process is stale. OMC runtime residue is not
Docker residue and must not be routed through Docker cleanup or counted as
Docker dirty state.

Workspace bootstrap captures a Docker resource baseline when Docker is
available. If Docker was unavailable during bootstrap, capture a baseline before
starting verification:

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py --workspace-dir <audit-workspace> --capture-baseline
```

At the start of every resumed or handed-off session, refresh and read the
handoff summary before opening raw logs:

```bash
python3 <audit-workspace>/bin/render-handoff-summary.py --workspace-dir <audit-workspace> --repo-root <repo-root>
```

Read lightweight files first (`stage-status.json`, `attack-surface.md`,
`initial-probes-summary.json`, `candidate-findings.md`, `false-positives.md`,
and `unverified-leads.md`). Avoid default-reading `evidence/**/*.log`, large
SBOM/dependency outputs, Docker diagnostic blocks, or raw scanner logs unless a
specific candidate, blocker, or reproduction question requires them.

3. Plan the repository-specific toolchain:

```bash
python3 <audit-workspace>/bin/plan-security-toolchain.py --target-dir <repo-root>
```

If the plan prints `specialized_playbooks`, use those playbooks as focused
source-to-sink guidance for this audit. For Java Web, Go Web, Node.js Web,
PHP/Swoole, and Python Web repositories, create or update `<audit-workspace>/attack-surface.md`
with the route/handler map, trust boundaries, authentication requirements, and
high-risk sinks before turning candidates into confirmed findings. For pure
Node.js or Python library/framework repositories, use the library playbooks
instead of forcing web route or middleware inventories; map public APIs,
extension hooks, parser inputs, option objects, transformations, high-risk
sinks, and consumer-impact assumptions.

If the plan prints `attack_surface_guidance`, use it to keep the handoff packet
small and stack-specific. For supported web playbooks, each entry inventory
should include route or endpoint, method, handler/controller, authentication
requirement, input source, downstream sink or service, and current verification
status. For library playbooks, each entry should include public API or CLI,
input shape, caller-controlled options, transformation path, high-risk sink,
consumer impact assumption, and current verification status. Do not use
`attack-surface.md` as a DOCX source or as a shortcut into `confirmed/`.
For Appwrite-like PHP/Swoole monorepos, treat frontend/test package-lock files
as secondary unless Node.js services are part of the verified runtime.

If the plan prints `local_knowledge_checklists`, read only the relevant local
checklists as concise source-to-sink and Docker-verification aids. These files
are optional references, not evidence; do not create DOCX reports or confirmed
findings from checklist hypotheses alone.

For first-pass scanner execution, prefer the bundled runner:

```bash
bash <audit-workspace>/bin/run-initial-probes.sh --repo-root <repo-root> --workspace-dir <audit-workspace>
```

After it finishes, read
`<audit-workspace>/evidence/initial-probes/initial-probes-summary.json` before
opening raw logs. The structured summary uses stable statuses:
`ran_ok`, `skipped_tool_missing`, `skipped_no_package_sources`,
`failed_nonfatal`, and `failed_fatal`. Treat missing optional tools as
`skipped_tool_missing`; treat `osv-scanner` output containing
`No package sources found` as `skipped_no_package_sources`, not as a fatal audit
failure and not as a vulnerability.

Do not treat raw dependency-scanner exit codes as workflow blockers without
reading the output. In particular, `osv-scanner scan source -r <repo>` may exit
128 with `No package sources found` when a repository has no supported lockfile,
manifest, or SBOM source. Record that state as `skipped_no_package_sources` and
continue with source review and Docker-based verification; it is not a confirmed
vulnerability and not a reason to stop the audit.

Before promoting suspicious behavior, perform a security-boundary triage check
when project materials are available: read `SECURITY.md`, the official security
policy, default configuration docs, or the project security model. Decide whether
the behavior is a vulnerability, expected behavior, administrator-trust behavior,
default-config-safe behavior, or outside the project's security boundary. Record
false-positive reasons with stable codes when applicable:
`expected_behavior`, `outside_security_boundary`,
`requires_non_default_admin_trust`, `default_config_not_vulnerable`,
`insufficient_attacker_condition`, or `insufficient_security_impact`.

4. Verify findings only inside Docker or Docker Compose.
When verification needs Docker images, prefer suitable local images or already-cached base images first. Only pull from the network if no suitable local image is available.

For a single verification case, prefer the bundled runner:

```bash
bash <audit-workspace>/bin/run-verification-case.sh \
  --workspace-dir <audit-workspace> \
  --case-id <case-id> \
  --mode docker-run \
  --image <local-or-cached-image> \
  --timeout-seconds 300 \
  --expected-oracle <token-or-regex> \
  --network <none-or-docker-network> \
  -- <container command...>
```

The runner enforces sandbox preflight before any Docker execution, then a
mandatory timeout, records stdout/stderr plus `verification-result.json` under
`<audit-workspace>/evidence/<case-id>/`, and never executes PoC logic on the
host. For `docker-run`, defaults include memory, CPU, pids, read-only root
filesystem, dropped capabilities, no-new-privileges, and explicit network
selection. Network use must be intentional: default `--network none` is safe for
offline parser/package PoCs, while service probes should name the target Docker
network. If the runner returns `rejected_unsafe_sandbox`, do not run Docker,
do not create confirmed bundles, and rewrite privileged/host/docker.sock/root
mount behavior before retrying. If the runner returns `failed_timeout`, pause
and re-analyze service readiness, waiting conditions, network blocking, loops,
or interactive prompts before retrying.

Runner-produced evidence is a workspace artifact. To confirm a vulnerability,
copy the relevant runner logs/result JSON into the final bundle's
`attachments/` and keep `verification-evidence.json` set to
`verification_status=confirmed_in_docker`; timed-out, blocked, resource-limited,
or rejected cases, including `rejected_unsafe_sandbox`, must stay out of
`confirmed/`. Sandbox preflight does not replace Docker cleanup and never
permits broad Docker prune.

Before final summary, inspect Docker resources created after the workspace
baseline. Start with a dry-run cleanup plan and apply only after confirming the
resources belong to this audit:

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py --workspace-dir <audit-workspace> --cleanup-created
python3 <audit-workspace>/bin/manage-docker-resources.py --workspace-dir <audit-workspace> --cleanup-created --apply
python3 <audit-workspace>/bin/manage-docker-resources.py --workspace-dir <audit-workspace> --verify-clean --strict
```

If cleanup is blocked because a container or volume is still in use, record the
blocker and do not fall back to broad Docker-wide cleanup commands.
If the cleanup plan lists unlabeled resources created after the baseline, treat
them as review-only because they may belong to another parallel Zhulong audit,
the target project's own Compose stack, or an unrelated Docker application.
For a target Docker Compose stack that this audit explicitly started, prefer a
unique project name such as `zhulong-<audit-workspace-name>-<target-name>` and
clean it with the exact command `docker compose -p <project> -f <compose.yml>
down -v --rmi local --remove-orphans` before the strict cleanliness check. Never
use broad prune as the Zhulong cleanup path.
If Compose leaves post-baseline build images, networks, or pulled service images
behind, rerun the cleanup helper with exact adoption flags such as
`--adopt-compose-project <project>` and, only for images proven absent from the
baseline and pulled by this audit, `--adopt-image-ref <image:tag>`. For
unlabeled networks or anonymous volumes, adopt only the exact name shown in
`docker-cleanup-plan.json` with `--adopt-network-name <network>` or
`--adopt-volume-name <volume>` after proving it belongs to this audit. If
BuildKit cache remains after review, it is review-only and cannot be
auto-deleted safely; the workspace must remain blocked unless the operator
resolves it before verification resumes. Use
`--adopt-build-cache --adopt-build-cache-id <cache-id>` only after the exact
cache ID is proven to belong to this isolated audit. Review the plan before
adding `--apply`, and never manually mark the audit completed while strict
Docker cleanliness is blocked. Do not use `--capture-baseline
--force-overwrite-baseline` after verification has created Docker resources;
the helper refuses this when post-baseline residue exists because it would hide
the residue from finalization.
Finalization reruns
`manage-docker-resources.py --verify-clean --strict` and must not trust a stale
`docker-cleanliness-status.json`. `assert-finalized-workspace.py` is an
after-the-fact consistency checker, not a substitute for rerunning
finalization.

Registry fallback is optional and operator-configured. If used, keep the
fallback list outside core logic, for example based on
`assets/references/docker-registry-fallbacks.example.json`. Only equivalent
mirrors or explicit image mappings are allowed. Record original image ref,
attempted image ref, registry source, success/failure reason, and final digest
when a pull succeeds. If digest or provenance is uncertain, mark source/runtime
identity uncertain and do not overclaim affected versions.

After a vulnerability is first confirmed, do not stop at the weakest trigger and immediately settle on a low or medium rating.
Run at least one deliberate severity-escalation pass that tries to verify stronger real-world impact inside Docker before final scoring.
That escalation pass should actively look for evidence such as:

- lower user-interaction requirements, especially startup-time or background-triggered exploitation paths
- lower privileges-required assumptions, including unauthenticated or cross-boundary reachability
- higher confidentiality, integrity, or availability impact than the earliest trigger showed
- realistic secrets exposure, arbitrary file read of high-value targets, write primitive, code execution pivot, or durable DoS proof
- a more realistic deployment path, such as default runtime folders, common service bootstrap flows, CI, container, or package-install hooks

Only upgrade severity when the stronger claim is actually verified and evidenced.
If the escalation pass does not succeed, keep the conservative rating, but say so explicitly in the report rationale instead of pretending the first weak proof was the only possible assessment.

5. Render and validate final bundles:

```bash
python3 <audit-workspace>/bin/render-confirmed-vuln-docx.py --input <audit-workspace>/confirmed/findings.json --output-dir <audit-workspace>/confirmed --language <zh-CN|en-US>
python3 <audit-workspace>/bin/validate-report-bundle.py --bundle-dir <audit-workspace>/confirmed/<bundle>
python3 <audit-workspace>/bin/validate-all-report-bundles.py --confirmed-dir <audit-workspace>/confirmed
```

The renderer output directory must be the top-level `<audit-workspace>/confirmed`
directory, never a per-vulnerability bundle directory. Let the renderer create
`confirmed/<one-folder-per-vulnerability>/`; do not hand-create final bundle
directories and then try to retrofit DOCX files into them.

Run the batch validator before writing the final summary. If it reports a
`partial confirmed bundle` or `validation_failed`, do not call that directory a
confirmed deliverable. List the failure and remediation step instead, such as
rerendering through `render-confirmed-vuln-docx.py` with
`--output-dir <audit-workspace>/confirmed` or moving unsupported leads back to
candidate/unverified records.

Do not produce thin DOCX reports. The `Vulnerability Analysis` section must explain, in reviewer-readable prose, at least:

- the exact vulnerable source location
- the attacker-controlled input or precondition
- the dangerous operation or sink
- the full trigger path from input to sink
- the root cause
- why existing checks, mitigations, or prior fixes do not block the issue

The same section must include a dedicated `关键代码上下文` / `Key Code
Context` subsection. It must contain at least one project-relative source path,
line number or line range when available, real code-like snippet lines, and a
code-level explanation tying the snippet to attacker-controlled input,
propagation path, dangerous operation, missing guard or validation, why adjacent
checks are insufficient or out of scope, and the verified impact boundary. Do
not use placeholder-only entries such as `代码上下文 1`, `Key Code Context 1`,
`待补充`, or `TODO`.

Confirmed reports must also include the three quality-gate labels in the report
language: `攻击者条件` / `Attacker Condition`, `服务端条件` /
`Server Condition`, and `安全影响` / `Security Impact`. Keep these sections
short but concrete: who can attack and what they control, what server-side
configuration or default runtime condition is required, and the confirmed CIA or
equivalent security impact. Do not use placeholder-only text, and do not claim a
security impact that the Docker evidence does not prove.

Confirmed reports must include a reviewer-readable real-world exploitability
section, such as `实际场景中的危害与利用方式` or `Real-World
Exploitability`. Keep it concise, but make it answer five concrete questions:
what real deployment or consumer scenario is affected, who the attacker is and
how they influence input or metadata, what call/trigger chain carries that input
to the affected code, what direct business or security consequence is proven,
and which impact is verified versus not claimed. If a PoC assumes strong attacker control, such as
directly writing a malicious JS/Python/PHP file or controlling a local source
file, explicitly explain why the PoC demonstrates the target component boundary
rather than a stronger unrelated capability.

The `Reproduction` section must include setup, exact Docker commands, expected result, observed result, and direct success evidence. If those details are missing from `findings.json`, enrich the finding before rendering instead of producing a shallow report.

Keep bundle identity strict:

- each directory under `<audit-workspace>/confirmed/` must represent exactly one confirmed vulnerability
- do not put multiple findings into one per-bundle `findings.json`
- include `verification-evidence.json` in each confirmed bundle with `verification_status=confirmed_in_docker`
- never place `high_confidence_unverified_due_to_sandbox_limitation` under `confirmed/`; keep it only as a future separate unverified evidence pool
- keep `poc_path` and all `evidence_files` bundle-relative, inside the bundle root, and pointing to real files under the final bundle
- use `attachments/` as the final delivery directory for PoC, evidence, Docker, and support files
- do not use `evidence/` as a final delivery directory; move final evidence files under `attachments/`
- do not leave runtime or source-control directories such as `.omc/`, `.git/`, `node_modules/`, `.venv/`, or `__pycache__/` inside final bundles
- keep false positives, non-security defects, unverified leads, and high-confidence-unverified leads out of `confirmed/`

For `.docx` handling inside Claude Code, use a two-stage rule:

- keep `render_confirmed_vuln_docx.py` as the canonical deterministic first-pass renderer for bundle generation
- when a generated report needs targeted edits, reviewer-driven wording fixes, redlines, or in-place polishing, call the built-in `Documents` skill instead of doing ad hoc OOXML surgery or one-off host-specific editing

When the `Documents` skill is used on a confirmed-vulnerability report:

- edit the actual bundle-root `.docx`, not a copied scratch document outside the bundle
- follow the skill's render-and-verify loop so the edited `.docx` is visually checked before delivery
- keep the report body aligned with the same bundle's `findings.json`, attachment note, reproduction supplement, and recording script
- preserve deterministic naming and bundle shape; the `Documents` skill is for content correction and polish, not for inventing a parallel delivery layout

Each confirmed vulnerability bundle should also include one bundle-root reproduction helper shell script for macOS and Linux, such as `run-<slug>-recording.sh`, that reproduces the shortest confirmed Docker case with one command.
That script should keep human-readable text aligned with the selected output language, include visible step markers, pause briefly at key checkpoints, and use ANSI color highlighting for dangerous lines or success evidence when stdout is interactive.
At the beginning of replay, before proof steps, it must print a highlighted target identity card that names the target software/package and the tested or affected version.
The opening identity card must include `测试软件名称` / `Tested Software` and `测试版本/分支` / `Tested Version / Branch` as separate fields, plus a short combined software/version line, so screen recordings make the tested target unambiguous.
It must print each concrete command before execution, capture raw command stdout/stderr to a bundle-local `.log` file under `attachments/evidence/`, and list that `.log` in `verification-evidence.json` or `attachments/reviewer-evidence-index.json`.
It must record a direct-impact marker such as `DIRECT_IMPACT_CONFIRMED`, `DIRECT_AVAILABILITY_IMPACT_CONFIRMED`, or an equivalent deterministic oracle in reviewer-facing replay evidence before final confirmation.
Keep that direct-impact marker synchronized across the replay helper, DOCX/supplement prose, `verification-evidence.json`, reviewer evidence index, and registered replay `.log` files.
It must derive `SCRIPT_DIR` from the script path, derive `ATTACH_DIR="$SCRIPT_DIR/attachments"`, and either self-bootstrap from bundle-local attachments or fail early with the exact bundle-local command the reviewer must run first.
Every helper-like function called by the proof flow must be defined in the same root script; do not call a missing local `run_*`, `verify_*`, `show_*`, `print_*`, or `require_*` helper.
Do not merely print a PoC/Docker command for the reviewer to run later; the bundle-root replay helper must execute the proof command itself, capture raw output, and fail closed if the command fails.
Do not reference `./helper.sh`, `./poc.py`, or similar local helper files in the supplement or evidence index unless those files are included in the delivered bundle.
Do not make root scripts or attachment scripts climb back to the submitter's
repository with deep `../../..` paths, parent-repository mounts, or package
external paths. Harmless `../` inside nested attachment directories is fine only
when it resolves inside the downloaded per-vulnerability bundle. Avoid
`npm install`, `yarn install`, or `pnpm install` in the shortest reviewer path
unless it uses `--ignore-scripts`, local/offline fixtures, or the supplement
documents why network install is unavoidable.
Before any `docker exec`, it should check that the target container exists and is running; before exploit traffic, it should run practical health/readiness checks that target the same runtime path used by proof commands.
Do not hide critical command errors with naked `2>/dev/null`; capture stderr/stdout and print enough context to diagnose failures.
Do not depend on pre-existing database state such as a first API token unless the helper explicitly creates or checks that state.
Success oracles must fail closed: a missing `grep -q`/`grep -Fq`/`jq -e`/HTTP-status/Docker-log marker must `exit 1` before any final `VULNERABILITY CONFIRMED`, `ATTACK SUCCESS`, `漏洞已确认`, or `攻击成功` banner can print. Explanatory text such as "if output contains X" is not enough.
If a PoC intentionally exits non-zero when the vulnerability is confirmed, normalize that expected code in the root script into explicit success evidence before any final confirmation banner.
The same bundle should also contain a finding-specific attachment index markdown and a finding-specific reproduction supplement markdown, not generic names such as `attachments.md` or `reproduction.md`.
The default reviewer-facing script skeleton should also make visual focus explicit:

- start with high-contrast review-focus cards such as key path, risk flow, and what evidence to watch for
- show a short numbered key code excerpt instead of dumping an entire long file when a snippet is available
- before executing proof commands, show separate screens for code context,
  code-level vulnerability analysis, and realistic exploitability / verified
  impact boundary
- the analysis screen should name attacker-controlled input, propagation or
  trigger path, dangerous sink, missing guard or validation, why adjacent checks
  do not block the issue, and the verified impact boundary
- keep short pauses even in quick mode so reviewers can read the critical lines
- place those pauses at reviewer-relevant checkpoints, especially after the opening focus cards, after the code excerpt, around critical command/output transitions, and before the final evidence summary disappears
- end with a dedicated evidence-summary block that replays the success oracle or DoS oracle in a stronger visual form before the script exits

Reviewer-facing supplements should not stop at "technical trigger" when the claim requires more:

- if the report claims denial of service, the materials should show the direct DoS oracle
- if the report claims attack success, the materials should show the exact success oracle
- if the reviewer is likely to ask about real-world harm or exploitation, include a short bundled supplement note that explains the practical scenario, attacker-controlled input, trigger/call chain, direct impact, and impact boundary without overstating the claim
- if report/supplement/evidence mention `PoC-4`, ensure the root recording
  script also covers `PoC-4`; stale videos that predate revised report/script
  material should be regenerated or clearly called out before submission

For reviewer-sensitive confirmed bundles, also add `reviewer-evidence-and-impact.md`
in the bundle root. Use it when the bundle involves a library/package,
fixture-based replay, a custom minimal Docker fixture, strong attacker-capability
assumptions, multiple PoC variants, non-obvious success oracles, or an impact
explanation spread across DOCX, scripts, JSON, logs, screenshots, or video. Keep
it concise and cover attacker capability/input boundary, runtime or deployment
preconditions, verified impact, explicitly non-claimed impact, success oracle
tokens, oracle-to-artifact mapping, the shortest bundle-local replay command,
and whether the replay uses the full upstream app, vendored source, a local
tarball, or a minimal fixture.

Reviewer-facing prose in DOCX/Markdown must not leak raw Python/JSON-like
intermediate objects; render dict/list finding data as prose, bullets, code
blocks, or machine-readable JSON files. Runtime identity should use stable
tested versions, commits, digests, or tested dates; mutable labels such as
`latest`, floating image tags, `main`, `master`, or vague "current version"
wording are not enough for final confirmed-bundle claims.

When useful, add `attachments/reviewer-evidence-index.json` as a structured
reviewer map. It is an index, not a hash manifest. Keep every artifact path
bundle-relative, make the replay command runnable from the bundle root, list the
success-oracle tokens, and ensure each token appears in a script, evidence log,
supplement, reviewer addendum, or `verification-evidence.json`.

Fixture and library boundaries must be explicit:

- minimal fixtures should explain which upstream source file or vulnerable
  pattern they preserve, why the fixture is sufficient for the vulnerability
  boundary, where the original/vendored source is attached, and which stronger
  impacts are not claimed
- library/package reports should explain the public API/function boundary, attacker-controlled argument/key/filename/metadata/config field, consumer application pattern needed for reachability, local library effect versus application-level impact, and non-claims such as no direct network endpoint exposed by the library itself

The final CVSS and severity label should reflect the strongest verified oracle from the severity-escalation pass, not merely the first technical trigger that proved the bug exists.

Final summaries must explicitly distinguish confirmed vulnerabilities, false positives / non-security defects, and unverified leads. If Docker confirmation did not complete, say that no vulnerability was confirmed for that lead, identify the missing evidence, and give the safe Docker-only resume step.
Save the final human-facing summary as `<audit-workspace>/SUMMARY.md` or `<audit-workspace>/final-audit-summary.md`; do not leave it only in chat output or timestamped terminal logs. Before writing that summary, refresh or explicitly resolve stale blocker wording in `attack-surface.md`, `candidate-findings.md`, `unverified-leads.md`, `audit-disposition.json`, and `handoff-summary.md` so they do not still claim `blocked_no_docker`, `NOT STARTED`, or `image pull required` after the summary claims Docker verification succeeded.

6. Run the completion gate before writing the final summary:

```bash
python3 <audit-workspace>/bin/finalize-audit-workspace.py --workspace-dir <audit-workspace> --language <zh-CN|en-US|auto> --result <completed_with_confirmed_bundles|completed_no_confirmed_findings>
python3 <audit-workspace>/bin/assert-finalized-workspace.py --workspace-dir <audit-workspace>
```

The completion gate refreshes `<audit-workspace>/audit-disposition.json` from
`confirmed/`, candidate findings, false positives, unverified leads, and blocked
verification signals. It enforces that the disposition ledger, bundle validation
state, Docker strict cleanliness, stage-status.json, and handoff-summary.md all
agree before the audit is declared finished. The Docker check is recomputed by
the finalization helper; a stale `docker-cleanliness-status.json` is not enough.
A dogfood run is not complete until this gate passes.
Before writing "completion gate passed" in a workspace summary, run the
finalization integrity verifier and confirm that `audit-events.jsonl` contains a
latest successful `finalization_succeeded` event for the declared result. A
manually edited `stage-status.json` or a hand-written summary is not completion.

- Use `completed_with_confirmed_bundles` when at least one confirmed bundle
  passes validation. This requires zero partial or failed bundles.
- Use `completed_no_confirmed_findings` when no confirmed vulnerabilities were
  found. This is an acceptable final result when candidates were correctly
  rejected or left unconfirmed. It requires zero partial confirmed bundle
  directories and zero validation failures.
- Scanner-only findings, unverified leads, dependency alerts, static hypotheses,
  and failed or timed-out Docker cases must not become confirmed.
- In `audit-disposition.json`, `state=confirmed` requires a valid
  `confirmed_bundle_path` and Docker `docker_status=reproduced`; scanner-only,
  dependency-only, static-only, and LLM-only items must remain non-confirmed.
- The gate updates stage-status.json to `stage=completed`, refreshes
  audit-disposition.json and handoff-summary.md, and writes finalization audit
  events.
- If the gate fails, fix the reported issues before declaring the audit complete.
- If Docker strict cleanliness fails, including a BuildKit cache blocker, report
  the workspace as blocked/failed rather than completed. For
  `completed_no_confirmed_findings`, no confirmed findings is a successful
  result only after finalization integrity passes.
- If blocked Docker/runtime verification remains in candidate-findings.md,
  unverified-leads.md, attack-surface.md, or stage-status.json, the completion
  gate must fail rather than write `finalization_succeeded`.

## Output Language

- Keep the prompt template in English.
- Select final deliverable language separately with `zh-CN` or `en-US`.
- Use the explicit locale token in prompts, for example `Output language: en-US`, instead of free-form values such as `Output language: English`.

## References

- [claude-code-invocation-template.md](./assets/references/claude-code-invocation-template.md)
- [document-output-stability.md](./assets/references/document-output-stability.md)
- [docker-resource-hygiene.md](./assets/references/docker-resource-hygiene.md)
- [docker-registry-fallbacks.example.json](./assets/references/docker-registry-fallbacks.example.json)
- [recommended-security-tooling.md](./assets/references/recommended-security-tooling.md)
- [java-web-audit-playbook.md](./assets/references/java-web-audit-playbook.md)
- [go-web-audit-playbook.md](./assets/references/go-web-audit-playbook.md)
- [nodejs-library-audit-playbook.md](./assets/references/nodejs-library-audit-playbook.md)
- [nodejs-web-audit-playbook.md](./assets/references/nodejs-web-audit-playbook.md)
- [php-swoole-audit-playbook.md](./assets/references/php-swoole-audit-playbook.md)
- [python-library-audit-playbook.md](./assets/references/python-library-audit-playbook.md)
- [python-web-audit-playbook.md](./assets/references/python-web-audit-playbook.md)
- [ssrf-checklist.md](./assets/references/ssrf-checklist.md)
- [path-traversal-checklist.md](./assets/references/path-traversal-checklist.md)
- [prototype-pollution-checklist.md](./assets/references/prototype-pollution-checklist.md)
- [confirmed-vuln-docx-format.md](./assets/references/confirmed-vuln-docx-format.md)
- [final-summary-template.md](./assets/references/final-summary-template.md)
- [false-positive-template.md](./assets/references/false-positive-template.md)
- [unverified-lead-template.md](./assets/references/unverified-lead-template.md)
