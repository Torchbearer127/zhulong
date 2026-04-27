---
name: zhulong
description: Zhulong (烛龙), a Docker-first autonomous security auditing workflow with runtime checks, dynamic toolchain planning, deterministic vulnerability reporting, and final bundle validation.
---

# Zhulong (烛龙)

Use this Claude Code skill when you want a repository audit workflow that is:

- Docker-first for PoC execution and verification
- dynamic in tool selection based on stack and installed capabilities
- deterministic in report generation
- packaged from the open-source plugin repository into a Claude-native skill layout

## Installed Claude Skill Layout

- runtime checks:
  - [check_docker_gate.sh](./scripts/check_docker_gate.sh)
  - [check_omc_runtime.sh](./scripts/check_omc_runtime.sh)
  - [check_security_tooling.sh](./scripts/check_security_tooling.sh)
  - [asr_exec.sh](./scripts/asr_exec.sh)
- Docker verification runner:
  - [run_verification_case.sh](./scripts/run_verification_case.sh)
- handoff summary:
  - [render_handoff_summary.py](./scripts/render_handoff_summary.py)
- dynamic planning:
  - [plan_security_toolchain.py](./scripts/plan_security_toolchain.py)
  - [tool-registry.json](./assets/tool-registry.json)
- language-specific source-to-sink playbooks:
  - [java-web-audit-playbook.md](./assets/references/java-web-audit-playbook.md)
  - [go-web-audit-playbook.md](./assets/references/go-web-audit-playbook.md)
- workspace setup:
  - [prepare_target_repo.sh](./scripts/prepare_target_repo.sh)
  - [bootstrap_verification_workspace.sh](./scripts/bootstrap_verification_workspace.sh)
- reporting:
  - [render_confirmed_vuln_docx.py](./scripts/render_confirmed_vuln_docx.py)
  - [scaffold_bilingual_findings.py](./scripts/scaffold_bilingual_findings.py)
  - [validate_report_bundle.py](./scripts/validate_report_bundle.py)
  - [validate_all_report_bundles.py](./scripts/validate_all_report_bundles.py)

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
- For individual PoC checks, prefer `run_verification_case.sh` or an equivalent
  Docker-only wrapper with a mandatory timeout, explicit network setting,
  resource limits, and structured evidence. The stable verification case labels
  are `blocked_docker_unavailable`, `blocked_missing_image`, `failed_timeout`,
  `failed_resource_limit`, `rejected_not_reproducible`, and
  `confirmed_in_docker`.
- Prefer `gh` for GitHub repositories, advisories, issues, pull requests,
  commits, and releases. Do not execute `web_search`, `Search(...)`,
  `Fetch(...)`, or `WebFetch(...)` as Bash commands.
- Before multi-agent execution, run the OMC runtime gate. If it reports
  `single_agent_only`, continue single-agent. If it reports `cleanup_needed`,
  show suspect processes or sockets for manual review; never auto-kill teammate
  processes.
- Confirm vulnerabilities only with Docker evidence. After the first
  confirmation, run one explicit severity-escalation pass in Docker before final
  scoring, and only upgrade severity when stronger impact is verified.
- Static scanning, source-to-sink reasoning, pattern matching, dependency alerts,
  and LLM analysis can only create candidates. They must not be written as
  confirmed findings unless Docker reproduction succeeds.
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
- Write final confirmed bundles only to
  `<audit-workspace>/confirmed/<one-folder-per-vulnerability>/`, with exactly one
  confirmed vulnerability per bundle.
- Every final bundle must be self-contained and portable: one finding-specific
  `.docx`, one finding-specific attachment index markdown, one finding-specific
  reproduction supplement markdown, `verification-evidence.json`, `attachments/`,
  and one reviewer-friendly bundle-root reproduction helper script.
- Validate every final bundle before finishing. A bare `findings.json`, generic
  filenames such as `report.docx` or `attachments.md`, final `evidence/`
  directories, runtime state, source-control directories, dependency trees, or
  cache directories inside a final bundle are incomplete output.
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

2. Check Docker gate, runtime, and tooling capability:

```bash
bash <audit-workspace>/bin/check-docker-gate.sh --repo-root <repo-root> --note "pre-verification gate"
bash <audit-workspace>/bin/check_omc_runtime.sh
bash <audit-workspace>/bin/check_security_tooling.sh
```

If the Docker gate blocks verification, stop immediately. Keep all collected artifacts under `<repo>/<audit-workspace>/`, update `<audit-workspace>/audit-log.md`, and do not execute PoCs on the host.

If Docker gate or OMC runtime gate pauses the workflow, do not fail silently. Print a clear terminal pause block that includes:

- the exact blocker and why it was triggered
- the relevant log or evidence path
- confirmation that collected artifacts were preserved
- the precise resume step
- a pointer to `<audit-workspace>/handoff-summary.md` or the command to render it:
  `python3 <audit-workspace>/bin/render-handoff-summary.py --workspace-dir <audit-workspace>`

If `check_omc_runtime.sh` reports `cleanup_needed`, treat it as a manual-review state first. Do not auto-kill teammate-mode processes. If `suspect_teammate_pids` or `stale_swarm_sockets` are reported, show them explicitly and require inspection before cleanup.

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
source-to-sink guidance for this audit. For Java Web and Go Web repositories,
create or update `<audit-workspace>/attack-surface.md` with the route/handler
map, trust boundaries, authentication requirements, and high-risk sinks before
turning candidates into confirmed findings.

If the plan prints `attack_surface_guidance`, use it to keep the handoff packet
small and stack-specific. For Java Web and Go Web, each entry inventory should
include route or endpoint, method, handler/controller, authentication
requirement, input source, downstream sink or service, and current verification
status. Do not use `attack-surface.md` as a DOCX source or as a shortcut into
`confirmed/`.

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

The runner enforces a mandatory timeout, records stdout/stderr plus
`verification-result.json` under `<audit-workspace>/evidence/<case-id>/`, and
never executes PoC logic on the host. For `docker-run`, defaults include memory,
CPU, pids, read-only root filesystem, dropped capabilities, no-new-privileges,
and explicit network selection. Network use must be intentional: default
`--network none` is safe for offline parser/package PoCs, while service probes
should name the target Docker network. If the runner returns `failed_timeout`,
pause and re-analyze service readiness, waiting conditions, network blocking,
loops, or interactive prompts before retrying.

Runner-produced evidence is a workspace artifact. To confirm a vulnerability,
copy the relevant runner logs/result JSON into the final bundle's
`attachments/` and keep `verification-evidence.json` set to
`verification_status=confirmed_in_docker`; timed-out, blocked, resource-limited,
or rejected cases must stay out of `confirmed/`.

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
python3 <audit-workspace>/bin/validate-report-bundle.py --bundle-dir <audit-workspace>/confirmed/<bundle>
python3 <audit-workspace>/bin/validate-all-report-bundles.py --confirmed-dir <audit-workspace>/confirmed
```

Do not produce thin DOCX reports. The `Vulnerability Analysis` section must explain, in reviewer-readable prose, at least:

- the exact vulnerable source location
- the attacker-controlled input or precondition
- the dangerous operation or sink
- the full trigger path from input to sink
- the root cause
- why existing checks, mitigations, or prior fixes do not block the issue

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
The same bundle should also contain a finding-specific attachment index markdown and a finding-specific reproduction supplement markdown, not generic names such as `attachments.md` or `reproduction.md`.
The default reviewer-facing script skeleton should also make visual focus explicit:

- start with high-contrast review-focus cards such as key path, risk flow, and what evidence to watch for
- show a short numbered key code excerpt instead of dumping an entire long file when a snippet is available
- keep short pauses even in quick mode so reviewers can read the critical lines
- place those pauses at reviewer-relevant checkpoints, especially after the opening focus cards, after the code excerpt, around critical command/output transitions, and before the final evidence summary disappears
- end with a dedicated evidence-summary block that replays the success oracle or DoS oracle in a stronger visual form before the script exits

Reviewer-facing supplements should not stop at "technical trigger" when the claim requires more:

- if the report claims denial of service, the materials should show the direct DoS oracle
- if the report claims attack success, the materials should show the exact success oracle
- if the reviewer is likely to ask about real-world harm or exploitation, include a short bundled supplement note that explains the practical impact and a typical exploitation path without overstating the claim

The final CVSS and severity label should reflect the strongest verified oracle from the severity-escalation pass, not merely the first technical trigger that proved the bug exists.

Final summaries must explicitly distinguish confirmed vulnerabilities, false positives / non-security defects, and unverified leads. If Docker confirmation did not complete, say that no vulnerability was confirmed for that lead, identify the missing evidence, and give the safe Docker-only resume step.

## Output Language

- Keep the prompt template in English.
- Select final deliverable language separately with `zh-CN` or `en-US`.
- Use the explicit locale token in prompts, for example `Output language: en-US`, instead of free-form values such as `Output language: English`.

## References

- [claude-code-invocation-template.md](./assets/references/claude-code-invocation-template.md)
- [document-output-stability.md](./assets/references/document-output-stability.md)
- [recommended-security-tooling.md](./assets/references/recommended-security-tooling.md)
- [java-web-audit-playbook.md](./assets/references/java-web-audit-playbook.md)
- [go-web-audit-playbook.md](./assets/references/go-web-audit-playbook.md)
- [confirmed-vuln-docx-format.md](./assets/references/confirmed-vuln-docx-format.md)
- [final-summary-template.md](./assets/references/final-summary-template.md)
- [false-positive-template.md](./assets/references/false-positive-template.md)
- [unverified-lead-template.md](./assets/references/unverified-lead-template.md)
