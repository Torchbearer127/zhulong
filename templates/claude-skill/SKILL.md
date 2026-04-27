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

If `check_omc_runtime.sh` reports `cleanup_needed`, treat it as a manual-review state first. Do not auto-kill teammate-mode processes. If `suspect_teammate_pids` or `stale_swarm_sockets` are reported, show them explicitly and require inspection before cleanup.

3. Plan the repository-specific toolchain:

```bash
python3 <audit-workspace>/bin/plan-security-toolchain.py --target-dir <repo-root>
```

If the plan prints `specialized_playbooks`, use those playbooks as focused
source-to-sink guidance for this audit. For Java Web and Go Web repositories,
create or update `<audit-workspace>/attack-surface.md` with the route/handler
map, trust boundaries, authentication requirements, and high-risk sinks before
turning candidates into confirmed findings.

For first-pass scanner execution, prefer the bundled runner:

```bash
bash <audit-workspace>/bin/run-initial-probes.sh --repo-root <repo-root> --workspace-dir <audit-workspace>
```

Do not treat raw dependency-scanner exit codes as workflow blockers without
reading the output. In particular, `osv-scanner scan source -r <repo>` may exit
128 with `No package sources found` when a repository has no supported lockfile,
manifest, or SBOM source. Record that state as `skipped_no_package_sources` and
continue with source review and Docker-based verification; it is not a confirmed
vulnerability and not a reason to stop the audit.

4. Verify findings only inside Docker or Docker Compose.
When verification needs Docker images, prefer suitable local images or already-cached base images first. Only pull from the network if no suitable local image is available.

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

## Output Language

- Keep the prompt template in English.
- Select final deliverable language separately with `zh-CN` or `en-US`.
- Use the explicit locale token in prompts, for example `Output language: en-US`, instead of free-form values such as `Output language: English`.

## References

- [claude-code-invocation-template.md](./assets/references/claude-code-invocation-template.md)
- [document-output-stability.md](./assets/references/document-output-stability.md)
- [recommended-security-tooling.md](./assets/references/recommended-security-tooling.md)
- [confirmed-vuln-docx-format.md](./assets/references/confirmed-vuln-docx-format.md)
