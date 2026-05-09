# Claude Code Invocation Template

This file is intentionally short. The operational rules live in the
`zhulong` skill (Zhulong / 烛龙) and its validators, not in the user
prompt. Do not copy the full plugin contract into every audit request.

## Readiness

- Sync this package into Claude Code before use:

```bash
bash scripts/sync_to_claude_skill.sh
```

- Restart Claude Code or open a new session after syncing.
- In normal use, do not ask the user to run a chain of helper Bash commands.
- If manual fallback is genuinely needed, use the single launcher:

```bash
bash scripts/asr_start.sh --source <repo-or-url>
```

By default the launcher records OMC suspect teammate PIDs in workspace status
and handoff documents without interrupting the run. Add
`--prompt-runtime-pid-review` only when you want an explicit terminal prompt for
operator review at startup. The option never enables automatic PID cleanup.

## Prompt Contract

The user prompt should provide only:

- the target repository URL or local path
- the desired output language, usually `zh-CN` or `en-US`
- optional audit preferences, such as "single-agent only" or "focus on parser bugs"

The skill itself owns the hard rules:

- Docker-only PoC and exploit verification
- repository-local timestamped audit workspace
- `gh`-first GitHub access
- Do not execute `web_search`, `Search(...)`, `Fetch(...)`, or `WebFetch(...)` as Bash commands
- local/cached Docker images before network pulls
- exactly one vulnerability per final confirmed bundle
- Do not produce a thin report; include detailed DOCX analysis, attachment index, reproduction supplement, `attachments/`, and a reviewer-friendly bundle-root reproduction script
- explicit Docker gate, OMC runtime gate, validation, and visible pause summaries
- one severity-escalation pass in Docker before final scoring
- P5 disposition ledger, runtime hygiene, sandbox preflight, and confirmed-report quality gates

If a future rule is important enough to repeat in every prompt, put it into the
skill or validator instead, then keep this invocation template short.

## Recommended: GitHub, Chinese Output

```text
Please use the zhulong skill to perform an end-to-end security-focused code audit on this repository:
https://github.com/owner/repo

Output language: zh-CN.
```

## Recommended: GitHub, English Output

```text
Please use the zhulong skill to perform an end-to-end security-focused code audit on this repository:
https://github.com/owner/repo

Output language: en-US.
```

## Local Repository

```text
Please use the zhulong skill to perform an end-to-end security-focused code audit on this local repository:
/path/to/repo

Output language: zh-CN.
```

## Optional Preferences

Add only the preferences that are truly specific to this run:

```text
Please use the zhulong skill to perform an end-to-end security-focused code audit on this repository:
https://github.com/owner/repo

Output language: zh-CN.
Preferences:
- Continue single-agent if team runtime is not clean.
- Focus first on XML/parser input handling and object-shape mutation bugs.
- Keep unverified leads in the audit log instead of final confirmed bundles.
```

Avoid long "Requirements" lists that restate the plugin's default behavior. Long
prompts drift over time; plugin-owned constraints are easier to test, sync, and
repair.

## Dogfood Pilot Prompt

Use this form when testing Zhulong on a real repository before broad rollout:

```text
Please use the zhulong skill to perform an end-to-end dogfood security-focused code audit pilot on this repository:
https://github.com/owner/repo

Output language: zh-CN.
Preferences:
- Treat this as a product validation run, not a quota-driven bug hunt.
- Do not force a confirmed finding; "no confirmed vulnerabilities" is acceptable if Docker evidence does not support any candidate.
- Record security issues, non-security defects, hardening-only observations, false positives, and unverified leads in the appropriate workspace files instead of forcing them into confirmed bundles.
- Keep playbooks and checklists as starting maps, not fences. Expand attack-surface.md for repository-specific frameworks, data flows, sinks, or deployment shapes not covered by the references.
- At the end, summarize confirmed findings, false positives, unverified leads, Docker blockers, and any friction in the Zhulong workflow itself.
```

For the first few real-world pilots, prefer a small Docker-ready repository or a
known-vulnerable benchmark before moving to a medium-sized production project.

## Release Candidate 5-Repository Pilot Prompt

Use this form for future release-candidate validation cycles after plugin
selftests pass and before publishing a new tagged release. The 0.2.0 P5
release-candidate dogfood pass has already been run and documented.

```text
Please use the zhulong skill to perform a P5 release-candidate dogfood security-focused code audit pilot on this repository:
https://github.com/owner/repo

Output language: zh-CN.
Preferences:
- Treat this as release validation, not a quota-driven bug hunt.
- Do not force confirmed findings; no-confirmed is acceptable when Docker evidence does not support any candidate.
- Record security issues, non-security defects, hardening-only observations, false positives, and unverified leads in the appropriate workspace files instead of forcing them into confirmed bundles.
- Preserve P5 gates: audit-disposition ledger, OMC runtime hygiene, sandbox preflight, finalization integrity, Docker strict clean, and attacker/server/impact report quality.
- At the end, export or summarize the workspace log with confirmed findings, false positives, unverified leads, blocked verification, sandbox preflight status, runtime hygiene status, Docker cleanup status, finalization/assert status, and Zhulong workflow friction.
```

For the manual release-candidate set, choose about five repositories that cover:

- one Docker-ready Web/API target
- one medium or large monorepo
- one Python or Node library/framework target
- one realistic Docker Compose stack
- one expected no-confirmed control

Pause release only for High/Medium workflow defects. Record Low-severity wording,
alias, or ergonomics issues as follow-up issues instead of restarting the P5
hardening loop.
