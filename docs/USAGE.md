# Usage Guide

This page explains how to start Zhulong and which prompt to use. It is written
for operators who want to run an authorized code audit, not for plugin
maintainers.

## Choose A Start Mode

| Situation | Recommended mode |
| --- | --- |
| You use a local AI coding agent that can load the Zhulong skill | Use the short agent prompt below. |
| You want to prepare a repository from the terminal first | Use `scripts/asr_start.sh`. |
| You are testing Zhulong on several repositories before a release | Use the trial-run prompt below. |
| You already have a cloned repository | Use either the local-repository prompt or `--repo-root`. |

## Standard Agent Prompt

Use this when you want Zhulong to audit a repository through your local agent:

```text
Please use the zhulong skill to perform an end-to-end security-focused code audit on this repository:
https://github.com/owner/repo

Output language: en-US.
```

For Simplified Chinese output:

```text
Please use the zhulong skill to perform an end-to-end security-focused code audit on this repository:
https://github.com/owner/repo

Output language: zh-CN.
```

For an existing local checkout:

```text
Please use the zhulong skill to perform an end-to-end security-focused code audit on this local repository:
/path/to/repo

Output language: en-US.
```

## Output Language

Use an explicit locale-style value in the prompt:

| Value | Use when |
| --- | --- |
| `en-US` | You want English workspace summaries, confirmed vulnerability reports, reproduction notes, and handoff files. |
| `zh-CN` | You want Simplified Chinese workspace summaries, confirmed vulnerability reports, reproduction notes, and handoff files. |

The terminal launcher exposes the same choice through `--output-language` and
`--summary-language`. Keep them the same unless you have a specific reason to
separate final reports from short summaries.

## Trial-Run Prompt

Use this when you are evaluating Zhulong on a real project and want a careful
audit run without pressure to produce a confirmed vulnerability:

```text
Please use the zhulong skill to perform an end-to-end trial security-focused code audit on this repository:
https://github.com/owner/repo

Output language: en-US.
Preferences:
- Treat this as a product validation run, not a quota-driven bug hunt.
- Do not force a confirmed finding; "no confirmed vulnerabilities" is acceptable when Docker evidence does not support any candidate.
- Record confirmed findings, false positives, unverified leads, non-security defects, hardening notes, Docker blockers, and usability issues in the generated workspace files.
- Keep playbooks and checklists as starting points. If this repository has project-specific frameworks, data flows, sinks, or deployment assumptions, document them in the audit workspace.
- At the end, summarize what was confirmed, what was rejected, what remains unverified, and whether the generated evidence is enough for a human reviewer to resume.
```

## Useful Prompt Preferences

Add preferences only when they help the current run:

```text
Preferences:
- Continue as a single-agent run if multi-agent runtime state is not clean.
- Focus first on XML/parser input handling and object-shape mutation bugs.
- Keep plausible but unverified issues in the audit notes instead of treating them as confirmed vulnerabilities.
```

Avoid copying a long policy checklist into every prompt. Zhulong already carries
its repeatable safety and reporting rules in the installed skill, reference
docs, and automated checks.

## Manual Terminal Startup

The agent prompt is the normal path. The terminal launcher is useful when you
want to clone or prepare the repository first, or when you want a machine-readable
startup summary.

Start from a remote repository:

```bash
bash scripts/asr_start.sh --source https://github.com/owner/repo
```

Start from `owner/repo` shorthand:

```bash
bash scripts/asr_start.sh --source owner/repo
```

Start from an existing local checkout:

```bash
bash scripts/asr_start.sh --repo-root /path/to/repo
```

Use a specific branch or tag:

```bash
bash scripts/asr_start.sh --source https://github.com/owner/repo --ref main
```

Emit startup information as JSON:

```bash
bash scripts/asr_start.sh --source https://github.com/owner/repo --json
```

Show suspicious multi-agent worker processes for manual review:

```bash
bash scripts/asr_start.sh --repo-root /path/to/repo --prompt-runtime-pid-review
```

This option only prints review information. It does not clean up or terminate
processes.

## Launcher Options

| Option | Use When | Notes |
| --- | --- | --- |
| `--source VALUE` | Starting from a URL, local path, or `owner/repo` shorthand. | Use either `--source` or `--repo-root`, not both. |
| `--repo-root DIR` | Starting from an already cloned repository. | Use either `--source` or `--repo-root`, not both. |
| `--workspace-root DIR` | You want remote clones placed under a specific directory. | Defaults to the current directory. |
| `--workspace-name NAME` | You want a fixed audit workspace name. | Otherwise Zhulong creates `security-research-YYYYMMDD-HHMMSS`. |
| `--output-language LANG` | You want report artifacts in `zh-CN` or `en-US`. | Use explicit locale values, not free-form language names. |
| `--summary-language LANG` | You want summaries in `zh-CN` or `en-US`. | Usually the same as `--output-language`. |
| `--ref REF` | You need a specific branch or tag. | Applies to remote sources. |
| `--force` | You need to recreate safe conflicting files during setup. | Do not use it to hide Docker residue or overwrite evidence. |
| `--skip-plan` | You are debugging startup and want to skip tool planning. | Normal audit runs should not need it. |
| `--prompt-runtime-pid-review` | You want a visible terminal reminder about suspicious multi-agent worker processes. | Review-only; no process cleanup. |
| `--json` | You want machine-readable startup output. | Useful for wrappers or scripts. |
| `-h`, `--help` | You want the built-in help text. | Prints launcher usage. |

## What Happens After Startup

Zhulong creates a timestamped audit workspace inside the target repository:

```text
<repo>/security-research-YYYYMMDD-HHMMSS/
```

The workspace stores candidate findings, false positives, unverified leads,
handoff notes, Docker status, runtime status, evidence, and confirmed
vulnerability packages if any are confirmed.

If Docker is unavailable or the verification environment is unsafe, Zhulong
should record the blocker and pause verification instead of running proof-of-
concept commands directly on the host.

## Advanced Resume Commands

Most users do not need these commands directly, but they are useful when
resuming or debugging an audit workspace:

```bash
bash <audit-workspace>/bin/run-initial-probes.sh --repo-root /path/to/repo
bash <audit-workspace>/bin/check-docker-gate.sh --repo-root /path/to/repo
python3 <audit-workspace>/bin/render-handoff-summary.py --workspace-dir <audit-workspace> --repo-root /path/to/repo
```

## Template Location

The short prompt template lives at:

```text
assets/references/claude-code-invocation-template.md
```

The sync script does not copy it outside the package by default. If you want a
convenience copy, opt in explicitly:

```bash
bash scripts/sync_to_claude_skill.sh --prompt-template-output ./claude-code-zhulong-prompt-template.md
```
