# Claude Code Invocation Template

This file is intentionally short. The operational rules live in the
`zhulong` skill (Zhulong / 烛龙) and its validators, not in the user
prompt. Do not copy the full plugin contract into every audit request.

## Readiness

- Sync this package into Claude Code before use:

```bash
bash plugins/zhulong-plugin/scripts/sync_to_claude_skill.sh
```

- Restart Claude Code or open a new session after syncing.
- In normal use, do not ask the user to run a chain of helper Bash commands.
- If manual fallback is genuinely needed, use the single launcher:

```bash
bash plugins/zhulong-plugin/scripts/asr_start.sh --source <repo-or-url>
```

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

If a future rule is important enough to repeat in every prompt, put it into the
skill or validator instead, then keep this invocation template short.

## Recommended: GitHub, Chinese Output

```text
Please use the zhulong skill to perform end-to-end autonomous vulnerability research on this repository:
https://github.com/owner/repo

Output language: zh-CN.
```

## Recommended: GitHub, English Output

```text
Please use the zhulong skill to perform end-to-end autonomous vulnerability research on this repository:
https://github.com/owner/repo

Output language: en-US.
```

## Local Repository

```text
Please use the zhulong skill to perform end-to-end autonomous vulnerability research on this local repository:
/path/to/repo

Output language: zh-CN.
```

## Optional Preferences

Add only the preferences that are truly specific to this run:

```text
Please use the zhulong skill to perform end-to-end autonomous vulnerability research on this repository:
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
