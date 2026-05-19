# Confirmed Vulnerability DOCX Format

Write only for vulnerabilities that were reproduced successfully inside Docker.

## Core Goal

The report must let a human reviewer do two things without reading the chat transcript:

- accurately locate the vulnerable code context
- reproduce the environment setup and vulnerability verification step by step

If either goal is not met, the report is incomplete.

## Claude Code DOCX Editing Rule

Inside Claude Code, use a split workflow:

- `scripts/render_confirmed_vuln_docx.py` remains the canonical first-pass renderer for deterministic bundle generation
- if the generated `.docx` needs targeted wording repair, reviewer-driven edits, or final polish, use Claude Code's built-in `Documents` skill on the actual bundle-root `.docx`

Do not treat these as competing systems. The renderer owns initial generation and bundle structure. The `Documents` skill owns in-place document editing quality.

## Portability Rule

The report must be portable across machines and reviewers.

- Vulnerable source-code locations should stay project-root-relative.
- Files shipped inside the per-vulnerability submission folder should be referenced with paths relative to that folder, for example `attachments/<audit-workspace>/docker/test-buffer-overread.js`.
- Do not use the operator's absolute local paths such as `/Users/...`.
- Embed key reproduction file content when that content is necessary to reproduce the result.
- Output one separate attachment-directory note file in the same per-vulnerability submission folder as the `.docx`, rather than placing attachment instructions inside the Word document.

## Language

- Keep the reusable Claude Code prompt / invocation template in English.
- Choose the report output language separately.
- Default report language: Simplified Chinese (`zh-CN`).
- Optional report language: English (`en-US`).
- Do not mix Chinese and English inside the same final deliverable set unless bilingual output is explicitly requested.

## Tone

- Use concise, engineering-style prose.
- Prefer direct statements over speculation.
- Separate observed facts from impact inference.
- Optimize for reviewability rather than operator shorthand.

## Required Sections

### 1. 标题

Use:

```text
<项目名> 库存在 <漏洞名称> 漏洞报告
```

Filename recommendation:

```text
<project>_<vuln-type>_<severity-cn>漏洞报告.docx
```

### 2. 漏洞描述

Use 1-2 paragraphs covering:

- what the project or component is
- where the flaw sits
- what attacker control reaches the sink
- what security impact is confirmed

### 3. 影响版本

Use one paragraph with line breaks:

```text
影响包/项目：
影响组件：
影响版本：
仓库链接：
```

If the exact introduction version is unknown, say `至少包括 <tested-version>` and explain the boundary briefly.

### 4. 漏洞危险性评估

Use a mainstream CVSS version. Prefer CVSS 4.0; if the submission target, CNA/CNVD-style process, or reviewer template still expects the older mainstream format, use CVSS 3.1 instead. Do not use CVSS 2.0.

Use:

```text
CVSS 4.0 向量： 或 CVSS 3.1 向量：
基础评分：
等级判定：
```

Follow with one paragraph beginning with `评估依据：`.

### 5. 漏洞分析

This section must be detailed enough for a human to locate and understand the vulnerable code path.

Do not compress this section into one summary sentence. A report that only says "input reaches function X and triggers Y" is incomplete even if the PoC is real.

Start this section with the quality-gate triplet in the selected report language:

- `攻击者条件：...` / `Attacker Condition: ...`
- `服务端条件：...` / `Server Condition: ...`
- `安全影响：...` / `Security Impact: ...`

Each line must be non-empty and concrete. `攻击者条件` states who can attack,
from where, with what privilege, and what input is controllable. `服务端条件`
states the required default setting, feature flag, plugin, OS/environment, or
server configuration. `安全影响` states a confirmed CIA impact or equivalent
concrete effect such as data exposure, unauthorized modification, DoS, SSRF
internal access, or information disclosure.

Prefer this structure:

- `位置：<相对于项目根目录的文件路径:行号>`
- `入口/可控输入：...`
- `危险函数/危险操作：...`
- `触发路径：从输入到危险操作的调用或执行路径`
- `根因：...`
- `现有校验为何失效：...`

Then add a dedicated `关键代码上下文` subsection in prose or structured notes.

Add a dedicated real-world exploitability section in the report body, using a
heading such as `实际场景中的危害与利用方式` or `Real-World
Exploitability`. This section may be short, but it must concretely state:

- who the attacker is and how they can influence the relevant input or metadata
- what server-side configuration, runtime condition, feature flag, dependency
  usage, debug/logging behavior, or deployment assumption makes the path
  reachable
- how the internal effect becomes visible or security-relevant, such as logs,
  error reporting, debug pages, response data, stored state, callback traffic,
  or operator-visible artifacts
- which impact is actually verified by Docker/PoC evidence and which stronger
  impact is not claimed

If a PoC writes or directly executes attacker-controlled code, assumes attacker
control of a local source file, or points metadata directly at a secret file,
explain why the PoC is still testing the target component boundary rather than
assuming a stronger unrelated capability.

### 6. 漏洞复现

This section must be detailed enough for another engineer to repeat the setup and verification.

Do not leave this section as only `结果证据：` plus a final verdict. The report body itself must include the shortest repeatable Docker path, not only an external shell script.

Structure as:

- `1. 环境准备`
- `2. 启动目标服务`
- `3. 执行 PoC / 发送攻击载荷`
- `4. 验证结果`
- `最终判定：`

If reviewer feedback or the vulnerability class suggests stronger evidence is needed, also cover the relevant one of the following in either the report body or the bundled reproduction supplement:

- actual harm in a realistic deployment path
- a typical exploitation path
- attack-success proof
- denial-of-service proof

For each step, include as applicable:

- the project-root-relative working directory
- the Docker image, container name, or compose service name
- files created or copied during setup
- exact commands in execution order
- PoC script path
- expected success oracle
- observed result

### 7. 验证环境关键文件

When reproducibility depends on a local file such as `Dockerfile`, `docker-compose.yml`, verification script, or PoC script, embed the critical file content in the report.

## Attachment Directory Note

In addition to the DOCX, output two Markdown companions in the same per-vulnerability submission folder:

- one attachment-directory note file
- one reproduction supplement note for reviewers

Recommended layout:

```text
<docx-stem>/
├── <docx-stem>.docx
├── run-<slug>-recording.sh
├── verification-evidence.json
├── <docx-stem>_补充复现说明.md
├── <docx-stem>_附件目录说明.md
└── attachments/...
```

One directory means one vulnerability. If two confirmed findings exist, create two sibling directories under `confirmed/`; do not put both findings into one bundle-local `findings.json`.

Docker-confirmed evidence is not by itself a completed deliverable. A directory
under `confirmed/` that contains `verification-evidence.json` or `findings.json`
but lacks the report DOCX, attachment index, reproduction supplement,
`attachments/`, or bundle-root reproduction helper is a partial confirmed
bundle. Report it as `Docker-confirmed but bundle incomplete` until
`validate-all-report-bundles.py` passes.

Use `attachments/` for final delivery files. `evidence/`, `poc/`, and `docker/` can exist in the audit workspace while researching, but files that support the final report must be copied into the per-vulnerability bundle under `attachments/`.

Final bundles must not contain runtime state or source-control/cache directories such as `.omc/`, `.git/`, `node_modules/`, `.venv/`, or `__pycache__/`.

For confirmed vulnerabilities, include one bundle-root reproduction helper script such as `run-<slug>-recording.sh` or `run-<slug>-repro.sh`.
The helper must be executable, pass a static shell syntax check, and use only Docker/Docker Compose reproduction paths.
It must derive `SCRIPT_DIR` and `ATTACH_DIR="$SCRIPT_DIR/attachments"` from the script location, then either start the reproduction environment from bundle-local attachments or fail early with a clear command such as `docker compose -f "$ATTACH_DIR/docker-compose.zhulong.yml" up -d`.
If it calls `docker exec`, check the target container first and print a diagnostic when it is missing.
Avoid naked `2>/dev/null` on critical Docker, curl, or token-generation commands; capture and print errors with context.
Do not rely on pre-existing database state such as `ApiToken.objects.first()` unless the helper explicitly creates or validates that state.
Every final confirmation banner must be guarded by a fail-closed success oracle: `grep`, `jq`, HTTP status checks, JSON field checks, or equivalent assertions must `exit 1` on failure before printing `VULNERABILITY CONFIRMED`, `ATTACK SUCCESS`, `漏洞已确认`, or `攻击成功`.
Docker Compose files shipped under `attachments/` must be self-consistent: relative `env_file` entries and relative bind-mount sources must exist relative to the Compose file, named volumes are allowed, and absolute host paths are not allowed in final bundles.

## Verification Evidence JSON

Each confirmed bundle must include `verification-evidence.json` in the bundle root. This file is an auxiliary machine-checkable index only. It does not replace `findings.json`, the finding-specific `.docx`, the attachment index, the reproduction supplement, `attachments/`, or the bundle-root recording helper script.

Minimum schema:

```json
{
  "schema_version": 1,
  "finding_slug": "example-slug",
  "verification_status": "confirmed_in_docker",
  "docker_required": true,
  "docker_image": "node:20-alpine",
  "docker_command": "docker run ...",
  "poc_path": "attachments/poc/repro.py",
  "expected_observation": "Expected success oracle.",
  "observed_observation": "Observed success oracle.",
  "oracle_token": "VULNERABILITY CONFIRMED",
  "evidence_files": [
    "attachments/poc/repro.py",
    "attachments/evidence/output.log"
  ],
  "severity_escalation_attempted": true,
  "severity_escalation_result": "Escalation attempted in Docker; no stronger impact was confirmed."
}
```

Allowed `verification_status` values:

- `confirmed_in_docker`: the only value accepted under `confirmed/`
- `high_confidence_unverified_due_to_sandbox_limitation`: reserved for a future separate `high-confidence-unverified/` pool; never place this status under `confirmed/`

All `poc_path` and `evidence_files` entries must be bundle-relative paths that stay inside the bundle root and point to real files. Do not use absolute paths, `file://` URLs, or `..` escapes.

Script requirements:

- use portable shell syntax that works on macOS and Linux
- use Docker / Docker Compose execution only; do not offer host fallback modes
- support the shortest-path reproducible case, not a long forensic workflow
- print clear step markers so the script is easy to screen-record
- keep human-readable script text aligned with the selected output language; only code snippets, tool names, shell keywords, and exact success-oracle tokens may stay in English when needed
- pause briefly around key review checkpoints so a reviewer can see code hints, build completion, and final success evidence without the terminal flashing past too fast
- use ANSI color highlighting for dangerous lines and final success evidence when stdout is interactive, with a plain-text fallback when color is unavailable
- fail fast with a readable message when Docker is unavailable
- use only bundle-relative or project-relative paths; never embed operator-local absolute paths
- never depend on deep parent traversal such as `../../../../..` to find the
  submitter's full repository; final scripts must work after a reviewer
  downloads only the per-vulnerability bundle
- avoid `npm install`, `yarn install`, or `pnpm install` in the shortest
  reviewer path unless lifecycle scripts are disabled with `--ignore-scripts`,
  dependencies are vendored/local/offline, or the supplement explains why
  network installation is unavoidable

The note file should explain:

- the bundled path inside the submission folder
- the original project-relative path
- what the file is used for

Do not add a separate `说明` field in the Markdown attachment note.

## Reproduction Supplement Note

The reproduction supplement note should help a reviewer quickly answer:

- what is the shortest trustworthy reproduction path
- what exact output proves successful reproduction
- what exact output proves successful exploitation when exploitation is part of the claim

Recommended sections:

- `补充目的` / `Purpose`
- `复现环境` / `Verification Environment`
- `建议的最短复现路径` / `Recommended Shortest Reproduction Path`
- `关键成功证据` / `Key Success Evidence`
- `实际场景中的危害与利用方式` / `Practical Impact and Exploitation Path`
- `补充材料说明` / `Bundled Materials`
- `结论` / `Conclusion`

The `关键成功证据` / `Key Success Evidence` section must include direct success oracles copied from the actual verification output, not only generic prose.

If the review claim is stronger than "technical trigger", the supplement should also explain why the observed oracle supports that stronger claim, while staying conservative and not overstating unproven impact.

Keep PoC labels aligned across the DOCX, supplement, attachment note,
`verification-evidence.json`, and root recording helper. If the materials refer
to `PoC-4`, the root helper should also cover or mention `PoC-4`. If a video was
recorded before the current report, supplement, evidence JSON, or root helper
was updated, treat it as stale and record a new video before final submission.

## Reviewer Evidence Addendum and Index

For reviewer-sensitive bundles, add a concise bundle-root
`reviewer-evidence-and-impact.md`. This is recommended when the confirmed
finding involves a library/package vulnerability, fixture-based reproduction, a
custom minimal Docker fixture, strong attacker-capability assumptions, multiple
PoC variants, non-obvious success oracles, or reviewer-facing impact spread
across DOCX, scripts, JSON, logs, screenshots, or video.

The addendum should answer:

- what attacker capability and input boundary are assumed
- what server, deployment, or runtime preconditions are needed
- what impact is verified and what stronger impact is explicitly not claimed
- which success-oracle tokens matter
- which files or scripts contain each oracle
- the shortest command a reviewer can run from the bundle root
- whether the replay uses the full upstream app, vendored source, a local
  tarball, or a minimal fixture

When the evidence map is non-trivial, also include
`attachments/reviewer-evidence-index.json`. This file is a reviewer map, not a
cryptographic hash manifest. Use bundle-relative artifact paths only, ensure
each referenced path exists in the submitted bundle, keep the replay command
bundle-root local, list success-oracle tokens, and make sure every listed token
appears in a reasonable source such as a root replay script, evidence log,
reproduction supplement, reviewer addendum, or `verification-evidence.json`.

For minimal fixtures and vendored subsets, explain the source provenance: which
upstream file or vulnerable pattern is preserved, why the fixture is sufficient
to reproduce the boundary, where the original/vendored source is attached, and
which impacts are not claimed. For library/package findings, explain the public
API/function boundary, attacker-controlled argument/key/filename/metadata/config
field, consuming-application pattern needed for reachability, local library
effect versus application-level impact, and non-claims such as no direct network
endpoint exposed by the library itself.

## Evidence Rules

- Mention Docker explicitly when describing verification.
- State explicitly that the PoC was executed in Docker or Docker Compose, not on the host.
- Mention the PoC artifact path if one exists, and use the bundled relative path when the file is shipped inside `attachments/`.
- Mention the exact vulnerable source file and, when available, line numbers.
- Mention only confirmed behavior. Do not claim shell access, file read, or RCE unless the oracle proves it.
- Prefer one clear expected-result sentence and one clear observed-result sentence over scattered fragments.
- Include at least one explicit success-evidence block in the reproduction steps, for example exact output lines proving “vulnerability confirmed”, “attack success”, “sensitive file read succeeded”, or another concrete oracle matching the claim.
- Prefer relative paths everywhere in the report body.

## Structured Input for the Generator Script

The generator at `scripts/render_confirmed_vuln_docx.py` accepts a JSON object or a JSON array.

In a generated audit workspace, use the workspace helper copy instead of the
installed-skill source path:

```bash
python3 <audit-workspace>/bin/render-confirmed-vuln-docx.py \
  --input <audit-workspace>/confirmed/findings.json \
  --output-dir <audit-workspace>/confirmed \
  --language zh-CN
```

`--output-dir` must be the top-level `confirmed/` directory. Do not point it at
`confirmed/<bundle>/`; the renderer owns creating the one-folder-per-vulnerability
bundle shape. After rendering, validate the generated bundle with
`validate-report-bundle.py` and optionally use `--write-audit-event` to record
`bundle_validated`.

Before final summary, run `validate-all-report-bundles.py` over the top-level
`confirmed/` directory. If it reports `partial confirmed bundle` or
`validation_failed`, list the failure and remediation step instead of calling
that directory a confirmed deliverable.

In addition to the basic fields, strongly prefer these richer fields:

```json
{
  "project_root": "is-utf8",
  "bundle_root_artifacts": [
    {
      "output_name": "run-is-utf8-buffer-overread-recording.sh",
      "generator": "reviewer-recording-shell",
      "purpose": "macOS 与 Linux 可直接执行的最小复现脚本"
    }
  ],
  "environment_files": [
    {
      "path": "security-research-demo/docker/Dockerfile",
      "purpose": "构建验证镜像",
      "snippet": "FROM node:18-alpine\nWORKDIR /app"
    }
  ],
  "attachments": [
    {
      "path": "security-research-demo/docker/test-buffer-overread.js",
      "purpose": "执行 PoC",
      "note": "建议与 docx 一并提交"
    }
  ]
}
```

Additional generator rules:

- If your source JSON is still an older minimal shape such as `{"findings":[...]}`, normalize it to the richer schema before rendering, or use a renderer version that performs that normalization explicitly.
- Mark a finding as confirmed only when `docker_verified` is `true`. If Docker verification is incomplete, do not generate a confirmed `.docx`.
- If a confirmed vulnerability ships a one-command reproduction helper, declare it in `bundle_root_artifacts` so the renderer copies it to the bundle root and the validator can check it.
- If you do not already have a polished helper shell script, you may set `bundle_root_artifacts[].generator` to `reviewer-recording-shell`. The renderer will generate a Docker-only reviewer-facing script skeleton from `reproduction` and `code_context`, including localized step markers, short pauses, and ANSI color highlighting.
- Generated or handwritten helpers should self-bootstrap from bundle-local attachments when practical. If they intentionally require a prerequisite environment start, they must fail early with the exact bundle-local command and must not silently assume containers or database rows already exist.
- If reviewer feedback later requires wording fixes or stronger explanation inside the `.docx`, edit the generated bundle-root report with Claude Code's built-in `Documents` skill and then re-run bundle validation.
- If a generated helper script should expose extra mode aliases such as `record-dos` or `quick-dos`, add `bundle_root_artifacts[].generator_options.modes`, for example `["record", "quick", "record-dos", "quick-dos"]`.
- In the `cvss` block, use a mainstream vector string beginning with `CVSS:4.0/` or `CVSS:3.1/`. Do not emit `CVSS:2.0`.
- When the project layout is not a default audit workspace such as `security-research-YYYYMMDD-HHMMSS/...`, set `project_root_dir` and keep file paths project-root-relative so the renderer can rewrite them into bundled `attachments/...` references without leaking `/tmp/...` or operator-local absolute paths.
- If you want one `findings.json` file to support both Chinese and English rendering, provide language-specific fields such as `title_en`, `title_zh`, `filename_en`, `filename_zh`, `vuln_type_en`, `vuln_type_zh`, `description_en`, `analysis_en`, `final_verdict_en`, `impact.affected_versions_en`, `impact.extra_en`, `cvss.rationale_en`, `reproduction[].title_en`, and `reproduction[].details_en`. The renderer will prefer the selected language and only fall back to generic fields when safe.
- If your current draft is still single-language, use `scripts/scaffold_bilingual_findings.py` to copy the current generic fields into `*_zh` or `*_en` keys first, then manually fill the opposite language.

Operational note for Docker-based verification:

- Use one foreground build command with readable logs when preparing the verification environment.
- Avoid launching duplicate background `docker build` or `docker pull` commands for the same artifact, because that can create misleading “hung task” symptoms and waste disk through repeated cache growth.
- In environment notes or reproduction prerequisites, prefer recording the active runtime context when it matters, for example `docker context show -> orbstack`, so another reviewer can tell which backend was used.
