# Output Language And Path Contract

This skill must keep human-readable output language and final output paths stable.

## Prompt Language

- Keep the invocation prompt, operator checklist, and reusable requirement template in English.
- Treat report language as a separate runtime setting, for example `Output language: zh-CN` or `Output language: en-US`.
- Do not silently translate the prompt template itself just because the report output language is Chinese.

## Language

- Default output language: `zh-CN`
- Supported override: `en-US` or `English`
- The selected language applies to:
  - terminal / chat summary
  - Markdown summaries
  - attachment-directory note
  - docx section headings and default labels
  - default report filename style
  - bundle-root reviewer-facing reproduction helper scripts such as `run-<slug>-recording.sh`
- The final summary should also distinguish confirmed vulnerabilities, false positives, and unverified leads in that same language.

Do not mix languages inside the same final deliverable set unless the user explicitly requests bilingual output.

For reviewer-facing shell scripts:

- match comments, banners, step markers, status lines, and evidence labels to the selected output language
- keep code snippets, shell keywords, command names, tool names, and exact oracle tokens in English when they are part of the real output
- avoid mixed-language narration inside the same script unless the user explicitly requests bilingual output

## Chinese Terminology

Use these forms consistently in Chinese explanatory prose. Exact commands,
fields, filenames, source quotations, and original output retain their bytes.

| Concept | Chinese prose convention | Distinction |
| --- | --- | --- |
| Docker tool/platform | `docker` | Keep the tool name in English; do not translate it as “容器”. Original product titles and quotations may retain `Docker`. |
| Docker Compose tool | `docker compose` | Preserve the exact `docker-compose` executable when that is the command being discussed. |
| Container instance | 容器 | An object created or run by docker, not a synonym for the tool. |
| Container image | 镜像 | Not interchangeable with a running container. |
| Agent skill | `skill` | Do not alternate with “技能” or `Skill` in ordinary prose; preserve `SKILL.md` and other exact identifiers. |
| Audit workspace | 审计工作区; 工作区 after context is established | Do not alternate with `Workspace` in ordinary prose. |
| Health check | 健康检查 | Preserve the configuration key `healthcheck` when naming the actual field. |
| Replay | 复现 | Use 复现脚本 / 复现日志 for the script or log; preserve identifiers containing `replay`. |
| Staging directory | 暂存目录 | Distinguish from the Git 暂存区 and preserve literal `.staging` paths. |
| Bundle | 漏洞包 | Use 交付包 where delivery rather than finding classification is the subject; do not alternate names for the same object without reason. |
| Validation | 校验 | Preserve 校验器 for the validator; do not replace runtime 验证 with static 校验. |

The maintenance procedure in `docs/AGENTS.md` requires checking surrounding
prose, other Chinese documents, and the corresponding English section before
accepting terminology changes. Existing inconsistent prose is not precedent.
English should remain only where it names a necessary technical object or an
exact machine-readable value; the rest of the sentence should read naturally
in Chinese. Internal development labels and audit round names do not belong
in public workflow explanations.

## Fixed Final Output Paths

Allowed final confirmed deliverables:

```text
<repo>/<audit-workspace>/confirmed/<one-folder-per-vulnerability>/
```

Allowed files inside each confirmed bundle:

- report docx
- attachment-directory note
- `attachments/`

## Forbidden Legacy Output Paths

Do not use these as final output locations:

- `<audit-workspace>/vulnerability-packages/`
- `<audit-workspace>/vulnerability-analysis/`
- `<audit-workspace>/SECURITY-RESEARCH-SUMMARY.md`

If older exploratory artifacts already exist there, treat them as temporary scratch output only. Do not describe them as the final confirmed package.

## Workspace Config

After bootstrap, the workspace should contain:

```text
<audit-workspace>/asr-config.json
```

Minimum fields:

```json
{
  "output_language": "zh-CN",
  "confirmed_output_dir": "<audit-workspace>/confirmed"
}
```

The active audit should honor that file unless the user explicitly overrides the language.

Renderer resolution order:

1. explicit `--language`
2. `<audit-workspace>/asr-config.json` -> `output_language`
3. fallback `zh-CN`
