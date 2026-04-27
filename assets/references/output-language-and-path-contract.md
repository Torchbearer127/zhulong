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
