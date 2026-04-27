# Document Output Stability

Use this workflow to keep confirmed vulnerability report bundles stable, portable, and reviewable.

## Recommended Stack

Primary generation:

- `python-docx` for deterministic `.docx` generation
- `scripts/render_confirmed_vuln_docx.py` as the canonical report renderer

Claude Code in-place editing:

- Claude Code built-in `Documents` skill for post-render `.docx` correction, reviewer-driven edits, and final polish

Required validation:

- `file <report>.docx`
- `unzip -t <report>.docx`
- `scripts/validate_report_bundle.py`

Optional secondary validation:

- LibreOffice headless conversion via `soffice --headless --convert-to pdf`
- MarkItDown extraction via `markitdown <report>.docx`

## Design Principle

Do not use external Office automation, MCP servers, or interactive document editors as the primary report-generation path.

Use them only as optional helpers for:

- extracting reference documents
- checking readability
- smoke-testing conversion robustness

Keep the final report bundle generation in a local deterministic script so it can be:

- diffed
- tested
- reproduced
- validated in CI or batch runs

Inside Claude Code, this means:

- initial bundle generation stays in `scripts/render_confirmed_vuln_docx.py`
- post-generation document editing should use the `Documents` skill rather than ad hoc OOXML edits
- after any `.docx` edit, the document should go through a render-and-verify pass before being considered final

## Required Bundle Shape

```text
<audit-workspace>/confirmed/<bundle>/
├── <report>.docx
├── <attachment-note>.md
└── attachments/...
```

## Required Validation Checks

Run after every final render:

```bash
python3 scripts/validate-report-bundle.py --bundle-dir <audit-workspace>/confirmed/<bundle>
```

For batch verification before final submission:

```bash
python3 scripts/validate-all-report-bundles.py \
  --confirmed-dir <audit-workspace>/confirmed
```

This validator checks:

- exactly one top-level `.docx`
- exactly one top-level attachment-note `.md`
- valid OOXML / ZIP structure
- required section headings for Chinese or English mode
- no operator-local absolute paths such as `/Users/...`
- no forbidden standalone `说明` / `Note` field in the attachment note
- bundle-relative attachment references

If the `.docx` was edited through the `Documents` skill, still run the same bundle validator after the edit. The editing path changes, but the bundle contract does not.

## Optional Stronger Validation

If LibreOffice is installed:

```bash
python3 scripts/validate-report-bundle.py \
  --bundle-dir <audit-workspace>/confirmed/<bundle> \
  --with-libreoffice
```

If MarkItDown is installed:

```bash
python3 scripts/validate-report-bundle.py \
  --bundle-dir <audit-workspace>/confirmed/<bundle> \
  --with-markitdown
```

These checks do not replace the primary validation chain. They are only extra confidence checks.

## Content Stability Rules

- Use project-root-relative source-code paths in the report body.
- Use bundle-relative paths such as `attachments/<audit-workspace>/poc/poc.js` for shipped artifacts.
- Keep the attachment note minimal: only original path and purpose.
- Keep prompt templates in English; keep final deliverables in the selected output language.
- When bilingual support is needed, store structured bilingual fields in `findings.json` instead of relying on ad-hoc translation during rendering.
- When a claim depends on practical harm, exploitation, attack success, or DoS proof, include that evidence explicitly in the report or bundled supplement instead of leaving it implicit.
- Reviewer-facing reproduction scripts should default to localized text, visible step markers, short pauses, and ANSI color highlighting for dangerous lines or final success evidence.

## Suggested End-of-Run Sequence

```bash
python3 scripts/scaffold_bilingual_findings.py \
  --input <audit-workspace>/confirmed/findings.json \
  --output <audit-workspace>/confirmed/findings.bilingual.json \
  --primary-language zh-CN \
  --add-secondary-placeholders

python3 scripts/render_confirmed_vuln_docx.py \
  --input <audit-workspace>/confirmed/findings.bilingual.json \
  --output-dir <audit-workspace>/confirmed

python3 scripts/validate-report-bundle.py \
  --bundle-dir <audit-workspace>/confirmed/<bundle>
```
