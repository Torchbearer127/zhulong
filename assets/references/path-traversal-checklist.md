# Path Traversal Checklist

Use this concise checklist when a candidate involves attacker-controlled file
names, paths, archive entries, uploads, downloads, templates, or static file
serving.

## Scope and When To Use It

- Use for source-to-sink review of filesystem reads, writes, deletes, extracts,
  or path-based routing.
- Prioritize endpoints that accept file paths, object keys, upload names, zip
  entries, template names, or download identifiers.
- This checklist is reasoning aid only; it cannot confirm a vulnerability.

## Common Sources

- Query/path/body fields named `path`, `file`, `filename`, `key`, `template`,
  `dir`, `download`, `upload`, or `archive`.
- Multipart filenames, zip/tar entry names, object storage keys, repository file
  paths, and plugin/theme/template selectors.

## High-Risk Sinks

- Java: `File`, `Paths.get`, `Files.read*`, `Files.write*`, upload/extract APIs.
- Go: `os.Open`, `os.ReadFile`, `os.WriteFile`, `filepath.Join`, archive loops.
- Node/Python: `fs.readFile`, `fs.createReadStream`, `path.join`, `sendFile`,
  `open`, `Path`, archive extraction.
- Static file handlers, template loaders, backup/export/import paths.

## Source-To-Sink Tracing Hints

- Track canonicalization order: decode, normalize, join, symlink resolution, and
  final boundary check.
- Check double encoding, absolute paths, Windows separators, null bytes where
  relevant, symlink escape, and archive traversal.
- Record whether validation is applied to the final resolved path, not only the
  raw input string.

## Docker-Only Verification Ideas

- In Docker, create a sentinel file inside and outside the intended base
  directory and prove whether the PoC can read/write/delete it.
- For zip slip, build a controlled archive in the attacker container and inspect
  the target container filesystem after extraction.
- Capture exact expected and observed paths in evidence files.

## Severity-Escalation Evidence To Seek

- Read of secrets/config, write primitive, overwrite of executable/config files,
  durable persistence, symlink escape, arbitrary delete, or traversal reachable
  without authentication.

## Common False Positives

- Input is an opaque ID mapped to a safe server-side path.
- Final path is resolved and checked against an immutable base directory.
- Framework static serving already blocks traversal after decoding.
- PoC only proves missing file behavior, not boundary escape.

## Confirmed-Only Routing Reminder

- Checklist matches and source-to-sink hypotheses stay in `candidate-findings.md`
  or `unverified-leads.md` until Docker evidence confirms impact.
- Do not generate DOCX reports from this checklist alone.
- Confirmed vulnerabilities belong only under
  `confirmed/<one-folder-per-vulnerability>/` with `verification_status=confirmed_in_docker`.
