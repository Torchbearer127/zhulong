# Path Discipline

Use this note whenever the audit needs to run shell commands against generated
files inside a bootstrapped per-audit workspace such as `security-research-YYYYMMDD-HHMMSS/`.

## Problem to Avoid

Relative paths are only correct when the current working directory is correct.
Commands such as:

```bash
chmod +x vulnerability-packages/CVE-2024-XXXXX-credential-exposure/test.sh
```

will fail if the current shell is not already inside the current audit workspace.

## Required Rule

Before any Bash command that references a relative path, choose the anchor:

- repo root
- current audit workspace root

Then use the execution wrapper instead of relying on implicit cwd.

## Wrapper Usage

From the repository root:

```bash
bash <audit-workspace>/bin/asr-exec.sh --repo-root -- <command...>
bash <audit-workspace>/bin/asr-exec.sh --workspace-root -- <command...>
```

From inside the current audit workspace:

```bash
bash scripts/asr-exec.sh --repo-root -- <command...>
bash scripts/asr-exec.sh --workspace-root -- <command...>
```

## Examples

Make a workspace-relative script executable:

```bash
bash <audit-workspace>/bin/asr-exec.sh --workspace-root -- \
  chmod +x vulnerability-packages/CVE-2024-XXXXX-credential-exposure/test.sh
```

Search the audited repository from the repo root:

```bash
bash <audit-workspace>/bin/asr-exec.sh --repo-root -- \
  rg -n "child_process|exec\\(" .
```

## Reporting Rule

- For shell execution, deterministic anchors are preferred over guessing cwd.
- For written reports, still use project-root-relative or bundle-relative paths rather than machine-specific absolute paths.
