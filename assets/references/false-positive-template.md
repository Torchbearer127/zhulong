# False Positive / Non-Security Defect Template

Use this template for candidates that were reviewed and rejected as confirmed vulnerabilities.

False positives and non-security defects are workspace records only. They must stay in `false-positives.md` or an equivalent workspace note. They must never be written under `confirmed/`, must not generate DOCX reports, and must not appear in the confirmed-vulnerability summary.

## Entry Template

```markdown
## FP-<number>: <short candidate title>

- Candidate ID: FP-<number>
- Original suspicion: <what initially looked vulnerable>
- Why it looked risky: <scanner result, source-to-sink pattern, LLM hypothesis, or code smell>
- Evidence reviewed:
  - <project-relative file or command output>
  - <project-relative file or command output>
- Files reviewed:
  - `<project-relative/path>`
- Docker verification status: <not attempted | attempted and rejected | blocked before verification>
- Rejection reason: <why this is not a security vulnerability>
- Classification: <false positive | non-security defect | hardening-only issue | duplicate>
- Next action: <usually none; or move to hardening notes / revisit if code changes>
```

## Required Discipline

- Keep scanner alerts, source-to-sink reasoning, pattern matches, and LLM analysis as candidates until Docker confirmation exists.
- If Docker verification rejects the candidate, record the exact observed result and why it contradicts the vulnerability hypothesis.
- If the issue is a bug but not a security vulnerability, classify it as `non-security defect` and do not promote it into confirmed output.
- Do not create `verification-evidence.json`, DOCX reports, attachment indexes, reproduction supplements, or `run-*.sh` confirmed-bundle scripts for false positives.
