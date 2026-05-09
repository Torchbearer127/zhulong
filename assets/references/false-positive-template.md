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
- Security policy / scope checked: <SECURITY.md | official security policy | default configuration docs | project security model | unavailable>
- In project security scope?: <yes | no | unclear>
- Expected behavior?: <yes | no | unclear>
- Administrator-trust or non-default configuration assumption?: <yes | no | unclear>
- Default configuration vulnerable?: <yes | no | not applicable | unclear>
- Docker verification status: <not attempted | attempted and rejected | blocked before verification>
- Rejection reason code: <expected_behavior | outside_security_boundary | requires_non_default_admin_trust | default_config_not_vulnerable | insufficient_attacker_condition | insufficient_security_impact | other>
- Rejection reason: <why this is not a security vulnerability>
- Classification: <false positive | non-security defect | hardening-only issue | duplicate>
- Next action: <usually none; or move to hardening notes / revisit if code changes>
```

## Required Discipline

- Keep scanner alerts, source-to-sink reasoning, pattern matches, and LLM analysis as candidates until Docker confirmation exists.
- Check `SECURITY.md`, the official security policy, default configuration docs, or the project security model when available before deciding that suspicious behavior crosses the project's security boundary.
- If Docker verification rejects the candidate, record the exact observed result and why it contradicts the vulnerability hypothesis.
- If the issue is a bug but not a security vulnerability, classify it as `non-security defect` and do not promote it into confirmed output.
- Do not create `verification-evidence.json`, DOCX reports, attachment indexes, reproduction supplements, or `run-*.sh` confirmed-bundle scripts for false positives.
