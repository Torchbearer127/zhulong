# Unverified Lead Template

Use this template for leads that remain plausible but are not Docker-confirmed.

Unverified leads are workspace records only. They must stay in `candidate-findings.md`, `unverified-leads.md`, or an equivalent workspace note. They must never be written under `confirmed/`, must not generate DOCX reports, and must not appear as confirmed vulnerabilities in the final summary.

## Entry Template

```markdown
## UV-<number>: <short lead title>

- Lead ID: UV-<number>
- Suspected weakness: <vulnerability class or unsafe behavior>
- Source-to-sink hypothesis: <attacker-controlled source -> transformation -> sink>
- Evidence found so far:
  - <project-relative file, line, scanner output, or observation>
  - <project-relative file, line, scanner output, or observation>
- Missing evidence:
  - <PoC, Docker runtime, reachable route, exploitability proof, oracle, or affected version boundary>
- Docker confirmation status: <not attempted | blocked | attempted but inconclusive | rejected>
- Why Docker confirmation was not completed: <specific blocker or uncertainty>
- Safe resume step: <exact next safe action, normally a Docker-only command or investigation step>
- High-confidence-unverified candidate: <yes | no>
- High-confidence-unverified rationale, if yes: <sandbox limitation such as unstable race, missing closed dependency, target service cannot run locally, or unavailable proprietary environment>
- Material blocker?: <yes | no>
- Default runtime scope?: <default runtime | optional integration | non-default deployment | source-only/library N/A>
- Why completion is still safe?: <required when high-confidence-unverified is yes and Docker confirmation status is blocked/not attempted; explain why this does not block completed_no_confirmed_findings, or leave blank and keep the workspace blocked>
- Confirmed-output guardrail: Not confirmed. Do not write to `confirmed/`; do not render DOCX; do not include in confirmed summary.
```

## Required Discipline

- A lead can be high-confidence and still not be a confirmed vulnerability.
- `high-confidence-unverified/` is reserved for a future separate evidence pool. It is not confirmed output, must not generate confirmed DOCX reports, and must not be included in confirmed-only summaries.
- If Docker is unavailable, pause and record the blocker. Do not switch to host-local PoC execution.
- If a high-confidence lead is also blocked/no-Docker, finalization requires an explicit materiality rationale. Without `Material blocker?`, `Default runtime scope?`, and `Why completion is still safe?`, keep the workspace blocked instead of declaring `completed_no_confirmed_findings`.
- The final summary must clearly state what evidence is missing and what safe Docker-only resume step remains.
