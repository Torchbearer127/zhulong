# Verification and Severity Phase

Use this reference for independent, Docker-only reproduction through a real
attacker-controlled API, CLI, UI, RPC, or library entrypoint.

## Preconditions

- A validated candidate and exact source identity.
- Docker, runtime hygiene, tooling, and sandbox preflight gates are clear.
- A bounded command, timeout, network setting, resource limits, and deterministic
  oracle are defined.

## Working path

1. Prefer `scripts/run_verification_case.sh`; its stable outcomes include
   `rejected_unsafe_sandbox`, blocked states, and `confirmed_in_docker`.
   In R2 it first requires a synchronized canonical
   `verification/running` or `severity_escalation/running` state, or an
   explicit blocked retry for either stage; wrong stages fail before any Docker
   CLI call. The wrapper captures the validated canonical stage and revision
   once, then reuses that stage for registry validation, retry/start/result
   events, and compare-and-swap checks. The PoC command starts only after a
   revision-bound same-stage start event commits.
2. A function-level, source-level, simulated, or container-local result is
   supporting evidence only. Confirmation requires accepted attacker input,
   entrypoint-to-sink path, Docker oracle, independent verifier verdict, and
   disposition.
3. Keep deployment, dependency, permission, health, or service blockers as
   `blocked_entrypoint_verification`; never fall back to host PoC execution.
4. After the first confirmation, run a separate Docker severity-escalation pass.
   Upgrade severity only for newly verified impact.

See `docs/runner-contracts/independent-verifier-r1.md`,
`docs/runner-contracts/finding-contract-r1.md`, and the relevant optional
playbook/checklist selected by the context plan.

## Prerequisite And Incremental-Impact Review

For authentication-bypass and secret/key/token findings, apply this review before
confirmation or severity escalation. A successful request or oracle marker is an
observation, not proof of causal attribution or new unauthorized authority.

1. Identify the actual attacker prerequisites and evidence of how they are
   obtained at the claimed starting privilege. Determine whether a supplied
   account value, hash, key, or token is an ordinary identifier or a credential /
   bearer-equivalent secret. A test operator supplying it is not an attacker
   acquisition path.
2. Compare the capability already available with those prerequisites against
   the claimed new capability. Inspect relevant normal/legacy entrypoints and
   adjacent guards in the tested deployment. A prerequisite that already grants
   equivalent authority cannot prove new authentication bypass through another
   route. Equal results do not invalidate every flaw: separately evidenced extra
   capability or secret acquisition may support a narrower or different claim.
3. Require source analysis that distinguishes the alleged flaw's effect from
   existing credential use; where that leaves a material ambiguity, use bounded
   Docker execution controls with the same attacker prerequisites. Correct-key
   success and wrong-key failure prove key use, not independent unauthorized
   impact. Distinguish removing the alleged flaw from changing credentials or
   inventing a deployment that disables an alternative path. Review relevant
   alternatives, not every possible bypass path; this is not a universal new
   control matrix for unrelated bug classes.
4. Separate observed behavior, causal attribution, and supported severity. An
   unsupported security-critical acquisition or impact link stays candidate /
   unverified; downgrade, reclassify, or withdraw claims as the evidence supports.
   Do not fabricate confirmation or treat incomplete evidence alone as proof of
   a false positive.

Keep the reasoning and source/control evidence in the existing prerequisite,
review, impact-interpretation, and evidence carriers. The independent verifier
must inspect them rather than repeat a finder verdict or success marker. These
are reviewer obligations, not an automatic semantic check by the validators;
they introduce no new field, status, or receipt protocol.

## Exit

- Success: source-bound Docker evidence and an independent verdict exist.
- Blocked/rejected: retain candidate or unverified status. Unsafe sandbox output
  and blocked verification never enter `confirmed/` and never justify
  `completed_no_confirmed_findings`.
