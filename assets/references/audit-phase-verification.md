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
   `verification/running` state or an explicit `verification/blocked` retry;
   wrong stages fail before any Docker CLI call, and the PoC command starts
   only after a revision-bound same-stage start event commits.
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

## Exit

- Success: source-bound Docker evidence and an independent verdict exist.
- Blocked/rejected: retain candidate or unverified status. Unsafe sandbox output
  and blocked verification never enter `confirmed/` and never justify
  `completed_no_confirmed_findings`.
