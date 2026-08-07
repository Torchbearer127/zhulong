# Intake and Recon Phase

Use this reference while preparing a repository, binding source identity, mapping
the attack surface, and closing Recon coverage. It is advisory guidance; the
production validators and gates linked below remain authoritative.

## Preconditions

- A local target repository and a timestamped audit workspace.
- An exact tested ref recorded by the target contract.
- Docker availability is checked before any dynamic verification, not during
  source-only Recon.

## Working path

1. Prepare the repository through `scripts/zhulong_audit.sh`; normal use should
   not ask the user to execute a long helper-command chain.
2. Validate the target contract as described by
   `docs/runner-contracts/target-contract-r1.md`.
3. Keep `attack-surface.md` concise: entrypoints, trust boundaries, high-risk
   sinks, and source-to-sink hypotheses. It is not a finding or confirmation.
4. Record the eight-category `recon-result.json` and validate it with
   `scripts/validate_recon_result.py`; see
   `docs/runner-contracts/recon-result-contract-r1.md`.

## Exit

- Success: the target identity and Recon result validate, with explicit
  `covered`, `not_applicable`, or `unknown` categories.
- Blocked/partial: preserve gaps, evidence, and executable resume actions.
  Recon completeness never creates a candidate, verdict, disposition, bundle,
  finalization event, or recording authority.
