# Candidate and Triage Phase

Use this reference after Recon to record candidate-only leads, stable identity,
deduplication advice, and bounded triage recommendations.

## Preconditions

- Existing candidate records with repository-relative evidence references.
- Source identity still matches the target contract.

## Working path

1. Route scanner, static, dependency, checklist, playbook, and LLM observations
   to candidates only. False positives, non-security defects, and unverified
   leads remain workspace records outside `confirmed/`.
2. Validate Candidate Contract R2 identity and provenance with
   `scripts/validate_candidate.py`. Upgrade legacy R1 only through
   `scripts/upgrade_candidate_identity.py`.
3. Build and validate advisory dedup plans with
   `scripts/build_candidate_dedup_plan.py` and
   `scripts/validate_candidate_dedup_plan.py`; see
   `docs/runner-contracts/candidate-identity-dedupe-r1.md`.
4. Validate a bounded `triage-batch.json` through
   `scripts/validate_triage_batch.py`. `scripts/finalize_stage.py` may append
   one same-stage terminal event only under its digest/revision CAS contract.

## Exit

- Success: candidates and advisory recommendations validate without changing
  verifier verdicts or `audit-disposition.json`.
- Blocked: preserve the candidate and blocker. An empty batch or unresolved
  Docker blocker cannot prove that no vulnerability exists.
