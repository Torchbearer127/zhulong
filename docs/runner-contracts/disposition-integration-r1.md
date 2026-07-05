# Zhulong Disposition Integration R1

Disposition Integration R1 connects the target, candidate, and verifier
contracts to `audit-disposition.json` without changing Zhulong's confirmed
bundle contract.

The integration exists to keep the state machine honest:

```text
candidate.json may describe identity and claim,
but audit-disposition.json may not mark confirmed_in_docker
unless a valid verifier-verdict.json exists.
```

## What Gets Written

`scripts/audit_disposition.py --update-from-verdict` reads one
`candidate.json` and one `verifier-verdict.json`, validates both, cross-checks
`candidate_id` and `target_ref`, then writes an additive
`candidate_dispositions` record in `audit-disposition.json`.

Example:

```bash
python3 scripts/audit_disposition.py \
  --workspace security-research-YYYYMMDD-HHMMSS \
  --candidate security-research-YYYYMMDD-HHMMSS/candidates/CAND-0001/candidate.json \
  --verdict security-research-YYYYMMDD-HHMMSS/verifier/CAND-0001/verifier-verdict.json \
  --update-from-verdict
```

The legacy `items` ledger remains compatible with existing finalization and
confirmed bundle validation. Candidate disposition records use `status` so they
can represent `confirmed_in_docker` without pretending that a confirmed bundle
already exists.

## Mapping Rules

Verifier verdicts map directly:

- `confirmed_in_docker` -> candidate disposition `status=confirmed_in_docker`
- `false_positive` -> candidate disposition `status=false_positive`
- `unverified` -> candidate disposition `status=unverified`
- `blocked` -> candidate disposition `status=blocked`

Candidate-only records stay `status=candidate`. A finder note, scanner note,
static finding, dependency alert, or LLM note cannot promote a candidate beyond
that state.

## Required Checks

`confirmed_in_docker` disposition requires all of the following:

- `candidate.json` validates;
- `verifier-verdict.json` validates;
- the verifier verdict cross-checks against the same `candidate_id`;
- the verifier verdict cross-checks against the same `target_ref`;
- the verifier verdict is exactly `confirmed_in_docker`.
- the verifier verdict has `evidence_level=entrypoint_reproduced` or
  `confirmed_in_docker`, attacker-entrypoint metadata, input shape,
  entrypoint-to-sink path, deterministic oracle, and replay material.

Invalid verifier verdicts fail closed. The script exits nonzero before writing a
new disposition ledger.

`code_level_reproduced` and `blocked_entrypoint_verification` verdict material
may be written to candidate or blocked/unverified records, but it must not map
to `confirmed_in_docker`.

## Non-Authoritative Notes

`finder-notes.md` is human context only. It is not read as promotion evidence,
and wording such as "confirmed" inside finder notes does not affect
`audit-disposition.json`.

## Confirmed Bundles

ZC-004 does not generate confirmed bundles, DOCX reports, patch material, or
replay artifacts. A `confirmed_in_docker` candidate disposition is only one gate
for future bundle generation. Confirmed bundle validation remains separate and
required: files under `confirmed/` must still pass `validate_report_bundle.py`
or `validate_all_report_bundles.py`.

Future confirmed bundle generation should require:

```text
candidate.json valid
verifier-verdict.json valid
verdict = confirmed_in_docker
audit-disposition.json candidate disposition status = confirmed_in_docker
validate_report_bundle.py pass
```

## Boundaries

This integration is not an autonomous runner, candidate discovery system,
parallel agent scheduler, patch loop, re-attack loop, backend service,
dashboard, queue, database, vector store, RAG service, MCP service, or Docker
execution implementation.
