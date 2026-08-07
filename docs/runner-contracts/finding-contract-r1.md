# Zhulong Finding Contract R1

Finding Contract R1 defines the pre-confirmation boundary between a finder and
an independent verifier. It adds two portable JSON files:

- `candidate.json`: a vulnerability claim, attacker model, PoC pointer, expected
  oracle, and evidence leads.
- `verifier-verdict.json`: an independent verification result and evidence
  summary.

The split exists so a finder cannot self-certify a finding. Static reasoning,
scanner output, pattern matching, dependency alerts, and LLM notes can create a
candidate, but they do not make a confirmed vulnerability.

## Candidate JSON

`candidate.json` is always a claim. Its `status` must be exactly `candidate`.
It cannot use `confirmed`, `confirmed_in_docker`, `verified`, or equivalent
confirmation wording as a status or top-level result.

Required fields include:

- `schema_version=1`
- `candidate_id`
- `target_ref.target_config` and `target_ref.tested_ref`
- `entrypoint`
- `attacker_model`
- `claim.source`, `claim.sink`, `claim.missing_constraint`, and `claim.impact`
- `poc.kind`, `poc.path`, and `poc.expected_oracle.type`
- `evidence.static_locations` and `evidence.dynamic_evidence`
- `finder.source` and `finder.created_at`

Static locations may be empty. When present, each location must use a
repository-relative path and valid line numbers.

The candidate `entrypoint` field is a claim about where verification should
look. It is not proof that the attacker can reach the sink. Entrypoint proof
must come from the verifier verdict and, for bundle generation, the bundle
contract.

Validate locally:

```bash
python3 scripts/validate_candidate.py path/to/candidate.json
```

## Verifier Verdict JSON

`verifier-verdict.json` is the only Finding Contract R1 structure that may
recommend `confirmed_in_docker`. Its `verdict`, `verification_status`, and
`disposition_recommendation` must stay consistent.

Allowed verdicts are:

- `blocked`
- `false_positive`
- `unverified`
- `confirmed_in_docker`

Verifier verdicts also carry `evidence_level`:

- `code_level_reproduced`: a container-local, function-level, or source-level
  proof succeeded, but attacker entrypoint reachability is not proven.
- `entrypoint_reproduced`: Docker or Docker Compose evidence reached the sink
  through a real attacker-controlled entrypoint and oracle.
- `confirmed_in_docker`: the evidence is entrypoint-backed and ready for
  confirmed-bundle gates.
- `blocked_entrypoint_verification`: code-level or partial evidence exists, but
  API/CLI/UI/RPC/library entrypoint verification is blocked.

`confirmed_in_docker` requires strong Docker evidence:

- `evidence_level=entrypoint_reproduced` or `confirmed_in_docker`
- `attacker_entrypoint.id`, `kind`, `route`, `input_shape`,
  `entrypoint_to_sink_path`, and `deterministic_impact_oracle`
- `replay_material.path` or `replay_material.generation_command`
- `environment.fresh_container=true`
- `environment.host_network=false`
- `environment.privileged=false`
- `environment.docker_socket_mounted=false`
- `environment.credential_paths_mounted=false`
- `oracle_result.success=true`
- non-empty `commands`
- non-empty `artifacts`

`code_level_reproduced` can be retained as supporting evidence, but it cannot
produce `confirmed_in_docker` or satisfy confirmed bundle readiness by itself.

`blocked`, `false_positive`, and `unverified` verdicts must include a reason or
summary explaining the non-confirmed decision.

Validate locally:

```bash
python3 scripts/validate_verifier_verdict.py path/to/verifier-verdict.json
```

Optionally cross-check the verdict against the candidate:

```bash
python3 scripts/validate_verifier_verdict.py \
  --candidate path/to/candidate.json \
  path/to/verifier-verdict.json
```

The cross-check rejects `candidate_id` or `target_ref` mismatches.

## Target Contract Link

Both files reference the target through `target_ref.target_config` and
`target_ref.tested_ref`. The referenced target contract records the target
runtime and scope; the candidate and verdict must describe the same target
identity before later disposition promotion can be trusted.

## Future Use

ZC-003 adds a minimal independent verifier documented in
[`independent-verifier-r1.md`](independent-verifier-r1.md). It reads
`candidate.json`, validates it against the target contract, and writes
`verifier-verdict.json` without turning the workflow into an autonomous runner.
ZC-004 makes disposition promotion depend on a valid `confirmed_in_docker`
verifier verdict plus the existing confirmed bundle gates.
Disposition Integration R1 is documented in
[`disposition-integration-r1.md`](disposition-integration-r1.md).

## Non-Goals

This step does not implement a verifier runner, execute PoCs, modify
`audit_disposition.py`, promote findings, generate confirmed bundles, add
runner orchestration, add patch or re-attack behavior, or change the confirmed
bundle directory structure.

The validators are local contract checks only. They reject machine-local paths,
parent traversal, secret-like text, broad Docker prune commands, dangerous PID
kill patterns, Docker socket mounts, credential mounts, privileged runtime
requests, and host-network runtime requests, but they never execute commands.

## Candidate R2 compatibility

Candidate Contract R2 adds recomputable identity, structured provenance, and
candidate-only relationships while preserving R1. R1 is visibly classified as
`legacy_r1` and is never silently upgraded. Fingerprints and duplicate metadata
cannot verify or confirm a vulnerability. See
[`candidate-identity-dedupe-r1.md`](candidate-identity-dedupe-r1.md).

When a verdict cross-checks Candidate R2, `candidate_binding` must match the
exact candidate file SHA-256 and independently recomputed fingerprint. This
prevents identity drift without changing verifier authority.
