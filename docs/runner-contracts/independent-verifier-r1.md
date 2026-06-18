# Zhulong Independent Verifier R1

`scripts/verify_candidate.py` is the minimal ZC-003 verifier for the contract
layer. It reads a target contract and one candidate, checks that they describe
the same target, and writes a valid `verifier-verdict.json`.

The verifier exists to keep finder and verifier responsibilities separate: a
finder cannot self-certify. A finder can create `candidate.json`, PoC files,
and notes, but it cannot certify its own result as confirmed. The independent
verifier is the first component in the R1 contract layer that may recommend
`confirmed_in_docker`.

## What It Does

- validates `zhulong-target.yaml` with `validate_target_contract.py` logic;
- validates `candidate.json` with `validate_candidate.py` logic;
- cross-checks `target_ref.target_config` and `target_ref.tested_ref`;
- creates `<workspace>/verifier/<candidate_id>/runs/<run_id>/`;
- writes verifier logs and fixture artifacts only below that verifier run
  directory;
- writes `verifier-verdict.json` at the default verifier path or explicit
  `--out` path;
- validates the generated verdict with `validate_verifier_verdict.py` logic.

## What It Does Not Do

R1 is not an autonomous runner. It does not discover candidates, spawn agents,
modify `audit_disposition.py`, promote findings, generate confirmed bundles,
render DOCX reports, generate patches, run a re-attack loop, create issues, or
change the `confirmed/` directory structure.

The script also does not read `finder-notes.md` or agent chat transcripts as
confirmation evidence. Those files may be useful human context, but they are
not independent oracle output.

## CLI

```bash
python3 scripts/verify_candidate.py \
  --target-config zhulong-target.yaml \
  --candidate security-research-YYYYMMDD-HHMMSS/candidates/CAND-0001/candidate.json \
  --workspace security-research-YYYYMMDD-HHMMSS \
  --out security-research-YYYYMMDD-HHMMSS/verifier/CAND-0001/verifier-verdict.json
```

Optional flags:

- `--dry-run` / `--no-execute`: keep verification in validator-only mode.
- `--allow-execute`: reserved for explicit Docker-only execution support.
- `--run-id`: names the verifier run directory.
- `--dry-run-result`: fixture-only selftest simulation. Simulated confirmed
  verdicts are clearly marked as dry-run fixtures and are not real bundle
  evidence.

By default, R1 avoids surprising execution. It never falls back to host-side PoC
execution.

## Runtime Behavior

`runtime.type=manual-blocked` always produces a `blocked` verdict. The reason
states that the target is non-confirmable by the automatic verifier.

For `docker` and `docker-compose` targets, R1 validates contracts and either
uses explicit fixture simulation or returns `unverified`/`blocked` without
executing. Future execution support must stay Docker or Docker Compose only,
use timeouts, record command text and exit codes, and avoid broad cleanup or
PID signaling.

## Oracle Types

R1 recognizes:

- `exit_code_zero`
- `http_response_contains`
- `log_pattern`
- `callback_observed`
- `file_marker_created`
- `process_crash`
- `manual_blocked`

Unsupported oracle types produce `blocked` with
`unsupported oracle type: <type>`. `manual_blocked` is recognized but cannot
produce confirmed.

## Safety Controls

The verdict records:

- `fresh_container`
- `runtime_type`
- `host_network`
- `privileged`
- `docker_socket_mounted`
- `credential_paths_mounted`
- `egress_policy`

Any `confirmed_in_docker` verdict must have a fresh Docker-backed environment,
no host network, no privileged mode, no Docker socket mount, no credential path
mounts, successful oracle output, and non-empty command and artifact records.

The verifier relies on the existing target, candidate, and verdict validators
to reject local absolute paths, parent traversal, privileged runtime text, host
networking, Docker socket mounts, credential-bearing mount paths, broad Docker
cleanup commands, and dangerous PID signaling.

## Disposition And Bundles

ZC-004 handles disposition promotion from a valid verifier verdict. ZC-003 only
writes a verifier verdict. A verifier verdict alone does not create a confirmed bundle
and does not replace confirmed bundle validation.

Disposition Integration R1 is documented in
[`disposition-integration-r1.md`](disposition-integration-r1.md).
