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
- `--allow-execute`: opt into the narrow fresh-execution path described below;
  requires `--execution-input` and an explicit new `--run-id`.
- `--execution-input`: workspace-relative JSON input for that opt-in path.
  It cannot be combined with `--dry-run`, `--no-execute`, or
  `--dry-run-result`.
- `--repo-root`: optional, invocation-local Git worktree root for fresh
  execution only. When supplied, `target.repo_root` must be exactly `.`; that
  portable value asserts the selected root and is not resolved from the target
  file. Other values reject. Without this flag, the existing rule remains:
  resolve `target.repo_root` relative to the target configuration directory.
  The selected directory must be the real Git worktree root, and the workspace
  must be strictly inside it. Prefer a normalized absolute path; relative paths
  use the invocation CWD, and `..` or symlink components are rejected. Do not
  store this local CLI path in the target.
- `--run-id`: names the verifier run directory.
- `--dry-run-result`: fixture-only selftest simulation. Simulated confirmed
  results are downgraded to blocked entrypoint verification because dry-run
  fixtures do not prove attacker-entrypoint reachability.

By default, R1 avoids surprising execution. It never falls back to host-side PoC
execution.

The explicit execution opt-in currently supports only a fresh Candidate R2 run
for an ordinary `runtime.type=docker` target with the `log_pattern` oracle. The
execution input names reviewed source files and binds their hashes to a tested
commit; it is review metadata, not an authenticated approval. For a standard
repository-child-workspace layout, `--repo-root` selects the repository for this
invocation while the portable target keeps `target.repo_root: .`; without the
flag, the default target-file-relative resolution above is unchanged. The
verifier still requires the target ref, Candidate R2 identity, execution input,
and checked-out HEAD to name the same commit. It snapshots those files from Git,
invokes only
`scripts/run_verification_case.sh` with network disabled and a local
sha256-pinned image, and accepts only its bounded, typed result and receipt.
`source-manifest.json` retains the source path/hash list; `run-binding.json`
records its relative path and SHA-256 instead of copying the full list.
The run, case, and source-snapshot paths must be new. The canonical candidate-
scoped `verifier-verdict.json` and the run-scoped `run-binding.json` must also
be absent; a successful run publishes only to the canonical verdict path. This
path does not resume or replace prior output. After a handled failure, the
verifier removes only this invocation's unchanged, owned, mode-0600, single-link
empty-file reservations. If identity, contents, parent directory, or access
cannot be verified, it leaves the object untouched and warns while preserving
the original failure. Cleanup checks identity then unlinks under the
trusted-workspace-owner model; it is not a kernel-atomic compare-and-delete. A
post-publication error followed by rollback may also leave an empty
`verifier-verdict.json` reservation with a different inode; while this canonical
path exists, even a new run ID is refused. Failure evidence and journal events
are not rewound; a maintainer must inspect the leftover file's ownership and
failed-run evidence before any recovery, without blindly deleting or overwriting it. A forced
process kill or crash can also leave a reservation behind. A retry requires a
different run ID and a valid R2 `verification/running` baseline; if the failed
attempt left the stage blocked, restore it through the production state writer
first.
Offline fake-Docker selftests exercise only the wrapper contract; they do not
demonstrate a live Docker execution or complete the independent verification
chain.

`scripts/run_verification_case.sh` is a separate Docker-evidence wrapper, not
an execution implementation hidden inside this R1 verifier. In an R2 audit
workspace it requires a synchronized `verification/running` state (or an
explicit retry from `verification/blocked`) before any Docker CLI call, then
commits a revision-bound same-stage start event before the PoC container
command. Its result remains Docker oracle material only. Legacy R1 behavior is
kept compatible, and a no-state path is never silently upgraded to R2.

## Runtime Behavior

`runtime.type=manual-blocked` always produces a `blocked` verdict. The reason
states that the target is non-confirmable by the automatic verifier.

In the R1 default, dry-run, and no-execute paths, `docker` and
`docker-compose` targets use explicit fixture simulation or return
`unverified`/`blocked` without executing. The opt-in path above currently
allows only ordinary Docker; `docker-compose` remains unsupported for
execution. Any expansion must stay Docker or Docker Compose only, use timeouts,
record command text and exit codes, and avoid broad cleanup or PID signaling.

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
mounts, successful oracle output, non-empty command and artifact records,
`evidence_level=entrypoint_reproduced` or `confirmed_in_docker`, an
attacker-controlled entrypoint with input shape and entrypoint-to-sink path, a
deterministic impact oracle, and reviewer-facing replay material. Code-level or
function-level reproduction remains supporting evidence only.

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
