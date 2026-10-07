# Zhulong Independent Verifier R1

`scripts/verify_candidate.py` is an independent, opt-in capability for generic
Zhulong workspaces; it is not specific to DeepSeek Harness (dsh). Its default
R1 path validates a target contract and candidate, then writes an unexecuted
diagnostic under `verifier/<candidate_id>/diagnostics/<run_id>/`. Only the
separate fresh-execution opt-in publishes the canonical
`verifier/<candidate_id>/verifier-verdict.json`.

The verifier exists to keep finder and verifier responsibilities separate: a
finder cannot self-certify. This is a responsibility rule, not authenticated
reviewer identity or a cryptographic boundary. A finder can create
`candidate.json`, PoC files, and notes, but it cannot certify its own result as
confirmed. The verifier can validate declared inputs and publish a verdict;
that does not independently prove that a human reviewer is who they claim to
be, that an entrypoint is attacker-reachable, or that the stated impact
semantics are correct.

## What It Does

- validates `zhulong-target.yaml` with `validate_target_contract.py` logic;
- validates `candidate.json` with `validate_candidate.py` logic;
- cross-checks `target_ref.target_config` and `target_ref.tested_ref`;
- creates `<workspace>/verifier/<candidate_id>/diagnostics/<run_id>/` for
  default non-execution runs;
- writes diagnostic logs and fixture artifacts only below that diagnostic
  directory;
- writes a schema-readable `verifier-diagnostic.json` by default; diagnostics
  are not canonical verdicts and are not discovered as named authority files;
- retains custom non-authority JSON output for callers that explicitly request
  it, but rejects non-execution `--out` paths whose filename is
  `verifier-verdict.json`;
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
  --run-id review-001 --no-execute
```

The command above writes to
`verifier/CAND-0001/diagnostics/review-001/verifier-diagnostic.json`. A
non-execution `--out` may still name a custom, non-authority JSON path; a path
named `verifier-verdict.json` is rejected even when it is outside the canonical
directory. This intentional narrowing protects authority consumers. Existing
custom diagnostic documents remain readable through the verifier verdict
schema validator, but their previous path or bytes are not guaranteed to be
unchanged.

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
- `--run-id`: names the diagnostic directory by default or the fresh run directory
  with `--allow-execute`.
- `--dry-run-result`: fixture-only selftest simulation. Simulated confirmed
  results are downgraded to blocked entrypoint verification because dry-run
  fixtures do not prove attacker-entrypoint reachability.

By default, R1 avoids surprising execution. It never falls back to host-side PoC
execution. Non-execution diagnostics use an exclusive destination and never
overwrite a prior file. A repeated diagnostic run ID is refused; it does not
reserve or block the corresponding fresh execution run ID.

The independent verifier is available to any compatible Zhulong workspace; it
is not a DSH-only feature. The explicit execution opt-in currently supports
only a fresh Candidate R2 run for an ordinary `runtime.type=docker` target with
the `log_pattern` oracle. The execution input names reviewed source files and
binds their hashes to a tested commit. Review text, token strings, and oracle
descriptions are supplied metadata: they do not authenticate reviewer identity,
prove entrypoint reachability, or automatically establish impact semantics. For a standard
repository-child-workspace layout, `--repo-root` selects the repository for this
invocation while the portable target keeps `target.repo_root: .`; without the
flag, the default target-file-relative resolution above is unchanged. The
verifier still requires the target ref, Candidate R2 identity, execution input,
and checked-out HEAD to name the same commit. It snapshots those files from Git,
invokes only
`scripts/run_verification_case.sh` with network disabled and a local
sha256-pinned image, and accepts only its bounded, typed result and receipt.
`source-manifest.json` binds each source path, Git mode, snapshot mode, and
content hash; regular files remain read-only, with executable Git files
retaining their execute bit. The fresh snapshot subtree
`poc/<run_id>/source/` is project data, including on failed or interrupted runs;
named-file discovery excludes that subtree without requiring a successful
run-binding. `run-binding.json` records the manifest's relative path and
SHA-256 instead of copying the full file list.
The run, case, and source-snapshot paths must be new. The canonical candidate-
scoped `verifier-verdict.json` and the run-scoped `run-binding.json` must also
be absent; a successful run publishes only to the canonical verdict path. This
path does not resume or replace prior output. After a handled failure, the
verifier removes only this invocation's unchanged, owned, mode-0600, single-link
empty-file reservations. If the atomic writer restores and rereads an empty
reservation, it returns the new inode identity through a narrow caller-provided
sink; the caller independently checks that identity before cleanup. If rollback
identity, contents, parent directory, or access cannot be verified, the object
is left untouched and a warning preserves the original failure. Cleanup checks
identity then unlinks under the trusted-workspace-owner model; it is not a
kernel-atomic compare-and-delete. Failure evidence and journal events are not
rewound. A forced process kill or crash can leave a reservation behind; inspect
its ownership and failed-run evidence before recovery, without blindly deleting
or overwriting it. A retry requires a different run ID and a valid R2
`verification/running` baseline; if the failed attempt left the stage blocked,
restore it through the production state writer first.
Offline fake-Docker selftests exercise only the wrapper contract; they do not
demonstrate a live Docker execution or complete the independent verification
chain.

`scripts/run_verification_case.sh` is a separate Docker-evidence wrapper, not
an execution implementation hidden inside this R1 verifier. In an R2 audit
workspace it requires a synchronized `verification/running` state (or an
explicit retry from `verification/blocked`) before any Docker CLI call, then
commits a revision-bound same-stage start event before the PoC container
command. Its result remains Docker oracle material only. Custom non-authority R1
diagnostics remain readable through the existing verdict schema; a
non-execution `--out` using the canonical verdict filename is intentionally
rejected, and a no-state path is never silently upgraded to R2.

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
