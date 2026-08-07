# Recording Phase

Recording is an opt-in post-confirmation gate. Use this reference only for a
validated confirmed bundle; recording cannot confirm a vulnerability.

## Working path

1. Bind project, commit, bundle, report, archive, and replay identity.
2. Run the bundle-local replay helper and retain real command/output/oracle
   transcripts.
3. Validate checkpoints, screenshots, timing observations, archive contents, and
   `recording-evidence.json` with `scripts/validate_recording_evidence.py`.
4. Promote recording output only after the recording gate passes.

Reviewer pause variables are visual holds, never readiness or retry timers.
Public issue text must not disclose unpublished target names, payloads, PoC
commands, bundle paths, attachment names, or local filesystem paths.

## Exit

- Success: recording evidence passes and the archive remains identity-bound.
- Failure: roll back recording-only staging and preserve the original validated
  bundle byte-for-byte.
