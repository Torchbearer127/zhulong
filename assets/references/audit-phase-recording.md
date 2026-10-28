# Recording Phase

Recording is an opt-in post-confirmation gate. Use this reference only for a
validated confirmed bundle; recording cannot confirm a vulnerability.

Desktop capture belongs to the separate `zhulong-record-bundle` skill. Invoke it
explicitly with `--zhulong-root` naming this core source or installed skill root.
The core does not control OBS or Terminal, install the recording skill, or
delegate automatically. Ordinary delivery needs no recording skill. The former
`scripts/auto_record_bundle.py` entry only reports the move and exits nonzero
except for help; it never reads bundles or creates staging.

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

The separate recorder owns Terminal creation and exact native OBS window
binding. It restores only its own window-setting edit if that setting still
matches its binding, before validation and promotion. An idle black prompt is
not a final-content frame and is not blocked by a preview-brightness preflight.
Final encoded frames, identity, live checkpoints and archive gates remain
required. Historical OBS fields remain readable data, not desktop authority.

## Exit

- Success: recording evidence passes and the archive remains identity-bound.
- Failure: roll back recording-only staging and preserve the original validated
  bundle byte-for-byte.
