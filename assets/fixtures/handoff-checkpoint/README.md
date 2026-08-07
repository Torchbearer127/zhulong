# Handoff / Checkpoint Contract Fixtures

These are an inventory for the offline selftest. The selftest creates each
workspace in a temporary directory and invokes the production CLIs as
subprocesses, so this fixture directory contains no absolute paths, evidence
copies, credentials, Docker state, prompts, or chat transcripts.

Positive cases cover running/blocked state, recovery material, completed
workspaces with and without a validated bundle, same-revision idempotence, and
legal historical checkpoints. Negative cases cover malformed authority,
stale/forged derived state, unsafe paths and symlinks, conflicting bytes,
concurrent changes, atomic-publication faults, and completion claims whose
validated bundle support was removed. Completion-source attribution cases keep
R2 diagnostics on `audit-events.jsonl` finalization events while preserving the
legacy R1 `stage-status.json` source.
