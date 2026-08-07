# Triage batch contract R1

`triage-batch.json` is a read-only, explicit inventory of existing
`candidate.json` records plus advisory recommendations. Its authority stops at
candidate triage. It cannot create a verifier verdict, update
`audit-disposition.json`, claim Docker confirmation, severity/CVSS, bundle
readiness, or audit completion.

Use the offline validator:

```bash
python3 scripts/validate_triage_batch.py \
  --repo-root <target-repository> \
  --workspace-dir <audit-workspace> \
  --triage-batch triage-batch.json \
  --json
```

The batch binds one target contract path/digest/tested ref and each candidate's
workspace-relative path, exact SHA-256, and candidate ID. The validator runs
the production candidate validator for every inventory item, rejects unsafe or
symlinked paths, and requires the explicit inventory rather than discovering a
directory.

When `recon_binding` is present, its workspace-relative `path`, exact SHA-256,
and `recon_id` are the batch's single bound Recon input. The triage validator
invokes the existing production Recon validator internally for that file; it
does not expose a second `--recon-result` CLI argument. Its declared
`--triage-batch` input remains workspace-relative, and handoff aggregation uses
that same declared invocation rather than inventing extra flags.

The only recommendations are `recommend_verification`, `unverified`,
`blocked`, `false_positive`, and `duplicate`. A recommendation is never a
verifier verdict or disposition. Verification recommendations have a unique,
positive `verification_order`; duplicate links stay inside the batch and cannot
self-reference or cycle.

`complete` means every inventory candidate has exactly one advisory decision
and no batch gap, blocker, or unprocessed candidate. It does not mean a
candidate was verified or that the audit is complete. `partial` records its
unprocessed candidate, gap, or blocker and an actionable next step. `blocked`
records a substantive blocker with affected candidates, evidence, recovery
condition, and resume action. Empty inventories are invalid and cannot be used
to claim no vulnerability or to finalize triage.

## Narrow stage finalizer

`finalize_stage.py` only records the terminal state of an already-running
`recon` or `triage` stage in an existing R2 workspace:

```bash
python3 scripts/finalize_stage.py \
  --workspace-dir <audit-workspace> \
  --repo-root <target-repository> \
  --stage recon|triage \
  --result <workspace-relative-result-path> \
  --expected-result-sha256 sha256:<64-hex> \
  --expected-state-revision <N> \
  --json
```

The mapping is `complete -> complete/completed`, `partial -> pause/paused`, and
`blocked -> block/blocked`. It appends one same-stage R2 event through the
canonical writer; it never advances to another stage, runs a next action, or
acts as a scheduler. It accepts no force or ignore-validation mode.

Before any append it validates the exact result, digest, R2 journal/state view,
current stage/status, and explicit revision. Immediately before journal append,
the writer-owned lock repeats result digest/contract and state checks. A failed
preflight or lock-held check leaves the journal and state view unchanged. If a
journal append succeeds but state-view replacement fails, the writer reports
the documented partial-commit state; recover only with the R2 recovery tool.

## Candidate R2 advisory references

An R2-aware triage workflow may cite a validated candidate fingerprint or
candidate deduplication plan as advisory evidence. It must retain the explicit
candidate path/digest/ID binding. Similarity, `review_required`, or an exact
fingerprint never creates a verdict or permits automatic disposition, merge, or
confirmation.
