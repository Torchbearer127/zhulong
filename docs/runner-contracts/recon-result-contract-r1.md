# Recon Result Coverage Contract R1

This contract is the portable handoff format for Recon coverage. It records
what was inspected, what remains unknown, and which review ranges should be
prioritized. It is deliberately not a finding, candidate, verifier verdict,
disposition, confirmed bundle, or audit-finalization record.

The source of truth is [`assets/schemas/recon-result.schema.json`](../../assets/schemas/recon-result.schema.json).
Use [`assets/references/recon-result-template.json`](../../assets/references/recon-result-template.json)
as a starting shape, then validate the completed file against the exact
repository and audit workspace that produced it:

```bash
python3 scripts/validate_recon_result.py \
  --repo-root <repo-root> \
  --workspace-dir <audit-workspace> \
  --recon-result <audit-workspace>/recon-result.json \
  --json
```

## Authority and field ownership

| Result area | What it may say | Authoritative owner and boundary |
| --- | --- | --- |
| `schema_version`, `recon_id`, `status` | Identity of this Recon record and its coverage state | The result schema and this contract; `status` does not finalize the audit. |
| `target_binding` | The exact target-contract path, digest, and `tested_ref` that this record was read against | `zhulong-target.yaml` owns target name, repository root, runtime, verification mode, and scope. The validator recomputes its digest and requires an exact `tested_ref` match. |
| `attack_surface_binding` | The exact digest of the workspace-root `attack-surface.md` handoff | `attack-surface.md` remains the human-readable handoff; the result's structured entities must point back to source and workspace evidence. |
| `technology_stack`, `public_entrypoints`, `trust_boundaries`, `high_risk_sinks` | Structured observations with stable IDs and source/evidence references | The checked-out repository and workspace evidence. These are Recon observations, not vulnerability claims. |
| `security_policy_explanations`, `default_deployment_assumptions` | Observed policy and deployment assumptions, including explicit unknowns | The cited source and evidence. They must not silently become target-contract facts or security conclusions. |
| `priority_areas`, `deferred_areas`, `focus_refs` | Bounded review planning and stable downstream references | Recon planning only. `focus_refs` may name `FOCUS-*` or `DEFER-*` IDs; it does not create candidate records. |
| `coverage` | Per-category `covered`, `not_applicable`, or `unknown` state, item IDs, reason, and evidence basis | The validator checks structural completeness and references; it does not infer truth from prose. |
| `coverage_gaps`, `unresolved_blockers` | Explicit unfinished work, evidence, recovery conditions, and next/resume actions | The Recon handoff. A gap or blocker keeps later work from being described as complete until its condition is resolved. |

The result must not contain permission or downstream-adjudication fields such
as `confirmed`, `verdict`, `severity`, `disposition`, `bundle_ready`, or
candidate material. The strict schema rejects unknown object properties, while
the validator also reports stable issue codes for forbidden permission and
candidate content.

## Coverage status semantics

- `complete` means the Recon coverage contract is complete: all eight coverage
  categories are either covered or evidence-backed `not_applicable`; no category
  is unknown; there are no gaps or blockers; and priority/deferred ranges plus
  stable focus references are present. It does not mean “no vulnerability”,
  “audit complete”, “ready to report”, or “confirmed”.
- `partial` means unfinished coverage is recorded as at least one structured gap
  or blocker. A gap has a stable code, affected coverage IDs, source/evidence
  basis, and an executable next action with an observable completion condition.
- `blocked` means at least one substantive blocker prevents continued Recon.
  Each blocker has a stable code, affected coverage IDs, source/evidence basis,
  a recovery condition, and a structured resume action. “Docker unavailable”
  alone is not enough; the blocked surface and safe recovery must be recorded.
- `not_applicable` is not an empty placeholder. Its `item_ids` are empty, its
  reason is concrete, and its basis has both source and workspace evidence.
  Natural-language absence claims such as “no issues found” are not coverage.

## Reference and binding rules

Source references are repository-relative POSIX paths. Evidence references are
audit-workspace-relative POSIX paths. Absolute paths, URIs, parent traversal,
backslashes, missing files, invalid line ranges, and symlink escapes are
rejected. The canonical attack-surface path is exactly `attack-surface.md` at
the workspace root. Every referenced file is checked without following a
symlink outside the supplied root.

The validator reads the target contract through the existing target-contract
validator, recomputes the target and attack-surface SHA-256 digests, and checks
the exact tested ref. It does not rewrite the result, target contract,
attack-surface handoff, source repository, audit state, or evidence.

## Downstream boundary

Recon output may inform later source review and candidate-generation planning
through stable `focus_refs`. It may not create a candidate, assert exploitability,
assign severity, produce a verifier verdict, build a confirmed bundle, or change
the audit state. Those actions remain governed by their own contracts and gates.
The separate stage-finalization entrypoint introduced by a later workflow step
alone can register Recon-stage termination; this validator never does so and
cannot finalize an audit workspace.

The validator is offline and read-only: it performs no Docker, network, package
manager, LLM, PoC, replay, or state-transition operation. Source, Claude, and
Codex layouts all ship the same schema, template, validator, and fixture matrix;
the source tree remains canonical and installed copies are generated by the
existing sync scripts.
