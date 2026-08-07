# Candidate identity, provenance, and deduplication contract R1

This contract adds Candidate Contract R2 while preserving every valid Candidate
R1 file. It is candidate-only metadata: a fingerprint, provenance record,
`merged_from`, `duplicate_of`, or deduplication plan never proves validity,
exploitability, Docker reproduction, severity, disposition, bundle readiness, or
audit completion.

## Compatibility and explicit upgrade

`assets/schemas/candidate.schema.json` is the single versioned entry point.
`schema_version=1` is reported as `protocol_mode=legacy_r1`; version 2 is
reported as `protocol_mode=r2`; unknown versions fail closed. R1 files are not
silently upgraded.

Use `scripts/upgrade_candidate_identity.py` with a separate structured identity
input and output path. Root-cause family, sink family, trust boundary, and the
primary source path are never inferred from a title, claim prose, filename,
prompt, Agent note, or hidden reasoning. The command preserves `candidate_id`,
writes a legacy ID mapping, refuses in-place updates, is idempotent only for the
same output bytes, and creates no verdict, disposition, event, bundle, evidence,
recording, or finalization artifact.

## Canonical fingerprint

Identity and normalization versions are both `1`. The fingerprint is SHA-256 of
compact UTF-8 JSON with sorted keys over exactly:

```text
normalization_version
target_commit (exactly target_ref.tested_ref)
normalized_entrypoint {kind, id, route}
trust_boundary_id (explicit token or null)
sink_family
root_cause_family
primary_source_path
```

HTTP entrypoints normalize the method to uppercase, collapse repeated path
slashes, and remove a non-root trailing slash while preserving path case. URL
authority, query/fragment text, backslashes, dot segments, malformed percent
encoding, and encoded separator/dot ambiguity fail closed. Non-HTTP routes use
only conservative whitespace normalization and reject URI syntax. Line numbers,
title, severity, CVSS, PoC output, impact prose, timestamps, and provenance are
not fingerprint inputs.

Sink families are `command_execution`, `file_read`, `file_write`,
`path_resolution`, `http_request`, `deserialization`, `template_render`,
`database_query`, `code_loading`, `authz_decision`, `secret_exposure`,
`resource_exhaustion`, `logging`, or `other:<stable-slug>`. Root-cause families
are `missing_validation`, `insufficient_validation`,
`canonicalization_mismatch`, `authorization_missing`,
`trust_boundary_confusion`, `unsafe_default`, `injection`,
`resource_limit_missing`, `race_condition`, or `other:<stable-slug>`.

## Provenance and relationships

Provenance is a non-empty, canonical, deduplicated array. Each item binds a
controlled source kind, stable source ID, workspace-relative artifact path and
SHA-256, with optional portable producer/version and audit-only `observed_at`.
Scanner, Agent, manual, imported legacy, and seeded-variant origins do not gain
verification authority.

`duplicate_of` points from a subordinate candidate to its canonical candidate;
the canonical candidate keeps it null. `merged_from` belongs only to a canonical
candidate and requires the complete provenance union. Every reference binds ID,
fingerprint, relative path, and digest. Self-reference, unknown targets,
duplicate edges, binding drift, bidirectional links, subordinate-as-canonical,
and cycles fail closed when validated against an explicit inventory.

## Advisory deduplication plan

`build_candidate_dedup_plan.py` reads only a supplied inventory. It never scans
the workspace. Exact duplicate requires equality of the target commit,
normalized entrypoint, trust boundary, sink family, root-cause family, primary
source path, and recomputed fingerprint. The canonical winner is the UTF-8 byte
ordering minimum of `(candidate_id, workspace-relative path, candidate digest)`.

Partial structured equality is `review_required`, never an automatic merge.
R1/R2 and R1/R1 pairs at the same tested ref are conservative
`review_required`; different tested refs are `distinct`. Input order, mtime,
locale, timezone, hash seed, and filesystem traversal order do not affect plan
bytes. The plan is advisory and does not modify candidates.

`validate_candidate_dedup_plan.py` reloads every bound candidate and provenance
artifact, resolves source paths under the supplied repository without symlink
escape, recomputes fingerprints/classifications/provenance unions, and rejects
candidate, repository, relationship, inventory, or plan drift.

## Consumer boundary

R2-aware verifier verdicts bind the exact candidate file digest and fingerprint
in `candidate_binding`; legacy R1 keeps the existing ID + tested-ref binding.
Disposition records retain the R2 digest/fingerprint and reject later identity
drift. These are consistency checks only. Verifier evidence, disposition policy,
Docker reproduction, confirmed-bundle validation, and finalization remain
separate mandatory authorities.
