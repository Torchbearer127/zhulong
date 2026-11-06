# Packaging and Finalization Phase

Use this reference after a source-bound `confirmed_in_docker` verifier verdict
and confirmed disposition exist.

Before packaging, check final validity, classification, and severity against the
[prerequisite and incremental-impact review](audit-phase-verification.md#prerequisite-and-incremental-impact-review).
A prior success marker or validator pass does not replace this review.

## Working path

1. Validate `confirmed/.contracts/<slug>.bundle-contract.json` with the real
   repository passed as `--repo-root`.
2. Build only through `scripts/build_confirmed_bundle.py`. It renders under
   `confirmed/.staging/<slug>`, validates the final bundle, promotes, and runs
   `scripts/validate_all_report_bundles.py`.
   For requested portable standalone or replay-ready delivery, use this same
   builder with `--require-standalone-replay`; it forwards the core's existing
   finite-subset static qualification before promotion. Unsupported provisioning
   is a delivery blocker, not a reason to omit the option. Ordinary static-only
   packaging can omit it, but must not claim standalone or runtime readiness.
3. Keep each bundle self-contained, portable, one-vulnerability-only, and free
   of submitter-local absolute paths or private material. Diagnostic
   `--all-errors` output never repairs or confirms a bundle.
   Static promotion does not prove a fresh build or healthy startup. Before
   claiming delivery-ready, obtain authorization for actual replay of the final
   bundle from a clean temporary copy, with fresh target provisioning and owned
   cleanup. Keep that runtime evidence separate from the build-only manifest;
   without authorized execution, report runtime/clean-room acceptance NOT_RUN.
4. Complete seeded variant discovery when confirmed bundles exist.
5. Review audit-owned Docker resources, apply only exact labeled cleanup, reject
   broad Docker prune or baseline rewriting, then require strict clean
   verification.
6. Finalize only through `scripts/finalize_audit_workspace.py` and verify with
   `scripts/assert_finalized_workspace.py`.

See `assets/references/bundle-generation-checklist.md`,
`assets/references/docker-resource-hygiene.md`,
`docs/runner-contracts/disposition-integration-r1.md`, and
`docs/runner-contracts/audit-state-protocol-r2.md`.

## Exit

- Success: every promoted bundle passes final and batch validation, cleanup is
  strict-clean, and the canonical finalization event is valid.
- Failure: staging remains non-confirmed; partial bundles, edited summaries,
  handoff text, or state files cannot manufacture completion.
