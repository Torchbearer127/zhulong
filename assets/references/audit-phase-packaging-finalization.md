# Packaging and Finalization Phase

Use this reference after a source-bound `confirmed_in_docker` verifier verdict
and confirmed disposition exist.

## Working path

1. Validate `confirmed/.contracts/<slug>.bundle-contract.json` with the real
   repository passed as `--repo-root`.
2. Build only through `scripts/build_confirmed_bundle.py`. It renders under
   `confirmed/.staging/<slug>`, validates the final bundle, promotes, and runs
   `scripts/validate_all_report_bundles.py`.
3. Keep each bundle self-contained, portable, one-vulnerability-only, and free
   of submitter-local absolute paths or private material. Diagnostic
   `--all-errors` output never repairs or confirms a bundle.
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
