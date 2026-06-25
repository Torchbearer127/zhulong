# P8 Bundle Generation Dogfood Report

## Scope

This report records a deterministic local-only P8.6 dogfood run. It exercises
temporary fixtures and local validators only. It does not execute Docker, replay
helpers, PoCs, scanners, package managers, network commands, or real target
code.

## Fixtures Used

- `assets/fixtures/p8-dogfood/bad-contract.bundle-contract.json`
- `assets/fixtures/p8-dogfood/marker-only-replay-output.log`
- Temporary renderer inputs derived from `assets/examples/confirmed-findings.example.json`

## Commands Represented

- `build_confirmed_bundle.py`
- `build_confirmed_bundle.py --keep-failed-staging`
- `validate_all_report_bundles.py`
- `validate_bundle_contract.py --all-errors --json`
- `validate_report_bundle.py`
- `validate_report_bundle.py --all-errors --json`

## Old Retry-Loop Failure Mode

Before P8, the last bundle stage often looked like a fail-fast repair chain:
generate a final bundle, see one validator error, patch one artifact, rerun,
and repeat. That pattern encouraged reactive edits to reviewer indexes, replay
logs, direct-impact markers, or fixture provenance after material already lived
under `confirmed/<slug>/`.

## New P8 Flow Result

- Bad contract preflight: one invocation returned `9` unique issue codes: `BUNDLE_PATH_ESCAPE, CODE_CONTEXT_TOO_THIN, DIRECT_IMPACT_MARKER_DRIFT, DOCKER_STATUS_NOT_CONFIRMED, FINAL_TARGET_EXISTS, FIXTURE_PROVENANCE_MISSING, REPLAY_LOG_UNREGISTERED, SSRF_IMPACT_OVERCLAIM, VARIANT_SEED_READINESS_MISSING`.
- Staging build failure: final bundle created = `false`; failed staging preserved = `true`.
- Marker-only replay log: rejected = `true`; issue codes = `REPLAY_LOG_MARKER_ONLY`; called confirmed = `false`.
- Valid happy path: contract preflight valid = `true`; promoted = `true`; batch validation passed = `true`.

## Metrics

```json
{
  "cases": {
    "bad_contract": {
      "issue_codes": [
        "BUNDLE_PATH_ESCAPE",
        "CODE_CONTEXT_TOO_THIN",
        "DIRECT_IMPACT_MARKER_DRIFT",
        "DOCKER_STATUS_NOT_CONFIRMED",
        "FINAL_TARGET_EXISTS",
        "FIXTURE_PROVENANCE_MISSING",
        "REPLAY_LOG_UNREGISTERED",
        "SSRF_IMPACT_OVERCLAIM",
        "VARIANT_SEED_READINESS_MISSING"
      ],
      "single_invocation_multi_error_count": 9,
      "valid": false
    },
    "marker_only_replay_log": {
      "called_confirmed": false,
      "issue_codes": [
        "REPLAY_LOG_MARKER_ONLY"
      ],
      "rejected": true
    },
    "staging_build_failure": {
      "failed_staging_preserved": true,
      "final_bundle_created": false
    },
    "valid_contract_happy_path": {
      "batch_validation_passed": true,
      "contract_preflight_valid": true,
      "promoted": true
    }
  },
  "closure": {
    "p8_1_bundle_contract_preflight": "accepted",
    "p8_2_staging_build_wrapper": "accepted",
    "p8_3_replay_log_trust_boundary": "accepted",
    "p8_4_final_validator_all_errors": "accepted",
    "p8_5_skill_docs_sync_closure": "accepted",
    "p8_6_dogfood_metrics_retry_loop_regression": "generated"
  },
  "commands_run": [
    "build_confirmed_bundle.py",
    "build_confirmed_bundle.py --keep-failed-staging",
    "validate_all_report_bundles.py",
    "validate_bundle_contract.py --all-errors --json",
    "validate_report_bundle.py",
    "validate_report_bundle.py --all-errors --json"
  ],
  "comparison": {
    "legacy_fail_fast_simulated_material_rewrite_count": 10,
    "legacy_fail_fast_simulated_validator_invocation_count": 11,
    "material_rewrite_count_delta": 10,
    "p8_material_rewrite_count": 0,
    "p8_validator_invocation_count": 5,
    "validator_invocation_count_delta": 6
  },
  "contract_preflight_caught_expected_issues": true,
  "local_only_non_goals": [
    "no Docker execution",
    "no replay helper execution",
    "no PoC execution",
    "no scanner execution",
    "no package manager execution",
    "no network execution",
    "no real target code execution"
  ],
  "manual_marker_patch_detected_or_required": false,
  "material_rewrite_count": 0,
  "partial_confirmed_bundle_created": false,
  "schema_version": 1,
  "staging_promote_required_for_final": true,
  "unique_error_count_per_invocation": [
    9,
    1,
    0,
    0,
    0
  ],
  "validator_invocation_count": 5
}
```

The simulated legacy fail-fast chain would require
`11` validator
invocations and `10`
material rewrites for this fixture set. The P8 dogfood path used
`5` validator invocations and
`0` material rewrites, so the measured
deltas are `6` fewer validator
invocations and `10` fewer material
rewrites.

## Boundaries

These checks prove only workflow behavior: preflight multi-error visibility,
staging non-promotion, marker-only replay rejection, and valid staging-to-final
promotion in a temporary workspace. They do not prove a real vulnerability,
replace Docker evidence, replace final bundle validation, or treat seeded
variant candidates as confirmed evidence.

Final bundle validation remains mandatory. Contract preflight and staging
validation are workflow gates only.

## P8 Closure State

- `p8_1_bundle_contract_preflight`: `accepted`
- `p8_2_staging_build_wrapper`: `accepted`
- `p8_3_replay_log_trust_boundary`: `accepted`
- `p8_4_final_validator_all_errors`: `accepted`
- `p8_5_skill_docs_sync_closure`: `accepted`
- `p8_6_dogfood_metrics_retry_loop_regression`: `generated`

## Residual Risks

- The legacy fail-fast comparison is a deterministic simulation based on unique
  issue codes, not a measurement from historical operator transcripts.
- The dogfood run uses fixture-sized bundles; real target repositories can still
  need human judgment for evidence quality and claim boundaries.
- P8-post.3 low polish is closed: `finding.severity` now uses the stable
  contract enum (`Critical`, `High`, `Medium`, `Low`, `Informational`),
  `bug_class` stays documented free text with recommended values, and the
  template no longer carries redundant empty full-app provenance or
  callback-only SSRF oracle fields.
