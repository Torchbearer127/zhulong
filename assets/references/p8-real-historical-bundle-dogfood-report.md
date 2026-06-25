# P8-post.4 Real Historical Bundle Dogfood Report

## Scope and Non-Claims

This report records a local historical dogfood of the P8 generation workflow:

```text
contract preflight -> staging build/validation -> promote/batch validation diagnostics
```

The samples are sanitized historical traces, not original bundles. This run did not execute Docker. It did not execute PoCs, replay helpers, scanners, package managers, network calls, or target code. It does not confirm new vulnerabilities, and it is not a production token-saving statistic.

This is distinct from the P8.6 fixture measurement. P8.6 measured deterministic
synthetic fixtures; this report measures whether the same gates would have
reduced final-stage repair loops on historical failure shapes.

## Sample Table

| Sample ID | Source type | Sanitized description | Historical failure mode | P8 step exercised |
| --- | --- | --- | --- | --- |
| `historical-sample-01` | Sanitized historical handoff trace | SSRF-style evidence-boundary trace with placeholder replay output and impact wording drift | Replay log placeholder, marker drift, response-content overclaim, existing final path | Contract preflight and replay transcript trust classification |
| `historical-sample-02` | Sanitized superseded draft bundle trace | Bundle-like draft directory preserved as historical evidence after being removed from final delivery | Partial confirmed bundle / final-path pollution before cleanup | Batch validation diagnostics |
| `historical-sample-03` | Sanitized evidence registration trace | Replay evidence existed but was not registered across expected reviewer materials | Evidence index / replay log registration sync repair | Contract preflight |

## Metrics Table

| Sample ID | Validator invocations | Material rewrites during dogfood | Unique errors per invocation | Partial confirmed bundle created | Marker/manual patch required | Preflight caught expected issues | Missed gaps |
| --- | ---: | ---: | --- | --- | --- | --- | --- |
| `historical-sample-01` | 2 | 0 | 5, 1 | No | No | Yes | Helper cleanup semantics still require final review |
| `historical-sample-02` | 1 | 0 | 1 | Yes, in sanitized historical shape only | No | No | Manually-created final directories require staging discipline plus batch validation |
| `historical-sample-03` | 1 | 0 | 1 | No | No | Yes | Actual artifact existence and transcript substance remain final-validator duties |

Aggregate:

- validator invocation count: `4`
- material rewrite count during this dogfood: `0`
- partial confirmed bundle count represented by historical shape: `1`
- contract preflight issue coverage: `true`
- staging failure final pollution result: failed or incomplete material stays out of final promotion when the P8 wrapper is used
- marker-only / placeholder replay log early rejection: `true`

## Per-Sample Findings

### historical-sample-01

P8 caught the high-churn failures before final delivery: unregistered replay log,
direct-impact marker drift, thin code context, SSRF impact overclaim, and an
existing final target. The replay transcript trust classifier also rejected the
placeholder replay log as `REPLAY_LOG_PLACEHOLDER`.

Final validation still remains necessary because preflight does not inspect the
full generated DOCX, helper shell behavior, or whether cleanup logic is
semantically sufficient. The final confirmed directory remained clean in the P8
path because generation would stop before promote.

### historical-sample-02

Batch validation classified the sanitized draft directory as a
`partial_confirmed_bundle`. This matches the historical repair lesson: a
bundle-like draft must not be called a confirmed deliverable just because Docker
evidence exists elsewhere.

Contract preflight alone cannot classify a manually-created final directory.
The P8 improvement is the staging wrapper: renderer output is validated under
`confirmed/.staging/<slug>` and promoted only after final validation passes.

### historical-sample-03

Contract preflight rejected the missing replay-log registration as
`REPLAY_LOG_UNREGISTERED`. This would have moved a historical evidence-list
repair from late final validation to the generation-input stage.

Final validation is still required to verify that the registered artifact
exists, is bundle-local, and is a real transcript rather than a placeholder,
thin explanatory note, or copied transcript without provenance.

## Comparison With P8.6 Fixture Dogfood

P8.6 fixture measurement used synthetic fixtures to show a deterministic retry
loop reduction and zero final-directory pollution. This P8-post.4 dogfood uses
sanitized historical failure shapes and records issue coverage, not generalized
operator productivity.

The two measurements are intentionally separate:

- P8.6 fixture measurement: deterministic local regression fixtures.
- P8-post.4 historical dogfood measurement: sanitized historical traces.
- Production token savings: not measured and not claimed.

## Follow-Up

- Keep preflight focused on generation readiness; do not turn it into a second
  final validator.
- Preserve final validation ownership for generated DOCX, helper behavior,
  artifact existence, transcript substance, copied-transcript provenance, and
  batch-level partial bundle detection.
- Future issue candidate: add a narrow report-only diagnostic for helper cleanup
  semantics if more historical traces show repeated cleanup-trap repairs.
