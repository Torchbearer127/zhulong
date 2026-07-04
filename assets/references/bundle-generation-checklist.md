# Bundle Generation Checklist

Before creating a final `confirmed/<slug>/` bundle:

- Follow the bundle contract -> staging build -> validate all -> finalization short path.
- Fill or derive `confirmed/.contracts/<slug>.bundle-contract.json` first.
- Set `render.source_findings_json` and `render.finding_slug` so exactly one source finding is selected.
- Before adding or changing contract fields, consult `assets/references/bundle-rule-mapping.md`; contract preflight remains ready-to-render only.
- Set `finding.severity` to one stable contract enum value: `Critical`, `High`, `Medium`, `Low`, or `Informational`. Keep it aligned with the strongest verified oracle; renderers may localize the displayed report label.
- Keep `finding.bug_class` and `impact_tier.bug_class` as free text because vulnerability classes are open-ended. The recommended bug classes include `SSRF`, `Path Traversal`, `Prototype Pollution`, `Command Injection`, `Deserialization`, `Authentication Bypass`, `Authorization Bypass`, `Information Disclosure`, and `Denial of Service`; project-specific or compound labels are acceptable when they are clearer.
- For `fixture_provenance.required=false` with `replay_type=full_app`, omit empty optional provenance detail fields. For callback-only SSRF, omit empty `impact_tier.ssrf.artifact_backed_oracle`; add that object only for stronger artifact-backed exposure tiers.
- Run `python3 scripts/validate_bundle_contract.py --workspace-dir <audit-workspace> --contract <contract> --all-errors`.
- Treat contract preflight as a workflow gate only. It does not prove a vulnerability.
- Fix the contract or the upstream Docker evidence when preflight fails; do not patch final bundle artifacts reactively.
- Do not hand-create final `confirmed/<slug>/` directories.
- Run `python3 scripts/build_confirmed_bundle.py --workspace-dir <audit-workspace> --contract <contract> --language <zh-CN|en-US>`.
- Let the wrapper render into `confirmed/.staging/<slug>`, validate the staging bundle, promote only after validation passes, and run batch validation.
- Failed builds stay under `confirmed/.staging/` and must not be called confirmed deliverables.
- Do not create marker-only replay logs. Replay logs must come from the reviewer helper path and be registered in evidence.
- Registered replay logs must be real transcripts with command/output/oracle
  evidence. Do not manually append direct-impact markers to placeholder or thin
  logs.
- Use `assets/fixtures/replay-transcript-corpus/` as the replay transcript corpus
  for positive and negative trust-boundary examples. Real transcripts do
  not need one single rigid log format, but marker-only, placeholder-only, thin
  explanatory logs, and copied transcripts without provenance are rejected.
- Copied successful replay transcripts require provenance in
  `bundle-build-manifest.json` or reviewer-facing evidence. The wrapper does not
  run replay by default; it validates bundled evidence and final replay-log
  trust checks.
- Do not patch the direct-impact marker in one file to silence drift; keep the marker aligned across helper, log, evidence JSON, and reviewer material.
- Run final confirmed bundle validation after generation. Contract preflight does not replace `validate_report_bundle.py` or `validate_all_report_bundles.py`.
- If staging or final validation fails, use `validate_report_bundle.py --bundle-dir <bundle> --all-errors --json --output-errors <bundle>/bundle-validation-errors.json` only to diagnose multiple actionable issues. Default validation remains fail-fast; all-errors reports do not repair bundles or confirm vulnerabilities.
- After promote, run seeded variant discovery only from a `confirmed/<bundle>/` directory that passes `validate_report_bundle.py`, then run finalization. Candidate output from seeded variant discovery remains candidate-only until independently Docker-confirmed and bundle-validated.
