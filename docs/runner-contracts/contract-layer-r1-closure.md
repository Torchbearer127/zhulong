# Zhulong Contract Layer R1 Closure

Contract Layer R1 closes the pre-confirmation state machine that starts with a
target contract and ends with a candidate disposition:

```text
zhulong-target.yaml
  -> candidate.json
  -> verifier-verdict.json
  -> audit-disposition.json
```

## Coverage

- ZC-001 defines `zhulong-target.yaml`, including runtime type, explicit
  build/start/verify/cleanup declarations, scope, entrypoints, trust
  boundaries, and `manual-blocked` handling.
- ZC-002 defines `candidate.json` and `verifier-verdict.json`. A candidate is
  claim-only; only a valid verifier verdict can recommend
  `confirmed_in_docker`.
- ZC-003 adds the minimal independent verifier contract path. It validates the
  target and candidate and writes a verifier verdict without discovering new
  candidates or promoting dispositions.
- ZC-004 connects valid verifier verdicts to `audit-disposition.json` while
  keeping candidate-only and finder-note material at candidate status.
- ZC-005 locks the cross-step fixture chain with four fixed contract fixtures
  and selftests.

## Fixture States

The fixed fixture matrix lives under `assets/fixtures/contracts/` so it is
available in both source and installed skill layouts:

- `confirmed_ssrf`: valid target, valid candidate, valid verifier verdict, and
  disposition status `confirmed_in_docker`.
- `false_positive_unreachable`: valid contracts with a verifier verdict that
  rejects the claim as unreachable, mapping to `false_positive`.
- `unverified_oracle_weak`: valid contracts with a weak oracle result that does
  not prove impact, mapping to `unverified`.
- `blocked_manual_runtime`: a `manual-blocked` target with unsupported automatic
  verification, mapping to `blocked`.

## Boundaries

This is not an autonomous runner. It does not discover candidates, spawn find
agents, schedule parallel work, execute Docker, execute PoCs, replay attacks,
generate patches, run a re-attack loop, create confirmed bundles, render DOCX,
open issues, or provide a hosted backend, queue, dashboard, database, vector
store, RAG service, daemon, scheduler, MCP service, hook, or runtime dependency.

Future ZR runner work should consume these contracts as stable inputs and
outputs. It should orchestrate the target, candidate, verifier, and disposition
steps without replacing their validators or weakening the promotion rules.

Confirmed bundle validation remains separate and required. A
`confirmed_in_docker` candidate disposition is not a completed deliverable until
the normal one-folder-per-vulnerability confirmed bundle contract and
`validate_report_bundle.py`/`validate_all_report_bundles.py` gates pass.

No Docker, PoC, replay, scanner, network, GitHub, package registry, or LLM
execution happens in contract selftests. The fixtures are inert JSON/YAML
protocol inputs used only by validators and `audit_disposition.py`.
