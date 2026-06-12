# Variant Seed Card Template

Purpose: capture a confirmed vulnerability as a root-cause-oriented seed for
same-repository variant discovery. A seed card is auxiliary evidence only. It is
not a confirmed vulnerability, cannot confirm variants, and never replaces
`verification-evidence.json`, findings JSON, DOCX reports, reproduction
supplements, attachment indexes, replay logs, Docker evidence, or confirmed
bundle validation.

Intended future workspace location:

```text
<audit-workspace>/evidence/variant-analysis/
├── seeds.jsonl
├── variant-candidates.jsonl
├── variant-expansion-summary.json
└── seed-<slug>.md
```

## JSONL Example

```jsonl
{"schema_version":1,"seed_id":"seed-confirmed-ssrf-import-url","confirmed_bundle_path":"confirmed/ssrf-import-url","bug_class":"SSRF","root_cause":"Server-side import flow trusted an attacker-controlled URL before enforcing private-network deny rules.","source_pattern":"Authenticated attacker controls the import URL submitted through the import API request body.","propagation_pattern":"Request body URL is passed through the import service to the server-side fetch helper without canonical host revalidation.","sink_pattern":"Server-side HTTP fetch/open-url helper that can reach internal or metadata-network targets.","missing_constraint_pattern":"Missing canonicalization and private-address denylist check immediately before the outbound fetch sink.","trigger_condition":"Import feature enabled; low-privilege authenticated user can submit imports; outbound network reachable from the service container.","docker_success_oracle":"Docker Compose replay observed the attacker-controlled callback and verification-evidence.json records verification_status=confirmed_in_docker.","search_scope":{"repository":"same-target-repository","default":"exclude generated outputs and confirmed bundles"},"negative_filters":["tests/","docs/","examples/","fixtures/","call sites with canonical host validation before fetch","admin-only maintenance code without attacker-controlled input"]}
```

## Draft Checklist

- Confirm the seed already has a valid confirmed bundle and Docker success
  oracle.
- Use a bundle-relative or workspace-relative `confirmed_bundle_path`; do not
  write local absolute paths, `file://` URLs, home directories, usernames, or
  sensitive historical report details.
- Describe `bug_class` as a label only; do not use it as the whole search
  strategy.
- Fill `root_cause`, `source_pattern`, `sink_pattern`, and
  `docker_success_oracle` before treating the card as final.
- Make `source_pattern` describe attacker control, not just a parameter or
  variable name.
- Make `sink_pattern` describe a sink family/API or dangerous behavior, not just
  a file path.
- Record the missing validation, authorization, canonicalization, bounds check,
  or equivalent constraint.
- Record trigger conditions such as auth, deployment mode, runtime, feature
  flag, or consumer pattern.
- Keep `search_scope` bounded to the same target repository by default.
- Use `negative_filters` for excluded directories, mitigated call sites,
  defensive patterns, or lower-priority contexts.

## Unknown Values

Draft cards may use `"unknown"` for non-final investigation notes, for example:

```jsonl
{"schema_version":1,"seed_id":"draft-seed","confirmed_bundle_path":"confirmed/example","bug_class":"path traversal","root_cause":"unknown","source_pattern":"Authenticated attacker controls the requested export path parameter.","propagation_pattern":"unknown","sink_pattern":"filesystem read/open path sink","missing_constraint_pattern":"unknown","trigger_condition":"unknown","docker_success_oracle":"Docker replay log shows the marker from verification-evidence.json.","search_scope":{"repository":"same-target-repository"},"negative_filters":[]}
```

A final seed card must not use `"unknown"` for `root_cause`, `source_pattern`,
`sink_pattern`, or `docker_success_oracle`. Any variant candidate produced from a
seed still needs independent Docker or Docker Compose reproduction and confirmed
bundle validation before it can be called confirmed.

## Candidate Output

`scripts/find_variant_candidates.py` writes auxiliary `variant-candidates.jsonl`
records from one final seed card. Finder output is ranking material only:
records must stay `status=candidate`, use repo-relative file paths, and require
independent Docker or Docker Compose verification before any confirmation
decision.

Validate this output with
`scripts/validate_report_bundle.py --variant-candidates <path>`. Candidate
records can guide follow-up verification, but they must not be copied into a
confirmed bundle or cited as confirmed evidence.
