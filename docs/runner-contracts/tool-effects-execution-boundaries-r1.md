# Tool Effects and Execution Boundaries Contract

`assets/tool-registry.json` is the R2 declaration used by Zhulong's dynamic
planner, offline registry validator, and the narrow wrappers that are named in
the registry. Its strict schema is
`assets/schemas/tool-registry.schema.json`; both files are copied into every
new audit workspace so the workspace planner and wrappers validate the same
snapshot.

## Scope and non-authority

This is a Zhulong-local contract. It does not sandbox, intercept, approve, or
disable native tool calls made by Claude Code, Codex, another Agent, or a human.
It only makes Zhulong's own planning and controlled entrypoints fail closed
when their declared metadata is malformed or their declared use is forbidden.

Registry validation is offline, deterministic, and read-only. A successful
validation means only that metadata is internally consistent. It does not run a
tool, create a candidate, issue a verifier verdict, update a disposition, or
confirm a vulnerability.

## Registry vocabulary

Every tool has one globally unique name and one tier. The registry owns its
role, allowed audit stages, execution boundaries, effects, network scope,
concurrency and timeout policies, failure behavior, workspace evidence output
families, confirmation authority, controlled-wrapper path, and availability
aliases. Unknown root, tier, tool, wrapper, and evidence fields are rejected.

`host_cache_write` is explicit. Tools that may download a database, contact a
package registry, or write a host cache must not be described as
host-read-only. Evidence output families are restricted to safe
workspace-relative `evidence/` or `runtime/` paths.

A `prohibited` tool is metadata only: its only boundary is `prohibited`, it has
no active effects or wrapper, and its authority is `none`. The validator also
rejects duplicate names, wrapper URI/absolute/traversal paths, symlinks,
directories, missing static markers, missing evidence output declarations, and
unimplemented mandatory-timeout claims.

The `prohibited` boundary is exclusive, not advisory. Such an entry must have
an empty effects list, no wrapper, no authority, no network scope, and a
`planner_status` of `prohibited` (or an explicitly inactive equivalent). Any
active effect, wrapper, authority, network declaration, or contradictory
planner status is rejected with a stable issue code before a planner can
produce an invocation hint. This rule is checked for both the source registry
and every installed layout.

External-network declarations are bidirectional: the `external_network`
boundary, an external `network_scope`, and the `external_network_access` effect
must appear together. An active DAST declaration must instead provide either
that complete external-network contract or an explicit `local_target_only` plus
`local_target_access` contract. DAST entries without either contract fail
closed even when they have a controlled wrapper.

## Execution and authority matrix

| Tool family | Planner outcome | Invocation rule | Authority |
| --- | --- | --- | --- |
| First-pass scanner, SAST, dependency, SBOM, and secret tools | available/unavailable metadata; wrapper-required when selected | `run_initial_probes.sh` only | candidate-only at most |
| Docker verification | wrapper-required | `run_verification_case.sh` only, with sandbox preflight and mandatory timeout | Docker oracle material only |
| Raw Docker CLI and uncontrolled live-target/DAST tooling | prohibited or planning-only | no direct command hint | none or candidate-only metadata only |
| Documentation QA and source inspection | planning-only or host-read-only | no confirmation path | none |

`run_initial_probes.sh` checks its declared `recon` use before writing probe
output. Its output stays in workspace evidence and is candidate material only.
`run_verification_case.sh` checks its declared Docker use before creating case
evidence or contacting Docker. `confirmed_in_docker` remains evidence labeling;
it does not bypass the existing verifier verdict, disposition, or bundle
validation gates.

The verification wrapper is also a file-ownership boundary. It performs the
sandbox preflight before creating case evidence, rejects dynamic or unsafe
Compose controls and unknown Docker run flags, keeps evidence read-only inside
the container, and exposes only a separate writable output directory. Host
stdout/stderr capture is descriptor-backed and fail-closed on symlinks,
hard-links, FIFOs, directories, replaced ancestors, or result-path swaps.
Runtime cleanliness is a strict, fresh evidence object whose digest and
workspace identity are repeated by the finalization event; a path alone never
proves Docker cleanup.

`prepare_target_repo.sh` has separate intake/preparation behavior that can
touch a remote or a target checkout. It is deliberately not a planner-selected
tool and receives no automatic execution authorization from this contract.

## Validation interface

Run the full metadata check with:

```bash
python3 scripts/validate_tool_registry.py \
  --skill-root <skill-or-workspace-root> \
  --registry <tool-registry.json> \
  --schema <tool-registry.schema.json> \
  --json
```

Use `--tool`, `--stage`, `--boundary`, and `--effect` for a wrapper's
declared-use check. The JSON issue codes are stable integration output and are
not vulnerability findings.
