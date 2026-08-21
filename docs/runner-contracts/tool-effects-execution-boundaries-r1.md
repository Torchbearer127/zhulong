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
The schema's lifecycle-stage enum is not a second authority: the production
registry validator requires it to match `audit_transition_policy.STAGES`
exactly, including order, and reports `TOOL_REGISTRY_STAGE_SCHEMA_DRIFT` on
deletion, rename, reorder, addition, or malformed enum shape.

`host_cache_write` is explicit. Tools that may download a database, contact a
package registry, or write a host cache must not be described as
host-read-only. Evidence output families are restricted to safe
workspace-relative `evidence/` or `runtime/` paths.

`isolation_required` is also explicit. A tool with that boundary has
`target_code_execute`, `planner_status=requires_isolation`,
`failure_policy=skipped_requires_isolation`, no controlled wrapper, and no
confirmation authority. The validator rejects an active status, a missing
target-code effect, a fabricated wrapper, or Docker authority on such an
entry. Until a separately audited fixed Docker wrapper exists, the planner may
describe the skip but must not emit an equivalent host command hint.

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
| Maven/Gradle project evaluation and target-configurable plugin loading | `skipped_requires_isolation` | never on the host; no raw replacement hint | none |
| Docker verification | wrapper-required | `run_verification_case.sh` only, with sandbox preflight and mandatory timeout | Docker oracle material only |
| Raw Docker CLI and uncontrolled live-target/DAST tooling | prohibited or planning-only | no direct command hint | none or candidate-only metadata only |
| Documentation QA and source inspection | planning-only or host-read-only | no confirmation path | none |

`run_initial_probes.sh` checks its declared `recon` use before writing probe
output. Its output stays in workspace evidence and is candidate material only.
Maven POM/plugin/lifecycle evaluation, Gradle wrapper/settings/build/plugin
evaluation, and target-configurable golangci-lint plugin loading are recorded
as `skipped_requires_isolation`; the status is not success and does not permit
an Agent or operator to run the omitted command manually on the host. The
remaining probes read source or package metadata through the fixed wrapper;
their declared external-network and host-cache effects remain explicit, npm
uses `--ignore-scripts`, and Go package loading uses `-mod=readonly`.
`run_verification_case.sh` checks its declared Docker use before creating case
evidence or contacting Docker. `confirmed_in_docker` remains evidence labeling;
it does not bypass the existing verifier verdict, disposition, or bundle
validation gates.

The verification wrapper is also a file-ownership boundary. Before evidence or
Docker access it resolves Compose inputs from the workspace (not caller CWD),
rejects unsafe file types and paths, and copies the ordered bytes into a fresh
private snapshot set with a digest/identity manifest. Preflight and every
`docker compose config`, pull, and run use only those snapshots with the
workspace as explicit project directory; identity drift aborts before the
service command, and the one-use set is cleaned without reuse.

The supported Compose subset is deliberately closed: top level contains only
`version` and `services`; every service is a static mapping with literal
`privileged: false`; unknown, build/host-file/include, namespace,
capability/device/security-option, interpolation, anchor/alias/merge, and
named/anonymous/external-volume forms are rejected. Host binds are limited to
the target repository at `/workspace/target` read-only and workspace `poc/` at
`/workspace/poc` read-only. The current case's `/workspace/output` is a fixed
64 MiB container tmpfs used only as non-authoritative scratch; new executions
do not import container files or create `container-output`. Historical bundles
remain readable. The selected service must use the exact `logging.driver=none`
policy, and the wrapper starts one foreground command with an explicit argv.
Other host paths are rejected even when read-only.

The bind check retains the source's logical spelling until the closed-set
comparison is complete; it does not compare only resolved targets. Existing
components are checked with `lstat` as real directories, bootstrap rejects
pre-existing unsafe directory entries before writing, and the wrapper repeats
the identity check before every Compose config, pull, and run. Stable identity
for every existing component (device, inode, type, mode, uid, and gid) is kept
separate from leaf mtime and link-count observations. Stable drift always
rejects; target and `poc/` observations remain strict, while ordinary writes to
the container tmpfs remain non-authoritative.
This is an explicit revalidation boundary under a trusted workspace-owner
assumption, not an atomic host-path pin or an OS-level TOCTOU guarantee.

The wrapper rejects unknown Docker run flags, keeps evidence read-only inside
the container, and exposes only the bounded tmpfs output. Host stdout/stderr
capture is continuously streamed through host-owned descriptors and terminates
the Docker process group at the 16 MiB per-stream limit; it is fail-closed on
symlinks,
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
