# Context Planning Contract R1

## Scope

`context-catalog.json` is the sole shipped declaration of stable local audit references. `plan_audit_context.py` produces a deterministic `context-plan.json` from a requested phase, explicit bug classes, and existing local stack and attack-surface detection. The planner never opens catalogued references, user notes, handoff narratives, candidates, or workspace evidence.

The plan is recommendation-only. It does not prove that an Agent read, understood, followed, applied, or completed a reference. It does not execute a tool or reference, create evidence, confirm a finding, or replace a validator, gate, or root Skill constraint.

## Facts and selection

The planner reuses `detect_stack()` and `detect_attack_surface()` from `plan_security_toolchain.py`. `--bug-class` is an explicit closed input. A catalogue module is mandatory only when it is a phase baseline. That label means recommended reading priority in this plan, not a security gate. Conditional modules are optional when an exact declared selector matches; values inside one selector dimension are alternatives. Phase-relevant conditional modules without a match are deferred. Modules for other phases are omitted.

Sorting uses module ID and path only. The serialized plan contains no target, workspace, or Skill-root absolute path. It binds the catalog ID, version, and a canonical SHA-256 digest.

## Path and maintenance boundary

The catalog validator accepts only regular, non-symlink files below `assets/references/` in the selected Skill root. It rejects absolute paths, URIs, backslashes, traversal, directories, missing files, duplicate IDs and paths, unknown selectors, and authority drift. It also rejects basenames with the independent `dogfood` marker, `-template.md` / `-template.json` suffixes, or a `.example.json` suffix; these name categories reserve dogfood artifacts, machine-input templates, and examples outside the catalog's stable reading scope. The stable `CONTEXT_REFERENCE_SCOPE_FORBIDDEN` issue code identifies that closed scope gate. New stable references may be registered when they do not use one of those reserved naming categories; absence from the current catalog is not itself a forbidden category. Diagnostics are stable issue codes and do not disclose machine-local paths.

Maintain the catalog, its strict schema, production validators, fixture matrix, and this contract together. New catalog modules must be stable user-facing references, not scripts, schemas, fixtures, prompts, machine inputs, bundles, or local artifacts. The catalog's non-authority statement is one fixed declaration, validated exactly by both schema and production validator; it is not a keyword blacklist. The `stacks` selector is a supported reserved capability even though the current shipped catalog has no stack-only module; do not add a broad stack selector to an unsuitable playbook merely to exercise it. The shared PHP attack-surface detector remains outside this catalog contract. Output publication currently rejects a symlink output path and a symlink direct parent; it does not claim ancestor-symlink rejection on every platform. The validator is read-only; the planner only writes an explicit output path atomically and refuses an existing output unless `--overwrite` is explicit.
