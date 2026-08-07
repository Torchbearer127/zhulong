# Root Skill Kernel Contract R1

## Purpose

The root `SKILL.md` is a small, always-loaded safety kernel. Operational detail
is carried by phase-scoped references, while production schema, validators,
gates, and fixed wrappers remain authoritative.

This split does not create a runner, scheduler, service, database, RAG layer,
MCP server, hook system, rules engine, or Agent runtime.

## Authority

`assets/root-skill-rule-inventory.json` is the only authoritative rule-carrier
inventory. Its schema is
`assets/schemas/root-skill-rule-inventory.schema.json`; the offline, read-only
validator is `scripts/validate_root_skill_rule_inventory.py`.

The inventory records stable rule identity, original semantic scope, class,
disposition, target section, all carriers, migration rationale, and residual
boundary. It does not itself enforce a production security decision.

## Validation rules

- Paths are safe relative POSIX paths under the Skill root.
- Carriers must exist as regular, non-symlink files and resolve inside the root.
- Rule IDs are unique and carriers are non-empty.
- Production carriers name a symbol, CLI, field, or issue code that is present
  in the declared file.
- `retain_kernel` requires a `root_kernel` carrier and targets the source
  `SKILL.md`.
- `move_to_reference` requires a reference carrier whose path is registered in
  the context catalog.
- A moved `hard_constraint` requires a production schema, validator, gate, or
  fixed wrapper. Docs, references, inventory, and selftests are not production
  authority.

Validation is deterministic, offline, and read-only. It never rewrites the
inventory, Skill, references, catalog, or carriers.

## Kernel invariants

The kernel retains concise invariants for Docker-only execution, candidate-only
analysis, the complete confirmation path, blocked-not-complete behavior, exact
source and fixture boundaries, unsafe sandbox rejection, cleanup/PID safety,
separate severity and variant passes, independent variant confirmation,
contract-first bundle promotion, canonical finalization, opt-in recording,
derived-context non-authority, and bundle portability.

Removing any invariant, changing its inventory target, or reducing a moved hard
rule to docs/reference/selftest-only must fail the relationship selftest.

## Phase references

The stable phase references cover:

- intake and Recon;
- candidate and triage;
- verification and severity;
- seeded variant discovery;
- packaging and finalization;
- opt-in recording;
- cross-phase continuation and state.

Each is registered as a baseline context module for the applicable existing
phase vocabulary. No new context-plan phase is introduced for triage or
recording: triage is represented by `candidate_generation`, while recording is
a post-bundle protocol selected with `finalization`. This preserves the context
plan schema and state protocol vocabulary.

Catalog `mandatory` means deterministic reading priority only. A plan never
proves that an Agent read, understood, applied, or completed a reference and
never grants execution, evidence, confirmation, promotion, recording, or
finalization authority.

## Maintenance

When a root rule changes:

1. update its inventory record;
2. retain it in the kernel unless a real production carrier exists;
3. update the phase reference without duplicating full contracts;
4. register moved operational guidance in the context catalog;
5. run inventory mutation tests, context fixture goldens, source/Claude/Codex
   byte comparisons, and the full plugin selftest.

Measure root lines, bytes, Unicode characters, and whitespace-split words
directly. Phase-reference line counts are separate transparency metrics and
must not be presented as reduced total documentation or measured token/cost
savings.
