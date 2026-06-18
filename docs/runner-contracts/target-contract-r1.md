# Zhulong Target Contract R1

`zhulong-target.yaml` is a small structured input file for a Zhulong audit. It
records how the target is built, started, checked for readiness, verified,
cleaned up, and scoped before candidates are promoted into later verification
protocols.

The contract solves a practical handoff problem: an agent should not guess the
target runtime, Compose service, cleanup command, attacker entrypoints, trust
boundaries, or in-scope bug classes from chat history. Those decisions belong in
a portable file that can be validated before any candidate or PoC work begins.

This does not change confirmed bundle rules. A target contract is not evidence,
does not confirm a vulnerability, and does not weaken the existing
`confirmed/` contract. Confirmed findings still require Docker or Docker Compose
reproduction evidence and a valid self-contained confirmed bundle.

## Runtime Types

`runtime.type` is one of:

- `docker-compose`: the target runs through Docker Compose. The contract must
  name `runtime.compose_file` and `runtime.service`.
- `docker`: the target runs through explicit Docker commands. Build, start,
  readiness, verification oracle, and cleanup commands must be declared.
- `manual-blocked`: the target cannot currently be verified by an automatic
  Docker verifier. The contract can still document scope, but later verifier
  protocols must treat it as non-confirmable until the runtime is made
  Docker-verifiable.

For Docker-backed runtimes, commands are declarative input only. The validator
checks that commands are explicit and rejects unsafe patterns, but it never
executes them.

## Scope Fields

Use `scope.entrypoints` for attacker-reachable inputs. Each entrypoint should
include a stable `id`, a `kind`, the route or API shape, the expected auth
level, and attacker-controlled fields. Empty `entrypoints: []` is accepted for
early reconnaissance, but validation marks `recon_incomplete=true`.

Use `scope.trust_boundaries` for concise source-to-sink boundaries such as
`external HTTP request -> backend import worker`. Use
`scope.in_scope_bug_classes` and `scope.out_of_scope` to keep the audit focused
and avoid re-litigating administrator-only or host-shell assumptions later.

## Validation

Validate a target contract locally:

```bash
python3 scripts/validate_target_contract.py path/to/zhulong-target.yaml
```

Successful validation prints a single `OK` line with `runtime_type`,
`confirmable`, `non_confirmable`, and `recon_incomplete` markers. Failures exit
nonzero with an actionable error. The validator rejects missing required fields,
unsupported runtime types, local absolute paths, parent path traversal, broad
Docker prune commands, dangerous PID kill patterns, privileged containers, host
networking, Docker socket mounts, and credential mount patterns.

## Future Use

R1 only defines the target contract. Later candidate and verifier protocols can
reference this file so candidate claims, verification verdicts, and disposition
promotion all agree on the same runtime and scope.

Finding Contract R1 is documented in
[`finding-contract-r1.md`](finding-contract-r1.md).

## Non-Goals

This contract is not an autonomous runner, multi-agent parallelism layer,
patch/re-attack loop, hosted backend, queue, scheduler, dashboard, database,
RAG system, vector store, MCP service, or confirmed bundle replacement.
