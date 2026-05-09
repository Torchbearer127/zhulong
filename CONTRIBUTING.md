# Contributing

## Principles

- Keep PoC execution Docker-only.
- Keep confirmed vulnerability reporting evidence-backed and bundle-validated.
- Keep report generation deterministic.
- Keep optional tools optional.
- Prefer adding runtime detection over hardcoded assumptions.
- Do not turn third-party MCP servers into mandatory dependencies.
- Do not reintroduce plugin-owned teammate PID signaling, broad process cleanup,
  or broad Docker prune.
- Do not treat Zhulong as only a scanner. It is a security-focused code audit
  workflow that separates confirmed vulnerabilities, candidates, false
  positives, non-security defects, hardening-only observations, and unverified
  leads.

## Before Opening A Change

1. Keep the plugin self-contained.
2. Avoid introducing machine-specific paths.
3. Update the reference docs if workflow behavior changes.
4. Run the plugin self-test:

```bash
python3 scripts/selftest_plugin.py
```

5. If the change affects installed skill content, sync and test the installed
   copy:

```bash
bash scripts/sync_to_claude_skill.sh
python3 ~/.claude/skills/zhulong/scripts/selftest_plugin.py
```

## When Adding New Security Tooling

- Add the tool to `assets/tool-registry.json`.
- Update `scripts/check_security_tooling.sh` if the tool should be detected at runtime.
- Update `scripts/plan_security_toolchain.py` if the tool changes selection logic.
- Document whether the tool is:
  - first-tier
  - second-tier
  - MCP hardening
  - document QA

## When Changing Report Output

- Update the renderer and the validators together.
- Preserve the fixed confirmed-bundle layout.
- Validate with:

```bash
python3 scripts/validate_report_bundle.py --bundle-dir <bundle>
python3 scripts/validate_all_report_bundles.py --confirmed-dir <confirmed-dir>
```

## When Changing Docker Or Runtime Hygiene

- Keep Docker residue separate from OMC runtime residue.
- Treat suspect OMC teammate PIDs as review-only inside Zhulong.
- Never use Docker-wide prune commands as a normal cleanup path. If BuildKit
  cache cleanup is ever needed, scope it to one reviewed cache ID.
- Do not overwrite an existing Docker baseline after verification resources have
  been created; late recapture can hide residue from strict cleanliness checks.
- If exact adoption is needed, require exact image refs, network names, volume
  names, or BuildKit cache IDs. Do not add wildcard, prefix, regex, or "all"
  adoption semantics.

## Before Publishing

Run `docs/RELEASE_CHECKLIST.md` from the plugin root. Do not publish a tagged release
with unresolved High/Medium workflow defects in confirmed-only, Docker-first,
Docker cleanup, sandbox preflight, OMC PID safety, finalization, or bundle
validation.
