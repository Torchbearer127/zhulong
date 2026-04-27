# Contributing

## Principles

- Keep PoC execution Docker-only.
- Keep report generation deterministic.
- Keep optional tools optional.
- Prefer adding runtime detection over hardcoded assumptions.
- Do not turn third-party MCP servers into mandatory dependencies.

## Before Opening A Change

1. Keep the plugin self-contained.
2. Avoid introducing machine-specific paths.
3. Update the reference docs if workflow behavior changes.
4. Run the plugin self-test:

```bash
python3 scripts/selftest_plugin.py
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
