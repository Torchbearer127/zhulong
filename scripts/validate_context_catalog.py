#!/usr/bin/env python3
"""Offline, read-only validation for the advisory Zhulong Context Catalog."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from audit_transition_policy import STAGES
from context_catalog import add, load_validated_catalog

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the advisory Context Catalog without reading its references.")
    parser.add_argument("--skill-root", required=True); parser.add_argument("--catalog", required=True); parser.add_argument("--schema"); parser.add_argument("--json", action="store_true")
    args = parser.parse_args(); root = Path(args.skill_root).expanduser().resolve(); catalog = Path(args.catalog).expanduser(); schema = Path(args.schema).expanduser() if args.schema else root / "assets/schemas/context-catalog.schema.json"
    value, issues = load_validated_catalog(root, catalog, schema)
    try:
        from plan_audit_context import planner_phase_choices

        choices = planner_phase_choices()
    except Exception:
        choices = ()
    if choices != STAGES:
        add(
            issues,
            "CONTEXT_PLANNER_PHASE_CHOICES_DRIFT",
            "scripts/plan_audit_context.py:--phase",
            "Planner phase choices must exactly match audit_transition_policy.STAGES.",
        )
        value = None
    payload = {"ok": not issues, "authority": "recommended_context_only", "module_count": len(value.get("modules", [])) if value else 0, "issue_codes": [item.code for item in issues], "issues": [item.as_dict() for item in issues]}
    if args.json: print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else: print("Context Catalog valid." if not issues else "Context Catalog invalid: " + ", ".join(payload["issue_codes"]))
    return 0 if not issues else 1
if __name__ == "__main__": raise SystemExit(main())
