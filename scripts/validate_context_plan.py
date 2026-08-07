#!/usr/bin/env python3
"""Offline, read-only validation for deterministic advisory context plans."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from typing import Any
from context_catalog import BUG_CLASSES, NON_CLAIMS, STACKS, SURFACES, Issue, add, canonical_digest, load_json, load_validated_catalog, schema_errors
from plan_audit_context import build_plan

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a Context Plan against a local Context Catalog.")
    parser.add_argument("--skill-root", required=True); parser.add_argument("--catalog", required=True); parser.add_argument("--plan", required=True); parser.add_argument("--schema"); parser.add_argument("--json", action="store_true")
    args = parser.parse_args(); root = Path(args.skill_root).expanduser().resolve(); catalog_path = Path(args.catalog).expanduser(); plan_path = Path(args.plan).expanduser(); catalog_schema = root / "assets/schemas/context-catalog.schema.json"; plan_schema = Path(args.schema).expanduser() if args.schema else root / "assets/schemas/context-plan.schema.json"
    catalog, issues = load_validated_catalog(root, catalog_path, catalog_schema); plan, error = load_json(plan_path); schema, schema_error = load_json(plan_schema)
    if error: add(issues, "CONTEXT_PLAN_JSON_INVALID", "$", "Plan JSON cannot be read.")
    if schema_error or not isinstance(schema, dict): add(issues, "CONTEXT_PLAN_SCHEMA_UNAVAILABLE", "$", "Plan schema cannot be read.")
    if isinstance(plan, dict) and isinstance(schema, dict):
        for path, message in schema_errors(plan, schema, schema): add(issues, "CONTEXT_PLAN_SCHEMA_INVALID", path, message)
    elif not error: add(issues, "CONTEXT_PLAN_SCHEMA_INVALID", "$", "Plan must be an object.")
    if catalog and isinstance(plan, dict):
        facts = plan.get("input_facts")
        if not isinstance(facts, dict): facts = {}
        for key, allowed in (("detected_stack", STACKS), ("attack_surface_hints", SURFACES), ("bug_classes", BUG_CLASSES)):
            values = facts.get(key, [])
            if not isinstance(values, list) or any(value not in allowed for value in values):
                add(issues, "CONTEXT_PLAN_INPUT_FACT_UNKNOWN", f"$.input_facts.{key}", "Plan input facts must use the closed planner vocabulary.")
        expected = build_plan(catalog, str(plan.get("phase", "")), facts) if isinstance(plan.get("phase"), str) else None
        if plan.get("authority") != "recommended_context_only": add(issues, "CONTEXT_PLAN_AUTHORITY_INVALID", "$.authority", "Plan authority must be recommendation-only.")
        if plan.get("catalog", {}).get("digest") != canonical_digest(catalog): add(issues, "CONTEXT_PLAN_CATALOG_DRIFT", "$.catalog.digest", "Plan catalog digest does not bind the validated catalog.")
        if plan.get("catalog", {}).get("id") != catalog.get("catalog_id") or plan.get("catalog", {}).get("version") != catalog.get("catalog_version"):
            add(issues, "CONTEXT_PLAN_CATALOG_DRIFT", "$.catalog", "Plan catalog identity does not bind the validated catalog.")
        if plan.get("non_claims") != NON_CLAIMS: add(issues, "CONTEXT_PLAN_NON_CLAIMS_INVALID", "$.non_claims", "Plan must retain the complete fixed non-claims.")
        if expected is not None:
            for group in ("mandatory", "optional", "deferred"):
                actual = plan.get(group)
                if actual != expected[group]: add(issues, "CONTEXT_PLAN_SELECTION_INVALID", f"$.{group}", "Plan group, selector reasons, or canonical ordering differs from catalog rules.")
            all_ids = [entry.get("id") for group in ("mandatory", "optional", "deferred") for entry in plan.get(group, []) if isinstance(entry, dict)]
            if len(all_ids) != len(set(all_ids)): add(issues, "CONTEXT_PLAN_MODULE_DUPLICATE", "$", "A module may appear in only one plan group.")
    payload = {"ok": not issues, "authority": "recommended_context_only", "issue_codes": [issue.code for issue in issues], "issues": [issue.as_dict() for issue in issues]}
    if args.json: print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else: print("Context Plan valid." if not issues else "Context Plan invalid: " + ", ".join(payload["issue_codes"]))
    return 0 if not issues else 1
if __name__ == "__main__": raise SystemExit(main())
