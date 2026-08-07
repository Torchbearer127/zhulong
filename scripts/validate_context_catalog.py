#!/usr/bin/env python3
"""Offline, read-only validation for the advisory Zhulong Context Catalog."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from context_catalog import load_validated_catalog

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the advisory Context Catalog without reading its references.")
    parser.add_argument("--skill-root", required=True); parser.add_argument("--catalog", required=True); parser.add_argument("--schema"); parser.add_argument("--json", action="store_true")
    args = parser.parse_args(); root = Path(args.skill_root).expanduser().resolve(); catalog = Path(args.catalog).expanduser(); schema = Path(args.schema).expanduser() if args.schema else root / "assets/schemas/context-catalog.schema.json"
    value, issues = load_validated_catalog(root, catalog, schema)
    payload = {"ok": not issues, "authority": "recommended_context_only", "module_count": len(value.get("modules", [])) if value else 0, "issue_codes": [item.code for item in issues], "issues": [item.as_dict() for item in issues]}
    if args.json: print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else: print("Context Catalog valid." if not issues else "Context Catalog invalid: " + ", ".join(payload["issue_codes"]))
    return 0 if not issues else 1
if __name__ == "__main__": raise SystemExit(main())
