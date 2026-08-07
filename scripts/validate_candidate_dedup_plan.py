#!/usr/bin/env python3
"""Recompute and validate an advisory candidate deduplication plan."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from candidate_dedup import DedupError, derive_plan, load_inventory
from candidate_identity import canonical_json_bytes


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate and independently recompute a candidate deduplication plan.")
    parser.add_argument("--repo-root", required=True); parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--plan", required=True); parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        workspace = Path(args.workspace_dir).resolve(strict=True); plan_path = Path(args.plan).resolve(strict=True)
        try: plan_path.relative_to(workspace)
        except ValueError as exc: raise DedupError("plan must stay inside workspace-dir") from exc
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        if not isinstance(plan, dict) or plan.get("authority") != "candidate_advisory_only": raise DedupError("plan schema or authority boundary is invalid")
        inventory_binding = plan.get("inventory") if isinstance(plan.get("inventory"), dict) else {}
        inventory_path = workspace.joinpath(*str(inventory_binding.get("path", "")).split("/"))
        inventory, candidates = load_inventory(Path(args.repo_root), workspace, inventory_path)
        expected = derive_plan(inventory, candidates)
        if canonical_json_bytes(plan) != canonical_json_bytes(expected): raise DedupError("plan is stale, forged, non-canonical, or inconsistent with candidate/source facts")
        payload = {"ok": True, "plan_id": plan["plan_id"], "classification_count": len(plan["classifications"]), "authority": plan["authority"]}
    except (DedupError, OSError, json.JSONDecodeError) as exc:
        payload = {"ok": False, "error": str(exc)}
        if args.json: print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else: print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if args.json: print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else: print(f"OK: candidate dedup plan valid; plan_id={plan['plan_id']} authority=candidate_advisory_only")


if __name__ == "__main__": main()
