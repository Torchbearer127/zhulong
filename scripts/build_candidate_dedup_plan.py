#!/usr/bin/env python3
"""Build one deterministic advisory candidate deduplication plan."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from candidate_dedup import DedupError, derive_plan, load_inventory
from candidate_identity import IdentityError, atomic_publish, pretty_json_bytes


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an advisory Candidate R2 deduplication plan.")
    parser.add_argument("--repo-root", required=True); parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--inventory", required=True); parser.add_argument("--output", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        workspace = Path(args.workspace_dir).resolve(strict=True)
        output = Path(args.output).resolve()
        try: output.relative_to(workspace)
        except ValueError as exc: raise DedupError("output must stay inside workspace-dir") from exc
        inventory, candidates = load_inventory(Path(args.repo_root), workspace, Path(args.inventory))
        plan = derive_plan(inventory, candidates)
        checked_inventory, checked_candidates = load_inventory(Path(args.repo_root), workspace, Path(args.inventory))
        if pretty_json_bytes(derive_plan(checked_inventory, checked_candidates)) != pretty_json_bytes(plan):
            raise DedupError("inventory or candidate inputs drifted during plan generation")
        status = atomic_publish(output, pretty_json_bytes(plan))
        payload = {"ok": True, "plan_id": plan["plan_id"], "output_status": status, "classification_count": len(plan["classifications"]), "authority": plan["authority"]}
    except (DedupError, IdentityError, OSError) as exc:
        payload = {"ok": False, "error": str(exc)}
        if args.json: print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else: print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if args.json: print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else: print(f"OK: advisory dedup plan built; plan_id={plan['plan_id']} output={status}")


if __name__ == "__main__": main()
