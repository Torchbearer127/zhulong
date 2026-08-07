#!/usr/bin/env python3
"""Read-only validation of next-actions.json against current authority."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from next_actions import validate_next_actions_current

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__); p.add_argument("--workspace-dir", required=True); p.add_argument("--repo-root", required=True); p.add_argument("--json", action="store_true", dest="as_json"); a = p.parse_args()
    result = validate_next_actions_current(Path(a.workspace_dir).expanduser().absolute(), Path(a.repo_root).expanduser().absolute())
    if a.as_json or not result["ok"]: print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else: print("next-actions.json is current")
    return 0 if result["ok"] else 1
if __name__ == "__main__": raise SystemExit(main())
