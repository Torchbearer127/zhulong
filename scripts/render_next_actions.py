#!/usr/bin/env python3
"""Derive and atomically publish advisory-only next-actions.json."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from audit_state_io import AuditStateError
from next_actions import generate_next_actions

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__); p.add_argument("--workspace-dir", required=True); p.add_argument("--repo-root", required=True); p.add_argument("--json", action="store_true", dest="as_json"); a = p.parse_args()
    try:
        document = generate_next_actions(Path(a.workspace_dir).expanduser().absolute(), Path(a.repo_root).expanduser().absolute())
        result = {"ok": True, "path": "next-actions.json", "state": document}
    except (AuditStateError, OSError, ValueError) as exc:
        result = {"ok": False, "error_code": getattr(exc, "code", "NEXT_ACTIONS_FAILED"), "error": str(getattr(exc, "message", exc))}
    if a.as_json: print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    elif result["ok"]: print("next-actions.json written")
    else: print(f"NEXT ACTIONS FAILED [{result['error_code']}]: {result['error']}", file=sys.stderr)
    return 0 if result["ok"] else 1
if __name__ == "__main__": raise SystemExit(main())
