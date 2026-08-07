#!/usr/bin/env python3
"""Derive and atomically publish the lightweight handoff-state.json index."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from audit_state_io import AuditStateError
from workspace_state import generate_handoff_state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    workspace = Path(args.workspace_dir).expanduser().absolute()
    repo_root = Path(args.repo_root).expanduser().absolute()
    try:
        document = generate_handoff_state(workspace, repo_root, write=True)
        result = {"ok": True, "path": "handoff-state.json", "state": document}
        if args.as_json:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        else:
            print("handoff-state.json written")
        return 0
    except (AuditStateError, OSError, ValueError) as exc:
        result = {"ok": False, "error_code": getattr(exc, "code", "HANDOFF_FAILED"), "error": str(getattr(exc, "message", exc))}
        if args.as_json:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        else:
            print(f"HANDOFF FAILED [{result['error_code']}]: {result['error']}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
