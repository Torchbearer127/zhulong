#!/usr/bin/env python3
"""Create an immutable, lightweight checkpoint index for the current R2 revision."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from audit_state_io import AuditStateError
from workspace_state import create_workspace_checkpoint


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    try:
        result = create_workspace_checkpoint(
            Path(args.workspace_dir).expanduser().absolute(),
            Path(args.repo_root).expanduser().absolute(),
        )
    except (AuditStateError, OSError, ValueError) as exc:
        result = {"ok": False, "error_code": getattr(exc, "code", "CHECKPOINT_FAILED"), "error": str(getattr(exc, "message", exc))}
        if args.as_json:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        else:
            print(f"CHECKPOINT FAILED [{result['error_code']}]: {result['error']}", file=sys.stderr)
        return 1
    if args.as_json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(f"checkpoint={result['path']} idempotent={str(bool(result.get('idempotent'))).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
