#!/usr/bin/env python3
"""Read-only validation of a workspace checkpoint index."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from workspace_state import validate_workspace_checkpoint


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--checkpoint", required=True, help="Workspace-relative checkpoints/<revision>.json path")
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    result = validate_workspace_checkpoint(
        Path(args.workspace_dir).expanduser().absolute(),
        args.checkpoint,
        Path(args.repo_root).expanduser().absolute(),
    )
    if args.as_json or not result.get("ok"):
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(f"checkpoint is valid ({result.get('classification')})")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
