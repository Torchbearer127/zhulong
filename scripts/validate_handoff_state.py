#!/usr/bin/env python3
"""Read-only validation of handoff-state.json against current authority."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from workspace_state import validate_handoff_state_current


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    result = validate_handoff_state_current(
        Path(args.workspace_dir).expanduser().absolute(),
        Path(args.repo_root).expanduser().absolute(),
    )
    if args.as_json or not result.get("ok"):
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print("handoff-state.json is current")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
