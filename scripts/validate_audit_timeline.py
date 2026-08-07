#!/usr/bin/env python3
"""Read-only validation of audit timeline JSON, HTML, and optional workspace bindings."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from audit_timeline import HTML_BASENAME, JSON_BASENAME, validate_published


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeline")
    parser.add_argument("--html")
    parser.add_argument("--workspace-dir")
    parser.add_argument("--repo-root")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    workspace = Path(args.workspace_dir).expanduser().absolute() if args.workspace_dir else None
    timeline = Path(args.timeline).expanduser().absolute() if args.timeline else (
        workspace / JSON_BASENAME if workspace is not None else None
    )
    if timeline is None:
        parser.error("--timeline or --workspace-dir is required")
    html = Path(args.html).expanduser().absolute() if args.html else (
        workspace / HTML_BASENAME if workspace is not None and (workspace / HTML_BASENAME).exists() else None
    )
    result = validate_published(
        timeline,
        workspace=workspace,
        repo_root=Path(args.repo_root).expanduser().absolute() if args.repo_root else None,
        html_path=html,
    )
    if args.as_json or not result["ok"]:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print("audit timeline is valid")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
