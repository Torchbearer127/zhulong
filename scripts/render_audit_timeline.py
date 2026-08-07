#!/usr/bin/env python3
"""Generate the derived audit timeline JSON and static offline HTML pair."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from audit_state_io import AuditStateError
from audit_timeline import HTML_BASENAME, JSON_BASENAME, publish_timeline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--json-output", default=JSON_BASENAME)
    parser.add_argument("--html-output", default=HTML_BASENAME)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    try:
        result = publish_timeline(
            Path(args.workspace_dir).expanduser().absolute(),
            Path(args.repo_root).expanduser().absolute(),
            json_output=args.json_output,
            html_output=args.html_output,
            overwrite=args.overwrite,
        )
        payload = {
            "ok": True,
            "json_path": result["json_path"],
            "html_path": result["html_path"],
            "json_sha256": result["json_sha256"],
            "html_sha256": result["html_sha256"],
            "idempotent": result["idempotent"],
        }
    except (AuditStateError, OSError, ValueError) as exc:
        payload = {
            "ok": False,
            "error_code": getattr(exc, "code", "TIMELINE_GENERATION_FAILED"),
            "error": str(getattr(exc, "message", exc)),
        }
    if args.as_json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    elif payload["ok"]:
        print(f"{payload['json_path']} and {payload['html_path']} written")
    else:
        print(f"TIMELINE FAILED [{payload['error_code']}]: {payload['error']}", file=sys.stderr)
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
