#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATE_FILE = "stage-status.json"
EVENTS_FILE = "audit-events.jsonl"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def infer_plugin_version(workspace: Path) -> str:
    status = load_json(workspace / STATE_FILE)
    value = str(status.get("plugin_version", "")).strip()
    if value:
        return value

    script_path = Path(__file__).resolve()
    for parent in [script_path.parent, *script_path.parents]:
        plugin_json = parent / ".codex-plugin" / "plugin.json"
        if plugin_json.exists():
            try:
                data = json.loads(plugin_json.read_text(encoding="utf-8"))
            except Exception:
                continue
            value = str(data.get("version", "")).strip()
            if value:
                return value
    return "unknown"


def parse_detail(values: list[str]) -> dict[str, str]:
    details: dict[str, str] = {}
    for item in values:
        if "=" not in item:
            raise SystemExit(f"--detail must use KEY=VALUE form: {item}")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise SystemExit(f"--detail key cannot be empty: {item}")
        details[key] = value
    return details


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Append a Zhulong audit event and update stage-status.json."
    )
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--target-repo", default="")
    parser.add_argument("--plugin-version", default="")
    parser.add_argument("--event", required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument(
        "--status",
        required=True,
        choices=["running", "paused", "blocked", "completed"],
        help="Workflow status to persist in stage-status.json.",
    )
    parser.add_argument(
        "--event-status",
        default="",
        help="Per-event status label for audit-events.jsonl. Defaults to --status.",
    )
    parser.add_argument("--message", default="")
    parser.add_argument("--blocker", default="")
    parser.add_argument("--resume-step", default="")
    parser.add_argument("--details-json", default="")
    parser.add_argument("--detail", action="append", default=[])
    args = parser.parse_args()

    workspace = Path(args.workspace_dir).expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True)

    details: dict[str, Any] = {}
    if args.details_json:
        try:
            parsed = json.loads(args.details_json)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"--details-json is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise SystemExit("--details-json must decode to a JSON object")
        details.update(parsed)
    details.update(parse_detail(args.detail))

    if args.status in {"blocked", "paused"}:
        if not args.blocker.strip():
            raise SystemExit("--blocker is required when --status is blocked or paused")
        if not args.resume_step.strip():
            raise SystemExit("--resume-step is required when --status is blocked or paused")

    timestamp = utc_now()
    event_status = args.event_status or args.status
    event = {
        "ts": timestamp,
        "event": args.event,
        "stage": args.stage,
        "status": event_status,
        "message": args.message,
        "details": details,
    }

    events_path = workspace / EVENTS_FILE
    with events_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")

    previous = load_json(workspace / STATE_FILE)
    plugin_version = args.plugin_version.strip() or infer_plugin_version(workspace)
    if args.target_repo.strip():
        target_repo = str(Path(args.target_repo).expanduser().resolve())
    else:
        target_repo = str(workspace.parent)

    if args.status in {"blocked", "paused"}:
        blocker = args.blocker.strip()
        resume_step = args.resume_step.strip()
    else:
        blocker = None
        resume_step = None

    state = {
        "schema_version": 1,
        "plugin": "zhulong",
        "plugin_version": plugin_version,
        "stage": args.stage,
        "status": args.status,
        "last_event_at": timestamp,
        "blocker": blocker,
        "resume_step": resume_step,
        "workspace": str(workspace),
        "target_repo": target_repo,
        "last_event": args.event,
        "last_message": args.message,
    }

    # Preserve forward-compatible fields from newer writers without letting stale
    # control fields survive a fresh running/completed event.
    for key, value in previous.items():
        if key not in state and key not in {"blocker", "resume_step"}:
            state[key] = value

    (workspace / STATE_FILE).write_text(
        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
