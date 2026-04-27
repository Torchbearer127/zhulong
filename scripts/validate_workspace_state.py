#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REQUIRED_STATUS_FIELDS = {
    "schema_version",
    "plugin",
    "plugin_version",
    "stage",
    "status",
    "last_event_at",
    "blocker",
    "resume_step",
    "workspace",
    "target_repo",
}


def fail(message: str) -> None:
    raise SystemExit(f"FAILED: {message}")


def load_status(path: Path) -> dict[str, Any]:
    if not path.exists():
        fail(f"missing {path.name}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"{path.name} is not valid JSON: {exc}")
    if not isinstance(data, dict):
        fail(f"{path.name} must contain a JSON object")
    return data


def resolve_workspace_value(repo_root: Path, value: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (repo_root / candidate).resolve()


def validate_events(path: Path) -> int:
    if not path.exists():
        fail(f"missing {path.name}")
    count = 0
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            raw = line.strip()
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                fail(f"{path.name}:{line_no} is not valid JSON: {exc}")
            if not isinstance(data, dict):
                fail(f"{path.name}:{line_no} must be a JSON object")
            if not str(data.get("ts", "")).strip():
                fail(f"{path.name}:{line_no} is missing ts")
            if not str(data.get("event", "")).strip():
                fail(f"{path.name}:{line_no} is missing event")
            count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Validate Zhulong workspace state files. By default this checks that "
            "the workspace matches repo_root/.asr-latest-workspace, so historical "
            "workspaces should be validated with --skip-latest-check."
        )
    )
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--repo-root", default="")
    parser.add_argument(
        "--skip-latest-check",
        action="store_true",
        help=(
            "Do not require repo_root/.asr-latest-workspace to point at this "
            "workspace. Use this when validating older, non-latest workspaces."
        ),
    )
    args = parser.parse_args()

    workspace = Path(args.workspace_dir).expanduser().resolve()
    if not workspace.is_dir():
        fail(f"workspace directory does not exist: {workspace}")

    repo_root = Path(args.repo_root).expanduser().resolve() if args.repo_root else workspace.parent

    status_path = workspace / "stage-status.json"
    events_path = workspace / "audit-events.jsonl"
    status = load_status(status_path)
    event_count = validate_events(events_path)

    missing = sorted(field for field in REQUIRED_STATUS_FIELDS if field not in status)
    if missing:
        fail(f"stage-status.json is missing required fields: {', '.join(missing)}")

    if status.get("schema_version") != 1:
        fail("stage-status.json schema_version must be 1")
    if status.get("plugin") != "zhulong":
        fail("stage-status.json plugin must be zhulong")

    status_value = str(status.get("status", "")).strip()
    if status_value not in {"running", "paused", "blocked", "completed"}:
        fail(f"stage-status.json status is invalid: {status_value or '<missing>'}")

    workspace_value = str(status.get("workspace", "")).strip()
    if not workspace_value:
        fail("stage-status.json workspace is empty")
    resolved_workspace = resolve_workspace_value(repo_root, workspace_value)
    if resolved_workspace != workspace:
        fail(
            "stage-status.json workspace mismatch: "
            f"expected {workspace}, got {workspace_value}"
        )

    latest_marker = repo_root / ".asr-latest-workspace"
    if latest_marker.exists() and not args.skip_latest_check:
        latest_value = latest_marker.read_text(encoding="utf-8").strip()
        if not latest_value:
            fail(".asr-latest-workspace is empty")
        latest_workspace = resolve_workspace_value(repo_root, latest_value)
        if latest_workspace != workspace:
            fail(
                ".asr-latest-workspace mismatch: "
                f"expected {workspace}, got {latest_value}"
            )

    if status_value in {"blocked", "paused"}:
        if not str(status.get("blocker") or "").strip():
            fail("blocked/paused stage-status.json must include blocker")
        if not str(status.get("resume_step") or "").strip():
            fail("blocked/paused stage-status.json must include resume_step")

    print(f"WORKSPACE STATE OK: {workspace} ({event_count} events)")


if __name__ == "__main__":
    main()
