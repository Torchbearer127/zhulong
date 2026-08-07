#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from audit_state_io import AuditStateError, normalize_workspace_state
from workspace_state import validate_handoff_state_current, validate_handoff_status_consistency


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


def resolve_workspace_value(repo_root: Path, value: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (repo_root / candidate).resolve()


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

    try:
        normalized = normalize_workspace_state(workspace)
    except AuditStateError as exc:
        fail(
            f"{exc.code}: {exc.message}; run <workspace>/bin/recover-audit-state.py "
            "--workspace-dir <audit-workspace> --check --json"
        )
    status = normalized["state"]
    event_count = int(normalized["event_count"])
    mode = str(normalized["mode"])

    if mode == "legacy_r1":
        missing = sorted(field for field in REQUIRED_STATUS_FIELDS if field not in status)
        if missing:
            fail(f"stage-status.json is missing required fields: {', '.join(missing)}")
    if status.get("plugin") != "zhulong":
        fail("stage-status.json plugin must be zhulong")

    status_value = str(status.get("status", "")).strip()
    if status_value not in {"running", "paused", "blocked", "completed"}:
        fail(f"stage-status.json status is invalid: {status_value or '<missing>'}")

    if mode == "legacy_r1":
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

    consistency = validate_handoff_status_consistency(
        workspace,
        status=status,
        language="auto",
    )
    if not consistency.get("ok"):
        errors = consistency.get("errors") or []
        first = str(errors[0]) if errors else "unknown handoff/status consistency error"
        fail(f"handoff/status consistency failed: {first}")

    handoff_path = workspace / "handoff-state.json"
    if handoff_path.exists() or handoff_path.is_symlink():
        handoff_consistency = validate_handoff_state_current(workspace, repo_root)
        if not handoff_consistency.get("ok"):
            codes = ", ".join(str(code) for code in handoff_consistency.get("issue_codes", [])) or "HANDOFF_UNVERIFIABLE"
            fail(f"handoff-state.json is stale or unverifiable: {codes}")

    print(f"WORKSPACE STATE OK: {workspace} ({event_count} events; mode={mode})")


if __name__ == "__main__":
    main()
