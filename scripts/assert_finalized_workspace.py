#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from blocked_verification import detect_blocked_verification


SUCCESS_EVENT = "finalization_succeeded"
FAILURE_EVENT = "finalization_failed"
VALID_RESULTS = {
    "completed_with_confirmed_bundles",
    "completed_no_confirmed_findings",
}


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.exists():
        return events
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            events.append(data)
    return events


def event_details(event: dict[str, Any] | None) -> dict[str, Any]:
    if not event:
        return {}
    raw = event.get("details")
    return raw if isinstance(raw, dict) else {}


def latest_finalization(events: list[dict[str, Any]]) -> tuple[int, dict[str, Any]] | None:
    for index in range(len(events) - 1, -1, -1):
        event = events[index]
        if event.get("event") in {SUCCESS_EVENT, FAILURE_EVENT}:
            return index, event
    return None


def latest_success(events: list[dict[str, Any]]) -> tuple[int, dict[str, Any]] | None:
    for index in range(len(events) - 1, -1, -1):
        event = events[index]
        if event.get("event") == SUCCESS_EVENT:
            return index, event
    return None


def declared_result(status: dict[str, Any], success_event: dict[str, Any] | None) -> str:
    status_result = str(status.get("result") or status.get("completion_result") or "").strip()
    if status_result:
        return status_result
    details = event_details(success_event)
    return str(details.get("result") or "").strip()


def completion_claimed(status: dict[str, Any]) -> bool:
    stage = str(status.get("stage") or "").strip()
    state = str(status.get("status") or "").strip()
    result = str(status.get("result") or status.get("completion_result") or "").strip()
    return stage == "completed" or state == "completed" or result in VALID_RESULTS or bool(status.get("completed_at"))


def validate_finalization(workspace: Path) -> tuple[bool, list[str], dict[str, Any]]:
    status = load_json(workspace / "stage-status.json")
    events = read_events(workspace / "audit-events.jsonl")
    docker_status = load_json(workspace / "docker" / "docker-cleanliness-status.json")
    blocked_summary = detect_blocked_verification(workspace)
    latest = latest_finalization(events)
    success = latest_success(events)
    success_index = success[0] if success else None
    success_event = success[1] if success else None
    details = event_details(success_event)
    errors: list[str] = []

    if not events:
        errors.append("audit-events.jsonl has no readable events; rerun the completion gate.")
    if success is None:
        errors.append("missing finalization_succeeded event; rerun finalize-audit-workspace.py.")
    if latest is not None and latest[1].get("event") == FAILURE_EVENT:
        errors.append("latest finalization event is finalization_failed; resolve the blocker and rerun the completion gate.")
    if success_index is not None:
        later_failures = [
            event for event in events[success_index + 1 :]
            if event.get("event") == FAILURE_EVENT
        ]
        if later_failures:
            errors.append("a later finalization_failed event exists after finalization_succeeded; rerun the completion gate.")

    stage = str(status.get("stage") or "").strip()
    state = str(status.get("status") or "").strip()
    if not completion_claimed(status):
        errors.append("stage-status.json does not declare a completed workspace; do not write a completion summary yet.")
    else:
        if stage and stage != "completed":
            errors.append(f"stage-status.json stage={stage!r} is not completed.")
        if state and state != "completed":
            errors.append(f"stage-status.json status={state!r} is not completed.")

    result = declared_result(status, success_event)
    success_result = str(details.get("result") or "").strip()
    if result and result not in VALID_RESULTS:
        errors.append(f"declared completion result is not valid: {result}.")
    if result and success_result and result != success_result:
        errors.append(
            f"stage-status.json result={result} disagrees with finalization_succeeded result={success_result}."
        )
    if result == "completed_no_confirmed_findings" and blocked_summary.get("blocked"):
        errors.append(
            "blocked verification evidence exists in lightweight workspace records; "
            "completed_no_confirmed_findings is not a valid terminal result until Docker verification resumes."
        )

    docker_clean_claim = details.get("docker_clean")
    docker_clean = docker_status.get("clean")
    docker_strict = docker_status.get("strict")
    if docker_clean_claim is True:
        if not docker_status:
            errors.append("finalization_succeeded claims docker_clean=true but docker-cleanliness-status.json is missing.")
        elif docker_clean is not True or docker_strict is not True:
            errors.append(
                "finalization_succeeded claims docker_clean=true but docker-cleanliness-status.json is not clean=true and strict=true."
            )
    if docker_status and docker_clean is False:
        errors.append("docker-cleanliness-status.json has clean=false; the workspace must remain blocked.")
    if completion_claimed(status) and docker_status and docker_strict is False:
        errors.append("completed workspace requires Docker strict cleanliness status strict=true.")

    summary = {
        "workspace": str(workspace),
        "result": result,
        "latest_finalization_event": latest[1].get("event") if latest else "",
        "finalization_succeeded": success is not None and not errors,
        "stage": stage,
        "status": state,
        "docker_clean": docker_clean,
        "docker_strict": docker_strict,
        "blocked_verification": blocked_summary,
    }
    return not errors, errors, summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Assert that a Zhulong audit workspace is truly finalized."
    )
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable result JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    workspace = Path(args.workspace_dir).expanduser().resolve()
    if not workspace.is_dir():
        message = f"workspace directory does not exist: {workspace}"
        if args.json:
            print(json.dumps({"ok": False, "errors": [message]}, ensure_ascii=False, indent=2))
        else:
            print(f"FINALIZATION INTEGRITY FAILED: {message}")
            print("Next action: pass a valid Zhulong audit workspace to --workspace-dir.")
        return 1
    ok, errors, summary = validate_finalization(workspace)
    if args.json:
        print(json.dumps({"ok": ok, "errors": errors, "summary": summary}, ensure_ascii=False, indent=2))
        return 0 if ok else 1
    if ok:
        print(
            "FINALIZATION INTEGRITY OK: "
            f"result={summary.get('result') or '<unknown>'} "
            f"docker_clean={str(summary.get('docker_clean')).lower()} "
            f"strict={str(summary.get('docker_strict')).lower()}"
        )
        return 0
    print("FINALIZATION INTEGRITY FAILED:")
    for error in errors:
        print(f"- {error}")
    print("Next action: resolve the blocker, rerun finalize-audit-workspace.py, then rerun this checker.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
