#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from audit_disposition import (
    LEDGER_FILENAME,
    load_disposition_ledger,
    validate_disposition_ledger,
    validate_workspace_confirmation_chain,
)
from audit_state_io import AuditStateError, read_normalized_workspace_events
from blocked_verification import detect_blocked_verification
from workspace_state import (
    _completion_result_from_authority,
    inspect_workspace_state,
    validate_strict_docker_cleanliness_evidence,
    validate_handoff_status_consistency,
)


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


def find_report_validator(workspace: Path) -> Path | None:
    validator = workspace / "bin" / "validate-report-bundle.py"
    if validator.exists():
        return validator
    validator = Path(__file__).resolve().parent / "validate_report_bundle.py"
    if validator.exists():
        return validator
    return None


def run_report_validator(workspace: Path, flag: str, path: Path) -> tuple[bool, str]:
    validator = find_report_validator(workspace)
    if validator is None:
        return False, "validate_report_bundle.py not found"
    proc = subprocess.run(
        [sys.executable, str(validator), "--workspace-dir", str(workspace), flag, str(path)],
        capture_output=True,
        text=True,
    )
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode == 0, output[:800]


def validate_seeded_variant_discovery(workspace: Path) -> tuple[bool, list[str], dict[str, Any]]:
    variant_dir = workspace / "evidence" / "variant-analysis"
    seeds_path = variant_dir / "seeds.jsonl"
    candidates_path = variant_dir / "variant-candidates.jsonl"
    errors: list[str] = []
    if not variant_dir.is_dir():
        errors.append("missing evidence/variant-analysis/")
    if not seeds_path.is_file():
        errors.append("missing evidence/variant-analysis/seeds.jsonl")
    if not candidates_path.is_file():
        errors.append("missing evidence/variant-analysis/variant-candidates.jsonl")
    if seeds_path.is_file():
        ok, output = run_report_validator(workspace, "--variant-seed-card", seeds_path)
        if not ok:
            errors.append(f"variant seed validation failed: {output or 'unknown error'}")
    if candidates_path.is_file():
        ok, output = run_report_validator(workspace, "--variant-candidates", candidates_path)
        if not ok:
            errors.append(f"variant candidates validation failed: {output or 'unknown error'}")
    summary = {
        "variant_dir": str(variant_dir),
        "seeds": str(seeds_path),
        "variant_candidates": str(candidates_path),
    }
    return not errors, errors, summary


def validate_finalization(workspace: Path) -> tuple[bool, list[str], dict[str, Any]]:
    try:
        status, events, mode = read_normalized_workspace_events(workspace)
    except AuditStateError as exc:
        guidance = "run <workspace>/bin/recover-audit-state.py --workspace-dir <audit-workspace> --check --json"
        return False, [f"audit state invalid [{exc.code}]: {exc.message}; {guidance}"], {}
    blocked_summary = detect_blocked_verification(workspace)
    inspected_state = inspect_workspace_state(workspace)
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
        expected_stage = "finalization" if status.get("schema_version") == 2 else "completed"
        if stage and stage != expected_stage:
            errors.append(f"stage-status.json stage={stage!r} is not {expected_stage!r}.")
        if state and state != "completed":
            errors.append(f"stage-status.json status={state!r} is not completed.")

    result = _completion_result_from_authority(status, events, protocol_mode=mode)
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
    variant_summary: dict[str, Any] = {}
    if result == "completed_with_confirmed_bundles":
        if int(inspected_state.get("validated_confirmed_bundle_count") or 0) == 0:
            errors.append(
                "completed_with_confirmed_bundles requires at least one validated confirmed bundle; validated_confirmed_bundle_count=0."
            )
        variant_summary = {
            "formal_variant_analysis_status": inspected_state.get("formal_variant_analysis_status"),
            "variant_dir": inspected_state.get("variant_dir"),
            "seeds": inspected_state.get("seeds"),
            "variant_candidates": inspected_state.get("variant_candidates"),
        }
        variant_ok = inspected_state.get("formal_variant_analysis_status") == "completed"
        variant_errors = inspected_state.get("errors", [])
        if not variant_ok:
            for error in variant_errors:
                errors.append(f"seeded variant discovery gate: {error}")
            if not variant_errors:
                errors.append(
                    "seeded variant discovery gate: formal seeded variant discovery is not completed."
                )
    if result == "completed_no_confirmed_findings" and int(inspected_state.get("validated_confirmed_bundle_count") or 0) > 0:
        errors.append(
            "completed_no_confirmed_findings conflicts with validated confirmed bundles present in confirmed/."
        )

    consistency = validate_handoff_status_consistency(
        workspace,
        status=status,
        state=inspected_state,
    )
    if not consistency.get("ok"):
        for error in consistency.get("errors", []):
            errors.append(f"handoff/status consistency: {error}")

    disposition_validation = validate_disposition_ledger(workspace, result=result, language="auto")
    if not disposition_validation.get("ok"):
        for error in disposition_validation.get("errors", []):
            errors.append(f"{LEDGER_FILENAME}: {error}")

    authority_chain = validate_workspace_confirmation_chain(
        workspace,
        result=result,
        protocol_mode=mode,
        ledger=load_disposition_ledger(workspace),
        disposition_validation=disposition_validation,
        language="auto",
    )
    if not authority_chain.get("ok"):
        for error in authority_chain.get("errors", []):
            errors.append(f"completion authority chain: {error}")

    docker_evidence = validate_strict_docker_cleanliness_evidence(
        workspace,
        success_event,
        previous_events=events[:success_index] if success_index is not None else events,
    )
    for error in docker_evidence.get("errors", []):
        errors.append(f"Docker strict cleanliness evidence: {error}")
    docker_status = docker_evidence.get("status") if isinstance(docker_evidence.get("status"), dict) else {}
    docker_clean = docker_status.get("clean")
    docker_strict = docker_status.get("strict")

    summary = {
        "workspace": str(workspace),
        "result": result,
        "latest_finalization_event": latest[1].get("event") if latest else "",
        "finalization_succeeded": success is not None and not errors,
        "stage": stage,
        "status": state,
        "docker_clean": docker_clean,
        "docker_strict": docker_strict,
        "docker_cleanliness_path": docker_evidence.get("path"),
        "docker_cleanliness_sha256": docker_evidence.get("sha256"),
        "blocked_verification": blocked_summary,
        "seeded_variant_discovery": variant_summary,
        "workspace_state": {
            "confirmed_bundle_dirs_total": inspected_state.get("confirmed_bundle_dirs_total"),
            "validated_confirmed_bundle_count": inspected_state.get("validated_confirmed_bundle_count"),
            "invalid_or_partial_confirmed_bundle_count": inspected_state.get("invalid_or_partial_confirmed_bundle_count"),
            "docker_evidence_only_count": inspected_state.get("docker_evidence_only_count"),
            "formal_variant_analysis_status": inspected_state.get("formal_variant_analysis_status"),
            "handoff_state": inspected_state.get("handoff_state"),
        },
        "audit_disposition": disposition_validation.get("summary", {}),
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
