#!/usr/bin/env python3
"""Finalize one already-running Recon or triage stage through the R2 writer.

This is intentionally not a runner.  It validates one exact result, performs
an explicit revision CAS, and appends one same-stage complete/pause/block event
only after lock-held revalidation.  It never advances a stage and never writes
candidate, verdict, disposition, bundle, or workspace-finalization material.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audit_state_io import AuditStateError, WorkspaceSnapshot, commit_event, read_workspace_snapshot
from validate_recon_result import is_safe_relative_text, load_json


SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SCRIPT_ROOT = Path(__file__).resolve().parent
RECON_VALIDATOR = SCRIPT_ROOT / "validate_recon_result.py"
TRIAGE_VALIDATOR = SCRIPT_ROOT / "validate_triage_batch.py"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def infer_plugin_version(workspace: Path) -> str:
    try:
        state = json.loads((workspace / "stage-status.json").read_text(encoding="utf-8"))
        if isinstance(state, dict) and isinstance(state.get("plugin_version"), str) and state["plugin_version"].strip():
            return state["plugin_version"].strip()
    except (OSError, json.JSONDecodeError):
        pass
    for parent in [SCRIPT_ROOT.parent, *SCRIPT_ROOT.parent.parents]:
        try:
            version = json.loads((parent / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")).get("version")
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(version, str) and version.strip():
            return version.strip()
    return "unknown"


def digest_file(path: Path) -> str:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise AuditStateError("RESULT_PATH_UNSAFE", "result path cannot be inspected") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise AuditStateError("RESULT_PATH_UNSAFE", "result must be a non-symlink regular file")
    try:
        fd = os.open(path, os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0)))
    except OSError as exc:
        raise AuditStateError("RESULT_PATH_UNSAFE", "result cannot be opened safely") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AuditStateError("RESULT_PATH_UNSAFE", "result must be a regular file")
        hash_value = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            hash_value.update(chunk)
        return "sha256:" + hash_value.hexdigest()
    finally:
        os.close(fd)


def resolve_root(raw: str, label: str) -> Path:
    try:
        path = Path(raw).expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise AuditStateError("PATH_UNSAFE", f"{label} cannot be resolved safely") from exc
    if not path.is_dir():
        raise AuditStateError("WORKSPACE_INVALID" if label == "workspace-dir" else "REPO_ROOT_INVALID", f"{label} must be an existing directory")
    return path


def resolve_result(workspace: Path, raw: str) -> tuple[Path, str]:
    if not is_safe_relative_text(raw):
        raise AuditStateError("RESULT_PATH_UNSAFE", "--result must be a workspace-relative POSIX path")
    candidate = workspace.joinpath(*raw.split("/"))
    if candidate.is_symlink():
        raise AuditStateError("RESULT_PATH_UNSAFE", "--result must not be a symlink")
    try:
        candidate.resolve(strict=True).relative_to(workspace.resolve())
    except ValueError as exc:
        raise AuditStateError("RESULT_PATH_UNSAFE", "--result resolves outside the workspace") from exc
    except OSError as exc:
        raise AuditStateError("RESULT_PATH_UNSAFE", "--result cannot be resolved safely") from exc
    digest_file(candidate)
    return candidate, raw


def validate_contract(stage: str, repo_root: Path, workspace: Path, result_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    validator = RECON_VALIDATOR if stage == "recon" else TRIAGE_VALIDATOR
    argument = "--recon-result" if stage == "recon" else "--triage-batch"
    result_argument = str(result_path) if stage == "recon" else result_path.relative_to(workspace).as_posix()
    command = [
        sys.executable, str(validator), "--repo-root", str(repo_root), "--workspace-dir", str(workspace),
        argument, result_argument, "--json",
    ]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuditStateError("CONTRACT_VALIDATOR_UNAVAILABLE", "result validator cannot be executed") from exc
    output = (proc.stdout or "").strip()
    try:
        validation = json.loads(output)
    except json.JSONDecodeError as exc:
        raise AuditStateError("CONTRACT_VALIDATOR_UNAVAILABLE", "result validator did not emit JSON") from exc
    if proc.returncode != 0 or not isinstance(validation, dict) or validation.get("ok") is not True:
        raise AuditStateError(
            "CONTRACT_INVALID",
            "result failed its stage-specific read-only validator",
            validator_issue_codes=validation.get("issue_codes") if isinstance(validation, dict) else [],
        )
    document, _raw, load_error = load_json(result_path)
    if load_error is not None or not isinstance(document, dict):
        raise AuditStateError("CONTRACT_INVALID", "validated result cannot be parsed as an object")
    subject_field = "recon_id" if stage == "recon" else "batch_id"
    subject_id = document.get(subject_field)
    if not isinstance(subject_id, str) or not subject_id.strip():
        raise AuditStateError("CONTRACT_INVALID", "validated result has no stable contract subject ID")
    if validation.get(subject_field) != subject_id:
        raise AuditStateError("CONTRACT_INVALID", "validator subject ID does not match the result document")
    if document.get("schema_version") != 1:
        raise AuditStateError("CONTRACT_INVALID", "result schema_version is unsupported")
    if document.get("status") not in {"complete", "partial", "blocked"}:
        raise AuditStateError("CONTRACT_STATUS_UNSUPPORTED", "result status is not finalizable")
    return validation, document


def current_state_or_raise(snapshot: WorkspaceSnapshot, stage: str, expected_revision: int) -> None:
    if snapshot.mode != "r2" or snapshot.state is None:
        raise AuditStateError("R2_REQUIRED", "stage finalization supports only an existing R2 workspace")
    current_revision = snapshot.state.get("state_revision")
    if current_revision != expected_revision:
        raise AuditStateError(
            "STATE_REVISION_CONFLICT",
            "state revision differs from --expected-state-revision",
            expected_state_revision=expected_revision,
            current_state_revision=current_revision,
        )
    if snapshot.state.get("stage") != stage or snapshot.state.get("status") != "running":
        raise AuditStateError(
            "CURRENT_STAGE_MISMATCH",
            "only the same currently running stage may be finalized",
            current_stage=snapshot.state.get("stage"),
            current_status=snapshot.state.get("status"),
        )


def select_pause_or_block_context(stage: str, document: dict[str, Any]) -> tuple[str | None, str | None]:
    status = document.get("status")
    if status == "complete":
        return None, None
    if stage == "recon":
        blockers = document.get("unresolved_blockers")
        gaps = document.get("coverage_gaps")
    else:
        blockers = document.get("batch_blockers")
        gaps = document.get("batch_gaps")
    if isinstance(blockers, list) and blockers:
        chosen = sorted((item for item in blockers if isinstance(item, dict)), key=lambda item: str(item.get("code", "")))[0]
        blocker = str(chosen.get("code") or "").strip()
        action = chosen.get("resume_action")
        if isinstance(action, dict):
            resume = str(action.get("summary") or "").strip()
        else:
            resume = str(action or "").strip()
        return blocker, resume
    if isinstance(gaps, list) and gaps:
        chosen = sorted((item for item in gaps if isinstance(item, dict)), key=lambda item: str(item.get("code", "")))[0]
        blocker = str(chosen.get("code") or "").strip()
        action = chosen.get("next_action")
        if isinstance(action, dict):
            resume = str(action.get("summary") or "").strip()
        else:
            resume = str(action or "").strip()
        return blocker, resume
    if stage == "triage":
        unprocessed = document.get("unprocessed_candidates")
        if isinstance(unprocessed, list) and unprocessed:
            chosen = sorted((item for item in unprocessed if isinstance(item, dict)), key=lambda item: str(item.get("candidate_id", "")))[0]
            return str(chosen.get("reason_code") or "").strip(), str(chosen.get("next_action") or "").strip()
    raise AuditStateError("EVENT_MATERIAL_INVALID", "partial or blocked result has no deterministic blocker/resume context")


def stage_event_material(stage: str, document: dict[str, Any], result_ref: str, digest: str) -> dict[str, Any]:
    status = str(document.get("status"))
    mapping = {
        "complete": ("complete", "completed", "normal_progress"),
        "partial": ("pause", "paused", "manual_review_required"),
        "blocked": ("block", "blocked", "verification_blocked"),
    }
    transition_kind, target_status, reason_code = mapping[status]
    subject_id = str(document["recon_id"] if stage == "recon" else document["batch_id"])
    blocker, resume_step = select_pause_or_block_context(stage, document)
    if blocker is not None and (len(blocker) > 2048 or not blocker or not resume_step or len(resume_step) > 2048):
        raise AuditStateError("EVENT_MATERIAL_INVALID", "contract blocker/resume material cannot be represented safely in an R2 event")
    authority = "recon_coverage_only" if stage == "recon" else "triage_advisory_only"
    event_name = f"{stage}_{'result' if stage == 'recon' else 'batch'}_finalized"
    action_id = f"ACTION-{stage.upper()}-{status.upper()}"
    next_action = {
        "action_id": action_id,
        "action_type": "review" if status == "complete" else "resume",
        "subject_ids": [subject_id],
        "summary": "Review the recorded stage outcome; this event does not execute downstream work.",
        "evidence_refs": [result_ref],
    }
    details: dict[str, Any] = {
        "summary": f"Recorded validated {stage} contract status={status}; no downstream authority is granted.",
        "metadata": [
            {"key": "contract_subject_id", "value": subject_id},
            {"key": "result_evidence_ref", "value": result_ref},
            {"key": "result_sha256", "value": digest},
            {"key": "contract_schema_version", "value": 1},
            {"key": "contract_status", "value": status},
            {"key": "validator_authority", "value": authority},
        ],
    }
    if status != "complete":
        details["reason_detail"] = f"{blocker}; resume only after the contract's recorded recovery action."
    return {
        "stage": stage,
        "to_status": target_status,
        "transition_kind": transition_kind,
        "event_name": event_name,
        "reason_code": reason_code,
        "subjects": [subject_id],
        "evidence_refs": [result_ref],
        "next_actions": [next_action],
        "details": details,
        "blocker": blocker,
        "resume_step": resume_step,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Finalize one validated Recon or triage stage through the R2 audit writer.")
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--stage", required=True, choices=["recon", "triage"])
    parser.add_argument("--result", required=True, help="Workspace-relative result path.")
    parser.add_argument("--expected-result-sha256", required=True)
    parser.add_argument("--expected-state-revision", required=True, type=int)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def emit(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    elif payload.get("ok"):
        print(f"OK: stage={payload.get('stage')} state_revision={payload.get('state_revision')} event={payload.get('event_name')}")
    else:
        print(f"ERROR [{payload.get('code')}]: {payload.get('message')}", file=sys.stderr)


def main() -> int:
    args = parse_args()
    try:
        if args.expected_state_revision < 0:
            raise AuditStateError("STATE_REVISION_CONFLICT", "--expected-state-revision must be non-negative")
        if SHA256_RE.fullmatch(args.expected_result_sha256) is None:
            raise AuditStateError("RESULT_DIGEST_EXPECTATION_INVALID", "--expected-result-sha256 must be sha256:<64 lowercase hex>")
        workspace = resolve_root(args.workspace_dir, "workspace-dir")
        repo_root = resolve_root(args.repo_root, "repo-root")
        result_path, result_ref = resolve_result(workspace, args.result)
        initial_digest = digest_file(result_path)
        if initial_digest != args.expected_result_sha256:
            raise AuditStateError("RESULT_DIGEST_CONFLICT", "result digest differs from --expected-result-sha256", expected_result_sha256=args.expected_result_sha256, actual_result_sha256=initial_digest)
        _validation, document = validate_contract(args.stage, repo_root, workspace, result_path)
        try:
            snapshot = read_workspace_snapshot(workspace, "r2")
        except AuditStateError as exc:
            if exc.code == "PROTOCOL_MODE_MISMATCH":
                raise AuditStateError("R2_REQUIRED", "legacy R1 workspaces require an explicit separate migration workflow") from exc
            raise
        current_state_or_raise(snapshot, args.stage, args.expected_state_revision)
        material = stage_event_material(args.stage, document, result_ref, initial_digest)

        def lock_held_recheck(locked_snapshot: WorkspaceSnapshot, _event: dict[str, Any]) -> None:
            current_state_or_raise(locked_snapshot, args.stage, args.expected_state_revision)
            current_digest = digest_file(result_path)
            if current_digest != args.expected_result_sha256:
                raise AuditStateError("RESULT_DIGEST_CONFLICT", "result changed before the journal commit boundary", expected_result_sha256=args.expected_result_sha256, actual_result_sha256=current_digest)
            _revalidation, current_document = validate_contract(args.stage, repo_root, workspace, result_path)
            subject_field = "recon_id" if args.stage == "recon" else "batch_id"
            if (
                current_document.get(subject_field) != document.get(subject_field)
                or current_document.get("status") != document.get("status")
                or current_document.get("schema_version") != document.get("schema_version")
            ):
                raise AuditStateError("RESULT_CONTRACT_CHANGED", "result contract changed before the journal commit boundary")

        request = {
            "accept_current_revision": False,
            "expected_state_revision": args.expected_state_revision,
            "run_id": "",
            "timestamp": utc_now(),
            "stage": material["stage"],
            "to_status": material["to_status"],
            "use_current_stage": False,
            "use_current_status": False,
            "event_type": "stage_transition",
            "transition_kind": material["transition_kind"],
            "expected_from_stage": args.stage,
            "expected_from_status": "running",
            "event_name": material["event_name"],
            "reason_code": material["reason_code"],
            "subjects": material["subjects"],
            "evidence_refs": material["evidence_refs"],
            "next_actions": material["next_actions"],
            "details": material["details"],
            "blocker": material["blocker"],
            "resume_step": material["resume_step"],
            "plugin_version": infer_plugin_version(workspace),
        }
        result = commit_event(
            workspace,
            mode_policy="r2",
            lock_timeout_seconds=10.0,
            request=request,
            precommit_validation=lock_held_recheck,
        )
        payload = result.as_dict()
        payload.update({"stage": args.stage, "event_name": material["event_name"], "result_sha256": initial_digest})
        emit(payload, args.json)
        return 0
    except AuditStateError as exc:
        payload: dict[str, Any] = {
            "ok": False,
            "code": exc.code,
            "message": exc.message,
            "journal_committed": bool(exc.fields.get("journal_committed", False)),
            "state_view_updated": bool(exc.fields.get("state_view_updated", False)),
        }
        payload.update(exc.fields)
        emit(payload, args.json)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
