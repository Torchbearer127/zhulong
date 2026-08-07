#!/usr/bin/env python3
"""Append one safely serialized Zhulong audit event and refresh its state view."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audit_transition_policy import STAGES as POLICY_STAGES
from audit_state_io import AuditStateError, commit_event


STAGE_ALIASES = {
    "workspace_preparing": "intake",
    "environment_checking": "intake",
    "initial_probing": "recon",
    "candidate_verifying": "verification",
    "reporting": "packaging",
    "completed": "finalization",
}
CANONICAL_STAGES = set(POLICY_STAGES)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def infer_plugin_version(workspace: Path) -> str:
    state_path = workspace / "stage-status.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if isinstance(state, dict) and str(state.get("plugin_version") or "").strip():
            return str(state["plugin_version"]).strip()
    except (OSError, json.JSONDecodeError):
        pass
    for parent in [Path(__file__).resolve().parent, *Path(__file__).resolve().parents]:
        manifest = parent / ".codex-plugin" / "plugin.json"
        try:
            value = json.loads(manifest.read_text(encoding="utf-8")).get("version")
        except (OSError, json.JSONDecodeError):
            continue
        if str(value or "").strip():
            return str(value).strip()
    return "unknown"


def parse_details(args: argparse.Namespace) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    details: dict[str, Any] = {"summary": args.message.strip()}
    if args.details_json:
        try:
            parsed = json.loads(args.details_json)
        except json.JSONDecodeError as exc:
            raise AuditStateError("EVENT_VALIDATION_FAILED", "--details-json is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise AuditStateError("EVENT_VALIDATION_FAILED", "--details-json must be a JSON object")
        if set(parsed).issubset({"summary", "reason_detail", "metadata"}):
            details.update(parsed)
            for item in parsed.get("metadata", []):
                if not isinstance(item, dict) or set(item) != {"key", "value"}:
                    raise AuditStateError("EVENT_VALIDATION_FAILED", "R2 metadata entries must be key/value objects")
                metadata[str(item["key"])] = item["value"]
        else:
            for key, value in parsed.items():
                if isinstance(value, (dict, list)):
                    raise AuditStateError(
                        "EVENT_VALIDATION_FAILED",
                        "legacy --details-json values must be scalar; pass structured R2 details explicitly",
                    )
                metadata[str(key)] = value
    for item in args.detail:
        if "=" not in item:
            raise AuditStateError("EVENT_VALIDATION_FAILED", "--detail must use KEY=VALUE form")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key or key in metadata:
            raise AuditStateError("EVENT_VALIDATION_FAILED", "--detail metadata keys must be non-empty and unique")
        metadata[key] = value
    if args.event_status:
        if "legacy_event_status" in metadata:
            raise AuditStateError("EVENT_VALIDATION_FAILED", "legacy_event_status metadata key is reserved")
        metadata["legacy_event_status"] = args.event_status
    if metadata:
        details["metadata"] = [{"key": key, "value": metadata[key]} for key in sorted(metadata)]
    if not str(details.get("summary") or "").strip():
        raise AuditStateError("EVENT_VALIDATION_FAILED", "R2 details require a non-empty summary message")
    return details


def default_reason(args: argparse.Namespace) -> str:
    if args.reason_code:
        return args.reason_code
    if args.status in {"blocked", "paused"}:
        return "policy_or_safety_block" if args.event_status == "rejected_unsafe_sandbox" else "verification_blocked"
    if args.event_status in {"failed", "warning"}:
        return "validation_failed"
    if args.event_status == "skipped":
        return "not_applicable"
    return "normal_progress"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Append one Zhulong audit event with a durable state view.")
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--target-repo", default="", help="Legacy R1 compatibility field; never written to R2.")
    parser.add_argument("--plugin-version", default="")
    parser.add_argument("--protocol-mode", choices=["auto", "r2", "legacy-r1"], default="auto")
    revision = parser.add_mutually_exclusive_group()
    revision.add_argument("--expected-state-revision", type=int)
    revision.add_argument("--accept-current-revision", action="store_true")
    parser.add_argument("--lock-timeout-seconds", type=float, default=10.0)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--event", required=True)
    parser.add_argument(
        "--stage",
        required=True,
        help="Canonical stage or the narrow 'current' shorthand for a same-state observation.",
    )
    parser.add_argument(
        "--status",
        required=True,
        choices=["running", "paused", "blocked", "completed", "current"],
        help="Canonical status or 'current' for an observe event that preserves locked state.",
    )
    parser.add_argument("--event-status", default="")
    parser.add_argument("--event-type", default="")
    parser.add_argument(
        "--transition-kind",
        default="",
        help="Required for new R2 writes: start, observe, advance, pause, block, resume, skip, return, reopen, or complete.",
    )
    parser.add_argument(
        "--from-stage",
        default="",
        help="Optional expected source stage. The writer cross-checks it under the workspace lock.",
    )
    parser.add_argument(
        "--from-status",
        default="",
        help="Optional expected source status. The writer cross-checks it under the workspace lock.",
    )
    parser.add_argument("--reason-code", default="")
    parser.add_argument("--subject", action="append", default=[])
    parser.add_argument("--evidence-ref", action="append", default=[])
    parser.add_argument("--next-action-json", action="append", default=[])
    parser.add_argument("--run-id", default="")
    parser.add_argument("--message", default="")
    parser.add_argument("--blocker", default="")
    parser.add_argument("--resume-step", default="")
    parser.add_argument("--details-json", default="")
    parser.add_argument("--detail", action="append", default=[])
    return parser.parse_args()


def emit(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return
    for key in (
        "ok", "code", "mode", "seq", "state_revision", "journal_committed", "state_view_updated",
        "cas_mode", "compatibility_code", "ignored_fields", "compatibility_diagnostic",
    ):
        if key in payload:
            value = payload[key]
            print(f"{key}={str(value).lower() if isinstance(value, bool) else value}")
    if not payload.get("ok"):
        print(f"error={payload.get('message', '')}", file=sys.stderr)


def main() -> int:
    args = parse_args()
    workspace = Path(args.workspace_dir).expanduser().resolve()
    try:
        if not workspace.is_dir():
            raise AuditStateError("WORKSPACE_INVALID", "workspace directory does not exist")
        use_current_stage = args.stage == "current"
        stage = "" if use_current_stage else STAGE_ALIASES.get(args.stage, args.stage)
        if not use_current_stage and stage not in CANONICAL_STAGES:
            raise AuditStateError("EVENT_VALIDATION_FAILED", "stage is not a known canonical name or compatibility alias")
        use_current_status = args.status == "current"
        expected_from_stage = args.from_stage.strip()
        if expected_from_stage:
            expected_from_stage = STAGE_ALIASES.get(expected_from_stage, expected_from_stage)
            if expected_from_stage not in CANONICAL_STAGES:
                raise AuditStateError(
                    "EVENT_VALIDATION_FAILED",
                    "from-stage is not a known canonical name or compatibility alias",
                )
        if args.status in {"blocked", "paused"} and (not args.blocker.strip() or not args.resume_step.strip()):
            raise AuditStateError("EVENT_VALIDATION_FAILED", "blocked and paused states require blocker and resume-step")
        next_actions: list[dict[str, Any]] = []
        for raw in args.next_action_json:
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise AuditStateError("EVENT_VALIDATION_FAILED", "--next-action-json is not valid JSON") from exc
            if not isinstance(value, dict):
                raise AuditStateError("EVENT_VALIDATION_FAILED", "--next-action-json must be a JSON object")
            next_actions.append(value)
        details = parse_details(args)
        legacy_details = {item["key"]: item["value"] for item in details.get("metadata", [])}
        target_repo_label = (
            Path(args.target_repo).expanduser().resolve().name
            if args.target_repo.strip()
            else workspace.parent.name
        )
        request = {
            "accept_current_revision": args.accept_current_revision,
            "expected_state_revision": args.expected_state_revision,
            "run_id": args.run_id.strip(),
            "timestamp": utc_now(),
            "stage": stage,
            "to_status": "" if use_current_status else args.status,
            "use_current_stage": use_current_stage,
            "use_current_status": use_current_status,
            "event_type": args.event_type.strip() or None,
            "transition_kind": args.transition_kind.strip(),
            "expected_from_stage": expected_from_stage,
            "expected_from_status": args.from_status.strip(),
            "event_name": args.event.strip(),
            "reason_code": default_reason(args),
            "reason_code_explicit": bool(args.reason_code.strip()),
            "reason_detail": details.get("reason_detail", ""),
            "subjects": args.subject,
            "evidence_refs": args.evidence_ref,
            "next_actions": next_actions,
            "details": details,
            "blocker": args.blocker.strip(),
            "resume_step": args.resume_step.strip(),
            "plugin_version": args.plugin_version.strip() or infer_plugin_version(workspace),
            "legacy_event": {
                "ts": utc_now(), "event": args.event, "stage": args.stage,
                "status": args.event_status or args.status, "message": args.message,
                "details": legacy_details,
            },
            "legacy_state": {
                "schema_version": 1,
                "plugin": "zhulong",
                "plugin_version": args.plugin_version.strip() or infer_plugin_version(workspace),
                "stage": args.stage,
                "status": args.status,
                "last_event_at": utc_now(),
                "blocker": args.blocker.strip() if args.status in {"blocked", "paused"} else None,
                "resume_step": args.resume_step.strip() if args.status in {"blocked", "paused"} else None,
                "workspace": workspace.name,
                "target_repo": target_repo_label,
                "last_event": args.event,
                "last_message": args.message,
            },
        }
        result = commit_event(
            workspace,
            mode_policy=args.protocol_mode,
            lock_timeout_seconds=args.lock_timeout_seconds,
            request=request,
        )
        emit(result.as_dict(), args.json)
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
