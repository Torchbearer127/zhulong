#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from audit_state_io import (
    AuditStateError,
    WorkspaceSnapshot,
    commit_event,
    normalize_workspace_state,
    project_legacy_snapshot,
    project_r2_snapshot,
    read_workspace_snapshot,
)
from audit_disposition import (
    DispositionUpdateError,
    LEDGER_FILENAME,
    load_disposition_ledger,
    synthesize_disposition_ledger,
    validate_workspace_confirmation_chain,
    validate_disposition_ledger,
    write_disposition_ledger,
)
from blocked_verification import detect_blocked_verification
from evidence_io import SafeEvidenceError, atomic_write_bytes, safe_read_bytes
from render_handoff_summary import publish_handoff_summary, render as render_handoff_summary
from workspace_state import (
    derive_handoff_state,
    inspect_workspace_state,
    publish_handoff_state_document,
    read_handoff_state,
    read_strict_docker_cleanliness,
    validate_current_strict_docker_cleanliness,
    validate_handoff_state_current,
    validate_handoff_status_consistency,
)


VALID_RESULTS = {
    "completed_with_confirmed_bundles",
    "completed_no_confirmed_findings",
}


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


class _FinalizationEventWriter:
    """State-changing finalization events must never degrade to warnings."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        try:
            normalized = normalize_workspace_state(workspace)
        except AuditStateError as exc:
            try:
                snapshot = read_workspace_snapshot(workspace)
            except AuditStateError:
                print(f"FINALIZATION FAILED: cannot read audit state: {exc.code}: {exc.message}; run <workspace>/bin/recover-audit-state.py --workspace-dir <audit-workspace> --check --json", file=sys.stderr)
                raise SystemExit(1) from exc
            if snapshot.mode == "r2" and not snapshot.journal.events and snapshot.state is None:
                # A just-created workspace has a precisely defined first-write
                # bootstrap case. Any non-empty journal/state mismatch still
                # failed in read_workspace_snapshot above.
                self.state_revision = 0
                self.current_stage: str | None = None
                self.current_status: str | None = None
                return
            print(f"FINALIZATION FAILED: cannot read audit state: {exc.code}: {exc.message}; run <workspace>/bin/recover-audit-state.py --workspace-dir <audit-workspace> --check --json", file=sys.stderr)
            raise SystemExit(1) from exc
        state = normalized["state"]
        self.state_revision: int | None = (
            int(state["state_revision"]) if normalized["mode"] == "r2" else None
        )
        self.current_stage = str(state.get("stage") or "") or None
        self.current_status = str(state.get("status") or "") or None

    def commit_terminal(
        self,
        *,
        result: str,
        validated_count: int,
        docker_clean: bool,
        docker_evidence: dict[str, Any],
        prepare_artifacts: Callable[[WorkspaceSnapshot], None],
    ) -> None:
        timestamp = utc_now()
        message = f"Audit finalized as {result}."
        metadata = {
            "docker_clean": docker_clean,
            "docker_clean_strict": True,
            "docker_cleanliness_checked_at": docker_evidence.get("checked_at"),
            "docker_cleanliness_path": docker_evidence.get("path"),
            "docker_cleanliness_sha256": docker_evidence.get("sha256"),
            "docker_cleanliness_workspace": self.workspace.name,
            "legacy_event_status": "ok",
            "result": result,
            "validated_bundles": validated_count,
        }
        details = {
            "summary": message,
            "metadata": [
                {"key": key, "value": value}
                for key, value in sorted(metadata.items())
            ],
        }
        try:
            snapshot = read_workspace_snapshot(self.workspace)
        except AuditStateError as exc:
            print(f"FINALIZATION FAILED: cannot read terminal snapshot [{exc.code}]: {exc.message}", file=sys.stderr)
            raise SystemExit(1) from exc
        plugin_version = str((snapshot.state or {}).get("plugin_version") or "unknown")
        legacy_details = {item["key"]: item["value"] for item in details["metadata"]}
        request = {
            "accept_current_revision": self.state_revision is None,
            "expected_state_revision": self.state_revision,
            "run_id": "",
            "timestamp": timestamp,
            "stage": "finalization",
            "to_status": "completed",
            "use_current_stage": False,
            "use_current_status": False,
            "event_type": None,
            "transition_kind": "complete",
            "expected_from_stage": "",
            "expected_from_status": "",
            "event_name": "finalization_succeeded",
            "reason_code": "normal_progress",
            "reason_code_explicit": False,
            "reason_detail": "",
            "subjects": [],
            "evidence_refs": [],
            "next_actions": [],
            "details": details,
            "blocker": "",
            "resume_step": "",
            "plugin_version": plugin_version,
            "legacy_event": {
                "ts": timestamp,
                "event": "finalization_succeeded",
                "stage": "completed",
                "status": "ok",
                "message": message,
                "details": legacy_details,
            },
            "legacy_state": {
                "schema_version": 1,
                "plugin": "zhulong",
                "plugin_version": plugin_version,
                "stage": "completed",
                "status": "completed",
                "last_event_at": timestamp,
                "blocker": None,
                "resume_step": None,
                "workspace": self.workspace.name,
                "target_repo": self.workspace.parent.name,
                "last_event": "finalization_succeeded",
                "last_message": message,
            },
        }

        def precommit(locked_snapshot: WorkspaceSnapshot, event: dict[str, Any]) -> None:
            prepare_artifacts(project_r2_snapshot(locked_snapshot, event))

        try:
            if snapshot.mode == "r2":
                write_result = commit_event(
                    self.workspace,
                    mode_policy="r2",
                    lock_timeout_seconds=10.0,
                    request=request,
                    precommit_validation=precommit,
                )
            else:
                prepare_artifacts(project_legacy_snapshot(snapshot, request))
                write_result = commit_event(
                    self.workspace,
                    mode_policy="legacy-r1",
                    lock_timeout_seconds=10.0,
                    request=request,
                )
        except AuditStateError as exc:
            partial = bool(exc.fields.get("journal_committed")) and not bool(exc.fields.get("state_view_updated"))
            label = "FINALIZATION PARTIAL" if partial else "FINALIZATION FAILED"
            guidance = "; run <workspace>/bin/recover-audit-state.py --workspace-dir <audit-workspace> --check --json" if partial else ""
            print(f"{label} [{exc.code}]: {exc.message}{guidance}", file=sys.stderr)
            raise SystemExit(1) from exc
        self.state_revision = write_result.state_revision
        self.current_stage = "finalization" if write_result.mode == "r2" else "completed"
        self.current_status = "completed"

    def write(
        self,
        event: str,
        stage: str,
        status: str,
        event_status: str,
        message: str,
        blocker: str = "",
        resume_step: str = "",
        *,
        transition_kind: str,
        reason_code: str = "",
        reason_detail: str = "",
        subjects: list[str] | None = None,
        evidence_refs: list[str] | None = None,
        next_actions: list[dict[str, Any]] | None = None,
        **details: Any,
    ) -> None:
        if self.state_revision is None and event == "finalization_succeeded" and stage == "finalization":
            # R1 has a historical completed-stage materialized view; do not rewrite
            # legacy workflows merely because the R2 canonical stage is finalization.
            stage = "completed"
        writer = self.workspace / "bin" / "write-audit-event.py"
        if not writer.exists():
            writer = Path(__file__).resolve().parent / "write_audit_event.py"
        if not writer.exists():
            print("FINALIZATION FAILED: audit event writer not found", file=sys.stderr)
            raise SystemExit(1)
        if any(isinstance(value, (dict, list)) for value in details.values()):
            print("FINALIZATION FAILED: finalization event details must be scalar metadata", file=sys.stderr)
            raise SystemExit(1)
        cmd = [
            sys.executable, str(writer),
            "--workspace-dir", str(self.workspace),
            "--event", event,
            "--stage", stage,
            "--status", status,
            "--transition-kind", transition_kind,
            "--event-status", event_status,
            "--message", message,
            "--json",
        ]
        if self.state_revision is None:
            cmd.extend(["--protocol-mode", "legacy-r1"])
            cmd.append("--accept-current-revision")
        else:
            cmd.extend(["--expected-state-revision", str(self.state_revision)])
        if blocker:
            cmd.extend(["--blocker", blocker])
        if resume_step:
            cmd.extend(["--resume-step", resume_step])
        if reason_code:
            cmd.extend(["--reason-code", reason_code])
        for subject in subjects or []:
            cmd.extend(["--subject", subject])
        for evidence_ref in evidence_refs or []:
            cmd.extend(["--evidence-ref", evidence_ref])
        for next_action in next_actions or []:
            cmd.extend(["--next-action-json", json.dumps(next_action, ensure_ascii=False, sort_keys=True)])
        details_payload: dict[str, Any] = {"summary": message}
        if reason_detail:
            details_payload["reason_detail"] = reason_detail
        if details:
            details_payload["metadata"] = [
                {"key": key, "value": value}
                for key, value in sorted(details.items())
            ]
        cmd.extend(["--details-json", json.dumps(details_payload, ensure_ascii=False, sort_keys=True)])
        proc = subprocess.run(cmd, capture_output=True, text=True)
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            payload = {}
        if proc.returncode != 0 or not payload.get("ok"):
            output = ((proc.stdout or "") + (proc.stderr or "")).strip()[:800]
            print(f"FINALIZATION FAILED: audit event writer failed for {event}: {output}", file=sys.stderr)
            raise SystemExit(1)
        if payload.get("mode") == "r2":
            revision = payload.get("state_revision")
            if type(revision) is not int:
                print("FINALIZATION FAILED: R2 writer did not return state_revision", file=sys.stderr)
                raise SystemExit(1)
            self.state_revision = revision
        self.current_stage = stage
        self.current_status = status


_EVENT_WRITER: _FinalizationEventWriter | None = None


def write_event(
    workspace: Path,
    event: str,
    stage: str,
    status: str,
    event_status: str,
    message: str,
    blocker: str = "",
    resume_step: str = "",
    *,
    transition_kind: str,
    reason_code: str = "",
    reason_detail: str = "",
    subjects: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    next_actions: list[dict[str, Any]] | None = None,
    **details: Any,
) -> None:
    if _EVENT_WRITER is None:
        print("FINALIZATION FAILED: audit event writer is not initialized", file=sys.stderr)
        raise SystemExit(1)
    _EVENT_WRITER.write(
        event,
        stage,
        status,
        event_status,
        message,
        blocker,
        resume_step,
        transition_kind=transition_kind,
        reason_code=reason_code,
        reason_detail=reason_detail,
        subjects=subjects,
        evidence_refs=evidence_refs,
        next_actions=next_actions,
        **details,
    )


def run_bundle_validator(workspace: Path, confirmed_dir: Path,
                         language: str) -> dict[str, Any]:
    validator = workspace / "bin" / "validate-all-report-bundles.py"
    if not validator.exists():
        validator = Path(__file__).resolve().parent / "validate_all_report_bundles.py"
    if not validator.exists():
        return {"error": "validate_all_report_bundles.py not found"}
    cmd = [
        sys.executable, str(validator),
        "--confirmed-dir", str(confirmed_dir),
        "--language", language,
        "--json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return {
            "error": "validator did not produce valid JSON",
            "exit_code": proc.returncode,
            "output": ((proc.stdout or "") + (proc.stderr or "")).strip()[:500],
        }


def find_report_validator(workspace: Path) -> Path | None:
    validator = workspace / "bin" / "validate-report-bundle.py"
    if validator.exists():
        return validator
    validator = Path(__file__).resolve().parent / "validate_report_bundle.py"
    if validator.exists():
        return validator
    return None


def run_single_report_validator(workspace: Path, flag: str, path: Path) -> dict[str, Any]:
    validator = find_report_validator(workspace)
    if validator is None:
        return {"ok": False, "error": "validate_report_bundle.py not found"}
    proc = subprocess.run(
        [sys.executable, str(validator), "--workspace-dir", str(workspace), flag, str(path)],
        capture_output=True,
        text=True,
    )
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "output": output[:800],
    }


def validate_seeded_variant_discovery(workspace: Path) -> dict[str, Any]:
    variant_dir = workspace / "evidence" / "variant-analysis"
    seeds_path = variant_dir / "seeds.jsonl"
    candidates_path = variant_dir / "variant-candidates.jsonl"
    errors: list[str] = []

    if not variant_dir.is_dir():
        errors.append(
            "missing evidence/variant-analysis/; run seeded variant discovery from a validated confirmed bundle before finalization."
        )
    if not seeds_path.is_file():
        errors.append(
            "missing evidence/variant-analysis/seeds.jsonl; run extract_variant_seed.py and validate the final seed card."
        )
    if not candidates_path.is_file():
        errors.append(
            "missing evidence/variant-analysis/variant-candidates.jsonl; run find_variant_candidates.py and validate candidate-only output."
        )

    seed_validation: dict[str, Any] = {}
    candidate_validation: dict[str, Any] = {}
    if seeds_path.is_file():
        seed_validation = run_single_report_validator(workspace, "--variant-seed-card", seeds_path)
        if not seed_validation.get("ok"):
            errors.append(
                "variant seed validation failed: "
                + str(seed_validation.get("error") or seed_validation.get("output") or "unknown error")
            )
    if candidates_path.is_file():
        candidate_validation = run_single_report_validator(workspace, "--variant-candidates", candidates_path)
        if not candidate_validation.get("ok"):
            errors.append(
                "variant candidates validation failed: "
                + str(candidate_validation.get("error") or candidate_validation.get("output") or "unknown error")
            )

    return {
        "ok": not errors,
        "errors": errors,
        "variant_dir": "evidence/variant-analysis",
        "seeds": "evidence/variant-analysis/seeds.jsonl",
        "variant_candidates": "evidence/variant-analysis/variant-candidates.jsonl",
        "seed_validation": seed_validation,
        "candidate_validation": candidate_validation,
    }


def run_docker_verify_clean(workspace: Path, *, strict: bool) -> dict[str, Any]:
    helper = workspace / "bin" / "manage-docker-resources.py"
    if not helper.exists():
        helper = Path(__file__).resolve().parent / "manage_docker_resources.py"
    if not helper.exists():
        return {"clean": False, "error": "manage_docker_resources.py not found"}
    baseline = workspace / "docker" / "docker-resource-baseline.json"
    if not baseline.exists():
        return {"clean": False, "error": "docker-resource-baseline.json missing; cannot verify Docker cleanliness"}
    cmd = [
        sys.executable, str(helper),
        "--workspace-dir", str(workspace),
        "--verify-clean",
    ]
    if strict:
        cmd.append("--strict")
    status_path = workspace / "docker" / "docker-cleanliness-status.json"
    status_mtime_before = status_path.stat().st_mtime_ns if status_path.exists() else None
    proc = subprocess.run(cmd, capture_output=True, text=True)
    status_refreshed = (
        status_path.exists()
        and (
            status_mtime_before is None
            or status_path.stat().st_mtime_ns != status_mtime_before
        )
    )
    if status_refreshed:
        return load_json(status_path)
    return {
        "clean": False,
        "exit_code": proc.returncode,
        "error": "Docker cleanliness helper did not refresh docker-cleanliness-status.json; refusing to trust stale status",
        "output": ((proc.stdout or "") + (proc.stderr or "")).strip()[:500],
    }


def refresh_handoff(workspace: Path, repo_root: Path) -> bool:
    renderer = workspace / "bin" / "render-handoff-summary.py"
    if not renderer.exists():
        renderer = Path(__file__).resolve().parent / "render_handoff_summary.py"
    if not renderer.exists():
        return False
    cmd = [
        sys.executable, str(renderer),
        "--workspace-dir", str(workspace),
        "--repo-root", str(repo_root),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode == 0


def runtime_hygiene_summary_line(workspace: Path, *, language: str) -> str:
    status = load_json(workspace / "runtime/runtime-hygiene-status.json")
    if not status:
        if language == "en-US":
            return "- OMC runtime hygiene: `not_recorded`; run `bin/check_omc_runtime.sh --json` before `/team` or `/ultrawork`.\n"
        return "- OMC runtime hygiene：`not_recorded`；使用 `/team` 或 `/ultrawork` 前运行 `bin/check_omc_runtime.sh --json`。\n"

    mode = str(status.get("recommended_mode") or "unknown")
    clean = bool(status.get("clean"))
    unresolved = status.get("unresolved_review_only")
    unresolved_count = len(unresolved) if isinstance(unresolved, list) else 0
    resume_step = str(status.get("resume_step") or "")
    attention_needed = mode == "cleanup_needed" or unresolved_count > 0 or not clean

    if language == "en-US":
        if attention_needed:
            return (
                f"- OMC runtime hygiene: `{mode}`; attention needed before `/team` or `/ultrawork`; "
                f"unresolved review-only: `{unresolved_count}`; teammate PID cleanup is manual outside Zhulong; "
                f"resume: {resume_step or '_none_'}\n"
            )
        return f"- OMC runtime hygiene: `{mode}`; clean: `{str(clean).lower()}`.\n"

    if attention_needed:
        return (
            f"- OMC runtime hygiene：`{mode}`；使用 `/team` 或 `/ultrawork` 前需要处理；"
            f"unresolved review-only：`{unresolved_count}`；teammate PID 只能由操作员在 Zhulong 外手动处理；"
            f"resume：{resume_step or '_none_'}\n"
        )
    return f"- OMC runtime hygiene：`{mode}`；clean：`{str(clean).lower()}`。\n"


def workspace_summary_content(
    workspace: Path,
    *,
    result: str,
    validated_count: int,
    docker_clean: bool,
    docker_strict: bool,
    language: str,
) -> str:
    placeholder_marker = "<!-- zhulong_completion_summary_placeholder: 1 -->"
    config = load_json(workspace / "asr-config.json")
    configured_language = str(config.get("summary_language") or config.get("output_language") or "").strip()
    effective_language = configured_language if language == "auto" and configured_language else language
    runtime_line = runtime_hygiene_summary_line(workspace, language=effective_language)
    if effective_language == "en-US":
        return (
            f"{placeholder_marker}\n"
            "# Audit Summary\n\n"
            "This summary was prepared from validated finalization inputs. Completion authority remains "
            "the canonical finalization event. Expand this placeholder with the final human-facing audit summary.\n\n"
            f"- Result: `{result}`\n"
            f"- Validated confirmed bundles: `{validated_count}`\n"
            f"- Docker clean: `{str(docker_clean).lower()}`\n"
            f"- Docker strict clean: `{str(docker_strict).lower()}`\n"
            f"{runtime_line}"
            "- Confirmed-output guardrail: scanner-only, dependency-only, static-only, unverified, blocked, "
            "or timed-out findings are not confirmed vulnerabilities.\n"
        )
    else:
        return (
            f"{placeholder_marker}\n"
            "# 审计总结\n\n"
            "本总结根据已通过校验的收尾输入生成；审计完成权限仍只来自 canonical finalization event。"
            "请在该占位内容上补充面向人的最终审计总结，不要只保留在聊天或终端日志中。\n\n"
            f"- 完成结果：`{result}`\n"
            f"- 已验证 confirmed bundles：`{validated_count}`\n"
            f"- Docker clean：`{str(docker_clean).lower()}`\n"
            f"- Docker strict clean：`{str(docker_strict).lower()}`\n"
            f"{runtime_line}"
            "- confirmed-only 约束：scanner-only、dependency-only、static-only、unverified、blocked、"
            "timed-out 结果都不是确认漏洞。\n"
        )


def ensure_workspace_summary(
    workspace: Path,
    *,
    result: str,
    validated_count: int,
    docker_clean: bool,
    docker_strict: bool,
    language: str,
) -> Path:
    summary_path = workspace / "SUMMARY.md"
    placeholder_marker = "<!-- zhulong_completion_summary_placeholder: 1 -->"
    if os.path.lexists(summary_path):
        existing = safe_read_bytes(workspace, summary_path).decode("utf-8", errors="ignore")
        if placeholder_marker not in existing:
            return summary_path
    content = workspace_summary_content(
        workspace,
        result=result,
        validated_count=validated_count,
        docker_clean=docker_clean,
        docker_strict=docker_strict,
        language=language,
    )
    atomic_write_bytes(workspace, summary_path, content.encode("utf-8"))
    return summary_path


def validate_completed_rerun(
    workspace: Path,
    repo_root: Path,
    *,
    result: str,
) -> dict[str, Any]:
    """Validate an already completed workspace without writing or probing Docker."""
    from assert_finalized_workspace import validate_finalization

    summary_raw = safe_read_bytes(workspace, workspace / "SUMMARY.md")
    handoff_raw = safe_read_bytes(workspace, workspace / "handoff-summary.md")
    current_handoff = validate_handoff_state_current(workspace, repo_root)
    if not current_handoff.get("ok"):
        codes = ",".join(str(code) for code in current_handoff.get("issue_codes", [])) or "unknown"
        raise AuditStateError("COMPLETED_WORKSPACE_DRIFT", f"handoff-state.json is not current [{codes}]")
    handoff_state = read_handoff_state(workspace)
    snapshot = read_workspace_snapshot(workspace)
    expected_handoff = render_handoff_summary(
        workspace,
        repo_root,
        workspace / "handoff-summary.md",
        snapshot_override=snapshot,
        handoff_state_override=handoff_state,
    ).encode("utf-8")
    if handoff_raw != expected_handoff:
        raise AuditStateError("COMPLETED_WORKSPACE_DRIFT", "handoff-summary.md differs from the current derived view")

    ok, errors, finalization = validate_finalization(workspace)
    if not ok:
        raise AuditStateError(
            "COMPLETED_WORKSPACE_DRIFT",
            str(errors[0]) if errors else "finalization assertion failed",
        )
    recorded_result = str(finalization.get("result") or "")
    if recorded_result != result:
        raise AuditStateError(
            "COMPLETED_RESULT_MISMATCH",
            f"requested result={result} differs from completed result={recorded_result or 'unknown'}",
        )

    marker = b"<!-- zhulong_completion_summary_placeholder: 1 -->"
    if marker in summary_raw:
        summary_text = summary_raw.decode("utf-8", errors="strict")
        summary_language = "en-US" if "# Audit Summary" in summary_text else "zh-CN"
        expected_summary = workspace_summary_content(
            workspace,
            result=recorded_result,
            validated_count=int(finalization.get("workspace_state", {}).get("validated_confirmed_bundle_count") or 0),
            docker_clean=bool(finalization.get("docker_clean")),
            docker_strict=bool(finalization.get("docker_strict")),
            language=summary_language,
        ).encode("utf-8")
        if summary_raw != expected_summary:
            raise AuditStateError("COMPLETED_WORKSPACE_DRIFT", "generated SUMMARY.md differs from validated finalization inputs")
    return finalization


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Zhulong audit workspace completion gate. "
            "Validates that bundle state, Docker cleanliness, stage-status.json, "
            "and handoff-summary.md are consistent before declaring an audit finished."
        ),
    )
    parser.add_argument("--workspace-dir", required=True,
                        help="Path to the Zhulong audit workspace.")
    parser.add_argument("--language", choices=["zh-CN", "en-US", "auto"], default="auto",
                        help="Language for bundle validation.")
    parser.add_argument("--result", required=True,
                        choices=sorted(VALID_RESULTS),
                        help="Expected completion result.")
    parser.add_argument("--confirmed-dir", default="",
                        help="Path to confirmed/ directory. Defaults to <workspace>/confirmed.")
    return parser.parse_args()


def main() -> int:
    global _EVENT_WRITER
    args = parse_args()
    workspace = Path(args.workspace_dir).expanduser().resolve()
    if not workspace.is_dir():
        print(f"FINALIZATION FAILED: workspace does not exist: {workspace}", file=sys.stderr)
        return 1
    if not (workspace / "asr-config.json").exists():
        print(f"FINALIZATION FAILED: not a Zhulong audit workspace: {workspace}", file=sys.stderr)
        return 1

    repo_root = workspace.parent.resolve()
    confirmed_dir = Path(args.confirmed_dir).expanduser().resolve() if args.confirmed_dir else workspace / "confirmed"
    result = args.result
    language = args.language
    errors: list[str] = []
    blocked_summary: dict[str, Any] = {}
    _EVENT_WRITER = _FinalizationEventWriter(workspace)

    if _EVENT_WRITER.current_status == "completed":
        try:
            completed = validate_completed_rerun(workspace, repo_root, result=result)
        except SafeEvidenceError as exc:
            print(f"FINALIZATION FAILED: completed workspace artifact is unsafe [{exc.code}]", file=sys.stderr)
            return 1
        except (AuditStateError, UnicodeError) as exc:
            code = exc.code if isinstance(exc, AuditStateError) else "COMPLETED_WORKSPACE_DRIFT"
            message = exc.message if isinstance(exc, AuditStateError) else "completed workspace artifact is not valid UTF-8"
            print(
                f"FINALIZATION FAILED [{code}]: {message}; explicitly recover or reopen the workspace before rerunning",
                file=sys.stderr,
            )
            return 1
        print(f"result={result}")
        print(
            "validated_bundles="
            + str(int(completed.get("workspace_state", {}).get("validated_confirmed_bundle_count") or 0))
        )
        print(f"docker_clean={str(bool(completed.get('docker_clean'))).lower()}")
        print("summary=SUMMARY.md")
        print("stage=completed")
        print(f"FINALIZATION PASSED: {workspace}")
        return 0

    initial_transition_kind = (
        "observe"
        if _EVENT_WRITER.current_stage == "finalization" and _EVENT_WRITER.current_status == "running"
        else "advance"
    )
    write_event(
        workspace,
        "finalization_started",
        "finalization",
        "running",
        "started",
        f"Completion gate started with result={result}.",
        transition_kind=initial_transition_kind,
        expected_result=result,
    )

    # --- Step 1: Bundle validation ---
    inspected_state = inspect_workspace_state(
        workspace,
        confirmed_dir=confirmed_dir,
        language=language,
    )
    bundle_summary: dict[str, Any] = {
        "summary": inspected_state.get("validator_summary", {}),
        "results": inspected_state.get("results", []),
    }
    validated_count = int(inspected_state.get("validated_confirmed_bundle_count") or 0)
    partial_count = int(inspected_state.get("partial_confirmed_bundle_count") or 0)
    failed_count = int(inspected_state.get("validation_failed_bundle_count") or 0)
    if inspected_state.get("validator_error"):
        errors.append(f"Bundle validation error: {inspected_state['validator_error']}")

    write_event(
        workspace,
        "bundle_validation_outcome",
        "finalization",
        "running",
        "ok" if not errors else "warning",
        f"Bundles: validated={validated_count}, partial={partial_count}, failed={failed_count}.",
        transition_kind="observe",
        validated=validated_count,
        partial=partial_count,
        failed=failed_count,
    )

    # --- Step 2: Check result vs bundle state ---
    if result == "completed_with_confirmed_bundles":
        if validated_count == 0:
            errors.append(
                "result=completed_with_confirmed_bundles requires at least one validated confirmed bundle, "
                f"but found {validated_count}."
            )
        if partial_count > 0:
            errors.append(
                f"Cannot finalize: {partial_count} partial confirmed bundle(s) exist. "
                "Complete or remove them before finalizing."
            )
        if failed_count > 0:
            errors.append(
                f"Cannot finalize: {failed_count} bundle(s) failed validation. "
                "Fix or remove them before finalizing."
            )
        if validated_count > 0 and partial_count == 0 and failed_count == 0:
            variant_summary = {
                "ok": inspected_state.get("formal_variant_analysis_status") == "completed",
                "errors": inspected_state.get("errors", []),
                "variant_dir": inspected_state.get("variant_dir"),
                "seeds": inspected_state.get("seeds"),
                "variant_candidates": inspected_state.get("variant_candidates"),
                "seed_validation": inspected_state.get("seed_validation", {}),
                "candidate_validation": inspected_state.get("candidate_validation", {}),
            }
            if not variant_summary.get("ok"):
                for error in variant_summary.get("errors", []):
                    errors.append(f"Seeded variant discovery gate: {error}")
            write_event(
                workspace,
                "seeded_variant_discovery_outcome",
                "finalization",
                "running",
                "ok" if variant_summary.get("ok") else "warning",
                (
                    "Seeded variant discovery artifacts checked: "
                    f"ok={str(bool(variant_summary.get('ok'))).lower()}."
                ),
                transition_kind="observe",
                variant_ok=bool(variant_summary.get("ok")),
            )
    elif result == "completed_no_confirmed_findings":
        if validated_count > 0:
            errors.append(
                f"result=completed_no_confirmed_findings but {validated_count} validated bundle(s) exist. "
                "Use completed_with_confirmed_bundles instead."
            )
        if partial_count > 0:
            errors.append(
                f"Cannot finalize with no-confirmed-findings: {partial_count} partial confirmed bundle(s) exist. "
                "Complete or remove them before finalizing."
            )
        if failed_count > 0:
            errors.append(
                f"Cannot finalize with no-confirmed-findings: {failed_count} bundle(s) failed validation. "
                "Fix or remove them before finalizing."
            )
        blocked_summary = detect_blocked_verification(workspace)
        if blocked_summary.get("blocked"):
            resume_step = str(blocked_summary.get("resume_step") or "")
            evidence = blocked_summary.get("findings") or []
            first_evidence = ""
            if evidence and isinstance(evidence[0], dict):
                first_evidence = (
                    f"{evidence[0].get('source')}:{evidence[0].get('line')} "
                    f"{evidence[0].get('excerpt')}"
                )
            errors.append(
                "Blocked Docker/runtime verification prevents completed_no_confirmed_findings. "
                "This is blocked_verification, not a terminal no-confirmed state. "
                f"Resume step: {resume_step or 'resolve the Docker/runtime blocker and rerun Docker verification.'} "
                f"Evidence: {first_evidence or 'see candidate-findings.md, unverified-leads.md, or attack-surface.md.'}"
            )

    # --- Step 3: Audit disposition ledger ---
    if not blocked_summary:
        blocked_summary = detect_blocked_verification(workspace)
    protocol_mode = "legacy_r1" if _EVENT_WRITER.state_revision is None else "r2"
    disposition_ledger = synthesize_disposition_ledger(workspace, blocked_summary=blocked_summary)
    try:
        write_disposition_ledger(
            workspace,
            disposition_ledger,
            result=result,
            bundle_summary=bundle_summary,
            language=language,
            protocol_mode=protocol_mode,
        )
        disposition_ledger = load_disposition_ledger(workspace)
        disposition_validation = validate_disposition_ledger(
            workspace,
            result=result,
            ledger=disposition_ledger,
            bundle_summary=bundle_summary,
            language=language,
        )
    except DispositionUpdateError as exc:
        errors.append(str(exc))
        disposition_validation = {"ok": False, "errors": [str(exc)], "summary": {"item_count": 0}}
    except SafeEvidenceError as exc:
        message = f"{LEDGER_FILENAME} safe write failed [{exc.code}]"
        errors.append(message)
        disposition_validation = {"ok": False, "errors": [message], "summary": {"item_count": 0}}
    disposition_summary = disposition_validation.get("summary", {})
    if not disposition_validation.get("ok"):
        for error in disposition_validation.get("errors", []):
            errors.append(f"{LEDGER_FILENAME}: {error}")

    authority_chain = validate_workspace_confirmation_chain(
        workspace,
        result=result,
        protocol_mode=protocol_mode,
        ledger=disposition_ledger,
        bundle_summary=bundle_summary,
        disposition_validation=disposition_validation,
        language=language,
    )
    if not authority_chain.get("ok"):
        for error in authority_chain.get("errors", []):
            errors.append(f"completion authority chain: {error}")

    write_event(
        workspace,
        "audit_disposition_outcome",
        "finalization",
        "running",
        "ok" if disposition_validation.get("ok") else "warning",
        (
            f"Audit disposition ledger: items={disposition_summary.get('item_count', 0)}, "
            f"unresolved={disposition_summary.get('unresolved_count', 0)}."
        ),
        transition_kind="observe",
        ledger=LEDGER_FILENAME,
        validation_ok=bool(disposition_validation.get("ok")),
        disposition_items=int(disposition_summary.get("item_count") or 0),
        disposition_unresolved=int(disposition_summary.get("unresolved_count") or 0),
    )

    # --- Step 4: Docker strict cleanliness ---
    docker_status = run_docker_verify_clean(workspace, strict=True)
    docker_evidence = validate_current_strict_docker_cleanliness(workspace)
    helper_clean = docker_status.get("clean") is True and docker_status.get("strict") is True
    docker_clean = helper_clean and bool(docker_evidence.get("ok"))
    if not helper_clean:
        helper_error = str(docker_status.get("error") or docker_status.get("output") or "strict Docker cleanliness helper did not report clean=true and strict=true")
        errors.append(f"Docker cleanliness check failed: {helper_error}")
    if not docker_clean:
        docker_errors = docker_evidence.get("errors") or []
        docker_error = docker_status.get("error", "")
        if docker_errors:
            errors.extend(f"Docker cleanliness check failed: {error}" for error in docker_errors)
        elif docker_error:
            errors.append(f"Docker cleanliness check failed: {docker_error}")
        else:
            errors.append(
                "Docker strict cleanliness check failed. "
                "Run manage-docker-resources.py --cleanup-created --apply and --verify-clean --strict."
            )

    docker_strict = bool(docker_status.get("strict", True))
    summary_path = workspace / "SUMMARY.md"
    if not errors:
        try:
            summary_path = ensure_workspace_summary(
                workspace,
                result=result,
                validated_count=validated_count,
                docker_clean=bool(docker_clean),
                docker_strict=docker_strict,
                language=language,
            )
        except SafeEvidenceError as exc:
            errors.append(f"SUMMARY.md safe write failed [{exc.code}]")
        except (OSError, UnicodeError) as exc:
            errors.append(f"SUMMARY.md publication failed: {type(exc).__name__}")

    # --- Step 5: Decide pass/fail ---
    if errors:
        error_text = "; ".join(errors)
        if blocked_summary.get("blocked"):
            blocker = "blocked_verification"
            resume_step = str(blocked_summary.get("resume_step") or "Resolve the Docker/runtime blocker and rerun Docker verification.")
            write_event(
                workspace,
                "finalization_returned_to_verification",
                "verification",
                "running",
                "returned",
                "Completion gate returned unresolved work to verification.",
                transition_kind="return",
                reason_code="verification_blocked",
                reason_detail="Completion cannot finish while Docker/runtime verification remains blocked.",
                subjects=["run:finalization"],
                evidence_refs=[LEDGER_FILENAME],
                next_actions=[
                    {
                        "action_id": "resume-verification",
                        "action_type": "verify",
                        "subject_ids": ["run:finalization"],
                        "summary": "Resolve the recorded verification blocker and rerun Docker-only verification.",
                        "evidence_refs": [LEDGER_FILENAME],
                    }
                ],
            )
            write_event(
                workspace,
                "finalization_failed",
                "verification",
                "blocked",
                "failed",
                f"Completion gate failed: {error_text}",
                blocker=blocker,
                resume_step=resume_step,
                transition_kind="block",
                reason_code="verification_blocked",
                evidence_refs=[LEDGER_FILENAME],
                error_count=len(errors),
                expected_result=result,
            )
        else:
            write_event(
                workspace,
                "finalization_failed",
                "finalization",
                "running",
                "failed",
                f"Completion gate failed: {error_text}",
                transition_kind="observe",
                error_count=len(errors),
                expected_result=result,
            )
        print(f"FINALIZATION FAILED: {error_text}", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        if blocked_summary.get("blocked"):
            print("  - blocked_verification resume_step: " + str(blocked_summary.get("resume_step") or ""), file=sys.stderr)
        refresh_handoff(workspace, repo_root)
        return 1

    # --- Step 6: Publish projected derived artifacts, then commit terminal state ---
    def prepare_terminal_artifacts(projected: WorkspaceSnapshot) -> None:
        try:
            document = derive_handoff_state(
                workspace,
                repo_root,
                snapshot_override=projected,
            )
            if document.get("integrity", {}).get("overall") != "valid":
                issues = document.get("integrity", {}).get("issues") or []
                first = str(issues[0].get("message") or issues[0].get("code")) if issues and isinstance(issues[0], dict) else "unknown"
                raise AuditStateError("FINALIZATION_HANDOFF_INVALID", f"projected handoff integrity failed: {first}")
            publish_handoff_state_document(workspace, document)
            if read_handoff_state(workspace) != document:
                raise AuditStateError("FINALIZATION_HANDOFF_DRIFT", "published handoff-state.json differs from its projected document")
            rendered = render_handoff_summary(
                workspace,
                repo_root,
                workspace / "handoff-summary.md",
                snapshot_override=projected,
                handoff_state_override=document,
            )
            publish_handoff_summary(workspace / "handoff-summary.md", rendered)
            disk_handoff = safe_read_bytes(workspace, workspace / "handoff-summary.md")
            if disk_handoff != rendered.encode("utf-8"):
                raise AuditStateError("FINALIZATION_HANDOFF_DRIFT", "published handoff-summary.md differs from its projected document")
            consistency = validate_handoff_status_consistency(
                workspace,
                state=inspected_state,
                language=language,
                snapshot_override=projected,
                handoff_text=disk_handoff.decode("utf-8", errors="strict"),
            )
            if not consistency.get("ok"):
                consistency_errors = consistency.get("errors") or []
                raise AuditStateError(
                    "FINALIZATION_HANDOFF_INCONSISTENT",
                    str(consistency_errors[0]) if consistency_errors else "projected handoff consistency failed",
                )
        except SafeEvidenceError as exc:
            raise AuditStateError(
                "FINALIZATION_DERIVED_ARTIFACT_FAILED",
                f"derived artifact safe I/O failed [{exc.code}]",
            ) from exc
        except UnicodeError as exc:
            raise AuditStateError(
                "FINALIZATION_DERIVED_ARTIFACT_FAILED",
                "derived handoff artifact is not valid UTF-8",
            ) from exc

    if _EVENT_WRITER is None:
        print("FINALIZATION FAILED: audit event writer is not initialized", file=sys.stderr)
        return 1
    _EVENT_WRITER.commit_terminal(
        result=result,
        validated_count=validated_count,
        docker_clean=docker_clean,
        docker_evidence=docker_evidence,
        prepare_artifacts=prepare_terminal_artifacts,
    )

    # --- Step 7: Read-only post-terminal assertions ---
    post_errors: list[str] = []
    current_handoff = validate_handoff_state_current(workspace, repo_root)
    if not current_handoff.get("ok"):
        post_errors.append(
            "handoff-state.json is not current ["
            + (",".join(str(code) for code in current_handoff.get("issue_codes", [])) or "unknown")
            + "]"
        )
    from assert_finalized_workspace import validate_finalization
    finalized_ok, finalized_errors, finalized_summary = validate_finalization(workspace)
    if not finalized_ok:
        post_errors.extend(str(error) for error in finalized_errors)
    elif finalized_summary.get("result") != result:
        post_errors.append("finalization assertion result differs from the requested result")
    final_consistency = validate_handoff_status_consistency(
        workspace,
        state=inspect_workspace_state(workspace, confirmed_dir=confirmed_dir, language=language),
        language=language,
    )
    if not final_consistency.get("ok"):
        post_errors.extend(str(error) for error in final_consistency.get("errors", []))
    if post_errors:
        print(
            "FINALIZATION PARTIAL: terminal event committed but a read-only assertion failed: "
            + post_errors[0]
            + "; explicitly recover or reopen the workspace",
            file=sys.stderr,
        )
        return 1

    # --- Output ---
    print(f"result={result}")
    print(f"validated_bundles={validated_count}")
    print(f"docker_clean={str(docker_clean).lower()}")
    print(f"summary={summary_path.relative_to(workspace).as_posix()}")
    print(f"stage=completed")
    print(f"FINALIZATION PASSED: {workspace}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
