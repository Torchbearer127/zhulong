#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audit_text_safety import first_sensitive_document_text, tested_ref_value_kind

from audit_state_io import (
    AuditStateError,
    normalize_event,
    read_normalized_workspace_events,
    read_workspace_snapshot,
    workspace_lock,
)
from blocked_verification import detect_blocked_verification


CONFIRMED_BUNDLE_SUCCESS = "completed_with_confirmed_bundles"
NO_CONFIRMED_SUCCESS = "completed_no_confirmed_findings"


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _jsonl_count(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            count += 1
    return count


def _rel(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return str(path)


def _script_path(workspace: Path, workspace_name: str, source_name: str) -> Path | None:
    candidates = [
        workspace / "bin" / workspace_name,
        Path(__file__).resolve().parent / source_name,
    ]
    return next((path for path in candidates if path.exists()), None)


def confirmed_bundle_dirs(confirmed_dir: Path) -> list[Path]:
    if not confirmed_dir.exists() or not confirmed_dir.is_dir():
        return []
    return sorted(
        path for path in confirmed_dir.iterdir()
        if path.is_dir() and not path.name.startswith(".")
    )


def _run_validate_all(
    workspace: Path,
    confirmed_dir: Path,
    language: str,
) -> dict[str, Any]:
    validator = _script_path(
        workspace,
        "validate-all-report-bundles.py",
        "validate_all_report_bundles.py",
    )
    if validator is None:
        return {"error": "validate_all_report_bundles.py not found"}
    proc = subprocess.run(
        [
            sys.executable,
            str(validator),
            "--confirmed-dir",
            str(confirmed_dir),
            "--language",
            language,
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    try:
        payload = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return {
            "error": "validator did not produce valid JSON",
            "exit_code": proc.returncode,
            "output": ((proc.stdout or "") + (proc.stderr or "")).strip()[:800],
        }
    payload["exit_code"] = proc.returncode
    if proc.stderr:
        payload["stderr"] = proc.stderr.strip()[:800]
    return payload


def inspect_confirmed_bundles(
    workspace: Path,
    *,
    confirmed_dir: Path | None = None,
    language: str = "auto",
) -> dict[str, Any]:
    confirmed_root = confirmed_dir or workspace / "confirmed"
    dirs = confirmed_bundle_dirs(confirmed_root)
    empty_counts = {
        "bundle_validated": 0,
        "partial_confirmed_bundle": 0,
        "validation_failed": 0,
        "ignored_helper_file": 0,
    }
    if not dirs:
        return {
            "confirmed_dir": str(confirmed_root),
            "confirmed_bundle_dirs_total": 0,
            "validated_confirmed_bundle_count": 0,
            "invalid_or_partial_confirmed_bundle_count": 0,
            "partial_confirmed_bundle_count": 0,
            "validation_failed_bundle_count": 0,
            "results": [],
            "validator_summary": empty_counts,
            "validator_error": "",
        }

    payload = _run_validate_all(workspace, confirmed_root, language)
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    validated = int(summary.get("bundle_validated") or 0)
    partial = int(summary.get("partial_confirmed_bundle") or 0)
    failed = int(summary.get("validation_failed") or 0)
    return {
        "confirmed_dir": str(confirmed_root),
        "confirmed_bundle_dirs_total": len(dirs),
        "validated_confirmed_bundle_count": validated,
        "invalid_or_partial_confirmed_bundle_count": partial + failed,
        "partial_confirmed_bundle_count": partial,
        "validation_failed_bundle_count": failed,
        "results": payload.get("results") if isinstance(payload.get("results"), list) else [],
        "validator_summary": summary or empty_counts,
        "validator_error": str(payload.get("error") or ""),
        "validator_exit_code": payload.get("exit_code"),
    }


def detect_docker_evidence_only(workspace: Path) -> dict[str, Any]:
    evidence_root = workspace / "evidence"
    if not evidence_root.exists():
        return {"docker_evidence_only_count": 0, "paths": []}

    paths: set[str] = set()
    evidence_names = {
        "verification-evidence.json",
        "verifier-verdict.json",
        "docker-evidence.json",
        "docker-verification.json",
    }
    ignored_parts = {"initial-probes", "variant-analysis"}
    for path in evidence_root.rglob("*"):
        if any(part in ignored_parts for part in path.relative_to(evidence_root).parts):
            continue
        lowered_parts = [part.lower() for part in path.parts]
        is_docker_named = any("docker" in part or "verification" in part for part in lowered_parts)
        is_evidence_file = path.is_file() and path.name in evidence_names
        if not is_docker_named and not is_evidence_file:
            continue
        evidence_dir = path if path.is_dir() else path.parent
        if evidence_dir == evidence_root:
            continue
        paths.add(_rel(evidence_dir, workspace))
    return {
        "docker_evidence_only_count": len(paths),
        "paths": sorted(paths),
    }


def _run_report_validator(workspace: Path, flag: str, path: Path) -> dict[str, Any]:
    validator = _script_path(workspace, "validate-report-bundle.py", "validate_report_bundle.py")
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
        "output": output[:1000],
    }


def inspect_formal_variant_analysis(
    workspace: Path,
    *,
    validated_confirmed_bundle_count: int,
) -> dict[str, Any]:
    variant_dir = workspace / "evidence" / "variant-analysis"
    seeds_path = variant_dir / "seeds.jsonl"
    candidates_path = variant_dir / "variant-candidates.jsonl"
    errors: list[str] = []
    seed_validation: dict[str, Any] = {}
    candidate_validation: dict[str, Any] = {}

    if validated_confirmed_bundle_count <= 0:
        status = "not_applicable_no_validated_confirmed_bundle"
        if seeds_path.exists() or candidates_path.exists():
            status = "invalid_no_validated_confirmed_bundle"
            errors.append(
                "formal seeded variant discovery requires at least one validated confirmed bundle"
            )
        return {
            "formal_variant_analysis_status": status,
            "completed": False,
            "errors": errors,
            "variant_dir": "evidence/variant-analysis",
            "seeds": "evidence/variant-analysis/seeds.jsonl",
            "variant_candidates": "evidence/variant-analysis/variant-candidates.jsonl",
            "seed_count": _jsonl_count(seeds_path),
            "candidate_count": _jsonl_count(candidates_path),
            "seed_validation": seed_validation,
            "candidate_validation": candidate_validation,
        }

    if not variant_dir.is_dir():
        errors.append("missing evidence/variant-analysis/")
    if not seeds_path.is_file():
        errors.append("missing evidence/variant-analysis/seeds.jsonl")
    if not candidates_path.is_file():
        errors.append("missing evidence/variant-analysis/variant-candidates.jsonl")

    if seeds_path.is_file():
        seed_validation = _run_report_validator(workspace, "--variant-seed-card", seeds_path)
        if not seed_validation.get("ok"):
            errors.append(
                "variant seed validation failed: "
                + str(seed_validation.get("error") or seed_validation.get("output") or "unknown error")
            )
    if candidates_path.is_file():
        candidate_validation = _run_report_validator(workspace, "--variant-candidates", candidates_path)
        if not candidate_validation.get("ok"):
            errors.append(
                "variant candidates validation failed: "
                + str(candidate_validation.get("error") or candidate_validation.get("output") or "unknown error")
            )

    if errors:
        status = "invalid" if seed_validation or candidate_validation else "not_executed"
    else:
        status = "completed"
    return {
        "formal_variant_analysis_status": status,
        "completed": status == "completed",
        "errors": errors,
        "variant_dir": "evidence/variant-analysis",
        "seeds": "evidence/variant-analysis/seeds.jsonl",
        "variant_candidates": "evidence/variant-analysis/variant-candidates.jsonl",
        "seed_count": _jsonl_count(seeds_path),
        "candidate_count": _jsonl_count(candidates_path),
        "seed_validation": seed_validation,
        "candidate_validation": candidate_validation,
    }


def inspect_workspace_state(
    workspace: Path,
    *,
    confirmed_dir: Path | None = None,
    language: str = "auto",
) -> dict[str, Any]:
    bundle_state = inspect_confirmed_bundles(workspace, confirmed_dir=confirmed_dir, language=language)
    docker_state = detect_docker_evidence_only(workspace)
    variant_state = inspect_formal_variant_analysis(
        workspace,
        validated_confirmed_bundle_count=int(bundle_state["validated_confirmed_bundle_count"]),
    )
    state = {
        **bundle_state,
        **docker_state,
        **variant_state,
    }
    if (
        state["validated_confirmed_bundle_count"] == 0
        and state["docker_evidence_only_count"] > 0
    ):
        state["handoff_state"] = "docker_evidence_collected_but_no_bundle"
    elif state["validated_confirmed_bundle_count"] > 0:
        state["handoff_state"] = "validated_confirmed_bundle_available"
    else:
        state["handoff_state"] = "no_validated_confirmed_bundle"
    return state


def _completion_result_from_authority(
    status: dict[str, Any],
    events: list[dict[str, Any]],
    *,
    protocol_mode: str,
) -> str:
    """Return the canonical completion result without inventing R2 state fields.

    Legacy R1 workspaces stored the completion claim directly on their state
    view.  R2 deliberately keeps that view rebuildable, so its authoritative
    claim is the string-valued ``result`` metadata of the latest finalization
    terminal event.  Callers must pass events already normalized by
    :func:`normalize_event`; this helper does not reimplement metadata
    flattening or infer completion from advisory material.
    """
    if protocol_mode == "legacy_r1":
        for key in ("result", "completion_result"):
            value = status.get(key)
            if isinstance(value, str):
                return value.strip()
        for event in reversed(events):
            if event.get("event") != "finalization_succeeded":
                continue
            details = event.get("details")
            if not isinstance(details, dict):
                continue
            value = details.get("result")
            if isinstance(value, str):
                return value.strip()
        return ""

    if protocol_mode != "r2":
        return ""

    for event in reversed(events):
        event_name = event.get("event")
        if event_name == "finalization_failed":
            # The existing finalization status logic owns a later failure; an
            # earlier success must not create a current completion claim.
            return ""
        if event_name != "finalization_succeeded":
            continue
        details = event.get("details")
        if not isinstance(details, dict):
            return ""
        value = details.get("result")
        return value.strip() if isinstance(value, str) else ""
    return ""


def _completion_source_from_protocol(protocol_mode: str) -> tuple[str | None, str]:
    """Describe the stable workspace-relative source of a completion result."""
    if protocol_mode == "r2":
        return "audit-events.jsonl", "finalization_succeeded event completion result"
    if protocol_mode == "legacy_r1":
        return "stage-status.json", "legacy stage-status.json completion result"
    return None, "completion result"


def _unsafe_claim_lines(text: str, *, validated_count: int) -> list[str]:
    issues: list[str] = []
    if validated_count > 0:
        return issues
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        lowered = line.lower()
        safe_negative = any(
            phrase in lowered
            for phrase in (
                "not applicable",
                "not executed",
                "not ready",
                "no validated",
                "no confirmed",
                "cannot",
                "must not",
                "not a confirmed",
                "不是",
                "不能",
                "不得",
                "未完成",
                "未执行",
            )
        )
        if CONFIRMED_BUNDLE_SUCCESS in line:
            issues.append(f"handoff-summary.md:{line_no}: claims {CONFIRMED_BUNDLE_SUCCESS} with zero validated bundles")
            continue
        if re.search(r"\b(?:validated\s+)?confirmed\s+bundles?\s*:\s*[1-9]\d*\b", lowered):
            issues.append(f"handoff-summary.md:{line_no}: claims nonzero confirmed bundle count with zero validated bundles")
            continue
        if not safe_negative and re.search(
            r"(?:confirmed\s+bundles?.{0,60}(?:completed|complete|passed|ready)|"
            r"(?:completed|complete|passed|ready).{0,60}confirmed\s+bundles?)",
            lowered,
        ):
            issues.append(f"handoff-summary.md:{line_no}: claims confirmed bundle completion with zero validated bundles")
            continue
        if not safe_negative and re.search(
            r"(?:formal\s+)?seeded\s+variant\s+discovery.{0,80}(?:completed|complete|passed|ready|can run|runnable)|"
            r"(?:completed|complete|passed|ready|can run|runnable).{0,80}(?:formal\s+)?seeded\s+variant\s+discovery",
            lowered,
        ):
            issues.append(f"handoff-summary.md:{line_no}: claims formal seeded variant discovery completion/readiness with zero validated bundles")
            continue
        if not safe_negative and "docker" in lowered and "evidence" in lowered and "confirmed bundle" in lowered:
            issues.append(f"handoff-summary.md:{line_no}: describes Docker evidence as a confirmed bundle")
            continue
        if not safe_negative and re.search(r"\bbundle[- ]ready\b|bundle generation ready|ready for bundle generation", lowered):
            issues.append(f"handoff-summary.md:{line_no}: claims bundle readiness with zero validated bundles")
            continue
    return issues


def validate_handoff_status_consistency(
    workspace: Path,
    *,
    status: dict[str, Any] | None = None,
    handoff_path: Path | None = None,
    state: dict[str, Any] | None = None,
    language: str = "auto",
) -> dict[str, Any]:
    inspected = state or inspect_workspace_state(workspace, language=language)
    canonical_status, normalized_events, protocol_mode = read_normalized_workspace_events(workspace)
    status_doc = status if status is not None else canonical_status
    handoff = handoff_path or workspace / "handoff-summary.md"
    errors: list[str] = []
    warnings: list[str] = []
    validated_count = int(inspected.get("validated_confirmed_bundle_count") or 0)

    result = _completion_result_from_authority(
        status_doc,
        normalized_events,
        protocol_mode=protocol_mode,
    )
    _completion_source_path, completion_source_label = _completion_source_from_protocol(protocol_mode)
    if result == CONFIRMED_BUNDLE_SUCCESS and validated_count == 0:
        errors.append(
            f"{completion_source_label} is completed_with_confirmed_bundles but validated_confirmed_bundle_count=0"
        )
    if result == CONFIRMED_BUNDLE_SUCCESS and inspected.get("formal_variant_analysis_status") != "completed":
        errors.append(
            f"{completion_source_label} is completed_with_confirmed_bundles but formal seeded variant discovery is not completed"
        )
    if result == NO_CONFIRMED_SUCCESS and validated_count > 0:
        errors.append(
            f"{completion_source_label} is completed_no_confirmed_findings but validated confirmed bundles exist"
        )

    if result in {CONFIRMED_BUNDLE_SUCCESS, NO_CONFIRMED_SUCCESS}:
        try:
            from audit_disposition import (
                load_disposition_ledger,
                validate_disposition_ledger,
                validate_workspace_confirmation_chain,
            )
            bundle_summary = {
                "summary": inspected.get("validator_summary", {}),
                "results": inspected.get("results", []),
            }
            ledger = load_disposition_ledger(workspace)
            disposition = validate_disposition_ledger(
                workspace,
                result=result,
                ledger=ledger,
                bundle_summary=bundle_summary,
                language=language,
            )
            chain = validate_workspace_confirmation_chain(
                workspace,
                result=result,
                protocol_mode=protocol_mode,
                ledger=ledger,
                bundle_summary=bundle_summary,
                disposition_validation=disposition,
                language=language,
            )
            errors.extend(str(item) for item in chain.get("errors", []))
        except Exception:
            errors.append("shared completion authority chain could not be evaluated")

    if handoff.exists():
        text = handoff.read_text(encoding="utf-8", errors="ignore")
        errors.extend(_unsafe_claim_lines(text, validated_count=validated_count))
    else:
        warnings.append("handoff-summary.md is missing")

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "state": inspected,
    }


# ---------------------------------------------------------------------------
# P9 lightweight handoff/checkpoint contract
# ---------------------------------------------------------------------------

HANDOFF_STATE_FILENAME = "handoff-state.json"
CHECKPOINT_DIRNAME = "checkpoints"
CHECKPOINT_SCHEMA_VERSION = 1
HANDOFF_SCHEMA_VERSION = 1
_URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_WINDOWS_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")
_ABSOLUTE_TEXT_RE = re.compile(r"(?:^|[\s:=,'\"])/(?:Users|home|private|tmp|var|etc|root|opt|Volumes|mnt|srv|usr)(?:/|$)")
_FATAL_PATH_CODES = {"PATH_UNSAFE", "PATH_ESCAPE", "PATH_MISSING", "SYMLINK_PATH_REJECTED", "WORKSPACE_PATH_UNSAFE"}


class HandoffContractError(AuditStateError):
    """Stable failure for derived handoff/checkpoint inputs and outputs."""


def _contract_error(code: str, message: str, **fields: Any) -> HandoffContractError:
    return HandoffContractError(code, message, **fields)


def _sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _sha256_regular_file(path: Path, workspace: Path | None = None) -> str:
    if workspace is not None:
        _safe_workspace_path(workspace, _path_relative_text(path, workspace), field="artifact", allow_missing=False, expected="file")
    try:
        return _sha256_bytes(path.read_bytes())
    except (OSError, UnicodeError) as exc:
        raise _contract_error("ARTIFACT_READ_FAILED", "authoritative artifact cannot be read") from exc


def _path_relative_text(path: Path, workspace: Path) -> str:
    try:
        return path.absolute().relative_to(workspace.absolute()).as_posix()
    except ValueError as exc:
        raise _contract_error("PATH_ESCAPE", "derived artifact path is outside the audit workspace") from exc


def _validate_relative_text(value: Any, field: str, *, allow_dot: bool = True) -> str:
    if not isinstance(value, str) or not value:
        raise _contract_error("PATH_UNSAFE", f"{field} must be a non-empty workspace-relative path")
    if value == "." and allow_dot:
        return value
    if value.startswith("/") or _WINDOWS_ABS_RE.match(value) or value.startswith("~"):
        raise _contract_error("PATH_UNSAFE", f"{field} must not be absolute or operator-local")
    if "\\" in value or _URI_SCHEME_RE.match(value):
        raise _contract_error("PATH_UNSAFE", f"{field} must use a POSIX workspace-relative path")
    parts = value.split("/")
    if any(part in {"", ".."} for part in parts):
        raise _contract_error("PATH_UNSAFE", f"{field} contains an empty or parent component")
    return value


def _safe_workspace_path(
    workspace: Path,
    value: str,
    *,
    field: str,
    allow_missing: bool,
    expected: str = "file",
) -> Path:
    relative = _validate_relative_text(value, field)
    if workspace.is_symlink() or not workspace.is_dir():
        raise _contract_error("WORKSPACE_PATH_UNSAFE", "audit workspace must be a real directory")
    current = workspace.absolute()
    if relative != ".":
        for index, part in enumerate(relative.split("/")):
            current = current / part
            try:
                info = os.lstat(current)
            except FileNotFoundError:
                if allow_missing:
                    return current
                raise _contract_error("PATH_MISSING", f"{field} does not exist")
            except OSError as exc:
                raise _contract_error("PATH_UNSAFE", f"{field} cannot be inspected") from exc
            if stat.S_ISLNK(info.st_mode):
                raise _contract_error("SYMLINK_PATH_REJECTED", f"{field} must not contain symlinks")
            is_last = index == len(relative.split("/")) - 1
            if not is_last and not stat.S_ISDIR(info.st_mode):
                raise _contract_error("PATH_UNSAFE", f"{field} has a non-directory parent")
            if is_last:
                if expected == "file" and not stat.S_ISREG(info.st_mode):
                    raise _contract_error("PATH_UNSAFE", f"{field} must be a regular file")
                if expected == "dir" and not stat.S_ISDIR(info.st_mode):
                    raise _contract_error("PATH_UNSAFE", f"{field} must be a directory")
    return current


def _safe_workspace_dir(workspace: Path, relative: str, *, allow_missing: bool = False) -> Path:
    return _safe_workspace_path(workspace, relative, field="directory", allow_missing=allow_missing, expected="dir")


def _safe_output_parent(workspace: Path, path: Path) -> None:
    relative = _path_relative_text(path.parent, workspace)
    _safe_workspace_dir(workspace, relative, allow_missing=False)


def _safe_json_object(workspace: Path, relative: str) -> tuple[Path, dict[str, Any]] | None:
    try:
        path = _safe_workspace_path(workspace, relative, field=relative, allow_missing=True)
    except HandoffContractError:
        raise
    if not path.exists():
        return None
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise _contract_error("PATH_UNSAFE", f"{relative} must be a single-link regular file", path=relative)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise _contract_error("PATH_UNSAFE", f"{relative} changed during safe open", path=relative)
            raw = b""
            while len(raw) <= 2 * 1024 * 1024:
                chunk = os.read(fd, min(65536, 2 * 1024 * 1024 + 1 - len(raw)))
                if not chunk:
                    break
                raw += chunk
            if len(raw) > 2 * 1024 * 1024:
                raise _contract_error("PATH_UNSAFE", f"{relative} exceeds the safe JSON size limit", path=relative)
        finally:
            os.close(fd)
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise _contract_error("AUTHORITATIVE_JSON_INVALID", f"{relative} is not valid UTF-8 JSON", path=relative) from exc
    if not isinstance(value, dict):
        raise _contract_error("AUTHORITATIVE_JSON_INVALID", f"{relative} must contain a JSON object", path=relative)
    return path, value


def _parse_utc_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def read_strict_docker_cleanliness(workspace: Path) -> dict[str, Any]:
    """Read and validate the one strict-clean artifact without trusting a pathname shortcut."""
    relative = "docker/docker-cleanliness-status.json"
    errors: list[str] = []
    try:
        loaded = _safe_json_object(workspace, relative)
    except HandoffContractError as exc:
        return {"ok": False, "errors": [f"{relative} is unsafe or unreadable [{exc.code}]"], "path": relative}
    if loaded is None:
        return {"ok": False, "errors": [f"{relative} is missing"], "path": relative}
    path, document = loaded
    required = {"schema_version", "checked_at", "workspace", "clean", "strict", "counts", "note"}
    if set(document) != required:
        errors.append(f"{relative} has an invalid strict schema")
    if document.get("schema_version") != 1:
        errors.append(f"{relative} has an unsupported schema_version")
    if document.get("clean") is not True or document.get("strict") is not True:
        errors.append(f"{relative} must declare clean=true and strict=true")
    if document.get("workspace") != workspace.name:
        errors.append(f"{relative} workspace binding does not match the current workspace")
    checked_at = _parse_utc_timestamp(document.get("checked_at"))
    if checked_at is None:
        errors.append(f"{relative} checked_at is invalid")
    if not isinstance(document.get("counts"), dict) or not isinstance(document.get("note"), str):
        errors.append(f"{relative} counts/note fields are invalid")
    return {
        "ok": not errors,
        "errors": errors,
        "path": relative,
        "sha256": _sha256_regular_file(path, workspace),
        "checked_at": document.get("checked_at"),
        "workspace": document.get("workspace"),
        "status": document,
    }


def validate_current_strict_docker_cleanliness(
    workspace: Path,
    *,
    now: datetime | None = None,
    max_age_seconds: int = 300,
) -> dict[str, Any]:
    """Require strict-clean evidence to be fresh enough for a new finalization."""
    evidence = read_strict_docker_cleanliness(workspace)
    errors = list(evidence.get("errors") or [])
    checked_at = _parse_utc_timestamp(evidence.get("checked_at"))
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if checked_at is None:
        if not any("checked_at" in error for error in errors):
            errors.append("docker/docker-cleanliness-status.json checked_at is invalid")
    else:
        age = (current - checked_at).total_seconds()
        if age < 0:
            errors.append("docker/docker-cleanliness-status.json checked_at is in the future")
        elif age > max_age_seconds:
            errors.append("docker/docker-cleanliness-status.json is stale for finalization")
    evidence["errors"] = errors
    evidence["ok"] = not errors
    return evidence


def validate_strict_docker_cleanliness_evidence(
    workspace: Path,
    success_event: dict[str, Any] | None,
    *,
    previous_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Bind strict-clean bytes to the finalization event and reject stale/manual pairings."""
    evidence = read_strict_docker_cleanliness(workspace)
    errors = list(evidence.get("errors") or [])
    details = success_event.get("details") if isinstance(success_event, dict) and isinstance(success_event.get("details"), dict) else {}
    expected_claims = {
        "docker_clean": True,
        "docker_clean_strict": True,
        "docker_cleanliness_path": evidence.get("path"),
        "docker_cleanliness_sha256": evidence.get("sha256"),
        "docker_cleanliness_checked_at": evidence.get("checked_at"),
        "docker_cleanliness_workspace": workspace.name,
    }
    if success_event is None:
        errors.append("finalization_succeeded event is missing for Docker cleanliness binding")
    else:
        for field, expected in expected_claims.items():
            if details.get(field) != expected:
                errors.append(f"finalization_succeeded {field} claim does not match strict-clean evidence")

    checked_at = _parse_utc_timestamp(evidence.get("checked_at"))
    event_at = _parse_utc_timestamp(success_event.get("ts") if isinstance(success_event, dict) else None)
    if checked_at is not None and event_at is not None:
        if checked_at > event_at:
            errors.append("Docker cleanliness checked_at is later than finalization_succeeded")
        if (event_at - checked_at).total_seconds() > 300:
            errors.append("Docker cleanliness status is stale relative to finalization_succeeded")
    elif success_event is not None:
        errors.append("finalization_succeeded timestamp cannot be compared to Docker cleanliness checked_at")

    prior_times = [
        parsed
        for parsed in (_parse_utc_timestamp(item.get("ts")) for item in (previous_events or []))
        if parsed is not None
    ]
    if checked_at is not None and prior_times and checked_at < max(prior_times):
        errors.append("Docker cleanliness status predates a later pre-finalization authority event")
    return {**evidence, "ok": not errors, "errors": errors, "claims": expected_claims}


def _safe_directory_entry(path: Path, *, allow_missing: bool = False) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return allow_missing
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)


def _discover_named_files(workspace: Path, name: str) -> list[tuple[str, Path]]:
    found: list[tuple[str, Path]] = []
    if not workspace.is_dir() or workspace.is_symlink():
        raise _contract_error("WORKSPACE_PATH_UNSAFE", "audit workspace must be a real directory")
    for root, dirs, files in os.walk(workspace, topdown=True, followlinks=False):
        root_path = Path(root)
        safe_dirs: list[str] = []
        for directory in dirs:
            candidate = root_path / directory
            try:
                info = os.lstat(candidate)
            except OSError as exc:
                raise _contract_error("PATH_UNSAFE", "workspace directory cannot be inspected") from exc
            if stat.S_ISLNK(info.st_mode):
                continue
            if directory in {".git", "__pycache__", CHECKPOINT_DIRNAME} or directory.startswith("."):
                continue
            safe_dirs.append(directory)
        dirs[:] = sorted(safe_dirs)
        if name not in files:
            continue
        path = root_path / name
        relative = _path_relative_text(path, workspace)
        found.append((relative, path))
    return sorted(found, key=lambda item: item[0])


def _sanitize_text(value: Any, *, fallback: str = "") -> str:
    text = str(value or "").strip()
    if not text:
        return fallback
    text = _ABSOLUTE_TEXT_RE.sub("<local-path>", text)
    text = re.sub(r"\b(?:password|passwd|api[_-]?key|secret|token)\s*[:=]\s*[^\s,;]+", "<redacted>", text, flags=re.I)
    return text[:240]


def _issue(code: str, message: str, path: str | None = None) -> dict[str, Any]:
    safe_path: str | None = None
    if isinstance(path, str) and path:
        try:
            _validate_relative_text(path, "issue.path")
            safe_path = path
        except HandoffContractError:
            safe_path = "<unsafe-path>"
    return {"code": code, "message": _sanitize_text(message), "path": safe_path}


def _artifact(path: Path, workspace: Path, *, kind: str, status: str, artifacts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    relative = _path_relative_text(path, workspace)
    _safe_workspace_path(workspace, relative, field=relative, allow_missing=False, expected="file")
    record = {"path": relative, "sha256": _sha256_regular_file(path), "kind": kind, "status": status}
    artifacts[relative] = record
    return record


def _status_ref(path: Path | None, workspace: Path, *, status: str, summary: str, artifacts: dict[str, dict[str, Any]], kind: str) -> dict[str, Any]:
    if path is None:
        return {"status": status, "path": None, "sha256": None, "summary": _sanitize_text(summary, fallback=status)}
    relative = _path_relative_text(path, workspace)
    _artifact(path, workspace, kind=kind, status="authoritative", artifacts=artifacts)
    return {"status": status, "path": relative, "sha256": artifacts[relative]["sha256"], "summary": _sanitize_text(summary, fallback=status)}


def _find_one_named(workspace: Path, name: str, issues: list[dict[str, Any]]) -> tuple[str, Path] | None:
    matches = _discover_named_files(workspace, name)
    if len(matches) > 1:
        issues.append(_issue("DUPLICATE_AUTHORITATIVE_FILE", f"multiple {name} files were found", None))
    return matches[0] if matches else None


def _run_json_validator(command: list[str]) -> tuple[bool, dict[str, Any] | None, str]:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False, None, "validator could not be executed"
    try:
        value = json.loads(proc.stdout)
    except (json.JSONDecodeError, TypeError):
        return False, None, "validator did not produce valid JSON"
    if not isinstance(value, dict):
        return False, None, "validator JSON result is not an object"
    return proc.returncode == 0 and value.get("ok") is not False, value, "validator rejected input"


def _run_target_validator(workspace: Path, path: Path, repo_root: Path) -> tuple[bool, str]:
    validator = _script_path(workspace, "validate-target-contract.py", "validate_target_contract.py")
    if validator is None:
        return False, "target-contract validator is missing"
    try:
        proc = subprocess.run([sys.executable, str(validator), str(path)], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False, "target-contract validator could not be executed"
    return proc.returncode == 0, "target contract validator rejected input"


def _append_tested_ref(refs: list[tuple[str, str]], relative: str, value: Any, issues: list[dict[str, Any]]) -> None:
    if not isinstance(value, str) or not value.strip():
        return
    text = value.strip()
    sensitive_kind = tested_ref_value_kind(text)
    if sensitive_kind is not None:
        raise _contract_error(
            "TESTED_REF_SENSITIVE_TEXT_FORBIDDEN",
            f"tested_ref contains forbidden source-identity material of category {sensitive_kind}",
            field="tested_ref",
            category=sensitive_kind,
        )
    if text.startswith(("/", "~")) or _WINDOWS_ABS_RE.match(text) or _URI_SCHEME_RE.match(text) or "\\" in text or any(part == ".." for part in text.split("/")):
        issues.append(_issue("TESTED_REF_UNSAFE", "tested_ref contains an absolute, URI, traversal, or backslash value", relative))
        return
    refs.append((relative, text))


def _target_and_structured_refs(
    workspace: Path,
    repo_root: Path,
    artifacts: dict[str, dict[str, Any]],
    issues: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    refs: list[tuple[str, str]] = []
    target_match = _find_one_named(workspace, "zhulong-target.yaml", issues)
    target_path: Path | None = None
    target_doc: dict[str, Any] | None = None
    if target_match:
        target_relative, target_path = target_match
        try:
            _safe_workspace_path(workspace, target_relative, field=target_relative, allow_missing=False)
            import yaml  # type: ignore
            target_value = yaml.safe_load(target_path.read_text(encoding="utf-8"))
            if not isinstance(target_value, dict):
                raise ValueError("target contract root is not an object")
            target_doc = target_value
            target = target_value.get("target")
            if not isinstance(target, dict) or not isinstance(target.get("tested_ref"), str) or not target.get("tested_ref", "").strip():
                raise ValueError("target.tested_ref is missing")
            _append_tested_ref(refs, target_relative, target.get("tested_ref"), issues)
            valid, message = _run_target_validator(workspace, target_path, repo_root)
            if not valid:
                issues.append(_issue("TARGET_CONTRACT_INVALID", message, target_relative))
            _artifact(target_path, workspace, kind="target_contract", status="authoritative", artifacts=artifacts)
        except HandoffContractError:
            raise
        except Exception:
            issues.append(_issue("TARGET_CONTRACT_INVALID", "target contract is unreadable or malformed", target_relative))
    return target_path_info(workspace, target_doc, refs, issues)


def target_path_info(workspace: Path, target_doc: dict[str, Any] | None, refs: list[tuple[str, str]], issues: list[dict[str, Any]]) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    # This tiny indirection keeps the target parser above easy to audit and makes
    # the source-kind decision explicit rather than inferring it from notes.
    if not refs:
        issues.append(_issue("TESTED_REF_UNVERIFIABLE", "no authoritative target or structured tested_ref was found", None))
        return {"value": None, "verified": False, "source_paths": [], "source_kind": "unknown"}, refs
    values = {value for _path, value in refs}
    if len(values) != 1:
        issues.append(_issue("TESTED_REF_DRIFT", "authoritative structured artifacts disagree on tested_ref", None))
        return {"value": sorted(values)[0], "verified": False, "source_paths": sorted(path for path, _value in refs), "source_kind": "unknown"}, refs
    value = next(iter(values))
    has_target = any(path.endswith("zhulong-target.yaml") for path, _value in refs)
    source_kind = "target_contract" if has_target and target_doc is not None else "structured_consensus"
    verified = source_kind == "target_contract" and not any(item["code"] in {"TARGET_CONTRACT_INVALID", "TESTED_REF_DRIFT"} for item in issues)
    return {"value": value, "verified": verified, "source_paths": sorted(path for path, _value in refs), "source_kind": source_kind}, refs


def _collect_recon_triage(
    workspace: Path,
    repo_root: Path,
    artifacts: dict[str, dict[str, Any]],
    issues: list[dict[str, Any]],
    refs: list[tuple[str, str]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for filename, key, validator_name, source_name, flags in (
        ("recon-result.json", "recon", "validate-recon-result.py", "validate_recon_result.py", ["--recon-result"]),
        ("triage-batch.json", "triage", "validate-triage-batch.py", "validate_triage_batch.py", ["--triage-batch"]),
    ):
        match = _find_one_named(workspace, filename, issues)
        if not match:
            results[key] = {"status": "missing", "path": None, "sha256": None, "summary": f"{filename} is missing"}
            continue
        relative, path = match
        try:
            loaded = _safe_json_object(workspace, relative)
            if loaded is None:
                results[key] = {"status": "missing", "path": None, "sha256": None, "summary": f"{filename} is missing"}
                continue
            _path, document = loaded
            _artifact(path, workspace, kind=key, status="authoritative", artifacts=artifacts)
            target_binding = document.get("target_binding")
            if isinstance(target_binding, dict) and isinstance(target_binding.get("tested_ref"), str):
                _append_tested_ref(refs, relative, target_binding.get("tested_ref"), issues)
            validator = _script_path(workspace, validator_name, source_name)
            if validator is None:
                issues.append(_issue("VALIDATOR_MISSING", f"{filename} validator is missing", relative))
                results[key] = {"status": "unverifiable", "path": relative, "sha256": artifacts[relative]["sha256"], "summary": "validator missing"}
                continue
            # Preserve each validator's declared input contract.  The Recon
            # validator resolves a workspace-local file path; the triage
            # validator explicitly declares a workspace-relative batch path.
            artifact_argument = relative if key == "triage" else str(path)
            command = [sys.executable, str(validator), "--repo-root", str(repo_root), "--workspace-dir", str(workspace), *flags, artifact_argument, "--json"]
            ok, payload, message = _run_json_validator(command)
            if not ok:
                issues.append(_issue("STRUCTURED_RESULT_INVALID", message, relative))
                status = "invalid"
            else:
                status = str(document.get("status") or "valid")
            identifier = str(document.get("recon_id") or document.get("batch_id") or "")
            summary = f"{status}; id={identifier or 'unknown'}"
            results[key] = {"status": status, "path": relative, "sha256": artifacts[relative]["sha256"], "summary": summary}
        except HandoffContractError as exc:
            if exc.code in _FATAL_PATH_CODES:
                raise
            issues.append(_issue(exc.code, exc.message, relative))
            results[key] = {"status": "invalid", "path": relative, "sha256": None, "summary": "structured result cannot be read"}
    return results["recon"], results["triage"]


def _collect_candidates_and_verdicts(
    workspace: Path,
    artifacts: dict[str, dict[str, Any]],
    issues: list[dict[str, Any]],
    refs: list[tuple[str, str]],
) -> tuple[list[str], list[str]]:
    candidate_paths: dict[str, Path] = {}
    candidate_ids: set[str] = set()
    for relative, path in _discover_named_files(workspace, "candidate.json"):
        if "confirmed/" in f"{relative}/" or "/examples/" in f"/{relative}/":
            continue
        try:
            loaded = _safe_json_object(workspace, relative)
            if loaded is None:
                continue
            _path, document = loaded
            from validate_candidate import ValidationError as CandidateValidationError, validate_candidate
            result = validate_candidate(document)
            candidate_id = str(result["candidate_id"])
            if candidate_id in candidate_paths:
                issues.append(_issue("DUPLICATE_STRUCTURED_ID", "duplicate candidate_id in structured candidate files", relative))
                continue
            candidate_paths[candidate_id] = path
            candidate_ids.add(candidate_id)
            target_ref = document.get("target_ref")
            if isinstance(target_ref, dict) and isinstance(target_ref.get("tested_ref"), str):
                _append_tested_ref(refs, relative, target_ref.get("tested_ref"), issues)
            _artifact(path, workspace, kind="candidate", status="authoritative", artifacts=artifacts)
        except HandoffContractError:
            raise
        except Exception:
            issues.append(_issue("CANDIDATE_VALIDATOR_REJECTED", "candidate validator rejected structured candidate", relative))

    verdict_ids: set[str] = set()
    for relative, path in _discover_named_files(workspace, "verifier-verdict.json"):
        if "confirmed/" in f"{relative}/" or "/examples/" in f"/{relative}/":
            continue
        try:
            loaded = _safe_json_object(workspace, relative)
            if loaded is None:
                continue
            _path, document = loaded
            from validate_verifier_verdict import ValidationError as VerdictValidationError, cross_check_candidate, validate_verdict
            result = validate_verdict(document)
            candidate_id = str(result["candidate_id"])
            candidate_path = candidate_paths.get(candidate_id)
            if candidate_path is None:
                raise ValueError("verdict has no matching validated candidate")
            cross_check_candidate(candidate_path, document)
            if candidate_id in verdict_ids:
                issues.append(_issue("DUPLICATE_STRUCTURED_ID", "duplicate verifier verdict for candidate", relative))
                continue
            verdict_ids.add(candidate_id)
            target_ref = document.get("target_ref")
            if isinstance(target_ref, dict) and isinstance(target_ref.get("tested_ref"), str):
                _append_tested_ref(refs, relative, target_ref.get("tested_ref"), issues)
            _artifact(path, workspace, kind="verdict", status="authoritative", artifacts=artifacts)
        except HandoffContractError:
            raise
        except Exception:
            issues.append(_issue("VERDICT_VALIDATOR_REJECTED", "verifier verdict validator rejected structured verdict", relative))
    return sorted(candidate_ids), sorted(verdict_ids)


def _collect_disposition(
    workspace: Path,
    bundle_summary: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    issues: list[dict[str, Any]],
) -> tuple[list[str], int, dict[str, Any]]:
    relative = "audit-disposition.json"
    loaded = _safe_json_object(workspace, relative)
    if loaded is None:
        return [], 0, {"status": "missing", "path": None, "sha256": None, "summary": "audit-disposition.json is missing"}
    path, ledger = loaded
    _artifact(path, workspace, kind="disposition", status="authoritative", artifacts=artifacts)
    try:
        from audit_disposition import validate_disposition_ledger
        checked = validate_disposition_ledger(workspace, ledger=ledger, bundle_summary=bundle_summary, language="auto")
    except Exception:
        checked = {"ok": False}
    if not checked.get("ok"):
        issues.append(_issue("DISPOSITION_VALIDATOR_REJECTED", "audit-disposition.json failed its existing validator", relative))
        return [], 0, {"status": "invalid", "path": relative, "sha256": artifacts[relative]["sha256"], "summary": "disposition validator rejected input"}
    ids: set[str] = set()
    for item in ledger.get("items", []):
        if isinstance(item, dict) and str(item.get("id") or "").strip():
            ids.add(str(item["id"]).strip())
    for item in ledger.get("candidate_dispositions", []):
        if isinstance(item, dict) and str(item.get("candidate_id") or "").strip():
            ids.add(str(item["candidate_id"]).strip())
    return sorted(ids), len(ledger.get("items", [])) if isinstance(ledger.get("items"), list) else 0, {"status": "valid", "path": relative, "sha256": artifacts[relative]["sha256"], "summary": "structured disposition ledger validated"}


def _read_status_artifact(
    workspace: Path,
    relative: str,
    artifacts: dict[str, dict[str, Any]],
    issues: list[dict[str, Any]],
    *,
    kind: str,
    missing_status: str = "missing",
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    try:
        loaded = _safe_json_object(workspace, relative)
    except HandoffContractError as exc:
        if exc.code in _FATAL_PATH_CODES:
            raise
        issues.append(_issue(exc.code, exc.message, relative))
        return {"status": "invalid", "path": relative, "sha256": None, "summary": "status artifact cannot be read"}, None
    if loaded is None:
        return {"status": missing_status, "path": None, "sha256": None, "summary": f"{relative} is missing"}, None
    path, document = loaded
    _artifact(path, workspace, kind=kind, status="authoritative", artifacts=artifacts)
    return {"status": "present", "path": relative, "sha256": artifacts[relative]["sha256"], "summary": "structured status artifact present"}, document


def _runtime_statuses(
    workspace: Path,
    artifacts: dict[str, dict[str, Any]],
    issues: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    docker, docker_doc = _read_status_artifact(workspace, "docker/docker-cleanliness-status.json", artifacts, issues, kind="docker")
    if docker_doc is not None:
        clean = docker_doc.get("clean") is True
        strict = docker_doc.get("strict") is True
        docker["status"] = "clean" if clean and strict else "dirty" if clean is False or strict is False else "unknown"
        docker["summary"] = f"clean={str(bool(clean)).lower()}, strict={str(bool(strict)).lower()}"
    baseline, baseline_doc = _read_status_artifact(workspace, "docker/docker-resource-baseline.json", artifacts, issues, kind="docker")
    baseline["status"] = "present" if baseline_doc is not None else "missing"
    runtime, runtime_doc = _read_status_artifact(workspace, "runtime/runtime-hygiene-status.json", artifacts, issues, kind="runtime")
    if runtime_doc is not None:
        runtime["status"] = "clean" if runtime_doc.get("clean") is True else "review_required" if runtime_doc.get("clean") is False else "unknown"
        runtime["summary"] = f"recommended_mode={_sanitize_text(runtime_doc.get('recommended_mode'), fallback='unknown')}"
    return docker, baseline, runtime, runtime_doc or {}


def _recording_statuses(workspace: Path, artifacts: dict[str, dict[str, Any]], issues: list[dict[str, Any]]) -> tuple[dict[str, Any], int]:
    matches = _discover_named_files(workspace, "recording-evidence.json")
    if not matches:
        return {"status": "missing", "path": None, "sha256": None, "summary": "recording manifest is missing"}, 0
    statuses: list[str] = []
    chosen: tuple[str, Path] | None = None
    for relative, path in matches:
        try:
            loaded = _safe_json_object(workspace, relative)
            if loaded is None:
                continue
            _path, manifest = loaded
            _artifact(path, workspace, kind="recording", status="observed", artifacts=artifacts)
            status = str(manifest.get("recording_status") or "invalid")
            statuses.append(status)
            chosen = (relative, path)
            if status not in {"staging", "passed", "failed"}:
                issues.append(_issue("RECORDING_MANIFEST_INVALID", "recording manifest has an unsupported status", relative))
        except HandoffContractError as exc:
            if exc.code in _FATAL_PATH_CODES:
                raise
            issues.append(_issue(exc.code, exc.message, relative))
    if not chosen:
        return {"status": "invalid", "path": None, "sha256": None, "summary": "recording manifest is unreadable"}, len(matches)
    relative, _path = chosen
    digest = artifacts[relative]["sha256"]
    if any(status == "passed" for status in statuses):
        status = "manifest_passed_not_revalidated"
    elif any(status == "staging" for status in statuses):
        status = "staging"
    else:
        status = "failed"
    return {"status": status, "path": relative, "sha256": digest, "summary": "recording status is observed conservatively; bundle validator remains authoritative"}, len(matches)


def _variant_analysis_status(
    workspace: Path,
    validated_confirmed_bundle_count: int,
    artifacts: dict[str, dict[str, Any]],
    issues: list[dict[str, Any]],
) -> dict[str, Any]:
    inspected = inspect_formal_variant_analysis(
        workspace,
        validated_confirmed_bundle_count=validated_confirmed_bundle_count,
    )
    status = str(inspected.get("formal_variant_analysis_status") or "unknown")
    seed_relative = "evidence/variant-analysis/seeds.jsonl"
    candidate_relative = "evidence/variant-analysis/variant-candidates.jsonl"
    existing_paths: list[str] = []
    for relative in (seed_relative, candidate_relative):
        try:
            path = _safe_workspace_path(workspace, relative, field=relative, allow_missing=True)
        except HandoffContractError as exc:
            if exc.code in _FATAL_PATH_CODES:
                raise
            issues.append(_issue(exc.code, exc.message, relative))
            continue
        if path.exists():
            _artifact(path, workspace, kind="other", status="authoritative", artifacts=artifacts)
            existing_paths.append(relative)
    errors = inspected.get("errors") if isinstance(inspected.get("errors"), list) else []
    if errors and status not in {"not_applicable_no_validated_confirmed_bundle"}:
        issues.append(_issue("VARIANT_ANALYSIS_INVALID", "formal seeded variant analysis is not currently verifiable", existing_paths[0] if existing_paths else "evidence/variant-analysis"))
    selected = candidate_relative if candidate_relative in existing_paths else seed_relative if seed_relative in existing_paths else None
    digest = artifacts[selected]["sha256"] if selected is not None else None
    return {
        "status": status,
        "path": selected,
        "sha256": digest,
        "summary": _sanitize_text(
            f"{status}; seeds={int(inspected.get('seed_count') or 0)}; candidates={int(inspected.get('candidate_count') or 0)}",
            fallback=status,
        ),
    }


def _finalization_status(events: list[dict[str, Any]], artifacts: dict[str, dict[str, Any]], workspace: Path) -> dict[str, Any]:
    latest: dict[str, Any] | None = None
    for event in reversed(events):
        if str(event.get("event") or "") in {"finalization_succeeded", "finalization_failed"}:
            latest = event
            break
    if latest is None:
        return {"status": "not_finalized", "path": None, "sha256": None, "summary": "no finalization event is recorded"}
    status = "completed" if latest.get("event") == "finalization_succeeded" else "failed"
    return {"status": status, "path": "audit-events.jsonl", "sha256": artifacts.get("audit-events.jsonl", {}).get("sha256"), "summary": f"latest finalization event={latest.get('event')}"}


def _safe_resume(state: dict[str, Any], issues: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    raw_step = _sanitize_text(state.get("resume_step"))
    active = str(state.get("status") or "") in {"paused", "blocked"} or bool(state.get("blocker")) or bool(issues)
    evidence_refs = sorted({str(item.get("path")) for item in issues if isinstance(item, dict) and isinstance(item.get("path"), str) and item.get("path")})
    entrypoint = "resume_stage" if raw_step and str(state.get("status") or "") in {"paused", "blocked"} else "validate_handoff_state" if issues else "none"
    handoff_resume = {
        "available": active,
        "step": raw_step or None,
        "entrypoint": entrypoint,
        "parameters": [{"name": "workspace-dir", "value": "."}] if active else [],
        "evidence_refs": evidence_refs[:8],
    }
    blocker_text = _sanitize_text(state.get("blocker"))
    blocker = {
        "active": active,
        "code": "STAGE_BLOCKED" if blocker_text else "DERIVED_INTEGRITY_BLOCK" if issues else None,
        "summary": blocker_text or (_sanitize_text(issues[0].get("message")) if issues else None),
        "source_path": evidence_refs[0] if evidence_refs else None,
    }
    return blocker, handoff_resume


def derive_handoff_state(
    workspace: Path,
    repo_root: Path | None = None,
    *,
    include_advisory_notes: bool = True,
) -> dict[str, Any]:
    """Derive one strict, path-redacted handoff document from authoritative files.

    This is the only aggregation layer used by the handoff and checkpoint CLIs.
    It never writes an audit event, state view, candidate, verdict, ledger, bundle,
    recording manifest, or finalization result.
    """
    workspace = workspace.absolute()
    repo_root = (repo_root or workspace.parent).absolute()
    snapshot = read_workspace_snapshot(workspace)
    if snapshot.state is None or not snapshot.journal.events:
        raise _contract_error("AUTHORITATIVE_STATE_MISSING", "a committed journal and state view are required")
    state = dict(snapshot.state)
    normalized_events: list[dict[str, Any]] = []
    for event in snapshot.journal.events:
        normalized = normalize_event(event)
        normalized_events.append({
            **event,
            "event": normalized["event_name"],
            "status": normalized["to_status"],
            "details": normalized["details"],
        })
    issues: list[dict[str, Any]] = []
    artifacts: dict[str, dict[str, Any]] = {}
    journal_path = workspace / "audit-events.jsonl"
    state_path = workspace / "stage-status.json"
    _artifact(journal_path, workspace, kind="journal", status="authoritative", artifacts=artifacts)
    _artifact(state_path, workspace, kind="state", status="authoritative", artifacts=artifacts)
    refs: list[tuple[str, str]] = []
    target_info, refs = _target_and_structured_refs(workspace, repo_root, artifacts, issues)
    recon_info, triage_info = _collect_recon_triage(workspace, repo_root, artifacts, issues, refs)
    candidate_ids, verdict_ids = _collect_candidates_and_verdicts(workspace, artifacts, issues, refs)
    confirmed_dirs: list[str] = []
    confirmed_root = workspace / "confirmed"
    if confirmed_root.is_symlink():
        raise _contract_error("SYMLINK_PATH_REJECTED", "confirmed directory must not be a symlink", path="confirmed")
    if confirmed_root.exists():
        if not _safe_directory_entry(confirmed_root):
            raise _contract_error("SYMLINK_PATH_REJECTED", "confirmed directory is not a real directory", path="confirmed")
    bundle_summary = inspect_confirmed_bundles(workspace, language="auto")
    if int(bundle_summary.get("confirmed_bundle_dirs_total") or 0) > 0 and str(bundle_summary.get("validator_error") or ""):
        issues.append(_issue("BUNDLE_VALIDATOR_UNVERIFIABLE", "confirmed bundle validator did not return a usable result", "confirmed"))
    if confirmed_root.exists():
        for entry in sorted(confirmed_root.iterdir(), key=lambda item: item.name):
            if entry.name.startswith("."):
                continue
            try:
                info = os.lstat(entry)
            except OSError:
                issues.append(_issue("PATH_UNSAFE", "confirmed entry cannot be inspected", "confirmed"))
                continue
            if stat.S_ISLNK(info.st_mode):
                issues.append(_issue("SYMLINK_PATH_REJECTED", "confirmed entries must not be symlinks", f"confirmed/{entry.name}"))
                continue
            if stat.S_ISDIR(info.st_mode):
                confirmed_dirs.append(entry.name)
                for child_name in ("findings.json", "verification-evidence.json", "validity-review.json"):
                    child = entry / child_name
                    if child.is_file() and not child.is_symlink():
                        _artifact(child, workspace, kind="bundle", status="validated" if child_name == "verification-evidence.json" else "observed", artifacts=artifacts)
    docker_evidence = detect_docker_evidence_only(workspace)
    variant_analysis = _variant_analysis_status(
        workspace,
        int(bundle_summary.get("validated_confirmed_bundle_count") or 0),
        artifacts,
        issues,
    )
    docker, docker_baseline, runtime, runtime_doc = _runtime_statuses(workspace, artifacts, issues)
    recording, recording_count = _recording_statuses(workspace, artifacts, issues)
    disposition_ids, disposition_item_count, disposition_info = _collect_disposition(workspace, bundle_summary, artifacts, issues)
    finalization = _finalization_status(normalized_events, artifacts, workspace)
    notes_path = workspace / "agent-notes.md"
    if include_advisory_notes and notes_path.exists():
        try:
            _safe_workspace_path(workspace, "agent-notes.md", field="agent-notes.md", allow_missing=False)
            _artifact(notes_path, workspace, kind="notes", status="advisory", artifacts=artifacts)
            notes = {"path": "agent-notes.md", "sha256": artifacts["agent-notes.md"]["sha256"], "status": "advisory"}
        except HandoffContractError as exc:
            if exc.code in _FATAL_PATH_CODES:
                raise
            issues.append(_issue(exc.code, exc.message, "agent-notes.md"))
            notes = {"path": None, "sha256": None, "status": "missing"}
    else:
        notes = {"path": None, "sha256": None, "status": "missing"}

    if refs:
        values = {value for _path, value in refs if value}
        target_info["source_paths"] = sorted({path for path, _value in refs})
        if len(values) > 1:
            issues.append(_issue("TESTED_REF_DRIFT", "structured artifacts disagree on tested_ref", None))
            target_info["verified"] = False
        if target_info.get("value") is None:
            target_info["value"] = sorted(values)[0] if values else None
    elif target_info.get("value") is None and not any(item.get("code") == "TESTED_REF_UNVERIFIABLE" for item in issues):
        issues.append(_issue("TESTED_REF_UNVERIFIABLE", "tested_ref has no structured source", None))
    if target_info.get("source_kind") == "target_contract" and any(item.get("code") == "TARGET_CONTRACT_INVALID" for item in issues):
        target_info["verified"] = False

    counts = {
        "candidates": len(candidate_ids),
        "verdicts": len(verdict_ids),
        "dispositions": len(disposition_ids),
        "disposition_items": disposition_item_count,
        "confirmed_bundle_dirs": len(confirmed_dirs),
        "validated_confirmed_bundles": int(bundle_summary.get("validated_confirmed_bundle_count") or 0),
        "partial_or_failed_confirmed_bundles": int(bundle_summary.get("invalid_or_partial_confirmed_bundle_count") or 0),
        "docker_evidence_only": int(docker_evidence.get("docker_evidence_only_count") or 0),
        "recording_manifests": recording_count,
    }
    identifiers = {
        "candidate_ids": sorted(candidate_ids),
        "verdict_candidate_ids": sorted(verdict_ids),
        "disposition_ids": sorted(disposition_ids),
        "confirmed_bundle_ids": sorted(confirmed_dirs),
    }
    completion_result = _completion_result_from_authority(
        state,
        normalized_events,
        protocol_mode=snapshot.mode,
    )
    completion_source_path, completion_source_label = _completion_source_from_protocol(snapshot.mode)
    blocked_verification = detect_blocked_verification(workspace)
    if blocked_verification.get("blocked"):
        first_finding = (blocked_verification.get("findings") or [{}])[0]
        issues.append(_issue(
            "BLOCKED_VERIFICATION_UNRESOLVED",
            "structured Docker/runtime verification facts contain an unresolved blocker",
            str(first_finding.get("source") or "audit-events.jsonl"),
        ))
    if completion_result == CONFIRMED_BUNDLE_SUCCESS and counts["validated_confirmed_bundles"] == 0:
        issues.append(_issue("COMPLETION_CLAIM_UNSUPPORTED", f"{completion_source_label} claims confirmed bundles but validated bundle count is zero", completion_source_path))
    if completion_result == CONFIRMED_BUNDLE_SUCCESS and int(bundle_summary.get("validated_confirmed_bundle_count") or 0) > 0 and variant_analysis.get("status") != "completed":
        issues.append(_issue("COMPLETION_VARIANT_GATE_UNSATISFIED", f"{completion_source_label} lacks completed formal seeded variant validation", completion_source_path))
    if completion_result in {CONFIRMED_BUNDLE_SUCCESS, NO_CONFIRMED_SUCCESS}:
        if disposition_info.get("status") != "valid":
            issues.append(_issue("COMPLETION_DISPOSITION_UNVERIFIABLE", "completion result has no valid disposition ledger", "audit-disposition.json"))
        if docker.get("status") != "clean":
            issues.append(_issue("COMPLETION_DOCKER_GATE_UNSATISFIED", "completion result has no clean strict Docker status artifact", "docker/docker-cleanliness-status.json"))
        try:
            from audit_disposition import load_disposition_ledger, validate_workspace_confirmation_chain
            chain = validate_workspace_confirmation_chain(
                workspace,
                result=completion_result,
                protocol_mode=snapshot.mode,
                ledger=load_disposition_ledger(workspace),
                bundle_summary=bundle_summary,
                language="auto",
            )
            for chain_error in chain.get("errors", []):
                issues.append(_issue("COMPLETION_AUTHORITY_CHAIN_INVALID", str(chain_error), "audit-disposition.json"))
        except Exception:
            issues.append(_issue("COMPLETION_AUTHORITY_CHAIN_INVALID", "shared completion authority chain could not be evaluated", "audit-disposition.json"))
    blocker, resume = _safe_resume(state, issues)
    artifact_list = [artifacts[key] for key in sorted(artifacts)]
    authoritative_digest = _sha256_bytes(json.dumps(artifact_list, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    integrity = {
        "overall": "valid" if not issues else "blocked",
        "journal_digest": artifacts["audit-events.jsonl"]["sha256"],
        "state_digest": artifacts["stage-status.json"]["sha256"],
        "authoritative_digest": authoritative_digest,
        "snapshot_consistent": True,
        "issues": sorted(issues, key=lambda item: (str(item.get("code")), str(item.get("path") or ""), str(item.get("message"))),),
    }
    plugin_version = _sanitize_text(state.get("plugin_version"), fallback="unknown")
    return {
        "schema_version": HANDOFF_SCHEMA_VERSION,
        "generated_from_revision": state.get("state_revision") if snapshot.mode == "r2" else None,
        "generated_from_event_sequence": state.get("last_event_seq") if snapshot.mode == "r2" else None,
        "protocol_mode": snapshot.mode,
        "plugin": "zhulong",
        "plugin_version": plugin_version,
        "tested_ref": target_info,
        "stage": _sanitize_text(state.get("stage"), fallback="unknown"),
        "status": _sanitize_text(state.get("status"), fallback="unknown"),
        "recon": recon_info,
        "triage": triage_info,
        "variant_analysis": variant_analysis,
        "docker": docker,
        "docker_baseline": docker_baseline,
        "runtime": runtime,
        "recording": recording,
        "finalization": finalization,
        "disposition": disposition_info,
        "blocker": blocker,
        "resume": resume,
        "artifacts": artifact_list,
        "counts": counts,
        "identifiers": identifiers,
        "integrity": integrity,
        "advisory_notes": notes,
    }


def _canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, separators=(",", ": ")) + "\n").encode("utf-8")


def _atomic_write_contract(path: Path, payload: bytes, workspace: Path, *, fault_prefix: str) -> None:
    _safe_output_parent(workspace, path)
    relative = _path_relative_text(path, workspace)
    if path.exists() or path.is_symlink():
        _safe_workspace_path(workspace, relative, field=relative, allow_missing=False, expected="file")
    temp_path: Path | None = None
    try:
        fd, raw_temp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temp_path = Path(raw_temp)
        try:
            if os.environ.get(f"ZHULONG_TEST_FAIL_{fault_prefix}_WRITE") == "1":
                raise OSError("injected temporary write failure")
            offset = 0
            while offset < len(payload):
                written = os.write(fd, payload[offset:])
                if written <= 0:
                    raise OSError("short write")
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
        _safe_output_parent(workspace, path)
        if os.environ.get(f"ZHULONG_TEST_FAIL_{fault_prefix}_REPLACE") == "1":
            raise OSError("injected replace failure")
        os.replace(temp_path, path)
        temp_path = None
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except OSError as exc:
        raise _contract_error("ATOMIC_WRITE_FAILED", "derived output was not published", path=relative) from exc
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except OSError:
                pass


def _snapshot_signature(workspace: Path, state: dict[str, Any]) -> tuple[Any, ...]:
    journal = workspace / "audit-events.jsonl"
    state_path = workspace / "stage-status.json"
    return (
        state.get("state_revision"),
        state.get("last_event_seq"),
        _sha256_regular_file(journal, workspace),
        _sha256_regular_file(state_path, workspace),
    )


def generate_handoff_state(workspace: Path, repo_root: Path | None = None, *, write: bool = True) -> dict[str, Any]:
    """Generate and optionally publish handoff-state.json under one state lock."""
    workspace = workspace.absolute()
    repo_root = (repo_root or workspace.parent).absolute()
    with workspace_lock(workspace, 10.0):
        before = read_workspace_snapshot(workspace)
        if before.state is None:
            raise _contract_error("AUTHORITATIVE_STATE_MISSING", "a committed journal and state view are required")
        before_signature = _snapshot_signature(workspace, before.state)
        document = derive_handoff_state(workspace, repo_root)
        sensitive_text = first_sensitive_document_text(document)
        if sensitive_text is not None:
            field, category = sensitive_text
            raise _contract_error(
                "HANDOFF_SENSITIVE_TEXT_FORBIDDEN",
                f"{field} contains sensitive material of category {category}",
                field=field,
                category=category,
            )
        if os.environ.get("ZHULONG_TEST_HANDOFF_PAUSE") == "1":
            pause_marker = os.environ.get("ZHULONG_TEST_HANDOFF_PAUSE_MARKER")
            if pause_marker:
                try:
                    Path(pause_marker).write_text("paused\n", encoding="utf-8")
                except OSError:
                    pass
            time.sleep(0.2)
        try:
            after = read_workspace_snapshot(workspace)
        except AuditStateError as exc:
            raise _contract_error("CONCURRENT_STATE_CHANGED", "authoritative journal or state became unreadable during handoff derivation") from exc
        if after.state is None or _snapshot_signature(workspace, after.state) != before_signature:
            raise _contract_error("CONCURRENT_STATE_CHANGED", "authoritative journal or state changed during handoff derivation")
        second_document = derive_handoff_state(workspace, repo_root)
        second_sensitive_text = first_sensitive_document_text(second_document)
        if second_sensitive_text is not None:
            field, category = second_sensitive_text
            raise _contract_error(
                "HANDOFF_SENSITIVE_TEXT_FORBIDDEN",
                f"{field} contains sensitive material of category {category}",
                field=field,
                category=category,
            )
        if (
            second_document.get("artifacts") != document.get("artifacts")
            or second_document.get("counts") != document.get("counts")
            or second_document.get("identifiers") != document.get("identifiers")
            or second_document.get("tested_ref") != document.get("tested_ref")
        ):
            raise _contract_error("CONCURRENT_STATE_CHANGED", "authoritative artifact digests changed during handoff derivation")
        if write:
            _atomic_write_contract(workspace / HANDOFF_STATE_FILENAME, _canonical_json_bytes(document), workspace, fault_prefix="HANDOFF")
        return document


def _validate_contract_shape(value: Any, *, checkpoint: bool = False) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        return [_issue("HANDOFF_SCHEMA_INVALID" if not checkpoint else "CHECKPOINT_SCHEMA_INVALID", "document root must be an object", None)]
    expected = {
        "schema_version", "generated_from_revision", "generated_from_event_sequence", "protocol_mode", "plugin", "plugin_version", "tested_ref", "stage", "status", "recon", "triage", "variant_analysis", "docker", "docker_baseline", "runtime", "recording", "finalization", "disposition", "blocker", "resume", "artifacts", "counts", "identifiers", "integrity", "advisory_notes"
    } if not checkpoint else {
        "schema_version", "state_revision", "event_sequence", "event_digest", "tested_ref", "created_at", "provenance", "authoritative_inputs", "identifiers", "docker", "docker_baseline", "recon", "triage", "handoff_state", "resume"
    }
    issues: list[dict[str, Any]] = []
    extras = sorted(set(value) - expected)
    missing = sorted(expected - set(value))
    code = "CHECKPOINT_SCHEMA_INVALID" if checkpoint else "HANDOFF_SCHEMA_INVALID"
    if extras:
        issues.append(_issue(code, "document contains unsupported fields", None))
    if missing:
        issues.append(_issue(code, "document is missing required fields", None))
    if value.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
        issues.append(_issue(code, "schema_version is unsupported", None))
    if not checkpoint and value.get("plugin") != "zhulong":
        issues.append(_issue(code, "plugin provenance is unsupported", None))
    return issues


def _require_exact_object(
    value: Any,
    field: str,
    required: set[str],
    issues: list[dict[str, Any]],
    *,
    optional: set[str] | None = None,
) -> bool:
    """Apply the schema's closed-object boundary without a runtime dependency."""
    code = "CHECKPOINT_SCHEMA_INVALID"
    if not isinstance(value, dict):
        issues.append(_issue(code, f"{field} must be an object", field))
        return False
    allowed = set(required) | set(optional or set())
    missing = sorted(required - set(value))
    extras = sorted(set(value) - allowed)
    if missing:
        issues.append(_issue(code, f"{field} is missing required fields", field))
    if extras:
        issues.append(_issue(code, f"{field} contains unsupported fields", field))
    return not missing and not extras


def validate_handoff_document(document: dict[str, Any]) -> list[dict[str, Any]]:
    issues = _validate_contract_shape(document)
    if issues:
        return issues
    sensitive_text = first_sensitive_document_text(document)
    if sensitive_text is not None:
        field, category = sensitive_text
        issues.append(_issue("HANDOFF_SENSITIVE_TEXT_FORBIDDEN", f"{field} contains sensitive material of category {category}", field))
    def check_digest(value: Any, field: str, *, nullable: bool = False) -> None:
        if nullable and value is None:
            return
        if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            issues.append(_issue("HANDOFF_SCHEMA_INVALID", f"{field} must be a sha256 digest", field))

    def check_path(value: Any, field: str, *, nullable: bool = False, allow_dot: bool = False) -> None:
        if nullable and value is None:
            return
        try:
            _validate_relative_text(value, field, allow_dot=allow_dot)
        except HandoffContractError as exc:
            issues.append(_issue(exc.code, exc.message, field))

    tested = document.get("tested_ref")
    if isinstance(tested, dict):
        if tested.get("value") is not None and (not isinstance(tested.get("value"), str) or not str(tested.get("value")).strip()):
            issues.append(_issue("HANDOFF_SCHEMA_INVALID", "tested_ref.value must be a non-empty string or null", "tested_ref.value"))
        if type(tested.get("verified")) is not bool or not isinstance(tested.get("source_paths"), list) or tested.get("source_kind") not in {"target_contract", "structured_consensus", "unknown"}:
            issues.append(_issue("HANDOFF_SCHEMA_INVALID", "tested_ref has an invalid shape", "tested_ref"))
        for path in tested.get("source_paths", []) if isinstance(tested.get("source_paths"), list) else []:
            check_path(path, "tested_ref.source_paths")
    for field in ("recon", "triage", "variant_analysis", "docker", "docker_baseline", "runtime", "recording", "finalization", "disposition"):
        status_ref = document.get(field)
        if isinstance(status_ref, dict):
            if not isinstance(status_ref.get("status"), str) or not status_ref.get("status"):
                issues.append(_issue("HANDOFF_SCHEMA_INVALID", "status reference has no status", field))
            check_path(status_ref.get("path"), f"{field}.path", nullable=True)
            check_digest(status_ref.get("sha256"), f"{field}.sha256", nullable=True)
            if not isinstance(status_ref.get("summary"), str) or not status_ref.get("summary"):
                issues.append(_issue("HANDOFF_SCHEMA_INVALID", "status reference has no summary", field))
    for item in document.get("artifacts", []):
        if not isinstance(item, dict):
            issues.append(_issue("HANDOFF_SCHEMA_INVALID", "artifact entries must be objects", None))
            continue
        try:
            _validate_relative_text(item.get("path"), "artifact.path", allow_dot=False)
        except HandoffContractError as exc:
            issues.append(_issue(exc.code, exc.message, None))
        check_digest(item.get("sha256"), "artifact.sha256")
    counts = document.get("counts")
    if isinstance(counts, dict):
        for key in ("candidates", "verdicts", "dispositions", "disposition_items", "confirmed_bundle_dirs", "validated_confirmed_bundles", "partial_or_failed_confirmed_bundles", "docker_evidence_only", "recording_manifests"):
            if type(counts.get(key)) is not int or counts.get(key) < 0:
                issues.append(_issue("HANDOFF_SCHEMA_INVALID", "count must be a non-negative integer", f"counts.{key}"))
    identifiers = document.get("identifiers")
    if isinstance(identifiers, dict):
        for key in ("candidate_ids", "verdict_candidate_ids", "disposition_ids", "confirmed_bundle_ids"):
            values = identifiers.get(key)
            if not isinstance(values, list) or values != sorted(values) or len(values) != len(set(values)) or any(not isinstance(item, str) or not item.strip() for item in values):
                issues.append(_issue("HANDOFF_SCHEMA_INVALID", "stable ID lists must be sorted and unique", f"identifiers.{key}"))
    integrity = document.get("integrity")
    if isinstance(integrity, dict):
        if integrity.get("overall") not in {"valid", "blocked", "invalid"} or type(integrity.get("snapshot_consistent")) is not bool:
            issues.append(_issue("HANDOFF_SCHEMA_INVALID", "integrity status is invalid", "integrity"))
        check_digest(integrity.get("journal_digest"), "integrity.journal_digest", nullable=True)
        check_digest(integrity.get("state_digest"), "integrity.state_digest", nullable=True)
        check_digest(integrity.get("authoritative_digest"), "integrity.authoritative_digest")
        if not isinstance(integrity.get("issues"), list):
            issues.append(_issue("HANDOFF_SCHEMA_INVALID", "integrity.issues must be a list", "integrity.issues"))
    resume = document.get("resume")
    if isinstance(resume, dict):
        if type(resume.get("available")) is not bool or resume.get("entrypoint") not in {"none", "manual_review", "render_handoff_state", "validate_handoff_state", "resume_stage"}:
            issues.append(_issue("HANDOFF_SCHEMA_INVALID", "resume entrypoint is invalid", "resume"))
        for item in resume.get("parameters", []) if isinstance(resume.get("parameters"), list) else []:
            if not isinstance(item, dict) or item.get("name") not in {"workspace-dir", "repo-root", "checkpoint", "artifact"}:
                issues.append(_issue("HANDOFF_SCHEMA_INVALID", "resume parameters must use fixed safe names", "resume.parameters"))
                continue
            check_path(item.get("value"), "resume.parameters.value", nullable=False, allow_dot=True)
    for field in ("tested_ref", "blocker", "resume", "counts", "identifiers", "integrity", "advisory_notes"):
        if not isinstance(document.get(field), dict):
            issues.append(_issue("HANDOFF_SCHEMA_INVALID", f"{field} must be an object", field))
    return issues


def read_handoff_state(workspace: Path) -> dict[str, Any]:
    loaded = _safe_json_object(workspace, HANDOFF_STATE_FILENAME)
    if loaded is None:
        raise _contract_error("HANDOFF_STATE_MISSING", "handoff-state.json is missing")
    _path, document = loaded
    issues = validate_handoff_document(document)
    if issues:
        raise _contract_error("HANDOFF_SCHEMA_INVALID", "handoff-state.json failed strict validation", issues=issues)
    return document


def _validate_handoff_state_current_unlocked(workspace: Path, repo_root: Path) -> dict[str, Any]:
    try:
        existing = read_handoff_state(workspace)
    except HandoffContractError as exc:
        issue = _issue(exc.code, exc.message, HANDOFF_STATE_FILENAME)
        return {"ok": False, "issue_codes": [issue["code"]], "issues": [issue], "classification": "unverifiable"}
    try:
        current = derive_handoff_state(workspace, repo_root)
    except HandoffContractError as exc:
        issue = _issue(exc.code, exc.message, None)
        return {"ok": False, "issue_codes": [issue["code"]], "issues": [issue], "classification": "unverifiable"}
    issues: list[dict[str, Any]] = []
    if existing.get("generated_from_revision") != current.get("generated_from_revision"):
        issues.append(_issue("HANDOFF_STALE_REVISION", "handoff state revision differs from authoritative state", HANDOFF_STATE_FILENAME))
    if existing.get("generated_from_event_sequence") != current.get("generated_from_event_sequence"):
        issues.append(_issue("HANDOFF_STALE_EVENT_SEQUENCE", "handoff event sequence differs from authoritative journal", HANDOFF_STATE_FILENAME))
    if existing.get("tested_ref") != current.get("tested_ref"):
        issues.append(_issue("HANDOFF_TESTED_REF_DRIFT", "handoff tested_ref differs from authoritative structured sources", HANDOFF_STATE_FILENAME))
    if existing.get("variant_analysis") != current.get("variant_analysis"):
        issues.append(_issue("HANDOFF_VARIANT_ANALYSIS_DRIFT", "handoff formal variant-analysis status differs from authoritative artifacts", HANDOFF_STATE_FILENAME))
    if existing.get("artifacts") != current.get("artifacts"):
        issues.append(_issue("HANDOFF_ARTIFACT_DIGEST_DRIFT", "handoff artifact digest index differs from authoritative files", HANDOFF_STATE_FILENAME))
    if existing.get("counts") != current.get("counts") or existing.get("identifiers") != current.get("identifiers"):
        issues.append(_issue("HANDOFF_COUNT_ID_DRIFT", "handoff counts or stable IDs differ from authoritative structured files", HANDOFF_STATE_FILENAME))
    if existing.get("integrity", {}).get("journal_digest") != current.get("integrity", {}).get("journal_digest"):
        issues.append(_issue("HANDOFF_JOURNAL_DIGEST_DRIFT", "handoff journal digest differs from the authoritative journal", HANDOFF_STATE_FILENAME))
    if existing.get("integrity", {}).get("state_digest") != current.get("integrity", {}).get("state_digest"):
        issues.append(_issue("HANDOFF_STATE_DIGEST_DRIFT", "handoff state digest differs from the authoritative state view", HANDOFF_STATE_FILENAME))
    if not issues and existing != current:
        issues.append(_issue("HANDOFF_DERIVED_FIELD_DRIFT", "handoff derived fields differ from the current snapshot", HANDOFF_STATE_FILENAME))
    completion_issues = [
        item for item in current.get("integrity", {}).get("issues", [])
        if isinstance(item, dict) and str(item.get("code") or "").startswith("COMPLETION_")
    ]
    if not issues and completion_issues:
        issues.extend(completion_issues)
    classification = "current" if not issues else "blocked" if completion_issues else "stale"
    result = {"ok": not issues, "issue_codes": sorted({str(item["code"]) for item in issues}), "issues": issues, "classification": classification}
    if not issues:
        result["state"] = existing
    return result


def validate_handoff_state_current(workspace: Path, repo_root: Path | None = None) -> dict[str, Any]:
    workspace = workspace.absolute()
    repo_root = (repo_root or workspace.parent).absolute()
    with workspace_lock(workspace, 10.0):
        return _validate_handoff_state_current_unlocked(workspace, repo_root)


def checkpoint_document_from_handoff(workspace: Path, handoff: dict[str, Any]) -> dict[str, Any]:
    revision = handoff.get("generated_from_revision")
    sequence = handoff.get("generated_from_event_sequence")
    if type(revision) is not int or revision < 1 or type(sequence) is not int or sequence < 1:
        raise _contract_error("CHECKPOINT_R1_UNSUPPORTED", "R1/legacy handoff state cannot invent an R2 checkpoint revision")
    event_digest = handoff.get("integrity", {}).get("journal_digest")
    if not isinstance(event_digest, str):
        raise _contract_error("CHECKPOINT_SOURCE_UNVERIFIABLE", "handoff journal digest is missing")
    input_items = [
        {"path": item["path"], "sha256": item["sha256"], "kind": item["kind"]}
        for item in handoff.get("artifacts", [])
        if isinstance(item, dict) and item.get("path") not in {HANDOFF_STATE_FILENAME}
    ]
    input_items = sorted(input_items, key=lambda item: item["path"])
    created_at = "unknown"
    try:
        state = read_workspace_snapshot(workspace).state or {}
        created_at = _sanitize_text(state.get("last_event_at"), fallback="unknown")
    except AuditStateError:
        pass
    safe_resume = dict(handoff.get("resume") or {})
    safe_resume["parameters"] = [
        item for item in safe_resume.get("parameters", [])
        if isinstance(item, dict) and item.get("name") in {"workspace-dir", "repo-root", "checkpoint", "artifact"} and isinstance(item.get("value"), str)
    ]
    safe_resume.setdefault("available", False)
    safe_resume.setdefault("entrypoint", "none")
    safe_resume.setdefault("evidence_refs", [])
    document = {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "state_revision": revision,
        "event_sequence": sequence,
        "event_digest": event_digest,
        "tested_ref": {
            "value": handoff.get("tested_ref", {}).get("value"),
            "verified": bool(handoff.get("tested_ref", {}).get("verified")),
            "source_paths": sorted(handoff.get("tested_ref", {}).get("source_paths", [])),
        },
        "created_at": created_at,
        "provenance": {
            "plugin": "zhulong",
            "plugin_version": str(handoff.get("plugin_version") or "unknown"),
            "protocol_mode": "r2",
            "source": "state-and-journal",
            "authority_boundary": "derived_snapshot_only",
        },
        "authoritative_inputs": input_items,
        "identifiers": handoff.get("identifiers"),
        "docker": {"status": handoff.get("docker", {}).get("status", "unknown"), "path": handoff.get("docker", {}).get("path"), "sha256": handoff.get("docker", {}).get("sha256")},
        "docker_baseline": {"status": handoff.get("docker_baseline", {}).get("status", "unknown"), "path": handoff.get("docker_baseline", {}).get("path"), "sha256": handoff.get("docker_baseline", {}).get("sha256")},
        "recon": {"status": handoff.get("recon", {}).get("status", "missing"), "path": handoff.get("recon", {}).get("path"), "sha256": handoff.get("recon", {}).get("sha256")},
        "triage": {"status": handoff.get("triage", {}).get("status", "missing"), "path": handoff.get("triage", {}).get("path"), "sha256": handoff.get("triage", {}).get("sha256")},
        "handoff_state": {"path": HANDOFF_STATE_FILENAME, "sha256": _sha256_regular_file(workspace / HANDOFF_STATE_FILENAME), "kind": "handoff_state"},
        "resume": safe_resume,
    }
    sensitive_text = first_sensitive_document_text(document)
    if sensitive_text is not None:
        field, category = sensitive_text
        raise _contract_error(
            "CHECKPOINT_SENSITIVE_TEXT_FORBIDDEN",
            f"{field} contains sensitive material of category {category}",
            field=field,
            category=category,
        )
    return document


def create_workspace_checkpoint(workspace: Path, repo_root: Path | None = None) -> dict[str, Any]:
    workspace = workspace.absolute()
    repo_root = (repo_root or workspace.parent).absolute()
    with workspace_lock(workspace, 10.0):
        current_check = _validate_handoff_state_current_unlocked(workspace, repo_root)
        if not current_check.get("ok"):
            raise _contract_error("CHECKPOINT_REQUIRES_CURRENT_HANDOFF", "checkpoint creation requires a current valid handoff-state.json", issues=current_check.get("issues", []))
        handoff = read_handoff_state(workspace)
        second_check = _validate_handoff_state_current_unlocked(workspace, repo_root)
        if not second_check.get("ok") or second_check.get("state") != handoff:
            raise _contract_error("CONCURRENT_STATE_CHANGED", "authoritative inputs changed during checkpoint derivation")
        payload = checkpoint_document_from_handoff(workspace, handoff)
        revision = int(payload["state_revision"])
        checkpoint_dir = workspace / CHECKPOINT_DIRNAME
        if checkpoint_dir.exists() or checkpoint_dir.is_symlink():
            _safe_workspace_dir(workspace, CHECKPOINT_DIRNAME, allow_missing=False)
        else:
            checkpoint_dir.mkdir(mode=0o700)
        checkpoint_path = checkpoint_dir / f"{revision}.json"
        raw = _canonical_json_bytes(payload)
        if checkpoint_path.exists() or checkpoint_path.is_symlink():
            _safe_workspace_path(workspace, f"{CHECKPOINT_DIRNAME}/{revision}.json", field="checkpoint", allow_missing=False)
            existing_raw = checkpoint_path.read_bytes()
            if existing_raw == raw:
                return {"ok": True, "idempotent": True, "path": f"{CHECKPOINT_DIRNAME}/{revision}.json", "state_revision": revision, "sha256": _sha256_bytes(raw)}
            raise _contract_error("CHECKPOINT_CONFLICTING_BYTES", "same-revision checkpoint exists with different bytes", path=f"{CHECKPOINT_DIRNAME}/{revision}.json")
        _atomic_write_contract(checkpoint_path, raw, workspace, fault_prefix="CHECKPOINT")
        return {"ok": True, "idempotent": False, "path": f"{CHECKPOINT_DIRNAME}/{revision}.json", "state_revision": revision, "sha256": _sha256_bytes(raw)}


def validate_workspace_checkpoint(workspace: Path, checkpoint_relative: str, repo_root: Path | None = None) -> dict[str, Any]:
    workspace = workspace.absolute()
    repo_root = (repo_root or workspace.parent).absolute()
    try:
        checkpoint_path = _safe_workspace_path(workspace, checkpoint_relative, field="checkpoint", allow_missing=False)
        if not checkpoint_relative.startswith(f"{CHECKPOINT_DIRNAME}/") or not checkpoint_relative.endswith(".json"):
            raise _contract_error("CHECKPOINT_FILENAME_MISMATCH", "checkpoint must be a workspace-relative checkpoints/<revision>.json path")
        document = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    except HandoffContractError as exc:
        issue = _issue(exc.code, exc.message, checkpoint_relative)
        return {"ok": False, "classification": "unverifiable", "issue_codes": [issue["code"]], "issues": [issue]}
    except (OSError, UnicodeError, json.JSONDecodeError):
        issue = _issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint is not valid UTF-8 JSON", checkpoint_relative)
        return {"ok": False, "classification": "unverifiable", "issue_codes": [issue["code"]], "issues": [issue]}
    issues = _validate_contract_shape(document, checkpoint=True)
    sensitive_text = first_sensitive_document_text(document)
    if sensitive_text is not None:
        field, category = sensitive_text
        issues.append(_issue("CHECKPOINT_SENSITIVE_TEXT_FORBIDDEN", f"{field} contains sensitive material of category {category}", field))
    if not issues:
        def checkpoint_path_check(value: Any, field: str, *, nullable: bool = False, allow_dot: bool = False) -> None:
            if nullable and value is None:
                return
            try:
                _validate_relative_text(value, field, allow_dot=allow_dot)
            except HandoffContractError as exc:
                issues.append(_issue(exc.code, exc.message, field))

        def checkpoint_digest_check(value: Any, field: str, *, nullable: bool = False) -> None:
            if nullable and value is None:
                return
            if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
                issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint digest is malformed", field))

        if type(document.get("state_revision")) is not int or document.get("state_revision", 0) < 1 or type(document.get("event_sequence")) is not int or document.get("event_sequence", 0) < 1:
            issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint revisions must be positive integers", checkpoint_relative))
        if type(document.get("state_revision")) is int and type(document.get("event_sequence")) is int and document.get("state_revision") != document.get("event_sequence"):
            issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "R2 checkpoint state_revision and event_sequence must agree", checkpoint_relative))
        checkpoint_digest_check(document.get("event_digest"), "event_digest")
        tested = document.get("tested_ref")
        if _require_exact_object(tested, "tested_ref", {"value", "verified", "source_paths"}, issues):
            if type(tested.get("verified")) is not bool or not isinstance(tested.get("source_paths"), list):
                issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint tested_ref has invalid field types", "tested_ref"))
            elif tested.get("value") is not None and (not isinstance(tested.get("value"), str) or not str(tested.get("value")).strip()):
                issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint tested_ref.value is invalid", "tested_ref.value"))
            for path in tested.get("source_paths", []) if isinstance(tested.get("source_paths"), list) else []:
                checkpoint_path_check(path, "tested_ref.source_paths")
        if not isinstance(document.get("created_at"), str) or not document.get("created_at", "").strip():
            issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint created_at must be non-empty", "created_at"))
        provenance = document.get("provenance")
        if _require_exact_object(provenance, "provenance", {"plugin", "plugin_version", "protocol_mode", "source", "authority_boundary"}, issues) and (provenance.get("plugin") != "zhulong" or provenance.get("protocol_mode") != "r2" or provenance.get("authority_boundary") != "derived_snapshot_only" or not isinstance(provenance.get("plugin_version"), str) or not provenance.get("plugin_version", "").strip() or provenance.get("source") not in {"audit-events.jsonl", "state-and-journal"}):
            issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint provenance is invalid", "provenance"))
        inputs = document.get("authoritative_inputs")
        if not isinstance(inputs, list):
            issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "authoritative_inputs must be a list", "authoritative_inputs"))
        else:
            paths: list[str] = []
            for item in inputs:
                if not _require_exact_object(item, "authoritative_inputs", {"path", "sha256", "kind"}, issues):
                    issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint input entry is invalid", "authoritative_inputs"))
                    continue
                checkpoint_path_check(item.get("path"), "authoritative_inputs.path")
                checkpoint_digest_check(item.get("sha256"), "authoritative_inputs.sha256")
                if not isinstance(item.get("kind"), str) or not item.get("kind", "").strip():
                    issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint input kind is invalid", "authoritative_inputs.kind"))
                if isinstance(item.get("path"), str):
                    paths.append(item["path"])
            if paths != sorted(paths) or len(paths) != len(set(paths)):
                issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint input paths must be sorted and unique", "authoritative_inputs"))
        identifiers = document.get("identifiers")
        if _require_exact_object(identifiers, "identifiers", {"candidate_ids", "verdict_candidate_ids", "disposition_ids", "confirmed_bundle_ids"}, issues):
            for key in identifiers:
                values = identifiers[key]
                if not isinstance(values, list) or values != sorted(values) or len(values) != len(set(values)) or any(not isinstance(item, str) or not item.strip() for item in values):
                    issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint identifier lists must be sorted and unique", f"identifiers.{key}"))
                if key in {"candidate_ids", "verdict_candidate_ids"} and isinstance(values, list) and any(not re.fullmatch(r"CAND-[0-9A-Za-z._-]+", item) for item in values if isinstance(item, str)):
                    issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "candidate identifier is malformed", f"identifiers.{key}"))
        for field in ("docker", "docker_baseline", "recon", "triage"):
            ref = document.get(field)
            if _require_exact_object(ref, field, {"status", "path", "sha256"}, issues):
                if not isinstance(ref.get("status"), str) or not ref.get("status", "").strip():
                    issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint status reference has no status", field))
                checkpoint_path_check(ref.get("path"), f"{field}.path", nullable=True)
                checkpoint_digest_check(ref.get("sha256"), f"{field}.sha256", nullable=True)
        handoff_ref = document.get("handoff_state")
        if _require_exact_object(handoff_ref, "handoff_state", {"path", "sha256", "kind"}, issues) and (handoff_ref.get("path") != HANDOFF_STATE_FILENAME or handoff_ref.get("kind") != "handoff_state"):
            issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint handoff_state reference is invalid", "handoff_state"))
        elif isinstance(handoff_ref, dict):
            checkpoint_digest_check(handoff_ref.get("sha256"), "handoff_state.sha256")
        resume = document.get("resume")
        if not _require_exact_object(resume, "resume", {"available", "entrypoint", "parameters", "evidence_refs"}, issues, optional={"step"}):
            issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint resume contract is invalid", "resume"))
        elif resume.get("entrypoint") not in {"none", "manual_review", "render_handoff_state", "validate_handoff_state", "resume_stage"} or type(resume.get("available")) is not bool or not isinstance(resume.get("parameters"), list) or not isinstance(resume.get("evidence_refs"), list) or (resume.get("step") is not None and (not isinstance(resume.get("step"), str) or not resume.get("step", "").strip())):
            issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint resume contract is invalid", "resume"))
        if isinstance(resume, dict) and isinstance(resume.get("parameters"), list) and isinstance(resume.get("evidence_refs"), list):
            for item in resume.get("parameters", []):
                if _require_exact_object(item, "resume.parameters", {"name", "value"}, issues):
                    if item.get("name") not in {"workspace-dir", "repo-root", "checkpoint", "artifact"}:
                        issues.append(_issue("CHECKPOINT_SCHEMA_INVALID", "checkpoint resume contains an unsafe parameter", "resume.parameters"))
                    checkpoint_path_check(item.get("value"), "resume.parameters.value", allow_dot=True)
            for item in resume.get("evidence_refs", []):
                checkpoint_path_check(item, "resume.evidence_refs")
        stem = Path(checkpoint_relative).stem
        if not stem.isdigit() or str(int(stem)) != stem or int(stem) != document.get("state_revision"):
            issues.append(_issue("CHECKPOINT_FILENAME_MISMATCH", "checkpoint filename and internal state_revision differ", checkpoint_relative))
        if document.get("provenance", {}).get("protocol_mode") != "r2":
            issues.append(_issue("CHECKPOINT_R1_UNSUPPORTED", "checkpoint provenance cannot claim R1 as an R2 snapshot", checkpoint_relative))
    if issues:
        return {"ok": False, "classification": "tampered_or_unverifiable", "issue_codes": sorted({str(item["code"]) for item in issues}), "issues": issues}
    current_check = validate_handoff_state_current(workspace, repo_root)
    if not current_check.get("ok"):
        issue = _issue("CHECKPOINT_CURRENT_HANDOFF_UNVERIFIABLE", "current handoff state cannot be used to compare checkpoint", HANDOFF_STATE_FILENAME)
        return {"ok": False, "classification": "unverifiable", "issue_codes": [issue["code"]], "issues": [issue]}
    current_handoff = current_check.get("state") or read_handoff_state(workspace)
    current_revision = current_handoff.get("generated_from_revision")
    checkpoint_revision = document.get("state_revision")
    if type(document.get("event_sequence")) is int and isinstance(document.get("event_digest"), str):
        try:
            snapshot = read_workspace_snapshot(workspace)
            prefix_digest = snapshot.journal.inspection.prefix_digests.get(document["event_sequence"])
        except AuditStateError:
            prefix_digest = None
        if prefix_digest != document.get("event_digest"):
            issue = _issue("CHECKPOINT_EVENT_DIGEST_DRIFT", "checkpoint event digest is not a journal prefix digest", checkpoint_relative)
            if type(current_revision) is int and type(checkpoint_revision) is int and checkpoint_revision < current_revision:
                return {"ok": False, "classification": "historical_unverifiable", "issue_codes": [issue["code"]], "issues": [issue]}
            return {"ok": False, "classification": "tampered_or_unverifiable", "issue_codes": [issue["code"]], "issues": [issue]}
    if type(current_revision) is int and checkpoint_revision < current_revision:
        # A prior revision is a legal historical snapshot when its own index is
        # structurally valid and its referenced files still match the index.
        ref_issues: list[dict[str, Any]] = []
        for item in document.get("authoritative_inputs", []):
            # Journal/state/handoff bytes necessarily move when a newer event is
            # appended and a current handoff is regenerated; they do not make a
            # previously valid index an invalid historical snapshot.
            if item.get("path") in {"audit-events.jsonl", "stage-status.json", HANDOFF_STATE_FILENAME}:
                continue
            try:
                path = _safe_workspace_path(workspace, item["path"], field="checkpoint.authoritative_inputs.path", allow_missing=False)
                if _sha256_regular_file(path) != item.get("sha256"):
                    ref_issues.append(_issue("CHECKPOINT_HISTORICAL_INPUT_CHANGED", "historical input digest is no longer present", item["path"]))
            except (HandoffContractError, OSError):
                ref_issues.append(_issue("CHECKPOINT_HISTORICAL_INPUT_UNVERIFIABLE", "historical input cannot be revalidated", str(item.get("path") or "")))
        if ref_issues:
            return {"ok": False, "classification": "historical_unverifiable", "issue_codes": sorted({str(item["code"]) for item in ref_issues}), "issues": ref_issues}
        current_ids = current_handoff.get("identifiers") if isinstance(current_handoff.get("identifiers"), dict) else {}
        old_ids = document.get("identifiers") if isinstance(document.get("identifiers"), dict) else {}
        for key in ("candidate_ids", "verdict_candidate_ids", "disposition_ids", "confirmed_bundle_ids"):
            old_values = set(old_ids.get(key, [])) if isinstance(old_ids.get(key), list) else set()
            current_values = set(current_ids.get(key, [])) if isinstance(current_ids.get(key), list) else set()
            if not old_values.issubset(current_values):
                issue = _issue("CHECKPOINT_HISTORICAL_ID_UNVERIFIABLE", "historical stable ID is not present in current structured material", checkpoint_relative)
                return {"ok": False, "classification": "historical_unverifiable", "issue_codes": [issue["code"]], "issues": [issue]}
        return {"ok": True, "classification": "valid_historical", "issue_codes": [], "issues": [], "state_revision": checkpoint_revision}
    if type(current_revision) is not int or checkpoint_revision > current_revision:
        issue = _issue("CHECKPOINT_FUTURE_REVISION", "checkpoint revision is newer than current authoritative state", checkpoint_relative)
        return {"ok": False, "classification": "unverifiable", "issue_codes": [issue["code"]], "issues": [issue]}
    expected = checkpoint_document_from_handoff(workspace, current_handoff)
    if document != expected:
        issues = [_issue("CHECKPOINT_CURRENT_DIGEST_DRIFT", "current checkpoint bytes do not match authoritative handoff snapshot", checkpoint_relative)]
        return {"ok": False, "classification": "tampered", "issue_codes": [issues[0]["code"]], "issues": issues}
    return {"ok": True, "classification": "current", "issue_codes": [], "issues": [], "state_revision": checkpoint_revision}
