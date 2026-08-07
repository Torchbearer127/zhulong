#!/usr/bin/env python3
"""Safe file-backed I/O for the Zhulong audit-state protocol.

This module deliberately implements a single-record commit, not a two-file
transaction.  ``audit-events.jsonl`` is committed first; ``stage-status.json``
is a derived view that is replaced only after the journal is durable.
"""
from __future__ import annotations

import errno
import json
import os
import stat
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from audit_text_safety import first_sensitive_document_text, first_sensitive_r2_event_text
from audit_transition_policy import (
    TRANSITION_POLICY_VERSION,
    TransitionPolicyError,
    TransitionState,
    validate_transition,
    validate_transition_metadata,
    validate_transition_sequence,
)
from validate_audit_protocol import (
    JournalInspection,
    ProtocolValidationError,
    detect_state_mode,
    inspect_journal_bytes,
    parse_json,
    sha256_digest,
    validate_event_document,
    validate_r2_event,
    validate_state_document,
)


EVENTS_FILE = "audit-events.jsonl"
STATE_FILE = "stage-status.json"
LOCK_FILE = ".audit-state.lock"
DEFAULT_LOCK_TIMEOUT_SECONDS = 10.0


class AuditStateError(Exception):
    """Stable, caller-safe failure from the audit-state I/O layer."""

    def __init__(self, code: str, message: str, **fields: Any) -> None:
        self.code = code
        self.message = message
        self.fields = fields
        super().__init__(message)


@dataclass(frozen=True)
class JournalInfo:
    mode: str
    events: list[dict[str, Any]]
    raw_bytes: bytes
    inspection: JournalInspection


@dataclass(frozen=True)
class WorkspaceSnapshot:
    mode: str
    journal: JournalInfo
    state: dict[str, Any] | None
    state_raw: bytes | None = None


@dataclass(frozen=True)
class WriteResult:
    mode: str
    seq: int | None
    state_revision: int | None
    journal_committed: bool
    state_view_updated: bool
    cas_mode: str
    ignored_fields: tuple[str, ...] = ()
    compatibility_code: str | None = None
    compatibility_diagnostic: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "ok": True,
            "mode": self.mode,
            "seq": self.seq,
            "state_revision": self.state_revision,
            "journal_committed": self.journal_committed,
            "state_view_updated": self.state_view_updated,
            "cas_mode": self.cas_mode,
        }
        if self.ignored_fields:
            payload["ignored_fields"] = list(self.ignored_fields)
        if self.compatibility_code:
            payload["compatibility_code"] = self.compatibility_code
        if self.compatibility_diagnostic:
            payload["compatibility_diagnostic"] = self.compatibility_diagnostic
        return payload


def _path_is_regular_or_missing(path: Path, code: str) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise AuditStateError(code, "audit-state path cannot be inspected") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise AuditStateError(code, "audit-state path must be a non-symlink regular file")
    return True


def _nofollow_flag() -> int:
    return int(getattr(os, "O_NOFOLLOW", 0))


def _read_regular_bytes(path: Path, code: str) -> bytes | None:
    if not _path_is_regular_or_missing(path, code):
        return None
    flags = os.O_RDONLY | _nofollow_flag()
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise AuditStateError(code, "audit-state path is unsafe") from exc
        raise AuditStateError(code, "audit-state path cannot be read") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise AuditStateError(code, "audit-state path must be a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(fd)


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def _write_state_temp(fd: int, payload: bytes) -> None:
    """Narrow internal seam for deterministic state-temp fault tests."""
    _write_all(fd, payload)


def _safe_append_fsync(path: Path, payload: bytes) -> None:
    _path_is_regular_or_missing(path, "JOURNAL_PATH_UNSAFE")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | _nofollow_flag()
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise AuditStateError("JOURNAL_PATH_UNSAFE", "audit journal path is unsafe") from exc
        raise AuditStateError("JOURNAL_APPEND_FAILED", "audit journal cannot be opened") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise AuditStateError("JOURNAL_PATH_UNSAFE", "audit journal must be a regular file")
        _write_all(fd, payload)
        os.fsync(fd)
    except AuditStateError:
        raise
    except OSError as exc:
        raise AuditStateError("JOURNAL_APPEND_FAILED", "audit journal append or fsync failed") from exc
    finally:
        os.close(fd)


def _fsync_directory(workspace: Path) -> None:
    try:
        fd = os.open(workspace, os.O_RDONLY)
    except OSError:
        return
    try:
        try:
            os.fsync(fd)
        except OSError as exc:
            # APFS and some supported filesystems do not permit directory fsync.
            if exc.errno not in {errno.EINVAL, errno.ENOTSUP, errno.EBADF}:
                raise
    finally:
        os.close(fd)


def _atomic_replace_state(workspace: Path, payload: bytes) -> None:
    state_path = workspace / STATE_FILE
    _path_is_regular_or_missing(state_path, "STATE_PATH_UNSAFE")
    temp_path: Path | None = None
    try:
        fd, raw_temp = tempfile.mkstemp(prefix=".stage-status.", suffix=".tmp", dir=workspace)
        temp_path = Path(raw_temp)
        os.fchmod(fd, 0o600)
        try:
            _write_state_temp(fd, payload)
            os.fsync(fd)
        except OSError as exc:
            raise AuditStateError("STATE_VIEW_WRITE_FAILED", "state view temporary write or fsync failed") from exc
        finally:
            os.close(fd)
        _path_is_regular_or_missing(state_path, "STATE_PATH_UNSAFE")
        try:
            os.replace(temp_path, state_path)
        except OSError as exc:
            raise AuditStateError("STATE_VIEW_REPLACE_FAILED", "state view atomic replacement failed") from exc
        temp_path = None
        _fsync_directory(workspace)
    except AuditStateError:
        raise
    except OSError as exc:
        raise AuditStateError("STATE_VIEW_WRITE_FAILED", "state view temporary file cannot be created") from exc
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


@contextmanager
def workspace_lock(workspace: Path, timeout_seconds: float) -> Iterator[None]:
    """Take the persistent per-workspace advisory lock or fail closed."""
    if timeout_seconds < 0 or timeout_seconds > 60:
        raise AuditStateError("LOCK_TIMEOUT", "lock timeout must be between 0 and 60 seconds")
    try:
        import fcntl  # POSIX only; deliberately no unlocked fallback.
    except ImportError as exc:
        raise AuditStateError("LOCK_UNSUPPORTED", "no supported advisory lock backend is available") from exc

    lock_path = workspace / LOCK_FILE
    _path_is_regular_or_missing(lock_path, "LOCK_PATH_UNSAFE")
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | _nofollow_flag(), 0o600)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise AuditStateError("LOCK_PATH_UNSAFE", "audit-state lock path is unsafe") from exc
        raise AuditStateError("LOCK_PATH_UNSAFE", "audit-state lock cannot be opened") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AuditStateError("LOCK_PATH_UNSAFE", "audit-state lock must be a regular file")
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise AuditStateError("LOCK_TIMEOUT", "audit-state lock timed out before any write")
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
            except OSError as exc:
                raise AuditStateError("LOCK_UNSUPPORTED", "advisory lock acquisition failed") from exc
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def _parse_journal(raw: bytes) -> JournalInfo:
    inspection = inspect_journal_bytes(raw)
    if inspection.issues:
        issue = inspection.issues[0]
        if issue.code == "JOURNAL_EMPTY":
            return JournalInfo("empty", [], raw, inspection)
        raise AuditStateError(
            issue.code,
            issue.message,
            line=issue.line,
            byte_offset=issue.byte_offset,
            validator_code=issue.validator_code,
            journal_digest=inspection.digest,
            valid_prefix_digest=inspection.valid_prefix_digest,
        )
    return JournalInfo(inspection.mode, inspection.events, raw, inspection)


def _parse_state(raw: bytes | None) -> dict[str, Any] | None:
    if raw is None:
        return None
    try:
        value = parse_json(raw.decode("utf-8"))
    except (UnicodeDecodeError, ProtocolValidationError) as exc:
        raise AuditStateError("STATE_VIEW_OUT_OF_SYNC", "state view is not valid JSON") from exc
    if not isinstance(value, dict):
        raise AuditStateError("STATE_VIEW_OUT_OF_SYNC", "state view must be a JSON object")
    try:
        validate_state_document(value)
    except ProtocolValidationError as exc:
        raise AuditStateError("STATE_VIEW_OUT_OF_SYNC", "state view is invalid") from exc
    return value


def _digest(raw: bytes) -> str:
    return sha256_digest(raw)


def _validate_r2_state_sync(journal: JournalInfo, state: dict[str, Any]) -> None:
    if not journal.events:
        raise AuditStateError("STATE_VIEW_OUT_OF_SYNC", "R2 state exists without an R2 journal")
    latest = journal.events[-1]
    comparisons = {
        "run_id": latest["run_id"],
        "last_event_seq": latest["seq"],
        "state_revision": len(journal.events),
        "event_log_digest": _digest(journal.raw_bytes),
        "stage": latest["stage"],
        "status": latest["to_status"],
        "last_event_at": latest["ts"],
        "last_event_type": latest["event_type"],
        "last_event_name": latest["event_name"],
    }
    if "plugin_version" in latest:
        comparisons["plugin_version"] = latest["plugin_version"]
    if "blocker" in latest and "resume_step" in latest:
        comparisons["blocker"] = latest["blocker"]
        comparisons["resume_step"] = latest["resume_step"]
    if any(state.get(key) != value for key, value in comparisons.items()):
        raise AuditStateError("STATE_VIEW_OUT_OF_SYNC", "state view does not match the committed R2 journal")


STATE_DERIVED_FIELDS = (
    "schema_version",
    "plugin",
    "plugin_version",
    "run_id",
    "state_revision",
    "last_event_seq",
    "event_log_digest",
    "stage",
    "status",
    "last_event_at",
    "last_event_type",
    "last_event_name",
    "blocker",
    "resume_step",
)


def _state_inspection(raw: bytes | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "presence": "missing" if raw is None else "present",
        "classification": "missing" if raw is None else "invalid",
        "digest": None if raw is None else _digest(raw),
        "document": None,
        "issues": [],
    }
    if raw is None:
        result["issues"].append({"code": "STATE_VIEW_MISSING", "message": "stage-status.json is missing"})
        return result
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        result["classification"] = "invalid_utf8"
        result["issues"].append({"code": "STATE_INVALID_UTF8", "message": "state view is not UTF-8"})
        return result
    try:
        value = parse_json(text)
    except ProtocolValidationError as exc:
        result["classification"] = "invalid_json"
        result["issues"].append({"code": "STATE_INVALID_JSON", "message": "state view is not valid JSON", "validator_code": exc.code})
        return result
    if not isinstance(value, dict):
        result["classification"] = "invalid_json_root"
        result["issues"].append({"code": "STATE_ROOT_NOT_OBJECT", "message": "state view must be a JSON object"})
        return result
    try:
        validated = validate_state_document(value)
    except ProtocolValidationError as exc:
        result["classification"] = "invalid_schema"
        result["issues"].append({"code": "STATE_SCHEMA_INVALID", "message": "state view failed canonical validation", "validator_code": exc.code})
        return result
    result["classification"] = str(validated["mode"])
    result["document"] = value
    return result


def _event_state_values(event: dict[str, Any], *, revision: int, digest: str) -> dict[str, Any]:
    values: dict[str, Any] = {
        "schema_version": 2,
        "plugin": "zhulong",
        "run_id": event["run_id"],
        "state_revision": revision,
        "last_event_seq": event["seq"],
        "event_log_digest": digest,
        "stage": event["stage"],
        "status": event["to_status"],
        "last_event_at": event["ts"],
        "last_event_type": event["event_type"],
        "last_event_name": event["event_name"],
    }
    if "plugin_version" in event:
        values["plugin_version"] = event["plugin_version"]
    if "blocker" in event and "resume_step" in event:
        values["blocker"] = event["blocker"]
        values["resume_step"] = event["resume_step"]
    elif event["to_status"] in {"running", "completed"}:
        values["blocker"] = None
        values["resume_step"] = None
    return values


def _anchored_legacy_state(inspection: JournalInspection, state: dict[str, Any] | None) -> dict[str, Any] | None:
    if not state or state.get("schema_version") != 2:
        return None
    seq = state.get("last_event_seq")
    if type(seq) is not int or seq < 1 or seq > len(inspection.records):
        return None
    if state.get("state_revision") != seq:
        return None
    if state.get("event_log_digest") != inspection.prefix_digests.get(seq):
        return None
    expected = _event_state_values(
        inspection.records[seq - 1].event,
        revision=seq,
        digest=str(inspection.prefix_digests[seq]),
    )
    for key, value in expected.items():
        if key in {"plugin_version", "blocker", "resume_step"}:
            continue
        if state.get(key) != value:
            return None
    event = inspection.records[seq - 1].event
    if "plugin_version" in event and state.get("plugin_version") != event.get("plugin_version"):
        return None
    if "blocker" in event and (
        state.get("blocker") != event.get("blocker") or state.get("resume_step") != event.get("resume_step")
    ):
        return None
    return state


def derive_r2_state(
    inspection: JournalInspection,
    current_state: dict[str, Any] | None,
) -> tuple[dict[str, Any], str, list[str], dict[str, int] | None]:
    """Derive the exact R2 view from valid journal facts and proven legacy metadata."""
    if inspection.mode != "r2" or not inspection.is_complete_valid or not inspection.records:
        raise AuditStateError("STATE_REBUILD_JOURNAL_INVALID", "R2 state derivation requires a complete valid R2 journal")
    latest = inspection.records[-1].event
    anchored = _anchored_legacy_state(inspection, current_state)
    used_legacy: list[str] = []
    anchor_provenance: dict[str, int] | None = None
    plugin_version = latest.get("plugin_version")
    if not isinstance(plugin_version, str) or not plugin_version.strip():
        if anchored is not None:
            plugin_version = anchored.get("plugin_version")
            used_legacy.append("plugin_version")
            anchor_seq = int(anchored["last_event_seq"])
            anchor_provenance = {
                "source_prefix_seq": anchor_seq,
                "source_prefix_revision": int(anchored["state_revision"]),
                "later_event_count": len(inspection.records) - anchor_seq,
            }
        else:
            raise AuditStateError(
                "STATE_REBUILD_METADATA_UNAVAILABLE",
                "latest historical R2 event does not prove plugin_version",
                missing_fields=["plugin_version"],
            )
    blocker: str | None
    resume_step: str | None
    if "blocker" in latest and "resume_step" in latest:
        blocker = latest.get("blocker")
        resume_step = latest.get("resume_step")
    elif latest.get("to_status") in {"running", "completed"}:
        blocker = None
        resume_step = None
    elif anchored is not None and anchored.get("last_event_seq") == latest.get("seq"):
        blocker = anchored.get("blocker")
        resume_step = anchored.get("resume_step")
        used_legacy.extend(["blocker", "resume_step"])
    else:
        raise AuditStateError(
            "STATE_REBUILD_METADATA_UNAVAILABLE",
            "latest historical paused/blocked event does not prove blocker context",
            missing_fields=["blocker", "resume_step"],
        )
    state = {
        "schema_version": 2,
        "plugin": "zhulong",
        "plugin_version": plugin_version,
        "run_id": latest["run_id"],
        "state_revision": len(inspection.records),
        "last_event_seq": latest["seq"],
        "event_log_digest": inspection.digest,
        "stage": latest["stage"],
        "status": latest["to_status"],
        "last_event_at": latest["ts"],
        "last_event_type": latest["event_type"],
        "last_event_name": latest["event_name"],
        "blocker": blocker,
        "resume_step": resume_step,
    }
    try:
        validate_state_document(state)
    except ProtocolValidationError as exc:
        raise AuditStateError("STATE_REBUILD_DERIVED_STATE_INVALID", "derived state failed canonical validation", validator_code=exc.code) from exc
    rebuildability = "complete_with_anchored_legacy_metadata" if used_legacy else "complete_from_journal"
    return state, rebuildability, sorted(set(used_legacy)), anchor_provenance


def inspect_workspace_recovery(workspace: Path) -> dict[str, Any]:
    """Return a deterministic, path-redacted recovery diagnostic without writes."""
    journal_raw = _read_regular_bytes(workspace / EVENTS_FILE, "JOURNAL_PATH_UNSAFE")
    state_raw = _read_regular_bytes(workspace / STATE_FILE, "STATE_PATH_UNSAFE")
    raw = journal_raw or b""
    inspection = inspect_journal_bytes(raw)
    state_info = _state_inspection(state_raw)
    issues = [issue.as_dict() for issue in inspection.issues]
    issues.extend(dict(issue) for issue in state_info.get("issues", []))
    if (
        inspection.mode in {"r2", "legacy_r1"}
        and state_info.get("classification") in {"r2", "legacy_r1"}
        and inspection.mode != state_info.get("classification")
    ):
        issues.append({
            "code": "STATE_PROTOCOL_MODE_MISMATCH",
            "message": "journal and state view use different protocol modes",
        })
    expected_state: dict[str, Any] | None = None
    rebuildability = "blocked_journal_invalid"
    used_legacy: list[str] = []
    anchor_provenance: dict[str, int] | None = None
    drift: list[dict[str, Any]] = []
    if inspection.mode == "legacy_r1" and inspection.is_complete_valid:
        rebuildability = "not_applicable_legacy_r1"
    elif inspection.mode == "r2" and inspection.is_complete_valid:
        try:
            expected_state, rebuildability, used_legacy, anchor_provenance = derive_r2_state(inspection, state_info.get("document"))
        except AuditStateError as exc:
            rebuildability = "blocked_missing_metadata" if exc.code == "STATE_REBUILD_METADATA_UNAVAILABLE" else "blocked_journal_invalid"
            issue = {"code": exc.code, "message": exc.message}
            issue.update(exc.fields)
            issues.append(issue)
    actual_state = state_info.get("document")
    if expected_state is not None:
        if not isinstance(actual_state, dict) or actual_state.get("schema_version") != 2:
            if state_raw is None:
                drift.append({"code": "STATE_VIEW_MISSING", "field": None})
            else:
                drift.append({"code": "STATE_VIEW_INVALID", "field": None})
        else:
            code_by_field = {
                "event_log_digest": "STATE_JOURNAL_DIGEST_MISMATCH",
                "state_revision": "STATE_REVISION_MISMATCH",
                "last_event_seq": "STATE_LAST_SEQ_MISMATCH",
                "run_id": "STATE_RUN_ID_MISMATCH",
                "stage": "STATE_STAGE_MISMATCH",
                "status": "STATE_STATUS_MISMATCH",
                "blocker": "STATE_BLOCKER_MISMATCH",
                "resume_step": "STATE_RESUME_STEP_MISMATCH",
                "plugin_version": "STATE_PLUGIN_VERSION_UNPROVEN",
            }
            for field_name in STATE_DERIVED_FIELDS:
                if actual_state.get(field_name) != expected_state.get(field_name):
                    drift.append({
                        "code": code_by_field.get(field_name, "STATE_LAST_EVENT_IDENTITY_MISMATCH"),
                        "field": field_name,
                        "expected": expected_state.get(field_name),
                        "actual": actual_state.get(field_name),
                    })
    if expected_state is not None and not drift:
        state_info["classification"] = "exact_match"
    elif drift and state_info["classification"] in {"r2", "legacy_r1"}:
        state_info["classification"] = "drifted"
    migration = _r1_migration_preflight(inspection, state_info)
    return {
        "ok": not issues and not drift,
        "protocol_mode": inspection.mode,
        "journal": {
            "classification": inspection.classification,
            "event_count": len(inspection.records),
            "digest": inspection.digest,
            "valid_prefix_digest": inspection.valid_prefix_digest,
            "valid_prefix_end_offset": inspection.valid_prefix_end_offset,
            "last_valid_record_end_offset": inspection.records[-1].end_offset if inspection.records else 0,
            "transition_policy": inspection.transition_policy,
        },
        "state": {key: value for key, value in state_info.items() if key != "document"},
        "expected_state_derivable": expected_state is not None,
        "expected_state": expected_state,
        "drift": drift,
        "rebuildability": rebuildability,
        "anchored_legacy_metadata_fields": used_legacy,
        "anchored_legacy_metadata_source": anchor_provenance if used_legacy else None,
        "r1_migration_preflight": migration,
        "issues": issues,
        "recovery_guidance": "Run <workspace>/bin/recover-audit-state.py --workspace-dir <audit-workspace> --check --json; apply only after reviewing both exact digests.",
    }


def _r1_migration_preflight(inspection: JournalInspection, state_info: dict[str, Any]) -> dict[str, Any]:
    available = inspection.mode == "legacy_r1" and inspection.is_complete_valid
    result: dict[str, Any] = {
        "available": available,
        "statement": "This preflight is read-only; it is not migration, state advancement, or vulnerability confirmation.",
    }
    if not available:
        result["eligibility"] = "not_applicable"
        return result
    events = inspection.events
    state = state_info.get("document") if isinstance(state_info.get("document"), dict) else {}
    known_stages = {
        "workspace_preparing", "environment_checking", "initial_probing",
        "candidate_verifying", "reporting", "completed", "intake", "recon",
        "candidate_generation", "triage", "verification", "severity_escalation",
        "variant_discovery", "packaging", "finalization", "recording",
    }
    known_statuses = {"ok", "failed", "warning", "skipped", "running", "paused", "blocked", "completed"}
    raw_stages = {str(event.get("stage")) for event in events if str(event.get("stage"))}
    raw_statuses = {str(event.get("status")) for event in events if str(event.get("status"))}
    result.update({
        "eligibility": "blocked_requires_explicit_r2_authority",
        "journal_digest": inspection.digest,
        "state_digest": state_info.get("digest"),
        "event_count": len(events),
        "recognized_legacy_stages": sorted(raw_stages & known_stages),
        "recognized_legacy_statuses": sorted(raw_statuses & known_statuses),
        "unrecognized_stage_count": len(raw_stages - known_stages),
        "unrecognized_status_count": len(raw_statuses - known_statuses),
        "exactly_mappable_fields": ["event timestamps", "legacy event names", "legacy stage/status strings", "source byte digests"],
        "inference_required_fields": ["run_id", "seq", "expected_state_revision", "from_stage", "from_status", "transition_kind", "reason_code", "subjects", "evidence_refs", "next_actions", "plugin_version provenance", "blocker context"],
        "unsafe_field_classifications": {
            "workspace": "machine_local_or_relative_present" if state.get("workspace") else "absent",
            "target_repo": "machine_local_or_relative_present" if state.get("target_repo") else "absent",
        },
        "blockers": ["R1_RUN_ID_UNAVAILABLE", "R1_SEQUENCE_AUTHORITY_UNAVAILABLE", "R1_TRANSITION_INTENT_UNAVAILABLE"],
    })
    return result


def rebuild_state_view(
    workspace: Path,
    *,
    expected_journal_digest: str,
    expected_state_digest: str | None,
    expect_state_missing: bool,
    lock_timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Atomically replace only stage-status.json after journal/state digest CAS."""
    if bool(expected_state_digest) == bool(expect_state_missing):
        raise AuditStateError("STATE_CAS_INTENT_REQUIRED", "provide exactly one state digest or missing-state expectation")
    with workspace_lock(workspace, lock_timeout_seconds):
        journal_raw = _read_regular_bytes(workspace / EVENTS_FILE, "JOURNAL_PATH_UNSAFE")
        state_raw = _read_regular_bytes(workspace / STATE_FILE, "STATE_PATH_UNSAFE")
        if journal_raw is None or _digest(journal_raw) != expected_journal_digest:
            raise AuditStateError("JOURNAL_DIGEST_CONFLICT", "journal bytes changed after the prior check")
        if expect_state_missing:
            if state_raw is not None:
                raise AuditStateError("STATE_MISSING_EXPECTATION_CONFLICT", "state view now exists")
        elif state_raw is None or _digest(state_raw) != expected_state_digest:
            raise AuditStateError("STATE_DIGEST_CONFLICT", "state view bytes changed after the prior check")
        inspection = inspect_journal_bytes(journal_raw)
        state_info = _state_inspection(state_raw)
        state, rebuildability, used_legacy, anchor_provenance = derive_r2_state(inspection, state_info.get("document"))
        payload = serialize_r2_state(state)
        _atomic_replace_state(workspace, payload)
        post_journal = _read_regular_bytes(workspace / EVENTS_FILE, "JOURNAL_PATH_UNSAFE")
        post_state = _read_regular_bytes(workspace / STATE_FILE, "STATE_PATH_UNSAFE")
        if post_journal != journal_raw:
            raise AuditStateError("JOURNAL_CHANGED_DURING_REBUILD", "journal bytes changed during state replacement")
        post_snapshot = read_workspace_snapshot(workspace, mode_policy="r2")
        if post_snapshot.state != state or post_state != payload:
            raise AuditStateError("STATE_REBUILD_POSTVALIDATION_FAILED", "rebuilt state did not pass exact post-validation")
        return {
            "ok": True,
            "applied": True,
            "journal_digest": expected_journal_digest,
            "state_digest": _digest(payload),
            "state_revision": state["state_revision"],
            "last_event_seq": state["last_event_seq"],
            "rebuildability": rebuildability,
            "anchored_legacy_metadata_fields": used_legacy,
            "anchored_legacy_metadata_source": anchor_provenance if used_legacy else None,
        }


def read_workspace_snapshot(workspace: Path, mode_policy: str = "auto") -> WorkspaceSnapshot:
    """Read and validate the workspace without creating or repairing anything."""
    journal_raw = _read_regular_bytes(workspace / EVENTS_FILE, "JOURNAL_PATH_UNSAFE")
    state_raw = _read_regular_bytes(workspace / STATE_FILE, "STATE_PATH_UNSAFE")
    journal = _parse_journal(journal_raw or b"")
    state = _parse_state(state_raw)

    if journal.mode == "empty" and state is None:
        detected = "r2" if mode_policy != "legacy-r1" else "legacy_r1"
    elif journal.mode == "empty" or state is None:
        if journal.mode == "r2" and state is None:
            raise AuditStateError("STATE_VIEW_MISSING", "committed R2 journal has no state view; rebuild is required")
        raise AuditStateError("PROTOCOL_MODE_MISMATCH", "journal and state view are not a compatible pair")
    else:
        try:
            state_mode = detect_state_mode(state)
        except ProtocolValidationError as exc:
            raise AuditStateError("PROTOCOL_MODE_MISMATCH", "state view protocol mode is unsupported") from exc
        expected_mode = "r2" if journal.mode == "r2" else "legacy_r1"
        if state_mode != expected_mode:
            raise AuditStateError("PROTOCOL_MODE_MISMATCH", "journal and state view use different protocol modes")
        detected = expected_mode
        if detected == "r2":
            _validate_r2_state_sync(journal, state)
            try:
                validate_transition_sequence(journal.events)
            except TransitionPolicyError as exc:
                raise AuditStateError(exc.code, exc.message) from exc

    if mode_policy == "r2" and detected != "r2":
        raise AuditStateError("PROTOCOL_MODE_MISMATCH", "R2 mode cannot migrate or append to an R1 workspace")
    if mode_policy == "legacy-r1" and detected != "legacy_r1":
        raise AuditStateError("PROTOCOL_MODE_MISMATCH", "legacy R1 mode cannot downgrade or append to an R2 workspace")
    return WorkspaceSnapshot(detected, journal, state, state_raw)


def serialize_r2_event(event: dict[str, Any]) -> bytes:
    return (json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def serialize_r2_state(state: dict[str, Any]) -> bytes:
    return (json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _commit_r2(
    workspace: Path,
    snapshot: WorkspaceSnapshot,
    request: dict[str, Any],
    *,
    precommit_validation: Callable[[WorkspaceSnapshot, dict[str, Any]], None] | None = None,
) -> WriteResult:
    if not bool(request.get("accept_current_revision")) and request.get("expected_state_revision") is None:
        raise AuditStateError("REVISION_INTENT_REQUIRED", "R2 writes require an explicit revision intent")
    transition_kind = str(request.get("transition_kind") or "").strip()
    if not transition_kind:
        raise AuditStateError("TRANSITION_KIND_REQUIRED", "new R2 writes require an explicit transition_kind")
    try:
        validate_transition_sequence(snapshot.journal.events)
    except TransitionPolicyError as exc:
        raise AuditStateError(exc.code, exc.message) from exc

    previous_revision = int(snapshot.state.get("state_revision", 0)) if snapshot.state else 0
    expected = request.get("expected_state_revision")
    if expected is not None and expected != previous_revision:
        raise AuditStateError(
            "STATE_REVISION_CONFLICT",
            "state revision changed before this event could be committed",
            expected_state_revision=expected,
            current_state_revision=previous_revision,
            resume_hint="read the current state revision and submit a new explicit compare-and-swap request",
        )
    previous = snapshot.state or {}
    previous_stage = previous.get("stage") if previous else None
    previous_status = previous.get("status") if previous else None
    expected_from_stage = str(request.get("expected_from_stage") or "").strip() or None
    expected_from_status = str(request.get("expected_from_status") or "").strip() or None
    if expected_from_stage is not None and expected_from_stage != previous_stage:
        raise AuditStateError("SOURCE_STAGE_MISMATCH", "requested from_stage does not match the locked current stage")
    if expected_from_status is not None and expected_from_status != previous_status:
        raise AuditStateError("SOURCE_STATUS_MISMATCH", "requested from_status does not match the locked current status")
    requested_run_id = str(request.get("run_id") or "")
    if previous and requested_run_id and requested_run_id != previous.get("run_id"):
        raise AuditStateError("EVENT_VALIDATION_FAILED", "R2 run_id must remain stable for one workspace")
    run_id = str(previous.get("run_id") or requested_run_id or ("run-" + uuid.uuid4().hex))
    seq = len(snapshot.journal.events) + 1
    state_revision = previous_revision + 1
    stage = str(request.get("stage") or "")
    to_status = str(request.get("to_status") or "")
    if bool(request.get("use_current_stage")):
        if previous_stage is None:
            raise AuditStateError("CURRENT_TARGET_UNAVAILABLE", "current stage is unavailable before the first event")
        if transition_kind in {"start", "advance", "return"}:
            raise AuditStateError(
                "CURRENT_STAGE_INTENT_INVALID",
                "current stage shorthand is limited to same-stage transition intents",
            )
        stage = str(previous_stage)
    if bool(request.get("use_current_status")):
        if previous_status is None:
            raise AuditStateError("CURRENT_TARGET_UNAVAILABLE", "current status is unavailable before the first event")
        if transition_kind != "observe":
            raise AuditStateError(
                "CURRENT_STATUS_INTENT_INVALID",
                "current status shorthand is limited to observe",
            )
        to_status = str(previous_status)
    provided_blocker = str(request.get("blocker") or "").strip() or None
    provided_resume_step = str(request.get("resume_step") or "").strip() or None
    if to_status in {"running", "completed"} and (provided_blocker is not None or provided_resume_step is not None):
        raise AuditStateError(
            "TRANSITION_STALE_BLOCKER_FIELDS",
            f"{to_status} transition cannot retain blocker or resume_step",
        )
    if (
        transition_kind == "observe"
        and stage == previous_stage
        and to_status == previous_status
        and to_status in {"paused", "blocked"}
    ):
        current_blocker = previous.get("blocker")
        current_resume_step = previous.get("resume_step")
        if provided_blocker is not None and provided_blocker != current_blocker:
            raise AuditStateError("TRANSITION_BLOCKER_CONTEXT_MISMATCH", "observe cannot replace the current blocker")
        if provided_resume_step is not None and provided_resume_step != current_resume_step:
            raise AuditStateError("TRANSITION_BLOCKER_CONTEXT_MISMATCH", "observe cannot replace the current resume_step")
        blocker = current_blocker
        resume_step = current_resume_step
    else:
        blocker = provided_blocker
        resume_step = provided_resume_step
    event_type = request.get("event_type")
    if not event_type:
        if transition_kind == "observe":
            event_type = "state_observation"
        elif transition_kind in {"resume", "return", "reopen"}:
            event_type = "recovery"
        else:
            event_type = "stage_transition"
    event = {
        "schema_version": 2,
        "plugin_version": request["plugin_version"],
        "seq": seq,
        "run_id": run_id,
        "ts": request["timestamp"],
        "stage": stage,
        "event_type": event_type,
        "event_name": request["event_name"],
        "from_status": previous_status,
        "from_stage": previous_stage,
        "transition_kind": transition_kind,
        "transition_policy_version": TRANSITION_POLICY_VERSION,
        "to_status": to_status,
        "blocker": blocker,
        "resume_step": resume_step,
        "reason_code": request["reason_code"],
        # Empty subjects are structurally valid for ordinary observations, but
        # the transition policy deliberately rejects them for enhanced
        # recovery intents.  Do not synthesize a subject and hide that
        # omission from the policy.
        "subjects": request["subjects"],
        "evidence_refs": request["evidence_refs"],
        "next_actions": request["next_actions"],
        "expected_state_revision": previous_revision,
        "details": request["details"],
    }
    try:
        # Preserve policy-specific failure codes (for example
        # INVALID_TRANSITION_KIND) instead of collapsing them into the
        # structural EVENT_VALIDATION_FAILED wrapper below.
        validate_transition_metadata(event)
        validate_r2_event(event)
        validate_transition(
            TransitionState(
                previous_stage,
                previous_status,
                previous.get("blocker") if previous else None,
                previous.get("resume_step") if previous else None,
            ),
            event,
        )
    except ProtocolValidationError as exc:
        raise AuditStateError("EVENT_VALIDATION_FAILED", "fully constructed R2 event is invalid") from exc
    except TransitionPolicyError as exc:
        raise AuditStateError(exc.code, exc.message) from exc
    sensitive_text = first_sensitive_r2_event_text(event)
    if sensitive_text is not None:
        field, category = sensitive_text
        raise AuditStateError(
            "EVENT_SENSITIVE_TEXT_FORBIDDEN",
            f"{field} contains sensitive material of category {category}",
            field=field,
            category=category,
            journal_committed=False,
            state_view_updated=False,
        )
    # Callers that bind an external, read-only contract (for example a stage
    # result) can repeat their digest and state checks while this writer owns
    # the workspace lock.  The hook is deliberately narrow: it receives the
    # locked snapshot and fully constructed event, may only raise
    # AuditStateError, and runs immediately before the durable journal append.
    # It is not an unlocked preflight substitute and must not acquire this
    # workspace lock again.
    if precommit_validation is not None:
        try:
            precommit_validation(snapshot, event)
        except AuditStateError:
            raise
        except Exception as exc:
            raise AuditStateError(
                "PRECOMMIT_VALIDATION_FAILED",
                "lock-held precommit validation failed before any journal write",
            ) from exc
    event_bytes = serialize_r2_event(event)
    try:
        _safe_append_fsync(workspace / EVENTS_FILE, event_bytes)
    except AuditStateError:
        raise
    committed_raw = _read_regular_bytes(workspace / EVENTS_FILE, "JOURNAL_PATH_UNSAFE")
    if committed_raw is None:
        raise AuditStateError("JOURNAL_APPEND_FAILED", "audit journal disappeared after append")
    state = {
        "schema_version": 2,
        "plugin": "zhulong",
        "plugin_version": request["plugin_version"],
        "run_id": run_id,
        "state_revision": state_revision,
        "last_event_seq": seq,
        "event_log_digest": _digest(committed_raw),
        "stage": stage,
        "status": to_status,
        "last_event_at": event["ts"],
        "last_event_type": event["event_type"],
        "last_event_name": event["event_name"],
        "blocker": blocker if to_status in {"blocked", "paused"} else None,
        "resume_step": resume_step if to_status in {"blocked", "paused"} else None,
    }
    try:
        _atomic_replace_state(workspace, serialize_r2_state(state))
    except AuditStateError as exc:
        exc.fields.update(
            journal_committed=True,
            state_view_updated=False,
            mode="r2",
            seq=seq,
            state_revision=state_revision,
            cas_mode="accept_current_revision" if request.get("accept_current_revision") else "explicit",
        )
        raise
    return WriteResult(
        "r2",
        seq,
        state_revision,
        True,
        True,
        "accept_current_revision" if request.get("accept_current_revision") else "explicit",
    )


def _commit_legacy_r1(workspace: Path, snapshot: WorkspaceSnapshot, request: dict[str, Any]) -> WriteResult:
    ignored_fields = tuple(_r1_r2_intent_fields(request))
    if request.get("expected_state_revision") is not None:
        raise AuditStateError("R2_CAS_UNAVAILABLE", "legacy R1 workspaces do not support revision compare-and-swap")
    current_state = dict(snapshot.state or {})
    if bool(request.get("use_current_stage")) and not current_state.get("stage"):
        raise AuditStateError("CURRENT_TARGET_UNAVAILABLE", "current stage is unavailable in this legacy workspace")
    if bool(request.get("use_current_status")) and not current_state.get("status"):
        raise AuditStateError("CURRENT_TARGET_UNAVAILABLE", "current status is unavailable in this legacy workspace")
    event = dict(request["legacy_event"])
    legacy_state = dict(request["legacy_state"])
    if bool(request.get("use_current_stage")):
        event["stage"] = current_state["stage"]
        legacy_state["stage"] = current_state["stage"]
    if bool(request.get("use_current_status")):
        legacy_state["status"] = current_state["status"]
        legacy_state["blocker"] = current_state.get("blocker")
        legacy_state["resume_step"] = current_state.get("resume_step")
    sensitive_text = first_sensitive_document_text({"event": event, "state": legacy_state})
    if sensitive_text is not None:
        field, category = sensitive_text
        raise AuditStateError(
            "EVENT_SENSITIVE_TEXT_FORBIDDEN",
            f"{field} contains sensitive material of category {category}",
            field=field,
            category=category,
            journal_committed=False,
            state_view_updated=False,
        )
    payload = (json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    _safe_append_fsync(workspace / EVENTS_FILE, payload)
    state = current_state
    state.update(legacy_state)
    try:
        _atomic_replace_state(
            workspace,
            (json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        )
    except AuditStateError as exc:
        exc.fields.update(
            journal_committed=True,
            state_view_updated=False,
            mode="legacy_r1",
            seq=None,
            state_revision=None,
            cas_mode="unavailable",
        )
        raise
    diagnostic = None
    compatibility_code = None
    if ignored_fields:
        compatibility_code = "LEGACY_R1_COMPATIBILITY_IGNORED"
        diagnostic = (
            "legacy R1 wrote the event using its historical representation; "
            "R2-only intent was not represented: " + ", ".join(ignored_fields)
        )
    return WriteResult(
        "legacy_r1",
        None,
        None,
        True,
        True,
        "unavailable",
        ignored_fields=ignored_fields,
        compatibility_code=compatibility_code,
        compatibility_diagnostic=diagnostic,
    )


def _r1_r2_intent_fields(request: dict[str, Any]) -> list[str]:
    """Return caller-supplied R2 intent which has no lossless R1 field.

    The legacy writer is intentionally allowed to retain its historical event
    shape, but automatic protocol detection must not silently discard modern
    transition semantics.  ``reason_code`` is included only when the caller
    explicitly supplied one; the writer's default reason is an implementation
    detail and is not itself an R2 intent claim.
    """
    fields: list[str] = []
    checks = (
        ("event_type", request.get("event_type")),
        ("transition_kind", request.get("transition_kind")),
        ("from_stage", request.get("expected_from_stage")),
        ("from_status", request.get("expected_from_status")),
        ("reason_code", request.get("reason_code") if request.get("reason_code_explicit") else ""),
        ("subjects", request.get("subjects")),
        ("evidence_refs", request.get("evidence_refs")),
        ("next_actions", request.get("next_actions")),
        ("run_id", request.get("run_id")),
        ("reason_detail", request.get("reason_detail")),
    )
    for field, value in checks:
        if isinstance(value, str):
            if value.strip():
                fields.append(field)
        elif isinstance(value, (list, dict)):
            if value:
                fields.append(field)
        elif value is not None:
            fields.append(field)
    return fields


def _reject_or_record_r1_r2_intent(snapshot: WorkspaceSnapshot, request: dict[str, Any], mode_policy: str) -> tuple[str, ...]:
    if snapshot.mode != "legacy_r1":
        return ()
    fields = tuple(_r1_r2_intent_fields(request))
    if fields and mode_policy == "auto":
        raise AuditStateError(
            "R1_R2_INTENT_MISMATCH",
            "legacy R1 auto mode cannot represent R2-only intent; retry with --protocol-mode legacy-r1",
            ignored_fields=list(fields),
            journal_committed=False,
            state_view_updated=False,
        )
    return fields


def commit_event(
    workspace: Path,
    *,
    mode_policy: str,
    lock_timeout_seconds: float,
    request: dict[str, Any],
    precommit_validation: Callable[[WorkspaceSnapshot, dict[str, Any]], None] | None = None,
) -> WriteResult:
    """Commit exactly one event while owning the workspace lock."""
    if not workspace.is_dir():
        raise AuditStateError("WORKSPACE_INVALID", "workspace directory does not exist")
    with workspace_lock(workspace, lock_timeout_seconds):
        snapshot = read_workspace_snapshot(workspace, mode_policy)
        if snapshot.mode == "r2":
            return _commit_r2(workspace, snapshot, request, precommit_validation=precommit_validation)
        if precommit_validation is not None:
            raise AuditStateError(
                "PROTOCOL_MODE_MISMATCH",
                "lock-held precommit validation is available only for R2 workspaces",
            )
        _reject_or_record_r1_r2_intent(snapshot, request, mode_policy)
        return _commit_legacy_r1(workspace, snapshot, request)


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Expose R1 and R2 event fields under one read-only consumer shape."""
    result = validate_event_document(event)
    if result["mode"] == "r2":
        details_raw = event.get("details") if isinstance(event.get("details"), dict) else {}
        details: dict[str, Any] = {"summary": details_raw.get("summary", "")}
        if "reason_detail" in details_raw:
            details["reason_detail"] = details_raw["reason_detail"]
        for item in details_raw.get("metadata", []):
            if isinstance(item, dict) and isinstance(item.get("key"), str):
                details[item["key"]] = item.get("value")
        return {
            "mode": "r2",
            "event_name": event["event_name"],
            "stage": event["stage"],
            "from_stage": event.get("from_stage"),
            "from_status": event["from_status"],
            "to_status": event["to_status"],
            "event_type": event["event_type"],
            "transition_kind": event.get("transition_kind"),
            "transition_policy": result.get("transition_policy"),
            "details": details,
            "raw": event,
        }
    return {
        "mode": "legacy_r1",
        "event_name": event["event"],
        "stage": event["stage"],
        "from_stage": None,
        "from_status": None,
        "to_status": event["status"],
        "event_type": "checkpoint",
        "transition_kind": None,
        "transition_policy": "legacy_r1",
        "details": event.get("details") if isinstance(event.get("details"), dict) else {},
        "raw": event,
    }


def read_normalized_workspace_events(workspace: Path) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    """Strict shared consumer reader; it never skips malformed journal records."""
    snapshot = read_workspace_snapshot(workspace)
    if snapshot.state is None:
        raise AuditStateError(
            "STATE_VIEW_MISSING",
            "state view is missing; run <workspace>/bin/recover-audit-state.py --workspace-dir <audit-workspace> --check --json",
        )
    events: list[dict[str, Any]] = []
    for event in snapshot.journal.events:
        normalized = normalize_event(event)
        events.append({
            **event,
            "event": normalized["event_name"],
            "status": normalized["to_status"],
            "details": normalized["details"],
        })
    return snapshot.state, events, snapshot.mode


def normalize_workspace_state(workspace: Path) -> dict[str, Any]:
    snapshot = read_workspace_snapshot(workspace)
    if snapshot.state is None:
        raise AuditStateError("STATE_VIEW_MISSING", "workspace has no state view")
    latest = normalize_event(snapshot.journal.events[-1]) if snapshot.journal.events else None
    state = snapshot.state
    return {
        "mode": snapshot.mode,
        "state": state,
        "events": [normalize_event(event) for event in snapshot.journal.events],
        "event_count": len(snapshot.journal.events),
        "stage": state.get("stage"),
        "status": state.get("status"),
        "last_message": (latest or {}).get("details", {}).get("summary", state.get("last_message", "")),
        "latest_event": latest,
    }
