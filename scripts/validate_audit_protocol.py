#!/usr/bin/env python3
"""Read-only validation for the Zhulong audit-state protocol R2."""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audit_transition_policy import (
    STAGES as POLICY_STAGES,
    STATUSES as POLICY_STATUSES,
    TransitionPolicyError,
    validate_transition_metadata,
    validate_transition_sequence,
)


STAGES = set(POLICY_STAGES)
STATUSES = set(POLICY_STATUSES)
EVENT_TYPES = {
    "stage_transition",
    "state_observation",
    "checkpoint",
    "recovery",
    "recording",
}
REASON_CODES = {
    "normal_progress",
    "operator_request",
    "prerequisite_missing",
    "policy_or_safety_block",
    "verification_blocked",
    "validation_failed",
    "external_dependency",
    "manual_review_required",
    "interrupted",
    "recovery_requested",
    "scope_change",
    "not_applicable",
}
ACTION_TYPES = {
    "review",
    "collect_evidence",
    "verify",
    "resume",
    "manual_follow_up",
}

R2_EVENT_REQUIRED = {
    "schema_version",
    "seq",
    "run_id",
    "ts",
    "stage",
    "event_type",
    "event_name",
    "from_status",
    "to_status",
    "reason_code",
    "subjects",
    "evidence_refs",
    "next_actions",
    "expected_state_revision",
    "details",
}
R2_EVENT_ALLOWED = R2_EVENT_REQUIRED | {
    "prev_event_hash",
    "plugin_version",
    "from_stage",
    "transition_kind",
    "transition_policy_version",
    "blocker",
    "resume_step",
}
R2_STATE_REQUIRED = {
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
}
R1_EVENT_REQUIRED = {"ts", "event", "stage", "status", "message", "details"}
R1_STATE_REQUIRED = {
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

LOGICAL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
EVENT_NAME_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
METADATA_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")


class ProtocolValidationError(Exception):
    def __init__(self, code: str, message: str, *, line: int | None = None) -> None:
        self.code = code
        self.message = message
        self.line = line
        super().__init__(message)


@dataclass(frozen=True)
class JournalIssue:
    code: str
    message: str
    line: int | None = None
    byte_offset: int | None = None
    validator_code: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.line is not None:
            result["line"] = self.line
        if self.byte_offset is not None:
            result["byte_offset"] = self.byte_offset
        if self.validator_code is not None:
            result["validator_code"] = self.validator_code
        return result


@dataclass(frozen=True)
class JournalRecord:
    line: int
    start_offset: int
    end_offset: int
    canonical_end_offset: int
    mode: str
    event: dict[str, Any]


@dataclass(frozen=True)
class JournalInspection:
    mode: str
    classification: str
    raw_bytes: bytes
    records: tuple[JournalRecord, ...] = ()
    issues: tuple[JournalIssue, ...] = ()
    transition_policy: str = "not_applicable"
    valid_prefix_end_offset: int = 0
    prefix_digests: dict[int, str] = field(default_factory=dict)

    @property
    def events(self) -> list[dict[str, Any]]:
        return [record.event for record in self.records]

    @property
    def digest(self) -> str:
        return sha256_digest(self.raw_bytes)

    @property
    def valid_prefix_digest(self) -> str:
        return sha256_digest(self.raw_bytes[: self.valid_prefix_end_offset])

    @property
    def is_complete_valid(self) -> bool:
        return self.classification == "complete_valid"


def sha256_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def fail(code: str, message: str, *, line: int | None = None) -> None:
    raise ProtocolValidationError(code, message, line=line)


def read_regular_bytes(path: Path, *, unsafe_code: str, missing_ok: bool = False) -> bytes | None:
    """Read exact bytes from a non-symlink regular file using the P9.2 rules."""
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        fail("INPUT_NOT_FOUND", "input file does not exist")
    except OSError:
        fail(unsafe_code, "input path cannot be inspected")
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        fail(unsafe_code, "input path must be a non-symlink regular file")
    flags = os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        if missing_ok:
            return None
        fail("INPUT_NOT_FOUND", "input file does not exist")
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            fail(unsafe_code, "input path is unsafe")
        fail(unsafe_code, "input path cannot be read")
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            fail(unsafe_code, "input path must be a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(fd)


def parse_json(raw: str, *, line: int | None = None) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant {value}")

    try:
        return json.loads(raw, parse_constant=reject_constant)
    except (json.JSONDecodeError, ValueError) as exc:
        fail("MALFORMED_JSON", f"invalid JSON: {exc}", line=line)


def load_json_file(path: Path) -> Any:
    try:
        return parse_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail("INPUT_NOT_FOUND", "input file does not exist")
    except (OSError, UnicodeError) as exc:
        fail("INPUT_READ_ERROR", f"input file cannot be read: {exc}")


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail("ROOT_NOT_OBJECT", f"{label} must be a JSON object")
    return value


def require_fields(document: dict[str, Any], required: set[str], label: str) -> None:
    missing = sorted(required - set(document))
    if missing:
        fail(
            "MISSING_REQUIRED_FIELD",
            f"{label} is missing required field(s): {', '.join(missing)}",
        )


def reject_unknown(document: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(document) - allowed)
    if unknown:
        fail(
            "UNEXPECTED_PROPERTY",
            f"{label} has unexpected property/properties: {', '.join(unknown)}",
        )


def require_string(
    value: Any,
    label: str,
    *,
    max_length: int | None = None,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        fail("INVALID_FIELD_TYPE", f"{label} must be a string")
    if not allow_empty and not value.strip():
        fail("INVALID_FIELD_VALUE", f"{label} must be a non-empty string")
    if max_length is not None and len(value) > max_length:
        fail("INVALID_FIELD_VALUE", f"{label} exceeds the maximum length of {max_length}")
    return value


def require_int(value: Any, label: str, *, minimum: int) -> int:
    if type(value) is not int:
        fail("INVALID_FIELD_TYPE", f"{label} must be an integer")
    if value < minimum:
        fail("INVALID_FIELD_VALUE", f"{label} must be greater than or equal to {minimum}")
    return value


def require_enum(value: Any, allowed: set[str], label: str, code: str) -> str:
    text = require_string(value, label, max_length=128)
    if text not in allowed:
        fail(code, f"{label} must be one of: {', '.join(sorted(allowed))}")
    return text


def validate_logical_id(value: Any, label: str) -> str:
    text = require_string(value, label, max_length=128)
    if not LOGICAL_ID_RE.fullmatch(text):
        fail("INVALID_LOGICAL_ID", f"{label} must be a portable logical identifier")
    return text


def validate_event_name(value: Any, label: str) -> str:
    text = require_string(value, label, max_length=128)
    if not EVENT_NAME_RE.fullmatch(text):
        fail("INVALID_EVENT_NAME", f"{label} must be a lower-snake-case identifier")
    return text


def validate_utc_timestamp(value: Any, label: str) -> str:
    text = require_string(value, label, max_length=64)
    if not UTC_TIMESTAMP_RE.fullmatch(text):
        fail("INVALID_TIMESTAMP", f"{label} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        fail("INVALID_TIMESTAMP", f"{label} is not a valid calendar timestamp")
    if parsed.tzinfo != timezone.utc:
        fail("INVALID_TIMESTAMP", f"{label} must use UTC Z notation")
    return text


def validate_evidence_ref(value: Any, label: str) -> str:
    text = require_string(value, label, max_length=512)
    if (
        text.startswith(("/", "\\", "~"))
        or "\\" in text
        or WINDOWS_DRIVE_RE.match(text)
        or URI_SCHEME_RE.match(text)
    ):
        fail("INVALID_EVIDENCE_REF", f"{label} must be a workspace-relative POSIX path")
    parts = text.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        fail("INVALID_EVIDENCE_REF", f"{label} must be normalized and must not traverse parent paths")
    if any(ord(char) < 32 for char in text):
        fail("INVALID_EVIDENCE_REF", f"{label} must not contain control characters")
    return text


def validate_string_list(
    value: Any,
    label: str,
    *,
    validator,
    min_items: int = 0,
    max_items: int = 64,
) -> list[Any]:
    if not isinstance(value, list):
        fail("INVALID_FIELD_TYPE", f"{label} must be an array")
    if len(value) < min_items or len(value) > max_items:
        fail(
            "INVALID_FIELD_VALUE",
            f"{label} must contain between {min_items} and {max_items} item(s)",
        )
    results = [validator(item, f"{label}[{index}]") for index, item in enumerate(value)]
    if len(set(results)) != len(results):
        fail("DUPLICATE_ITEM", f"{label} must not contain duplicate values")
    return results


def validate_metadata(value: Any) -> None:
    if not isinstance(value, list):
        fail("INVALID_FIELD_TYPE", "$.details.metadata must be an array")
    if len(value) > 32:
        fail("INVALID_FIELD_VALUE", "$.details.metadata must contain at most 32 entries")
    keys: set[str] = set()
    for index, entry in enumerate(value):
        label = f"$.details.metadata[{index}]"
        if not isinstance(entry, dict):
            fail("INVALID_FIELD_TYPE", f"{label} must be an object")
        require_fields(entry, {"key", "value"}, label)
        reject_unknown(entry, {"key", "value"}, label)
        key = require_string(entry["key"], f"{label}.key", max_length=64)
        if not METADATA_KEY_RE.fullmatch(key):
            fail("INVALID_FIELD_VALUE", f"{label}.key must be lower-snake-case")
        if key in keys:
            fail("DUPLICATE_ITEM", "$.details.metadata must not repeat metadata keys")
        keys.add(key)
        metadata_value = entry["value"]
        if isinstance(metadata_value, (dict, list)):
            fail("INVALID_FIELD_TYPE", f"{label}.value must be a scalar JSON value")
        if isinstance(metadata_value, str) and len(metadata_value) > 1024:
            fail("INVALID_FIELD_VALUE", f"{label}.value string exceeds the maximum length of 1024")
        if isinstance(metadata_value, float) and not math.isfinite(metadata_value):
            fail("INVALID_FIELD_VALUE", f"{label}.value number must be finite")
        if metadata_value is not None and type(metadata_value) not in {str, int, float, bool}:
            fail("INVALID_FIELD_TYPE", f"{label}.value must be a scalar JSON value")


def validate_details(value: Any) -> None:
    if not isinstance(value, dict):
        fail("INVALID_FIELD_TYPE", "$.details must be an object")
    require_fields(value, {"summary"}, "$.details")
    reject_unknown(value, {"summary", "reason_detail", "metadata"}, "$.details")
    require_string(value["summary"], "$.details.summary", max_length=2048)
    if "reason_detail" in value:
        require_string(value["reason_detail"], "$.details.reason_detail", max_length=2048)
    if "metadata" in value:
        validate_metadata(value["metadata"])


def validate_next_actions(value: Any) -> None:
    if not isinstance(value, list):
        fail("INVALID_FIELD_TYPE", "$.next_actions must be an array")
    if len(value) > 32:
        fail("INVALID_FIELD_VALUE", "$.next_actions must contain at most 32 entries")
    action_ids: set[str] = set()
    for index, action in enumerate(value):
        label = f"$.next_actions[{index}]"
        if not isinstance(action, dict):
            fail("INVALID_FIELD_TYPE", f"{label} must be an object")
        require_fields(action, {"action_id", "action_type", "subject_ids", "summary"}, label)
        reject_unknown(action, {"action_id", "action_type", "subject_ids", "summary", "evidence_refs"}, label)
        action_id = validate_logical_id(action["action_id"], f"{label}.action_id")
        if action_id in action_ids:
            fail("DUPLICATE_ITEM", "$.next_actions must not repeat action_id")
        action_ids.add(action_id)
        require_enum(action["action_type"], ACTION_TYPES, f"{label}.action_type", "INVALID_ACTION_TYPE")
        validate_string_list(
            action["subject_ids"],
            f"{label}.subject_ids",
            validator=validate_logical_id,
            min_items=1,
        )
        require_string(action["summary"], f"{label}.summary", max_length=1024)
        if "evidence_refs" in action:
            validate_string_list(
                action["evidence_refs"],
                f"{label}.evidence_refs",
                validator=validate_evidence_ref,
            )


def validate_r2_event(document: dict[str, Any]) -> dict[str, Any]:
    require_fields(document, R2_EVENT_REQUIRED, "R2 event")
    reject_unknown(document, R2_EVENT_ALLOWED, "R2 event")
    if document["schema_version"] != 2 or type(document["schema_version"]) is not int:
        fail("SCHEMA_VERSION_UNSUPPORTED", "R2 event schema_version must be exactly 2")
    seq_value = document["seq"]
    if type(seq_value) is not int or seq_value < 1:
        fail("INVALID_SEQ", "$.seq must be an integer greater than or equal to 1")
    seq = seq_value
    validate_logical_id(document["run_id"], "$.run_id")
    validate_utc_timestamp(document["ts"], "$.ts")
    require_enum(document["stage"], STAGES, "$.stage", "INVALID_STAGE")
    require_enum(document["event_type"], EVENT_TYPES, "$.event_type", "INVALID_EVENT_TYPE")
    validate_event_name(document["event_name"], "$.event_name")
    if document["from_status"] is not None:
        require_enum(document["from_status"], STATUSES, "$.from_status", "INVALID_STATUS")
    require_enum(document["to_status"], STATUSES, "$.to_status", "INVALID_STATUS")
    require_enum(document["reason_code"], REASON_CODES, "$.reason_code", "INVALID_REASON_CODE")
    validate_string_list(document["subjects"], "$.subjects", validator=validate_logical_id)
    validate_string_list(document["evidence_refs"], "$.evidence_refs", validator=validate_evidence_ref)
    validate_next_actions(document["next_actions"])
    expected_state_revision = document["expected_state_revision"]
    if type(expected_state_revision) is not int or expected_state_revision < 0:
        fail(
            "INVALID_EXPECTED_STATE_REVISION",
            "$.expected_state_revision must be an integer greater than or equal to 0",
        )
    validate_details(document["details"])
    if "plugin_version" in document:
        require_string(document["plugin_version"], "$.plugin_version", max_length=128)
    if "prev_event_hash" in document:
        prev_hash = require_string(document["prev_event_hash"], "$.prev_event_hash", max_length=64)
        if not SHA256_RE.fullmatch(prev_hash):
            fail("INVALID_EVENT_HASH", "$.prev_event_hash must be a lowercase SHA-256 digest")
    try:
        transition_policy = validate_transition_metadata(document)
    except TransitionPolicyError as exc:
        fail(exc.code, exc.message)
    return {"mode": "r2", "seq": seq, "transition_policy": transition_policy}


def validate_r2_state(document: dict[str, Any]) -> dict[str, Any]:
    require_fields(document, R2_STATE_REQUIRED, "R2 state view")
    reject_unknown(document, R2_STATE_REQUIRED, "R2 state view")
    if document["schema_version"] != 2 or type(document["schema_version"]) is not int:
        fail("SCHEMA_VERSION_UNSUPPORTED", "R2 state schema_version must be exactly 2")
    if document["plugin"] != "zhulong" or not isinstance(document["plugin"], str):
        fail("INVALID_PLUGIN", "$.plugin must be exactly zhulong")
    require_string(document["plugin_version"], "$.plugin_version", max_length=128)
    validate_logical_id(document["run_id"], "$.run_id")
    state_revision = document["state_revision"]
    if type(state_revision) is not int or state_revision < 0:
        fail("INVALID_STATE_REVISION", "$.state_revision must be an integer greater than or equal to 0")
    last_event_seq = document["last_event_seq"]
    if type(last_event_seq) is not int or last_event_seq < 1:
        fail("INVALID_LAST_EVENT_SEQ", "$.last_event_seq must be an integer greater than or equal to 1")
    digest = require_string(document["event_log_digest"], "$.event_log_digest", max_length=71)
    if not SHA256_DIGEST_RE.fullmatch(digest):
        fail("INVALID_EVENT_LOG_DIGEST", "$.event_log_digest must use sha256:<64-lowercase-hex>")
    require_enum(document["stage"], STAGES, "$.stage", "INVALID_STAGE")
    status = require_enum(document["status"], STATUSES, "$.status", "INVALID_STATUS")
    validate_utc_timestamp(document["last_event_at"], "$.last_event_at")
    require_enum(document["last_event_type"], EVENT_TYPES, "$.last_event_type", "INVALID_EVENT_TYPE")
    validate_event_name(document["last_event_name"], "$.last_event_name")

    blocker = document["blocker"]
    resume_step = document["resume_step"]
    for label, value in (("$.blocker", blocker), ("$.resume_step", resume_step)):
        if value is not None:
            require_string(value, label, max_length=2048)
    if status in {"blocked", "paused"}:
        if not isinstance(blocker, str) or not blocker.strip():
            fail("MISSING_BLOCKER", f"{status} R2 state requires a non-empty blocker")
        if not isinstance(resume_step, str) or not resume_step.strip():
            fail("MISSING_RESUME_STEP", f"{status} R2 state requires a non-empty resume_step")
    elif blocker is not None or resume_step is not None:
        fail("STALE_BLOCKER_FIELDS", f"{status} R2 state requires blocker and resume_step to be null")
    return {"mode": "r2"}


def validate_r1_event(document: dict[str, Any]) -> dict[str, Any]:
    if "schema_version" in document:
        fail("SCHEMA_VERSION_UNSUPPORTED", "legacy R1 event must not contain schema_version")
    require_fields(document, R1_EVENT_REQUIRED, "legacy R1 event")
    validate_utc_timestamp(document["ts"], "$.ts")
    require_string(document["event"], "$.event", max_length=256)
    require_string(document["stage"], "$.stage", max_length=256)
    require_string(document["status"], "$.status", max_length=256)
    require_string(document["message"], "$.message", max_length=4096, allow_empty=True)
    if not isinstance(document["details"], dict):
        fail("INVALID_FIELD_TYPE", "$.details must be an object")
    return {"mode": "legacy_r1"}


def validate_r1_state(document: dict[str, Any]) -> dict[str, Any]:
    require_fields(document, R1_STATE_REQUIRED, "legacy R1 state view")
    if document["schema_version"] != 1 or type(document["schema_version"]) is not int:
        fail("SCHEMA_VERSION_UNSUPPORTED", "legacy R1 state schema_version must be exactly 1")
    if document["plugin"] != "zhulong" or not isinstance(document["plugin"], str):
        fail("INVALID_PLUGIN", "$.plugin must be exactly zhulong")
    require_string(document["plugin_version"], "$.plugin_version", max_length=256)
    require_string(document["stage"], "$.stage", max_length=256)
    status = require_enum(document["status"], STATUSES, "$.status", "INVALID_STATUS")
    validate_utc_timestamp(document["last_event_at"], "$.last_event_at")
    require_string(document["workspace"], "$.workspace", max_length=4096)
    require_string(document["target_repo"], "$.target_repo", max_length=4096)
    for label in ("$.blocker", "$.resume_step"):
        value = document[label[2:]]
        if value is not None:
            require_string(value, label, max_length=4096)
    if status in {"blocked", "paused"}:
        if not isinstance(document["blocker"], str) or not document["blocker"].strip():
            fail("MISSING_BLOCKER", f"{status} legacy R1 state requires a non-empty blocker")
        if not isinstance(document["resume_step"], str) or not document["resume_step"].strip():
            fail("MISSING_RESUME_STEP", f"{status} legacy R1 state requires a non-empty resume_step")
    return {"mode": "legacy_r1"}


def detect_event_mode(document: dict[str, Any]) -> str:
    if "schema_version" not in document:
        return "legacy_r1"
    if document.get("schema_version") == 2 and type(document.get("schema_version")) is int:
        return "r2"
    fail("SCHEMA_VERSION_UNSUPPORTED", "event schema_version is unsupported")


def validate_event_document(document: dict[str, Any]) -> dict[str, Any]:
    mode = detect_event_mode(document)
    return validate_r2_event(document) if mode == "r2" else validate_r1_event(document)


def detect_state_mode(document: dict[str, Any]) -> str:
    version = document.get("schema_version")
    if version == 1 and type(version) is int:
        return "legacy_r1"
    if version == 2 and type(version) is int:
        return "r2"
    fail("SCHEMA_VERSION_UNSUPPORTED", "state schema_version is unsupported")


def validate_state_document(document: dict[str, Any]) -> dict[str, Any]:
    mode = detect_state_mode(document)
    return validate_r2_state(document) if mode == "r2" else validate_r1_state(document)


def inspect_journal_bytes(raw: bytes) -> JournalInspection:
    """Inspect exact journal bytes once without repairing or executing records."""
    if not raw:
        return JournalInspection(
            mode="empty",
            classification="empty",
            raw_bytes=raw,
            issues=(JournalIssue("JOURNAL_EMPTY", "audit journal is empty", line=1, byte_offset=0),),
        )
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        prefix_end = raw.rfind(b"\n", 0, exc.start) + 1
        line = raw.count(b"\n", 0, exc.start) + 1
        return JournalInspection(
            mode="unknown",
            classification="invalid_utf8",
            raw_bytes=raw,
            issues=(JournalIssue("JOURNAL_INVALID_UTF8", "audit journal contains non-UTF-8 bytes", line, exc.start),),
            valid_prefix_end_offset=prefix_end,
        )

    records: list[JournalRecord] = []
    issues: list[JournalIssue] = []
    mode = "empty"
    offset = 0
    lines = raw.splitlines(keepends=True)
    if not lines:
        lines = [raw]
    for line_number, line_bytes in enumerate(lines, start=1):
        start = offset
        offset += len(line_bytes)
        has_newline = line_bytes.endswith(b"\n")
        content = line_bytes[:-1] if has_newline else line_bytes
        if content.endswith(b"\r"):
            content = content[:-1]
        if not content.strip():
            continue
        try:
            value = parse_json(content.decode("utf-8"), line=line_number)
        except ProtocolValidationError as exc:
            final_suffix = not has_newline and offset == len(raw)
            code = "JOURNAL_TAIL_INCOMPLETE" if final_suffix else "JOURNAL_MIDDLE_CORRUPTION"
            message = (
                "final non-newline journal suffix is not a complete accepted event"
                if final_suffix
                else "malformed journal content occurs before a canonical append boundary"
            )
            issues.append(JournalIssue(code, message, line_number, start, exc.code))
            break
        if not isinstance(value, dict):
            issues.append(
                JournalIssue(
                    "JOURNAL_MIDDLE_CORRUPTION" if has_newline or offset < len(raw) else "JOURNAL_EVENT_SCHEMA_INVALID",
                    "journal record must be a JSON object",
                    line_number,
                    start,
                    "ROOT_NOT_OBJECT",
                )
            )
            break
        try:
            result = validate_event_document(value)
        except ProtocolValidationError as exc:
            code = "JOURNAL_SCHEMA_VERSION_UNSUPPORTED" if exc.code == "SCHEMA_VERSION_UNSUPPORTED" else "JOURNAL_EVENT_SCHEMA_INVALID"
            issues.append(JournalIssue(code, "journal event failed canonical validation", line_number, start, exc.code))
            break
        record_mode = str(result["mode"])
        if mode == "empty":
            mode = record_mode
        elif mode != record_mode:
            issues.append(
                JournalIssue(
                    "JOURNAL_MIXED_PROTOCOL_MODE",
                    "journal mixes R1 and R2 records",
                    line_number,
                    start,
                    "MIXED_JOURNAL_MODE",
                )
            )
            break
        records.append(
            JournalRecord(
                line=line_number,
                start_offset=start,
                end_offset=offset,
                canonical_end_offset=offset if has_newline else start,
                mode=record_mode,
                event=value,
            )
        )
        if not has_newline:
            issues.append(
                JournalIssue(
                    "JOURNAL_FINAL_NEWLINE_MISSING",
                    "final accepted event is missing its canonical newline",
                    line_number,
                    offset,
                )
            )
            break

    prefix_end = 0
    if records:
        if issues:
            prefix_end = records[-1].canonical_end_offset
        else:
            prefix_end = len(raw)
    prefix_digests: dict[int, str] = {}
    for index, record in enumerate(records, start=1):
        if index < len(records):
            end = records[index].start_offset
        else:
            end = prefix_end
        prefix_digests[index] = sha256_digest(raw[:end])

    transition_policy = "not_applicable"
    if not issues and mode == "r2":
        seen: set[int] = set()
        previous_seq: int | None = None
        run_id = str(records[0].event.get("run_id") or "") if records else ""
        for index, record in enumerate(records, start=1):
            event = record.event
            seq = int(event["seq"])
            if seq in seen:
                issues.append(JournalIssue("JOURNAL_DUPLICATE_SEQ", "R2 seq duplicates an earlier record", record.line, record.start_offset, "DUPLICATE_SEQ"))
            if previous_seq is not None and seq < previous_seq:
                issues.append(JournalIssue("JOURNAL_NON_MONOTONIC_SEQ", "R2 seq is lower than the previous seq", record.line, record.start_offset, "NON_MONOTONIC_SEQ"))
            if seq != index:
                issues.append(JournalIssue("JOURNAL_SEQ_GAP", "R2 seq does not match its exact 1..N position", record.line, record.start_offset))
            if event.get("expected_state_revision") != index - 1:
                issues.append(JournalIssue("JOURNAL_REVISION_CHAIN_MISMATCH", "expected_state_revision does not equal seq-1", record.line, record.start_offset))
            if event.get("run_id") != run_id:
                issues.append(JournalIssue("JOURNAL_RUN_ID_DRIFT", "run_id changes within one journal", record.line, record.start_offset))
            seen.add(seq)
            previous_seq = seq
        if not issues:
            try:
                sequence = validate_transition_sequence([record.event for record in records])
                transition_policy = str(sequence["classification"])
            except TransitionPolicyError as exc:
                record = records[exc.event_index - 1] if exc.event_index and exc.event_index <= len(records) else None
                issues.append(
                    JournalIssue(
                        "JOURNAL_TRANSITION_SEQUENCE_INVALID",
                        exc.message,
                        record.line if record else None,
                        record.start_offset if record else None,
                        exc.code,
                    )
                )

    classification = "complete_valid" if records and not issues else (issues[0].code.lower() if issues else "empty")
    return JournalInspection(
        mode=mode,
        classification=classification,
        raw_bytes=raw,
        records=tuple(records),
        issues=tuple(issues),
        transition_policy=transition_policy,
        valid_prefix_end_offset=prefix_end,
        prefix_digests=prefix_digests,
    )


def inspect_journal_path(path: Path) -> JournalInspection:
    raw = read_regular_bytes(path, unsafe_code="JOURNAL_PATH_UNSAFE")
    assert raw is not None
    return inspect_journal_bytes(raw)


def validate_events_jsonl(path: Path) -> dict[str, Any]:
    inspection = inspect_journal_path(path)
    if inspection.issues:
        issue = next(
            (item for item in inspection.issues if item.validator_code in {"DUPLICATE_SEQ", "NON_MONOTONIC_SEQ"}),
            inspection.issues[0],
        )
        fail(issue.validator_code or issue.code, issue.message, line=issue.line)
    return {
        "mode": inspection.mode,
        "record_count": len(inspection.records),
        "transition_policy": inspection.transition_policy,
        "journal_digest": inspection.digest,
        "classification": inspection.classification,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only validator for Zhulong audit-events.jsonl and stage-status.json protocol records."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--event", help="Validate one event JSON document.")
    group.add_argument("--events-jsonl", help="Validate an event JSONL journal.")
    group.add_argument("--state", help="Validate one stage-status JSON document.")
    parser.add_argument("--json", action="store_true", help="Emit deterministic JSON output.")
    return parser.parse_args()


def emit_success(
    *,
    input_kind: str,
    mode: str,
    record_count: int,
    as_json: bool,
    transition_policy: str | None = None,
) -> None:
    payload = {
        "input_kind": input_kind,
        "mode": mode,
        "ok": True,
        "record_count": record_count,
    }
    if transition_policy is not None:
        payload["transition_policy"] = transition_policy
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    else:
        print(
            "OK: audit protocol valid; "
            f"kind={input_kind} mode={mode} records={record_count}"
        )


def emit_failure(exc: ProtocolValidationError, *, input_kind: str, as_json: bool) -> None:
    message = exc.message if exc.line is None else f"line {exc.line}: {exc.message}"
    payload: dict[str, Any] = {
        "code": exc.code,
        "input_kind": input_kind,
        "message": message,
        "ok": False,
    }
    if exc.line is not None:
        payload["line"] = exc.line
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")), file=sys.stderr)
    else:
        print(f"ERROR [{exc.code}]: {message}", file=sys.stderr)


def main() -> int:
    args = parse_args()
    if args.event:
        input_kind = "event"
        try:
            document = require_object(load_json_file(Path(args.event)), "event")
            result = validate_event_document(document)
        except ProtocolValidationError as exc:
            emit_failure(exc, input_kind=input_kind, as_json=args.json)
            return 1
        emit_success(
            input_kind=input_kind,
            mode=str(result["mode"]),
            record_count=1,
            as_json=args.json,
            transition_policy=str(result.get("transition_policy") or "not_applicable"),
        )
        return 0

    if args.state:
        input_kind = "state"
        try:
            document = require_object(load_json_file(Path(args.state)), "state")
            result = validate_state_document(document)
        except ProtocolValidationError as exc:
            emit_failure(exc, input_kind=input_kind, as_json=args.json)
            return 1
        emit_success(
            input_kind=input_kind,
            mode=str(result["mode"]),
            record_count=1,
            as_json=args.json,
        )
        return 0

    input_kind = "events_jsonl"
    try:
        result = validate_events_jsonl(Path(args.events_jsonl))
    except ProtocolValidationError as exc:
        emit_failure(exc, input_kind=input_kind, as_json=args.json)
        return 1
    emit_success(
        input_kind=input_kind,
        mode=str(result["mode"]),
        record_count=int(result["record_count"]),
        as_json=args.json,
        transition_policy=str(result.get("transition_policy") or "not_applicable"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
