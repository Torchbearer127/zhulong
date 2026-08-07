#!/usr/bin/env python3
"""Shared, side-effect-free text safety checks for publishable audit text."""
from __future__ import annotations

import re
from typing import Any, Iterator


# These patterns intentionally classify portable-text hazards only.  They do
# not attempt to parse arbitrary prose or redact values; callers fail closed
# and report only the stable category.
_PATH_BOUNDARY = r"[\s:=,;'\"`()\[\]{}<>\uFF08\uFF09\u3010\u3011\u3008\u3009\u300A\u300B]"
_POSIX_LOCAL_ROOTS = (
    r"Applications|Library|System|Users|Volumes|dev|etc|home|mnt|opt|private|proc|root|run|srv|tmp|usr|var"
)
LOCAL_PATH_RE = re.compile(
    rf"(?:^|{_PATH_BOUNDARY})/(?!/)(?:{_POSIX_LOCAL_ROOTS})(?:/|$)"
)
WINDOWS_ABSOLUTE_PATH_RE = re.compile(rf"(?:^|{_PATH_BOUNDARY})[A-Za-z]:[\\/]")
UNC_BACKSLASH_PATH_RE = re.compile(rf"(?:^|{_PATH_BOUNDARY})\\\\[^\\/\s]+\\[^\\/\s]+")
UNC_FORWARD_PATH_RE = re.compile(r"(?<!:)//[^/\s]+/[^/\s]+")
FILE_URI_RE = re.compile(rf"(?:^|{_PATH_BOUNDARY})file://", re.I)
SENSITIVE_VALUE_PATTERNS = (
    ("private_key_header", re.compile(
        r"-----BEGIN (?:PGP PRIVATE KEY BLOCK|"
        r"(?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----",
        re.I,
    )),
    ("aws_access_key_id", re.compile(
        r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"
    )),
    ("http_bearer_token", re.compile(
        r"(?<![A-Za-z0-9])bearer[ \t\r\n]+[A-Za-z0-9._~+/=-]+",
        re.I,
    )),
    ("github_token", re.compile(
        r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9_-]+",
        re.I,
    )),
    ("gitlab_token", re.compile(
        r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]+",
        re.I,
    )),
    ("slack_token", re.compile(
        r"(?<![A-Za-z0-9_-])xox[a-z]-[A-Za-z0-9-]+",
        re.I,
    )),
    ("token_assignment", re.compile(
        r"(?<![A-Za-z0-9_-])token[ \t\r\n]*[:=][ \t\r\n]*\S+",
        re.I,
    )),
    ("secret_assignment", re.compile(
        r"(?<![A-Za-z0-9_-])secret[ \t\r\n]*[:=][ \t\r\n]*\S+",
        re.I,
    )),
    ("api_key_assignment", re.compile(
        r"(?<![A-Za-z0-9_-])api[_-]?key[ \t\r\n]*[:=][ \t\r\n]*\S+",
        re.I,
    )),
    ("access_token_assignment", re.compile(
        r"(?<![A-Za-z0-9_-])access[_-]?token[ \t\r\n]*[:=][ \t\r\n]*\S+",
        re.I,
    )),
    ("password_assignment", re.compile(
        r"(?<![A-Za-z0-9_-])(?:password|passwd)[ \t\r\n]*[:=][ \t\r\n]*\S+",
        re.I,
    )),
    ("client_secret_assignment", re.compile(
        r"(?<![A-Za-z0-9_-])client[_-]?secret[ \t\r\n]*[:=][ \t\r\n]*\S+",
        re.I,
    )),
    ("credential_url", re.compile(
        r"\bhttps?://[^/\s:@]+:[^@/\s]+@",
        re.I,
    )),
)


def sensitive_value_kind(value: str) -> str | None:
    """Return a stable category for unsafe publishable text, never the value."""
    if (
        LOCAL_PATH_RE.search(value)
        or WINDOWS_ABSOLUTE_PATH_RE.search(value)
        or UNC_BACKSLASH_PATH_RE.search(value)
        or UNC_FORWARD_PATH_RE.search(value)
        or FILE_URI_RE.search(value)
    ):
        return "local_path"
    for kind, pattern in SENSITIVE_VALUE_PATTERNS:
        if pattern.search(value):
            return kind
    return None


def tested_ref_value_kind(value: str) -> str | None:
    """Classify a source identity that must remain exact, portable, and low-sensitivity."""
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return "control_character"
    return sensitive_value_kind(value)


def iter_publishable_text(value: Any, field: str = "$") -> Iterator[tuple[str, str]]:
    """Walk a JSON-like publishable document in deterministic field order."""
    if isinstance(value, dict):
        for key in sorted(value, key=lambda item: str(item)):
            child_field = f"{field}.{key}" if field else str(key)
            yield from iter_publishable_text(value[key], child_field)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_publishable_text(item, f"{field}[{index}]")
    elif isinstance(value, str):
        yield field, value


def first_sensitive_document_text(value: Any) -> tuple[str, str] | None:
    """Return only the first field/category pair, never the matched value."""
    for field, text in iter_publishable_text(value):
        category = sensitive_value_kind(text)
        if category is not None:
            return field, category
    return None


def iter_r2_event_publishable_text(event: dict[str, Any]) -> Iterator[tuple[str, str]]:
    """Yield every R2 event text field that can reach a derived review view."""
    subjects = event.get("subjects")
    if isinstance(subjects, list):
        for index, value in enumerate(subjects):
            if isinstance(value, str):
                yield f"subjects[{index}]", value

    for field in ("blocker", "resume_step"):
        value = event.get(field)
        if isinstance(value, str):
            yield field, value

    details = event.get("details")
    if isinstance(details, dict):
        for field in ("summary", "reason_detail"):
            value = details.get(field)
            if isinstance(value, str):
                yield f"details.{field}", value
        metadata = details.get("metadata")
        if isinstance(metadata, list):
            for index, item in enumerate(metadata):
                if isinstance(item, dict) and isinstance(item.get("value"), str):
                    yield f"details.metadata[{index}].value", item["value"]

    next_actions = event.get("next_actions")
    if isinstance(next_actions, list):
        for index, item in enumerate(next_actions):
            if isinstance(item, dict) and isinstance(item.get("summary"), str):
                yield f"next_actions[{index}].summary", item["summary"]


def first_sensitive_r2_event_text(event: dict[str, Any]) -> tuple[str, str] | None:
    """Return the first unsafe field/category pair in deterministic field order."""
    for field, value in iter_r2_event_publishable_text(event):
        category = sensitive_value_kind(value)
        if category is not None:
            return field, category
    return None
