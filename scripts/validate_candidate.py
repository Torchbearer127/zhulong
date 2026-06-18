#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


TOP_LEVEL_KEYS = {
    "schema_version",
    "candidate_id",
    "title",
    "bug_class",
    "status",
    "target_ref",
    "entrypoint",
    "attacker_model",
    "claim",
    "poc",
    "evidence",
    "finder",
}
CONFIRMED_LIKE_KEYS = {
    "confirmed",
    "confirmation",
    "verdict",
    "verification_status",
    "disposition_recommendation",
    "docker_status",
}
CONFIRMED_LIKE_TEXT_RE = re.compile(r"\b(?:confirmed(?:_in_docker)?|verified)\b", re.IGNORECASE)
ABSOLUTE_POSIX_RE = re.compile(
    r"(?:^|[\s:=,'\"])/(?:Users|home|private|tmp|var|etc|root|opt|Volumes|mnt|srv|usr)(?:/|$)"
)
ABSOLUTE_WINDOWS_RE = re.compile(r"(?:^|[\s:=,'\"])[A-Za-z]:[\\/]")
PATH_TRAVERSAL_RE = re.compile(r"(?:^|[\s:=,'\"])\.\.(?:/|\\|$)")
BROAD_DOCKER_PRUNE_RE = re.compile(
    r"\bdocker\s+(?:system|builder|buildx|image|container|volume|network)\s+prune\b",
    re.IGNORECASE,
)
PID_KILL_RE = re.compile(
    r"\b(?:sudo\s+)?(?:kill\s+-(?:9|KILL|TERM|SIGKILL|SIGTERM)|pkill|killall)\b",
    re.IGNORECASE,
)
UNSAFE_RUNTIME_RE = re.compile(
    r"("
    r"--privileged\b|"
    r"\bprivileged\s*:\s*true\b|"
    r"--net(?:work)?[=\s]+host\b|"
    r"\bnetwork_mode\s*:\s*host\b|"
    r"--pid[=\s]+host\b|"
    r"\bpid\s*:\s*host\b|"
    r"docker\.sock|"
    r"(?:^|[\s:=,'\"])/(?:root|home/[^/\s]+|Users/[^/\s]+)/\.(?:ssh|aws|config/gcloud)(?:/|$)|"
    r"(?:^|[\s:=,'\"])\.(?:npmrc|pypirc)\b|"
    r"_authToken|"
    r"credential(?:s)?(?:_file|s)?\s*:"
    r")",
    re.IGNORECASE,
)
SECRET_LIKE_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|api[_-]?key|secret|token)\s*[:=])",
    re.IGNORECASE,
)
PATH_KEYS = {"target_config", "path", "file", "artifact"}


class ValidationError(Exception):
    pass


def fail(message: str) -> None:
    raise ValidationError(message)


def load_candidate(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"candidate file not found: {path}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON: {exc}")
    if not isinstance(data, dict):
        fail("candidate root must be an object")
    return data


def reject_unknown(mapping: dict[str, Any], allowed: set[str], path: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        fail(f"{path} has unsupported field(s): {', '.join(unknown)}")


def require_mapping(parent: dict[str, Any], key: str, path: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        fail(f"missing required object: {path}.{key}")
    return value


def require_list(parent: dict[str, Any], key: str, path: str) -> list[Any]:
    value = parent.get(key)
    if not isinstance(value, list):
        fail(f"missing required list: {path}.{key}")
    return value


def require_nonempty_string(parent: dict[str, Any], key: str, path: str) -> str:
    value = parent.get(key)
    if not isinstance(value, str) or not value.strip():
        fail(f"missing required string: {path}.{key}")
    return value


def require_positive_int(parent: dict[str, Any], key: str, path: str) -> int:
    value = parent.get(key)
    if type(value) is not int or value < 1:
        fail(f"missing required positive integer: {path}.{key}")
    return value


def require_string_list(parent: dict[str, Any], key: str, path: str, *, min_items: int = 0) -> list[str]:
    values = require_list(parent, key, path)
    if len(values) < min_items:
        fail(f"{path}.{key} must contain at least {min_items} item(s)")
    for index, item in enumerate(values):
        if not isinstance(item, str) or not item.strip():
            fail(f"{path}.{key}[{index}] must be a non-empty string")
    return values


def check_path_text(value: str, path: str) -> None:
    if value.startswith(("~", "file://")):
        fail(f"{path} must not use operator-local path syntax")
    if ABSOLUTE_POSIX_RE.search(value) or ABSOLUTE_WINDOWS_RE.search(value):
        fail(f"{path} must not contain an operator-local absolute path")
    if PATH_TRAVERSAL_RE.search(value) or any(part == ".." for part in value.replace("\\", "/").split("/")):
        fail(f"{path} must not contain parent path traversal")


def scan_security_text(value: str, path: str) -> None:
    if value.startswith(("~", "file://")):
        fail(f"{path} must not use operator-local path syntax")
    if ABSOLUTE_POSIX_RE.search(value) or ABSOLUTE_WINDOWS_RE.search(value):
        fail(f"{path} must not contain an operator-local absolute path")
    if PATH_TRAVERSAL_RE.search(value):
        fail(f"{path} must not contain parent path traversal")
    if BROAD_DOCKER_PRUNE_RE.search(value):
        fail(f"{path} must not use broad Docker prune commands")
    if PID_KILL_RE.search(value):
        fail(f"{path} must not use dangerous PID kill patterns")
    if UNSAFE_RUNTIME_RE.search(value):
        fail(f"{path} must not request privileged, host-network, docker-socket, or credential mounts")
    if SECRET_LIKE_RE.search(value):
        fail(f"{path} must not contain secret-like material")


def walk_strings(value: Any, path: str = "$", key: str = "") -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            child_key_text = str(child_key)
            walk_strings(child, f"{path}.{child_key_text}", child_key_text)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk_strings(child, f"{path}[{index}]", key)
    elif isinstance(value, str):
        if key.lower() in PATH_KEYS or key.lower().endswith("_path") or key.lower().endswith("_file"):
            check_path_text(value, path)
        scan_security_text(value, path)


def check_candidate_not_confirmed(candidate: dict[str, Any]) -> None:
    for key, value in candidate.items():
        lowered = str(key).lower()
        if lowered in CONFIRMED_LIKE_KEYS or "confirmed" in lowered or "verified" in lowered:
            fail(f"candidate must not contain confirmed-like top-level field: {key}")
        if isinstance(value, str) and key != "status" and CONFIRMED_LIKE_TEXT_RE.search(value):
            fail(f"candidate must not contain confirmed-like top-level wording: {key}")


def validate_candidate(candidate: dict[str, Any]) -> dict[str, str]:
    reject_unknown(candidate, TOP_LEVEL_KEYS, "$")
    if candidate.get("schema_version") != 1:
        fail("schema_version must be 1")
    check_candidate_not_confirmed(candidate)

    candidate_id = require_nonempty_string(candidate, "candidate_id", "$")
    if not re.fullmatch(r"CAND-[0-9A-Za-z._-]+", candidate_id):
        fail("$.candidate_id must be stable and start with CAND-")
    require_nonempty_string(candidate, "title", "$")
    require_nonempty_string(candidate, "bug_class", "$")
    status = require_nonempty_string(candidate, "status", "$")
    if status != "candidate":
        fail("$.status must be exactly candidate; candidates cannot be confirmed or verified")

    target_ref = require_mapping(candidate, "target_ref", "$")
    reject_unknown(target_ref, {"target_config", "tested_ref"}, "$.target_ref")
    require_nonempty_string(target_ref, "target_config", "$.target_ref")
    require_nonempty_string(target_ref, "tested_ref", "$.target_ref")

    entrypoint = require_mapping(candidate, "entrypoint", "$")
    reject_unknown(entrypoint, {"id", "kind", "route"}, "$.entrypoint")
    require_nonempty_string(entrypoint, "id", "$.entrypoint")
    require_nonempty_string(entrypoint, "kind", "$.entrypoint")
    require_nonempty_string(entrypoint, "route", "$.entrypoint")

    attacker_model = require_mapping(candidate, "attacker_model", "$")
    reject_unknown(
        attacker_model,
        {"required_auth", "attacker_controls", "environment_assumptions"},
        "$.attacker_model",
    )
    require_nonempty_string(attacker_model, "required_auth", "$.attacker_model")
    require_string_list(attacker_model, "attacker_controls", "$.attacker_model", min_items=1)
    require_string_list(attacker_model, "environment_assumptions", "$.attacker_model")

    claim = require_mapping(candidate, "claim", "$")
    reject_unknown(claim, {"source", "sink", "missing_constraint", "impact"}, "$.claim")
    require_nonempty_string(claim, "source", "$.claim")
    require_nonempty_string(claim, "sink", "$.claim")
    require_nonempty_string(claim, "missing_constraint", "$.claim")
    require_nonempty_string(claim, "impact", "$.claim")

    poc = require_mapping(candidate, "poc", "$")
    reject_unknown(poc, {"kind", "path", "expected_oracle"}, "$.poc")
    require_nonempty_string(poc, "kind", "$.poc")
    require_nonempty_string(poc, "path", "$.poc")
    expected_oracle = require_mapping(poc, "expected_oracle", "$.poc")
    reject_unknown(expected_oracle, {"type", "description"}, "$.poc.expected_oracle")
    require_nonempty_string(expected_oracle, "type", "$.poc.expected_oracle")
    require_nonempty_string(expected_oracle, "description", "$.poc.expected_oracle")

    evidence = require_mapping(candidate, "evidence", "$")
    reject_unknown(evidence, {"static_locations", "dynamic_evidence"}, "$.evidence")
    static_locations = require_list(evidence, "static_locations", "$.evidence")
    for index, location in enumerate(static_locations):
        if not isinstance(location, dict):
            fail(f"$.evidence.static_locations[{index}] must be an object")
        item_path = f"$.evidence.static_locations[{index}]"
        reject_unknown(location, {"path", "start_line", "end_line", "reason"}, item_path)
        require_nonempty_string(location, "path", item_path)
        start_line = require_positive_int(location, "start_line", item_path)
        end_line = require_positive_int(location, "end_line", item_path)
        if end_line < start_line:
            fail(f"{item_path}.end_line must be greater than or equal to start_line")
        require_nonempty_string(location, "reason", item_path)

    dynamic_evidence = require_list(evidence, "dynamic_evidence", "$.evidence")
    for index, item in enumerate(dynamic_evidence):
        if not isinstance(item, dict):
            fail(f"$.evidence.dynamic_evidence[{index}] must be an object")
        item_path = f"$.evidence.dynamic_evidence[{index}]"
        reject_unknown(item, {"type", "path", "summary"}, item_path)
        require_nonempty_string(item, "type", item_path)
        require_nonempty_string(item, "summary", item_path)
        if "path" in item:
            require_nonempty_string(item, "path", item_path)

    finder = require_mapping(candidate, "finder", "$")
    reject_unknown(finder, {"source", "created_at"}, "$.finder")
    require_nonempty_string(finder, "source", "$.finder")
    require_nonempty_string(finder, "created_at", "$.finder")

    walk_strings(candidate)
    return {"candidate_id": candidate_id, "status": status}


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a Zhulong candidate.json file.")
    parser.add_argument("candidate", help="Path to candidate.json")
    args = parser.parse_args()

    try:
        result = validate_candidate(load_candidate(Path(args.candidate)))
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)

    print(f"OK: candidate valid; candidate_id={result['candidate_id']} status={result['status']}")


if __name__ == "__main__":
    main()
