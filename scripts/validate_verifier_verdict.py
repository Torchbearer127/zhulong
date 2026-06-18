#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from validate_candidate import (
    ValidationError as CandidateValidationError,
    check_path_text,
    load_candidate,
    scan_security_text,
    validate_candidate,
)


VERDICTS = {"blocked", "false_positive", "unverified", "confirmed_in_docker"}
RUNTIME_TYPES = {"docker", "docker-compose", "manual-blocked"}
TOP_LEVEL_KEYS = {
    "schema_version",
    "candidate_id",
    "verdict",
    "verification_status",
    "target_ref",
    "environment",
    "commands",
    "oracle_result",
    "disposition_recommendation",
    "negative_checks",
    "artifacts",
    "reason",
    "verified_at",
}
PATH_KEYS = {"target_config", "path", "file", "artifact"}


class ValidationError(Exception):
    pass


def fail(message: str) -> None:
    raise ValidationError(message)


def load_verdict(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"verifier verdict file not found: {path}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON: {exc}")
    if not isinstance(data, dict):
        fail("verifier verdict root must be an object")
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


def require_bool(parent: dict[str, Any], key: str, path: str) -> bool:
    value = parent.get(key)
    if type(value) is not bool:
        fail(f"missing required boolean: {path}.{key}")
    return value


def require_int(parent: dict[str, Any], key: str, path: str) -> int:
    value = parent.get(key)
    if type(value) is not int:
        fail(f"missing required integer: {path}.{key}")
    return value


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


def validate_verdict(verdict_doc: dict[str, Any]) -> dict[str, str]:
    reject_unknown(verdict_doc, TOP_LEVEL_KEYS, "$")
    if verdict_doc.get("schema_version") != 1:
        fail("schema_version must be 1")

    candidate_id = require_nonempty_string(verdict_doc, "candidate_id", "$")
    if not re.fullmatch(r"CAND-[0-9A-Za-z._-]+", candidate_id):
        fail("$.candidate_id must be stable and start with CAND-")

    verdict = require_nonempty_string(verdict_doc, "verdict", "$")
    if verdict not in VERDICTS:
        fail("$.verdict must be one of: blocked, false_positive, unverified, confirmed_in_docker")
    verification_status = require_nonempty_string(verdict_doc, "verification_status", "$")
    if verification_status != verdict:
        fail("$.verification_status must be consistent with verdict")
    disposition = require_nonempty_string(verdict_doc, "disposition_recommendation", "$")
    if disposition != verdict:
        fail("$.disposition_recommendation must equal the safe disposition derived from verdict")

    target_ref = require_mapping(verdict_doc, "target_ref", "$")
    reject_unknown(target_ref, {"target_config", "tested_ref"}, "$.target_ref")
    require_nonempty_string(target_ref, "target_config", "$.target_ref")
    require_nonempty_string(target_ref, "tested_ref", "$.target_ref")

    environment = require_mapping(verdict_doc, "environment", "$")
    reject_unknown(
        environment,
        {
            "fresh_container",
            "runtime_type",
            "host_network",
            "privileged",
            "docker_socket_mounted",
            "credential_paths_mounted",
            "egress_policy",
        },
        "$.environment",
    )
    fresh_container = require_bool(environment, "fresh_container", "$.environment")
    runtime_type = require_nonempty_string(environment, "runtime_type", "$.environment")
    if runtime_type not in RUNTIME_TYPES:
        fail("$.environment.runtime_type must be docker, docker-compose, or manual-blocked")
    host_network = require_bool(environment, "host_network", "$.environment")
    privileged = require_bool(environment, "privileged", "$.environment")
    docker_socket_mounted = require_bool(environment, "docker_socket_mounted", "$.environment")
    credential_paths_mounted = require_bool(environment, "credential_paths_mounted", "$.environment")
    require_nonempty_string(environment, "egress_policy", "$.environment")

    commands = require_list(verdict_doc, "commands", "$")
    for index, command_doc in enumerate(commands):
        if not isinstance(command_doc, dict):
            fail(f"$.commands[{index}] must be an object")
        item_path = f"$.commands[{index}]"
        reject_unknown(command_doc, {"name", "command", "exit_code"}, item_path)
        require_nonempty_string(command_doc, "name", item_path)
        require_nonempty_string(command_doc, "command", item_path)
        require_int(command_doc, "exit_code", item_path)

    oracle_result = require_mapping(verdict_doc, "oracle_result", "$")
    reject_unknown(oracle_result, {"type", "success", "summary"}, "$.oracle_result")
    require_nonempty_string(oracle_result, "type", "$.oracle_result")
    oracle_success = require_bool(oracle_result, "success", "$.oracle_result")
    oracle_summary = require_nonempty_string(oracle_result, "summary", "$.oracle_result")

    negative_checks = require_list(verdict_doc, "negative_checks", "$")
    for index, check in enumerate(negative_checks):
        if not isinstance(check, dict):
            fail(f"$.negative_checks[{index}] must be an object")
        item_path = f"$.negative_checks[{index}]"
        reject_unknown(check, {"check", "passed", "reason"}, item_path)
        require_nonempty_string(check, "check", item_path)
        require_bool(check, "passed", item_path)
        if "reason" in check:
            require_nonempty_string(check, "reason", item_path)

    artifacts = require_list(verdict_doc, "artifacts", "$")
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, str) or not artifact.strip():
            fail(f"$.artifacts[{index}] must be a non-empty string")

    if "reason" in verdict_doc:
        require_nonempty_string(verdict_doc, "reason", "$")
    require_nonempty_string(verdict_doc, "verified_at", "$")

    if verdict == "confirmed_in_docker":
        if runtime_type == "manual-blocked":
            fail("confirmed_in_docker requires a Docker-backed runtime")
        if not fresh_container:
            fail("confirmed_in_docker requires environment.fresh_container=true")
        if host_network:
            fail("confirmed_in_docker requires environment.host_network=false")
        if privileged:
            fail("confirmed_in_docker requires environment.privileged=false")
        if docker_socket_mounted:
            fail("confirmed_in_docker requires environment.docker_socket_mounted=false")
        if credential_paths_mounted:
            fail("confirmed_in_docker requires environment.credential_paths_mounted=false")
        if not oracle_success:
            fail("confirmed_in_docker requires oracle_result.success=true")
        if not commands:
            fail("confirmed_in_docker requires non-empty commands")
        if not artifacts:
            fail("confirmed_in_docker requires non-empty artifacts")
    else:
        reason = verdict_doc.get("reason")
        if not (isinstance(reason, str) and reason.strip()) and not oracle_summary.strip():
            fail(f"{verdict} verdict requires a reason or oracle_result.summary explaining the decision")

    walk_strings(verdict_doc)
    return {"candidate_id": candidate_id, "verdict": verdict}


def cross_check_candidate(candidate_path: Path, verdict_doc: dict[str, Any]) -> None:
    try:
        candidate_doc = load_candidate(candidate_path)
        validate_candidate(candidate_doc)
    except CandidateValidationError as exc:
        fail(f"candidate cross-check failed because candidate is invalid: {exc}")

    if verdict_doc.get("candidate_id") != candidate_doc.get("candidate_id"):
        fail("candidate cross-check failed: candidate_id mismatch")
    if verdict_doc.get("target_ref") != candidate_doc.get("target_ref"):
        fail("candidate cross-check failed: target_ref mismatch")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a Zhulong verifier-verdict.json file.")
    parser.add_argument("--candidate", help="Optional candidate.json path for candidate_id and target_ref cross-check")
    parser.add_argument("verdict", help="Path to verifier-verdict.json")
    args = parser.parse_args()

    try:
        verdict_doc = load_verdict(Path(args.verdict))
        result = validate_verdict(verdict_doc)
        if args.candidate:
            cross_check_candidate(Path(args.candidate), verdict_doc)
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)

    print(f"OK: verifier-verdict valid; candidate_id={result['candidate_id']} verdict={result['verdict']}")


if __name__ == "__main__":
    main()
