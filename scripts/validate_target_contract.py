#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception as exc:  # pragma: no cover - dependency check path
    raise SystemExit(f"ERROR: PyYAML is required to validate zhulong-target.yaml: {exc}")


RUNTIME_TYPES = {"docker", "docker-compose", "manual-blocked"}
COMMAND_KEYS = {"command"}
PATH_KEYS = {"repo_root", "compose_file", "path", "file", "env_file"}

ABSOLUTE_POSIX_RE = re.compile(
    r"(?:^|[\s:=,'\"])/(?:Users|home|private|tmp|var|etc|root|opt|Volumes|mnt|srv|usr)(?:/|$)"
)
ABSOLUTE_WINDOWS_RE = re.compile(r"(?:^|[\s:=,'\"])[A-Za-z]:[\\/]")
PATH_TRAVERSAL_RE = re.compile(r"(?:^|[\s:=,'\"])\.\.(?:/|\\|$)")
BROAD_DOCKER_PRUNE_RE = re.compile(
    r"\bdocker\s+(?:system|builder|buildx|image|container|volume|network)\s+prune\b",
    re.IGNORECASE,
)
_PID_SIGNAL_WORDS = "9|KILL|TERM|SIG" + "KILL|SIG" + "TERM"
PID_KILL_RE = re.compile(
    r"\b(?:sudo\s+)?(?:kill\s+-(?:" + _PID_SIGNAL_WORDS + r")|pkill|killall)\b",
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


class ValidationError(Exception):
    pass


def fail(message: str) -> None:
    raise ValidationError(message)


def load_contract(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"target contract file not found: {path}")
    except yaml.YAMLError as exc:
        fail(f"invalid YAML: {exc}")
    if not isinstance(data, dict):
        fail("target contract root must be a mapping")
    return data


def require_mapping(parent: dict[str, Any], key: str, path: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        fail(f"missing required mapping: {path}.{key}")
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
    if not isinstance(value, int) or value < 1:
        fail(f"missing required positive integer: {path}.{key}")
    return value


def check_path_text(value: str, path: str) -> None:
    if value.startswith(("~", "file://")):
        fail(f"{path} must not use operator-local path syntax")
    if ABSOLUTE_POSIX_RE.search(value) or ABSOLUTE_WINDOWS_RE.search(value):
        fail(f"{path} must not contain an operator-local absolute path")
    if PATH_TRAVERSAL_RE.search(value) or any(part == ".." for part in value.replace("\\", "/").split("/")):
        fail(f"{path} must not contain parent path traversal")


def check_command_text(value: str, path: str) -> None:
    check_path_text(value, path)
    if BROAD_DOCKER_PRUNE_RE.search(value):
        fail(f"{path} must not use broad Docker prune commands")
    if PID_KILL_RE.search(value):
        fail(f"{path} must not use dangerous PID kill patterns")
    if UNSAFE_RUNTIME_RE.search(value):
        fail(f"{path} must not request privileged, host-network, docker-socket, or credential mounts")


def scan_security_text(value: str, path: str) -> None:
    if BROAD_DOCKER_PRUNE_RE.search(value):
        fail(f"{path} must not use broad Docker prune commands")
    if PID_KILL_RE.search(value):
        fail(f"{path} must not use dangerous PID kill patterns")
    if UNSAFE_RUNTIME_RE.search(value):
        fail(f"{path} must not request privileged, host-network, docker-socket, or credential mounts")


def walk_strings(value: Any, path: str = "$", key: str = "") -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            child_key_text = str(child_key)
            walk_strings(child, f"{path}.{child_key_text}", child_key_text)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk_strings(child, f"{path}[{index}]", key)
    elif isinstance(value, str):
        lowered_key = key.lower()
        if lowered_key in COMMAND_KEYS:
            check_command_text(value, path)
        elif lowered_key in PATH_KEYS or lowered_key.endswith("_path") or lowered_key.endswith("_file"):
            check_path_text(value, path)
            scan_security_text(value, path)
        else:
            scan_security_text(value, path)


def validate_target(contract: dict[str, Any]) -> dict[str, bool | str]:
    if contract.get("schema_version") != 1:
        fail("schema_version must be 1")

    target = require_mapping(contract, "target", "$")
    require_nonempty_string(target, "name", "$.target")
    require_nonempty_string(target, "repo_root", "$.target")
    require_nonempty_string(target, "tested_ref", "$.target")
    language_hint = require_list(target, "language_hint", "$.target")
    if not language_hint or any(not isinstance(item, str) or not item.strip() for item in language_hint):
        fail("$.target.language_hint must contain at least one non-empty string")

    runtime = require_mapping(contract, "runtime", "$")
    runtime_type = require_nonempty_string(runtime, "type", "$.runtime")
    if runtime_type not in RUNTIME_TYPES:
        fail("$.runtime.type must be one of: docker, docker-compose, manual-blocked")

    verify = require_mapping(contract, "verify", "$")
    require_nonempty_string(verify, "mode", "$.verify")

    scope = require_mapping(contract, "scope", "$")
    entrypoints = require_list(scope, "entrypoints", "$.scope")
    require_list(scope, "trust_boundaries", "$.scope")
    require_list(scope, "in_scope_bug_classes", "$.scope")
    require_list(scope, "out_of_scope", "$.scope")
    recon_incomplete = len(entrypoints) == 0

    if runtime_type == "docker-compose":
        require_nonempty_string(runtime, "compose_file", "$.runtime")
        require_nonempty_string(runtime, "service", "$.runtime")

    if runtime_type != "manual-blocked":
        healthcheck = require_mapping(runtime, "healthcheck", "$.runtime")
        require_nonempty_string(healthcheck, "command", "$.runtime.healthcheck")
        require_positive_int(healthcheck, "timeout_seconds", "$.runtime.healthcheck")

        build = require_mapping(contract, "build", "$")
        require_nonempty_string(build, "command", "$.build")

        start = require_mapping(contract, "start", "$")
        require_nonempty_string(start, "command", "$.start")
        readiness = require_mapping(start, "readiness", "$.start")
        require_nonempty_string(readiness, "command", "$.start.readiness")
        require_positive_int(readiness, "timeout_seconds", "$.start.readiness")

        require_nonempty_string(verify, "allowed_network", "$.verify")
        success_oracles = require_list(verify, "success_oracles", "$.verify")
        if not success_oracles:
            fail("$.verify.success_oracles must be non-empty unless runtime.type=manual-blocked")
        for index, oracle in enumerate(success_oracles):
            if not isinstance(oracle, dict):
                fail(f"$.verify.success_oracles[{index}] must be a mapping")
            require_nonempty_string(oracle, "type", f"$.verify.success_oracles[{index}]")
        cleanup = require_mapping(verify, "cleanup", "$.verify")
        require_nonempty_string(cleanup, "command", "$.verify.cleanup")
    else:
        success_oracles = verify.get("success_oracles", [])
        if success_oracles is not None and not isinstance(success_oracles, list):
            fail("$.verify.success_oracles must be a list when present")

    walk_strings(contract)
    return {
        "runtime_type": runtime_type,
        "confirmable": runtime_type != "manual-blocked",
        "recon_incomplete": recon_incomplete,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a Zhulong target contract YAML file.")
    parser.add_argument("contract", help="Path to zhulong-target.yaml")
    args = parser.parse_args()

    try:
        result = validate_target(load_contract(Path(args.contract)))
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)

    print(
        "OK: zhulong-target valid; "
        f"runtime_type={result['runtime_type']} "
        f"confirmable={str(result['confirmable']).lower()} "
        f"non_confirmable={str(not bool(result['confirmable'])).lower()} "
        f"recon_incomplete={str(result['recon_incomplete']).lower()}"
    )


if __name__ == "__main__":
    main()
