#!/usr/bin/env python3
"""Host-owned Docker verification case lifecycle and resource policy."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from evidence_io import (
    SafeEvidenceError,
    atomic_write_bytes,
    atomic_write_json,
    safe_read_bytes,
    safe_read_json,
)


POLICY_VERSION = "docker-case-policy-v1"
RECEIPT_SCHEMA_VERSION = 1
CLEANUP_SCHEMA_VERSION = 1
DEFAULT_MEMORY = "512m"
DEFAULT_CPUS = "1"
DEFAULT_PIDS_LIMIT = 256
OUTPUT_TMPFS_SIZE = "64m"
MIN_MEMORY_BYTES = 16 * 1024 * 1024
MAX_MEMORY_BYTES = 2 * 1024 * 1024 * 1024
MIN_CPUS = Decimal("0.1")
MAX_CPUS = Decimal("4")
MIN_PIDS = 1
MAX_PIDS = 1024
CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
DOCKER_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
MEMORY_RE = re.compile(r"^([1-9][0-9]*)(b|k|kb|kib|m|mb|mib|g|gb|gib)?$", re.I)
RESERVED_LABELS = {
    "org.zhulong.managed": "true",
    "org.zhulong.case": "",
    "org.zhulong.policy": POLICY_VERSION,
}


class LifecycleError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def memory_bytes(value: str) -> int:
    match = MEMORY_RE.fullmatch(value.strip())
    if not match:
        raise LifecycleError("DOCKER_RESOURCE_LIMIT_INVALID", "memory limit must be a positive bounded Docker memory value")
    number = int(match.group(1))
    unit = (match.group(2) or "b").lower()
    multiplier = {
        "b": 1,
        "k": 1024,
        "kb": 1000,
        "kib": 1024,
        "m": 1024**2,
        "mb": 1000**2,
        "mib": 1024**2,
        "g": 1024**3,
        "gb": 1000**3,
        "gib": 1024**3,
    }[unit]
    result = number * multiplier
    if result < MIN_MEMORY_BYTES or result > MAX_MEMORY_BYTES:
        raise LifecycleError("DOCKER_RESOURCE_LIMIT_INVALID", "memory limit is outside the host policy range")
    return result


def cpu_value(value: str) -> Decimal:
    try:
        result = Decimal(value.strip())
    except (InvalidOperation, AttributeError) as exc:
        raise LifecycleError("DOCKER_RESOURCE_LIMIT_INVALID", "CPU limit must be a positive bounded decimal") from exc
    if not result.is_finite() or result < MIN_CPUS or result > MAX_CPUS:
        raise LifecycleError("DOCKER_RESOURCE_LIMIT_INVALID", "CPU limit is outside the host policy range")
    return result


def pids_value(value: str | int) -> int:
    try:
        if isinstance(value, bool):
            raise ValueError
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise LifecycleError("DOCKER_RESOURCE_LIMIT_INVALID", "pids limit must be a positive bounded integer") from exc
    if str(result) != str(value).strip() or result < MIN_PIDS or result > MAX_PIDS:
        raise LifecycleError("DOCKER_RESOURCE_LIMIT_INVALID", "pids limit is outside the host policy range")
    return result


def normalize_cpu(value: Decimal) -> str:
    rendered = format(value.normalize(), "f")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def validate_policy(memory: str, cpus: str, pids_limit: str | int) -> dict[str, Any]:
    memory_size = memory_bytes(memory)
    cpus_decimal = cpu_value(cpus)
    pids = pids_value(pids_limit)
    return {
        "version": POLICY_VERSION,
        "memory": memory.lower(),
        "memory_bytes": memory_size,
        "cpus": normalize_cpu(cpus_decimal),
        "pids_limit": pids,
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "restart": "no",
        "output_tmpfs": OUTPUT_TMPFS_SIZE,
    }


def safe_case_component(case_id: str) -> str:
    if not CASE_ID_RE.fullmatch(case_id) or case_id in {".", ".."}:
        raise LifecycleError("DOCKER_CASE_LIFECYCLE_UNSAFE", "case id is not a safe logical identifier")
    return re.sub(r"[^a-z0-9_.-]", "-", case_id.lower())[:28].strip(".-_") or "case"


def validate_service(value: str) -> str:
    if not CASE_ID_RE.fullmatch(value) or value in {".", ".."}:
        raise LifecycleError("DOCKER_CASE_LIFECYCLE_UNSAFE", "Compose service is not a safe static identifier")
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def require_root(path: Path) -> Path:
    value = path.absolute()
    try:
        info = os.lstat(value)
    except OSError as exc:
        raise LifecycleError("DOCKER_CASE_LIFECYCLE_UNSAFE", "host-owned lifecycle evidence root is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise LifecycleError("DOCKER_CASE_LIFECYCLE_UNSAFE", "host-owned lifecycle evidence root is unsafe")
    return value


def receipt_digest(root: Path, path: Path) -> str:
    return sha256_bytes(safe_read_bytes(root, path))


def _labels(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, dict) and all(isinstance(key, str) and isinstance(item, (str, int, float, bool)) for key, item in value.items()):
        return {key: str(item).lower() if isinstance(item, bool) else str(item) for key, item in value.items()}
    if isinstance(value, list) and all(isinstance(item, str) and "=" in item for item in value):
        return dict(item.split("=", 1) for item in value)
    raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "merged Compose labels are not a static mapping")


def validate_receipt(value: Any) -> dict[str, Any]:
    required = {
        "schema_version", "policy", "case_id", "mode", "token", "project_name",
        "container_name", "compose_service", "labels", "override_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise LifecycleError("DOCKER_CASE_RECEIPT_DRIFT", "Docker case receipt shape is invalid")
    if value.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise LifecycleError("DOCKER_CASE_RECEIPT_DRIFT", "Docker case receipt schema is unsupported")
    safe_case_component(value.get("case_id", ""))
    if value.get("mode") not in {"docker-run", "docker-compose"}:
        raise LifecycleError("DOCKER_CASE_RECEIPT_DRIFT", "Docker case receipt mode is invalid")
    token = value.get("token")
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        raise LifecycleError("DOCKER_CASE_RECEIPT_DRIFT", "Docker case ownership token is invalid")
    for key in ("project_name", "container_name"):
        item = value.get(key)
        if not isinstance(item, str) or not DOCKER_NAME_RE.fullmatch(item):
            raise LifecycleError("DOCKER_CASE_RECEIPT_DRIFT", "Docker case resource identity is invalid")
    service = value.get("compose_service")
    if value["mode"] == "docker-compose":
        validate_service(service)
    elif service is not None:
        raise LifecycleError("DOCKER_CASE_RECEIPT_DRIFT", "docker-run receipt must not name a Compose service")
    policy = value.get("policy")
    if not isinstance(policy, dict) or set(policy) != {
        "version", "memory", "memory_bytes", "cpus", "pids_limit", "read_only",
        "cap_drop", "security_opt", "restart", "output_tmpfs",
    }:
        raise LifecycleError("DOCKER_CASE_RECEIPT_DRIFT", "Docker case policy receipt is invalid")
    expected_policy = validate_policy(policy.get("memory", ""), policy.get("cpus", ""), policy.get("pids_limit", ""))
    if policy != expected_policy:
        raise LifecycleError("DOCKER_CASE_RECEIPT_DRIFT", "Docker case policy receipt changed")
    labels = value.get("labels")
    expected_labels = dict(RESERVED_LABELS)
    expected_labels["org.zhulong.case"] = token
    expected_labels["org.zhulong.project"] = value["project_name"]
    if labels != expected_labels:
        raise LifecycleError("DOCKER_CASE_RECEIPT_DRIFT", "Docker case ownership labels changed")
    if not isinstance(value.get("override_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", value["override_sha256"]):
        raise LifecycleError("DOCKER_CASE_RECEIPT_DRIFT", "Docker case override digest is invalid")
    return value


def load_receipt(root: Path, path: Path, expected_digest: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise LifecycleError("DOCKER_CASE_RECEIPT_DRIFT", "an exact receipt digest is required")
    raw = safe_read_bytes(root, path)
    if sha256_bytes(raw) != expected_digest:
        raise LifecycleError("DOCKER_CASE_RECEIPT_DRIFT", "Docker case receipt digest changed")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LifecycleError("DOCKER_CASE_RECEIPT_DRIFT", "Docker case receipt is invalid JSON") from exc
    if canonical_json_bytes(value) != raw:
        raise LifecycleError("DOCKER_CASE_RECEIPT_DRIFT", "Docker case receipt is not canonical")
    return validate_receipt(value)


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    root = require_root(Path(args.evidence_root))
    case = safe_case_component(args.case_id)
    service = validate_service(args.compose_service) if args.mode == "docker-compose" else None
    policy = validate_policy(args.memory, args.cpus, args.pids_limit)
    token = secrets.token_hex(16)
    project = f"zhulong-{case[:20]}-{token[:12]}"
    container = f"zhulong-{case[:20]}-{token[12:24]}"
    labels = dict(RESERVED_LABELS)
    labels["org.zhulong.case"] = token
    labels["org.zhulong.project"] = project

    override: dict[str, Any] = {"services": {}}
    if service is not None:
        override["services"][service] = {
            "restart": "no",
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "mem_limit": policy["memory"],
            "memswap_limit": policy["memory"],
            "cpus": float(Decimal(policy["cpus"])),
            "pids_limit": policy["pids_limit"],
            "labels": labels,
            "logging": {"driver": "none"},
            "tmpfs": [f"/workspace/output:rw,nosuid,nodev,noexec,size={OUTPUT_TMPFS_SIZE}"],
        }
    override_raw = canonical_json_bytes(override)
    override_path = root / f"docker-case-policy-{token}.override.json"
    atomic_write_bytes(root, override_path, override_raw)
    override_sha = sha256_bytes(override_raw)
    receipt = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "policy": policy,
        "case_id": args.case_id,
        "mode": args.mode,
        "token": token,
        "project_name": project,
        "container_name": container,
        "compose_service": service,
        "labels": labels,
        "override_sha256": override_sha,
    }
    receipt_path = root / f"docker-case-receipt-{token}.json"
    atomic_write_json(root, receipt_path, receipt)
    digest = receipt_digest(root, receipt_path)
    return {
        "ok": True,
        "status": "prepared",
        "policy_version": POLICY_VERSION,
        "receipt_path": receipt_path.as_posix(),
        "receipt_sha256": digest,
        "override_path": override_path.as_posix(),
        "override_sha256": override_sha,
        "project_name": project,
        "container_name": container,
        "token": token,
        "resource_policy": policy,
    }


def _number_matches(value: Any, expected: int) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return int(value) == expected and float(value) == float(expected)
    if isinstance(value, str):
        try:
            return memory_bytes(value) == expected
        except LifecycleError:
            try:
                return int(value) == expected
            except ValueError:
                return False
    return False


def validate_config(args: argparse.Namespace) -> dict[str, Any]:
    root = require_root(Path(args.evidence_root))
    receipt_path = Path(args.receipt)
    receipt = load_receipt(root, receipt_path, args.receipt_sha256)
    if receipt["mode"] != "docker-compose":
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "only Compose receipts have a merged configuration")
    override_path = Path(args.override)
    if sha256_bytes(safe_read_bytes(root, override_path)) != receipt["override_sha256"]:
        raise LifecycleError("DOCKER_CASE_RECEIPT_DRIFT", "host-owned Compose override changed")
    config = safe_read_json(root, Path(args.config_json))
    services = config.get("services") if isinstance(config, dict) else None
    service = services.get(receipt["compose_service"]) if isinstance(services, dict) else None
    if not isinstance(service, dict):
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service is missing from merged Compose configuration")
    if "depends_on" in service:
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service gained unsupported dependencies")
    if service.get("privileged", False) is not False:
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service privileged policy changed")
    if service.get("restart", "no") != "no":
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service restart policy changed")
    if service.get("read_only") is not True:
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service read-only policy changed")
    if service.get("cap_drop") != ["ALL"]:
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service capability policy changed")
    if service.get("security_opt") != ["no-new-privileges:true"]:
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service security option policy changed")
    if service.get("logging") != {"driver": "none"}:
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service logging policy changed")
    if service.get("tmpfs") != [f"/workspace/output:rw,nosuid,nodev,noexec,size={OUTPUT_TMPFS_SIZE}"]:
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service output tmpfs policy changed")
    volumes = service.get("volumes", [])
    if not isinstance(volumes, list):
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service volume policy is invalid")
    for volume in volumes:
        target = volume.get("target") if isinstance(volume, dict) else str(volume).split(":")[1] if isinstance(volume, str) and ":" in volume else ""
        if target == "/workspace/output":
            raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "host output binds are forbidden; output must use the fixed tmpfs")
    policy = receipt["policy"]
    if not _number_matches(service.get("mem_limit"), policy["memory_bytes"]):
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service memory policy changed")
    if not _number_matches(service.get("memswap_limit"), policy["memory_bytes"]):
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service memory-swap policy changed")
    try:
        config_cpus = Decimal(str(service.get("cpus")))
    except InvalidOperation as exc:
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service CPU policy is invalid") from exc
    if config_cpus != Decimal(policy["cpus"]):
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service CPU policy changed")
    if service.get("pids_limit") != policy["pids_limit"]:
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service PID policy changed")
    labels = _labels(service.get("labels"))
    if any(labels.get(key) != value for key, value in receipt["labels"].items()):
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service ownership labels changed")
    image = service.get("image")
    if not isinstance(image, str) or not image or any(ord(char) < 32 for char in image):
        raise LifecycleError("COMPOSE_CONFIG_POLICY_MISMATCH", "selected service image is not a static value")
    return {
        "ok": True,
        "status": "validated",
        "policy_version": POLICY_VERSION,
        "selected_image": image,
        "receipt_sha256": args.receipt_sha256,
    }


def _docker(docker: str, *arguments: str) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [docker, *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, ""
    return result.returncode == 0, result.stdout


def _ids(docker: str, kind: str) -> tuple[bool, list[str]]:
    command = {
        "container": ("container", "ls", "--all", "--no-trunc", "--quiet"),
        "network": ("network", "ls", "--no-trunc", "--quiet"),
        "volume": ("volume", "ls", "--quiet"),
    }[kind]
    ok, output = _docker(docker, *command)
    values = [line.strip() for line in output.splitlines() if line.strip()]
    return ok, values


def _inspect(docker: str, kind: str, identity: str) -> dict[str, Any] | None:
    ok, output = _docker(docker, kind, "inspect", identity)
    if not ok:
        return None
    try:
        value = json.loads(output)
    except json.JSONDecodeError:
        return None
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
        return value[0]
    return value if isinstance(value, dict) else None


def _resource_labels(kind: str, value: dict[str, Any]) -> dict[str, str]:
    if kind == "container":
        config = value.get("Config")
        return _labels(config.get("Labels")) if isinstance(config, dict) else {}
    return _labels(value.get("Labels"))


def _container_name(value: dict[str, Any]) -> str:
    name = value.get("Name")
    return name.lstrip("/") if isinstance(name, str) else ""


def scan_owned_resources(docker: str, receipt: dict[str, Any]) -> tuple[bool, dict[str, list[str]], int]:
    owned = {"containers": [], "networks": [], "volumes": []}
    conflict_count = 0
    all_ok = True
    for singular, plural in (("container", "containers"), ("network", "networks"), ("volume", "volumes")):
        ok, identities = _ids(docker, singular)
        all_ok = all_ok and ok
        if not ok:
            continue
        for identity in identities:
            value = _inspect(docker, singular, identity)
            if value is None:
                all_ok = False
                continue
            labels = _resource_labels(singular, value)
            case_owned = labels.get("org.zhulong.case") == receipt["token"]
            project_owned = (
                receipt["mode"] == "docker-compose"
                and labels.get("com.docker.compose.project") == receipt["project_name"]
            )
            exact_name = singular == "container" and _container_name(value) == receipt["container_name"]
            if exact_name and not case_owned:
                conflict_count += 1
                continue
            if case_owned or project_owned:
                if singular == "container" and _container_name(value) != receipt["container_name"]:
                    conflict_count += 1
                    continue
                if receipt["mode"] == "docker-compose" and labels.get("com.docker.compose.project") != receipt["project_name"]:
                    conflict_count += 1
                    continue
                owned[plural].append(identity)
    return all_ok, owned, conflict_count


def cleanup(args: argparse.Namespace) -> dict[str, Any]:
    root = require_root(Path(args.evidence_root))
    receipt = load_receipt(root, Path(args.receipt), args.receipt_sha256)
    before_ok, before, before_conflicts = scan_owned_resources(args.docker, receipt)
    command_failures = 0
    settlement_checks = 0
    after_ok, after, after_conflicts = before_ok, before, before_conflicts
    settled = False
    for attempt in range(5):
        for identity in after["containers"]:
            ok, _ = _docker(args.docker, "container", "rm", "--force", "--volumes", identity)
            command_failures += 0 if ok else 1
        for identity in after["networks"]:
            ok, _ = _docker(args.docker, "network", "rm", identity)
            command_failures += 0 if ok else 1
        for identity in after["volumes"]:
            ok, _ = _docker(args.docker, "volume", "rm", identity)
            command_failures += 0 if ok else 1
        after_ok, after, after_conflicts = scan_owned_resources(args.docker, receipt)
        settlement_checks += 1
        if not after_ok or after_conflicts or any(after.values()):
            if attempt < 4:
                time.sleep(0.15)
                continue
        else:
            # Require three consecutive zero-residue observations so a delayed
            # daemon create cannot appear immediately after a single clean scan.
            stable = 1
            while stable < 3:
                time.sleep(0.15)
                after_ok, after, after_conflicts = scan_owned_resources(args.docker, receipt)
                settlement_checks += 1
                if not after_ok or after_conflicts or any(after.values()):
                    break
                stable += 1
            if stable >= 3:
                settled = True
                break
            if attempt < 4:
                time.sleep(0.15)
                continue
            break
    counts_before = {key: len(value) for key, value in before.items()}
    counts_after = {key: len(value) for key, value in after.items()}
    verified = (
        before_ok
        and after_ok
        and command_failures == 0
        and before_conflicts == 0
        and after_conflicts == 0
        and settled
        and all(value == 0 for value in counts_after.values())
    )
    report = {
        "schema_version": CLEANUP_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "receipt_sha256": args.receipt_sha256,
        "cleanup_attempted": True,
        "cleanup_verified": verified,
        "residue_counts_before": counts_before,
        "residue_counts_after": counts_after,
        "identity_conflict_count": before_conflicts + after_conflicts,
        "command_failure_count": command_failures,
        "settlement_checks": settlement_checks,
    }
    report_path = root / f"docker-case-cleanup-{receipt['token']}.json"
    atomic_write_json(root, report_path, report)
    return {
        "ok": verified,
        "status": "clean" if verified else "cleanup_failed",
        "issue_code": "" if verified else "DOCKER_CASE_CLEANUP_FAILED",
        "cleanup_path": report_path.as_posix(),
        **report,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage one exact Zhulong Docker verification case lifecycle.")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    policy_parser = subparsers.add_parser("validate-policy")
    policy_parser.add_argument("--memory", default=DEFAULT_MEMORY)
    policy_parser.add_argument("--cpus", default=DEFAULT_CPUS)
    policy_parser.add_argument("--pids-limit", default=str(DEFAULT_PIDS_LIMIT))

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--evidence-root", required=True)
    prepare_parser.add_argument("--case-id", required=True)
    prepare_parser.add_argument("--mode", required=True, choices=("docker-run", "docker-compose"))
    prepare_parser.add_argument("--compose-service", default="")
    prepare_parser.add_argument("--memory", default=DEFAULT_MEMORY)
    prepare_parser.add_argument("--cpus", default=DEFAULT_CPUS)
    prepare_parser.add_argument("--pids-limit", default=str(DEFAULT_PIDS_LIMIT))

    config_parser = subparsers.add_parser("validate-config")
    config_parser.add_argument("--evidence-root", required=True)
    config_parser.add_argument("--receipt", required=True)
    config_parser.add_argument("--receipt-sha256", required=True)
    config_parser.add_argument("--override", required=True)
    config_parser.add_argument("--config-json", required=True)

    cleanup_parser = subparsers.add_parser("cleanup")
    cleanup_parser.add_argument("--evidence-root", required=True)
    cleanup_parser.add_argument("--receipt", required=True)
    cleanup_parser.add_argument("--receipt-sha256", required=True)
    cleanup_parser.add_argument("--docker", default="docker")

    import_parser = subparsers.add_parser("import-output")
    import_parser.add_argument("--evidence-root", required=True)
    import_parser.add_argument("--receipt", required=True)
    import_parser.add_argument("--receipt-sha256", required=True)
    import_parser.add_argument("--output-dir", required=True)
    import_parser.add_argument("--docker", default="docker")
    return parser.parse_args()


def historical_output_only(_args: argparse.Namespace) -> dict[str, Any]:
    return {
        "ok": False,
        "status": "rejected",
        "issue_code": "CONTAINER_OUTPUT_HISTORICAL_ONLY",
    }


def main() -> int:
    args = parse_args()
    try:
        if args.operation == "validate-policy":
            result = {"ok": True, "status": "valid", "resource_policy": validate_policy(args.memory, args.cpus, args.pids_limit)}
        elif args.operation == "prepare":
            result = prepare(args)
        elif args.operation == "validate-config":
            result = validate_config(args)
        elif args.operation == "cleanup":
            result = cleanup(args)
        else:
            result = historical_output_only(args)
    except (LifecycleError, SafeEvidenceError) as exc:
        code = exc.code if hasattr(exc, "code") else "DOCKER_CASE_LIFECYCLE_UNSAFE"
        print(json.dumps({"ok": False, "status": "rejected", "issue_code": code}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
