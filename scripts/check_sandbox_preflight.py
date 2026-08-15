#!/usr/bin/env python3
# zhulong-tool-contract: sandbox-preflight-v1; compose-input-pinning=r1
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import yaml
    from yaml.constructor import ConstructorError
    from yaml.tokens import AliasToken, AnchorToken

    YAML_DYNAMIC_TOKEN_TYPES: tuple[type, ...] = (AnchorToken, AliasToken)
except Exception:  # pragma: no cover - reported as a fail-closed finding
    yaml = None
    ConstructorError = Exception
    YAML_DYNAMIC_TOKEN_TYPES = ()


REJECTED_STATUS = "rejected_unsafe_sandbox"
PASSED_STATUS = "passed"
PIN_SCHEMA_VERSION = 1
BIND_IDENTITY_SCHEMA_VERSION = 3
MAX_COMPOSE_FILES = 8
MAX_COMPOSE_FILE_BYTES = 1024 * 1024
MAX_COMPOSE_TOTAL_BYTES = 4 * 1024 * 1024
PIN_ID_RE = re.compile(r"^pin-[0-9a-f]{32}$")
CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
RESUME_UNSAFE = (
    "Rewrite the verification definition to the closed Compose subset or safe "
    "docker-run contract. Keep the case candidate/blocked/unverified until a "
    "fresh pinned input set passes sandbox preflight."
)
RESUME_OK = "Sandbox preflight passed; continue with the same pinned Docker verification input."


LINE_RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    ("dangerous_docker_config", "privileged_true", re.compile(r"^\s*privileged\s*:\s*(?:true|yes|1)\b", re.I), "Compose service enables privileged mode."),
    ("dangerous_docker_config", "network_mode_host", re.compile(r"^\s*network_mode\s*:\s*['\"]?host['\"]?\s*(?:#.*)?$", re.I), "Compose service uses host networking."),
    ("dangerous_docker_config", "pid_host", re.compile(r"^\s*pid\s*:\s*['\"]?host['\"]?\s*(?:#.*)?$", re.I), "Compose service joins the host PID namespace."),
    ("credential_exposure_risk", "docker_socket_mount", re.compile(r"/var/run/docker\.sock"), "Docker socket mount exposes host Docker control."),
    ("dangerous_docker_config", "host_root_mount", re.compile(r"^\s*-\s*['\"]?/\s*:\s*[^#]+", re.I), "Compose volume mounts host root."),
    ("dangerous_docker_config", "host_root_mount", re.compile(r"^\s*source\s*:\s*['\"]?/\s*['\"]?\s*(?:#.*)?$", re.I), "Compose bind mount source is host root."),
    ("dangerous_docker_config", "host_root_mount", re.compile(r"(?:^|\s)--mount(?:=|\s+)[^\n#]*(?:source|src)=/(?:,|\s|$)", re.I), "Docker mount uses host root as bind source."),
    ("dangerous_docker_config", "host_root_mount", re.compile(r"(?:^|\s)(?:-v|--volume)(?:=|\s+)['\"]?/\s*:", re.I), "Docker volume mounts host root."),
]

SHELL_FLAG_RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    ("dangerous_shell_flag", "docker_run_privileged", re.compile(r"(?:^|\s)--privileged(?:[=\s]|$)", re.I), "Docker run command requests privileged mode."),
    ("dangerous_shell_flag", "docker_run_network_host", re.compile(r"(?:^|\s)--net(?:work)?(?:=|\s+)host(?:\s|$)", re.I), "Docker run command requests host networking."),
    ("dangerous_shell_flag", "docker_run_pid_host", re.compile(r"(?:^|\s)--pid(?:=|\s+)host(?:\s|$)", re.I), "Docker run command requests host PID namespace."),
]

TOP_LEVEL_FIELDS = {"version", "services"}
SERVICE_FIELDS = {
    "image", "privileged", "command", "entrypoint", "environment", "working_dir",
    "user", "read_only", "healthcheck", "depends_on", "volumes", "labels",
    "cap_drop", "init", "restart", "stop_grace_period",
}
NAMESPACE_FIELDS = {"network_mode", "pid", "ipc", "uts", "cgroup", "userns_mode"}
CAPABILITY_FIELDS = {"cap_add", "devices", "device_cgroup_rules", "security_opt", "volumes_from"}
HOST_FILE_FIELDS = {"build", "env_file", "secrets", "configs", "extends", "develop", "label_file", "credential_spec", "include"}


class PinningError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


if yaml is not None:
    class NoDuplicateSafeLoader(yaml.SafeLoader):
        pass


    def _construct_unique_mapping(loader: Any, node: Any, deep: bool = False) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise ConstructorError("while constructing a mapping", node.start_mark, "unhashable mapping key", key_node.start_mark) from exc
            if duplicate:
                raise ConstructorError("while constructing a mapping", node.start_mark, f"duplicate key: {key!r}", key_node.start_mark)
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping


    NoDuplicateSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        _construct_unique_mapping,
    )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fail-closed Zhulong Docker sandbox and Compose-input boundary helper.")
    parser.add_argument("--workspace-dir", default="", help="Canonical Zhulong audit workspace.")
    parser.add_argument("--case-id", default="", help="Verification case id.")
    parser.add_argument("--mode", default="", help="Verification mode, such as docker-run or docker-compose.")
    parser.add_argument("--compose-operation", choices=("preflight", "pin", "verify", "cleanup"), default="preflight")
    parser.add_argument("--compose-file", action="append", default=[], help="Compose source or pinned file. Repeatable and ordered.")
    parser.add_argument("--compose-service", default="", help="Selected Compose service; must exist in the pinned input set.")
    parser.add_argument("--compose-manifest", default="", help="Pinned Compose manifest path.")
    parser.add_argument("--compose-manifest-sha256", default="", help="Expected pinned manifest SHA-256.")
    parser.add_argument("--compose-project-directory", default="", help="Explicit Compose project directory; must be the workspace.")
    parser.add_argument("--expected-bind-identities", default="", help="Internal JSON identity snapshot for repeated host-bind checks.")
    parser.add_argument("--verify-default-mounts", action="store_true", help="Recheck the fixed docker-run default mount directories.")
    parser.add_argument("--shell-script", action="append", default=[], help="Shell script to inspect. Repeatable.")
    parser.add_argument("--input-file", action="append", default=[], help="Generated verification input to inspect. Repeatable.")
    parser.add_argument("--docker-run-arg", action="append", default=[], help="One docker-run argv token to inspect. Repeatable.")
    parser.add_argument("--docker-run-snippet", action="append", default=[], help="Docker command snippet text to inspect.")
    parser.add_argument("--network", default="", help="Docker-run network selected by the verification runner.")
    parser.add_argument("--json", action="store_true", help="Accepted for compatibility; output is always JSON.")
    return parser.parse_args()


def require_workspace(value: str) -> Path:
    if not value:
        raise PinningError("COMPOSE_INPUT_UNSAFE", "A workspace directory is required.")
    raw = Path(value).expanduser()
    if raw.is_symlink() or not raw.is_dir():
        raise PinningError("COMPOSE_INPUT_UNSAFE", "The workspace must be an existing real directory.")
    workspace = raw.resolve(strict=True)
    try:
        config_info = os.lstat(workspace / "asr-config.json")
    except OSError as exc:
        raise PinningError("COMPOSE_INPUT_UNSAFE", "The directory is not a Zhulong audit workspace.") from exc
    if not stat.S_ISREG(config_info.st_mode) or stat.S_ISLNK(config_info.st_mode) or config_info.st_nlink != 1:
        raise PinningError("COMPOSE_INPUT_UNSAFE", "The directory is not a Zhulong audit workspace.")
    require_real_directory(workspace, allow_missing_suffix=False, issue_code="COMPOSE_INPUT_UNSAFE")
    return workspace


def safe_relative(raw_value: str, workspace: Path) -> PurePosixPath:
    if not raw_value or any(ord(char) < 32 for char in raw_value) or "\\" in raw_value or "://" in raw_value:
        raise PinningError("COMPOSE_INPUT_UNSAFE", "Compose inputs must use a static workspace-local path.")
    raw = Path(raw_value).expanduser()
    if raw.is_absolute():
        try:
            raw = raw.relative_to(workspace)
        except ValueError as exc:
            raise PinningError("COMPOSE_INPUT_UNSAFE", "Compose inputs must remain within the audit workspace.") from exc
    pure = PurePosixPath(raw.as_posix())
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise PinningError("COMPOSE_INPUT_UNSAFE", "Compose input paths must not contain dot or parent components.")
    if not pure.parts:
        raise PinningError("COMPOSE_INPUT_UNSAFE", "Compose input path is empty.")
    return pure


def open_workspace_file(workspace: Path, relative: PurePosixPath) -> tuple[int, os.stat_result]:
    flags_dir = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags_file = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    dir_fd = os.open(workspace, flags_dir)
    try:
        for part in relative.parts[:-1]:
            next_fd = os.open(part, flags_dir, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        file_fd = os.open(relative.parts[-1], flags_file, dir_fd=dir_fd)
    except OSError as exc:
        raise PinningError("COMPOSE_INPUT_UNSAFE", "Compose input must be an existing regular file with no symlink traversal.") from exc
    finally:
        os.close(dir_fd)
    info = os.fstat(file_fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(file_fd)
        raise PinningError("COMPOSE_INPUT_UNSAFE", "Compose input must be a single-link regular file.")
    if info.st_size > MAX_COMPOSE_FILE_BYTES:
        os.close(file_fd)
        raise PinningError("COMPOSE_INPUT_UNSAFE", "Compose input exceeds the per-file size limit.")
    return file_fd, info


def read_stable_workspace_file(workspace: Path, relative: PurePosixPath) -> tuple[bytes, os.stat_result]:
    file_fd, before = open_workspace_file(workspace, relative)
    try:
        chunks: list[bytes] = []
        remaining = MAX_COMPOSE_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(file_fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(file_fd)
    finally:
        os.close(file_fd)
    data = b"".join(chunks)
    if identity(before) != identity(after) or len(data) != before.st_size or len(data) > MAX_COMPOSE_FILE_BYTES:
        raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose file changed while it was being read.")
    return data, before


def ensure_real_private_dir(path: Path, *, create: bool) -> None:
    if path.exists() or path.is_symlink():
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise PinningError("COMPOSE_INPUT_UNSAFE", "Compose pin storage must contain real directories only.")
        if info.st_mode & 0o077:
            raise PinningError("COMPOSE_INPUT_UNSAFE", "Compose pin storage must not be accessible by group or other users.")
        return
    if not create:
        raise PinningError("COMPOSE_INPUT_UNSAFE", "Pinned Compose storage is missing.")
    try:
        path.mkdir(mode=0o700)
        path.chmod(0o700)
    except OSError as exc:
        raise PinningError("COMPOSE_INPUT_UNSAFE", "Could not create private Compose pin storage.") from exc


def pin_root(workspace: Path, *, create: bool) -> Path:
    runtime = workspace / "runtime"
    if runtime.exists() or runtime.is_symlink():
        info = os.lstat(runtime)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise PinningError("COMPOSE_INPUT_UNSAFE", "Workspace runtime path is not a real directory.")
    elif create:
        runtime.mkdir(mode=0o700)
        runtime.chmod(0o700)
    else:
        raise PinningError("COMPOSE_INPUT_UNSAFE", "Workspace runtime directory is missing.")
    root = runtime / "compose-inputs"
    ensure_real_private_dir(root, create=create)
    return root


def identity(info: os.stat_result) -> dict[str, int]:
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "mode": int(stat.S_IMODE(info.st_mode)),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "nlink": int(info.st_nlink),
    }


def cleanup_pin_dir(pin_dir: Path) -> None:
    try:
        if pin_dir.is_symlink() or not pin_dir.is_dir():
            return
        for child in list(pin_dir.iterdir()):
            try:
                info = os.lstat(child)
                if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                    child.unlink()
            except OSError:
                pass
        pin_dir.rmdir()
    except OSError:
        pass


def pin_compose_inputs(workspace: Path, values: list[str], case_id: str) -> dict[str, Any]:
    if not CASE_ID_RE.fullmatch(case_id) or case_id in {".", ".."}:
        raise PinningError("COMPOSE_INPUT_UNSAFE", "A safe case id is required for Compose input pinning.")
    if not values or len(values) > MAX_COMPOSE_FILES:
        raise PinningError("COMPOSE_INPUT_UNSAFE", "Compose input count is outside the allowed range.")
    root = pin_root(workspace, create=True)
    pin_id = "pin-" + secrets.token_hex(16)
    pin_dir = root / pin_id
    try:
        pin_dir.mkdir(mode=0o700)
        pin_dir.chmod(0o700)
    except OSError as exc:
        raise PinningError("COMPOSE_INPUT_UNSAFE", "Could not allocate a fresh private Compose pin directory.") from exc

    entries: list[dict[str, Any]] = []
    snapshot_paths: list[str] = []
    total = 0
    try:
        for index, raw_value in enumerate(values, start=1):
            relative = safe_relative(raw_value, workspace)
            file_fd, before = open_workspace_file(workspace, relative)
            try:
                chunks: list[bytes] = []
                remaining = MAX_COMPOSE_FILE_BYTES + 1
                while remaining > 0:
                    chunk = os.read(file_fd, min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                after = os.fstat(file_fd)
            finally:
                os.close(file_fd)
            if identity(before) != identity(after):
                raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Compose source changed while it was being pinned.")
            data = b"".join(chunks)
            if len(data) != before.st_size or len(data) > MAX_COMPOSE_FILE_BYTES:
                raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Compose source size changed while it was being pinned.")
            total += len(data)
            if total > MAX_COMPOSE_TOTAL_BYTES:
                raise PinningError("COMPOSE_INPUT_UNSAFE", "Compose inputs exceed the aggregate size limit.")

            name = f"input-{index:03d}.yaml"
            snapshot = pin_dir / name
            out_fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.fchmod(out_fd, 0o600)
                view = memoryview(data)
                while view:
                    written = os.write(out_fd, view)
                    view = view[written:]
                os.fsync(out_fd)
                snapshot_info = os.fstat(out_fd)
            finally:
                os.close(out_fd)
            snapshot_rel = snapshot.relative_to(workspace).as_posix()
            snapshot_paths.append(snapshot.as_posix())
            entries.append({
                "order": index,
                "logical_source": relative.as_posix(),
                "source_identity": identity(before),
                "snapshot": snapshot_rel,
                "snapshot_identity": identity(snapshot_info),
                "sha256": sha256_bytes(data),
                "size": len(data),
            })

        manifest = {
            "schema_version": PIN_SCHEMA_VERSION,
            "case_id": case_id,
            "file_count": len(entries),
            "files": entries,
        }
        manifest_data = canonical_json_bytes(manifest)
        manifest_path = pin_dir / "manifest.json"
        manifest_fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchmod(manifest_fd, 0o600)
            view = memoryview(manifest_data)
            while view:
                written = os.write(manifest_fd, view)
                view = view[written:]
            os.fsync(manifest_fd)
        finally:
            os.close(manifest_fd)
        return {
            "ok": True,
            "status": "pinned",
            "pin_id": pin_id,
            "manifest": manifest_path.as_posix(),
            "manifest_sha256": sha256_bytes(manifest_data),
            "compose_files": snapshot_paths,
            "file_count": len(entries),
        }
    except Exception:
        cleanup_pin_dir(pin_dir)
        raise


def resolve_manifest(workspace: Path, raw_value: str) -> tuple[Path, Path]:
    relative = safe_relative(raw_value, workspace)
    if len(relative.parts) != 4 or relative.parts[:2] != ("runtime", "compose-inputs") or relative.parts[3] != "manifest.json" or not PIN_ID_RE.fullmatch(relative.parts[2]):
        raise PinningError("COMPOSE_INPUT_UNSAFE", "Compose manifest must name one allocated pin directory.")
    pin_dir = workspace.joinpath(*relative.parts[:-1])
    root = pin_root(workspace, create=False)
    ensure_real_private_dir(pin_dir, create=False)
    if pin_dir.parent != root:
        raise PinningError("COMPOSE_INPUT_UNSAFE", "Compose manifest escaped the pin storage root.")
    return workspace / Path(*relative.parts), pin_dir


def read_manifest(workspace: Path, raw_value: str, expected_sha256: str) -> tuple[dict[str, Any], Path, bytes]:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise PinningError("COMPOSE_INPUT_UNSAFE", "An exact lowercase manifest SHA-256 is required.")
    path, pin_dir = resolve_manifest(workspace, raw_value)
    try:
        data, info = read_stable_workspace_file(workspace, safe_relative(path.as_posix(), workspace))
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose manifest identity is unsafe.")
    except OSError as exc:
        raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose manifest is missing or unreadable.") from exc
    if sha256_bytes(data) != expected_sha256:
        raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose manifest digest changed.")
    try:
        manifest = json.loads(data)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose manifest is invalid.") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != PIN_SCHEMA_VERSION or canonical_json_bytes(manifest) != data:
        raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose manifest is not canonical schema version 1.")
    return manifest, pin_dir, data


def verify_compose_inputs(workspace: Path, manifest_value: str, expected_sha256: str, supplied_files: list[str] | None = None) -> dict[str, Any]:
    manifest, pin_dir, _ = read_manifest(workspace, manifest_value, expected_sha256)
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries or len(entries) != manifest.get("file_count") or len(entries) > MAX_COMPOSE_FILES:
        raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose manifest file ordering is invalid.")
    verified: list[str] = []
    logical_sources: list[str] = []
    total = 0
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict) or entry.get("order") != index:
            raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose manifest ordering changed.")
        expected_rel = f"runtime/compose-inputs/{pin_dir.name}/input-{index:03d}.yaml"
        if entry.get("snapshot") != expected_rel or not isinstance(entry.get("logical_source"), str):
            raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose snapshot reference changed.")
        snapshot = workspace / expected_rel
        try:
            data, info = read_stable_workspace_file(workspace, PurePosixPath(expected_rel))
            if stat.S_IMODE(info.st_mode) != 0o600:
                raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose snapshot identity is unsafe.")
        except OSError as exc:
            raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose snapshot is missing or unreadable.") from exc
        if identity(info) != entry.get("snapshot_identity") or len(data) != entry.get("size") or sha256_bytes(data) != entry.get("sha256"):
            raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose snapshot identity or content changed.")
        total += len(data)
        if total > MAX_COMPOSE_TOTAL_BYTES:
            raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose input size exceeds its boundary.")
        verified.append(snapshot.as_posix())
        logical_sources.append(entry["logical_source"])
    if supplied_files is not None:
        supplied = [Path(value).expanduser().resolve(strict=False).as_posix() for value in supplied_files]
        if supplied != verified:
            raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Compose file order or identity differs from the pinned manifest.")
    return {
        "ok": True,
        "status": "verified",
        "manifest_sha256": expected_sha256,
        "compose_files": verified,
        "logical_sources": logical_sources,
        "file_count": len(verified),
    }


def cleanup_compose_inputs(workspace: Path, manifest_value: str, expected_sha256: str) -> dict[str, Any]:
    manifest, pin_dir, _ = read_manifest(workspace, manifest_value, expected_sha256)
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose cleanup manifest is invalid.")
    expected_names = {"manifest.json"}
    for index, entry in enumerate(entries, start=1):
        expected_rel = f"runtime/compose-inputs/{pin_dir.name}/input-{index:03d}.yaml"
        if not isinstance(entry, dict) or entry.get("order") != index or entry.get("snapshot") != expected_rel:
            raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose cleanup manifest ordering changed.")
        expected_names.add(f"input-{index:03d}.yaml")
    actual_names = {child.name for child in pin_dir.iterdir()}
    if actual_names != expected_names:
        raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose directory contains unexpected entries; refusing cleanup.")
    for name in sorted(expected_names):
        child = pin_dir / name
        info = os.lstat(child)
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise PinningError("COMPOSE_INPUT_IDENTITY_DRIFT", "Pinned Compose cleanup encountered an unsafe entry.")
    for name in sorted(expected_names):
        (pin_dir / name).unlink()
    pin_dir.rmdir()
    return {"ok": True, "status": "cleaned", "pin_id": pin_dir.name}


def finding(*, label: str, pattern: str, source_type: str, source: str, reason: str, issue_code: str = "", line: int | None = None, excerpt: str = "") -> dict[str, Any]:
    item: dict[str, Any] = {"label": label, "pattern": pattern, "source_type": source_type, "source": source, "reason": reason}
    if issue_code:
        item["issue_code"] = issue_code
    if line is not None:
        item["line"] = line
    if excerpt:
        item["excerpt"] = excerpt[:120]
    return item


def add_unique(findings: list[dict[str, Any]], item: dict[str, Any]) -> None:
    key = tuple(item.get(name) for name in ("issue_code", "label", "pattern", "source_type", "source", "line", "excerpt"))
    if all(tuple(old.get(name) for name in ("issue_code", "label", "pattern", "source_type", "source", "line", "excerpt")) != key for old in findings):
        findings.append(item)


def scan_text(text: str, *, source: str, source_type: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for label, pattern_name, pattern, reason in LINE_RULES + SHELL_FLAG_RULES:
            if pattern.search(raw):
                add_unique(findings, finding(label=label, pattern=pattern_name, source_type=source_type, source=source, line=line_no, excerpt=line, reason=reason))
    return findings


def _compose_finding(pattern: str, source: str, reason: str, *, issue_code: str = "COMPOSE_FIELD_UNSUPPORTED", excerpt: str = "") -> dict[str, Any]:
    return finding(label="dangerous_docker_config", pattern=pattern, source_type="compose_file", source=source, excerpt=excerpt, reason=reason, issue_code=issue_code)


def has_dynamic_value(value: Any) -> bool:
    if isinstance(value, str):
        return "${" in value
    if isinstance(value, list):
        return any(has_dynamic_value(item) for item in value)
    if isinstance(value, dict):
        return any(has_dynamic_value(key) or has_dynamic_value(item) for key, item in value.items())
    return False


def stable_directory_identity(info: os.stat_result) -> dict[str, int]:
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "file_type": int(stat.S_IFMT(info.st_mode)),
        "mode": int(stat.S_IMODE(info.st_mode)),
        "uid": int(info.st_uid),
        "gid": int(info.st_gid),
    }


def directory_identity(components: list[os.stat_result], *, present: bool) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": BIND_IDENTITY_SCHEMA_VERSION,
        "present": present,
        "stable": {
            "components": [stable_directory_identity(info) for info in components],
        },
    }
    if present:
        leaf = components[-1]
        value["observation"] = {
            "mtime_ns": int(leaf.st_mtime_ns),
            "nlink": int(leaf.st_nlink),
        }
    return value


def validate_bind_identity_value(value: Any) -> None:
    if not isinstance(value, dict) or value.get("schema_version") != BIND_IDENTITY_SCHEMA_VERSION or not isinstance(value.get("present"), bool):
        raise PinningError("COMPOSE_BIND_SOURCE_FORBIDDEN", "Repeated Compose bind identity input uses an unsupported schema.")
    expected_fields = {"schema_version", "present", "stable", "observation"} if value["present"] else {"schema_version", "present", "stable"}
    if set(value) != expected_fields:
        raise PinningError("COMPOSE_BIND_SOURCE_FORBIDDEN", "Repeated Compose bind identity input is invalid.")
    stable = value.get("stable")
    if not isinstance(stable, dict) or set(stable) != {"components"} or not isinstance(stable.get("components"), list) or not stable["components"]:
        raise PinningError("COMPOSE_BIND_SOURCE_FORBIDDEN", "Repeated Compose bind stable identity is invalid.")
    stable_fields = {"device", "inode", "file_type", "mode", "uid", "gid"}
    for component in stable["components"]:
        if not isinstance(component, dict) or set(component) != stable_fields:
            raise PinningError("COMPOSE_BIND_SOURCE_FORBIDDEN", "Repeated Compose bind stable identity is invalid.")
        if any(not isinstance(item, int) or isinstance(item, bool) for item in component.values()):
            raise PinningError("COMPOSE_BIND_SOURCE_FORBIDDEN", "Repeated Compose bind identity values must be integers.")
        if component["file_type"] != stat.S_IFDIR or component["mode"] < 0 or component["mode"] > 0o7777:
            raise PinningError("COMPOSE_BIND_SOURCE_FORBIDDEN", "Repeated Compose bind identity does not describe real directories.")
        if any(component[field] < 0 for field in ("device", "inode", "uid", "gid")):
            raise PinningError("COMPOSE_BIND_SOURCE_FORBIDDEN", "Repeated Compose bind identity contains an invalid stable value.")
    if value["present"] is False:
        return
    observation = value.get("observation")
    if not isinstance(observation, dict) or set(observation) != {"mtime_ns", "nlink"}:
        raise PinningError("COMPOSE_BIND_SOURCE_FORBIDDEN", "Repeated Compose bind observation is invalid.")
    if any(not isinstance(item, int) or isinstance(item, bool) for item in observation.values()):
        raise PinningError("COMPOSE_BIND_SOURCE_FORBIDDEN", "Repeated Compose bind identity values must be integers.")
    if observation["nlink"] < 1:
        raise PinningError("COMPOSE_BIND_SOURCE_FORBIDDEN", "Repeated Compose bind observation is invalid.")


def bind_identity_matches(expected: dict[str, Any], current: dict[str, Any], target: str) -> bool:
    validate_bind_identity_value(expected)
    validate_bind_identity_value(current)
    if expected["present"] != current["present"]:
        return False
    if expected["stable"] != current["stable"]:
        return False
    if expected["present"] is False:
        return True
    # A writable output bind may legitimately gain children. mtime/nlink are
    # observations, not directory-object identity, for that one mapping.
    return target == "/workspace/output" or expected["observation"] == current["observation"]


def bind_identity_maps_match(expected: dict[str, Any], current: dict[str, Any]) -> bool:
    if set(expected) != set(current):
        return False
    return all(bind_identity_matches(expected[target], current[target], target) for target in sorted(current))


def require_real_directory(
    path: Path,
    *,
    allow_missing_suffix: bool,
    issue_code: str = "COMPOSE_BIND_SOURCE_FORBIDDEN",
) -> dict[str, Any]:
    """Check a logical host directory without resolving any path component.

    A missing suffix is tolerated because the wrapper may create the case output
    after read-only preflight. Every component that already exists is still
    checked with lstat, and a symlink is never followed.
    """
    if not path.is_absolute() or not path.anchor:
        raise PinningError(issue_code, "Allowed host bind sources must be absolute logical paths.")
    current = Path(path.anchor)
    components: list[os.stat_result] = []
    try:
        root_info = os.lstat(current)
    except OSError as exc:
        raise PinningError(issue_code, "Allowed host bind source has an unsafe directory ancestor.") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise PinningError(issue_code, "Allowed host bind source has an unsafe directory ancestor.")
    components.append(root_info)

    for part in path.parts[1:]:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if allow_missing_suffix:
                return directory_identity(components, present=False)
            raise PinningError(issue_code, "Allowed host bind source must be an existing real directory.")
        except OSError as exc:
            raise PinningError(issue_code, "Allowed host bind source cannot be inspected safely.") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise PinningError(issue_code, "Allowed host bind source must contain real directories only.")
        components.append(info)
    return directory_identity(components, present=True)


def logical_bind_source(source_value: str, *, workspace: Path, explicit_bind: bool) -> tuple[Path | None, str | None, str | None]:
    """Map a Compose source lexically to the fixed project directory.

    This deliberately does not call resolve(). Compose source identity is
    checked before filesystem resolution so a symlink cannot turn an allowed
    logical name into an arbitrary host directory.
    """
    if not source_value:
        return None, "COMPOSE_VOLUME_UNSUPPORTED", "Compose bind source must be a static path."
    if "${" in source_value:
        return None, "COMPOSE_FIELD_UNSUPPORTED", "Compose bind source and target must be static paths."
    if "\\" in source_value:
        return None, "COMPOSE_BIND_SOURCE_FORBIDDEN", "Compose bind source uses an unsupported path separator."
    if source_value.startswith("~") or "://" in source_value or "//" in source_value:
        return None, "COMPOSE_BIND_SOURCE_FORBIDDEN", "Compose bind source uses an unsupported path alias."

    raw_source = Path(source_value)
    if not explicit_bind and not raw_source.is_absolute() and source_value not in {".", ".."} and not source_value.startswith(("./", "../")):
        return None, "COMPOSE_VOLUME_UNSUPPORTED", "Named and anonymous Compose volumes are outside the closed subset."
    if any(part == ".." for part in raw_source.parts):
        return None, "COMPOSE_BIND_SOURCE_FORBIDDEN", "Compose bind source must not contain parent path components."

    if raw_source.is_absolute():
        return raw_source, None, None
    return workspace.joinpath(*raw_source.parts), None, None


def compose_roots(workspace: Path) -> tuple[Path, Path, Path]:
    try:
        config_path = workspace / "asr-config.json"
        config_info = os.lstat(config_path)
        if stat.S_ISLNK(config_info.st_mode) or not stat.S_ISREG(config_info.st_mode) or config_info.st_nlink != 1:
            raise PinningError("COMPOSE_INPUT_UNSAFE", "Workspace configuration must be a real regular file.")
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PinningError("COMPOSE_INPUT_UNSAFE", "Workspace configuration is not readable JSON.") from exc
    require_real_directory(workspace, allow_missing_suffix=False, issue_code="COMPOSE_INPUT_UNSAFE")
    target = workspace.parent
    require_real_directory(target, allow_missing_suffix=False, issue_code="COMPOSE_BIND_SOURCE_FORBIDDEN")
    root_name = config.get("project_root_name")
    if root_name is not None and root_name != target.name:
        raise PinningError("COMPOSE_INPUT_UNSAFE", "Workspace target identity does not match its configuration.")
    return target, workspace / "poc", workspace / "evidence"


def classify_bind(
    source_value: str,
    target_value: str,
    read_only: bool,
    *,
    workspace: Path,
    case_id: str,
    explicit_bind: bool,
    bind_identities: dict[str, Any] | None = None,
) -> tuple[bool, str, str]:
    if not target_value or "${" in target_value or "\\" in target_value:
        return False, "COMPOSE_VOLUME_UNSUPPORTED", "Compose bind source and target must be static paths."
    source, path_issue_code, path_reason = logical_bind_source(source_value, workspace=workspace, explicit_bind=explicit_bind)
    if source is None:
        return False, path_issue_code or "COMPOSE_BIND_SOURCE_FORBIDDEN", path_reason or "Compose bind source is outside the closed subset."
    target_repo, poc_dir, evidence_root = compose_roots(workspace)
    output_dir = evidence_root / case_id / "container-output"
    allowed: tuple[tuple[Path, str, bool], ...] = (
        (target_repo, "/workspace/target", True),
        (poc_dir, "/workspace/poc", True),
        (output_dir, "/workspace/output", False),
    )
    for allowed_source, allowed_target, must_be_ro in allowed:
        if source == allowed_source and target_value == allowed_target and (not must_be_ro or read_only):
            try:
                identity_value = require_real_directory(
                    source,
                    allow_missing_suffix=source == output_dir,
                    issue_code="COMPOSE_BIND_SOURCE_FORBIDDEN",
                )
            except PinningError as exc:
                return False, exc.code, str(exc)
            if bind_identities is not None:
                previous = bind_identities.get(allowed_target)
                if previous is not None and not bind_identity_matches(previous, identity_value, allowed_target):
                    return False, "COMPOSE_BIND_SOURCE_FORBIDDEN", "Allowed Compose bind directory identity changed during inspection."
                bind_identities[allowed_target] = identity_value
            return True, "", ""
    return False, "COMPOSE_BIND_SOURCE_FORBIDDEN", "Compose bind must match one fixed target-repo, PoC, or case-output mapping."


def scan_compose_bytes(
    data: bytes,
    *,
    logical_source: str,
    workspace: Path,
    case_id: str,
    bind_identities: dict[str, Any] | None = None,
    declared_services: set[str] | None = None,
) -> list[dict[str, Any]]:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError:
        return [_compose_finding("compose_yaml_unverifiable", logical_source, "Compose input is not UTF-8 YAML.", issue_code="COMPOSE_INPUT_UNSAFE")]
    findings = scan_text(text, source=logical_source, source_type="compose_file")
    if yaml is None:
        findings.append(_compose_finding("compose_yaml_unverifiable", logical_source, "A YAML parser is required to prove Compose boundaries.", issue_code="COMPOSE_INPUT_UNSAFE"))
        return findings
    try:
        tokens = list(yaml.scan(text))
    except Exception:
        findings.append(_compose_finding("compose_yaml_unverifiable", logical_source, "Compose YAML must parse without duplicate keys.", issue_code="COMPOSE_INPUT_UNSAFE"))
        return findings
    if any(isinstance(token, YAML_DYNAMIC_TOKEN_TYPES) for token in tokens):
        findings.append(_compose_finding("compose_yaml_anchor_or_alias", logical_source, "Compose anchors, aliases, and merges are outside the closed subset.", issue_code="COMPOSE_FIELD_UNSUPPORTED"))
    try:
        document = yaml.load(text, Loader=NoDuplicateSafeLoader)
    except Exception:
        findings.append(_compose_finding("compose_yaml_unverifiable", logical_source, "Compose YAML must parse without duplicate keys.", issue_code="COMPOSE_INPUT_UNSAFE"))
        return findings
    if has_dynamic_value(document):
        findings.append(_compose_finding("compose_dynamic_value", logical_source, "Compose interpolation is outside the closed subset.", issue_code="COMPOSE_FIELD_UNSUPPORTED"))
    if not isinstance(document, dict) or not isinstance(document.get("services"), dict) or not document["services"]:
        findings.append(_compose_finding("compose_services_unverifiable", logical_source, "Compose services must be a non-empty static mapping.", issue_code="COMPOSE_INPUT_UNSAFE"))
        return findings
    if declared_services is not None:
        declared_services.update(name for name in document["services"] if isinstance(name, str))
    for key in document:
        if key not in TOP_LEVEL_FIELDS:
            if key == "volumes":
                issue_code = "COMPOSE_VOLUME_UNSUPPORTED"
            elif key in HOST_FILE_FIELDS:
                issue_code = "COMPOSE_HOST_FILE_UNSUPPORTED"
            else:
                issue_code = "COMPOSE_FIELD_UNSUPPORTED"
            findings.append(_compose_finding("compose_top_level_unsupported", logical_source, f"Top-level Compose field {key!r} is outside the closed subset.", issue_code=issue_code))
    if "version" in document and not isinstance(document["version"], (str, int, float)):
        findings.append(_compose_finding("compose_version_unverifiable", logical_source, "Compose version must be a static scalar.", issue_code="COMPOSE_FIELD_UNSUPPORTED"))

    for service_name, service in document["services"].items():
        service_label = str(service_name)
        if not isinstance(service_name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", service_name) or not isinstance(service, dict):
            findings.append(_compose_finding("compose_service_unverifiable", logical_source, "Every Compose service must have a static safe name and mapping.", issue_code="COMPOSE_INPUT_UNSAFE"))
            continue
        if service.get("privileged") is not False:
            findings.append(_compose_finding("privileged_not_static_false", logical_source, "Every Compose service must declare literal privileged: false.", issue_code="COMPOSE_CAPABILITY_UNSUPPORTED", excerpt=service_label))
        for field in service:
            if field in NAMESPACE_FIELDS:
                findings.append(_compose_finding(f"compose_{field}_unsafe", logical_source, f"Compose namespace field {field!r} is not permitted.", issue_code="COMPOSE_NAMESPACE_UNSUPPORTED", excerpt=service_label))
            elif field in CAPABILITY_FIELDS:
                findings.append(_compose_finding(f"compose_{field}_unsafe", logical_source, f"Compose capability/device field {field!r} is not permitted.", issue_code="COMPOSE_CAPABILITY_UNSUPPORTED", excerpt=service_label))
            elif field in HOST_FILE_FIELDS:
                findings.append(_compose_finding(f"compose_{field}_unsupported", logical_source, f"Compose host-file or expansion field {field!r} is not permitted.", issue_code="COMPOSE_HOST_FILE_UNSUPPORTED", excerpt=service_label))
            elif field not in SERVICE_FIELDS:
                findings.append(_compose_finding("compose_service_field_unsupported", logical_source, f"Compose service field {field!r} is outside the closed subset.", issue_code="COMPOSE_FIELD_UNSUPPORTED", excerpt=service_label))
        if "read_only" in service and service["read_only"] is not True:
            findings.append(_compose_finding("compose_read_only_not_true", logical_source, "If declared, service read_only must be literal true.", issue_code="COMPOSE_FIELD_UNSUPPORTED", excerpt=service_label))
        if "cap_drop" in service and service["cap_drop"] != ["ALL"]:
            findings.append(_compose_finding("compose_cap_drop_unverifiable", logical_source, "cap_drop, when used, must be exactly [ALL].", issue_code="COMPOSE_CAPABILITY_UNSUPPORTED", excerpt=service_label))
        if "depends_on" in service:
            findings.append(_compose_finding(
                "compose_dependency_unsupported",
                logical_source,
                "Compose service dependencies are outside the single-service execution contract.",
                issue_code="COMPOSE_DEPENDENCY_UNSUPPORTED",
                excerpt=service_label,
            ))
        if "restart" in service and (not isinstance(service["restart"], str) or service["restart"] != "no"):
            findings.append(_compose_finding(
                "compose_restart_policy_unsafe",
                logical_source,
                "Compose restart must be absent or the exact string 'no'.",
                issue_code="COMPOSE_RESTART_POLICY_UNSAFE",
                excerpt=service_label,
            ))
        if "labels" in service:
            labels = service["labels"]
            label_names: list[str] = []
            if isinstance(labels, dict) and all(isinstance(key, str) for key in labels):
                label_names = list(labels)
            elif isinstance(labels, list) and all(isinstance(item, str) and "=" in item for item in labels):
                label_names = [item.split("=", 1)[0] for item in labels]
            else:
                findings.append(_compose_finding(
                    "compose_labels_unverifiable",
                    logical_source,
                    "Compose labels must be a static mapping or key=value list.",
                    issue_code="COMPOSE_RESERVED_LABEL_FORBIDDEN",
                    excerpt=service_label,
                ))
            if any(name.startswith(("org.zhulong.", "com.docker.compose.")) for name in label_names):
                findings.append(_compose_finding(
                    "compose_reserved_label_forbidden",
                    logical_source,
                    "Target-defined Compose labels must not claim Zhulong or Compose lifecycle ownership.",
                    issue_code="COMPOSE_RESERVED_LABEL_FORBIDDEN",
                    excerpt=service_label,
                ))

        volumes = service.get("volumes", [])
        if not isinstance(volumes, list):
            findings.append(_compose_finding("compose_volumes_unverifiable", logical_source, "Compose volumes must be a static list.", issue_code="COMPOSE_VOLUME_UNSUPPORTED", excerpt=service_label))
            continue
        for volume in volumes:
            source_value = target_value = ""
            read_only = False
            explicit_bind = False
            if isinstance(volume, str):
                parts = volume.split(":")
                if len(parts) not in {2, 3} or (len(parts) == 3 and parts[2] != "ro"):
                    findings.append(_compose_finding("compose_volume_unverifiable", logical_source, "Short Compose volumes must be static bind mappings with optional ro.", issue_code="COMPOSE_VOLUME_UNSUPPORTED", excerpt=service_label))
                    continue
                source_value, target_value = parts[:2]
                read_only = len(parts) == 3
            elif isinstance(volume, dict):
                if set(volume) - {"type", "source", "target", "read_only"} or volume.get("type") != "bind" or not isinstance(volume.get("source"), str) or not isinstance(volume.get("target"), str) or not isinstance(volume.get("read_only"), bool):
                    findings.append(_compose_finding("compose_volume_unverifiable", logical_source, "Long Compose volumes must use only type=bind, source, target, and literal read_only.", issue_code="COMPOSE_VOLUME_UNSUPPORTED", excerpt=service_label))
                    continue
                source_value = volume["source"]
                target_value = volume["target"]
                read_only = volume["read_only"]
                explicit_bind = True
            else:
                findings.append(_compose_finding("compose_volume_unverifiable", logical_source, "Compose volume entries must be static bind mappings.", issue_code="COMPOSE_VOLUME_UNSUPPORTED", excerpt=service_label))
                continue
            allowed, issue_code, reason = classify_bind(
                source_value,
                target_value,
                read_only,
                workspace=workspace,
                case_id=case_id,
                explicit_bind=explicit_bind,
                bind_identities=bind_identities,
            )
            if not allowed:
                findings.append(_compose_finding("compose_bind_forbidden", logical_source, reason, issue_code=issue_code, excerpt=service_label))
    return findings


def parse_expected_bind_identities(value: str) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        parsed = json.loads(value)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PinningError("COMPOSE_BIND_SOURCE_FORBIDDEN", "Repeated Compose bind identity input is invalid.") from exc
    if not isinstance(parsed, dict):
        raise PinningError("COMPOSE_BIND_SOURCE_FORBIDDEN", "Repeated Compose bind identity input is invalid.")
    allowed_targets = {"/workspace/target", "/workspace/poc", "/workspace/output"}
    if any(not isinstance(target, str) or target not in allowed_targets for target in parsed):
        raise PinningError("COMPOSE_BIND_SOURCE_FORBIDDEN", "Repeated Compose bind identity target is invalid.")
    for identity_value in parsed.values():
        validate_bind_identity_value(identity_value)
    return parsed


def inspect_pinned_compose(
    workspace: Path,
    manifest_value: str,
    expected_sha256: str,
    supplied_files: list[str] | None,
    *,
    case_id: str,
    compose_service: str = "",
    expected_bind_identities: dict[str, Any] | None = None,
) -> dict[str, Any]:
    verified = verify_compose_inputs(workspace, manifest_value, expected_sha256, supplied_files)
    bind_identities: dict[str, Any] = {}
    declared_services: set[str] = set()
    findings: list[dict[str, Any]] = []
    for path_value, logical_source in zip(verified["compose_files"], verified["logical_sources"]):
        data, _ = read_stable_workspace_file(workspace, safe_relative(path_value, workspace))
        findings.extend(
            scan_compose_bytes(
                data,
                logical_source=logical_source,
                workspace=workspace,
                case_id=case_id,
                bind_identities=bind_identities,
                declared_services=declared_services,
            )
        )
    verify_compose_inputs(workspace, manifest_value, expected_sha256, supplied_files)
    if findings:
        first = findings[0]
        raise PinningError(
            str(first.get("issue_code") or "COMPOSE_INPUT_UNSAFE"),
            "Pinned Compose input failed the closed host-bind or capability policy.",
        )
    if compose_service and compose_service not in declared_services:
        raise PinningError("COMPOSE_SERVICE_MISSING", "Selected Compose service is absent from the pinned input set.")
    if expected_bind_identities is not None and not bind_identity_maps_match(expected_bind_identities, bind_identities):
        raise PinningError("COMPOSE_BIND_SOURCE_FORBIDDEN", "Allowed Compose bind directory identity changed during revalidation.")
    verified["bind_identities"] = bind_identities
    return verified


def validate_default_mount_directories(workspace: Path, case_id: str) -> list[dict[str, Any]]:
    _target_repo, poc_dir, evidence_root = compose_roots(workspace)
    findings: list[dict[str, Any]] = []
    for path, label, allow_missing_suffix in (
        (poc_dir, "docker-run-poc", False),
        (evidence_root / case_id / "container-output", "docker-run-output", True),
    ):
        try:
            require_real_directory(path, allow_missing_suffix=allow_missing_suffix, issue_code="COMPOSE_BIND_SOURCE_FORBIDDEN")
        except PinningError as exc:
            findings.append(_compose_finding("default_mount_directory_unsafe", label, str(exc), issue_code=exc.code))
    return findings


def token_contains_docker_socket(token: str) -> bool:
    return "/var/run/docker.sock" in token


def scan_docker_tokens(tokens: list[str], *, source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    boundary_options = {
        "--privileged": "docker_run_privileged", "--cap-add": "docker_run_cap_add", "--device": "docker_run_device",
        "--device-cgroup-rule": "docker_run_device_cgroup_rule", "--security-opt": "docker_run_security_opt",
        "--userns": "docker_run_userns", "--ipc": "docker_run_ipc", "--pid": "docker_run_pid", "--uts": "docker_run_uts",
        "--cgroupns": "docker_run_cgroupns", "--mount": "docker_run_mount", "--volume": "docker_run_volume", "-v": "docker_run_volume",
        "--network": "docker_run_network_override", "--net": "docker_run_network_override", "--publish": "docker_run_publish", "-p": "docker_run_publish",
    }
    policy_value_options = {"--memory", "-m", "--memory-swap", "--memory-reservation", "--cpus", "--cpu-shares", "--cpu-quota", "--cpu-period", "--pids-limit", "--shm-size", "--ulimit"}
    policy_flags = {"--read-only"}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        option = token.split("=", 1)[0]
        matched = next((name for name in boundary_options if option == name or (name in {"-v", "-p"} and token.startswith(name) and token != name)), None)
        if matched is not None:
            needs_value = matched != "--privileged"
            if "=" not in token and token == matched and needs_value:
                if index + 1 < len(tokens):
                    index += 1
                else:
                    add_unique(findings, finding(label="dangerous_shell_flag", pattern="docker_run_arg_missing_value", source_type="docker_run_args", source=source, reason="Docker boundary option is missing its value."))
            add_unique(findings, finding(label="dangerous_shell_flag", pattern=boundary_options[matched], source_type="docker_run_args", source=source, reason="Extra Docker arguments must not alter isolation or host exposure.", issue_code="DOCKER_RESOURCE_OVERRIDE_FORBIDDEN"))
        elif option in policy_value_options:
            if "=" not in token:
                if index + 1 >= len(tokens) or tokens[index + 1].startswith("-"):
                    add_unique(findings, finding(label="dangerous_shell_flag", pattern="docker_run_arg_missing_value", source_type="docker_run_args", source=source, reason="Host policy option is missing its value.", issue_code="DOCKER_RESOURCE_OVERRIDE_FORBIDDEN"))
                else:
                    index += 1
            add_unique(findings, finding(label="dangerous_shell_flag", pattern="docker_resource_override_forbidden", source_type="docker_run_args", source=source, reason="Extra Docker arguments must not override the host resource policy.", issue_code="DOCKER_RESOURCE_OVERRIDE_FORBIDDEN"))
        elif option in policy_flags:
            add_unique(findings, finding(label="dangerous_shell_flag", pattern="docker_resource_override_forbidden", source_type="docker_run_args", source=source, reason="Extra Docker arguments must not override the host resource policy.", issue_code="DOCKER_RESOURCE_OVERRIDE_FORBIDDEN"))
        else:
            add_unique(findings, finding(label="dangerous_shell_flag", pattern="docker_run_arg_unknown", source_type="docker_run_args", source=source, reason="Unknown extra Docker argument is outside the closed wrapper contract.", issue_code="DOCKER_RUN_ARG_UNSUPPORTED"))
        if token_contains_docker_socket(token):
            add_unique(findings, finding(label="credential_exposure_risk", pattern="docker_socket_mount", source_type="docker_run_args", source=source, reason="Docker socket mount exposes host Docker control."))
        index += 1
    return findings


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return "# unreadable file"


def scan_file(path_value: str, *, source_type: str, base: Path | None) -> list[dict[str, Any]]:
    path = Path(path_value).expanduser()
    if not path.is_absolute() and base is not None:
        path = (base / path).resolve()
    source = path.as_posix()
    if not path.exists():
        return [finding(label="prompt_injection_context_risk", pattern="missing_generated_input", source_type=source_type, source=source, reason="Preflight input file is missing.")]
    return scan_text(read_text(path), source=source, source_type=source_type)


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    workspace = require_workspace(args.workspace_dir) if args.workspace_dir else None
    findings: list[dict[str, Any]] = []
    bind_identities: dict[str, Any] = {}
    declared_services: set[str] = set()
    expected_bind_identities = parse_expected_bind_identities(args.expected_bind_identities)
    if args.mode == "docker-compose":
        if workspace is None or not args.case_id or not args.compose_service or not args.compose_manifest or not args.compose_manifest_sha256 or not args.compose_project_directory:
            findings.append(_compose_finding("compose_pin_required", "compose-input", "Compose preflight requires a selected service, pinned manifest, digest, case id, and explicit project directory.", issue_code="COMPOSE_INPUT_UNSAFE"))
        else:
            project = Path(args.compose_project_directory).expanduser().resolve(strict=False)
            if project != workspace:
                findings.append(_compose_finding("compose_project_directory_unsafe", "compose-project-directory", "Compose project directory must equal the canonical audit workspace.", issue_code="COMPOSE_INPUT_UNSAFE"))
            try:
                verified = verify_compose_inputs(workspace, args.compose_manifest, args.compose_manifest_sha256, args.compose_file)
                for path_value, logical_source in zip(verified["compose_files"], verified["logical_sources"]):
                    data, _ = read_stable_workspace_file(workspace, safe_relative(path_value, workspace))
                    findings.extend(
                        scan_compose_bytes(
                            data,
                            logical_source=logical_source,
                            workspace=workspace,
                            case_id=args.case_id,
                            bind_identities=bind_identities,
                            declared_services=declared_services,
                        )
                    )
                verify_compose_inputs(workspace, args.compose_manifest, args.compose_manifest_sha256, args.compose_file)
                if expected_bind_identities is not None and not bind_identity_maps_match(expected_bind_identities, bind_identities):
                    findings.append(_compose_finding(
                        "compose_bind_identity_drift",
                        "compose-bind-source",
                        "Allowed Compose bind directory identity changed during revalidation.",
                        issue_code="COMPOSE_BIND_SOURCE_FORBIDDEN",
                    ))
            except PinningError as exc:
                findings.append(_compose_finding("compose_input_identity_drift", "compose-input", str(exc), issue_code=exc.code))
            if args.compose_service and args.compose_service not in declared_services:
                findings.append(_compose_finding(
                    "compose_service_missing",
                    "compose-input",
                    "Selected Compose service is absent from the pinned input set.",
                    issue_code="COMPOSE_SERVICE_MISSING",
                ))
    elif args.compose_file:
        findings.append(_compose_finding("compose_pin_required", "compose-input", "Raw Compose inputs are not accepted outside pinned docker-compose preflight.", issue_code="COMPOSE_INPUT_UNSAFE"))

    if args.mode == "docker-run" and args.verify_default_mounts:
        if workspace is None or not args.case_id:
            findings.append(_compose_finding("default_mount_directory_unsafe", "docker-run-mounts", "Docker-run default mounts require a workspace and case id.", issue_code="COMPOSE_BIND_SOURCE_FORBIDDEN"))
        else:
            findings.extend(validate_default_mount_directories(workspace, args.case_id))

    for shell_script in args.shell_script:
        findings.extend(scan_file(shell_script, source_type="shell_script", base=workspace))
    for input_file in args.input_file:
        findings.extend(scan_file(input_file, source_type="generated_input", base=workspace))
    for index, snippet in enumerate(args.docker_run_snippet, start=1):
        findings.extend(scan_text(snippet, source=f"docker_run_snippet:{index}", source_type="docker_run_snippet"))
    docker_tokens = list(args.docker_run_arg or [])
    if args.network and (args.network == "host" or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.network)):
        findings.append(finding(label="dangerous_shell_flag", pattern="docker_run_network_unsafe", source_type="docker_run_args", source="network", reason="Wrapper network must be a static non-host Docker network name."))
    if docker_tokens:
        findings.extend(scan_docker_tokens(docker_tokens, source="docker_run_args"))
        findings.extend(scan_text(" ".join(docker_tokens), source="docker_run_args", source_type="docker_run_args"))
    labels = sorted({str(item.get("label")) for item in findings if item.get("label")})
    issue_codes = sorted({str(item.get("issue_code")) for item in findings if item.get("issue_code")})
    ok = not findings
    return {
        "checked_at": utc_now(), "ok": ok, "status": PASSED_STATUS if ok else REJECTED_STATUS,
        "case_id": args.case_id, "mode": args.mode, "findings": findings, "labels": labels,
        "issue_codes": issue_codes, "resume_step": RESUME_OK if ok else RESUME_UNSAFE, "review_only": not ok,
        "bind_identities": bind_identities, "selected_service": args.compose_service,
    }


def write_status(workspace_value: str, payload: dict[str, Any]) -> bool:
    if not workspace_value or not payload.get("ok"):
        return True
    workspace = Path(workspace_value).expanduser()
    if workspace.is_symlink() or not workspace.is_dir():
        return False
    status_path = workspace / "runtime/sandbox-preflight-status.json"
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from evidence_io import SafeEvidenceError, atomic_write_json, ensure_host_directory
        ensure_host_directory(workspace, status_path.parent)
        atomic_write_json(workspace, status_path, payload)
        return True
    except (OSError, SafeEvidenceError):
        return False


def operation_error(operation: str, exc: PinningError) -> int:
    print(json.dumps({"ok": False, "status": "rejected", "operation": operation, "issue_code": exc.code, "reason": str(exc)}, ensure_ascii=False, indent=2, sort_keys=True))
    return 1


def main() -> int:
    args = parse_args()
    operation = args.compose_operation
    if operation != "preflight":
        try:
            workspace = require_workspace(args.workspace_dir)
            if operation == "pin":
                payload = pin_compose_inputs(workspace, args.compose_file, args.case_id)
            elif operation == "verify":
                expected_bind_identities = parse_expected_bind_identities(args.expected_bind_identities)
                if args.case_id:
                    payload = inspect_pinned_compose(
                        workspace,
                        args.compose_manifest,
                        args.compose_manifest_sha256,
                        args.compose_file or None,
                        case_id=args.case_id,
                        compose_service=args.compose_service,
                        expected_bind_identities=expected_bind_identities,
                    )
                else:
                    payload = verify_compose_inputs(workspace, args.compose_manifest, args.compose_manifest_sha256, args.compose_file or None)
            else:
                payload = cleanup_compose_inputs(workspace, args.compose_manifest, args.compose_manifest_sha256)
        except PinningError as exc:
            return operation_error(operation, exc)
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    try:
        payload = build_payload(args)
    except PinningError as exc:
        payload = {
            "checked_at": utc_now(), "ok": False, "status": REJECTED_STATUS, "case_id": args.case_id,
            "mode": args.mode, "findings": [_compose_finding("compose_input_unsafe", "compose-input", str(exc), issue_code=exc.code)],
            "labels": ["dangerous_docker_config"], "issue_codes": [exc.code], "resume_step": RESUME_UNSAFE, "review_only": True,
        }
    if not write_status(args.workspace_dir, payload):
        payload = dict(payload)
        payload["ok"] = False
        payload["status"] = REJECTED_STATUS
        payload["labels"] = sorted(set(payload.get("labels", [])) | {"dangerous_docker_config"})
        payload["issue_codes"] = sorted(set(payload.get("issue_codes", [])) | {"COMPOSE_INPUT_UNSAFE"})
        payload["findings"] = list(payload.get("findings", [])) + [_compose_finding("sandbox_status_publish_failed", "workspace", "Sandbox status could not be published through host-owned safe I/O.", issue_code="COMPOSE_INPUT_UNSAFE")]
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
