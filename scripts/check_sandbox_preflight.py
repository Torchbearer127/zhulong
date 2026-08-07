#!/usr/bin/env python3
# zhulong-tool-contract: sandbox-preflight-v1
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
    from yaml.tokens import AliasToken, AnchorToken
    YAML_DYNAMIC_TOKEN_TYPES: tuple[type, ...] = (AnchorToken, AliasToken)
except Exception:  # pragma: no cover - reported as a fail-closed finding
    yaml = None
    YAML_DYNAMIC_TOKEN_TYPES = ()


REJECTED_STATUS = "rejected_unsafe_sandbox"
PASSED_STATUS = "passed"
RESUME_UNSAFE = (
    "Manually review and rewrite the verification container or script to avoid "
    "privileged mode, host network, host PID, Docker socket mounts, or host-root "
    "mounts. Keep the case as candidate/blocked/unverified until a safe Docker "
    "verification path exists."
)
RESUME_OK = "Sandbox preflight passed; continue with normal Docker verification."


LINE_RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    (
        "dangerous_docker_config",
        "privileged_true",
        re.compile(r"^\s*privileged\s*:\s*(?:true|yes|1)\b", re.I),
        "Compose service enables privileged mode.",
    ),
    (
        "dangerous_docker_config",
        "network_mode_host",
        re.compile(r"^\s*network_mode\s*:\s*['\"]?host['\"]?\s*(?:#.*)?$", re.I),
        "Compose service uses host networking.",
    ),
    (
        "dangerous_docker_config",
        "pid_host",
        re.compile(r"^\s*pid\s*:\s*['\"]?host['\"]?\s*(?:#.*)?$", re.I),
        "Compose service joins the host PID namespace.",
    ),
    (
        "credential_exposure_risk",
        "docker_socket_mount",
        re.compile(r"/var/run/docker\.sock"),
        "Docker socket mount exposes host Docker control.",
    ),
    (
        "dangerous_docker_config",
        "host_root_mount",
        re.compile(r"^\s*-\s*['\"]?/\s*:\s*[^#]+", re.I),
        "Compose volume mounts host root.",
    ),
    (
        "dangerous_docker_config",
        "host_root_mount",
        re.compile(r"^\s*source\s*:\s*['\"]?/\s*['\"]?\s*(?:#.*)?$", re.I),
        "Compose bind mount source is host root.",
    ),
    (
        "dangerous_docker_config",
        "host_root_mount",
        re.compile(r"(?:^|\s)--mount(?:=|\s+)[^\n#]*(?:source|src)=/(?:,|\s|$)", re.I),
        "Docker mount uses host root as bind source.",
    ),
    (
        "dangerous_docker_config",
        "host_root_mount",
        re.compile(r"(?:^|\s)(?:-v|--volume)(?:=|\s+)['\"]?/\s*:", re.I),
        "Docker volume mounts host root.",
    ),
]

SHELL_FLAG_RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    (
        "dangerous_shell_flag",
        "docker_run_privileged",
        re.compile(r"(?:^|\s)--privileged(?:[=\s]|$)", re.I),
        "Docker run command requests privileged mode.",
    ),
    (
        "dangerous_shell_flag",
        "docker_run_network_host",
        re.compile(r"(?:^|\s)--net(?:work)?(?:=|\s+)host(?:\s|$)", re.I),
        "Docker run command requests host networking.",
    ),
    (
        "dangerous_shell_flag",
        "docker_run_pid_host",
        re.compile(r"(?:^|\s)--pid(?:=|\s+)host(?:\s|$)", re.I),
        "Docker run command requests host PID namespace.",
    ),
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Reject unsafe Docker sandbox settings before Zhulong verification "
            "cases reach Docker execution."
        )
    )
    parser.add_argument("--workspace-dir", default="", help="Optional Zhulong audit workspace.")
    parser.add_argument("--case-id", default="", help="Optional verification case id.")
    parser.add_argument("--mode", default="", help="Verification mode, such as docker-run or docker-compose.")
    parser.add_argument("--compose-file", action="append", default=[], help="Compose file to inspect. Repeatable.")
    parser.add_argument("--shell-script", action="append", default=[], help="Shell script to inspect. Repeatable.")
    parser.add_argument("--input-file", action="append", default=[], help="Generated verification input to inspect. Repeatable.")
    parser.add_argument("--docker-run-arg", action="append", default=[], help="One docker-run argv token to inspect. Repeatable.")
    parser.add_argument("--docker-run-snippet", action="append", default=[], help="Docker command snippet text to inspect.")
    parser.add_argument("--network", default="", help="Docker-run network selected by the verification runner.")
    parser.add_argument("--json", action="store_true", help="Accepted for compatibility; output is always JSON.")
    return parser.parse_args()


def finding(
    *,
    label: str,
    pattern: str,
    source_type: str,
    source: str,
    reason: str,
    line: int | None = None,
    excerpt: str = "",
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "label": label,
        "pattern": pattern,
        "source_type": source_type,
        "source": source,
        "reason": reason,
    }
    if line is not None:
        item["line"] = line
    if excerpt:
        item["excerpt"] = excerpt[:240]
    return item


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return f"# unreadable file: {exc}"


def add_unique(findings: list[dict[str, Any]], item: dict[str, Any]) -> None:
    key = (
        item.get("label"),
        item.get("pattern"),
        item.get("source_type"),
        item.get("source"),
        item.get("line"),
        item.get("excerpt"),
    )
    for old in findings:
        old_key = (
            old.get("label"),
            old.get("pattern"),
            old.get("source_type"),
            old.get("source"),
            old.get("line"),
            old.get("excerpt"),
        )
        if old_key == key:
            return
    findings.append(item)


def scan_text(text: str, *, source: str, source_type: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for label, pattern_name, pattern, reason in LINE_RULES + SHELL_FLAG_RULES:
            if pattern.search(raw):
                add_unique(
                    findings,
                    finding(
                        label=label,
                        pattern=pattern_name,
                        source_type=source_type,
                        source=source,
                        line=line_no,
                        excerpt=line,
                        reason=reason,
                    ),
                )
    return findings


def _compose_finding(pattern: str, source: str, reason: str, *, excerpt: str = "") -> dict[str, Any]:
    return finding(
        label="dangerous_docker_config",
        pattern=pattern,
        source_type="compose_file",
        source=source,
        excerpt=excerpt,
        reason=reason,
    )


def _path_overlaps_workspace(source: Path, workspace: Path | None) -> bool:
    if workspace is None:
        return False
    try:
        source_resolved = source.resolve(strict=False)
        workspace_resolved = workspace.resolve(strict=False)
        return (
            source_resolved == workspace_resolved
            or source_resolved in workspace_resolved.parents
            or workspace_resolved in source_resolved.parents
        )
    except OSError:
        return True


def scan_compose_file(path_value: str, *, workspace: Path | None) -> list[dict[str, Any]]:
    path = Path(path_value).expanduser()
    if not path.is_absolute() and workspace is not None:
        path = workspace / path
    source = path.resolve(strict=False).as_posix()
    if not path.is_file() or path.is_symlink():
        return [_compose_finding("compose_file_unsafe", source, "Compose input must be an existing regular non-symlink file.")]
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return [_compose_finding("compose_yaml_unverifiable", source, "Compose input is not readable UTF-8 YAML.")]
    findings = scan_text(text, source=source, source_type="compose_file")
    if yaml is None:
        findings.append(_compose_finding("compose_yaml_unverifiable", source, "A YAML parser is required to prove Compose sandbox boundaries."))
        return findings
    try:
        tokens = list(yaml.scan(text))
        document = yaml.safe_load(text)
    except Exception:
        findings.append(_compose_finding("compose_yaml_unverifiable", source, "Compose YAML could not be parsed safely."))
        return findings
    if any(isinstance(token, YAML_DYNAMIC_TOKEN_TYPES) for token in tokens):
        findings.append(_compose_finding("compose_yaml_anchor_or_alias", source, "Compose anchors and aliases are not accepted for sandbox boundary fields."))
    if not isinstance(document, dict) or not isinstance(document.get("services"), dict) or not document["services"]:
        findings.append(_compose_finding("compose_services_unverifiable", source, "Compose services must be a non-empty static mapping."))
        return findings

    for service_name, service in document["services"].items():
        service_label = str(service_name)
        if not isinstance(service, dict):
            findings.append(_compose_finding("compose_service_unverifiable", source, "Every Compose service must be a static mapping.", excerpt=service_label))
            continue
        if service.get("privileged") is not False:
            findings.append(_compose_finding("privileged_not_static_false", source, "Every Compose service must declare literal privileged: false.", excerpt=service_label))
        for field, host_value in (("network_mode", "host"), ("pid", "host"), ("ipc", "host"), ("uts", "host"), ("cgroup", "host"), ("userns_mode", "host")):
            value = service.get(field)
            if value is None:
                continue
            if not isinstance(value, str) or "${" in value or value.strip().lower() == host_value:
                findings.append(_compose_finding(f"compose_{field}_unsafe", source, f"Compose {field} must not select or dynamically resolve a host boundary.", excerpt=service_label))

        volumes = service.get("volumes", [])
        if volumes is None:
            volumes = []
        if not isinstance(volumes, list):
            findings.append(_compose_finding("compose_volumes_unverifiable", source, "Compose service volumes must be a static list.", excerpt=service_label))
            continue
        for volume in volumes:
            bind_source = ""
            bind_target = ""
            read_only = False
            if isinstance(volume, str):
                parts = volume.split(":")
                if len(parts) >= 2:
                    bind_source, bind_target = parts[0], parts[1]
                    read_only = any(part == "ro" for part in parts[2:])
            elif isinstance(volume, dict):
                if volume.get("type") == "bind" or "source" in volume:
                    bind_source = str(volume.get("source") or "")
                    bind_target = str(volume.get("target") or "")
                    read_only = volume.get("read_only") is True
            else:
                findings.append(_compose_finding("compose_volume_unverifiable", source, "Compose volume entries must be static strings or mappings.", excerpt=service_label))
                continue
            if not bind_source:
                continue
            if "${" in bind_source or "${" in bind_target:
                findings.append(_compose_finding("compose_volume_dynamic", source, "Compose bind mount boundaries must not use variable expansion.", excerpt=service_label))
                continue
            source_path = Path(bind_source).expanduser()
            if not source_path.is_absolute():
                source_path = path.parent / source_path
            if (bind_target == "/workspace/evidence" or _path_overlaps_workspace(source_path, workspace)) and not read_only:
                findings.append(_compose_finding("workspace_bind_writable", source, "Compose must not expose workspace or evidence control paths through a writable bind mount.", excerpt=service_label))
    return findings


def token_contains_docker_socket(token: str) -> bool:
    return "/var/run/docker.sock" in token


def token_is_host_root_volume(token: str) -> bool:
    stripped = token.strip("'\"")
    return stripped.startswith("/:") or stripped.startswith("type=bind,source=/,") or re.search(
        r"(?:^|,)(?:source|src)=/(?:,|$)", stripped
    ) is not None


def option_equals_host(token: str, option: str) -> bool:
    prefix = f"{option}="
    return token.startswith(prefix) and token.split("=", 1)[1].strip("'\"") == "host"


def scan_docker_tokens(tokens: list[str], *, source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    boundary_options = {
        "--privileged": "docker_run_privileged",
        "--cap-add": "docker_run_cap_add",
        "--device": "docker_run_device",
        "--device-cgroup-rule": "docker_run_device_cgroup_rule",
        "--security-opt": "docker_run_security_opt",
        "--userns": "docker_run_userns",
        "--ipc": "docker_run_ipc",
        "--pid": "docker_run_pid",
        "--uts": "docker_run_uts",
        "--cgroupns": "docker_run_cgroupns",
        "--mount": "docker_run_mount",
        "--volume": "docker_run_volume",
        "-v": "docker_run_volume",
        "--network": "docker_run_network_override",
        "--net": "docker_run_network_override",
        "--publish": "docker_run_publish",
        "-p": "docker_run_publish",
    }
    safe_value_options = {
        "--memory", "-m", "--memory-swap", "--memory-reservation", "--cpus",
        "--cpu-shares", "--cpu-quota", "--cpu-period", "--pids-limit", "--shm-size", "--ulimit",
    }
    safe_flags = {"--read-only"}

    index = 0
    while index < len(tokens):
        token = tokens[index]
        option = token.split("=", 1)[0]
        matched_boundary = next((name for name in boundary_options if option == name or (name in {"-v", "-p"} and token.startswith(name) and token != name)), None)
        if matched_boundary is not None:
            excerpt = token
            needs_value = matched_boundary != "--privileged"
            if "=" not in token and token == matched_boundary and needs_value:
                if index + 1 < len(tokens):
                    excerpt = f"{token} {tokens[index + 1]}"
                    index += 1
                else:
                    add_unique(findings, finding(label="dangerous_shell_flag", pattern="docker_run_arg_missing_value", source_type="docker_run_args", source=source, excerpt=token, reason="Docker boundary option is missing its value."))
            add_unique(findings, finding(label="dangerous_shell_flag", pattern=boundary_options[matched_boundary], source_type="docker_run_args", source=source, excerpt=excerpt, reason="Extra Docker arguments must not alter container isolation, devices, mounts, namespaces, security policy, network, or host exposure."))
        elif option in safe_value_options:
            if "=" not in token:
                if index + 1 >= len(tokens) or tokens[index + 1].startswith("-"):
                    add_unique(findings, finding(label="dangerous_shell_flag", pattern="docker_run_arg_missing_value", source_type="docker_run_args", source=source, excerpt=token, reason="Allowed resource option is missing its value."))
                else:
                    index += 1
        elif token not in safe_flags:
            add_unique(findings, finding(label="dangerous_shell_flag", pattern="docker_run_arg_unknown", source_type="docker_run_args", source=source, excerpt=token, reason="Unknown extra Docker arguments are not part of the verification wrapper safe resource allowlist."))
        if token_contains_docker_socket(token):
            add_unique(findings, finding(label="credential_exposure_risk", pattern="docker_socket_mount", source_type="docker_run_args", source=source, excerpt=token, reason="Docker socket mount exposes host Docker control."))
        index += 1
    return findings


def scan_file(path_value: str, *, source_type: str, base: Path | None) -> list[dict[str, Any]]:
    path = Path(path_value).expanduser()
    if not path.is_absolute() and base is not None:
        path = (base / path).resolve()
    source = path.as_posix()
    if not path.exists():
        return [
            finding(
                label="prompt_injection_context_risk",
                pattern="missing_generated_input",
                source_type=source_type,
                source=source,
                reason="Preflight input file is missing; review the generated verification inputs before running Docker.",
            )
        ]
    return scan_text(read_text(path), source=source, source_type=source_type)


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    workspace = Path(args.workspace_dir).expanduser().resolve() if args.workspace_dir else None
    findings: list[dict[str, Any]] = []

    for compose_file in args.compose_file:
        findings.extend(scan_compose_file(compose_file, workspace=workspace))
    for shell_script in args.shell_script:
        findings.extend(scan_file(shell_script, source_type="shell_script", base=workspace))
    for input_file in args.input_file:
        findings.extend(scan_file(input_file, source_type="generated_input", base=workspace))
    for index, snippet in enumerate(args.docker_run_snippet, start=1):
        findings.extend(scan_text(snippet, source=f"docker_run_snippet:{index}", source_type="docker_run_snippet"))

    docker_tokens = list(args.docker_run_arg or [])
    if args.network:
        if args.network == "host" or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.network):
            findings.append(finding(label="dangerous_shell_flag", pattern="docker_run_network_unsafe", source_type="docker_run_args", source="network", excerpt="--network", reason="Wrapper network selection must be a static non-host Docker network name."))
    if docker_tokens:
        findings.extend(scan_docker_tokens(docker_tokens, source="docker_run_args"))
        findings.extend(scan_text(" ".join(docker_tokens), source="docker_run_args", source_type="docker_run_args"))

    labels = sorted({str(item.get("label")) for item in findings if item.get("label")})
    ok = not findings
    payload = {
        "checked_at": utc_now(),
        "ok": ok,
        "status": PASSED_STATUS if ok else REJECTED_STATUS,
        "case_id": args.case_id,
        "mode": args.mode,
        "findings": findings,
        "labels": labels,
        "resume_step": RESUME_OK if ok else RESUME_UNSAFE,
        "review_only": not ok,
    }
    return payload


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


def main() -> int:
    args = parse_args()
    payload = build_payload(args)
    if not write_status(args.workspace_dir, payload):
        payload = dict(payload)
        payload["ok"] = False
        payload["status"] = REJECTED_STATUS
        payload["labels"] = sorted(set(payload.get("labels", [])) | {"dangerous_docker_config"})
        payload["findings"] = list(payload.get("findings", [])) + [
            _compose_finding(
                "sandbox_status_publish_failed",
                str(args.workspace_dir),
                "Sandbox status could not be published through host-owned safe I/O.",
            )
        ]
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
