#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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
    for index, token in enumerate(tokens):
        next_token = tokens[index + 1] if index + 1 < len(tokens) else ""
        if token == "--privileged" or token.startswith("--privileged="):
            add_unique(
                findings,
                finding(
                    label="dangerous_shell_flag",
                    pattern="docker_run_privileged",
                    source_type="docker_run_args",
                    source=source,
                    excerpt=token,
                    reason="Docker run command requests privileged mode.",
                ),
            )
        if token in {"--network", "--net"} and next_token == "host":
            add_unique(
                findings,
                finding(
                    label="dangerous_shell_flag",
                    pattern="docker_run_network_host",
                    source_type="docker_run_args",
                    source=source,
                    excerpt=f"{token} {next_token}",
                    reason="Docker run command requests host networking.",
                ),
            )
        if option_equals_host(token, "--network") or option_equals_host(token, "--net"):
            add_unique(
                findings,
                finding(
                    label="dangerous_shell_flag",
                    pattern="docker_run_network_host",
                    source_type="docker_run_args",
                    source=source,
                    excerpt=token,
                    reason="Docker run command requests host networking.",
                ),
            )
        if token == "--pid" and next_token == "host":
            add_unique(
                findings,
                finding(
                    label="dangerous_shell_flag",
                    pattern="docker_run_pid_host",
                    source_type="docker_run_args",
                    source=source,
                    excerpt=f"{token} {next_token}",
                    reason="Docker run command requests host PID namespace.",
                ),
            )
        if option_equals_host(token, "--pid"):
            add_unique(
                findings,
                finding(
                    label="dangerous_shell_flag",
                    pattern="docker_run_pid_host",
                    source_type="docker_run_args",
                    source=source,
                    excerpt=token,
                    reason="Docker run command requests host PID namespace.",
                ),
            )
        if token in {"-v", "--volume"} and token_is_host_root_volume(next_token):
            add_unique(
                findings,
                finding(
                    label="dangerous_docker_config",
                    pattern="host_root_mount",
                    source_type="docker_run_args",
                    source=source,
                    excerpt=f"{token} {next_token}",
                    reason="Docker volume mounts host root.",
                ),
            )
        if (token.startswith("-v") and token_is_host_root_volume(token[2:])) or (
            token.startswith("--volume=") and token_is_host_root_volume(token.split("=", 1)[1])
        ):
            add_unique(
                findings,
                finding(
                    label="dangerous_docker_config",
                    pattern="host_root_mount",
                    source_type="docker_run_args",
                    source=source,
                    excerpt=token,
                    reason="Docker volume mounts host root.",
                ),
            )
        if token == "--mount" and token_is_host_root_volume(next_token):
            add_unique(
                findings,
                finding(
                    label="dangerous_docker_config",
                    pattern="host_root_mount",
                    source_type="docker_run_args",
                    source=source,
                    excerpt=f"{token} {next_token}",
                    reason="Docker mount uses host root as bind source.",
                ),
            )
        if token.startswith("--mount=") and token_is_host_root_volume(token.split("=", 1)[1]):
            add_unique(
                findings,
                finding(
                    label="dangerous_docker_config",
                    pattern="host_root_mount",
                    source_type="docker_run_args",
                    source=source,
                    excerpt=token,
                    reason="Docker mount uses host root as bind source.",
                ),
            )
        if token_contains_docker_socket(token):
            add_unique(
                findings,
                finding(
                    label="credential_exposure_risk",
                    pattern="docker_socket_mount",
                    source_type="docker_run_args",
                    source=source,
                    excerpt=token,
                    reason="Docker socket mount exposes host Docker control.",
                ),
            )
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
        findings.extend(scan_file(compose_file, source_type="compose_file", base=workspace))
    for shell_script in args.shell_script:
        findings.extend(scan_file(shell_script, source_type="shell_script", base=workspace))
    for input_file in args.input_file:
        findings.extend(scan_file(input_file, source_type="generated_input", base=workspace))
    for index, snippet in enumerate(args.docker_run_snippet, start=1):
        findings.extend(scan_text(snippet, source=f"docker_run_snippet:{index}", source_type="docker_run_snippet"))

    docker_tokens = list(args.docker_run_arg or [])
    if args.network:
        docker_tokens.extend(["--network", args.network])
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


def write_status(workspace_value: str, payload: dict[str, Any]) -> None:
    if not workspace_value:
        return
    workspace = Path(workspace_value).expanduser().resolve()
    if not workspace.exists():
        return
    status_path = workspace / "runtime/sandbox-preflight-status.json"
    status_path.parent.mkdir(parents=True, exist_ok=True)
    status_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    payload = build_payload(args)
    write_status(args.workspace_dir, payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
