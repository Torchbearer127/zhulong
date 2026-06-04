#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET


REQUIRED_FILES = [
    ".claude-plugin/plugin.json",
    ".codex-plugin/plugin.json",
    "README.md",
    "assets/tool-registry.json",
    "assets/confirmed-vuln-report-template.docx",
    "assets/examples/confirmed-findings.example.json",
    "assets/references/false-positive-template.md",
    "assets/references/unverified-lead-template.md",
    "assets/references/final-summary-template.md",
    "assets/references/docker-resource-hygiene.md",
    "assets/references/docker-registry-fallbacks.example.json",
    "assets/references/java-web-audit-playbook.md",
    "assets/references/go-web-audit-playbook.md",
    "assets/references/nodejs-library-audit-playbook.md",
    "assets/references/nodejs-web-audit-playbook.md",
    "assets/references/php-swoole-audit-playbook.md",
    "assets/references/python-library-audit-playbook.md",
    "assets/references/python-web-audit-playbook.md",
    "assets/references/ssrf-checklist.md",
    "assets/references/path-traversal-checklist.md",
    "assets/references/prototype-pollution-checklist.md",
    "scripts/bootstrap_verification_workspace.sh",
    "scripts/asr_start.sh",
    "scripts/prepare_target_repo.sh",
    "scripts/check_docker_gate.sh",
    "scripts/check_omc_runtime.sh",
    "scripts/check_sandbox_preflight.py",
    "scripts/check_security_tooling.sh",
    "scripts/run_initial_probes.sh",
    "scripts/run_verification_case.sh",
    "scripts/manage_docker_resources.py",
    "scripts/render_handoff_summary.py",
    "scripts/assert_finalized_workspace.py",
    "scripts/audit_disposition.py",
    "scripts/blocked_verification.py",
    "scripts/refresh_workspace_helpers.sh",
    "scripts/sync_to_claude_skill.sh",
    "scripts/write_audit_event.py",
    "scripts/validate_workspace_state.py",
    "scripts/plan_security_toolchain.py",
    "scripts/render_confirmed_vuln_docx.py",
    "scripts/scaffold_bilingual_findings.py",
    "scripts/validate_report_bundle.py",
    "scripts/validate_all_report_bundles.py",
    "scripts/finalize_audit_workspace.py",
    "skills/zhulong/SKILL.md",
    "templates/claude-skill/SKILL.md",
]

INSTALLED_SKILL_REQUIRED_FILES = [
    "SKILL.md",
    "README.plugin-package.md",
    "INSTALL.plugin-package.md",
    "assets/tool-registry.json",
    "assets/confirmed-vuln-report-template.docx",
    "assets/references/docker-resource-hygiene.md",
    "assets/references/docker-registry-fallbacks.example.json",
    "assets/references/nodejs-web-audit-playbook.md",
    "assets/references/php-swoole-audit-playbook.md",
    "assets/references/python-library-audit-playbook.md",
    "scripts/asr_start.sh",
    "scripts/bootstrap_verification_workspace.sh",
    "scripts/check_docker_gate.sh",
    "scripts/check_omc_runtime.sh",
    "scripts/check_sandbox_preflight.py",
    "scripts/check_security_tooling.sh",
    "scripts/run_initial_probes.sh",
    "scripts/run_verification_case.sh",
    "scripts/manage_docker_resources.py",
    "scripts/render_confirmed_vuln_docx.py",
    "scripts/validate_report_bundle.py",
    "scripts/validate_all_report_bundles.py",
    "scripts/finalize_audit_workspace.py",
    "scripts/assert_finalized_workspace.py",
    "scripts/audit_disposition.py",
    "scripts/blocked_verification.py",
    "scripts/render_handoff_summary.py",
]


def run(command: list[str], cwd: Path) -> None:
    proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        output = ((proc.stdout or "") + (proc.stderr or "")).strip()
        raise SystemExit(f"FAILED: {' '.join(command)}\n{output}")


def run_capture(command: list[str], cwd: Path) -> str:
    proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if proc.returncode != 0:
        raise SystemExit(f"FAILED: {' '.join(command)}\n{output}")
    return output


def run_capture_with_env(
    command: list[str],
    cwd: Path,
    env: dict[str, str],
    *,
    expected_returncode: int = 0,
) -> str:
    merged_env = {**os.environ, **env}
    proc = subprocess.run(command, cwd=cwd, env=merged_env, capture_output=True, text=True)
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if proc.returncode != expected_returncode:
        raise SystemExit(
            f"FAILED: {' '.join(command)}\n"
            f"Expected exit code {expected_returncode}, got {proc.returncode}\n{output}"
        )
    return output


def docx_text(docx_path: Path) -> list[str]:
    with zipfile.ZipFile(docx_path) as archive:
        xml = archive.read("word/document.xml")
    root = ET.fromstring(xml)
    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    lines: list[str] = []
    for para in root.findall(".//w:p", ns):
        text = "".join(node.text or "" for node in para.findall(".//w:t", ns)).strip()
        if text:
            lines.append(text)
    return lines


def rewrite_docx_paragraphs(docx_path: Path, replacer) -> None:
    from docx import Document

    doc = Document(docx_path)
    for paragraph in list(doc.paragraphs):
        replacement = replacer(paragraph.text.strip())
        if replacement is None:
            element = paragraph._element
            element.getparent().remove(element)
        elif replacement != paragraph.text:
            paragraph.text = replacement
    doc.save(docx_path)




def run_with_env(command: list[str], cwd: Path, env: dict[str, str]) -> None:
    merged_env = {**os.environ, **env}
    proc = subprocess.run(command, cwd=cwd, env=merged_env, capture_output=True, text=True)
    if proc.returncode != 0:
        output = ((proc.stdout or "") + (proc.stderr or "")).strip()
        raise SystemExit(f"FAILED: {' '.join(command)}\n{output}")


def run_expect_fail(command: list[str], cwd: Path, expected: str,
                   extra_env: dict[str, str] | None = None) -> None:
    env = {**os.environ, **extra_env} if extra_env else None
    proc = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if proc.returncode == 0:
        raise SystemExit(f"FAILED: command unexpectedly succeeded: {' '.join(command)}")
    if expected not in output:
        raise SystemExit(
            f"FAILED: command did not fail with expected text: {expected}\n"
            f"Command: {' '.join(command)}\nOutput:\n{output}"
        )


def require_text(path: Path, needle: str, label: str) -> None:
    content = path.read_text(encoding="utf-8")
    if needle not in content:
        raise SystemExit(f"FAILED: missing expected text for {label}: {needle}")


def forbid_text(path: Path, needle: str, label: str) -> None:
    content = path.read_text(encoding="utf-8")
    if needle in content:
        raise SystemExit(f"FAILED: forbidden text for {label}: {needle}")


def require_no_repo_text(plugin_root: Path, needle: str, label: str) -> None:
    checked_suffixes = {".md", ".py", ".sh", ".json"}
    for path in plugin_root.rglob("*"):
        if any(part in {".git", ".omc", "__pycache__"} for part in path.parts):
            continue
        if not path.is_file() or path.suffix not in checked_suffixes:
            continue
        if needle in path.read_text(encoding="utf-8", errors="ignore"):
            raise SystemExit(f"FAILED: forbidden repository text for {label}: {path}: {needle}")


def iter_json_strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        strings: list[str] = []
        for nested in value.values():
            strings.extend(iter_json_strings(nested))
        return strings
    if isinstance(value, list):
        strings = []
        for nested in value:
            strings.extend(iter_json_strings(nested))
        return strings
    return []


def is_empty_manifest_component(value) -> bool:
    if value is None or value is False or value == "":
        return True
    if isinstance(value, (list, dict)) and not value:
        return True
    return False


def require_relative_manifest_path(
    plugin_root: Path,
    manifest: dict,
    field: str,
    *,
    must_be_file: bool = False,
) -> Path:
    value = manifest.get(field)
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"FAILED: Claude plugin manifest missing relative path field: {field}")
    token = value.strip()
    if "://" in token:
        raise SystemExit(f"FAILED: Claude plugin manifest path must be relative, not URL: {field}={token}")
    if Path(token).is_absolute() or token.startswith("~"):
        raise SystemExit(f"FAILED: Claude plugin manifest path must be relative: {field}={token}")
    candidate = (plugin_root / token).resolve()
    try:
        candidate.relative_to(plugin_root.resolve())
    except ValueError as exc:
        raise SystemExit(f"FAILED: Claude plugin manifest path escapes package: {field}={token}") from exc
    if must_be_file and not candidate.is_file():
        raise SystemExit(f"FAILED: Claude plugin manifest file path does not exist: {field}={token}")
    if not must_be_file and not candidate.exists():
        raise SystemExit(f"FAILED: Claude plugin manifest path does not exist: {field}={token}")
    return candidate


def validate_claude_plugin_manifest(plugin_root: Path) -> None:
    manifest_path = plugin_root / ".claude-plugin/plugin.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"FAILED: invalid Claude plugin manifest JSON: {manifest_path}: {exc}") from exc

    if not isinstance(manifest, dict):
        raise SystemExit("FAILED: Claude plugin manifest must be a JSON object")
    if manifest.get("name") != "zhulong":
        raise SystemExit("FAILED: Claude plugin manifest name must be zhulong")
    for field in ("version", "displayName", "description"):
        if not isinstance(manifest.get(field), str) or not manifest[field].strip():
            raise SystemExit(f"FAILED: Claude plugin manifest missing metadata field: {field}")
    description = manifest["description"].lower()
    if "docker" not in description or "audit" not in description:
        raise SystemExit("FAILED: Claude plugin manifest description must describe Docker audit workflow")

    for field in ("skills", "scripts", "assets"):
        require_relative_manifest_path(plugin_root, manifest, field)
    if not (plugin_root / "skills/zhulong/SKILL.md").is_file():
        raise SystemExit("FAILED: Claude plugin package missing skills/zhulong/SKILL.md")
    if not (plugin_root / "scripts").is_dir():
        raise SystemExit("FAILED: Claude plugin package missing scripts/")
    if not (plugin_root / "assets").is_dir():
        raise SystemExit("FAILED: Claude plugin package missing assets/")

    runtime = manifest.get("runtime")
    if runtime is not None:
        if not isinstance(runtime, dict):
            raise SystemExit("FAILED: Claude plugin manifest runtime must be metadata object")
        if runtime.get("entrypoint"):
            require_relative_manifest_path(
                plugin_root,
                runtime,
                "entrypoint",
                must_be_file=True,
            )

    for text in iter_json_strings(manifest):
        if text.startswith("file://") or text.startswith("/"):
            raise SystemExit(f"FAILED: Claude plugin manifest contains an absolute local path: {text}")
        if re.match(r"^[A-Za-z]:[\\/]", text):
            raise SystemExit(f"FAILED: Claude plugin manifest contains a Windows absolute path: {text}")
        operator_local_path = "/" + "Users" + "/" + "torchbearer"
        if operator_local_path in text:
            raise SystemExit("FAILED: Claude plugin manifest contains operator-local absolute path")

    forbidden_component_fields = (
        "hooks",
        "mcpServers",
        "mcp_servers",
        "apps",
        "agents",
        "commands",
        "services",
        "platformServices",
        "backgroundServices",
        "daemons",
    )
    for field in forbidden_component_fields:
        if field in manifest and not is_empty_manifest_component(manifest[field]):
            raise SystemExit(
                "FAILED: Claude plugin manifest must not declare runtime component "
                f"{field!r}; Zhulong remains skill-and-scripts only"
            )


def require_probe_record(
    summary_path: Path,
    output_dir: Path,
    probe_name: str,
    expected_status: str,
    expected_exit_code: int | None,
    reason_snippet: str,
    forbidden_reason_snippet: str = "",
) -> dict:
    summary_data = json.loads(summary_path.read_text(encoding="utf-8"))
    probes = summary_data.get("probes") or []
    probe = next((item for item in probes if item.get("name") == probe_name), None)
    if probe is None:
        raise SystemExit(f"FAILED: missing probe record for {probe_name}")
    if probe.get("status") != expected_status:
        raise SystemExit(
            f"FAILED: {probe_name} status mismatch: "
            f"expected {expected_status}, got {probe.get('status')}"
        )
    if probe.get("exit_code") != expected_exit_code:
        raise SystemExit(
            f"FAILED: {probe_name} exit_code mismatch: "
            f"expected {expected_exit_code}, got {probe.get('exit_code')}"
        )
    reason = str(probe.get("reason") or "")
    if reason_snippet not in reason:
        raise SystemExit(f"FAILED: {probe_name} reason missing expected text: {reason_snippet}")
    if forbidden_reason_snippet and forbidden_reason_snippet in reason:
        raise SystemExit(f"FAILED: {probe_name} reason contains forbidden text: {forbidden_reason_snippet}")

    status_path = output_dir / f"{probe_name}.status"
    if not status_path.exists():
        raise SystemExit(f"FAILED: missing probe status file for {probe_name}: {status_path}")
    status_lines = status_path.read_text(encoding="utf-8").splitlines()
    if not status_lines or status_lines[0] != expected_status:
        raise SystemExit(f"FAILED: {probe_name}.status does not match summary status")
    status_exit = None
    for line in status_lines[1:]:
        if line.startswith("exit_code="):
            status_exit = int(line.split("=", 1)[1])
            break
    if expected_exit_code is not None and status_exit != expected_exit_code:
        raise SystemExit(f"FAILED: {probe_name}.status exit_code does not match summary exit_code")
    return probe


RUNTIME_STATUS_FIELDS = {
    "checked_at",
    "recommended_mode",
    "teams_enabled",
    "suspect_teammate_pids",
    "suspect_teammate_processes",
    "stale_swarm_sockets",
    "live_swarm_sockets",
    "ignored_current_session_teammate_pids",
    "ignored_current_session_teammate_processes",
    "cleanup_actions",
    "attempt_history",
    "heartbeat_seen",
    "resume_step",
    "unresolved_review_only",
    "clean",
}


def require_runtime_status_shape(status: dict, label: str) -> None:
    missing = sorted(RUNTIME_STATUS_FIELDS - set(status))
    if missing:
        raise SystemExit(f"FAILED: runtime hygiene status missing fields for {label}: {missing}")
    if status.get("recommended_mode") not in {"native_team_ready", "cleanup_needed", "single_agent_only"}:
        raise SystemExit(f"FAILED: invalid runtime hygiene mode for {label}: {status.get('recommended_mode')}")
    for key in (
        "suspect_teammate_pids",
        "suspect_teammate_processes",
        "stale_swarm_sockets",
        "live_swarm_sockets",
        "ignored_current_session_teammate_pids",
        "ignored_current_session_teammate_processes",
        "cleanup_actions",
        "attempt_history",
        "unresolved_review_only",
    ):
        if not isinstance(status.get(key), list):
            raise SystemExit(f"FAILED: runtime hygiene status field must be a list for {label}: {key}")


def run_omc_runtime_mock(
    script_path: Path,
    workspace: Path,
    plugin_root: Path,
    *,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    expected_returncode: int = 0,
) -> dict:
    command = [
        "bash",
        str(script_path),
        "--workspace-dir",
        str(workspace),
        "--json",
    ]
    if args:
        command.extend(args)
    output = run_capture_with_env(
        command,
        plugin_root,
        {
            "ZHULONG_OMC_MOCK_TEAMS_ENABLED": "1",
            **(env or {}),
        },
        expected_returncode=expected_returncode,
    )
    try:
        status = json.loads(output)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"FAILED: OMC runtime helper did not emit JSON for {script_path}: {output}") from exc
    require_runtime_status_shape(status, script_path.name)
    status_path = workspace / "runtime/runtime-hygiene-status.json"
    if not status_path.exists():
        raise SystemExit(f"FAILED: OMC runtime helper did not write status file: {status_path}")
    stored = json.loads(status_path.read_text(encoding="utf-8"))
    require_runtime_status_shape(stored, f"stored {script_path.name}")
    return status


def exercise_omc_runtime_hygiene(script_path: Path, workspace: Path, plugin_root: Path) -> None:
    def assert_no_teammate_signal_actions(status: dict, label: str) -> None:
        forbidden = {
            item.get("status")
            for item in status.get("cleanup_actions", [])
            if item.get("kind") == "cleanup_suspect_pid"
        }
        if forbidden & {"term_sent", "terminated"}:
            raise SystemExit(f"FAILED: OMC teammate PID cleanup recorded signal action for {label}: {status}")

    status = run_omc_runtime_mock(
        script_path,
        workspace,
        plugin_root,
        env={"ZHULONG_OMC_MOCK_TEAMMATE_RECORDS": "12345|111|222|333|ttys123|S+|claude --teammate-mode tmux audit"},
    )
    if status.get("recommended_mode") != "cleanup_needed" or status.get("suspect_teammate_pids") != ["12345"]:
        raise SystemExit(f"FAILED: OMC runtime helper did not report exact suspect PID: {status}")
    process = (status.get("suspect_teammate_processes") or [{}])[0]
    if process.get("tty") != "ttys123" or process.get("active_session_uncertain") is not True:
        raise SystemExit(f"FAILED: OMC runtime helper did not preserve process metadata: {status}")
    if not any(item.get("kind") == "suspect_teammate_pid" for item in status.get("unresolved_review_only", [])):
        raise SystemExit("FAILED: OMC runtime helper must record suspect teammate PIDs as review-only")
    assert_no_teammate_signal_actions(status, "initial suspect report")
    handoff = workspace / "handoff-summary.md"
    require_text(handoff, "## OMC Runtime Hygiene", "handoff runtime hygiene section")
    require_text(handoff, "`12345`", "handoff suspect PID")
    require_text(handoff, "review-only", "handoff review-only teammate PID guidance")
    require_text(handoff, "ttys123", "handoff suspect PID process metadata")
    forbidden_apply = "--" + "cleanup-suspect-pid 12345 --" + "apply"
    forbid_text(handoff, forbidden_apply, "handoff must not recommend teammate PID cleanup apply")

    kill_log = workspace / "runtime/mock-kill-dry-run.log"
    status = run_omc_runtime_mock(
        script_path,
        workspace,
        plugin_root,
        args=["--cleanup-suspect-pid", "12346"],
        env={
            "ZHULONG_OMC_MOCK_TEAMMATE_RECORDS": "12346|claude --teammate-mode tmux audit",
            "ZHULONG_OMC_MOCK_PID_EXISTS": "12346",
            "ZHULONG_OMC_MOCK_KILL_LOG": str(kill_log),
        },
    )
    if kill_log.exists() and kill_log.read_text(encoding="utf-8").strip():
        raise SystemExit("FAILED: OMC exact PID dry-run sent a signal")
    if status.get("cleanup_actions"):
        raise SystemExit(f"FAILED: OMC teammate PID review-only dry-run must not create cleanup actions: {status}")
    if not any(item.get("kind") == "suspect_teammate_pid" and "review-only" in item.get("reason", "") for item in status.get("unresolved_review_only", [])):
        raise SystemExit("FAILED: OMC exact PID dry-run must be unresolved review-only")
    assert_no_teammate_signal_actions(status, "review-only dry-run")

    status = run_omc_runtime_mock(
        script_path,
        workspace,
        plugin_root,
        args=["--cleanup-suspect-pid", "12347", "--apply"],
        env={
            "ZHULONG_OMC_MOCK_PID_EXISTS": "12347",
            "ZHULONG_OMC_MOCK_CMDLINE_RECORDS": "12347|python unrelated.py",
        },
        expected_returncode=1,
    )
    if not any(item.get("status") == "refused" and "command line" in item.get("reason", "") for item in status.get("cleanup_actions", [])):
        raise SystemExit("FAILED: OMC exact PID cleanup must refuse command-line mismatch")
    assert_no_teammate_signal_actions(status, "command-line mismatch")

    status = run_omc_runtime_mock(
        script_path,
        workspace,
        plugin_root,
        args=["--cleanup-suspect-pid", "12348", "--apply"],
        env={
            "ZHULONG_OMC_MOCK_TEAMMATE_RECORDS": "12348|claude --teammate-mode tmux audit",
            "ZHULONG_OMC_MOCK_PID_EXISTS": "12348",
            "ZHULONG_OMC_MOCK_LIVE_SOCKETS": "/private/tmp/tmux-501/claude-swarm-live",
        },
        expected_returncode=1,
    )
    if not any(item.get("kind") == "live_swarm_socket" for item in status.get("unresolved_review_only", [])):
        raise SystemExit("FAILED: OMC exact PID cleanup must refuse when a live swarm socket exists")
    assert_no_teammate_signal_actions(status, "live swarm socket")

    status = run_omc_runtime_mock(
        script_path,
        workspace,
        plugin_root,
        args=["--cleanup-suspect-pid", "12349", "--apply"],
        env={
            "ZHULONG_OMC_MOCK_TEAMMATE_RECORDS": "12349|claude --teammate-mode tmux audit",
            "ZHULONG_OMC_MOCK_PID_EXISTS": "12349",
            "ZHULONG_OMC_MOCK_CURRENT_SESSION_TEAMMATE_PIDS": "12349",
        },
        expected_returncode=1,
    )
    if status.get("ignored_current_session_teammate_pids") != ["12349"]:
        raise SystemExit("FAILED: OMC runtime helper must record ignored current-session teammate PIDs")
    ignored_process = (status.get("ignored_current_session_teammate_processes") or [{}])[0]
    if ignored_process.get("active_session_uncertain") is not False:
        raise SystemExit(f"FAILED: current-session teammate metadata must be marked certain/protected: {status}")
    if not any(item.get("kind") == "current_session_teammate_pid" for item in status.get("unresolved_review_only", [])):
        raise SystemExit("FAILED: OMC exact PID cleanup must refuse current-session teammate PIDs")
    assert_no_teammate_signal_actions(status, "current-session PID")

    kill_log = workspace / "runtime/mock-kill-apply.log"
    status = run_omc_runtime_mock(
        script_path,
        workspace,
        plugin_root,
        args=["--cleanup-suspect-pid", "12350", "--apply"],
        env={
            "ZHULONG_OMC_MOCK_TEAMMATE_RECORDS": "12350|claude --teammate-mode tmux audit",
            "ZHULONG_OMC_MOCK_PID_EXISTS": "12350",
            "ZHULONG_OMC_MOCK_KILL_LOG": str(kill_log),
        },
        expected_returncode=1,
    )
    if kill_log.exists() and kill_log.read_text(encoding="utf-8").strip():
        raise SystemExit("FAILED: OMC exact PID cleanup with --apply must not send a signal")
    if not any("refused --apply" in item.get("reason", "") for item in status.get("unresolved_review_only", [])):
        raise SystemExit("FAILED: OMC exact PID cleanup with --apply must be refused review-only")
    assert_no_teammate_signal_actions(status, "apply refused teammate PID")

    socket_log = workspace / "runtime/mock-socket-cleanup.log"
    status = run_omc_runtime_mock(
        script_path,
        workspace,
        plugin_root,
        args=["--cleanup-stale"],
        env={
            "ZHULONG_OMC_MOCK_STALE_SOCKETS": "/tmp/claude-swarm-stale\n/tmp/not-omc.sock",
            "ZHULONG_OMC_MOCK_SOCKET_CLEANUP_LOG": str(socket_log),
        },
    )
    socket_text = socket_log.read_text(encoding="utf-8")
    if "REMOVE_SOCKET /tmp/claude-swarm-stale" not in socket_text or "not-omc.sock" in socket_text:
        raise SystemExit("FAILED: OMC stale socket cleanup must remove only stale claude-swarm sockets")
    if not any(item.get("kind") == "stale_swarm_socket" and "non-claude-swarm" in item.get("reason", "") for item in status.get("unresolved_review_only", [])):
        raise SystemExit("FAILED: OMC stale socket cleanup must review-only non claude-swarm mock sockets")

    run_expect_fail(
        ["bash", str(script_path), "--force-kill-suspect-teammates"],
        plugin_root,
        "Refusing deprecated --force-kill-suspect-teammates",
    )


def run_sandbox_preflight(
    script_path: Path,
    workspace: Path,
    plugin_root: Path,
    args: list[str],
    *,
    expected_returncode: int,
) -> dict:
    output = run_capture_with_env(
        [
            sys.executable,
            str(script_path),
            "--workspace-dir",
            str(workspace),
            "--case-id",
            "sandbox-selftest",
            "--json",
            *args,
        ],
        plugin_root,
        {},
        expected_returncode=expected_returncode,
    )
    try:
        status = json.loads(output)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"FAILED: sandbox preflight did not emit JSON: {output}") from exc
    for key in ("checked_at", "ok", "status", "findings", "labels", "resume_step", "review_only"):
        if key not in status:
            raise SystemExit(f"FAILED: sandbox preflight missing status field: {key}")
    status_path = workspace / "runtime/sandbox-preflight-status.json"
    if not status_path.exists():
        raise SystemExit("FAILED: sandbox preflight did not write runtime/sandbox-preflight-status.json")
    return status


def require_sandbox_rejection(status: dict, pattern: str, label: str) -> None:
    if status.get("status") != "rejected_unsafe_sandbox" or status.get("ok") is not False:
        raise SystemExit(f"FAILED: sandbox preflight should reject {label}: {status}")
    if not any(item.get("pattern") == pattern for item in status.get("findings", [])):
        raise SystemExit(f"FAILED: sandbox preflight missing pattern {pattern} for {label}: {status}")
    if not status.get("review_only"):
        raise SystemExit(f"FAILED: rejected sandbox status must be review-only for {label}")


def exercise_sandbox_preflight(script_path: Path, workspace: Path, plugin_root: Path) -> None:
    fixtures = workspace / "sandbox-preflight-fixtures"
    fixtures.mkdir(parents=True, exist_ok=True)

    compose_privileged = fixtures / "privileged.yml"
    compose_privileged.write_text("services:\n  app:\n    image: alpine\n    privileged: true\n", encoding="utf-8")
    require_sandbox_rejection(
        run_sandbox_preflight(script_path, workspace, plugin_root, ["--compose-file", str(compose_privileged)], expected_returncode=1),
        "privileged_true",
        "Compose privileged:true",
    )

    compose_host_network = fixtures / "host-network.yml"
    compose_host_network.write_text("services:\n  app:\n    image: alpine\n    network_mode: host\n", encoding="utf-8")
    require_sandbox_rejection(
        run_sandbox_preflight(script_path, workspace, plugin_root, ["--compose-file", str(compose_host_network)], expected_returncode=1),
        "network_mode_host",
        "Compose network_mode:host",
    )

    compose_host_pid = fixtures / "host-pid.yml"
    compose_host_pid.write_text("services:\n  app:\n    image: alpine\n    pid: host\n", encoding="utf-8")
    require_sandbox_rejection(
        run_sandbox_preflight(script_path, workspace, plugin_root, ["--compose-file", str(compose_host_pid)], expected_returncode=1),
        "pid_host",
        "Compose pid:host",
    )

    compose_sock = fixtures / "docker-sock.yml"
    compose_sock.write_text(
        "services:\n  app:\n    image: alpine\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )
    require_sandbox_rejection(
        run_sandbox_preflight(script_path, workspace, plugin_root, ["--compose-file", str(compose_sock)], expected_returncode=1),
        "docker_socket_mount",
        "Compose Docker socket mount",
    )

    compose_root = fixtures / "root-mount.yml"
    compose_root.write_text("services:\n  app:\n    image: alpine\n    volumes:\n      - /:/host:ro\n", encoding="utf-8")
    require_sandbox_rejection(
        run_sandbox_preflight(script_path, workspace, plugin_root, ["--compose-file", str(compose_root)], expected_returncode=1),
        "host_root_mount",
        "Compose host root mount",
    )

    script_sock_root = fixtures / "unsafe-run.sh"
    script_sock_root.write_text(
        "#!/usr/bin/env bash\n"
        "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v /:/host alpine true\n",
        encoding="utf-8",
    )
    status = run_sandbox_preflight(script_path, workspace, plugin_root, ["--shell-script", str(script_sock_root)], expected_returncode=1)
    require_sandbox_rejection(status, "docker_socket_mount", "script Docker socket mount")
    require_sandbox_rejection(status, "host_root_mount", "script host root mount")

    require_sandbox_rejection(
        run_sandbox_preflight(script_path, workspace, plugin_root, ["--docker-run-arg=--privileged"], expected_returncode=1),
        "docker_run_privileged",
        "docker run --privileged",
    )
    require_sandbox_rejection(
        run_sandbox_preflight(
            script_path,
            workspace,
            plugin_root,
            ["--docker-run-arg=--network", "--docker-run-arg=host"],
            expected_returncode=1,
        ),
        "docker_run_network_host",
        "docker run --network host",
    )
    require_sandbox_rejection(
        run_sandbox_preflight(
            script_path,
            workspace,
            plugin_root,
            ["--docker-run-arg=--pid=host"],
            expected_returncode=1,
        ),
        "docker_run_pid_host",
        "docker run --pid host",
    )

    safe_compose = fixtures / "safe-attacker.yml"
    safe_compose.write_text(
        "services:\n"
        "  attacker:\n"
        "    image: alpine:3.20\n"
        "    labels:\n"
        "      org.zhulong.managed: \"true\"\n"
        "    cap_drop:\n"
        "      - ALL\n"
        "    security_opt:\n"
        "      - no-new-privileges:true\n"
        "    network_mode: bridge\n"
        "    volumes:\n"
        "      - type: bind\n"
        "        source: ./poc\n"
        "        target: /workspace/poc\n"
        "        read_only: true\n",
        encoding="utf-8",
    )
    status = run_sandbox_preflight(script_path, workspace, plugin_root, ["--compose-file", str(safe_compose)], expected_returncode=0)
    if status.get("status") != "passed" or status.get("findings"):
        raise SystemExit(f"FAILED: safe Zhulong attacker compose should pass sandbox preflight: {status}")


def exercise_runner_sandbox_rejection(run_script: Path, workspace: Path, plugin_root: Path) -> None:
    fakebin = workspace / "fakebin"
    fakebin.mkdir(parents=True, exist_ok=True)
    docker_log = workspace / "runtime/docker-called.log"
    fake_docker = fakebin / "docker"
    fake_docker.write_text(
        "#!/usr/bin/env bash\n"
        "echo docker-called \"$@\" >> \"$ZHULONG_DOCKER_CALL_LOG\"\n"
        "exit 0\n",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)

    output = run_capture_with_env(
        [
            "bash",
            str(run_script),
            "--workspace-dir",
            str(workspace),
            "--case-id",
            "unsafe-host-network",
            "--mode",
            "docker-run",
            "--image",
            "alpine:3.20",
            "--timeout-seconds",
            "30",
            "--allow-exit-zero-oracle",
            "--network",
            "host",
            "--",
            "true",
        ],
        plugin_root,
        {
            "PATH": f"{fakebin}{os.pathsep}{os.environ.get('PATH', '')}",
            "ZHULONG_DOCKER_CALL_LOG": str(docker_log),
        },
        expected_returncode=1,
    )
    if "rejected_unsafe_sandbox" not in output:
        raise SystemExit(f"FAILED: runner did not surface rejected_unsafe_sandbox:\n{output}")
    if docker_log.exists():
        raise SystemExit("FAILED: run_verification_case.sh called docker after sandbox preflight rejection")
    result_path = workspace / "evidence/unsafe-host-network/verification-result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if result.get("status") != "rejected_unsafe_sandbox":
        raise SystemExit(f"FAILED: runner result did not persist rejected_unsafe_sandbox: {result}")
    status_path = workspace / "runtime/sandbox-preflight-status.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    if status.get("status") != "rejected_unsafe_sandbox" or not status.get("review_only"):
        raise SystemExit(f"FAILED: runtime sandbox status is not rejected review-only: {status}")


def exercise_sandbox_ledger_guard(workspace: Path, plugin_root: Path) -> None:
    sys.path.insert(0, str(plugin_root / "scripts"))
    from audit_disposition import synthesize_disposition_ledger  # type: ignore

    unverified_path = workspace / "unverified-leads.md"
    original = unverified_path.read_text(encoding="utf-8", errors="ignore") if unverified_path.exists() else ""
    try:
        unverified_path.write_text(
            "| Lead ID | Suspected Weakness | Evidence So Far | Missing Evidence | Docker Confirmation Status | Safe Resume Step | High-Confidence-Unverified? | Material blocker? | Default runtime scope? | Why completion is still safe? |\n"
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"
            "| U-SANDBOX | SSRF candidate | PoC needs unsafe Docker flags | safe sandbox rewrite | rejected_unsafe_sandbox | rewrite verification container without host/privileged/docker.sock/root mount | Yes | Yes | default runtime | unsafe sandbox rejection is blocked/unverified, not confirmed |\n",
            encoding="utf-8",
        )
        ledger = synthesize_disposition_ledger(workspace, merge_existing=False)
    finally:
        unverified_path.write_text(original, encoding="utf-8")

    matches = [
        item for item in ledger.get("items", [])
        if "sandbox" in str(item.get("id", "")).lower() or "sandbox" in str(item.get("title", "")).lower()
    ]
    if not matches:
        raise SystemExit("FAILED: audit disposition ledger did not capture rejected_unsafe_sandbox lead")
    if any(item.get("state") == "confirmed" or item.get("confirmed_bundle_path") for item in matches):
        raise SystemExit(f"FAILED: rejected_unsafe_sandbox entered confirmed ledger state: {matches}")
    if not any(item.get("state") in {"blocked", "unverified"} for item in matches):
        raise SystemExit(f"FAILED: rejected_unsafe_sandbox must stay blocked/unverified: {matches}")


def selftest_installed_skill(skill_root: Path) -> None:
    for rel in INSTALLED_SKILL_REQUIRED_FILES:
        path = skill_root / rel
        if not path.exists():
            raise SystemExit(f"FAILED: missing required installed skill file: {path}")

    run([sys.executable, "-m", "py_compile",
         str(skill_root / "scripts/plan_security_toolchain.py"),
         str(skill_root / "scripts/render_handoff_summary.py"),
         str(skill_root / "scripts/assert_finalized_workspace.py"),
         str(skill_root / "scripts/audit_disposition.py"),
         str(skill_root / "scripts/blocked_verification.py"),
         str(skill_root / "scripts/write_audit_event.py"),
         str(skill_root / "scripts/validate_workspace_state.py"),
         str(skill_root / "scripts/check_sandbox_preflight.py"),
         str(skill_root / "scripts/manage_docker_resources.py"),
         str(skill_root / "scripts/render_confirmed_vuln_docx.py"),
         str(skill_root / "scripts/validate_report_bundle.py"),
         str(skill_root / "scripts/validate_all_report_bundles.py"),
         str(skill_root / "scripts/finalize_audit_workspace.py")], skill_root)

    for script in [
        "scripts/bootstrap_verification_workspace.sh",
        "scripts/asr_start.sh",
        "scripts/prepare_target_repo.sh",
        "scripts/check_docker_gate.sh",
        "scripts/check_omc_runtime.sh",
        "scripts/check_security_tooling.sh",
        "scripts/run_initial_probes.sh",
        "scripts/run_verification_case.sh",
    ]:
        run(["bash", "-n", str(skill_root / script)], skill_root)

    require_text(
        skill_root / "SKILL.md",
        "Confirm vulnerabilities only with Docker evidence",
        "installed skill Docker-confirmed-only contract",
    )
    require_text(
        skill_root / "SKILL.md",
        "completed_no_confirmed_findings",
        "installed skill completion result contract",
    )
    require_text(
        skill_root / "SKILL.md",
        "Blocked Docker/runtime verification is not the same as",
        "installed skill blocked verification semantics",
    )
    require_text(
        skill_root / "SKILL.md",
        "runtime/runtime-hygiene-status.json",
        "installed skill OMC runtime hygiene status contract",
    )
    require_text(
        skill_root / "SKILL.md",
        "Teammate PID cleanup is review-only",
        "installed skill review-only OMC PID cleanup contract",
    )
    require_text(
        skill_root / "SKILL.md",
        "check_sandbox_preflight.py",
        "installed skill sandbox preflight helper reference",
    )
    require_text(
        skill_root / "SKILL.md",
        "rejected_unsafe_sandbox",
        "installed skill sandbox preflight rejected label",
    )
    require_text(
        skill_root / "SKILL.md",
        "攻击者条件",
        "installed skill confirmed quality-gate attacker label",
    )
    require_text(
        skill_root / "SKILL.md",
        "Security Impact",
        "installed skill confirmed quality-gate impact label",
    )
    require_text(
        skill_root / "SKILL.md",
        "SECURITY.md",
        "installed skill security-boundary triage check",
    )
    require_text(
        skill_root / "SKILL.md",
        "outside_security_boundary",
        "installed skill false-positive boundary reason code",
    )
    require_text(
        skill_root / "SKILL.md",
        "<audit-workspace>/SUMMARY.md",
        "installed skill stable summary contract",
    )
    require_text(
        skill_root / "assets/references/unverified-lead-template.md",
        "Material blocker?",
        "installed skill unverified lead materiality template",
    )
    require_text(
        skill_root / "assets/references/false-positive-template.md",
        "expected_behavior",
        "installed skill false-positive expected behavior reason code",
    )
    require_text(
        skill_root / "assets/references/false-positive-template.md",
        "outside_security_boundary",
        "installed skill false-positive outside boundary reason code",
    )
    require_text(
        skill_root / "assets/references/false-positive-template.md",
        "requires_non_default_admin_trust",
        "installed skill false-positive admin trust reason code",
    )
    require_text(
        skill_root / "assets/references/unverified-lead-template.md",
        "Security policy / scope checked",
        "installed skill unverified security policy check field",
    )

    operator_local_path = "/" + "Users" + "/" + "torchbearer"
    require_no_repo_text(skill_root, operator_local_path, "operator-local absolute path")
    stale_asr_name = "autonomous-security" + "-researcher"
    require_no_repo_text(skill_root, stale_asr_name, "stale ASR naming")

    with tempfile.TemporaryDirectory(prefix="zhulong-installed-omc-selftest-") as tempdir:
        repo_dir = Path(tempdir) / "repo"
        repo_dir.mkdir(parents=True, exist_ok=True)
        run([
            "bash",
            str(skill_root / "scripts/bootstrap_verification_workspace.sh"),
            "--target-dir",
            str(repo_dir),
            "--workspace-name",
            "security-research-installed-omc",
        ], skill_root)
        exercise_omc_runtime_hygiene(
            skill_root / "scripts/check_omc_runtime.sh",
            repo_dir / "security-research-installed-omc",
            skill_root,
        )
        installed_workspace = repo_dir / "security-research-installed-omc"
        exercise_sandbox_preflight(
            skill_root / "scripts/check_sandbox_preflight.py",
            installed_workspace,
            skill_root,
        )
        exercise_runner_sandbox_rejection(
            skill_root / "scripts/run_verification_case.sh",
            installed_workspace,
            skill_root,
        )
        exercise_sandbox_ledger_guard(installed_workspace, skill_root)

    print(f"SELFTEST PASSED: installed Claude skill layout {skill_root}")


def main() -> None:
    plugin_root = Path(__file__).resolve().parent.parent

    if (plugin_root / "SKILL.md").exists() and not (plugin_root / ".codex-plugin/plugin.json").exists():
        selftest_installed_skill(plugin_root)
        return

    for rel in REQUIRED_FILES:
        path = plugin_root / rel
        if not path.exists():
            raise SystemExit(f"FAILED: missing required plugin file: {path}")

    plugin_json = json.loads((plugin_root / ".codex-plugin/plugin.json").read_text(encoding="utf-8"))
    if plugin_json.get("name") != "zhulong":
        raise SystemExit("FAILED: plugin.json name mismatch")
    validate_claude_plugin_manifest(plugin_root)

    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "Documents` skill",
        "Claude skill template docx editing contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "practical scenario, attacker-controlled input, trigger/call chain, direct impact, and impact boundary",
        "Claude skill template reviewer-proof contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "severity-escalation pass",
        "Claude skill template severity escalation contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "Do not execute `web_search`",
        "Claude skill template web lookup shell-safety contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "specialized_playbooks",
        "Claude skill template language playbook contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "Do not produce thin DOCX reports",
        "Claude skill template report-depth contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "攻击者条件",
        "Claude skill template confirmed quality-gate attacker label",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "Security Impact",
        "Claude skill template confirmed quality-gate impact label",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "SECURITY.md",
        "Claude skill template security-boundary triage check",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "outside_security_boundary",
        "Claude skill template false-positive boundary reason codes",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "exactly one confirmed vulnerability",
        "Claude skill template one-finding-per-bundle contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "do not use `evidence/` as a final delivery directory",
        "Claude skill template attachments-only final delivery contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "do not leave runtime or source-control directories",
        "Claude skill template final bundle cleanliness contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "verification-evidence.json",
        "Claude skill template verification evidence contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "Static scanning, source-to-sink reasoning",
        "Claude skill template candidate-only analysis contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "False positives, non-security defects, unverified leads",
        "Claude skill template triage workspace-only contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "Final summaries must explicitly distinguish confirmed vulnerabilities",
        "Claude skill template final summary triage contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "initial-probes-summary.json",
        "Claude skill template initial probes summary contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "skipped_no_package_sources",
        "Claude skill template initial probes no package sources status",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "must not be reported as confirmed vulnerabilities",
        "Claude skill template initial probes confirmed-output guardrail",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "handoff-summary.md",
        "Claude skill template handoff summary contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "context-slimming index",
        "Claude skill template handoff context-slimming contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "Avoid default-reading",
        "Claude skill template handoff raw-log avoidance contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "run_verification_case.sh",
        "Claude skill template verification runner reference",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "mandatory timeout, explicit network setting",
        "Claude skill template verification runner timeout/network contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "blocked_docker_unavailable",
        "Claude skill template verification runner stable labels",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "rejected_unsafe_sandbox",
        "Claude skill template sandbox preflight rejected label",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "check_sandbox_preflight.py",
        "Claude skill template sandbox preflight helper reference",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "timed-out, blocked, resource-limited",
        "Claude skill template verification runner confirmed-output guardrail",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "Fill `<audit-workspace>/attack-surface.md` as a concise handoff artifact",
        "Claude skill template attack-surface handoff contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "not a vulnerability report, not raw scanner output",
        "Claude skill template attack-surface non-report guardrail",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "unverified until Docker confirmation succeeds",
        "Claude skill template attack-surface Docker confirmation guardrail",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "java-web-audit-playbook.md",
        "Claude skill template Java Web playbook reference",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "go-web-audit-playbook.md",
        "Claude skill template Go Web playbook reference",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "nodejs-library-audit-playbook.md",
        "Claude skill template Node.js Library playbook reference",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "For pure\nNode.js or Python library/framework repositories",
        "Claude skill template library route-inventory guardrail",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "nodejs-web-audit-playbook.md",
        "Claude skill template Node.js Web playbook reference",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "python-web-audit-playbook.md",
        "Claude skill template Python Web playbook reference",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "python-library-audit-playbook.md",
        "Claude skill template Python Library playbook reference",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "php-swoole-audit-playbook.md",
        "Claude skill template PHP/Swoole playbook reference",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "Blocked Docker/runtime verification is not the same as",
        "Claude skill template blocked verification semantics",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "runtime/runtime-hygiene-status.json",
        "Claude skill template OMC runtime hygiene status contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "Teammate PID cleanup is review-only",
        "Claude skill template review-only OMC PID cleanup contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "docker-registry-fallbacks.example.json",
        "Claude skill template registry fallback reference",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "local_knowledge_checklists",
        "Claude skill template local checklist planner contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "Checklist matches, source-to-sink hypotheses",
        "Claude skill template local checklist confirmed-only guardrail",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "Language playbooks are starting maps, not fences",
        "Claude skill template playbook exploration freedom guardrail",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "finalize-audit-workspace.py",
        "Claude skill template completion gate command",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "completed_no_confirmed_findings",
        "Claude skill template no-confirmed-findings result",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "A dogfood run is not complete until this gate passes",
        "Claude skill template completion gate enforcement",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "assert-finalized-workspace.py",
        "Claude skill template finalization integrity checker",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "Material blocker?",
        "Claude skill template unverified lead materiality requirement",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "<audit-workspace>/SUMMARY.md",
        "Claude skill template stable workspace summary requirement",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "manually edited `stage-status.json`",
        "Claude skill template manual completion guardrail",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "exact source commit SHA",
        "Claude skill template archive fallback commit identity",
    )
    require_text(
        plugin_root / "assets/references/false-positive-template.md",
        "must never be written under `confirmed/`",
        "false-positive template confirmed-output guardrail",
    )
    require_text(
        plugin_root / "assets/references/false-positive-template.md",
        "Docker verification status",
        "false-positive template Docker status field",
    )
    require_text(
        plugin_root / "assets/references/false-positive-template.md",
        "expected_behavior",
        "false-positive template expected behavior reason code",
    )
    require_text(
        plugin_root / "assets/references/false-positive-template.md",
        "outside_security_boundary",
        "false-positive template outside boundary reason code",
    )
    require_text(
        plugin_root / "assets/references/false-positive-template.md",
        "requires_non_default_admin_trust",
        "false-positive template admin trust reason code",
    )
    require_text(
        plugin_root / "assets/references/false-positive-template.md",
        "default_config_not_vulnerable",
        "false-positive template default config reason code",
    )
    require_text(
        plugin_root / "assets/references/false-positive-template.md",
        "insufficient_attacker_condition",
        "false-positive template attacker-condition reason code",
    )
    require_text(
        plugin_root / "assets/references/false-positive-template.md",
        "insufficient_security_impact",
        "false-positive template security-impact reason code",
    )
    require_text(
        plugin_root / "assets/references/unverified-lead-template.md",
        "Safe resume step",
        "unverified lead template resume field",
    )
    require_text(
        plugin_root / "assets/references/unverified-lead-template.md",
        "high-confidence-unverified/",
        "unverified lead template high-confidence guardrail",
    )
    require_text(
        plugin_root / "assets/references/unverified-lead-template.md",
        "Why completion is still safe?",
        "unverified lead template materiality rationale field",
    )
    require_text(
        plugin_root / "assets/references/unverified-lead-template.md",
        "Confirmed-output guardrail",
        "unverified lead template confirmed-output guardrail field",
    )
    require_text(
        plugin_root / "assets/references/unverified-lead-template.md",
        "Security policy / scope checked",
        "unverified lead template security policy check field",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "final-summary-template.md",
        "Claude skill template final summary reference",
    )
    require_text(
        plugin_root / "assets/references/final-summary-template.md",
        "false positives / non-security defects",
        "final summary false-positive section",
    )
    require_text(
        plugin_root / "assets/references/final-summary-template.md",
        "high-confidence-but-not-Docker-confirmed leads",
        "final summary high-confidence unverified section",
    )
    require_text(
        plugin_root / "assets/references/final-summary-template.md",
        "<audit-workspace>/SUMMARY.md",
        "final summary stable workspace summary requirement",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "Docker-confirmed but bundle incomplete",
        "Claude skill template partial bundle final-summary guardrail",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "partial confirmed bundle",
        "Claude skill template partial confirmed bundle guardrail",
    )
    require_text(
        plugin_root / "assets/references/final-summary-template.md",
        "Docker-confirmed but bundle incomplete",
        "final summary partial bundle section",
    )
    require_text(
        plugin_root / "assets/references/confirmed-vuln-docx-format.md",
        "Claude Code DOCX Editing Rule",
        "confirmed-vuln-docx-format docx workflow section",
    )
    require_text(
        plugin_root / "assets/references/confirmed-vuln-docx-format.md",
        "Verification Evidence JSON",
        "confirmed-vuln-docx-format verification evidence schema",
    )
    require_text(
        plugin_root / "assets/references/confirmed-vuln-docx-format.md",
        "partial confirmed bundle",
        "confirmed-vuln-docx-format partial bundle guardrail",
    )
    require_text(
        plugin_root / "scripts/render_handoff_summary.py",
        "partial_confirmed_bundle",
        "handoff renderer partial bundle classification hint",
    )
    require_text(
        plugin_root / "scripts/render_handoff_summary.py",
        "Finalization integrity",
        "handoff renderer finalization integrity hint",
    )
    require_text(
        plugin_root / "scripts/render_handoff_summary.py",
        "OMC Runtime Hygiene",
        "handoff renderer OMC runtime hygiene section",
    )
    require_text(
        plugin_root / "scripts/check_omc_runtime.sh",
        "--cleanup-suspect-pid",
        "OMC runtime helper exact PID cleanup flag",
    )
    require_text(
        plugin_root / "scripts/check_omc_runtime.sh",
        "--force-kill-suspect-teammates",
        "OMC runtime helper deprecated broad cleanup refusal",
    )
    require_text(
        plugin_root / "scripts/asr_start.sh",
        "--prompt-runtime-pid-review",
        "asr launcher optional runtime PID review prompt flag",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "--prompt-runtime-pid-review",
        "Claude skill optional runtime PID review prompt guidance",
    )
    require_text(
        plugin_root / "scripts/assert_finalized_workspace.py",
        "FINALIZATION INTEGRITY FAILED",
        "finalization integrity checker failure heading",
    )
    require_text(
        plugin_root / "scripts/audit_disposition.py",
        "state=confirmed requires confirmed_bundle_path",
        "audit disposition confirmed bundle gate",
    )
    require_text(
        plugin_root / "scripts/blocked_verification.py",
        "Docker Hub pull rate limit blocked runtime verification",
        "blocked verification Docker Hub recovery guidance",
    )
    require_text(
        plugin_root / "scripts/finalize_audit_workspace.py",
        "Blocked Docker/runtime verification prevents completed_no_confirmed_findings",
        "finalization blocks blocked verification no-confirmed success",
    )
    require_text(
        plugin_root / "scripts/finalize_audit_workspace.py",
        "zhulong_completion_summary_placeholder",
        "finalization writes stable summary placeholder",
    )
    require_text(
        plugin_root / "scripts/manage_docker_resources.py",
        "BuildKit cache blocker",
        "Docker strict BuildKit blocker messaging",
    )
    require_text(
        plugin_root / "assets/references/docker-resource-hygiene.md",
        "cannot be auto-deleted safely",
        "Docker hygiene BuildKit review-only blocker guidance",
    )
    require_text(
        plugin_root / "assets/references/docker-resource-hygiene.md",
        "Registry Fallback Guidance",
        "Docker hygiene registry fallback guidance",
    )
    require_text(
        plugin_root / "assets/references/document-output-stability.md",
        "Claude Code built-in `Documents` skill",
        "document-output-stability Documents skill rule",
    )
    require_text(
        plugin_root / "assets/references/java-web-audit-playbook.md",
        "source-to-sink",
        "Java Web playbook source-to-sink contract",
    )
    require_text(
        plugin_root / "assets/references/java-web-audit-playbook.md",
        "Minimum entry inventory fields",
        "Java Web playbook entry inventory contract",
    )
    require_text(
        plugin_root / "assets/references/java-web-audit-playbook.md",
        "Current Verification Status",
        "Java Web playbook verification status field",
    )
    require_text(
        plugin_root / "assets/references/go-web-audit-playbook.md",
        "source-to-sink",
        "Go Web playbook source-to-sink contract",
    )
    require_text(
        plugin_root / "assets/references/go-web-audit-playbook.md",
        "Minimum entry inventory fields",
        "Go Web playbook entry inventory contract",
    )
    require_text(
        plugin_root / "assets/references/go-web-audit-playbook.md",
        "Current Verification Status",
        "Go Web playbook verification status field",
    )
    node_library_playbook = plugin_root / "assets/references/nodejs-library-audit-playbook.md"
    for expected in (
        "Fast Model",
        "Minimum library inventory fields",
        "Public API / CLI",
        "Input Shape",
        "Caller-Controlled Options",
        "Transformation Path",
        "High-Risk Sink",
        "Consumer Impact Assumption",
        "Current Verification Status",
        "Source-To-Sink Tracing Guidance",
        "Docker-Only Verification Reminders",
        "Package metadata, API matches",
        "cannot confirm a vulnerability by",
        "verification_status=confirmed_in_docker",
        "OWASP Prototype Pollution Prevention Cheat Sheet",
    ):
        require_text(
            node_library_playbook,
            expected,
            f"Node.js Library playbook required text {expected}",
        )
    python_library_playbook = plugin_root / "assets/references/python-library-audit-playbook.md"
    for expected in (
        "Python Library / Framework Audit Playbook",
        "Minimum Python library inventory fields",
        "Public API / Hook",
        "Caller-Controlled Options",
        "Consumer Impact Assumption",
        "Source-To-Sink Tracing Guidance",
        "Docker-Only Verification Reminders",
        "Flask, Werkzeug, Jinja, Click",
        "Do not force a route / method / handler table",
        "cannot confirm a vulnerability by themselves",
        "verification_status=confirmed_in_docker",
    ):
        require_text(
            python_library_playbook,
            expected,
            f"Python Library playbook required text {expected}",
        )
    php_swoole_playbook = plugin_root / "assets/references/php-swoole-audit-playbook.md"
    for expected in (
        "PHP / Swoole Web Audit Playbook",
        "Minimum entry inventory fields",
        "Route / Command / Worker",
        "HTTP-exposed controllers from CLI-only",
        "curl_exec",
        "GraphQL",
        "Docker-Only Verification Reminders",
        "verification_status=confirmed_in_docker",
    ):
        require_text(
            php_swoole_playbook,
            expected,
            f"PHP/Swoole playbook required text {expected}",
        )
    registry_fallback = plugin_root / "assets/references/docker-registry-fallbacks.example.json"
    registry_data = json.loads(registry_fallback.read_text(encoding="utf-8"))
    if registry_data.get("policy", {}).get("configurable_not_hardcoded") is not True:
        raise SystemExit("FAILED: registry fallback example must be configurable, not hardcoded")
    for expected_field in (
        "original_image_ref",
        "attempted_image_ref",
        "registry_source",
        "final_digest",
        "failure_reason",
    ):
        if expected_field not in json.dumps(registry_data, ensure_ascii=False):
            raise SystemExit(f"FAILED: registry fallback example missing field: {expected_field}")
    for playbook in (
        "nodejs-web-audit-playbook.md",
        "python-web-audit-playbook.md",
    ):
        path = plugin_root / "assets/references" / playbook
        for expected in (
            "Fast Model",
            "Minimum entry inventory fields",
            "Route / Endpoint",
            "Method",
            "Handler / Controller",
            "Authentication Requirement",
            "Input Source",
            "Downstream Sink / Service",
            "Current Verification Status",
            "Source-To-Sink Tracing Guidance",
            "Docker-Only Verification Reminders",
            "Reference Sources",
            "cannot confirm a vulnerability by themselves",
            "not exhaustive and must not narrow exploration",
            "Do not generate DOCX reports from playbook hypotheses alone",
            "verification_status=confirmed_in_docker",
            "OWASP Web Security Testing Guide",
        ):
            require_text(
                path,
                expected,
                f"{playbook} required text {expected}",
            )
    require_text(
        plugin_root / "assets/references/python-web-audit-playbook.md",
        "Django REST framework viewsets",
        "Python Web playbook DRF authoritative source",
    )
    require_text(
        plugin_root / "assets/references/recommended-security-tooling.md",
        "Do not paste raw scanner logs into `attack-surface.md`",
        "recommended tooling attack-surface log-dump guardrail",
    )
    for checklist in (
        "ssrf-checklist.md",
        "path-traversal-checklist.md",
        "prototype-pollution-checklist.md",
    ):
        path = plugin_root / "assets/references" / checklist
        for section in (
            "Scope and When To Use It",
            "Common Sources",
            "High-Risk Sinks",
            "Source-To-Sink Tracing Hints",
            "Docker-Only Verification Ideas",
            "Severity-Escalation Evidence To Seek",
            "Common False Positives",
            "Confirmed-Only Routing Reminder",
        ):
            require_text(
                path,
                section,
                f"{checklist} section {section}",
            )
        require_text(
            path,
            "cannot confirm a vulnerability",
            f"{checklist} reasoning-only guardrail",
        )
        require_text(
            path,
            "Do not generate DOCX reports from this checklist alone",
            f"{checklist} no-DOCX guardrail",
        )
        require_text(
            path,
            "verification_status=confirmed_in_docker",
            f"{checklist} Docker-confirmed-only guardrail",
        )
    require_text(
        plugin_root / "assets/references/attacker-container-pattern.md",
        "Verification Runner Contract",
        "attacker container verification runner contract section",
    )
    require_text(
        plugin_root / "assets/references/attacker-container-pattern.md",
        "failed_timeout",
        "attacker container runner timeout label",
    )
    require_text(
        plugin_root / "assets/references/attacker-container-pattern.md",
        "resource limits are managed by the Compose files",
        "attacker container compose resource limit note",
    )
    require_text(
        plugin_root / "scripts/run_verification_case.sh",
        "STABLE_LABELS=\"blocked_docker_unavailable blocked_missing_image failed_timeout failed_resource_limit rejected_unsafe_sandbox rejected_not_reproducible confirmed_in_docker\"",
        "verification runner stable labels",
    )
    require_text(
        plugin_root / "scripts/run_initial_probes.sh",
        "PROBE_STATUS_LABELS=\"ran_ok skipped_tool_missing skipped_no_package_sources failed_nonfatal failed_fatal\"",
        "initial probes stable status labels",
    )
    require_text(
        plugin_root / "scripts/run_initial_probes.sh",
        "initial-probes-summary.json",
        "initial probes structured summary filename",
    )
    require_text(
        plugin_root / "scripts/run_initial_probes.sh",
        "No package sources found",
        "initial probes OSV no package sources classifier",
    )
    require_text(
        plugin_root / "scripts/run_initial_probes.sh",
        "--report-format json",
        "initial probes gitleaks JSON report mode",
    )
    require_text(
        plugin_root / "scripts/run_initial_probes.sh",
        "Full Secret and Match values are omitted",
        "initial probes gitleaks secret redaction contract",
    )
    require_text(
        plugin_root / "assets/references/python-web-audit-playbook.md",
        "Werkzeug Debugger / Gunicorn Verification Hint",
        "Python Web playbook Werkzeug debugger section",
    )
    require_text(
        plugin_root / "assets/references/python-web-audit-playbook.md",
        "WEB_CONCURRENCY=1",
        "Python Web playbook Gunicorn single-worker verification hint",
    )
    require_text(
        plugin_root / "assets/references/python-web-audit-playbook.md",
        "Never recommend enabling Flask/Werkzeug debugger",
        "Python Web playbook no production debugger guardrail",
    )
    require_text(
        plugin_root / "scripts/render_handoff_summary.py",
        "Heavy Logs To Avoid Unless Needed",
        "handoff renderer heavy-log avoidance heading",
    )
    require_text(
        plugin_root / "scripts/render_handoff_summary.py",
        "Confirmed-Only Routing Guardrails",
        "handoff renderer confirmed-only heading",
    )
    require_text(
        plugin_root / "scripts/render_handoff_summary.py",
        "Do not copy raw scanner logs into this handoff",
        "handoff renderer raw-log dump warning",
    )
    require_text(
        plugin_root / "scripts/run_verification_case.sh",
        "--timeout-seconds is required and must be positive",
        "verification runner mandatory timeout contract",
    )
    require_text(
        plugin_root / "scripts/run_verification_case.sh",
        "--memory \"$MEMORY_LIMIT\"",
        "verification runner memory limit",
    )
    require_text(
        plugin_root / "scripts/run_verification_case.sh",
        "--cpus \"$CPU_LIMIT\"",
        "verification runner CPU limit",
    )
    require_text(
        plugin_root / "scripts/run_verification_case.sh",
        "--pids-limit \"$PIDS_LIMIT\"",
        "verification runner pids limit",
    )
    require_text(
        plugin_root / "scripts/run_verification_case.sh",
        "--network \"$NETWORK\"",
        "verification runner explicit network",
    )
    require_text(
        plugin_root / "scripts/run_verification_case.sh",
        "managed_by_compose_file",
        "verification runner compose resource limit reporting",
    )
    forbid_text(
        plugin_root / "scripts/run_verification_case.sh",
        "stable_status_labels",
        "verification runner static labels in result json",
    )
    require_text(
        plugin_root / "scripts/run_verification_case.sh",
        "no host fallback is provided",
        "verification runner no-host-fallback contract",
    )
    forbid_text(
        plugin_root / "scripts/run_verification_case.sh",
        "may execute PoC logic directly on the host",
        "verification runner positive host execution wording",
    )
    operator_local_path = "/" + "Users" + "/" + "torchbearer"
    require_no_repo_text(plugin_root, operator_local_path, "operator-local absolute path")
    stale_asr_name = "autonomous-security" + "-researcher"
    require_no_repo_text(plugin_root, stale_asr_name, "stale ASR naming")
    require_text(
        plugin_root / "assets/references/claude-code-invocation-template.md",
        "severity-escalation pass",
        "Claude invocation template severity escalation contract",
    )
    require_text(
        plugin_root / "assets/references/claude-code-invocation-template.md",
        "Do not execute `web_search`",
        "Claude invocation template web lookup shell-safety contract",
    )
    require_text(
        plugin_root / "assets/references/claude-code-invocation-template.md",
        "Do not produce a thin report",
        "Claude invocation template report-depth contract",
    )
    require_text(
        plugin_root / "assets/references/claude-code-invocation-template.md",
        "exactly one vulnerability",
        "Claude invocation template one-finding-per-bundle contract",
    )
    canonical_prompt = plugin_root / "assets" / "references" / "claude-code-invocation-template.md"
    root_prompt = plugin_root.parent.parent / "claude-code-zhulong-prompt-template.md"
    if root_prompt.exists() and canonical_prompt.read_text(encoding="utf-8") != root_prompt.read_text(encoding="utf-8"):
        raise SystemExit(
            "FAILED: root prompt template is out of sync with the canonical plugin invocation template. "
            "Run scripts/sync_to_claude_skill.sh --sync-root-prompt-template or resync the repository prompt copy."
        )

    run([sys.executable, "-m", "py_compile",
         str(plugin_root / "scripts/plan_security_toolchain.py"),
         str(plugin_root / "scripts/render_handoff_summary.py"),
         str(plugin_root / "scripts/assert_finalized_workspace.py"),
         str(plugin_root / "scripts/audit_disposition.py"),
         str(plugin_root / "scripts/blocked_verification.py"),
         str(plugin_root / "scripts/write_audit_event.py"),
         str(plugin_root / "scripts/validate_workspace_state.py"),
         str(plugin_root / "scripts/check_sandbox_preflight.py"),
         str(plugin_root / "scripts/manage_docker_resources.py"),
         str(plugin_root / "scripts/render_confirmed_vuln_docx.py"),
         str(plugin_root / "scripts/scaffold_bilingual_findings.py"),
         str(plugin_root / "scripts/validate_report_bundle.py"),
         str(plugin_root / "scripts/validate_all_report_bundles.py"),
         str(plugin_root / "scripts/finalize_audit_workspace.py")], plugin_root)

    run(["bash", "-n", str(plugin_root / "scripts/bootstrap_verification_workspace.sh")], plugin_root)
    run(["bash", "-n", str(plugin_root / "scripts/asr_start.sh")], plugin_root)
    run(["bash", "-n", str(plugin_root / "scripts/prepare_target_repo.sh")], plugin_root)
    run(["bash", "-n", str(plugin_root / "scripts/check_docker_gate.sh")], plugin_root)
    run(["bash", "-n", str(plugin_root / "scripts/check_omc_runtime.sh")], plugin_root)
    run(["bash", "-n", str(plugin_root / "scripts/check_security_tooling.sh")], plugin_root)
    run(["bash", "-n", str(plugin_root / "scripts/run_initial_probes.sh")], plugin_root)
    run(["bash", "-n", str(plugin_root / "scripts/run_verification_case.sh")], plugin_root)
    run(["bash", "-n", str(plugin_root / "scripts/refresh_workspace_helpers.sh")], plugin_root)
    run(["bash", "-n", str(plugin_root / "scripts/sync_to_claude_skill.sh")], plugin_root)
    run(["bash", str(plugin_root / "scripts/run_verification_case.sh"), "--help"], plugin_root)
    run([sys.executable, str(plugin_root / "scripts/manage_docker_resources.py"), "--help"], plugin_root)
    run([sys.executable, str(plugin_root / "scripts/render_handoff_summary.py"), "--help"], plugin_root)
    run([sys.executable, str(plugin_root / "scripts/assert_finalized_workspace.py"), "--help"], plugin_root)
    run([sys.executable, str(plugin_root / "scripts/finalize_audit_workspace.py"), "--help"], plugin_root)
    require_text(
        plugin_root / "scripts/manage_docker_resources.py",
        '"image", "ls", "-a", "--no-trunc"',
        "Docker cleanup helper snapshots dangling images",
    )

    with tempfile.TemporaryDirectory(prefix="asr-plugin-selftest-") as tempdir:
        repo_dir = Path(tempdir) / "repo"
        repo_dir.mkdir(parents=True, exist_ok=True)
        workspace_name = "security-research-selftest"
        run([
            "bash",
            str(plugin_root / "scripts/bootstrap_verification_workspace.sh"),
            "--target-dir",
            str(repo_dir),
            "--workspace-name",
            workspace_name,
        ], plugin_root)
        workspace = repo_dir / workspace_name
        if not (workspace / "bin/check_security_tooling.sh").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing check_security_tooling.sh")
        if not (workspace / "bin/check-docker-gate.sh").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing check-docker-gate.sh")
        if not (workspace / "bin/run-initial-probes.sh").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing run-initial-probes.sh")
        if not (workspace / "bin/run-verification-case.sh").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing run-verification-case.sh")
        if not (workspace / "bin/check-sandbox-preflight.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing check-sandbox-preflight.py")
        if not (workspace / "bin/manage-docker-resources.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing manage-docker-resources.py")
        if not (workspace / "bin/render-handoff-summary.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing render-handoff-summary.py")
        if not (workspace / "bin/assert-finalized-workspace.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing assert-finalized-workspace.py")
        if not (workspace / "bin/blocked_verification.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing blocked_verification.py")
        if not (workspace / "bin/audit_disposition.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing audit_disposition.py")
        if not (workspace / "scripts/render-handoff-summary.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing scripts/render-handoff-summary.py")
        if not (workspace / "scripts/assert-finalized-workspace.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing scripts/assert-finalized-workspace.py")
        if not (workspace / "handoff-summary.md").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing handoff-summary.md")
        require_text(
            workspace / "handoff-summary.md",
            "<!-- schema_version: 1 -->",
            "bootstrapped handoff schema version marker",
        )
        require_text(
            workspace / "handoff-summary.md",
            "It is not a vulnerability report",
            "bootstrapped handoff non-report disclaimer",
        )
        for heading in (
            "Target and Workspace",
            "Current Stage / Status",
            "Recommended First Reads",
            "Context-Slimming Rules",
            "Attack-Surface Highlights",
            "Initial Probe Summary",
            "Blocked Verification Status",
            "Audit Disposition Ledger",
            "Candidate Findings",
            "False Positives / Non-Security Defects",
            "Unverified Leads",
            "Confirmed Bundle Pointers",
            "Heavy Logs To Avoid Unless Needed",
            "Next Safe Steps",
            "Confirmed-Only Routing Guardrails",
        ):
            require_text(
                workspace / "handoff-summary.md",
                heading,
                f"bootstrapped handoff heading {heading}",
            )
        require_text(
            workspace / "handoff-summary.md",
            "Read lightweight files first",
            "bootstrapped handoff context-slimming rule",
        )
        require_text(
            workspace / "handoff-summary.md",
            "Avoid default-reading full raw logs",
            "bootstrapped handoff raw-log avoidance rule",
        )
        require_text(
            workspace / "handoff-summary.md",
            "Confirmed vulnerabilities belong only under `confirmed/<one-folder-per-vulnerability>/`",
            "bootstrapped handoff confirmed-only guardrail",
        )
        require_text(
            workspace / "handoff-summary.md",
            "Finalization integrity: `not_finalized`",
            "bootstrapped handoff finalization integrity state",
        )

        docker_baseline = workspace / "docker" / "baseline-fixture.json"
        docker_current = workspace / "docker" / "current-fixture.json"
        docker_baseline.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "captured_at": "2026-04-28T00:00:00Z",
                    "docker_available": True,
                    "images": [{"id": "sha256:base", "repository": "node", "tag": "20-alpine"}],
                    "volumes": [{"name": "existing-volume", "driver": "local"}],
                    "networks": [{"id": "net0", "name": "bridge", "driver": "bridge"}],
                    "containers": [{"id": "container0", "name": "existing", "state": "exited"}],
                    "build_cache": [{"id": "cache0", "reclaimable": True, "size": "1MB"}],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        docker_current.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "captured_at": "2026-04-28T00:10:00Z",
                    "docker_available": True,
                    "images": [
                        {"id": "sha256:base", "repository": "node", "tag": "20-alpine"},
                        {
                            "id": "sha256:new",
                            "repository": "target-app",
                            "tag": "latest",
                            "labels": {
                                "org.zhulong.managed": "true",
                                "org.zhulong.workspace": workspace_name,
                            },
                        },
                        {
                            "id": "sha256:foreign",
                            "repository": "other-app",
                            "tag": "latest",
                            "labels": {
                                "org.zhulong.managed": "true",
                                "org.zhulong.workspace": "security-research-other",
                            },
                        },
                        {
                            "id": "sha256:projectonly",
                            "repository": "project-only-app",
                            "tag": "latest",
                            "labels": {"com.zhulong.project": workspace_name},
                        },
                        {
                            "id": "sha256:legacy",
                            "repository": "starlette-verify",
                            "tag": "zhulong",
                            "labels": {"com.zhulong.workspace": workspace_name},
                        },
                        {
                            "id": "sha256:compose",
                            "repository": "<none>",
                            "tag": "<none>",
                            "labels": {"com.docker.compose.project": "zhulong-test-compose"},
                        },
                        {"id": "sha256:compose-pulled", "repository": "mysql", "tag": "5.7"},
                        {"id": "sha256:unlabeled", "repository": "parallel-app", "tag": "latest"},
                    ],
                    "volumes": [
                        {"name": "existing-volume", "driver": "local"},
                        {
                            "name": "target-created-volume",
                            "driver": "local",
                            "labels": {
                                "org.zhulong.managed": "true",
                                "org.zhulong.workspace": workspace_name,
                            },
                        },
                        {
                            "name": "target-compose-volume",
                            "driver": "local",
                            "labels": {"com.docker.compose.project": "zhulong-test-compose"},
                        },
                        {
                            "name": "legacy-labeled-volume",
                            "driver": "local",
                            "labels": {"com.zhulong.workspace": workspace_name},
                        },
                        {
                            "name": "project-only-volume",
                            "driver": "local",
                            "labels": {"com.zhulong.project": workspace_name},
                        },
                        {"name": "parallel-created-volume", "driver": "local"},
                    ],
                    "networks": [
                        {"id": "net0", "name": "bridge", "driver": "bridge"},
                        {
                            "id": "net1",
                            "name": "target-created-network",
                            "driver": "bridge",
                            "labels": {
                                "org.zhulong.managed": "true",
                                "org.zhulong.workspace": workspace_name,
                            },
                        },
                        {
                            "id": "net3",
                            "name": "target-compose-network",
                            "driver": "bridge",
                            "labels": {"com.docker.compose.project": "zhulong-test-compose"},
                        },
                        {
                            "id": "net4",
                            "name": "legacy-labeled-network",
                            "driver": "bridge",
                            "labels": {"com.zhulong.workspace": workspace_name},
                        },
                        {
                            "id": "net5",
                            "name": "project-only-network",
                            "driver": "bridge",
                            "labels": {"com.zhulong.project": workspace_name},
                        },
                        {"id": "net2", "name": "parallel-created-network", "driver": "bridge"},
                    ],
                    "containers": [
                        {"id": "container0", "name": "existing", "state": "exited"},
                        {
                            "id": "container1",
                            "name": "target-stopped",
                            "state": "exited",
                            "labels": {
                                "org.zhulong.managed": "true",
                                "org.zhulong.workspace": workspace_name,
                            },
                        },
                        {
                            "id": "container2",
                            "name": "target-running",
                            "state": "running",
                            "labels": {
                                "org.zhulong.managed": "true",
                                "org.zhulong.workspace": workspace_name,
                            },
                        },
                        {
                            "id": "container6",
                            "name": "legacy-labeled-stopped",
                            "state": "exited",
                            "labels": {"com.zhulong.workspace": workspace_name},
                        },
                        {
                            "id": "container5",
                            "name": "target-compose-stopped",
                            "state": "exited",
                            "labels": {"com.docker.compose.project": "zhulong-test-compose"},
                        },
                        {
                            "id": "container3",
                            "name": "other-zhulong-stopped",
                            "state": "exited",
                            "labels": {
                                "org.zhulong.managed": "true",
                                "org.zhulong.workspace": "security-research-other",
                            },
                        },
                        {
                            "id": "container7",
                            "name": "project-only-stopped",
                            "state": "exited",
                            "labels": {"com.zhulong.project": workspace_name},
                        },
                        {"id": "container4", "name": "parallel-unlabeled-stopped", "state": "exited"},
                    ],
                    "build_cache": [
                        {"id": "cache0", "reclaimable": True, "size": "1MB"},
                        {"id": "cache1", "reclaimable": True, "size": "2MB"},
                        {"id": "cache2", "reclaimable": False, "size": "3MB"},
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        run([
            sys.executable,
            str(plugin_root / "scripts/manage_docker_resources.py"),
            "--workspace-dir",
            str(workspace),
            "--baseline-file",
            str(docker_baseline),
            "--current-file",
            str(docker_current),
            "--show-created",
        ], plugin_root)
        cleanup_plan = json.loads((workspace / "docker" / "docker-cleanup-plan.json").read_text(encoding="utf-8"))
        if cleanup_plan.get("safety_policy", {}).get("uses_docker_prune") is not False:
            raise SystemExit("FAILED: Docker cleanup helper must not use broad prune semantics")
        if cleanup_plan.get("safety_policy", {}).get("delete_unowned_resources") is not False:
            raise SystemExit("FAILED: Docker cleanup helper must not delete unowned resources")
        planned_images = {item.get("id") for item in cleanup_plan.get("images", [])}
        if planned_images != {"sha256:new", "sha256:legacy"}:
            raise SystemExit(f"FAILED: Docker cleanup image plan should only include owned new image: {planned_images}")
        planned_volumes = {item.get("name") for item in cleanup_plan.get("volumes", [])}
        if planned_volumes != {"target-created-volume", "legacy-labeled-volume"}:
            raise SystemExit(f"FAILED: Docker cleanup volume plan should only include owned new volume: {planned_volumes}")
        planned_networks = {item.get("name") for item in cleanup_plan.get("networks", [])}
        if planned_networks != {"target-created-network", "legacy-labeled-network"}:
            raise SystemExit(f"FAILED: Docker cleanup network plan should only include owned new non-default network: {planned_networks}")
        running_skipped = {item.get("name") for item in cleanup_plan.get("containers", {}).get("running_owned_skipped", [])}
        if running_skipped != {"target-running"}:
            raise SystemExit("FAILED: Docker cleanup helper must skip running containers by default")
        planned_containers = {item.get("name") for item in cleanup_plan.get("containers", {}).get("stopped_owned", [])}
        if planned_containers != {"target-stopped", "legacy-labeled-stopped"}:
            raise SystemExit(f"FAILED: Docker cleanup should only remove owned stopped containers: {planned_containers}")
        skipped_containers = {item.get("name") for item in cleanup_plan.get("containers", {}).get("unattributed_new_skipped", [])}
        if skipped_containers != {"other-zhulong-stopped", "parallel-unlabeled-stopped", "project-only-stopped", "target-compose-stopped"}:
            raise SystemExit(f"FAILED: Docker cleanup must skip foreign/unlabeled containers: {skipped_containers}")
        skipped_images = {item.get("id") for item in cleanup_plan.get("unattributed_new_skipped", {}).get("images", [])}
        if skipped_images != {"sha256:foreign", "sha256:projectonly", "sha256:unlabeled", "sha256:compose", "sha256:compose-pulled"}:
            raise SystemExit(f"FAILED: Docker cleanup must skip foreign/unlabeled images: {skipped_images}")
        skipped_volumes = {item.get("name") for item in cleanup_plan.get("unattributed_new_skipped", {}).get("volumes", [])}
        if skipped_volumes != {"parallel-created-volume", "project-only-volume", "target-compose-volume"}:
            raise SystemExit(f"FAILED: Docker cleanup must skip unlabeled volumes: {skipped_volumes}")
        skipped_networks = {item.get("name") for item in cleanup_plan.get("unattributed_new_skipped", {}).get("networks", [])}
        if skipped_networks != {"parallel-created-network", "project-only-network", "target-compose-network"}:
            raise SystemExit(f"FAILED: Docker cleanup must skip unlabeled networks: {skipped_networks}")
        run([
            sys.executable,
            str(plugin_root / "scripts/manage_docker_resources.py"),
            "--workspace-dir",
            str(workspace),
            "--baseline-file",
            str(docker_baseline),
            "--current-file",
            str(docker_current),
            "--show-created",
            "--adopt-compose-project",
            "zhulong-*",
            "--adopt-image-ref",
            "*",
            "--adopt-network-name",
            "parallel-*",
            "--adopt-volume-name",
            "parallel-*",
            "--adopt-build-cache",
            "--adopt-build-cache-id",
            "cache*",
        ], plugin_root)
        cleanup_plan = json.loads((workspace / "docker" / "docker-cleanup-plan.json").read_text(encoding="utf-8"))
        planned_images = {item.get("id") for item in cleanup_plan.get("images", [])}
        planned_volumes = {item.get("name") for item in cleanup_plan.get("volumes", [])}
        planned_networks = {item.get("name") for item in cleanup_plan.get("networks", [])}
        planned_build_cache = {item.get("id") for item in cleanup_plan.get("build_cache", {}).get("adopted_reclaimable", [])}
        if (
            planned_images != {"sha256:new", "sha256:legacy"}
            or planned_volumes != {"target-created-volume", "legacy-labeled-volume"}
            or planned_networks != {"target-created-network", "legacy-labeled-network"}
            or planned_build_cache
        ):
            raise SystemExit("FAILED: Docker adoption flags must use exact literal matches, not wildcard/prefix semantics")
        run([
            sys.executable,
            str(plugin_root / "scripts/manage_docker_resources.py"),
            "--workspace-dir",
            str(workspace),
            "--baseline-file",
            str(docker_baseline),
            "--current-file",
            str(docker_current),
            "--show-created",
            "--adopt-compose-project",
            "zhulong-test-compose",
            "--adopt-image-ref",
            "node:20-alpine",
            "--adopt-image-ref",
            "mysql:5.7",
            "--adopt-build-cache",
            "--adopt-build-cache-id",
            "cache1",
            "--adopt-volume-name",
            "existing-volume",
            "--adopt-network-name",
            "parallel-created-network",
            "--adopt-volume-name",
            "parallel-created-volume",
        ], plugin_root)
        cleanup_plan = json.loads((workspace / "docker" / "docker-cleanup-plan.json").read_text(encoding="utf-8"))
        planned_images = {item.get("id") for item in cleanup_plan.get("images", [])}
        if planned_images != {"sha256:new", "sha256:legacy", "sha256:compose", "sha256:compose-pulled"}:
            raise SystemExit(f"FAILED: adopted compose/image resources should enter cleanup image plan: {planned_images}")
        planned_volumes = {item.get("name") for item in cleanup_plan.get("volumes", [])}
        if planned_volumes != {"target-created-volume", "legacy-labeled-volume", "target-compose-volume", "parallel-created-volume"}:
            raise SystemExit(f"FAILED: adopted compose/exact resources should enter cleanup volume plan: {planned_volumes}")
        planned_networks = {item.get("name") for item in cleanup_plan.get("networks", [])}
        if planned_networks != {"target-created-network", "legacy-labeled-network", "target-compose-network", "parallel-created-network"}:
            raise SystemExit(f"FAILED: adopted compose/exact resources should enter cleanup network plan: {planned_networks}")
        planned_containers = {item.get("name") for item in cleanup_plan.get("containers", {}).get("stopped_owned", [])}
        if planned_containers != {"target-stopped", "legacy-labeled-stopped", "target-compose-stopped"}:
            raise SystemExit(f"FAILED: adopted compose containers should enter cleanup plan: {planned_containers}")
        planned_build_cache = {item.get("id") for item in cleanup_plan.get("build_cache", {}).get("adopted_reclaimable", [])}
        if planned_build_cache != {"cache1"}:
            raise SystemExit(f"FAILED: adopted build cache should enter cleanup plan: {planned_build_cache}")
        run([
            sys.executable,
            str(plugin_root / "scripts/manage_docker_resources.py"),
            "--workspace-dir",
            str(workspace),
            "--baseline-file",
            str(docker_baseline),
            "--current-file",
            str(docker_current),
            "--show-created",
            "--adopt-build-cache",
        ], plugin_root)
        cleanup_plan = json.loads((workspace / "docker" / "docker-cleanup-plan.json").read_text(encoding="utf-8"))
        if cleanup_plan.get("build_cache", {}).get("adopted_reclaimable"):
            raise SystemExit("FAILED: BuildKit cache adoption must require explicit cache IDs")
        skipped_build_cache = {item.get("id") for item in cleanup_plan.get("build_cache", {}).get("unattributed_new_skipped", [])}
        if skipped_build_cache != {"cache1"}:
            raise SystemExit(f"FAILED: unattributed BuildKit cache should remain review-only without exact IDs: {skipped_build_cache}")
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/manage_docker_resources.py"),
            "--workspace-dir",
            str(workspace),
            "--baseline-file",
            str(docker_baseline),
            "--current-file",
            str(docker_current),
            "--show-created",
            "--adopt-build-cache-id",
            "cache1",
        ], plugin_root, "--adopt-build-cache-id requires --adopt-build-cache")

        def docker_overwrite_fixture(
            name: str,
            *,
            images: list[dict[str, object]] | None = None,
            volumes: list[dict[str, object]] | None = None,
            networks: list[dict[str, object]] | None = None,
            containers: list[dict[str, object]] | None = None,
            build_cache: list[dict[str, object]] | None = None,
        ) -> Path:
            path = workspace / "docker" / f"{name}.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "captured_at": "2026-04-28T00:15:00Z",
                        "docker_available": True,
                        "images": [
                            {"id": "sha256:base", "repository": "node", "tag": "20-alpine"},
                            *(images or []),
                        ],
                        "volumes": [
                            {"name": "existing-volume", "driver": "local"},
                            *(volumes or []),
                        ],
                        "networks": [
                            {"id": "net0", "name": "bridge", "driver": "bridge"},
                            *(networks or []),
                        ],
                        "containers": [
                            {"id": "container0", "name": "existing", "state": "exited"},
                            *(containers or []),
                        ],
                        "build_cache": [
                            {"id": "cache0", "reclaimable": True, "size": "1MB"},
                            *(build_cache or []),
                        ],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            return path

        overwrite_owned_image = docker_overwrite_fixture(
            "current-overwrite-owned-image",
            images=[
                {
                    "id": "sha256:owned-overwrite",
                    "repository": "owned-overwrite",
                    "tag": "latest",
                    "labels": {
                        "org.zhulong.managed": "true",
                        "org.zhulong.workspace": workspace_name,
                    },
                }
            ],
        )
        overwrite_unlabeled_image = docker_overwrite_fixture(
            "current-overwrite-unlabeled-image",
            images=[{"id": "sha256:unlabeled-overwrite", "repository": "unlabeled-overwrite", "tag": "latest"}],
        )
        overwrite_unlabeled_network_volume = docker_overwrite_fixture(
            "current-overwrite-unlabeled-network-volume",
            volumes=[{"name": "unlabeled-overwrite-volume", "driver": "local"}],
            networks=[{"id": "net-overwrite", "name": "unlabeled-overwrite-network", "driver": "bridge"}],
        )
        overwrite_build_cache = docker_overwrite_fixture(
            "current-overwrite-build-cache",
            build_cache=[{"id": "cache-overwrite", "reclaimable": True, "size": "2MB"}],
        )
        for overwrite_current in (
            overwrite_owned_image,
            overwrite_unlabeled_image,
            overwrite_unlabeled_network_volume,
            overwrite_build_cache,
        ):
            run_expect_fail([
                sys.executable,
                str(plugin_root / "scripts/manage_docker_resources.py"),
                "--workspace-dir",
                str(workspace),
                "--baseline-file",
                str(docker_baseline),
                "--current-file",
                str(overwrite_current),
                "--capture-baseline",
                "--force-overwrite-baseline",
            ], plugin_root, "hide Docker residue from strict cleanliness checks")
        cleanup_plan = json.loads((workspace / "docker" / "docker-cleanup-plan.json").read_text(encoding="utf-8"))
        skipped_build_cache = {
            item.get("id")
            for item in cleanup_plan.get("build_cache", {}).get("unattributed_new_skipped", [])
        }
        if skipped_build_cache != {"cache-overwrite"}:
            raise SystemExit(f"FAILED: baseline overwrite refusal must record BuildKit cache residue: {skipped_build_cache}")
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/manage_docker_resources.py"),
            "--workspace-dir",
            str(workspace),
            "--baseline-file",
            str(docker_baseline),
            "--current-file",
            str(docker_current),
            "--capture-baseline",
            "--force-overwrite-baseline",
        ], plugin_root, "Refusing to overwrite Docker baseline while post-baseline resources remain")
        run([
            sys.executable,
            str(plugin_root / "scripts/manage_docker_resources.py"),
            "--workspace-dir",
            str(workspace),
            "--baseline-file",
            str(docker_baseline),
            "--current-file",
            str(docker_current),
            "--cleanup-created",
        ], plugin_root)
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/manage_docker_resources.py"),
            "--workspace-dir",
            str(workspace),
            "--baseline-file",
            str(docker_baseline),
            "--current-file",
            str(docker_current),
            "--verify-clean",
        ], plugin_root, "owned Docker resources remain")
        cleanliness_status = json.loads((workspace / "docker" / "docker-cleanliness-status.json").read_text(encoding="utf-8"))
        if cleanliness_status.get("clean") is not False:
            raise SystemExit("FAILED: Docker verify-clean must fail when owned resources remain")
        docker_clean_current = workspace / "docker" / "current-clean-fixture.json"
        docker_clean_current.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "captured_at": "2026-04-28T00:20:00Z",
                    "docker_available": True,
                    "images": [
                        {"id": "sha256:base", "repository": "node", "tag": "20-alpine"},
                        {"id": "sha256:foreign", "repository": "other-app", "tag": "latest"},
                    ],
                    "volumes": [
                        {"name": "existing-volume", "driver": "local"},
                        {"name": "parallel-created-volume", "driver": "local"},
                    ],
                    "networks": [
                        {"id": "net0", "name": "bridge", "driver": "bridge"},
                        {"id": "net2", "name": "parallel-created-network", "driver": "bridge"},
                    ],
                    "containers": [
                        {"id": "container0", "name": "existing", "state": "exited"},
                        {"id": "container4", "name": "parallel-unlabeled-stopped", "state": "exited"},
                    ],
                    "build_cache": [
                        {"id": "cache0", "reclaimable": True, "size": "1MB"},
                        {"id": "cache3", "reclaimable": True, "size": "2MB"},
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        run([
            sys.executable,
            str(plugin_root / "scripts/manage_docker_resources.py"),
            "--workspace-dir",
            str(workspace),
            "--baseline-file",
            str(docker_baseline),
            "--current-file",
            str(docker_clean_current),
            "--verify-clean",
        ], plugin_root)
        cleanliness_status = json.loads((workspace / "docker" / "docker-cleanliness-status.json").read_text(encoding="utf-8"))
        if cleanliness_status.get("clean") is not True:
            raise SystemExit("FAILED: Docker verify-clean must pass when no current-workspace owned resources remain")
        strict_blocker_proc = subprocess.run([
            sys.executable,
            str(plugin_root / "scripts/manage_docker_resources.py"),
            "--workspace-dir",
            str(workspace),
            "--baseline-file",
            str(docker_baseline),
            "--current-file",
            str(docker_clean_current),
            "--verify-clean",
            "--strict",
        ], cwd=plugin_root, capture_output=True, text=True)
        strict_blocker_output = (strict_blocker_proc.stdout or "") + (strict_blocker_proc.stderr or "")
        if strict_blocker_proc.returncode == 0:
            raise SystemExit("FAILED: Docker strict verify-clean unexpectedly passed on post-baseline unattributed resources")
        for expected in (
            "unattributed Docker resources remain",
            "BuildKit cache blocker",
            "review-only and cannot be auto-deleted safely",
            "must remain blocked",
            "must not manually mark the audit completed",
            "--adopt-build-cache --adopt-build-cache-id <cache-id>",
        ):
            if expected not in strict_blocker_output:
                raise SystemExit(f"FAILED: Docker strict BuildKit blocker output missing: {expected}")
        cleanliness_status = json.loads((workspace / "docker" / "docker-cleanliness-status.json").read_text(encoding="utf-8"))
        if cleanliness_status.get("clean") is not False or cleanliness_status.get("strict") is not True:
            raise SystemExit("FAILED: Docker strict verify-clean must fail on post-baseline unattributed resources")
        docker_strict_clean_current = workspace / "docker" / "current-strict-clean-fixture.json"
        docker_strict_clean_current.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "captured_at": "2026-04-28T00:30:00Z",
                    "docker_available": True,
                    "images": [{"id": "sha256:base", "repository": "node", "tag": "20-alpine"}],
                    "volumes": [{"name": "existing-volume", "driver": "local"}],
                    "networks": [{"id": "net0", "name": "bridge", "driver": "bridge"}],
                    "containers": [{"id": "container0", "name": "existing", "state": "exited"}],
                    "build_cache": [{"id": "cache0", "reclaimable": True, "size": "1MB"}],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        run([
            sys.executable,
            str(plugin_root / "scripts/manage_docker_resources.py"),
            "--workspace-dir",
            str(workspace),
            "--baseline-file",
            str(docker_baseline),
            "--current-file",
            str(docker_strict_clean_current),
            "--verify-clean",
            "--strict",
        ], plugin_root)
        cleanliness_status = json.loads((workspace / "docker" / "docker-cleanliness-status.json").read_text(encoding="utf-8"))
        if cleanliness_status.get("clean") is not True or cleanliness_status.get("strict") is not True:
            raise SystemExit("FAILED: Docker strict verify-clean must pass when the Docker state matches the baseline")
        docker_overwrite_success_baseline = workspace / "docker" / "baseline-overwrite-success.json"
        docker_overwrite_success_baseline.write_text(docker_baseline.read_text(encoding="utf-8"), encoding="utf-8")
        run([
            sys.executable,
            str(plugin_root / "scripts/manage_docker_resources.py"),
            "--workspace-dir",
            str(workspace),
            "--baseline-file",
            str(docker_overwrite_success_baseline),
            "--current-file",
            str(docker_strict_clean_current),
            "--capture-baseline",
            "--force-overwrite-baseline",
        ], plugin_root)
        overwritten_baseline = json.loads(docker_overwrite_success_baseline.read_text(encoding="utf-8"))
        if overwritten_baseline.get("captured_at") != "2026-04-28T00:30:00Z":
            raise SystemExit("FAILED: force-overwrite baseline should succeed only after current state matches baseline residue-free")
        require_text(
            workspace / "handoff-summary.md",
            "Do not generate DOCX reports from handoff content",
            "bootstrapped handoff no-DOCX guardrail",
        )
        require_text(
            workspace / "handoff-summary.md",
            "Do not copy raw scanner logs into this handoff",
            "bootstrapped handoff raw-log dump warning",
        )
        if not (workspace / "scripts/run-verification-case.sh").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing scripts/run-verification-case.sh")
        if not (workspace / "bin/asr-start.sh").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing asr-start.sh")
        fake_bin = Path(tempdir) / "fake-bin"
        fake_bin.mkdir(parents=True, exist_ok=True)
        fake_osv = fake_bin / "osv-scanner"
        fake_osv.write_text(
            "#!/usr/bin/env bash\n"
            "echo 'No package sources found'\n"
            "exit 128\n",
            encoding="utf-8",
        )
        fake_osv.chmod(0o755)
        fake_gitleaks = fake_bin / "gitleaks"
        fake_gitleaks.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "report_path=''\n"
            "while [[ $# -gt 0 ]]; do\n"
            "  case \"$1\" in\n"
            "    --report-path)\n"
            "      report_path=\"${2:-}\"\n"
            "      shift 2\n"
            "      ;;\n"
            "    *)\n"
            "      shift\n"
            "      ;;\n"
            "  esac\n"
            "done\n"
            "[[ -n \"$report_path\" ]] || exit 64\n"
            "cat >\"$report_path\" <<'JSON'\n"
            "[\n"
            "  {\n"
            "    \"RuleID\": \"generic-api-key\",\n"
            "    \"Description\": \"Generic API Key\",\n"
            "    \"File\": \"config/example.env\",\n"
            "    \"StartLine\": 3,\n"
            "    \"Commit\": \"abcdef1234567890\",\n"
            "    \"Secret\": \"sk_live_SUPER_SECRET_VALUE_123456\",\n"
            "    \"Match\": \"API_KEY=sk_live_SUPER_SECRET_VALUE_123456\"\n"
            "  },\n"
            "  {\n"
            "    \"RuleID\": \"private-key\",\n"
            "    \"Description\": \"Private Key\",\n"
            "    \"File\": \"tests/fixtures/key.pem\",\n"
            "    \"StartLine\": 1,\n"
            "    \"Secret\": \"-----BEGIN PRIVATE KEY-----FAKESECRET-----END PRIVATE KEY-----\"\n"
            "  }\n"
            "]\n"
            "JSON\n"
            "echo 'leaks found: 2'\n"
            "exit 1\n",
            encoding="utf-8",
        )
        fake_gitleaks.chmod(0o755)
        fake_trivy = fake_bin / "trivy"
        fake_trivy.write_text(
            "#!/usr/bin/env bash\n"
            "echo 'simulated scanner failure for nonfatal classification' >&2\n"
            "exit 2\n",
            encoding="utf-8",
        )
        fake_trivy.chmod(0o755)
        fake_grype = fake_bin / "grype"
        fake_grype.write_text(
            "#!/usr/bin/env bash\n"
            "echo 'simulated command execution failure for fatal classification' >&2\n"
            "exit 127\n",
            encoding="utf-8",
        )
        fake_grype.chmod(0o755)
        probe_env = {
            **dict(),
            "PATH": f"{fake_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(Path.home()),
        }
        run_with_env([
            "/bin/bash",
            str(workspace / "bin/run-initial-probes.sh"),
            "--repo-root",
            str(repo_dir),
            "--workspace-dir",
            str(workspace),
        ], plugin_root, probe_env)
        initial_summary = workspace / "evidence/initial-probes/initial-probes-summary.json"
        if not initial_summary.exists():
            raise SystemExit("FAILED: run_initial_probes did not write initial-probes-summary.json")
        summary_data = json.loads(initial_summary.read_text(encoding="utf-8"))
        for field in ("schema_version", "generated_at", "repo_root", "workspace_dir", "output_dir", "probes"):
            if field not in summary_data:
                raise SystemExit(f"FAILED: initial-probes-summary.json is missing {field}")
        labels = set(summary_data.get("stable_status_labels") or [])
        expected_labels = {"ran_ok", "skipped_tool_missing", "skipped_no_package_sources", "failed_nonfatal", "failed_fatal"}
        if labels != expected_labels:
            raise SystemExit(f"FAILED: initial probe stable labels mismatch: {sorted(labels)}")
        probes = summary_data.get("probes") or []
        if not isinstance(probes, list) or not probes:
            raise SystemExit("FAILED: initial-probes-summary.json probes must be a non-empty list")
        by_name = {probe.get("name"): probe for probe in probes}
        require_probe_record(
            initial_summary,
            workspace / "evidence/initial-probes",
            "osv-scanner",
            "skipped_no_package_sources",
            128,
            "no supported package lockfile",
            "exited non-zero",
        )
        if by_name.get("semgrep", {}).get("status") != "skipped_tool_missing":
            raise SystemExit("FAILED: missing semgrep was not classified as skipped_tool_missing")
        gitleaks_probe = by_name.get("gitleaks", {})
        if gitleaks_probe.get("status") != "failed_nonfatal":
            raise SystemExit("FAILED: gitleaks leak-found exit was not classified as failed_nonfatal")
        if gitleaks_probe.get("exit_code") != 1:
            raise SystemExit("FAILED: gitleaks leak-found exit code was not preserved")
        gitleaks_summary = gitleaks_probe.get("summary") or {}
        if gitleaks_summary.get("finding_count") != 2:
            raise SystemExit("FAILED: gitleaks summary did not preserve finding_count")
        samples = gitleaks_summary.get("sample_findings") or []
        if not (2 <= len(samples) <= 5):
            raise SystemExit("FAILED: gitleaks summary samples were not captured")
        if samples[0].get("rule_id") != "generic-api-key" or samples[0].get("file") != "config/example.env":
            raise SystemExit("FAILED: gitleaks summary did not include actionable metadata")
        summary_text = json.dumps(gitleaks_probe, ensure_ascii=False)
        for forbidden_secret in (
            "sk_live_SUPER_SECRET_VALUE_123456",
            "API_KEY=sk_live_SUPER_SECRET_VALUE_123456",
            "-----BEGIN PRIVATE KEY-----FAKESECRET-----END PRIVATE KEY-----",
        ):
            if forbidden_secret in summary_text:
                raise SystemExit("FAILED: gitleaks summary copied a secret-like value verbatim")
        if "secret_sha256_12" not in summary_text or "secret_redacted" not in summary_text:
            raise SystemExit("FAILED: gitleaks summary should include only redacted/hash secret hints")
        for field in ("top_rule_ids", "path_category_counts", "top_rule_path_categories"):
            if field not in gitleaks_summary:
                raise SystemExit(f"FAILED: gitleaks summary missing aggregation field: {field}")
        if str(gitleaks_summary.get("raw_log_path", "")).startswith("/"):
            raise SystemExit("FAILED: gitleaks raw_log_path should be relative")
        if not (workspace / "evidence/initial-probes/gitleaks.log").exists():
            raise SystemExit("FAILED: gitleaks raw log was not preserved")
        if not (workspace / "evidence/initial-probes/gitleaks.json").exists():
            raise SystemExit("FAILED: gitleaks JSON report was not preserved")
        if by_name.get("syft", {}).get("status") != "skipped_tool_missing":
            raise SystemExit("FAILED: missing syft was not classified as skipped_tool_missing")
        if by_name.get("trivy", {}).get("status") != "failed_nonfatal":
            raise SystemExit("FAILED: non-zero trivy was not classified as failed_nonfatal")
        if by_name.get("trivy", {}).get("exit_code") != 2:
            raise SystemExit("FAILED: failed_nonfatal trivy exit code was not preserved")
        if by_name.get("grype", {}).get("status") != "failed_fatal":
            raise SystemExit("FAILED: exit-127 grype was not classified as failed_fatal")
        if by_name.get("grype", {}).get("exit_code") != 127:
            raise SystemExit("FAILED: failed_fatal grype exit code was not preserved")
        if by_name.get("semgrep", {}).get("command") != "(not executed)":
            raise SystemExit("FAILED: skipped semgrep should use a descriptive command placeholder")
        for probe in probes:
            for field in ("name", "status", "command", "exit_code", "log_path", "reason", "next_action"):
                if field not in probe:
                    raise SystemExit(f"FAILED: initial probe record missing {field}: {probe}")
            for path_field in ("log_path",):
                value = str(probe.get(path_field) or "")
                if value.startswith("/"):
                    raise SystemExit(f"FAILED: initial probe {path_field} should be relative: {value}")
        if str(summary_data.get("repo_root")).startswith("/"):
            raise SystemExit("FAILED: initial-probes-summary.json repo_root should not leak an absolute path")
        if str(summary_data.get("workspace_dir")).startswith("/"):
            raise SystemExit("FAILED: initial-probes-summary.json workspace_dir should not leak an absolute path")
        if str(summary_data.get("output_dir")).startswith("/"):
            raise SystemExit("FAILED: initial-probes-summary.json output_dir should not leak an absolute path")
        fake_gitleaks.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "report_path=''\n"
            "while [[ $# -gt 0 ]]; do\n"
            "  case \"$1\" in --report-path) report_path=\"${2:-}\"; shift 2 ;; *) shift ;; esac\n"
            "done\n"
            "[[ -n \"$report_path\" ]] || exit 64\n"
            "python3 - <<'PY' \"$report_path\"\n"
            "import json, sys\n"
            "items=[]\n"
            "paths=['tests/fixtures/a.env','docs/example.md','examples/demo.env','app/config/specs/open-api.json','src/Service.php','fixtures/key.txt']\n"
            "rules=['generic-api-key','jwt','private-key']\n"
            "for i in range(36):\n"
            "    secret=f'SECRET_VALUE_{i:04d}_DO_NOT_COPY'\n"
            "    items.append({'RuleID': rules[i % len(rules)], 'Description': 'Synthetic secret', 'File': paths[i % len(paths)], 'StartLine': i + 1, 'Commit': f'commit{i % 4}', 'Secret': secret, 'Match': 'TOKEN=' + secret})\n"
            "open(sys.argv[1], 'w', encoding='utf-8').write(json.dumps(items))\n"
            "PY\n"
            "echo 'leaks found: 36'\n"
            "exit 1\n",
            encoding="utf-8",
        )
        fake_gitleaks.chmod(0o755)
        large_gitleaks_output = workspace / "evidence/initial-probes-gitleaks-large"
        run_with_env([
            "/bin/bash",
            str(workspace / "bin/run-initial-probes.sh"),
            "--repo-root",
            str(repo_dir),
            "--workspace-dir",
            str(workspace),
            "--output-dir",
            str(large_gitleaks_output),
        ], plugin_root, probe_env)
        large_probe = require_probe_record(
            large_gitleaks_output / "initial-probes-summary.json",
            large_gitleaks_output,
            "gitleaks",
            "failed_nonfatal",
            1,
            "gitleaks exited non-zero",
        )
        large_summary = large_probe.get("summary") or {}
        if large_summary.get("finding_count") != 36:
            raise SystemExit("FAILED: large gitleaks summary did not preserve finding_count")
        if len(large_summary.get("sample_findings") or []) > 5:
            raise SystemExit("FAILED: large gitleaks summary sample_findings exceeded cap")
        for field in ("top_rule_ids", "path_category_counts", "top_rule_path_categories", "top_commits"):
            if not large_summary.get(field):
                raise SystemExit(f"FAILED: large gitleaks summary missing populated aggregation: {field}")
        large_summary_text = json.dumps(large_summary, ensure_ascii=False)
        if "SECRET_VALUE_" in large_summary_text or "TOKEN=SECRET" in large_summary_text:
            raise SystemExit("FAILED: large gitleaks summary copied secret-like values verbatim")
        fake_osv.write_text(
            "#!/usr/bin/env bash\n"
            "echo 'OSV scan completed successfully with no vulnerable packages'\n"
            "exit 0\n",
            encoding="utf-8",
        )
        fake_osv.chmod(0o755)
        osv_ok_output = workspace / "evidence/initial-probes-osv-ok"
        run_with_env([
            "/bin/bash",
            str(workspace / "bin/run-initial-probes.sh"),
            "--repo-root",
            str(repo_dir),
            "--workspace-dir",
            str(workspace),
            "--output-dir",
            str(osv_ok_output),
        ], plugin_root, probe_env)
        require_probe_record(
            osv_ok_output / "initial-probes-summary.json",
            osv_ok_output,
            "osv-scanner",
            "ran_ok",
            0,
            "completed with exit code 0",
            "exited non-zero",
        )
        fake_osv.write_text(
            "#!/usr/bin/env bash\n"
            "echo 'simulated unexpected OSV failure' >&2\n"
            "exit 42\n",
            encoding="utf-8",
        )
        fake_osv.chmod(0o755)
        osv_failure_output = workspace / "evidence/initial-probes-osv-failure"
        run_with_env([
            "/bin/bash",
            str(workspace / "bin/run-initial-probes.sh"),
            "--repo-root",
            str(repo_dir),
            "--workspace-dir",
            str(workspace),
            "--output-dir",
            str(osv_failure_output),
        ], plugin_root, probe_env)
        require_probe_record(
            osv_failure_output / "initial-probes-summary.json",
            osv_failure_output,
            "osv-scanner",
            "failed_nonfatal",
            42,
            "exited non-zero for a reason other than no package sources",
        )
        run([
            sys.executable,
            str(workspace / "bin/render-handoff-summary.py"),
            "--workspace-dir",
            str(workspace),
            "--repo-root",
            str(repo_dir),
        ], plugin_root)
        require_text(
            workspace / "handoff-summary.md",
            "osv-scanner: skipped_no_package_sources",
            "rendered handoff initial probe status",
        )
        require_text(
            workspace / "handoff-summary.md",
            "semgrep: skipped_tool_missing",
            "rendered handoff missing tool status",
        )
        require_text(
            workspace / "bin/run-verification-case.sh",
            "failed_resource_limit",
            "bootstrapped verification runner stable labels",
        )
        require_text(
            workspace / "bin/run-verification-case.sh",
            "Verification command timed out. Re-analyze service readiness",
            "bootstrapped verification runner timeout guidance",
        )
        if not (workspace / "unverified-leads.md").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing unverified-leads.md")
        if not (workspace / "attack-surface.md").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing attack-surface.md")
        for heading in (
            "Repository / Stack Summary",
            "External Entry Points",
            "Trusted and Untrusted Input Sources / Trust Boundaries",
            "Auth / Session / Permission Boundaries",
            "High-Risk Sinks",
            "Source-to-Sink Hypotheses",
            "Docker Verification Status",
            "Confirmed / False-Positive / Unverified Routing Reminder",
            "Next Safe Audit Steps",
        ):
            require_text(
                workspace / "attack-surface.md",
                heading,
                f"bootstrapped attack-surface heading {heading}",
            )
        require_text(
            workspace / "attack-surface.md",
            "not a vulnerability report, not raw scanner output",
            "bootstrapped attack-surface non-report guardrail",
        )
        require_text(
            workspace / "candidate-findings.md",
            "Source-to-Sink Hypothesis",
            "bootstrapped candidate findings stable columns",
        )
        require_text(
            workspace / "false-positives.md",
            "False Positives and Non-Security Defects",
            "bootstrapped false positives stable heading",
        )
        require_text(
            workspace / "unverified-leads.md",
            "High-Confidence-Unverified?",
            "bootstrapped unverified leads stable columns",
        )
        require_text(
            workspace / "unverified-leads.md",
            "Why completion is still safe?",
            "bootstrapped unverified leads materiality columns",
        )
        if not (workspace / "stage-status.json").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing stage-status.json")
        if not (workspace / "audit-events.jsonl").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing audit-events.jsonl")
        if not (workspace / "bin/write-audit-event.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing write-audit-event.py")
        if not (workspace / "bin/validate-workspace-state.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing validate-workspace-state.py")
        if not (workspace / "bin/plan-security-toolchain.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing plan-security-toolchain.py")
        if not (workspace / "bin/render-confirmed-vuln-docx.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing render-confirmed-vuln-docx.py")
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_workspace_state.py"),
            "--workspace-dir",
            str(workspace),
            "--repo-root",
            str(repo_dir),
        ], plugin_root)
        sandbox_workspace = Path(tempdir) / "sandbox-preflight-workspace"
        sandbox_workspace.mkdir(parents=True, exist_ok=True)
        (sandbox_workspace / "asr-config.json").write_text('{"schema_version":1}\n', encoding="utf-8")
        (sandbox_workspace / "audit-log.md").write_text("# Audit Log\n", encoding="utf-8")
        exercise_sandbox_preflight(
            plugin_root / "scripts/check_sandbox_preflight.py",
            sandbox_workspace,
            plugin_root,
        )
        exercise_sandbox_preflight(
            workspace / "bin/check-sandbox-preflight.py",
            sandbox_workspace,
            plugin_root,
        )
        exercise_runner_sandbox_rejection(
            plugin_root / "scripts/run_verification_case.sh",
            sandbox_workspace,
            plugin_root,
        )
        exercise_sandbox_ledger_guard(sandbox_workspace, plugin_root)
        run([
            "bash",
            str(workspace / "bin/check_omc_runtime.sh"),
            "--workspace-dir",
            str(workspace),
            "--json",
        ], plugin_root)
        exercise_omc_runtime_hygiene(
            plugin_root / "scripts/check_omc_runtime.sh",
            workspace,
            plugin_root,
        )
        exercise_omc_runtime_hygiene(
            workspace / "bin/check_omc_runtime.sh",
            workspace,
            plugin_root,
        )
        run([
            sys.executable,
            str(workspace / "bin/plan-security-toolchain.py"),
            "--target-dir",
            str(repo_dir),
            "--workspace-dir",
            str(workspace),
        ], plugin_root)
        (repo_dir / "pom.xml").write_text(
            "<project><modelVersion>4.0.0</modelVersion><groupId>selftest</groupId><artifactId>demo</artifactId><version>1</version></project>\n",
            encoding="utf-8",
        )
        java_controller = repo_dir / "src/main/java/example/DemoController.java"
        java_controller.parent.mkdir(parents=True, exist_ok=True)
        java_controller.write_text(
            "@RestController\nclass DemoController {\n  @GetMapping(\"/demo\") String demo(@RequestParam String name) { return name; }\n}\n",
            encoding="utf-8",
        )
        planner_output = run_capture([
            sys.executable,
            str(workspace / "bin/plan-security-toolchain.py"),
            "--target-dir",
            str(repo_dir),
            "--workspace-dir",
            str(workspace),
        ], plugin_root)
        for expected in (
            "attack_surface_guidance:",
            "Java Web: inventory Spring/JAX-RS/Servlet routes",
            "Minimum entry inventory fields: route or endpoint, method, handler/controller",
            "current verification status",
        ):
            if expected not in planner_output:
                raise SystemExit(f"FAILED: planner output missing attack-surface guidance text: {expected}")
        go_router = repo_dir / "cmd/server/main.go"
        go_router.parent.mkdir(parents=True, exist_ok=True)
        (repo_dir / "go.mod").write_text(
            "module selftest\n\ngo 1.22\n",
            encoding="utf-8",
        )
        go_router.write_text(
            "package main\n\nimport \"net/http\"\n\nfunc main() {\n  http.HandleFunc(\"/demo\", func(w http.ResponseWriter, r *http.Request) {})\n}\n",
            encoding="utf-8",
        )
        mixed_planner_output = run_capture([
            sys.executable,
            str(workspace / "bin/plan-security-toolchain.py"),
            "--target-dir",
            str(repo_dir),
            "--workspace-dir",
            str(workspace),
        ], plugin_root)
        if mixed_planner_output.count("Minimum entry inventory fields: route or endpoint, method, handler/controller") != 1:
            raise SystemExit("FAILED: planner output duplicated minimum entry inventory fields for mixed Java/Go workspace")
        (repo_dir / "package.json").write_text(
            '{"name":"selftest","version":"1.0.0","dependencies":{"express":"^4.18.0","fastify":"^4.0.0","next":"^14.0.0","lodash":"^4.17.21"}}\n',
            encoding="utf-8",
        )
        node_route = repo_dir / "routes/proxy.js"
        node_route.parent.mkdir(parents=True, exist_ok=True)
        node_route.write_text(
            "const fs = require('fs');\n"
            "const path = require('path');\n"
            "const express = require('express');\n"
            "const fastify = require('fastify')();\n"
            "const _ = require('lodash');\n"
            "const app = express();\n"
            "app.get('/proxy', proxy);\n"
            "fastify.post('/upload', async function route(request, reply) { return reply.send({ok: true}); });\n"
            "export default function handler(req, res) { return res.json({ok: true}); }\n"
            "async function proxy(req) {\n"
            "  await fetch(req.query.url);\n"
            "  fs.readFileSync(path.join('/srv/files', req.query.filename));\n"
            "  _.merge({}, JSON.parse('{\"__proto__\":{\"polluted\":true}}'));\n"
            "}\n",
            encoding="utf-8",
        )
        checklist_output = run_capture([
            sys.executable,
            str(workspace / "bin/plan-security-toolchain.py"),
            "--target-dir",
            str(repo_dir),
            "--workspace-dir",
            str(workspace),
        ], plugin_root)
        for expected in (
            "local_knowledge_checklists:",
            "assets/references/ssrf-checklist.md",
            "assets/references/path-traversal-checklist.md",
            "assets/references/prototype-pollution-checklist.md",
        ):
            if expected not in checklist_output:
                raise SystemExit(f"FAILED: planner output missing checklist recommendation: {expected}")
        for expected in (
            "assets/references/nodejs-web-audit-playbook.md",
            "Node.js Web: inventory Express/Koa/Fastify/Next.js routes",
        ):
            if expected not in checklist_output:
                raise SystemExit(f"FAILED: planner output missing Node.js Web playbook recommendation: {expected}")
        library_repo = Path(tempdir) / "node-library-repo"
        library_repo.mkdir(parents=True, exist_ok=True)
        (library_repo / "package.json").write_text(
            '{"name":"selftest-library","version":"1.0.0","main":"lib/index.js","exports":"./lib/index.js"}\n',
            encoding="utf-8",
        )
        (library_repo / "lib").mkdir(parents=True, exist_ok=True)
        (library_repo / "lib" / "index.js").write_text(
            "exports.parse = function parse(input, options = {}) { return {input, options}; };\n",
            encoding="utf-8",
        )
        (library_repo / "api").mkdir(parents=True, exist_ok=True)
        (library_repo / "api" / "README.md").write_text(
            "# Public API documentation\n\nThis directory documents exported library APIs; it is not an HTTP API.\n",
            encoding="utf-8",
        )
        stale_workspace_api = library_repo / "security-research-20250101-000000/api/app.py"
        stale_workspace_api.parent.mkdir(parents=True, exist_ok=True)
        stale_workspace_api.write_text(
            "from flask import Flask\napp = Flask(__name__)\n@app.route('/stale')\ndef stale(): return 'stale'\n",
            encoding="utf-8",
        )
        library_plan = json.loads(run_capture([
            sys.executable,
            str(workspace / "bin/plan-security-toolchain.py"),
            "--target-dir",
            str(library_repo),
            "--workspace-dir",
            str(workspace),
            "--format",
            "json",
        ], plugin_root))
        library_hints = set(library_plan["attack_surface_hints"])
        if "node-library" not in library_hints:
            raise SystemExit("FAILED: planner did not classify pure Node.js package as node-library")
        for unexpected in ("http-api", "node-web", "python-web"):
            if unexpected in library_hints:
                raise SystemExit(f"FAILED: planner treated pure Node.js package as {unexpected}")
        if "assets/references/nodejs-library-audit-playbook.md" not in library_plan["specialized_playbooks"]:
            raise SystemExit("FAILED: planner did not recommend Node.js Library playbook")
        guidance_text = "\n".join(library_plan["attack_surface_guidance"])
        for expected in (
            "Node.js Library: inventory exported APIs",
            "Minimum library inventory fields: public API or CLI",
            "distinguish library-local behavior from application-level impact",
        ):
            if expected not in guidance_text:
                raise SystemExit(f"FAILED: planner output missing Node.js Library guidance: {expected}")
        (repo_dir / "requirements.txt").write_text(
            "flask\nfastapi\ndjango\n",
            encoding="utf-8",
        )
        python_app = repo_dir / "api/app.py"
        python_app.parent.mkdir(parents=True, exist_ok=True)
        python_app.write_text(
            "from flask import Flask, request\n"
            "from fastapi import FastAPI, UploadFile\n"
            "from django.urls import path\n\n"
            "app = Flask(__name__)\n"
            "api = FastAPI()\n\n"
            "@app.route('/download')\n"
            "def download():\n"
            "    return request.args.get('file', '')\n\n"
            "@api.post('/upload')\n"
            "async def upload(file: UploadFile):\n"
            "    return {'name': file.filename}\n\n"
            "urlpatterns = [path('demo/', lambda request: None)]\n",
            encoding="utf-8",
        )
        python_planner_output = run_capture([
            sys.executable,
            str(workspace / "bin/plan-security-toolchain.py"),
            "--target-dir",
            str(repo_dir),
            "--workspace-dir",
            str(workspace),
        ], plugin_root)
        for expected in (
            "assets/references/python-web-audit-playbook.md",
            "Python Web: inventory Flask/Django/FastAPI/Starlette routes",
        ):
            if expected not in python_planner_output:
                raise SystemExit(f"FAILED: planner output missing Python Web playbook recommendation: {expected}")
        python_library_repo = Path(tempdir) / "python-library-repo"
        python_library_repo.mkdir(parents=True, exist_ok=True)
        (python_library_repo / "pyproject.toml").write_text(
            "[project]\nname = \"werkzeug-style-selftest\"\nversion = \"1.0.0\"\n",
            encoding="utf-8",
        )
        package_dir = python_library_repo / "src/werkzeug_style_selftest"
        package_dir.mkdir(parents=True, exist_ok=True)
        (package_dir / "__init__.py").write_text(
            "def parse_path(user_value, options=None):\n"
            "    return user_value\n",
            encoding="utf-8",
        )
        python_library_plan = json.loads(run_capture([
            sys.executable,
            str(workspace / "bin/plan-security-toolchain.py"),
            "--target-dir",
            str(python_library_repo),
            "--workspace-dir",
            str(workspace),
            "--format",
            "json",
        ], plugin_root))
        if "python-library" not in python_library_plan["attack_surface_hints"]:
            raise SystemExit("FAILED: planner did not classify pure Python package as python-library")
        if "http-api" in python_library_plan["attack_surface_hints"]:
            raise SystemExit("FAILED: planner forced a web route model on a pure Python library")
        if "assets/references/python-library-audit-playbook.md" not in python_library_plan["specialized_playbooks"]:
            raise SystemExit("FAILED: planner did not recommend Python Library playbook")
        python_library_guidance = "\n".join(python_library_plan["attack_surface_guidance"])
        for expected in (
            "Python Library: inventory public APIs",
            "Minimum Python library inventory fields: public API or hook",
            "do not force a route/method/handler table",
        ):
            if expected not in python_library_guidance:
                raise SystemExit(f"FAILED: planner output missing Python Library guidance: {expected}")
        appwrite_like_repo = Path(tempdir) / "appwrite-like-repo"
        appwrite_like_repo.mkdir(parents=True, exist_ok=True)
        (appwrite_like_repo / "composer.json").write_text(
            json.dumps({
                "name": "selftest/appwrite-like",
                "require": {
                    "php": "^8.3",
                    "ext-swoole": "*",
                    "utopia-php/framework": "^0.0.0",
                },
            }),
            encoding="utf-8",
        )
        php_worker = appwrite_like_repo / "src/Appwrite/Platform/Workers/Webhooks.php"
        php_worker.parent.mkdir(parents=True, exist_ok=True)
        php_worker.write_text(
            "<?php\n"
            "namespace Appwrite\\Platform\\Workers;\n"
            "use Swoole\\Runtime;\n"
            "final class Webhooks { public function execute($url) { $ch = curl_init($url); return curl_exec($ch); } }\n",
            encoding="utf-8",
        )
        (appwrite_like_repo / "frontend").mkdir()
        (appwrite_like_repo / "frontend/package-lock.json").write_text('{"lockfileVersion":3}\n', encoding="utf-8")
        (appwrite_like_repo / "tests/resources").mkdir(parents=True)
        (appwrite_like_repo / "tests/resources/package-lock.json").write_text('{"lockfileVersion":3}\n', encoding="utf-8")
        (appwrite_like_repo / "docker-compose.yml").write_text(
            "services:\n  appwrite:\n    image: appwrite/appwrite:dev\n",
            encoding="utf-8",
        )
        appwrite_plan = json.loads(run_capture([
            sys.executable,
            str(workspace / "bin/plan-security-toolchain.py"),
            "--target-dir",
            str(appwrite_like_repo),
            "--workspace-dir",
            str(workspace),
            "--format",
            "json",
        ], plugin_root))
        appwrite_hints = set(appwrite_plan["attack_surface_hints"])
        for expected in ("php-web", "php-swoole", "docker-compose"):
            if expected not in appwrite_hints:
                raise SystemExit(f"FAILED: Appwrite-like planner missing {expected}")
        playbooks = appwrite_plan["specialized_playbooks"]
        if not playbooks or playbooks[0] != "assets/references/php-swoole-audit-playbook.md":
            raise SystemExit(f"FAILED: Appwrite-like planner should lead with PHP/Swoole playbook: {playbooks}")
        if "assets/references/nodejs-web-audit-playbook.md" in playbooks:
            raise SystemExit("FAILED: Appwrite-like planner should not lead with Node Web from frontend/test lockfiles")
        appwrite_guidance = "\n".join(appwrite_plan["attack_surface_guidance"])
        for expected in (
            "PHP/Swoole: inventory Utopia routes/controllers",
            "frontend/test package-lock files as secondary",
        ):
            if expected not in appwrite_guidance:
                raise SystemExit(f"FAILED: Appwrite-like planner output missing PHP/Swoole guidance: {expected}")
        run_with_env([
            "bash",
            str(plugin_root / "scripts/refresh_workspace_helpers.sh"),
            "--workspace",
            str(workspace),
        ], plugin_root, {
            "SKILL_DIR": str(plugin_root),
            "HOME": str(Path.home()),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        })
        (repo_dir / "docker").mkdir(parents=True, exist_ok=True)
        (repo_dir / "poc").mkdir(parents=True, exist_ok=True)
        (repo_dir / "docker" / "docker-compose.attacker.yml").write_text(
            "services:\n  attacker:\n    image: alpine:3.20\n",
            encoding="utf-8",
        )
        (repo_dir / "poc" / "path_traversal.py").write_text(
            "print('demo poc')\\n",
            encoding="utf-8",
        )
        run([
            sys.executable,
            str(workspace / "bin/render-confirmed-vuln-docx.py"),
            "--input",
            str(plugin_root / "assets/examples/confirmed-findings.example.json"),
            "--output-dir",
            str(workspace / "confirmed"),
            "--language",
            "zh-CN",
        ], plugin_root)
        run([
            sys.executable,
            str(workspace / "bin/render-confirmed-vuln-docx.py"),
            "--input",
            str(plugin_root / "assets/examples/confirmed-findings.example.json"),
            "--output-dir",
            str(workspace / "confirmed"),
            "--language",
            "en-US",
        ], plugin_root)
        rendered_bundles = sorted(
            [
                path for path in (workspace / "confirmed").iterdir()
                if path.is_dir() and not path.name.startswith(".")
            ],
            key=lambda path: path.name,
        )
        if len(rendered_bundles) < 2:
            raise SystemExit("FAILED: bilingual example confirmed bundles were not rendered during selftest")
        zh_bundle = next((path for path in rendered_bundles if "漏洞报告" in path.name), None)
        en_bundle = next((path for path in rendered_bundles if path.name.endswith("_report")), None)
        if zh_bundle is None:
            raise SystemExit("FAILED: zh-CN confirmed bundle was not rendered during selftest")
        if en_bundle is None:
            raise SystemExit("FAILED: en-US confirmed bundle was not rendered during selftest")
        if not (zh_bundle / "verification-evidence.json").exists():
            raise SystemExit("FAILED: zh-CN confirmed bundle is missing verification-evidence.json")
        if not (en_bundle / "verification-evidence.json").exists():
            raise SystemExit("FAILED: en-US confirmed bundle is missing verification-evidence.json")
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(zh_bundle),
            "--language",
            "zh-CN",
        ], plugin_root)
        standard_fixture_poc = repo_dir / "poc/jwt-forge-poc.py"
        standard_fixture_poc.parent.mkdir(parents=True, exist_ok=True)
        standard_fixture_poc.write_text("print('forged token accepted')\n", encoding="utf-8")
        standard_fixture_evidence = repo_dir / "poc/forged-token-response.json"
        standard_fixture_evidence.write_text('{"ok":true,"user":{"id":1}}\n', encoding="utf-8")
        standard_fixture = workspace / "standard-vulnerability-name-finding.json"
        standard_fixture.write_text(json.dumps({
            "project_name": "gothinkster/node-express-realworld-example-app",
            "vulnerability_id": "SELFTEST-001",
            "vulnerability_name": "硬编码 JWT 密钥导致身份认证绕过",
            "vulnerability_name_en": "Hardcoded JWT Secret Leading to Authentication Bypass",
            "severity": "critical",
            "severity_cn": "严重",
            "cwe": "CWE-798: Use of Hardcoded Credentials",
            "description": [
                "默认配置缺失 JWT_SECRET 时，应用回退到公开硬编码密钥，攻击者可伪造认证 token。"
            ],
            "impact": {
                "package": "gothinkster/node-express-realworld-example-app",
                "component": "src/app/routes/auth/auth.ts",
                "affected_versions": "default configuration",
                "repo_url": "https://github.com/gothinkster/node-express-realworld-example-app",
            },
            "cvss": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L",
                "score": "9.3",
                "severity": "Critical",
                "rationale": ["评估依据：攻击者可伪造任意用户 token，并完成未授权读写操作。"],
            },
            "analysis": [
                "位置：src/app/routes/auth/auth.ts 使用 process.env.JWT_SECRET || 'superSecret'。",
                "入口/可控输入：攻击者提交自签名 JWT token，请求受保护 API。",
                "危险函数/危险操作：express-jwt 使用公开默认密钥验证 HS256 token。",
                "触发路径：缺失 JWT_SECRET -> 默认密钥生效 -> 攻击者签发 token -> API 接受认证。",
                "根因：认证密钥存在硬编码回退值。",
                "现有校验为何失效：启动流程没有强制要求安全 JWT_SECRET。",
            ],
            "reproduction": [
                {
                    "title": "1. 伪造 token 并访问受保护接口",
                    "details": [
                        "在 Docker Compose 环境中不设置 JWT_SECRET，确认应用按默认配置启动。",
                        "使用公开硬编码密钥 superSecret 构造 HS256 JWT，载荷中写入 user.id=1。",
                        "将伪造 token 放入 Authorization: Token <token> 请求头访问受保护接口。",
                    ],
                    "commands": [
                        "python3 poc/jwt-forge-poc.py",
                        "curl -s http://localhost:3000/api/user -H 'Authorization: Token <FORGED_TOKEN>'",
                    ],
                    "expected": ["预期结果：伪造 token 被服务端接受。"],
                    "observed": ["实际结果：HTTP 200 返回用户资料。"],
                    "results": [
                        "结果证据：forged-token-response.json 显示认证绕过成功。",
                        "结果证据：响应中包含 user.id=1，且没有返回 401 未授权错误。",
                    ],
                }
            ],
            "verification_status": "confirmed_in_docker",
            "verification_evidence": {
                "docker_image": "selftest-realworld-api",
                "docker_command": "docker compose up -d",
                "poc_path": "poc/jwt-forge-poc.py",
                "evidence_files": ["poc/forged-token-response.json"],
                "expected_observation": "预期结果：伪造 token 被服务端接受。",
                "observed_observation": "实际结果：HTTP 200 返回用户资料。",
                "oracle_token": "认证绕过成功",
                "severity_escalation_attempted": True,
                "severity_escalation_result": "Critical impact confirmed in Docker.",
            },
            "attachments": [
                {"path": "poc/jwt-forge-poc.py", "purpose": "JWT 伪造 PoC"},
                {"path": "poc/forged-token-response.json", "purpose": "认证绕过响应证据"},
            ],
            "bundle_root_artifacts": [
                {
                    "generator": "reviewer-recording-shell",
                    "output_name": "run-selftest-jwt-recording.sh",
                    "purpose": "审核复现脚本",
                    "generator_options": {"modes": ["quick"]},
                }
            ],
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        run([
            sys.executable,
            str(workspace / "bin/render-confirmed-vuln-docx.py"),
            "--input",
            str(standard_fixture),
            "--output-dir",
            str(workspace / "confirmed"),
            "--language",
            "zh-CN",
        ], plugin_root)
        standard_bundle = next(
            (
                path for path in (workspace / "confirmed").iterdir()
                if path.is_dir() and "硬编码" in path.name and "安全漏洞" not in path.name
            ),
            None,
        )
        if standard_bundle is None:
            raise SystemExit("FAILED: standard vulnerability_name fixture did not render a finding-specific bundle name")
        standard_docx = next(standard_bundle.glob("*.docx"))
        if "硬编码" not in standard_docx.name or "安全漏洞" in standard_docx.name:
            raise SystemExit("FAILED: standard vulnerability_name fixture rendered a generic DOCX filename")
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(standard_bundle),
            "--language",
            "zh-CN",
        ], plugin_root)
        standard_lines = docx_text(standard_docx)
        if not standard_lines or "硬编码 JWT 密钥导致身份认证绕过" not in standard_lines[0]:
            raise SystemExit("FAILED: standard vulnerability_name fixture rendered a generic DOCX title")
        if "最终判定待补充" in "\n".join(standard_lines):
            raise SystemExit("FAILED: standard vulnerability_name fixture left final verdict placeholder text")
        standard_text = "\n".join(standard_lines)
        for label in ("攻击者条件", "服务端条件", "安全影响"):
            if label not in standard_text:
                raise SystemExit(f"FAILED: zh-CN confirmed report is missing quality-gate label: {label}")
        if "实际场景中的危害与利用方式" not in standard_text:
            raise SystemExit("FAILED: zh-CN confirmed report is missing real-world exploitability section")
        en_docx = next(en_bundle.glob("*.docx"))
        en_text = "\n".join(docx_text(en_docx))
        for label in ("Attacker Condition", "Server Condition", "Security Impact"):
            if label not in en_text:
                raise SystemExit(f"FAILED: en-US confirmed report is missing quality-gate label: {label}")
        if "Real-World Exploitability" not in en_text:
            raise SystemExit("FAILED: en-US confirmed report is missing real-world exploitability section")
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(en_bundle),
            "--language",
            "en-US",
        ], plugin_root)
        en_scripts = sorted(en_bundle.glob("run-*.sh"))
        if en_scripts:
            en_script_text = en_scripts[0].read_text(encoding="utf-8")
            for expected in ("print_target_identity", "Target Software", "Target Version"):
                if expected not in en_script_text:
                    raise SystemExit(f"FAILED: generated en-US recording script is missing target identity marker: {expected}")
        standard_script = standard_bundle / "run-selftest-jwt-recording.sh"
        standard_script_text = standard_script.read_text(encoding="utf-8")
        if "announce_step '代码'" not in standard_script_text or re.search(
            r"(?:announce_step\s+['\"]0/\d+|\[0/\d+\]|Step\s+0/\d+|步骤\s*0/\d+)",
            standard_script_text,
        ):
            raise SystemExit("FAILED: generated zh-CN recording script must use [代码], not 0/N, for code hints")
        for expected in (
            "print_target_identity",
            "目标软件",
            "版本号",
            "gothinkster/node-express-realworld-example-app",
            "default configuration",
            "REPLAY_LOG",
            "replay-output.log",
            "run_logged_command",
            "verify_success_marker",
            "SUCCESS_MARKER",
            "DIRECT_IMPACT_MARKER",
            "DIRECT_IMPACT_CONFIRMED",
            "record_direct_impact_marker",
            "> \"$command_output\" 2>&1",
            "cat \"$command_output\" >> \"$REPLAY_LOG\"",
            "grep -Fq -- \"$marker\" \"$REPLAY_LOG\"",
            "show_evidence_summary",
            "漏洞已确认",
        ):
            if expected not in standard_script_text:
                raise SystemExit(f"FAILED: generated recording script is missing target identity marker: {expected}")
        standard_evidence = json.loads((standard_bundle / "verification-evidence.json").read_text(encoding="utf-8"))
        if "attachments/evidence/replay-output.log" not in standard_evidence.get("evidence_files", []):
            raise SystemExit("FAILED: generated verification evidence must register replay-output.log")
        if not (standard_bundle / "attachments/evidence/replay-output.log").exists():
            raise SystemExit("FAILED: generated confirmed bundle must include replay-output.log placeholder")

        def copy_standard_bundle(suffix: str) -> Path:
            copied = standard_bundle.parent / f"{standard_bundle.name}_{suffix}"
            if copied.exists():
                shutil.rmtree(copied)
            shutil.copytree(standard_bundle, copied)
            return copied

        def mutate_bundle_finding(bundle: Path, mutator) -> None:
            findings_path = bundle / "findings.json"
            if not findings_path.exists():
                shared_findings_path = bundle.parent / "findings.json"
                source_findings_path = shared_findings_path if shared_findings_path.exists() else standard_fixture
                shared_data = json.loads(source_findings_path.read_text(encoding="utf-8"))
                if isinstance(shared_data, dict) and isinstance(shared_data.get("findings"), list):
                    candidates = [item for item in shared_data["findings"] if isinstance(item, dict)]
                    selected = next(
                        (
                            item for item in candidates
                            if str(item.get("slug") or "").strip() == standard_bundle.name
                            or Path(str(item.get("filename") or item.get("report_file") or "")).stem == standard_bundle.name
                            or "硬编码" in str(item.get("vulnerability_name") or item.get("vulnerability_name_zh") or "")
                        ),
                        candidates[0] if candidates else None,
                    )
                elif isinstance(shared_data, dict):
                    selected = shared_data
                elif isinstance(shared_data, list) and shared_data and isinstance(shared_data[0], dict):
                    selected = shared_data[0]
                else:
                    raise SystemExit("FAILED: shared selftest findings.json has unexpected shape")
                if selected is None:
                    raise SystemExit("FAILED: shared selftest findings.json has no finding objects")
                findings_path.write_text(json.dumps(selected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            data = json.loads(findings_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("findings"), list):
                target = data["findings"][0]
            elif isinstance(data, dict):
                target = data
            else:
                raise SystemExit("FAILED: selftest bundle findings.json has unexpected shape")
            mutator(target)
            findings_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        neutral_pr_bundle = copy_standard_bundle("prl_neutral_title_pass")
        mutate_bundle_finding(
            neutral_pr_bundle,
            lambda finding: finding.setdefault("cvss", {}).update({"vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L"}),
        )
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(neutral_pr_bundle),
            "--language",
            "zh-CN",
        ], plugin_root)
        shutil.rmtree(neutral_pr_bundle)

        bad_unauth_title = copy_standard_bundle("unauthenticated_title_prl")
        mutate_bundle_finding(
            bad_unauth_title,
            lambda finding: finding.setdefault("cvss", {}).update({"vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L"}),
        )
        rewrite_docx_paragraphs(
            next(bad_unauth_title.glob("*.docx")),
            lambda text: (
                "gothinkster/node-express-realworld-example-app Unauthenticated SSRF 硬编码 JWT 密钥导致身份认证绕过 严重漏洞报告"
                if text.startswith("gothinkster/node-express-realworld-example-app")
                else text
            ),
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_unauth_title),
            "--language",
            "zh-CN",
        ], plugin_root, "title/CVSS/auth consistency failure")
        shutil.rmtree(bad_unauth_title)

        bad_zero_step = copy_standard_bundle("recording_zero_step")
        zero_script = bad_zero_step / "run-selftest-jwt-recording.sh"
        zero_script.write_text(
            zero_script.read_text(encoding="utf-8").replace("announce_step '代码'", "announce_step '0/2'"),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_zero_step),
            "--language",
            "zh-CN",
        ], plugin_root, "must not use 0/N step labels")
        shutil.rmtree(bad_zero_step)

        bad_unconditional_poc = copy_standard_bundle("unconditional_poc_confirmation")
        bad_confirm_script = bad_unconditional_poc / "attachments/unconditional-confirm.sh"
        bad_confirm_script.write_text(
            "#!/bin/sh\nset -eu\necho \"VULNERABILITY CONFIRMED\"\n",
            encoding="utf-8",
        )
        bad_confirm_script.chmod(0o755)
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_unconditional_poc),
            "--language",
            "zh-CN",
        ], plugin_root, "without a nearby or preceding concrete success oracle")
        shutil.rmtree(bad_unconditional_poc)

        good_conditional_poc = copy_standard_bundle("conditional_poc_confirmation")
        good_confirm_script = good_conditional_poc / "attachments/conditional-confirm.sh"
        good_confirm_script.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "RESPONSE='{\"ok\":true,\"status_code\":200}'\n"
            "if printf '%s' \"$RESPONSE\" | grep -q '\"ok\":true'; then\n"
            "  echo \"VULNERABILITY CONFIRMED\"\n"
            "else\n"
            "  echo \"$RESPONSE\"\n"
            "  exit 1\n"
            "fi\n",
            encoding="utf-8",
        )
        good_confirm_script.chmod(0o755)
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(good_conditional_poc),
            "--language",
            "zh-CN",
        ], plugin_root)
        shutil.rmtree(good_conditional_poc)

        bad_root_syntax = copy_standard_bundle("root_script_syntax_error")
        bad_root_syntax_script = bad_root_syntax / "run-selftest-jwt-recording.sh"
        bad_root_syntax_script.write_text(
            bad_root_syntax_script.read_text(encoding="utf-8") + "\nif then\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_root_syntax),
            "--language",
            "zh-CN",
        ], plugin_root, "shell syntax check failed")
        shutil.rmtree(bad_root_syntax)

        bad_grep_echo_oracle = copy_standard_bundle("fail_open_grep_echo_oracle")
        bad_grep_echo_script = bad_grep_echo_oracle / "run-selftest-jwt-recording.sh"
        bad_grep_echo_script.write_text(
            bad_grep_echo_script.read_text(encoding="utf-8")
            + "\nprintf 'missing\\n' | grep --color=always '认证绕过成功' || echo '未检测到成功判据'\n"
            + "echo -e \"${G}═══ 漏洞已确认：gothinkster/node-express-realworld-example-app 硬编码 JWT 密钥导致身份认证绕过 ═══${N}\"\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_grep_echo_oracle),
            "--language",
            "zh-CN",
        ], plugin_root, "softens a success-oracle failure")
        shutil.rmtree(bad_grep_echo_oracle)

        bad_grep_true_oracle = copy_standard_bundle("fail_open_grep_true_oracle")
        bad_grep_true_script = bad_grep_true_oracle / "run-selftest-jwt-recording.sh"
        bad_grep_true_script.write_text(
            bad_grep_true_script.read_text(encoding="utf-8")
            + "\nprintf 'missing\\n' | grep -q '认证绕过成功' || true\n"
            + "printf '%s\\n' \"${G}VULNERABILITY CONFIRMED: gothinkster/node-express-realworld-example-app hardcoded JWT secret${N}\"\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_grep_true_oracle),
            "--language",
            "zh-CN",
        ], plugin_root, "softens a success-oracle failure")
        shutil.rmtree(bad_grep_true_oracle)

        bad_wrapper_confirmation = copy_standard_bundle("fail_open_wrapper_confirmation")
        bad_wrapper_script = bad_wrapper_confirmation / "run-selftest-jwt-recording.sh"
        bad_wrapper_script.write_text(
            bad_wrapper_script.read_text(encoding="utf-8")
            + "\nprintf 'missing\\n' | grep -q '认证绕过成功' || echo '未检测到成功判据'\n"
            + "highlight_success \"${G}═══ 漏洞已确认：gothinkster/node-express-realworld-example-app 硬编码 JWT 密钥导致身份认证绕过 ═══${N}\"\n"
            + "print_banner \"${G}VULNERABILITY CONFIRMED: hardcoded JWT secret${N}\"\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_wrapper_confirmation),
            "--language",
            "zh-CN",
        ], plugin_root, "softens a success-oracle failure")
        shutil.rmtree(bad_wrapper_confirmation)

        good_fail_closed_oracle = copy_standard_bundle("fail_closed_oracle")
        good_fail_closed_script = good_fail_closed_oracle / "run-selftest-jwt-recording.sh"
        good_fail_closed_script.write_text(
            good_fail_closed_script.read_text(encoding="utf-8")
            + "\nif ! printf '认证绕过成功\\n' | grep -q '认证绕过成功'; then\n"
            + "  echo '未检测到成功判据，不能确认漏洞。'\n"
            + "  exit 1\n"
            + "fi\n"
            + "echo '漏洞已确认：gothinkster/node-express-realworld-example-app 硬编码 JWT 密钥导致身份认证绕过'\n",
            encoding="utf-8",
        )
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(good_fail_closed_oracle),
            "--language",
            "zh-CN",
        ], plugin_root)
        shutil.rmtree(good_fail_closed_oracle)

        bad_missing_compose_env = copy_standard_bundle("compose_missing_env_file")
        bad_missing_compose_env_file = bad_missing_compose_env / "attachments/docker-compose.zhulong.yml"
        bad_missing_compose_env_file.write_text(
            "services:\n"
            "  app:\n"
            "    image: alpine:3.20\n"
            "    env_file: .env\n"
            "    command: ['sh', '-c', 'sleep 1']\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_missing_compose_env),
            "--language",
            "zh-CN",
        ], plugin_root, "env_file")
        shutil.rmtree(bad_missing_compose_env)

        bad_missing_compose_bind = copy_standard_bundle("compose_missing_bind_source")
        (bad_missing_compose_bind / "attachments/.env").write_text("SELFTEST=1\n", encoding="utf-8")
        (bad_missing_compose_bind / "attachments/docker-compose.zhulong.yml").write_text(
            "services:\n"
            "  app:\n"
            "    image: alpine:3.20\n"
            "    env_file:\n"
            "      - .env\n"
            "    volumes:\n"
            "      - ./missing-listener.py:/scripts/listener.py:ro\n"
            "    command: ['sh', '-c', 'sleep 1']\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_missing_compose_bind),
            "--language",
            "zh-CN",
        ], plugin_root, "volume source")
        shutil.rmtree(bad_missing_compose_bind)

        good_compose_bundle = copy_standard_bundle("compose_existing_env_bind_and_named_volume")
        (good_compose_bundle / "attachments/.env").write_text("SELFTEST=1\n", encoding="utf-8")
        (good_compose_bundle / "attachments/listen.py").write_text("print('ready')\n", encoding="utf-8")
        (good_compose_bundle / "attachments/docker-compose.zhulong.yml").write_text(
            "services:\n"
            "  app:\n"
            "    image: alpine:3.20\n"
            "    env_file:\n"
            "      - .env\n"
            "    volumes:\n"
            "      - ./listen.py:/scripts/listen.py:ro\n"
            "      - named-cache:/cache\n"
            "      - type: bind\n"
            "        source: ./listen.py\n"
            "        target: /scripts/listen-copy.py\n"
            "        read_only: true\n"
            "    command: ['sh', '-c', 'sleep 1']\n"
            "volumes:\n"
            "  named-cache: {}\n",
            encoding="utf-8",
        )
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(good_compose_bundle),
            "--language",
            "zh-CN",
        ], plugin_root)
        shutil.rmtree(good_compose_bundle)

        bad_english_docx = copy_standard_bundle("untranslated_english_docx")
        rewrite_docx_paragraphs(
            next(bad_english_docx.glob("*.docx")),
            lambda text: (
                "The vulnerable endpoint accepts attacker controlled input and forwards it to a sensitive server side operation. This vulnerability allows an attacker to trigger a security impact through the default configuration."
                if text.startswith("默认配置缺失 JWT_SECRET")
                else text
            ),
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_english_docx),
            "--language",
            "zh-CN",
        ], plugin_root, "long English natural-language paragraph")
        shutil.rmtree(bad_english_docx)

        bad_english_supplement = copy_standard_bundle("untranslated_english_supplement")
        bad_supplement_path = next(bad_english_supplement.glob("*_补充复现说明.md"))
        bad_supplement_path.write_text(
            bad_supplement_path.read_text(encoding="utf-8")
            + "\nThe vulnerable endpoint accepts attacker controlled input and forwards it to a sensitive server side operation. This vulnerability allows an attacker to trigger a security impact through the default configuration.\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_english_supplement),
            "--language",
            "zh-CN",
        ], plugin_root, "long English natural-language paragraph")
        shutil.rmtree(bad_english_supplement)

        technical_english_ok = copy_standard_bundle("technical_english_ok")
        technical_supplement_path = next(technical_english_ok.glob("*_补充复现说明.md"))
        technical_supplement_path.write_text(
            technical_supplement_path.read_text(encoding="utf-8")
            + "\n```sh\ncurl -s http://localhost:3000/api/user -H 'Authorization: Bearer TOKEN'\n```\n"
            + "`{\"access_token\":\"TOKEN\",\"status_code\":200}`\n"
            + "`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L`\n"
            + "`VULNERABILITY CONFIRMED`\n",
            encoding="utf-8",
        )
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(technical_english_ok),
            "--language",
            "zh-CN",
        ], plugin_root)
        shutil.rmtree(technical_english_ok)

        def quality_gate_bad_bundle(suffix: str, replacer) -> Path:
            bad_bundle = standard_bundle.parent / f"{standard_bundle.name}_{suffix}"
            shutil.copytree(standard_bundle, bad_bundle)
            rewrite_docx_paragraphs(next(bad_bundle.glob("*.docx")), replacer)
            return bad_bundle

        def remove_docx_real_world_section(docx_path: Path, *, language: str) -> None:
            stop_prefixes = ("位置：", "Location:")
            headings = (
                ("实际场景中的危害与利用方式",)
                if language == "zh-CN"
                else ("Real-World Exploitability",)
            )
            removing = False

            def replacer(text: str):
                nonlocal removing
                if any(heading in text for heading in headings):
                    removing = True
                    return None
                if removing and text.startswith(stop_prefixes):
                    removing = False
                    return text
                if removing:
                    return None
                return text

            rewrite_docx_paragraphs(docx_path, replacer)

        def remove_markdown_real_world_section(path: Path, *, language: str) -> None:
            text = path.read_text(encoding="utf-8")
            heading_fragment = "实际场景中的危害与利用方式" if language == "zh-CN" else "Practical Impact and Exploitation Path"
            kept: list[str] = []
            skipping = False
            for line in text.splitlines():
                if line.startswith("## ") and heading_fragment in line:
                    skipping = True
                    continue
                if skipping and line.startswith("## "):
                    skipping = False
                if not skipping:
                    kept.append(line)
            path.write_text("\n".join(kept) + "\n", encoding="utf-8")

        def weaken_markdown_success_evidence(path: Path, *, language: str) -> None:
            text = path.read_text(encoding="utf-8")
            evidence_heading = "关键成功证据" if language == "zh-CN" else "Key Success Evidence"
            replacement = "- 技术触发完成。" if language == "zh-CN" else "- Technical trigger completed."
            kept: list[str] = []
            in_evidence = False
            inserted = False
            for line in text.splitlines():
                if line.startswith("## ") and evidence_heading in line:
                    in_evidence = True
                    inserted = False
                    kept.append(line)
                    continue
                if in_evidence and line.startswith("## "):
                    if not inserted:
                        kept.append(replacement)
                    in_evidence = False
                if in_evidence:
                    if not inserted and line.strip():
                        kept.append(replacement)
                        inserted = True
                    continue
                kept.append(line)
            if in_evidence and not inserted:
                kept.append(replacement)
            path.write_text("\n".join(kept) + "\n", encoding="utf-8")

        def weaken_real_world_fallback_docx(docx_path: Path) -> None:
            protected_prefixes = (
                "漏洞描述",
                "影响版本",
                "漏洞危险性评估",
                "漏洞分析",
                "漏洞复现",
                "最终判定：",
                "攻击者条件",
                "服务端条件",
                "安全影响",
            )
            weak_markers = ("返回", "响应", "输出", "证据", "Docker", "验证", "确认", "成功", "记录")

            rewrite_docx_paragraphs(
                docx_path,
                lambda text: (
                    "攻击者条件：攻击者能够访问测试入口。"
                    if text.startswith("攻击者条件")
                    else "服务端条件：服务端运行测试组件。"
                    if text.startswith("服务端条件")
                    else "安全影响：存在机密性影响。"
                    if text.startswith("安全影响")
                    else None
                    if text.startswith("结果证据：") or text.startswith("实际结果：")
                    else "技术触发完成。"
                    if any(marker in text for marker in weak_markers) and not text.startswith(protected_prefixes)
                    else text
                ),
            )

        def weaken_en_real_world_fallback_docx(docx_path: Path) -> None:
            protected_prefixes = (
                "Vulnerability Description",
                "Affected Versions",
                "Risk Assessment",
                "Vulnerability Analysis",
                "Reproduction",
                "Final Verdict:",
                "Attacker Condition",
                "Server Condition",
                "Security Impact",
            )
            weak_markers = ("response", "output", "evidence", "docker", "verified", "confirmed", "success", "record")

            rewrite_docx_paragraphs(
                docx_path,
                lambda text: (
                    "Attacker Condition: attacker can reach the test entry point."
                    if text.startswith("Attacker Condition")
                    else "Server Condition: server runs the tested component."
                    if text.startswith("Server Condition")
                    else "Security Impact: confidentiality impact exists."
                    if text.startswith("Security Impact")
                    else None
                    if text.startswith("Evidence:") or text.startswith("Observed result:")
                    else "Technical trigger completed."
                    if any(marker in text.lower() for marker in weak_markers) and not text.startswith(protected_prefixes)
                    else text
                ),
            )

        bad_missing_real_world = copy_standard_bundle("missing_real_world_exploitability")
        remove_docx_real_world_section(next(bad_missing_real_world.glob("*.docx")), language="zh-CN")
        bad_missing_real_world_supplement = next(bad_missing_real_world.glob("*_补充复现说明.md"))
        remove_markdown_real_world_section(bad_missing_real_world_supplement, language="zh-CN")
        weaken_markdown_success_evidence(bad_missing_real_world_supplement, language="zh-CN")
        weaken_real_world_fallback_docx(next(bad_missing_real_world.glob("*.docx")))
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_missing_real_world),
            "--language",
            "zh-CN",
        ], plugin_root, "VALIDATION FAILED")

        bad_en_missing_real_world = en_bundle.parent / f"{en_bundle.name}_missing_real_world_exploitability"
        if bad_en_missing_real_world.exists():
            shutil.rmtree(bad_en_missing_real_world)
        shutil.copytree(en_bundle, bad_en_missing_real_world)
        remove_docx_real_world_section(next(bad_en_missing_real_world.glob("*.docx")), language="en-US")
        bad_en_missing_real_world_supplement = next(bad_en_missing_real_world.glob("*_reproduction_note.md"))
        remove_markdown_real_world_section(bad_en_missing_real_world_supplement, language="en-US")
        weaken_markdown_success_evidence(bad_en_missing_real_world_supplement, language="en-US")
        weaken_en_real_world_fallback_docx(next(bad_en_missing_real_world.glob("*.docx")))
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_en_missing_real_world),
            "--language",
            "en-US",
        ], plugin_root, "VALIDATION FAILED")

        bad_placeholder_real_world = copy_standard_bundle("placeholder_real_world_exploitability")
        rewrite_docx_paragraphs(
            next(bad_placeholder_real_world.glob("*.docx")),
            lambda text: (
                "实际场景中的危害与利用方式"
                if "实际场景中的危害与利用方式" in text
                else "待补充"
                if (
                    text.startswith("实际使用场景")
                    or text.startswith("攻击者路径")
                    or text.startswith("触发调用链")
                    or text.startswith("直接危害证明")
                    or text.startswith("影响边界")
                    or text.startswith("服务端可达条件")
                    or text.startswith("影响外显通道")
                    or text.startswith("已验证影响边界")
                )
                else text
            ),
        )
        remove_markdown_real_world_section(next(bad_placeholder_real_world.glob("*_补充复现说明.md")), language="zh-CN")
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_placeholder_real_world),
            "--language",
            "zh-CN",
        ], plugin_root, "real-world exploitability section is too thin")

        bad_strong_boundary = copy_standard_bundle("strong_attacker_boundary_missing")
        remove_docx_real_world_section(next(bad_strong_boundary.glob("*.docx")), language="zh-CN")
        remove_markdown_real_world_section(next(bad_strong_boundary.glob("*_补充复现说明.md")), language="zh-CN")
        poc_boundary_script = bad_strong_boundary / "attachments/strong-boundary.sh"
        poc_boundary_script.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "# PoC uses malicious JS and directly executes it to reach the component.\n"
            "printf 'ok {\"ok\":true}\\n' | grep -q 'ok'\n"
            "echo 'VULNERABILITY CONFIRMED'\n",
            encoding="utf-8",
        )
        poc_boundary_script.chmod(0o755)
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_strong_boundary),
            "--language",
            "zh-CN",
        ], plugin_root, "strong-attacker-control PoC wording")

        good_strong_boundary = copy_standard_bundle("strong_attacker_boundary_explained")
        good_boundary_script = good_strong_boundary / "attachments/strong-boundary.sh"
        good_boundary_script.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "# PoC mentions malicious JS, but the report explains the component boundary.\n"
            "printf 'ok {\"ok\":true}\\n' | grep -q 'ok'\n"
            "echo 'VULNERABILITY CONFIRMED'\n",
            encoding="utf-8",
        )
        good_boundary_script.chmod(0o755)
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(good_strong_boundary),
            "--language",
            "zh-CN",
        ], plugin_root)

        bad_bundle_escape = copy_standard_bundle("bundle_escape_root_script")
        escape_script = bad_bundle_escape / "run-selftest-jwt-recording.sh"
        escape_script.write_text(
            escape_script.read_text(encoding="utf-8")
            + "\nREPO_ROOT=\"$(cd \"$SCRIPT_DIR/../../../../..\" && pwd)\"\n"
            + "printf '%s\\n' \"$REPO_ROOT\" >/dev/null\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_bundle_escape),
            "--language",
            "zh-CN",
        ], plugin_root, "depends on a parent path outside the confirmed bundle")

        bad_pkg_dependency = copy_standard_bundle("pkg_index_dependency")
        pkg_script = bad_pkg_dependency / "run-selftest-jwt-recording.sh"
        pkg_script.write_text(
            pkg_script.read_text(encoding="utf-8")
            + "\nprintf '%s\\n' 'unsafe external checkout path /pkg/index.js /pkg/security-research-YYYYMMDD-HHMMSS'\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_pkg_dependency),
            "--language",
            "zh-CN",
        ], plugin_root, "non-standalone path text")

        bad_workspace_marker = copy_standard_bundle("workspace_marker_leak")
        workspace_supplement = next(bad_workspace_marker.glob("*_补充复现说明.md"))
        workspace_supplement.write_text(
            workspace_supplement.read_text(encoding="utf-8")
            + "\n错误示例：材料仍提到 oss-vulnerability-research 和 security-research-YYYYMMDD-HHMMSS。\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_workspace_marker),
            "--language",
            "zh-CN",
        ], plugin_root, "non-standalone path text")

        bad_missing_target_identity = copy_standard_bundle("missing_target_identity")
        missing_target_script = bad_missing_target_identity / "run-selftest-jwt-recording.sh"
        missing_target_script.write_text(
            missing_target_script.read_text(encoding="utf-8")
            .replace("print_target_identity() {", "print_identity_removed() {")
            .replace("    print_target_identity\n    pause_step \"$PAUSE_SHORT\"\n", ""),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_missing_target_identity),
            "--language",
            "zh-CN",
        ], plugin_root, "target software/package")

        bad_late_target_identity = copy_standard_bundle("late_target_identity")
        late_target_script = bad_late_target_identity / "run-selftest-jwt-recording.sh"
        late_target_script.write_text(
            late_target_script.read_text(encoding="utf-8")
            .replace("    print_target_identity\n", "", 1)
            .replace("    show_code_hint\n", "    show_code_hint\n    print_target_identity\n", 1),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_late_target_identity),
            "--language",
            "zh-CN",
        ], plugin_root, "before proof steps")

        bad_undefined_root_helper = copy_standard_bundle("undefined_root_helper")
        undefined_helper_script = bad_undefined_root_helper / "run-selftest-jwt-recording.sh"
        undefined_helper_script.write_text(
            undefined_helper_script.read_text(encoding="utf-8")
            .replace("    show_code_hint\n", "    run_docker_poc\n    show_code_hint\n", 1),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_undefined_root_helper),
            "--language",
            "zh-CN",
        ], plugin_root, "not defined in the same root script")

        good_helper_closed = copy_standard_bundle("helper_closed")
        helper_closed_script = good_helper_closed / "run-selftest-jwt-recording.sh"
        helper_closed_script.write_text(
            helper_closed_script.read_text(encoding="utf-8")
            + "\nverify_closed_helper() {\n    return 0\n}\n\nrun_closed_helper() {\n    verify_closed_helper\n}\n\nrun_closed_helper\n",
            encoding="utf-8",
        )
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(good_helper_closed),
            "--language",
            "zh-CN",
        ], plugin_root)
        shutil.rmtree(good_helper_closed)

        bad_missing_replay_log = copy_standard_bundle("missing_replay_log")
        missing_log_script = bad_missing_replay_log / "run-selftest-jwt-recording.sh"
        missing_log_script.write_text(
            missing_log_script.read_text(encoding="utf-8")
            .replace('REPLAY_LOG="$EVIDENCE_DIR/replay-output.log"', 'REPLAY_TEXT="$EVIDENCE_DIR/replay-output.txt"')
            .replace('> "$REPLAY_LOG"', '> "$REPLAY_TEXT"')
            .replace('>> "$REPLAY_LOG"', '>> "$REPLAY_TEXT"'),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_missing_replay_log),
            "--language",
            "zh-CN",
        ], plugin_root, "bundle-local .log replay evidence")

        bad_unregistered_replay_log = copy_standard_bundle("unregistered_replay_log")
        unregistered_evidence_path = bad_unregistered_replay_log / "verification-evidence.json"
        unregistered_data = json.loads(unregistered_evidence_path.read_text(encoding="utf-8"))
        unregistered_data["evidence_files"] = [
            item for item in unregistered_data.get("evidence_files", [])
            if item != "attachments/evidence/replay-output.log"
        ]
        unregistered_evidence_path.write_text(
            json.dumps(unregistered_data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_unregistered_replay_log),
            "--language",
            "zh-CN",
        ], plugin_root, "must be registered")

        bad_final_without_marker_check = copy_standard_bundle("final_without_marker_check")
        final_without_marker_script = bad_final_without_marker_check / "run-selftest-jwt-recording.sh"
        final_without_marker_script.write_text(
            final_without_marker_script.read_text(encoding="utf-8")
            .replace("    verify_success_marker \"$SUCCESS_MARKER\"\n", ""),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_final_without_marker_check),
            "--language",
            "zh-CN",
        ], plugin_root, "programmatic success-marker check")

        bad_explanatory_marker_text = copy_standard_bundle("explanatory_marker_text")
        explanatory_marker_script = bad_explanatory_marker_text / "run-selftest-jwt-recording.sh"
        explanatory_marker_script.write_text(
            explanatory_marker_script.read_text(encoding="utf-8")
            .replace(
                "    verify_success_marker \"$SUCCESS_MARKER\"\n",
                "    printf '%s\\n' 'if output contains the success marker then the vulnerability is confirmed'\n",
            ),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_explanatory_marker_text),
            "--language",
            "zh-CN",
        ], plugin_root, "programmatic success-marker check")

        bad_log_without_raw_output = copy_standard_bundle("replay_log_without_raw_output")
        log_without_raw_script = bad_log_without_raw_output / "run-selftest-jwt-recording.sh"
        log_without_raw_script.write_text(
            log_without_raw_script.read_text(encoding="utf-8")
            .replace(' > "$command_output" 2>&1', ' >/dev/null 2>/dev/null')
            .replace('        cat "$command_output" >> "$REPLAY_LOG"\n', ''),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_log_without_raw_output),
            "--language",
            "zh-CN",
        ], plugin_root, "raw command stdout/stderr")

        bad_missing_direct_impact = copy_standard_bundle("missing_direct_impact")
        missing_direct_script = bad_missing_direct_impact / "run-selftest-jwt-recording.sh"
        missing_direct_script.write_text(
            re.sub(
                r"\nrecord_direct_impact_marker\(\) \{\n(?:    .+\n)+\}\n",
                "\n",
                missing_direct_script.read_text(encoding="utf-8"),
            )
            .replace("DIRECT_IMPACT_MARKER='DIRECT_IMPACT_CONFIRMED'\n", "")
            .replace("    record_direct_impact_marker \"$DIRECT_IMPACT_MARKER\"\n", "")
            .replace("_CONFIRMED", "_CHECKED")
            .replace("认证绕过成功", "认证检查完成")
            .replace("会话伪造成功", "会话检查完成")
            .replace("direct impact is supported by the DIRECT_IMPACT_CONFIRMED-equivalent marker ", "direct impact is supported by the replay marker "),
            encoding="utf-8",
        )
        for text_path in [
            path for path in bad_missing_direct_impact.rglob("*")
            if path.is_file() and path.suffix in {".json", ".log", ".md", ".sh", ".txt"}
        ]:
            text_path.write_text(
                text_path.read_text(encoding="utf-8")
                .replace("DIRECT_IMPACT_CONFIRMED", "replay success marker")
                .replace("DIRECT_AVAILABILITY_IMPACT_CONFIRMED", "replay availability marker")
                .replace("_CONFIRMED", "_CHECKED")
                .replace("认证绕过成功", "认证检查完成")
                .replace("会话伪造成功", "会话检查完成"),
                encoding="utf-8",
            )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_missing_direct_impact),
            "--language",
            "zh-CN",
        ], plugin_root, "direct-impact replay evidence")

        bad_displayed_command_only = copy_standard_bundle("displayed_command_only")
        displayed_only_script = bad_displayed_command_only / "run-selftest-jwt-recording.sh"
        displayed_only_script.write_text(
            re.sub(
                r"^(\s*)run_logged_command\s+(.+)$",
                r"\1printf '%s\n' \2",
                displayed_only_script.read_text(encoding="utf-8"),
                flags=re.MULTILINE,
            ),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_displayed_command_only),
            "--language",
            "zh-CN",
        ], plugin_root, "without an actual bundle-local execution path")

        bad_missing_helper_reference = copy_standard_bundle("missing_helper_reference")
        missing_helper_note = next(bad_missing_helper_reference.glob("*_补充复现说明.md"))
        missing_helper_note.write_text(
            missing_helper_note.read_text(encoding="utf-8")
            + "\n\n补充检查：如需复核，请执行 `bash ./missing-helper.sh`。\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_missing_helper_reference),
            "--language",
            "zh-CN",
        ], plugin_root, "missing local helper")

        bad_pause_overwrite = copy_standard_bundle("quick_pause_overwrite")
        pause_script = bad_pause_overwrite / "run-selftest-jwt-recording.sh"
        pause_script.write_text(
            pause_script.read_text(encoding="utf-8")
            .replace('PAUSE_SHORT="${REVIEWER_PAUSE_SHORT:-1}"', "PAUSE_SHORT=0")
            .replace('PAUSE_LONG="${REVIEWER_PAUSE_LONG:-2}"', "PAUSE_LONG=0"),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_pause_overwrite),
            "--language",
            "zh-CN",
        ], plugin_root, "quick mode overwrites reviewer pause settings")

        bad_hardcoded_pause = copy_standard_bundle("hardcoded_pause")
        hardcoded_pause_script = bad_hardcoded_pause / "run-selftest-jwt-recording.sh"
        hardcoded_pause_script.write_text(
            hardcoded_pause_script.read_text(encoding="utf-8")
            .replace('pause_step "$PAUSE_SHORT"', "pause_step 1", 1),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_hardcoded_pause),
            "--language",
            "zh-CN",
        ], plugin_root, "fixed reviewer pause")

        bad_recursive_replay = copy_standard_bundle("recursive_replay")
        recursive_script = bad_recursive_replay / "run-selftest-jwt-recording.sh"
        recursive_script.write_text(
            recursive_script.read_text(encoding="utf-8")
            + "\n./$(basename \"$0\") quick docker\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_recursive_replay),
            "--language",
            "zh-CN",
        ], plugin_root, "recursively invoke itself")

        bad_exec_recursive_replay = copy_standard_bundle("exec_recursive_replay")
        exec_recursive_script = bad_exec_recursive_replay / "run-selftest-jwt-recording.sh"
        exec_recursive_script.write_text(
            exec_recursive_script.read_text(encoding="utf-8")
            + "\nexec \"$0\" quick docker\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_exec_recursive_replay),
            "--language",
            "zh-CN",
        ], plugin_root, "recursively invoke itself")

        bad_time_exact = copy_standard_bundle("stale_exact_timing_summary")
        time_supplement = next(bad_time_exact.glob("*_补充复现说明.md"))
        time_supplement.write_text(
            time_supplement.read_text(encoding="utf-8")
            + "\n补充：可用性 proof 的稳定结论是触发耗时 1.37 seconds。\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_time_exact),
            "--language",
            "zh-CN",
        ], plugin_root, "stale exact timings")

        good_time_range = copy_standard_bundle("time_range_summary")
        time_range_supplement = next(good_time_range.glob("*_补充复现说明.md"))
        time_range_supplement.write_text(
            time_range_supplement.read_text(encoding="utf-8")
            + "\n补充：可用性 proof 使用至少 1 秒阈值描述，并要求审核者查看最新日志中的精确数值。\n",
            encoding="utf-8",
        )
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(good_time_range),
            "--language",
            "zh-CN",
        ], plugin_root)

        good_nested_parent_path = copy_standard_bundle("nested_parent_path_inside_bundle")
        nested_script = good_nested_parent_path / "attachments/nested/inside-bundle.sh"
        nested_script.parent.mkdir(parents=True, exist_ok=True)
        nested_script.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "SCRIPT_DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n"
            "BUNDLE_LOCAL=\"$(cd \"$SCRIPT_DIR/..\" && pwd)\"\n"
            "test -d \"$BUNDLE_LOCAL\"\n",
            encoding="utf-8",
        )
        nested_script.chmod(0o755)
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(good_nested_parent_path),
            "--language",
            "zh-CN",
        ], plugin_root)

        npm_warning_bundle = copy_standard_bundle("package_manager_install_warning")
        npm_script = npm_warning_bundle / "attachments/npm-install-warning.sh"
        npm_script.write_text("#!/bin/sh\nset -eu\nnpm install left-pad\n", encoding="utf-8")
        npm_script.chmod(0o755)
        npm_warning_output = run_capture([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(npm_warning_bundle),
            "--language",
            "zh-CN",
        ], plugin_root)
        if "package manager install command" not in npm_warning_output:
            raise SystemExit("FAILED: package manager install warning fixture did not emit a warning")

        poc_label_warning_bundle = copy_standard_bundle("poc_label_warning")
        poc_label_supplement = next(poc_label_warning_bundle.glob("*_补充复现说明.md"))
        poc_label_supplement.write_text(
            poc_label_supplement.read_text(encoding="utf-8")
            + "\n补充：PoC-4 展示了最高编号复现路径，但根录屏脚本尚未覆盖该标签。\n",
            encoding="utf-8",
        )
        poc_label_output = run_capture([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(poc_label_warning_bundle),
            "--language",
            "zh-CN",
        ], plugin_root)
        if "root recording script appears to miss the highest PoC label" not in poc_label_output:
            raise SystemExit("FAILED: PoC label drift fixture did not emit a warning")

        stale_video_bundle = copy_standard_bundle("stale_video_warning")
        stale_video = stale_video_bundle / "复现视频.mp4"
        stale_video.write_bytes(b"placeholder video bytes")
        os.utime(stale_video, (1, 1))
        stale_output = run_capture([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(stale_video_bundle),
            "--language",
            "zh-CN",
        ], plugin_root)
        if "recording appears older than current reproduction script or report material" not in stale_output:
            raise SystemExit("FAILED: stale recording video fixture did not emit a warning")

        def standard_reviewer_paths(bundle: Path) -> tuple[str, str]:
            poc_matches = sorted((bundle / "attachments").rglob("jwt-forge-poc.py"))
            evidence_matches = sorted((bundle / "attachments").rglob("forged-token-response.json"))
            if not poc_matches or not evidence_matches:
                raise SystemExit("FAILED: standard bundle is missing expected reviewer evidence selftest attachments")
            return (
                poc_matches[0].relative_to(bundle).as_posix(),
                evidence_matches[0].relative_to(bundle).as_posix(),
            )

        def write_useful_reviewer_addendum(bundle: Path, *, extra: str = "") -> None:
            _poc_rel, evidence_rel = standard_reviewer_paths(bundle)
            (bundle / "reviewer-evidence-and-impact.md").write_text(
                "# 审核证据与影响说明\n\n"
                "## 攻击者能力与边界\n\n"
                "攻击者需要能够向已确认的 Docker 复现入口提交伪造 JWT；服务端条件是默认密钥配置生效。"
                "本包只声称 Docker 成功判据证明的认证绕过影响，不声称未验证的主机执行或容器逃逸。\n\n"
                "## 审核方最短复现\n\n"
                "在 bundle 根目录运行 `REVIEWER_PAUSE_SHORT=0 REVIEWER_PAUSE_LONG=0 ./run-selftest-jwt-recording.sh quick docker`。\n\n"
                "## 成功判据与证据映射\n\n"
                "- 成功判据：`认证绕过成功`\n"
                f"- 证据文件：`{evidence_rel}`\n\n"
                "## 已验证影响\n\n"
                "已验证影响是完整性与认证边界绕过，审核材料中的证据和 replay command 均为 bundle-local。\n"
                + (f"\n{extra}\n" if extra else ""),
                encoding="utf-8",
            )

        def write_standard_reviewer_index(
            bundle: Path,
            *,
            oracle: str = "认证绕过成功",
            artifact_paths: list[str] | None = None,
            command: str = "REVIEWER_PAUSE_SHORT=0 REVIEWER_PAUSE_LONG=0 ./run-selftest-jwt-recording.sh quick docker",
            extra: dict | None = None,
        ) -> None:
            poc_rel, evidence_rel = standard_reviewer_paths(bundle)
            data = {
                "schema_version": 1,
                "finding_slug": bundle.name,
                "bundle_root_command": command,
                "poc_files": [poc_rel],
                "evidence_outputs": artifact_paths if artifact_paths is not None else [evidence_rel],
                "success_oracles": [oracle],
                "real_world_exploitability_summary": "攻击者控制伪造 JWT，默认密钥配置让认证绕过在 Docker 中可达。",
                "boundaries": ["不声称容器逃逸或宿主机执行。"],
            }
            if extra:
                data.update(extra)
            index_path = bundle / "attachments/reviewer-evidence-index.json"
            index_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        good_reviewer_index = copy_standard_bundle("reviewer_index_valid")
        write_useful_reviewer_addendum(good_reviewer_index)
        write_standard_reviewer_index(good_reviewer_index)
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(good_reviewer_index),
            "--language",
            "zh-CN",
        ], plugin_root)

        bad_index_missing_artifact = copy_standard_bundle("reviewer_index_missing_artifact")
        write_useful_reviewer_addendum(bad_index_missing_artifact)
        write_standard_reviewer_index(
            bad_index_missing_artifact,
            artifact_paths=["attachments/evidence/does-not-exist.log"],
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_index_missing_artifact),
            "--language",
            "zh-CN",
        ], plugin_root, "referenced artifact path does not exist")

        bad_index_outside_path = copy_standard_bundle("reviewer_index_outside_path")
        write_useful_reviewer_addendum(bad_index_outside_path)
        write_standard_reviewer_index(bad_index_outside_path, artifact_paths=["../outside.log"])
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_index_outside_path),
            "--language",
            "zh-CN",
        ], plugin_root, "must stay inside the bundle")

        bad_index_local_path = copy_standard_bundle("reviewer_index_local_path")
        write_useful_reviewer_addendum(bad_index_local_path)
        submitter_local_path = "/" + "Users/" + "torchbearer/tmp/evidence.log"
        write_standard_reviewer_index(bad_index_local_path, artifact_paths=[submitter_local_path])
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_index_local_path),
            "--language",
            "zh-CN",
        ], plugin_root, "absolute/operator-local")

        bad_index_missing_oracle_source = copy_standard_bundle("reviewer_index_missing_oracle_source")
        write_useful_reviewer_addendum(bad_index_missing_oracle_source)
        write_standard_reviewer_index(bad_index_missing_oracle_source, oracle="NEVER_OBSERVED_REVIEWER_ORACLE")
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_index_missing_oracle_source),
            "--language",
            "zh-CN",
        ], plugin_root, "success oracle token is not present")

        bad_placeholder_addendum = copy_standard_bundle("reviewer_addendum_placeholder")
        (bad_placeholder_addendum / "reviewer-evidence-and-impact.md").write_text(
            "# 审核证据\n\nTODO\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_placeholder_addendum),
            "--language",
            "zh-CN",
        ], plugin_root, "placeholder-only")

        bad_fixture_without_provenance = copy_standard_bundle("fixture_without_provenance")
        fixture_supplement = next(bad_fixture_without_provenance.glob("*_补充复现说明.md"))
        fixture_supplement.write_text(
            fixture_supplement.read_text(encoding="utf-8")
            + "\n补充：本包使用 minimal fixture replay。\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_fixture_without_provenance),
            "--language",
            "zh-CN",
        ], plugin_root, "source-grounded provenance")

        good_fixture_provenance = copy_standard_bundle("fixture_with_provenance")
        write_useful_reviewer_addendum(
            good_fixture_provenance,
            extra=(
                "## fixture provenance\n\n"
                "本包使用最小 fixture，但它保留原始源码中的危险模式和 Docker 复现边界；"
                "该 fixture 足以复现认证绕过边界。未验证、不声称容器逃逸、宿主机 RCE 或更强影响。"
            ),
        )
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(good_fixture_provenance),
            "--language",
            "zh-CN",
        ], plugin_root)

        bad_library_boundary = copy_standard_bundle("library_boundary_missing")
        library_supplement = next(bad_library_boundary.glob("*_补充复现说明.md"))
        library_supplement.write_text(
            library_supplement.read_text(encoding="utf-8")
            + "\n补充：这是一个库漏洞，public API 接收攻击者可控 key。\n",
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_library_boundary),
            "--language",
            "zh-CN",
        ], plugin_root, "consumer application boundary")

        good_q_style_boundary = copy_standard_bundle("q_style_library_boundary")
        write_useful_reviewer_addendum(
            good_q_style_boundary,
            extra=(
                "## library consumer boundary\n\n"
                "这是 q-style library/package 漏洞：public API `Q.set` 接收攻击者可控 key/name 参数。"
                "消费方或上层应用需要把用户字段名桥接到该 API，库本身不提供网络入口。"
                "单步路径是目标对象局部 prototype chain hijack；全局 `Object.prototype` 污染只在额外 consumer pattern 中成立，"
                "本包不声称无上层应用桥接即可远程触发。"
            ),
        )
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(good_q_style_boundary),
            "--language",
            "zh-CN",
        ], plugin_root)

        good_speedtest_style_fixture = copy_standard_bundle("speedtest_style_fixture")
        speedtest_evidence_dir = good_speedtest_style_fixture / "attachments/evidence"
        speedtest_evidence_dir.mkdir(parents=True, exist_ok=True)
        (speedtest_evidence_dir / "webshell-oracle.txt").write_text(
            "WEBSHELL_CONFIRMED\nuid=82(www-data)\n",
            encoding="utf-8",
        )
        write_useful_reviewer_addendum(
            good_speedtest_style_fixture,
            extra=(
                "## Speedtest-style source-grounded fixture\n\n"
                "本包使用最小 fixture，保留原始源码中的 sed/entrypoint 危险模式；fixture 足以复现代码注入边界。"
                "成功判据包括 `WEBSHELL_CONFIRMED` 与 `uid=82(www-data)`，对应 `attachments/evidence/webshell-oracle.txt`。"
                "未验证、不声称容器逃逸、宿主机执行或匿名公开入口。"
            ),
        )
        write_standard_reviewer_index(
            good_speedtest_style_fixture,
            oracle="WEBSHELL_CONFIRMED",
            artifact_paths=["attachments/evidence/webshell-oracle.txt"],
            extra={"fixture_files": ["attachments/evidence/webshell-oracle.txt"]},
        )
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(good_speedtest_style_fixture),
            "--language",
            "zh-CN",
        ], plugin_root)

        bad_severity_mismatch = copy_standard_bundle("severity_body_mismatch")
        mutate_bundle_finding(bad_severity_mismatch, lambda _finding: None)
        from docx import Document
        severity_docx_path = next(bad_severity_mismatch.glob("*.docx"))
        severity_doc = Document(severity_docx_path)
        severity_doc.add_paragraph("等级判定：中危")
        severity_doc.save(severity_docx_path)
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_severity_mismatch),
            "--language",
            "zh-CN",
        ], plugin_root, "report body severity does not match")

        bad_claim_overreach = copy_standard_bundle("webshell_claim_without_oracle")
        write_useful_reviewer_addendum(
            bad_claim_overreach,
            extra=(
                "## 过强声明夹具\n\n"
                "本段故意声称已验证 HTTP webshell 命令执行，但成功判据仍只有 `认证绕过成功`，用于确认 validator 会拒绝 claim/oracle 不一致。"
            ),
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_claim_overreach),
            "--language",
            "zh-CN",
        ], plugin_root, "webshell or HTTP command execution")

        bad_missing_attacker = quality_gate_bad_bundle(
            "missing_attacker_condition",
            lambda text: None if text.startswith("攻击者条件") or text.startswith("入口/可控输入") else text,
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_missing_attacker),
            "--language",
            "zh-CN",
        ], plugin_root, "missing 攻击者条件")

        bad_missing_server = quality_gate_bad_bundle(
            "missing_server_condition",
            lambda text: None if text.startswith("服务端条件") else text,
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_missing_server),
            "--language",
            "zh-CN",
        ], plugin_root, "missing 服务端条件")

        bad_missing_impact = quality_gate_bad_bundle(
            "missing_security_impact",
            lambda text: None if text.startswith("安全影响") else text,
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_missing_impact),
            "--language",
            "zh-CN",
        ], plugin_root, "missing 安全影响")

        bad_placeholder_attacker = quality_gate_bad_bundle(
            "placeholder_attacker_condition",
            lambda text: "攻击者条件：待补充" if text.startswith("攻击者条件") else text,
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_placeholder_attacker),
            "--language",
            "zh-CN",
        ], plugin_root, "placeholder-only")

        bad_weak_impact = quality_gate_bad_bundle(
            "weak_security_impact",
            lambda text: "安全影响：该问题很危险。" if text.startswith("安全影响") else text,
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_weak_impact),
            "--language",
            "zh-CN",
        ], plugin_root, "must mention a concrete CIA impact")
        for bad_quality_bundle in (
            bad_missing_attacker,
            bad_missing_server,
            bad_missing_impact,
            bad_placeholder_attacker,
            bad_weak_impact,
            bad_missing_real_world,
            bad_placeholder_real_world,
            bad_strong_boundary,
            good_strong_boundary,
            bad_en_missing_real_world,
            bad_bundle_escape,
            bad_pkg_dependency,
            bad_workspace_marker,
            bad_missing_target_identity,
            bad_late_target_identity,
            bad_undefined_root_helper,
            bad_missing_replay_log,
            bad_unregistered_replay_log,
            bad_final_without_marker_check,
            bad_explanatory_marker_text,
            bad_log_without_raw_output,
            bad_missing_direct_impact,
            bad_displayed_command_only,
            bad_missing_helper_reference,
            bad_pause_overwrite,
            bad_hardcoded_pause,
            bad_recursive_replay,
            bad_exec_recursive_replay,
            bad_time_exact,
            good_time_range,
            good_nested_parent_path,
            npm_warning_bundle,
            poc_label_warning_bundle,
            stale_video_bundle,
            good_reviewer_index,
            bad_index_missing_artifact,
            bad_index_outside_path,
            bad_index_local_path,
            bad_index_missing_oracle_source,
            bad_placeholder_addendum,
            bad_fixture_without_provenance,
            good_fixture_provenance,
            bad_library_boundary,
            good_q_style_boundary,
            good_speedtest_style_fixture,
            bad_severity_mismatch,
            bad_claim_overreach,
        ):
            shutil.rmtree(bad_quality_bundle)
        legacy_marker_fixture = workspace / "legacy-english-analysis-markers-finding.json"
        legacy_marker_data = json.loads(standard_fixture.read_text(encoding="utf-8"))
        legacy_marker_data["vulnerability_id"] = "SELFTEST-LEGACY-MARKERS"
        legacy_marker_data["vulnerability_name"] = "导入URL服务端请求伪造"
        legacy_marker_data["severity"] = "高危"
        legacy_marker_data["severity_cn"] = "高危"
        legacy_marker_data["cvss"] = {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "score": "7.5",
            "severity": "高危",
            "rationale": ["评估依据：服务端可被诱导访问内网资源，形成 SSRF 信息泄露风险。"],
        }
        legacy_marker_data["analysis"] = [
            "Location: api/src/services/files.ts importOne() accepts a user-supplied URL.",
            "Entry / controllable input: an authenticated attacker submits an import URL.",
            "Dangerous operation: axios.get() performs a server-side fetch.",
            "Trigger path: URL import -> server fetch -> attacker-controlled internal destination.",
            "Root cause: URL import lacks complete private-network deny-list validation.",
            "Why existing checks fail: the current deny list is incomplete for common internal ranges.",
        ]
        legacy_marker_fixture.write_text(json.dumps(legacy_marker_data, ensure_ascii=False, indent=2), encoding="utf-8")
        run([
            sys.executable,
            str(workspace / "bin/render-confirmed-vuln-docx.py"),
            "--input",
            str(legacy_marker_fixture),
            "--output-dir",
            str(workspace / "confirmed"),
            "--language",
            "zh-CN",
        ], plugin_root)
        legacy_marker_bundle = next(
            (
                path for path in (workspace / "confirmed").iterdir()
                if path.is_dir() and "导入URL" in path.name
            ),
            None,
        )
        if legacy_marker_bundle is None:
            raise SystemExit("FAILED: legacy marker fixture did not render a confirmed bundle")
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(legacy_marker_bundle),
            "--language",
            "zh-CN",
        ], plugin_root)
        legacy_marker_lines = "\n".join(docx_text(next(legacy_marker_bundle.glob("*.docx"))))
        if "Location:" in legacy_marker_lines or "Entry / controllable input:" in legacy_marker_lines:
            raise SystemExit("FAILED: renderer did not localize legacy English analysis markers for zh-CN output")
        if "位置：" not in legacy_marker_lines or "入口/可控输入：" not in legacy_marker_lines:
            raise SystemExit("FAILED: localized zh-CN analysis markers are missing from legacy marker fixture")
        missing_name_fixture = workspace / "missing-vulnerability-name-finding.json"
        missing_name_data = json.loads(standard_fixture.read_text(encoding="utf-8"))
        missing_name_data.pop("vulnerability_name", None)
        missing_name_data.pop("vulnerability_name_en", None)
        missing_name_data["title_zh"] = "gothinkster/node-express-realworld-example-app 默认配置下硬编码 JWT 密钥导致身份认证绕过并允许攻击者伪造任意用户 token 的完整漏洞报告标题"
        missing_name_fixture.write_text(json.dumps(missing_name_data, ensure_ascii=False, indent=2), encoding="utf-8")
        run_expect_fail([
            sys.executable,
            str(workspace / "bin/render-confirmed-vuln-docx.py"),
            "--input",
            str(missing_name_fixture),
            "--output-dir",
            str(workspace / "confirmed"),
            "--language",
            "zh-CN",
        ], plugin_root, "must include vulnerability_name")

        bad_runtime_scope = zh_bundle.parent / f"{standard_bundle.name}_runtime_scope_overclaim"
        shutil.copytree(standard_bundle, bad_runtime_scope)
        runtime_scope_findings_path = bad_runtime_scope / "findings.json"
        if not runtime_scope_findings_path.exists():
            shutil.copy2(standard_fixture, runtime_scope_findings_path)
        runtime_scope_data = json.loads(runtime_scope_findings_path.read_text(encoding="utf-8"))
        runtime_scope_data["source_runtime_match"] = False
        runtime_scope_data.setdefault("impact", {})["affected_versions"] = "v2.9.1（Docker 验证版本），可能影响所有版本"
        runtime_scope_findings_path.write_text(
            json.dumps(runtime_scope_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_runtime_scope),
            "--language",
            "zh-CN",
        ], plugin_root, "source/runtime mismatch detected")

        nested_warning_bundle = zh_bundle.parent / f"{standard_bundle.name}_nested_attachment_warning"
        shutil.copytree(standard_bundle, nested_warning_bundle)
        nested_dir = nested_warning_bundle / "attachments/security-research-20260502-123456/evidence"
        nested_dir.mkdir(parents=True, exist_ok=True)
        nested_file = nested_dir / "forged-token-response.json"
        nested_file.write_text('{"ok":true,"nested":true}\n', encoding="utf-8")
        nested_evidence_data = json.loads((nested_warning_bundle / "verification-evidence.json").read_text(encoding="utf-8"))
        nested_evidence_data["evidence_files"].append("attachments/security-research-20260502-123456/evidence/forged-token-response.json")
        (nested_warning_bundle / "verification-evidence.json").write_text(
            json.dumps(nested_evidence_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        nested_proc = subprocess.run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(nested_warning_bundle),
            "--language",
            "zh-CN",
        ], cwd=plugin_root, capture_output=True, text=True)
        nested_output = (nested_proc.stdout or "") + (nested_proc.stderr or "")
        if nested_proc.returncode == 0:
            raise SystemExit("FAILED: nested timestamped workspace attachment fixture unexpectedly validated")
        if "non-standalone path text" not in nested_output:
            raise SystemExit(
                "FAILED: nested timestamped workspace attachment fixture did not fail on the new path-redaction gate\n"
                + nested_output
            )
        shutil.rmtree(bad_runtime_scope)
        shutil.rmtree(nested_warning_bundle)
        events_before_bundle_validation = [
            json.loads(line)
            for line in (workspace / "audit-events.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        bundle_validated_before = sum(
            1 for event in events_before_bundle_validation
            if event.get("event") == "bundle_validated"
        )
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(en_bundle),
            "--language",
            "en-US",
            "--write-audit-event",
        ], plugin_root)
        shutil.copy2(
            plugin_root / "assets/examples/confirmed-findings.example.json",
            workspace / "confirmed/findings.example.json",
        )
        shutil.copy2(
            plugin_root / "assets/confirmed-vuln-report-template.docx",
            workspace / "confirmed/confirmed-vuln-report-template.docx",
        )
        (workspace / "confirmed/.DS_Store").write_text("", encoding="utf-8")
        run([
            sys.executable,
            str(workspace / "bin/validate-all-report-bundles.py"),
            "--confirmed-dir",
            str(workspace / "confirmed"),
        ], plugin_root)
        partial_confirmed = workspace / "confirmed/C99-partial-confirmed"
        partial_confirmed.mkdir()
        shutil.copy2(zh_bundle / "verification-evidence.json", partial_confirmed / "verification-evidence.json")
        (partial_confirmed / "findings.json").write_text(
            json.dumps({"findings": [{"slug": "c99-partial-confirmed"}]}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(workspace / "bin/validate-all-report-bundles.py"),
            "--confirmed-dir",
            str(workspace / "confirmed"),
        ], plugin_root, "partial confirmed bundle")
        partial_json_proc = subprocess.run([
            sys.executable,
            str(workspace / "bin/validate-all-report-bundles.py"),
            "--confirmed-dir",
            str(workspace / "confirmed"),
            "--json",
        ], cwd=plugin_root, capture_output=True, text=True)
        if partial_json_proc.returncode == 0:
            raise SystemExit("FAILED: validate-all-report-bundles.py --json unexpectedly passed with a partial bundle")
        partial_json = json.loads(partial_json_proc.stdout)
        partial_entries = [
            item for item in partial_json.get("results", [])
            if item.get("name") == "C99-partial-confirmed"
        ]
        if not partial_entries or partial_entries[0].get("classification") != "partial_confirmed_bundle":
            raise SystemExit("FAILED: validate-all-report-bundles.py --json did not classify the partial bundle")
        helper_classes = {
            item.get("name"): item.get("classification")
            for item in partial_json.get("results", [])
            if item.get("name") in {
                "findings.example.json",
                "confirmed-vuln-report-template.docx",
                ".DS_Store",
            }
        }
        expected_helpers = {
            "findings.example.json",
            "confirmed-vuln-report-template.docx",
            ".DS_Store",
        }
        if set(helper_classes) != expected_helpers or set(helper_classes.values()) != {"ignored_helper_file"}:
            raise SystemExit("FAILED: validate-all-report-bundles.py --json did not ignore confirmed/ helper files")
        events_after_bundle_validation = [
            json.loads(line)
            for line in (workspace / "audit-events.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        bundle_validated_events = [
            event for event in events_after_bundle_validation
            if event.get("event") == "bundle_validated"
        ]
        if len(bundle_validated_events) != bundle_validated_before + 1:
            raise SystemExit("FAILED: validate_report_bundle.py did not append exactly one bundle_validated event")
        bundle_event = bundle_validated_events[-1]
        if bundle_event.get("stage") != "reporting" or bundle_event.get("status") != "ok":
            raise SystemExit("FAILED: bundle_validated event must use reporting/ok without completing the audit")
        details = bundle_event.get("details") or {}
        if details.get("bundle") != f"confirmed/{en_bundle.name}":
            raise SystemExit("FAILED: bundle_validated event must store a workspace-relative bundle path")
        if details.get("verification_status") != "confirmed_in_docker":
            raise SystemExit("FAILED: bundle_validated event must preserve confirmed_in_docker evidence status")
        stage_status = json.loads((workspace / "stage-status.json").read_text(encoding="utf-8"))
        if stage_status.get("last_event") != "bundle_validated" or stage_status.get("status") != "running":
            raise SystemExit("FAILED: bundle validation must update state without marking the audit completed")

        bad_missing_verification = zh_bundle.parent / f"{zh_bundle.name}_missing_verification_evidence"
        shutil.copytree(zh_bundle, bad_missing_verification)
        (bad_missing_verification / "verification-evidence.json").unlink()
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_missing_verification),
            "--language",
            "zh-CN",
        ], plugin_root, "confirmed bundle must include verification-evidence.json")

        bad_high_confidence = zh_bundle.parent / f"{zh_bundle.name}_high_confidence_status"
        shutil.copytree(zh_bundle, bad_high_confidence)
        high_confidence_data = json.loads((bad_high_confidence / "verification-evidence.json").read_text(encoding="utf-8"))
        high_confidence_data["verification_status"] = "high_confidence_unverified_due_to_sandbox_limitation"
        (bad_high_confidence / "verification-evidence.json").write_text(
            json.dumps(high_confidence_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_high_confidence),
            "--language",
            "zh-CN",
        ], plugin_root, "verification_status=confirmed_in_docker")

        bad_missing_evidence_file = zh_bundle.parent / f"{zh_bundle.name}_missing_evidence_file"
        shutil.copytree(zh_bundle, bad_missing_evidence_file)
        missing_evidence_data = json.loads((bad_missing_evidence_file / "verification-evidence.json").read_text(encoding="utf-8"))
        missing_evidence_data["evidence_files"] = ["attachments/evidence/missing.log"]
        (bad_missing_evidence_file / "verification-evidence.json").write_text(
            json.dumps(missing_evidence_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_missing_evidence_file),
            "--language",
            "zh-CN",
        ], plugin_root, "does not exist inside bundle")

        bad_absolute_evidence = zh_bundle.parent / f"{zh_bundle.name}_absolute_evidence_path"
        shutil.copytree(zh_bundle, bad_absolute_evidence)
        absolute_evidence_data = json.loads((bad_absolute_evidence / "verification-evidence.json").read_text(encoding="utf-8"))
        absolute_evidence_data["evidence_files"] = [str((bad_absolute_evidence / "attachments/poc/path_traversal.py").resolve())]
        (bad_absolute_evidence / "verification-evidence.json").write_text(
            json.dumps(absolute_evidence_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_absolute_evidence),
            "--language",
            "zh-CN",
        ], plugin_root, "must be bundle-relative")

        bad_escape_evidence = zh_bundle.parent / f"{zh_bundle.name}_escape_evidence_path"
        shutil.copytree(zh_bundle, bad_escape_evidence)
        escape_evidence_data = json.loads((bad_escape_evidence / "verification-evidence.json").read_text(encoding="utf-8"))
        escape_evidence_data["evidence_files"] = ["../outside.log"]
        (bad_escape_evidence / "verification-evidence.json").write_text(
            json.dumps(escape_evidence_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_escape_evidence),
            "--language",
            "zh-CN",
        ], plugin_root, "must not escape the bundle with '..'")

        bad_empty_poc = zh_bundle.parent / f"{zh_bundle.name}_empty_poc_path"
        shutil.copytree(zh_bundle, bad_empty_poc)
        empty_poc_data = json.loads((bad_empty_poc / "verification-evidence.json").read_text(encoding="utf-8"))
        empty_poc_data["poc_path"] = ""
        (bad_empty_poc / "verification-evidence.json").write_text(
            json.dumps(empty_poc_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_empty_poc),
            "--language",
            "zh-CN",
        ], plugin_root, "verification-evidence.json poc_path must not be empty")

        bad_absolute_poc = zh_bundle.parent / f"{zh_bundle.name}_absolute_poc_path"
        shutil.copytree(zh_bundle, bad_absolute_poc)
        absolute_poc_data = json.loads((bad_absolute_poc / "verification-evidence.json").read_text(encoding="utf-8"))
        absolute_poc_data["poc_path"] = str((bad_absolute_poc / "attachments/poc/path_traversal.py").resolve())
        (bad_absolute_poc / "verification-evidence.json").write_text(
            json.dumps(absolute_poc_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_absolute_poc),
            "--language",
            "zh-CN",
        ], plugin_root, "must be bundle-relative")

        bad_escape_poc = zh_bundle.parent / f"{zh_bundle.name}_escape_poc_path"
        shutil.copytree(zh_bundle, bad_escape_poc)
        escape_poc_data = json.loads((bad_escape_poc / "verification-evidence.json").read_text(encoding="utf-8"))
        escape_poc_data["poc_path"] = "../outside-poc.py"
        (bad_escape_poc / "verification-evidence.json").write_text(
            json.dumps(escape_poc_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_escape_poc),
            "--language",
            "zh-CN",
        ], plugin_root, "must not escape the bundle with '..'")

        bad_symlink_escape = zh_bundle.parent / f"{zh_bundle.name}_symlink_escape"
        shutil.copytree(zh_bundle, bad_symlink_escape)
        outside_file = zh_bundle.parent / "outside-symlink-target.log"
        outside_file.write_text("outside evidence\n", encoding="utf-8")
        symlink_path = bad_symlink_escape / "attachments/evidence/outside-link.log"
        symlink_path.parent.mkdir(parents=True, exist_ok=True)
        symlink_path.symlink_to(outside_file)
        symlink_data = json.loads((bad_symlink_escape / "verification-evidence.json").read_text(encoding="utf-8"))
        symlink_data["evidence_files"] = ["attachments/evidence/outside-link.log"]
        (bad_symlink_escape / "verification-evidence.json").write_text(
            json.dumps(symlink_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_symlink_escape),
            "--language",
            "zh-CN",
        ], plugin_root, "escapes the bundle root")

        bad_docker_required = zh_bundle.parent / f"{zh_bundle.name}_docker_required_false"
        shutil.copytree(zh_bundle, bad_docker_required)
        docker_required_data = json.loads((bad_docker_required / "verification-evidence.json").read_text(encoding="utf-8"))
        docker_required_data["docker_required"] = False
        (bad_docker_required / "verification-evidence.json").write_text(
            json.dumps(docker_required_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_docker_required),
            "--language",
            "zh-CN",
        ], plugin_root, "docker_required must be true")

        bad_no_escalation = zh_bundle.parent / f"{zh_bundle.name}_no_severity_escalation"
        shutil.copytree(zh_bundle, bad_no_escalation)
        no_escalation_data = json.loads((bad_no_escalation / "verification-evidence.json").read_text(encoding="utf-8"))
        no_escalation_data["severity_escalation_attempted"] = False
        (bad_no_escalation / "verification-evidence.json").write_text(
            json.dumps(no_escalation_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_no_escalation),
            "--language",
            "zh-CN",
        ], plugin_root, "severity_escalation_attempted must be true")

        bad_empty_docker_command = zh_bundle.parent / f"{zh_bundle.name}_empty_docker_command"
        shutil.copytree(zh_bundle, bad_empty_docker_command)
        empty_command_data = json.loads((bad_empty_docker_command / "verification-evidence.json").read_text(encoding="utf-8"))
        empty_command_data["docker_command"] = ""
        (bad_empty_docker_command / "verification-evidence.json").write_text(
            json.dumps(empty_command_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_empty_docker_command),
            "--language",
            "zh-CN",
        ], plugin_root, "docker_command must not be empty")

        bad_placeholder_image = zh_bundle.parent / f"{zh_bundle.name}_placeholder_docker_image"
        shutil.copytree(zh_bundle, bad_placeholder_image)
        placeholder_image_data = json.loads((bad_placeholder_image / "verification-evidence.json").read_text(encoding="utf-8"))
        placeholder_image_data["docker_image"] = "project-specific Docker image or Docker Compose service"
        (bad_placeholder_image / "verification-evidence.json").write_text(
            json.dumps(placeholder_image_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_placeholder_image),
            "--language",
            "zh-CN",
        ], plugin_root, "must not use placeholder text")

        bad_missing_attachments = zh_bundle.parent / f"{zh_bundle.name}_missing_attachments"
        shutil.copytree(zh_bundle, bad_missing_attachments)
        shutil.rmtree(bad_missing_attachments / "attachments")
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_missing_attachments),
            "--language",
            "zh-CN",
        ], plugin_root, "does not exist inside bundle")

        bad_multi_finding = zh_bundle.parent / f"{zh_bundle.name}_multi_finding"
        shutil.copytree(zh_bundle, bad_multi_finding)
        (bad_multi_finding / "findings.json").write_text(
            json.dumps({"findings": [{"slug": "one"}, {"slug": "two"}]}, ensure_ascii=False),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_multi_finding),
            "--language",
            "zh-CN",
        ], plugin_root, "per-bundle findings.json must describe exactly one confirmed vulnerability")

        bad_runtime_state = zh_bundle.parent / f"{zh_bundle.name}_runtime_state"
        shutil.copytree(zh_bundle, bad_runtime_state)
        (bad_runtime_state / ".omc" / "state").mkdir(parents=True)
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(bad_runtime_state),
            "--language",
            "zh-CN",
        ], plugin_root, "final confirmed bundle must not contain runtime or source-control directory")

        # --- Finalization gate tests ---
        if not (workspace / "bin/finalize-audit-workspace.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing finalize-audit-workspace.py")

        SKIP_DOCKER_ENV = {"ZHULONG_TEST_SKIP_DOCKER_CLEAN_CHECK": "1"}

        def disposition_item(
            *,
            item_id: str,
            state: str,
            source_type: str,
            docker_status: str,
            reason_code: str,
            confirmed_bundle_path: str = "",
            docker_applicable: bool = True,
            title: str = "selftest disposition item",
            materiality_rationale: str = "selftest material item",
        ) -> dict:
            return {
                "id": item_id,
                "title": title,
                "state": state,
                "source_type": source_type,
                "docker_applicable": docker_applicable,
                "docker_status": docker_status,
                "reason_code": reason_code,
                "confirmed_bundle_path": confirmed_bundle_path,
                "materiality_rationale": materiality_rationale,
            }

        def make_disposition_fixture(
            name: str,
            *,
            items: list[dict],
            copy_valid_bundle: bool,
        ) -> Path:
            fixture = repo_dir / name
            if fixture.exists():
                shutil.rmtree(fixture)
            (fixture / "confirmed").mkdir(parents=True, exist_ok=True)
            (fixture / "docker").mkdir(parents=True, exist_ok=True)
            (fixture / "asr-config.json").write_text(
                json.dumps({
                    "workspace_root": fixture.name,
                    "workspace_created_at": "2026-05-06T00:00:00Z",
                    "confirmed_output_dir": f"{fixture.name}/confirmed",
                }, indent=2),
                encoding="utf-8",
            )
            for filename, heading in (
                ("candidate-findings.md", "# Candidate Findings\n\n"),
                ("false-positives.md", "# False Positives and Non-Security Defects\n\n"),
                ("unverified-leads.md", "# Unverified Leads\n\n"),
                ("attack-surface.md", "# Attack Surface Handoff\n\n"),
            ):
                (fixture / filename).write_text(heading, encoding="utf-8")
            if copy_valid_bundle:
                shutil.copytree(zh_bundle, fixture / "confirmed" / zh_bundle.name)
            (fixture / "audit-disposition.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "generated_at": "2026-05-06T00:00:01Z",
                        "workspace": fixture.name,
                        "items": items,
                    },
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ) + "\n",
                encoding="utf-8",
            )
            return fixture

        valid_bundle_rel = f"confirmed/{zh_bundle.name}"
        valid_disposition_workspace = make_disposition_fixture(
            "security-research-disposition-valid",
            items=[
                disposition_item(
                    item_id="confirmed:selftest",
                    state="confirmed",
                    source_type="hybrid",
                    docker_status="reproduced",
                    reason_code="docker_reproduced",
                    confirmed_bundle_path=valid_bundle_rel,
                    materiality_rationale="Docker reproduction succeeded and bundle validation passes.",
                )
            ],
            copy_valid_bundle=True,
        )
        run([
            sys.executable,
            str(plugin_root / "scripts/audit_disposition.py"),
            "--workspace-dir",
            str(valid_disposition_workspace),
            "--result",
            "completed_with_confirmed_bundles",
        ], plugin_root)
        for source_type, reason_code in (
            ("scanner", "scanner_only"),
            ("dependency", "dependency_only"),
            ("static", "static_only"),
            ("llm", "llm_only"),
        ):
            source_only_workspace = make_disposition_fixture(
                f"security-research-disposition-{source_type}",
                items=[
                    disposition_item(
                        item_id=f"confirmed:{source_type}",
                        state="confirmed",
                        source_type=source_type,
                        docker_status="reproduced",
                        reason_code=reason_code,
                        confirmed_bundle_path=valid_bundle_rel,
                    )
                ],
                copy_valid_bundle=True,
            )
            run_expect_fail([
                sys.executable,
                str(plugin_root / "scripts/audit_disposition.py"),
                "--workspace-dir",
                str(source_only_workspace),
                "--result",
                "completed_with_confirmed_bundles",
            ], plugin_root, f"source_type={source_type} cannot be confirmed")
        not_reproduced_workspace = make_disposition_fixture(
            "security-research-disposition-not-reproduced",
            items=[
                disposition_item(
                    item_id="confirmed:not-reproduced",
                    state="confirmed",
                    source_type="hybrid",
                    docker_status="failed",
                    reason_code="not_reproducible",
                    confirmed_bundle_path=valid_bundle_rel,
                )
            ],
            copy_valid_bundle=True,
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/audit_disposition.py"),
            "--workspace-dir",
            str(not_reproduced_workspace),
            "--result",
            "completed_with_confirmed_bundles",
        ], plugin_root, "requires docker_status=reproduced")
        non_confirmed_points_to_confirmed = make_disposition_fixture(
            "security-research-disposition-non-confirmed-path",
            items=[
                disposition_item(
                    item_id="candidate:bad-path",
                    state="candidate",
                    source_type="manual",
                    docker_status="not_started",
                    reason_code="insufficient_evidence",
                    confirmed_bundle_path=valid_bundle_rel,
                )
            ],
            copy_valid_bundle=True,
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/audit_disposition.py"),
            "--workspace-dir",
            str(non_confirmed_points_to_confirmed),
            "--result",
            "completed_with_confirmed_bundles",
        ], plugin_root, "non-confirmed items must not point into confirmed/")
        for docker_status, reason_code in (
            ("blocked", "blocked_by_docker"),
            ("timed_out", "timed_out"),
            ("dirty_state", "dirty_docker"),
        ):
            blocking_workspace = make_disposition_fixture(
                f"security-research-disposition-{docker_status}",
                items=[
                    disposition_item(
                        item_id=f"candidate:{docker_status}",
                        state="candidate",
                        source_type="runtime",
                        docker_status=docker_status,
                        reason_code=reason_code,
                    )
                ],
                copy_valid_bundle=False,
            )
            run_expect_fail([
                sys.executable,
                str(plugin_root / "scripts/audit_disposition.py"),
                "--workspace-dir",
                str(blocking_workspace),
                "--result",
                "completed_no_confirmed_findings",
            ], plugin_root, "blocks completed_no_confirmed_findings")

        def write_integrity_fixture(
            fixture_workspace: Path,
            *,
            events: list[dict],
            status: dict,
            docker_status: dict,
            ledger: dict | None = None,
        ) -> None:
            fixture_workspace.mkdir(parents=True, exist_ok=True)
            (fixture_workspace / "docker").mkdir(parents=True, exist_ok=True)
            (fixture_workspace / "asr-config.json").write_text(
                json.dumps({
                    "workspace_root": fixture_workspace.name,
                    "workspace_created_at": "2026-05-06T00:00:00Z",
                    "confirmed_output_dir": f"{fixture_workspace.name}/confirmed",
                }, indent=2),
                encoding="utf-8",
            )
            (fixture_workspace / "stage-status.json").write_text(
                json.dumps(status, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            (fixture_workspace / "audit-events.jsonl").write_text(
                "".join(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n" for event in events),
                encoding="utf-8",
            )
            (fixture_workspace / "docker/docker-cleanliness-status.json").write_text(
                json.dumps(docker_status, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            if ledger is not None:
                (fixture_workspace / "audit-disposition.json").write_text(
                    json.dumps(ledger, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )

        bad_integrity_workspace = repo_dir / "security-research-integrity-bad"
        write_integrity_fixture(
            bad_integrity_workspace,
            events=[
                {
                    "ts": "2026-05-06T00:00:01Z",
                    "event": "finalization_failed",
                    "stage": "finalization",
                    "status": "failed",
                    "message": "Completion gate failed.",
                    "details": {"expected_result": "completed_no_confirmed_findings"},
                }
            ],
            status={
                "stage": "completed",
                "status": "completed",
                "result": "completed_no_confirmed_findings",
                "completed_at": "2026-05-06T00:00:02Z",
            },
            docker_status={
                "schema_version": 1,
                "clean": False,
                "strict": True,
                "workspace": bad_integrity_workspace.name,
            },
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/assert_finalized_workspace.py"),
            "--workspace-dir",
            str(bad_integrity_workspace),
        ], plugin_root, "latest finalization event is finalization_failed")
        run([
            sys.executable,
            str(plugin_root / "scripts/render_handoff_summary.py"),
            "--workspace-dir",
            str(bad_integrity_workspace),
            "--repo-root",
            str(repo_dir),
        ], plugin_root)
        require_text(
            bad_integrity_workspace / "handoff-summary.md",
            "Finalization integrity: `blocked`",
            "handoff blocks manually completed failed finalization",
        )
        require_text(
            bad_integrity_workspace / "handoff-summary.md",
            "Completion gate passed: `false`",
            "handoff does not claim completion gate passed after failed finalization",
        )

        good_integrity_workspace = repo_dir / "security-research-integrity-good"
        write_integrity_fixture(
            good_integrity_workspace,
            events=[
                {
                    "ts": "2026-05-06T00:00:01Z",
                    "event": "finalization_succeeded",
                    "stage": "completed",
                    "status": "ok",
                    "message": "Audit finalized.",
                    "details": {
                        "result": "completed_no_confirmed_findings",
                        "docker_clean": True,
                        "validated_bundles": 0,
                    },
                }
            ],
            status={
                "stage": "completed",
                "status": "completed",
                "result": "completed_no_confirmed_findings",
            },
            docker_status={
                "schema_version": 1,
                "clean": True,
                "strict": True,
                "workspace": good_integrity_workspace.name,
            },
            ledger={
                "schema_version": 1,
                "generated_at": "2026-05-06T00:00:01Z",
                "workspace": good_integrity_workspace.name,
                "items": [],
            },
        )
        run([
            sys.executable,
            str(plugin_root / "scripts/assert_finalized_workspace.py"),
            "--workspace-dir",
            str(good_integrity_workspace),
        ], plugin_root)
        integrity_json = json.loads(run_capture([
            sys.executable,
            str(plugin_root / "scripts/assert_finalized_workspace.py"),
            "--workspace-dir",
            str(good_integrity_workspace),
            "--json",
        ], plugin_root))
        if integrity_json.get("ok") is not True:
            raise SystemExit("FAILED: finalization integrity JSON did not pass for valid completion fixture")

        blocked_finalization_workspace = repo_dir / "security-research-blocked-verification"
        blocked_finalization_workspace.mkdir(parents=True, exist_ok=True)
        (blocked_finalization_workspace / "confirmed").mkdir()
        (blocked_finalization_workspace / "docker").mkdir()
        (blocked_finalization_workspace / "asr-config.json").write_text(
            json.dumps({
                "workspace_root": blocked_finalization_workspace.name,
                "workspace_created_at": "2026-05-06T00:00:00Z",
                "confirmed_output_dir": f"{blocked_finalization_workspace.name}/confirmed",
            }, indent=2),
            encoding="utf-8",
        )
        (blocked_finalization_workspace / "candidate-findings.md").write_text(
            "# Candidate Findings\n\n"
            "| Candidate ID | Suspected Weakness | Evidence So Far | Source-to-Sink Hypothesis | Docker Verification Plan | Status |\n"
            "| --- | --- | --- | --- | --- | --- |\n"
            "| C1 | SSRF | curl_exec sink | webhook url -> curl_exec | start runtime and test internal service | BLOCKED (Docker rate limit) |\n",
            encoding="utf-8",
        )
        (blocked_finalization_workspace / "unverified-leads.md").write_text("# Unverified Leads\n\n", encoding="utf-8")
        (blocked_finalization_workspace / "attack-surface.md").write_text(
            "# Attack Surface Handoff\n\n## Docker Verification Status\n\n"
            "- Running service target: BLOCKED - Docker Hub rate limit, no cached images.\n",
            encoding="utf-8",
        )
        (blocked_finalization_workspace / "docker/docker-cleanliness-status.json").write_text(
            json.dumps({"schema_version": 1, "clean": True, "strict": True}, indent=2),
            encoding="utf-8",
        )
        blocked_proc = subprocess.run([
            sys.executable,
            str(plugin_root / "scripts/finalize_audit_workspace.py"),
            "--workspace-dir",
            str(blocked_finalization_workspace),
            "--result",
            "completed_no_confirmed_findings",
        ], cwd=plugin_root, capture_output=True, text=True, env={**os.environ, **SKIP_DOCKER_ENV})
        blocked_output = (blocked_proc.stdout or "") + (blocked_proc.stderr or "")
        if blocked_proc.returncode == 0:
            raise SystemExit("FAILED: blocked verification finalized as completed_no_confirmed_findings")
        for expected in (
            "Blocked Docker/runtime verification prevents completed_no_confirmed_findings",
            "blocked_verification",
            "docker login",
            "rerun Docker verification",
        ):
            if expected not in blocked_output:
                raise SystemExit(f"FAILED: blocked finalization output missing: {expected}\n{blocked_output}")
        blocked_events = (blocked_finalization_workspace / "audit-events.jsonl").read_text(encoding="utf-8")
        if "finalization_succeeded" in blocked_events:
            raise SystemExit("FAILED: blocked verification wrote finalization_succeeded")
        blocked_status = json.loads((blocked_finalization_workspace / "stage-status.json").read_text(encoding="utf-8"))
        if blocked_status.get("status") != "blocked" or blocked_status.get("blocker") != "blocked_verification":
            raise SystemExit("FAILED: blocked verification did not leave stage-status.json in blocked state")
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/assert_finalized_workspace.py"),
            "--workspace-dir",
            str(blocked_finalization_workspace),
        ], plugin_root, "stage-status.json does not declare a completed workspace")
        run([
            sys.executable,
            str(plugin_root / "scripts/render_handoff_summary.py"),
            "--workspace-dir",
            str(blocked_finalization_workspace),
            "--repo-root",
            str(repo_dir),
        ], plugin_root)
        require_text(
            blocked_finalization_workspace / "handoff-summary.md",
            "Blocked verification: `blocked_verification`",
            "handoff surfaces blocked verification",
        )

        stale_blocker_workspace = repo_dir / "security-research-stale-blocker"
        stale_blocker_workspace.mkdir(parents=True, exist_ok=True)
        (stale_blocker_workspace / "confirmed").mkdir()
        (stale_blocker_workspace / "docker").mkdir()
        (stale_blocker_workspace / "asr-config.json").write_text(
            json.dumps({
                "workspace_root": stale_blocker_workspace.name,
                "workspace_created_at": "2026-05-06T00:00:00Z",
                "confirmed_output_dir": f"{stale_blocker_workspace.name}/confirmed",
            }, indent=2),
            encoding="utf-8",
        )
        (stale_blocker_workspace / "candidate-findings.md").write_text("# Candidate Findings\n\n", encoding="utf-8")
        (stale_blocker_workspace / "unverified-leads.md").write_text("# Unverified Leads\n\n", encoding="utf-8")
        (stale_blocker_workspace / "attack-surface.md").write_text(
            "# Attack Surface Handoff\n\n## Docker Verification Status\n\n"
            "- Docker gate: ready\n"
            "- Running service target: NOT STARTED (images being pulled)\n"
            "- Still blocked or missing: Image pull required\n",
            encoding="utf-8",
        )
        stale_proc = subprocess.run([
            sys.executable,
            str(plugin_root / "scripts/finalize_audit_workspace.py"),
            "--workspace-dir",
            str(stale_blocker_workspace),
            "--result",
            "completed_no_confirmed_findings",
        ], cwd=plugin_root, capture_output=True, text=True, env={**os.environ, **SKIP_DOCKER_ENV})
        stale_output = (stale_proc.stdout or "") + (stale_proc.stderr or "")
        if stale_proc.returncode == 0:
            raise SystemExit("FAILED: stale attack-surface Docker blocker finalized as no-confirmed")
        for expected in ("images being pulled", "Blocked Docker/runtime verification prevents completed_no_confirmed_findings"):
            if expected not in stale_output:
                raise SystemExit(f"FAILED: stale blocker finalization output missing: {expected}\n{stale_output}")

        high_confidence_blocked_workspace = repo_dir / "security-research-high-confidence-blocked"
        high_confidence_blocked_workspace.mkdir(parents=True, exist_ok=True)
        (high_confidence_blocked_workspace / "confirmed").mkdir()
        (high_confidence_blocked_workspace / "asr-config.json").write_text(
            json.dumps({
                "workspace_root": high_confidence_blocked_workspace.name,
                "workspace_created_at": "2026-05-06T00:00:00Z",
                "confirmed_output_dir": f"{high_confidence_blocked_workspace.name}/confirmed",
            }, indent=2),
            encoding="utf-8",
        )
        (high_confidence_blocked_workspace / "candidate-findings.md").write_text("# Candidate Findings\n\n", encoding="utf-8")
        (high_confidence_blocked_workspace / "attack-surface.md").write_text("# Attack Surface Handoff\n\n", encoding="utf-8")
        (high_confidence_blocked_workspace / "unverified-leads.md").write_text(
            "# Unverified Leads\n\n"
            "| Lead ID | Suspected Weakness | Evidence So Far | Missing Evidence | Docker Confirmation Status | Safe Resume Step | High-Confidence-Unverified? |\n"
            "| --- | --- | --- | --- | --- | --- | --- |\n"
            "| U1 | Optional Kafka TLS | rejectUnauthorized:false | deployment materiality | blocked_no_docker | configure Kafka and rerun Docker verification | Yes |\n",
            encoding="utf-8",
        )
        high_conf_blocked_proc = subprocess.run([
            sys.executable,
            str(plugin_root / "scripts/finalize_audit_workspace.py"),
            "--workspace-dir",
            str(high_confidence_blocked_workspace),
            "--result",
            "completed_no_confirmed_findings",
        ], cwd=plugin_root, capture_output=True, text=True, env={**os.environ, **SKIP_DOCKER_ENV})
        high_conf_output = (high_conf_blocked_proc.stdout or "") + (high_conf_blocked_proc.stderr or "")
        if high_conf_blocked_proc.returncode == 0:
            raise SystemExit("FAILED: high-confidence blocked lead without materiality finalized as no-confirmed")
        if "Material blocker?" not in high_conf_output:
            raise SystemExit("FAILED: high-confidence blocked lead failure did not request materiality rationale")

        high_confidence_safe_workspace = repo_dir / "security-research-high-confidence-safe"
        high_confidence_safe_workspace.mkdir(parents=True, exist_ok=True)
        (high_confidence_safe_workspace / "confirmed").mkdir()
        (high_confidence_safe_workspace / "asr-config.json").write_text(
            json.dumps({
                "workspace_root": high_confidence_safe_workspace.name,
                "workspace_created_at": "2026-05-06T00:00:00Z",
                "confirmed_output_dir": f"{high_confidence_safe_workspace.name}/confirmed",
            }, indent=2),
            encoding="utf-8",
        )
        (high_confidence_safe_workspace / "candidate-findings.md").write_text("# Candidate Findings\n\n", encoding="utf-8")
        (high_confidence_safe_workspace / "attack-surface.md").write_text("# Attack Surface Handoff\n\n", encoding="utf-8")
        (high_confidence_safe_workspace / "unverified-leads.md").write_text(
            "# Unverified Leads\n\n"
            "| Lead ID | Suspected Weakness | Evidence So Far | Missing Evidence | Docker Confirmation Status | Safe Resume Step | High-Confidence-Unverified? | Material blocker? | Default runtime scope? | Why completion is still safe? |\n"
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"
            "| U1 | Optional Kafka TLS | rejectUnauthorized:false | deployment materiality | blocked_no_docker | configure Kafka and rerun Docker verification | Yes | No | optional integration | Kafka is disabled in default runtime and this is a non-material optional integration follow-up. |\n",
            encoding="utf-8",
        )
        run_with_env([
            sys.executable,
            str(plugin_root / "scripts/finalize_audit_workspace.py"),
            "--workspace-dir",
            str(high_confidence_safe_workspace),
            "--result",
            "completed_no_confirmed_findings",
        ], plugin_root, SKIP_DOCKER_ENV)
        require_text(
            high_confidence_safe_workspace / "SUMMARY.md",
            "completed_no_confirmed_findings",
            "finalization creates stable workspace SUMMARY.md",
        )

        legacy_clean_workspace = repo_dir / "security-research-legacy-clean-no-ledger"
        legacy_clean_workspace.mkdir(parents=True, exist_ok=True)
        (legacy_clean_workspace / "confirmed").mkdir()
        (legacy_clean_workspace / "docker").mkdir()
        (legacy_clean_workspace / "asr-config.json").write_text(
            json.dumps({
                "workspace_root": legacy_clean_workspace.name,
                "workspace_created_at": "2026-05-06T00:00:00Z",
                "confirmed_output_dir": f"{legacy_clean_workspace.name}/confirmed",
            }, indent=2),
            encoding="utf-8",
        )
        (legacy_clean_workspace / "docker/docker-cleanliness-status.json").write_text(
            json.dumps({"schema_version": 1, "clean": True, "strict": True}, indent=2),
            encoding="utf-8",
        )
        if (legacy_clean_workspace / "audit-disposition.json").exists():
            raise SystemExit("FAILED: legacy clean fixture unexpectedly started with audit-disposition.json")
        run_with_env([
            sys.executable,
            str(plugin_root / "scripts/finalize_audit_workspace.py"),
            "--workspace-dir",
            str(legacy_clean_workspace),
            "--result",
            "completed_no_confirmed_findings",
        ], plugin_root, SKIP_DOCKER_ENV)
        if not (legacy_clean_workspace / "audit-disposition.json").exists():
            raise SystemExit("FAILED: legacy clean no-confirmed finalization did not write audit-disposition.json")
        run([
            sys.executable,
            str(plugin_root / "scripts/assert_finalized_workspace.py"),
            "--workspace-dir",
            str(legacy_clean_workspace),
        ], plugin_root)

        stale_docker_status_workspace = repo_dir / "security-research-stale-docker-status"
        stale_docker_status_workspace.mkdir(parents=True, exist_ok=True)
        (stale_docker_status_workspace / "confirmed").mkdir()
        (stale_docker_status_workspace / "docker").mkdir()
        (stale_docker_status_workspace / "bin").mkdir()
        (stale_docker_status_workspace / "asr-config.json").write_text(
            json.dumps({
                "workspace_root": stale_docker_status_workspace.name,
                "workspace_created_at": "2026-05-06T00:00:00Z",
                "confirmed_output_dir": f"{stale_docker_status_workspace.name}/confirmed",
            }, indent=2),
            encoding="utf-8",
        )
        for filename, heading in (
            ("candidate-findings.md", "# Candidate Findings\n\n"),
            ("unverified-leads.md", "# Unverified Leads\n\n"),
            ("false-positives.md", "# False Positives\n\n"),
            ("attack-surface.md", "# Attack Surface Handoff\n\n"),
        ):
            (stale_docker_status_workspace / filename).write_text(heading, encoding="utf-8")
        (stale_docker_status_workspace / "docker/docker-resource-baseline.json").write_text(
            json.dumps({
                "schema_version": 1,
                "captured_at": "2026-05-06T00:00:00Z",
                "docker_available": True,
                "images": [],
                "volumes": [],
                "networks": [],
                "containers": [],
                "build_cache": [],
            }, indent=2),
            encoding="utf-8",
        )
        stale_status_path = stale_docker_status_workspace / "docker/docker-cleanliness-status.json"
        stale_status_path.write_text(
            json.dumps({"schema_version": 1, "clean": True, "strict": True, "checked_at": "2026-05-06T00:00:01Z"}, indent=2),
            encoding="utf-8",
        )
        fake_manage = stale_docker_status_workspace / "bin/manage-docker-resources.py"
        fake_manage.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "print('simulated Docker helper failure without status refresh', file=sys.stderr)\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        fake_manage.chmod(0o755)
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/finalize_audit_workspace.py"),
            "--workspace-dir",
            str(stale_docker_status_workspace),
            "--result",
            "completed_no_confirmed_findings",
        ], plugin_root, "did not refresh docker-cleanliness-status.json")

        # Test 1: Finalization with valid bundles succeeds
        # Remove partial/bad bundles first so only valid ones remain
        for bad in (
            partial_confirmed,
            bad_missing_verification,
            bad_high_confidence,
            bad_missing_evidence_file,
            bad_absolute_evidence,
            bad_escape_evidence,
            bad_empty_poc,
            bad_absolute_poc,
            bad_escape_poc,
            bad_symlink_escape,
            bad_docker_required,
            bad_no_escalation,
            bad_empty_docker_command,
            bad_placeholder_image,
            bad_missing_attachments,
            bad_multi_finding,
            bad_runtime_state,
            bad_runtime_scope,
            nested_warning_bundle,
        ):
            if bad.exists():
                shutil.rmtree(bad)
        run_with_env([
            sys.executable,
            str(plugin_root / "scripts/finalize_audit_workspace.py"),
            "--workspace-dir", str(workspace),
            "--language", "auto",
            "--result", "completed_with_confirmed_bundles",
        ], plugin_root, SKIP_DOCKER_ENV)
        finalized_status = json.loads((workspace / "stage-status.json").read_text(encoding="utf-8"))
        if finalized_status.get("status") != "completed":
            raise SystemExit("FAILED: finalization did not set stage-status.json status to completed")
        if finalized_status.get("stage") != "completed":
            raise SystemExit("FAILED: finalization did not set stage-status.json stage to completed")
        if finalized_status.get("blocker") is not None:
            raise SystemExit("FAILED: finalization did not clear blocker in stage-status.json")
        if finalized_status.get("resume_step") is not None:
            raise SystemExit("FAILED: finalization did not clear resume_step in stage-status.json")
        finalized_handoff = (workspace / "handoff-summary.md").read_text(encoding="utf-8")
        if "running" in finalized_handoff.split("Status:")[1].split("\n")[0] if "Status:" in finalized_handoff else "":
            raise SystemExit("FAILED: finalized handoff-summary.md still reports running status")
        finalized_events = (workspace / "audit-events.jsonl").read_text(encoding="utf-8")
        if "finalization_succeeded" not in finalized_events:
            raise SystemExit("FAILED: finalization did not write finalization_succeeded event")
        if "finalization_started" not in finalized_events:
            raise SystemExit("FAILED: finalization did not write finalization_started event")
        if "bundle_validation_outcome" not in finalized_events:
            raise SystemExit("FAILED: finalization did not write bundle_validation_outcome event")
        if "audit_disposition_outcome" not in finalized_events:
            raise SystemExit("FAILED: finalization did not write audit_disposition_outcome event")
        finalized_ledger = json.loads((workspace / "audit-disposition.json").read_text(encoding="utf-8"))
        if not finalized_ledger.get("items"):
            raise SystemExit("FAILED: finalization did not write audit-disposition.json items for confirmed bundles")
        run([
            sys.executable,
            str(workspace / "bin/assert-finalized-workspace.py"),
            "--workspace-dir",
            str(workspace),
        ], plugin_root)
        require_text(
            workspace / "SUMMARY.md",
            "completed_with_confirmed_bundles",
            "bundle finalization writes stable workspace SUMMARY.md",
        )
        # Test 2: Finalization with no confirmed bundles succeeds under completed_no_confirmed_findings
        # Reset stage-status back to running for next test
        write_event_cmd = [
            sys.executable,
            str(workspace / "bin/write-audit-event.py"),
            "--workspace-dir", str(workspace),
            "--event", "selftest_reset",
            "--stage", "verification",
            "--status", "running",
            "--message", "Reset for finalization selftest.",
        ]
        subprocess.run(write_event_cmd, capture_output=True, text=True)
        # Remove all bundle dirs to simulate no-finding workspace
        for entry in (workspace / "confirmed").iterdir():
            if entry.is_dir() and not entry.name.startswith("."):
                shutil.rmtree(entry)
        run_with_env([
            sys.executable,
            str(plugin_root / "scripts/finalize_audit_workspace.py"),
            "--workspace-dir", str(workspace),
            "--result", "completed_no_confirmed_findings",
        ], plugin_root, SKIP_DOCKER_ENV)
        no_finding_status = json.loads((workspace / "stage-status.json").read_text(encoding="utf-8"))
        if no_finding_status.get("status") != "completed":
            raise SystemExit("FAILED: no-finding finalization did not set status to completed")
        if no_finding_status.get("stage") != "completed":
            raise SystemExit("FAILED: no-finding finalization did not set stage to completed")
        no_finding_handoff = (workspace / "handoff-summary.md").read_text(encoding="utf-8")
        if "No confirmed vulnerabilities" not in no_finding_handoff:
            raise SystemExit("FAILED: no-finding handoff does not show 'No confirmed vulnerabilities'")
        if "initial_probing" in no_finding_handoff:
            raise SystemExit("FAILED: no-finding handoff still shows stale initial_probing")
        if "running" in no_finding_handoff.split("Status:")[1].split("\n")[0] if "Status:" in no_finding_handoff else "":
            raise SystemExit("FAILED: no-finding handoff still reports running status")
        require_text(
            workspace / "SUMMARY.md",
            "completed_no_confirmed_findings",
            "no-finding finalization updates generated SUMMARY.md",
        )
        no_finding_ledger = json.loads((workspace / "audit-disposition.json").read_text(encoding="utf-8"))
        if any(item.get("state") == "confirmed" for item in no_finding_ledger.get("items", [])):
            raise SystemExit("FAILED: refreshed no-finding audit-disposition.json kept stale confirmed items")
        run([
            sys.executable,
            str(workspace / "bin/assert-finalized-workspace.py"),
            "--workspace-dir",
            str(workspace),
        ], plugin_root)

        # Test 3: Finalization fails when partial confirmed bundles exist
        subprocess.run(write_event_cmd, capture_output=True, text=True)
        partial_for_gate = workspace / "confirmed/C99-partial-gate-test"
        partial_for_gate.mkdir(parents=True, exist_ok=True)
        (partial_for_gate / "verification-evidence.json").write_text(
            json.dumps({"verification_status": "confirmed_in_docker"}, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/finalize_audit_workspace.py"),
            "--workspace-dir", str(workspace),
            "--result", "completed_with_confirmed_bundles",
        ], plugin_root, "partial confirmed bundle",
           extra_env=SKIP_DOCKER_ENV)

        # Test 4: Finalization fails when result=completed_with_confirmed_bundles but zero bundles validate
        shutil.rmtree(partial_for_gate)
        subprocess.run(write_event_cmd, capture_output=True, text=True)
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/finalize_audit_workspace.py"),
            "--workspace-dir", str(workspace),
            "--result", "completed_with_confirmed_bundles",
        ], plugin_root, "requires at least one validated confirmed bundle",
           extra_env=SKIP_DOCKER_ENV)

        # Test 5: Finalization fails when Docker strict cleanliness fails
        # Re-render a valid bundle for this test
        run([
            sys.executable,
            str(workspace / "bin/render-confirmed-vuln-docx.py"),
            "--input",
            str(plugin_root / "assets/examples/confirmed-findings.example.json"),
            "--output-dir", str(workspace / "confirmed"),
            "--language", "zh-CN",
        ], plugin_root)
        subprocess.run(write_event_cmd, capture_output=True, text=True)
        # Use a fake baseline that will make verify-clean fail
        fake_docker_baseline = workspace / "docker" / "docker-resource-baseline.json"
        fake_docker_baseline.write_text(
            json.dumps({
                "schema_version": 1, "captured_at": "2026-04-30T00:00:00Z",
                "docker_available": True,
                "images": [], "volumes": [], "networks": [], "containers": [], "build_cache": [],
            }, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(workspace / "bin/manage-docker-resources.py"),
            "--workspace-dir",
            str(workspace),
            "--capture-baseline",
        ], plugin_root, "Refusing to overwrite existing Docker resource baseline")
        # The real Docker environment likely has resources, so verify-clean --strict should fail
        # But if Docker is clean, this test would pass incorrectly. Use a fixture instead.
        fake_current = workspace / "docker" / "current-finalize-fixture.json"
        fake_current.write_text(
            json.dumps({
                "schema_version": 1, "captured_at": "2026-04-30T00:01:00Z",
                "docker_available": True,
                "images": [{"id": "sha256:leftover", "repository": "leftover", "tag": "latest",
                            "labels": {"org.zhulong.managed": "true",
                                       "org.zhulong.workspace": workspace.name}}],
                "volumes": [], "networks": [], "containers": [], "build_cache": [],
            }, indent=2),
            encoding="utf-8",
        )
        # We can't easily inject the current-file into the finalization gate's Docker check,
        # so test the Docker failure path by removing the baseline entirely
        real_baseline = workspace / "docker" / "docker-resource-baseline.json"
        backup_baseline = workspace / "docker" / "docker-resource-baseline.json.bak"
        real_baseline.rename(backup_baseline)
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/finalize_audit_workspace.py"),
            "--workspace-dir", str(workspace),
            "--result", "completed_with_confirmed_bundles",
        ], plugin_root, "Docker cleanliness check failed")
        backup_baseline.rename(real_baseline)

        # Test 5a: completed_no_confirmed_findings fails when partial confirmed bundles exist
        subprocess.run(write_event_cmd, capture_output=True, text=True)
        # Remove the valid bundle rendered for Test 5
        for entry in (workspace / "confirmed").iterdir():
            if entry.is_dir() and not entry.name.startswith("."):
                shutil.rmtree(entry)
        partial_no_finding = workspace / "confirmed/C98-partial-no-finding"
        partial_no_finding.mkdir(parents=True, exist_ok=True)
        (partial_no_finding / "verification-evidence.json").write_text(
            json.dumps({"verification_status": "confirmed_in_docker"}, indent=2),
            encoding="utf-8",
        )
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/finalize_audit_workspace.py"),
            "--workspace-dir", str(workspace),
            "--result", "completed_no_confirmed_findings",
        ], plugin_root, "partial confirmed bundle",
           extra_env=SKIP_DOCKER_ENV)
        shutil.rmtree(partial_no_finding)

        # Test 5b: completed_no_confirmed_findings fails when Docker cleanliness fails
        subprocess.run(write_event_cmd, capture_output=True, text=True)
        real_baseline2 = workspace / "docker" / "docker-resource-baseline.json"
        backup_baseline2 = workspace / "docker" / "docker-resource-baseline.json.bak2"
        real_baseline2.rename(backup_baseline2)
        run_expect_fail([
            sys.executable,
            str(plugin_root / "scripts/finalize_audit_workspace.py"),
            "--workspace-dir", str(workspace),
            "--result", "completed_no_confirmed_findings",
        ], plugin_root, "Docker cleanliness check failed")
        backup_baseline2.rename(real_baseline2)

        # Test 5c: missing audit-event writer must be visible, not silent.
        subprocess.run(write_event_cmd, capture_output=True, text=True)
        isolated_finalizer_dir = Path(tempdir) / "isolated-finalizer"
        isolated_finalizer_dir.mkdir(parents=True, exist_ok=True)
        isolated_finalizer = isolated_finalizer_dir / "finalize_audit_workspace.py"
        shutil.copy2(plugin_root / "scripts/finalize_audit_workspace.py", isolated_finalizer)
        shutil.copy2(plugin_root / "scripts/blocked_verification.py", isolated_finalizer_dir / "blocked_verification.py")
        shutil.copy2(plugin_root / "scripts/audit_disposition.py", isolated_finalizer_dir / "audit_disposition.py")
        workspace_writer = workspace / "bin/write-audit-event.py"
        hidden_workspace_writer = workspace / "bin/write-audit-event.py.hidden-for-selftest"
        workspace_writer.rename(hidden_workspace_writer)
        try:
            proc = subprocess.run([
                sys.executable,
                str(isolated_finalizer),
                "--workspace-dir", str(workspace),
                "--result", "completed_no_confirmed_findings",
            ], cwd=plugin_root, capture_output=True, text=True,
                env={**os.environ, **SKIP_DOCKER_ENV})
        finally:
            hidden_workspace_writer.rename(workspace_writer)
        if proc.returncode != 0:
            raise SystemExit(
                "FAILED: finalization should warn but continue when audit-event writer is missing: "
                + ((proc.stdout or "") + (proc.stderr or ""))
            )
        if "WARNING: audit event writer not found" not in proc.stderr:
            raise SystemExit("FAILED: missing audit-event writer did not produce a visible warning")

        claude_home = Path(tempdir) / "claude-home"
        claude_home.mkdir(parents=True, exist_ok=True)
        default_sync_output = run_capture([
            "bash",
            str(plugin_root / "scripts/sync_to_claude_skill.sh"),
            "--claude-skills-dir",
            str(claude_home / "skills"),
            "--keep-backups",
            "2",
        ], plugin_root)
        if "Prompt template sync:" not in default_sync_output or "skipped" not in default_sync_output:
            raise SystemExit("FAILED: sync_to_claude_skill.sh should skip external prompt template sync by default")
        if "Prompt template synced from canonical source:" in default_sync_output:
            raise SystemExit("FAILED: sync_to_claude_skill.sh wrote an external prompt template by default")
        prompt_template_output = Path(tempdir) / "prompt-template.md"
        run([
            "bash",
            str(plugin_root / "scripts/sync_to_claude_skill.sh"),
            "--claude-skills-dir",
            str(claude_home / "skills"),
            "--keep-backups",
            "2",
            "--prompt-template-output",
            str(prompt_template_output),
        ], plugin_root)
        if prompt_template_output.read_text(encoding="utf-8") != (
            plugin_root / "assets/references/claude-code-invocation-template.md"
        ).read_text(encoding="utf-8"):
            raise SystemExit("FAILED: sync_to_claude_skill.sh did not honor --prompt-template-output")
        installed_skill = claude_home / "skills" / "zhulong"
        if not (installed_skill / "SKILL.md").exists():
            raise SystemExit("FAILED: Claude skill sync did not create SKILL.md")
        if not (installed_skill / "scripts/check_security_tooling.sh").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy scripts")
        if not (installed_skill / "scripts/check_docker_gate.sh").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy check_docker_gate.sh")
        if not (installed_skill / "scripts/run_initial_probes.sh").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy run_initial_probes.sh")
        if not (installed_skill / "scripts/run_verification_case.sh").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy run_verification_case.sh")
        if not (installed_skill / "scripts/check_sandbox_preflight.py").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy check_sandbox_preflight.py")
        if not (installed_skill / "scripts/render_handoff_summary.py").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy render_handoff_summary.py")
        if not (installed_skill / "scripts/asr_start.sh").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy asr_start.sh")
        if not (installed_skill / "scripts/write_audit_event.py").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy write_audit_event.py")
        if not (installed_skill / "scripts/validate_workspace_state.py").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy validate_workspace_state.py")
        if not (installed_skill / "scripts/assert_finalized_workspace.py").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy assert_finalized_workspace.py")
        if not (installed_skill / "scripts/audit_disposition.py").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy audit_disposition.py")
        if not (installed_skill / "scripts/blocked_verification.py").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy blocked_verification.py")
        if not (installed_skill / "assets/tool-registry.json").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy assets")
        if not (installed_skill / "assets/references/python-library-audit-playbook.md").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy Python Library playbook")
        if not (installed_skill / "assets/references/php-swoole-audit-playbook.md").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy PHP/Swoole playbook")
        if not (installed_skill / "assets/references/docker-registry-fallbacks.example.json").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy registry fallback example")
        require_text(
            installed_skill / "SKILL.md",
            "Documents` skill",
            "installed Claude skill docx editing contract",
        )
        require_text(
            installed_skill / "SKILL.md",
            "if the report claims denial of service, the materials should show the direct DoS oracle",
            "installed Claude skill stronger-evidence contract",
        )
        require_text(
            installed_skill / "SKILL.md",
            "攻击者条件",
            "installed Claude skill confirmed quality-gate attacker label",
        )
        require_text(
            installed_skill / "SKILL.md",
            "Security Impact",
            "installed Claude skill confirmed quality-gate impact label",
        )
        require_text(
            installed_skill / "SKILL.md",
            "outside_security_boundary",
            "installed Claude skill false-positive boundary reason code",
        )
        require_text(
            installed_skill / "SKILL.md",
            "severity-escalation pass",
            "installed Claude skill severity escalation contract",
        )
        require_text(
            installed_skill / "SKILL.md",
            "reviewer-evidence-and-impact.md",
            "installed Claude skill reviewer evidence addendum guidance",
        )
        require_text(
            installed_skill / "SKILL.md",
            "consumer application pattern",
            "installed Claude skill library consumer boundary guidance",
        )
        require_text(
            installed_skill / "SKILL.md",
            "rejected_unsafe_sandbox",
            "installed Claude skill sandbox preflight rejected label",
        )
        require_text(
            installed_skill / "SKILL.md",
            "Do not execute `web_search`",
            "installed Claude skill web lookup shell-safety contract",
        )
        require_text(
            installed_skill / "SKILL.md",
            "Do not produce thin DOCX reports",
            "installed Claude skill report-depth contract",
        )
        require_text(
            installed_skill / "SKILL.md",
            "exactly one confirmed vulnerability",
            "installed Claude skill one-finding-per-bundle contract",
        )
        require_text(
            installed_skill / "SKILL.md",
            "do not leave runtime or source-control directories",
            "installed Claude skill final bundle cleanliness contract",
        )
        require_text(
            installed_skill / "SKILL.md",
            "verification-evidence.json",
            "installed Claude skill verification evidence contract",
        )
        require_text(
            installed_skill / "SKILL.md",
            "Static scanning, source-to-sink reasoning",
            "installed Claude skill candidate-only analysis contract",
        )
        require_text(
            installed_skill / "SKILL.md",
            "False positives, non-security defects, unverified leads",
            "installed Claude skill triage workspace-only contract",
        )
        require_text(
            installed_skill / "SKILL.md",
            "Final summaries must explicitly distinguish confirmed vulnerabilities",
            "installed Claude skill final summary triage contract",
        )
        require_text(
            installed_skill / "SKILL.md",
            "Material blocker?",
            "installed Claude skill unverified lead materiality requirement",
        )
        require_text(
            installed_skill / "SKILL.md",
            "<audit-workspace>/SUMMARY.md",
            "installed Claude skill stable workspace summary requirement",
        )
        require_text(
            installed_skill / "SKILL.md",
            "initial-probes-summary.json",
            "installed Claude skill initial probes summary contract",
        )
        require_text(
            installed_skill / "SKILL.md",
            "skipped_tool_missing",
            "installed Claude skill initial probes missing-tool status",
        )
        require_text(
            installed_skill / "SKILL.md",
            "handoff-summary.md",
            "installed Claude skill handoff summary contract",
        )
        require_text(
            installed_skill / "SKILL.md",
            "local_knowledge_checklists",
            "installed Claude skill local checklist planner contract",
        )
        require_text(
            installed_skill / "SKILL.md",
            "nodejs-web-audit-playbook.md",
            "installed Claude skill Node.js Web playbook reference",
        )
        require_text(
            installed_skill / "SKILL.md",
            "python-web-audit-playbook.md",
            "installed Claude skill Python Web playbook reference",
        )
        require_text(
            installed_skill / "SKILL.md",
            "python-library-audit-playbook.md",
            "installed Claude skill Python Library playbook reference",
        )
        require_text(
            installed_skill / "SKILL.md",
            "php-swoole-audit-playbook.md",
            "installed Claude skill PHP/Swoole playbook reference",
        )
        require_text(
            installed_skill / "SKILL.md",
            "run_verification_case.sh",
            "installed Claude skill verification runner reference",
        )
        require_text(
            installed_skill / "SKILL.md",
            "failed_timeout",
            "installed Claude skill verification runner timeout label",
        )
        require_text(
            installed_skill / "SKILL.md",
            "Fill `<audit-workspace>/attack-surface.md` as a concise handoff artifact",
            "installed Claude skill attack-surface handoff contract",
        )
        require_text(
            installed_skill / "SKILL.md",
            "finalize-audit-workspace.py",
            "installed Claude skill completion gate command",
        )
        require_text(
            installed_skill / "SKILL.md",
            "completed_no_confirmed_findings",
            "installed Claude skill no-confirmed-findings result",
        )
        require_text(
            installed_skill / "SKILL.md",
            "A dogfood run is not complete until this gate passes",
            "installed Claude skill completion gate enforcement",
        )
        require_text(
            installed_skill / "SKILL.md",
            "assert-finalized-workspace.py",
            "installed Claude skill finalization integrity checker",
        )
        require_text(
            installed_skill / "SKILL.md",
            "Blocked Docker/runtime verification is not the same as",
            "installed Claude skill blocked verification semantics",
        )
        require_text(
            installed_skill / "SKILL.md",
            "`attack-surface.md` as a DOCX source or as a shortcut into",
            "installed Claude skill attack-surface routing guardrail",
        )
        run([
            sys.executable,
            str(installed_skill / "scripts/selftest_plugin.py"),
        ], installed_skill)
        backups = sorted((claude_home / "skills" / ".zhulong-backups").glob("zhulong.backup.*"))
        if len(backups) > 2:
            raise SystemExit("FAILED: sync_to_claude_skill.sh did not enforce backup retention")
        top_level_backups = sorted((claude_home / "skills").glob("zhulong.backup.*"))
        if top_level_backups:
            raise SystemExit("FAILED: sync_to_claude_skill.sh left loadable backups at skills root")

    print(f"SELFTEST PASSED: {plugin_root}")


if __name__ == "__main__":
    main()
