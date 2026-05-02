#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET


REQUIRED_FILES = [
    ".codex-plugin/plugin.json",
    "README.md",
    "assets/tool-registry.json",
    "assets/confirmed-vuln-report-template.docx",
    "assets/examples/confirmed-findings.example.json",
    "assets/references/false-positive-template.md",
    "assets/references/unverified-lead-template.md",
    "assets/references/final-summary-template.md",
    "assets/references/docker-resource-hygiene.md",
    "assets/references/java-web-audit-playbook.md",
    "assets/references/go-web-audit-playbook.md",
    "assets/references/nodejs-library-audit-playbook.md",
    "assets/references/nodejs-web-audit-playbook.md",
    "assets/references/python-web-audit-playbook.md",
    "assets/references/ssrf-checklist.md",
    "assets/references/path-traversal-checklist.md",
    "assets/references/prototype-pollution-checklist.md",
    "scripts/bootstrap_verification_workspace.sh",
    "scripts/asr_start.sh",
    "scripts/prepare_target_repo.sh",
    "scripts/check_docker_gate.sh",
    "scripts/check_omc_runtime.sh",
    "scripts/check_security_tooling.sh",
    "scripts/run_initial_probes.sh",
    "scripts/run_verification_case.sh",
    "scripts/manage_docker_resources.py",
    "scripts/render_handoff_summary.py",
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


def main() -> None:
    plugin_root = Path(__file__).resolve().parent.parent

    for rel in REQUIRED_FILES:
        path = plugin_root / rel
        if not path.exists():
            raise SystemExit(f"FAILED: missing required plugin file: {path}")

    plugin_json = json.loads((plugin_root / ".codex-plugin/plugin.json").read_text(encoding="utf-8"))
    if plugin_json.get("name") != "zhulong-plugin":
        raise SystemExit("FAILED: plugin.json name mismatch")

    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "Documents` skill",
        "Claude skill template docx editing contract",
    )
    require_text(
        plugin_root / "templates/claude-skill/SKILL.md",
        "practical impact and a typical exploitation path",
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
        "For pure\nNode.js library/package repositories",
        "Claude skill template Node.js Library route-inventory guardrail",
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
        "Confirmed-output guardrail",
        "unverified lead template confirmed-output guardrail field",
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
        "STABLE_LABELS=\"blocked_docker_unavailable blocked_missing_image failed_timeout failed_resource_limit rejected_not_reproducible confirmed_in_docker\"",
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
    if canonical_prompt.read_text(encoding="utf-8") != root_prompt.read_text(encoding="utf-8"):
        raise SystemExit(
            "FAILED: root prompt template is out of sync with the canonical plugin invocation template. "
            "Run scripts/sync_to_claude_skill.sh or resync the repository prompt copy."
        )

    run([sys.executable, "-m", "py_compile",
         str(plugin_root / "scripts/plan_security_toolchain.py"),
         str(plugin_root / "scripts/render_handoff_summary.py"),
         str(plugin_root / "scripts/write_audit_event.py"),
         str(plugin_root / "scripts/validate_workspace_state.py"),
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
        if not (workspace / "bin/manage-docker-resources.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing manage-docker-resources.py")
        if not (workspace / "bin/render-handoff-summary.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing render-handoff-summary.py")
        if not (workspace / "scripts/render-handoff-summary.py").exists():
            raise SystemExit("FAILED: bootstrapped workspace is missing scripts/render-handoff-summary.py")
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
        if planned_images != {"sha256:new"}:
            raise SystemExit(f"FAILED: Docker cleanup image plan should only include owned new image: {planned_images}")
        planned_volumes = {item.get("name") for item in cleanup_plan.get("volumes", [])}
        if planned_volumes != {"target-created-volume"}:
            raise SystemExit(f"FAILED: Docker cleanup volume plan should only include owned new volume: {planned_volumes}")
        planned_networks = {item.get("name") for item in cleanup_plan.get("networks", [])}
        if planned_networks != {"target-created-network"}:
            raise SystemExit(f"FAILED: Docker cleanup network plan should only include owned new non-default network: {planned_networks}")
        running_skipped = {item.get("name") for item in cleanup_plan.get("containers", {}).get("running_owned_skipped", [])}
        if running_skipped != {"target-running"}:
            raise SystemExit("FAILED: Docker cleanup helper must skip running containers by default")
        planned_containers = {item.get("name") for item in cleanup_plan.get("containers", {}).get("stopped_owned", [])}
        if planned_containers != {"target-stopped"}:
            raise SystemExit(f"FAILED: Docker cleanup should only remove owned stopped containers: {planned_containers}")
        skipped_containers = {item.get("name") for item in cleanup_plan.get("containers", {}).get("unattributed_new_skipped", [])}
        if skipped_containers != {"other-zhulong-stopped", "parallel-unlabeled-stopped", "target-compose-stopped"}:
            raise SystemExit(f"FAILED: Docker cleanup must skip foreign/unlabeled containers: {skipped_containers}")
        skipped_images = {item.get("id") for item in cleanup_plan.get("unattributed_new_skipped", {}).get("images", [])}
        if skipped_images != {"sha256:foreign", "sha256:unlabeled", "sha256:compose", "sha256:compose-pulled"}:
            raise SystemExit(f"FAILED: Docker cleanup must skip foreign/unlabeled images: {skipped_images}")
        skipped_volumes = {item.get("name") for item in cleanup_plan.get("unattributed_new_skipped", {}).get("volumes", [])}
        if skipped_volumes != {"parallel-created-volume", "target-compose-volume"}:
            raise SystemExit(f"FAILED: Docker cleanup must skip unlabeled volumes: {skipped_volumes}")
        skipped_networks = {item.get("name") for item in cleanup_plan.get("unattributed_new_skipped", {}).get("networks", [])}
        if skipped_networks != {"parallel-created-network", "target-compose-network"}:
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
            "zhulong-test-compose",
            "--adopt-image-ref",
            "mysql:5.7",
            "--adopt-build-cache",
            "--adopt-build-cache-id",
            "cache1",
        ], plugin_root)
        cleanup_plan = json.loads((workspace / "docker" / "docker-cleanup-plan.json").read_text(encoding="utf-8"))
        planned_images = {item.get("id") for item in cleanup_plan.get("images", [])}
        if planned_images != {"sha256:new", "sha256:compose", "sha256:compose-pulled"}:
            raise SystemExit(f"FAILED: adopted compose/image resources should enter cleanup image plan: {planned_images}")
        planned_volumes = {item.get("name") for item in cleanup_plan.get("volumes", [])}
        if planned_volumes != {"target-created-volume", "target-compose-volume"}:
            raise SystemExit(f"FAILED: adopted compose resources should enter cleanup volume plan: {planned_volumes}")
        planned_networks = {item.get("name") for item in cleanup_plan.get("networks", [])}
        if planned_networks != {"target-created-network", "target-compose-network"}:
            raise SystemExit(f"FAILED: adopted compose resources should enter cleanup network plan: {planned_networks}")
        planned_containers = {item.get("name") for item in cleanup_plan.get("containers", {}).get("stopped_owned", [])}
        if planned_containers != {"target-stopped", "target-compose-stopped"}:
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
        run_expect_fail([
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
        ], plugin_root, "unattributed Docker resources remain")
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
        if len(samples) != 2:
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
        run([
            "bash",
            str(workspace / "bin/check_omc_runtime.sh"),
            "--workspace-dir",
            str(workspace),
            "--json",
        ], plugin_root)
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
            "services:\\n  attacker:\\n    image: alpine:3.20\\n",
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
        if nested_proc.returncode != 0:
            raise SystemExit(f"FAILED: nested attachment warning fixture should still validate\n{nested_output}")
        if "WARN: nested workspace attachment paths detected" not in nested_output:
            raise SystemExit("FAILED: validator did not warn about nested workspace attachment paths")
        if "WARN: duplicate attachment basenames detected" not in nested_output:
            raise SystemExit("FAILED: validator did not warn about duplicate attachment basenames")
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
        run([
            "bash",
            str(plugin_root / "scripts/sync_to_claude_skill.sh"),
            "--claude-skills-dir",
            str(claude_home / "skills"),
            "--keep-backups",
            "2",
        ], plugin_root)
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
        if not (installed_skill / "scripts/render_handoff_summary.py").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy render_handoff_summary.py")
        if not (installed_skill / "scripts/asr_start.sh").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy asr_start.sh")
        if not (installed_skill / "scripts/write_audit_event.py").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy write_audit_event.py")
        if not (installed_skill / "scripts/validate_workspace_state.py").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy validate_workspace_state.py")
        if not (installed_skill / "assets/tool-registry.json").exists():
            raise SystemExit("FAILED: Claude skill sync did not copy assets")
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
            "severity-escalation pass",
            "installed Claude skill severity escalation contract",
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
            "`attack-surface.md` as a DOCX source or as a shortcut into",
            "installed Claude skill attack-surface routing guardrail",
        )
        backups = sorted((claude_home / "skills" / ".zhulong-backups").glob("zhulong.backup.*"))
        if len(backups) > 2:
            raise SystemExit("FAILED: sync_to_claude_skill.sh did not enforce backup retention")
        top_level_backups = sorted((claude_home / "skills").glob("zhulong.backup.*"))
        if top_level_backups:
            raise SystemExit("FAILED: sync_to_claude_skill.sh left loadable backups at skills root")

    print(f"SELFTEST PASSED: {plugin_root}")


if __name__ == "__main__":
    main()
