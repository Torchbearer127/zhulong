#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REQUIRED_FILES = [
    ".codex-plugin/plugin.json",
    "README.md",
    "assets/tool-registry.json",
    "assets/confirmed-vuln-report-template.docx",
    "assets/examples/confirmed-findings.example.json",
    "assets/references/false-positive-template.md",
    "assets/references/unverified-lead-template.md",
    "assets/references/final-summary-template.md",
    "assets/references/java-web-audit-playbook.md",
    "assets/references/go-web-audit-playbook.md",
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


def run_with_env(command: list[str], cwd: Path, env: dict[str, str]) -> None:
    proc = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        output = ((proc.stdout or "") + (proc.stderr or "")).strip()
        raise SystemExit(f"FAILED: {' '.join(command)}\n{output}")


def run_expect_fail(command: list[str], cwd: Path, expected: str) -> None:
    proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
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
         str(plugin_root / "scripts/render_confirmed_vuln_docx.py"),
         str(plugin_root / "scripts/scaffold_bilingual_findings.py"),
         str(plugin_root / "scripts/validate_report_bundle.py"),
         str(plugin_root / "scripts/validate_all_report_bundles.py")], plugin_root)

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
    run([sys.executable, str(plugin_root / "scripts/render_handoff_summary.py"), "--help"], plugin_root)

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
        if by_name.get("osv-scanner", {}).get("status") != "skipped_no_package_sources":
            raise SystemExit("FAILED: osv-scanner No package sources found was not classified as skipped_no_package_sources")
        if by_name.get("semgrep", {}).get("status") != "skipped_tool_missing":
            raise SystemExit("FAILED: missing semgrep was not classified as skipped_tool_missing")
        if by_name.get("gitleaks", {}).get("status") != "skipped_tool_missing":
            raise SystemExit("FAILED: missing gitleaks was not classified as skipped_tool_missing")
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
        run([
            sys.executable,
            str(plugin_root / "scripts/validate_workspace_state.py"),
            "--workspace-dir",
            str(workspace),
            "--repo-root",
            str(repo_dir),
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
        run([
            "bash",
            str(plugin_root / "scripts/refresh_workspace_helpers.sh"),
            "--workspace",
            str(workspace),
        ], plugin_root)
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
            str(plugin_root / "scripts/render_confirmed_vuln_docx.py"),
            "--input",
            str(plugin_root / "assets/examples/confirmed-findings.example.json"),
            "--output-dir",
            str(workspace / "confirmed"),
            "--language",
            "zh-CN",
        ], plugin_root)
        run([
            sys.executable,
            str(plugin_root / "scripts/render_confirmed_vuln_docx.py"),
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
            "Do not use `attack-surface.md` as a DOCX source or as a shortcut into",
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
