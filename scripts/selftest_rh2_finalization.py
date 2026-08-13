#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

import audit_state_io
import finalize_audit_workspace as finalizer
from audit_state_io import AuditStateError
from evidence_io import SafeEvidenceError
from workspace_state import _find_one_named, validate_handoff_state_current


RESULT = "completed_no_confirmed_findings"


def run(command: list[str], cwd: Path, *, expected: int = 0, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(command, cwd=cwd, capture_output=True, text=True, env=env)
    if process.returncode != expected:
        output = ((process.stdout or "") + (process.stderr or "")).strip()
        raise SystemExit(
            f"FAILED: command returned {process.returncode}, expected {expected}: {' '.join(command)}\n{output}"
        )
    return process


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def make_ready_workspace(plugin_root: Path, root: Path, name: str) -> Path:
    repo = root / f"{name}-repo"
    workspace = repo / f"security-research-{name}"
    fixture = plugin_root / "assets/fixtures/recon-result/service"
    shutil.copytree(fixture / "repo", repo)
    shutil.copytree(fixture / "workspace", workspace)
    shutil.copy2(workspace / "cases/complete-service.json", workspace / "recon-result.json")
    for directory in (workspace / "confirmed", workspace / "docker", workspace / "bin"):
        directory.mkdir(parents=True, exist_ok=True)
    write_json(
        workspace / "asr-config.json",
        {
            "workspace_root": workspace.name,
            "workspace_created_at": "2026-08-08T00:00:00Z",
            "confirmed_output_dir": f"{workspace.name}/confirmed",
            "output_language": "en-US",
            "summary_language": "en-US",
        },
    )
    for filename, heading in (
        ("candidate-findings.md", "# Candidate Findings\n\n"),
        ("false-positives.md", "# False Positives and Non-Security Defects\n\n"),
        ("unverified-leads.md", "# Unverified Leads\n\n"),
    ):
        (workspace / filename).write_text(heading, encoding="utf-8")
    write_json(
        workspace / "docker/docker-resource-baseline.json",
        {
            "schema_version": 1,
            "captured_at": "2026-08-08T00:00:00Z",
            "docker_available": True,
            "images": [],
            "volumes": [],
            "networks": [],
            "containers": [],
            "build_cache": [],
        },
    )
    helper = workspace / "bin/manage-docker-resources.py"
    helper.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "import sys\n"
        "from datetime import datetime, timezone\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "workspace = Path(args[args.index('--workspace-dir') + 1])\n"
        "log = workspace / 'docker/fake-helper-calls.log'\n"
        "with log.open('a', encoding='utf-8') as stream:\n"
        "    stream.write('verify-clean\\n')\n"
        "status = {'schema_version': 1, 'checked_at': datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'), 'workspace': workspace.name, 'clean': True, 'strict': '--strict' in args, 'counts': {}, 'note': 'deterministic local finalization stub'}\n"
        "(workspace / 'docker/docker-cleanliness-status.json').write_text(json.dumps(status, sort_keys=True) + '\\n', encoding='utf-8')\n",
        encoding="utf-8",
    )
    helper.chmod(0o755)

    writer = plugin_root / "scripts/write_audit_event.py"
    event_prefix = name.replace("-", "_")
    for event_name, stage, transition_kind in (
        (f"{event_prefix}_intake_started", "intake", "start"),
        (f"{event_prefix}_recon_started", "recon", "advance"),
        (f"{event_prefix}_candidates_started", "candidate_generation", "advance"),
        (f"{event_prefix}_triage_started", "triage", "advance"),
        (f"{event_prefix}_verification_started", "verification", "advance"),
    ):
        run(
            [
                sys.executable,
                str(writer),
                "--workspace-dir",
                str(workspace),
                "--event",
                event_name,
                "--stage",
                stage,
                "--status",
                "running",
                "--transition-kind",
                transition_kind,
                "--message",
                "Seed deterministic RH2 finalization fixture.",
                "--accept-current-revision",
            ],
            plugin_root,
        )
    return workspace


def event_names(workspace: Path) -> list[str]:
    names: list[str] = []
    for raw in (workspace / "audit-events.jsonl").read_text(encoding="utf-8").splitlines():
        event = json.loads(raw)
        names.append(str(event.get("event_name") or event.get("event") or ""))
    return names


def invoke_main(workspace: Path, *, environment: dict[str, str] | None = None) -> tuple[int, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    argv = [
        "finalize_audit_workspace.py",
        "--workspace-dir",
        str(workspace),
        "--result",
        RESULT,
        "--language",
        "en-US",
    ]
    with mock.patch.object(sys, "argv", argv), mock.patch.dict(os.environ, environment or {}, clear=False):
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                return_code = finalizer.main()
            except SystemExit as exc:
                return_code = int(exc.code or 0)
    return return_code, stdout.getvalue() + stderr.getvalue()


def require_no_terminal(workspace: Path, label: str) -> None:
    if "finalization_succeeded" in event_names(workspace):
        raise SystemExit(f"FAILED: {label} committed finalization_succeeded")


def main() -> None:
    plugin_root = Path(__file__).resolve().parent.parent
    finalizer_command = [
        sys.executable,
        str(plugin_root / "scripts/finalize_audit_workspace.py"),
    ]
    with tempfile.TemporaryDirectory(prefix="zhulong-rh2-finalization-") as raw_temp:
        root = Path(raw_temp)

        discovery = make_ready_workspace(plugin_root, root, "authority-discovery")
        copied_target = discovery / "confirmed/reviewer-copy/attachments/zhulong-target.yaml"
        copied_target.parent.mkdir(parents=True)
        shutil.copy2(discovery / "zhulong-target.yaml", copied_target)
        discovery_issues: list[dict] = []
        target_match = _find_one_named(discovery, "zhulong-target.yaml", discovery_issues)
        if target_match is None or target_match[0] != "zhulong-target.yaml" or discovery_issues:
            raise SystemExit("FAILED: confirmed reviewer material became a second workspace target authority")

        success = make_ready_workspace(plugin_root, root, "success")
        run(finalizer_command + ["--workspace-dir", str(success), "--result", RESULT, "--language", "en-US"], plugin_root)
        if event_names(success)[-1] != "finalization_succeeded":
            raise SystemExit("FAILED: finalization_succeeded is not the last success-path event")
        tracked = [
            success / "audit-events.jsonl",
            success / "stage-status.json",
            success / "audit-disposition.json",
            success / "SUMMARY.md",
            success / "handoff-state.json",
            success / "handoff-summary.md",
            success / "docker/docker-cleanliness-status.json",
            success / "docker/fake-helper-calls.log",
        ]
        before = {path: path.read_bytes() for path in tracked}
        run(finalizer_command + ["--workspace-dir", str(success), "--result", RESULT, "--language", "en-US"], plugin_root)
        if any(path.read_bytes() != raw for path, raw in before.items()):
            raise SystemExit("FAILED: completed finalization rerun changed authoritative or derived bytes")
        if event_names(success).count("finalization_succeeded") != 1:
            raise SystemExit("FAILED: completed finalization rerun appended a duplicate terminal event")

        journal_before_drift = (success / "audit-events.jsonl").read_bytes()
        handoff_before_drift = (success / "handoff-summary.md").read_bytes()
        (success / "handoff-summary.md").write_bytes(handoff_before_drift + b"\nbenign drift\n")
        drift = subprocess.run(
            finalizer_command + ["--workspace-dir", str(success), "--result", RESULT],
            cwd=plugin_root,
            capture_output=True,
            text=True,
        )
        if drift.returncode == 0 or "COMPLETED_WORKSPACE_DRIFT" not in (drift.stdout + drift.stderr):
            raise SystemExit("FAILED: completed handoff drift did not fail closed")
        if (success / "audit-events.jsonl").read_bytes() != journal_before_drift:
            raise SystemExit("FAILED: completed handoff drift appended an event")
        (success / "handoff-summary.md").write_bytes(handoff_before_drift)

        docker_before_drift = (success / "docker/docker-cleanliness-status.json").read_bytes()
        docker_document = json.loads(docker_before_drift)
        docker_document["clean"] = False
        write_json(success / "docker/docker-cleanliness-status.json", docker_document)
        docker_drift = subprocess.run(
            finalizer_command + ["--workspace-dir", str(success), "--result", RESULT],
            cwd=plugin_root,
            capture_output=True,
            text=True,
        )
        if docker_drift.returncode == 0:
            raise SystemExit("FAILED: completed Docker cleanliness drift did not fail closed")
        if (success / "audit-events.jsonl").read_bytes() != journal_before_drift:
            raise SystemExit("FAILED: completed Docker drift appended an event")
        (success / "docker/docker-cleanliness-status.json").write_bytes(docker_before_drift)

        ledger_before_drift = (success / "audit-disposition.json").read_bytes()
        ledger_document = json.loads(ledger_before_drift)
        ledger_document["schema_version"] = 999
        write_json(success / "audit-disposition.json", ledger_document)
        chain_assertion = subprocess.run(
            [sys.executable, str(plugin_root / "scripts/assert_finalized_workspace.py"), "--workspace-dir", str(success)],
            cwd=plugin_root,
            capture_output=True,
            text=True,
        )
        if chain_assertion.returncode == 0 or "audit-disposition.json" not in (chain_assertion.stdout + chain_assertion.stderr):
            raise SystemExit("FAILED: completed confirmation-chain drift passed the production assertion")
        chain_drift = subprocess.run(
            finalizer_command + ["--workspace-dir", str(success), "--result", RESULT],
            cwd=plugin_root,
            capture_output=True,
            text=True,
        )
        if chain_drift.returncode == 0:
            raise SystemExit("FAILED: completed confirmation-chain drift did not fail closed")
        if (success / "audit-events.jsonl").read_bytes() != journal_before_drift:
            raise SystemExit("FAILED: completed confirmation-chain drift appended an event")
        (success / "audit-disposition.json").write_bytes(ledger_before_drift)

        summary_fault = make_ready_workspace(plugin_root, root, "summary-fault")
        marker = summary_fault.parent / "summary-marker"
        marker.write_bytes(b"outside-marker\n")
        (summary_fault / "SUMMARY.md").symlink_to(marker)
        failed = subprocess.run(
            finalizer_command + ["--workspace-dir", str(summary_fault), "--result", RESULT],
            cwd=plugin_root,
            capture_output=True,
            text=True,
        )
        if failed.returncode == 0 or marker.read_bytes() != b"outside-marker\n":
            raise SystemExit("FAILED: unsafe SUMMARY.md target did not fail closed")
        require_no_terminal(summary_fault, "summary publication fault")

        handoff_fault = make_ready_workspace(plugin_root, root, "handoff-fault")
        handoff_process = subprocess.run(
            finalizer_command + ["--workspace-dir", str(handoff_fault), "--result", RESULT],
            cwd=plugin_root,
            capture_output=True,
            text=True,
            env={**os.environ, "ZHULONG_TEST_FAIL_HANDOFF_WRITE": "1"},
        )
        if handoff_process.returncode == 0:
            raise SystemExit("FAILED: injected handoff-state write fault unexpectedly finalized")
        require_no_terminal(handoff_fault, "handoff-state publication fault")

        summary_handoff_fault = make_ready_workspace(plugin_root, root, "handoff-summary-fault")
        with mock.patch.object(
            finalizer,
            "publish_handoff_summary",
            side_effect=SafeEvidenceError("EVIDENCE_ATOMIC_WRITE_FAILED", "injected handoff summary failure"),
        ):
            return_code, _output = invoke_main(summary_handoff_fault)
        if return_code == 0:
            raise SystemExit("FAILED: injected handoff-summary fault unexpectedly finalized")
        require_no_terminal(summary_handoff_fault, "handoff-summary publication fault")

        consistency_fault = make_ready_workspace(plugin_root, root, "consistency-fault")
        with mock.patch.object(
            finalizer,
            "validate_handoff_status_consistency",
            return_value={"ok": False, "errors": ["injected projected consistency failure"]},
        ):
            return_code, _output = invoke_main(consistency_fault)
        if return_code == 0:
            raise SystemExit("FAILED: injected handoff consistency fault unexpectedly finalized")
        require_no_terminal(consistency_fault, "projected consistency fault")

        journal_fault = make_ready_workspace(plugin_root, root, "journal-fault")
        with mock.patch.object(
            audit_state_io,
            "_safe_append_fsync",
            side_effect=AuditStateError("JOURNAL_APPEND_FAILED", "injected terminal journal failure"),
        ):
            return_code, _output = invoke_main(journal_fault)
        if return_code == 0:
            raise SystemExit("FAILED: injected terminal journal fault unexpectedly finalized")
        require_no_terminal(journal_fault, "terminal journal fault")
        stale = validate_handoff_state_current(journal_fault, journal_fault.parent)
        if stale.get("ok") or not set(stale.get("issue_codes", [])) & {
            "HANDOFF_STALE_REVISION",
            "HANDOFF_STALE_EVENT_SEQUENCE",
            "HANDOFF_ARTIFACT_DIGEST_DRIFT",
        }:
            raise SystemExit("FAILED: uncommitted projected handoff was not classified stale")

        state_fault = make_ready_workspace(plugin_root, root, "state-fault")
        with mock.patch.object(
            audit_state_io,
            "_atomic_replace_state",
            side_effect=AuditStateError("STATE_VIEW_WRITE_FAILED", "injected terminal state-view failure"),
        ):
            return_code, output = invoke_main(state_fault)
        if return_code == 0 or "FINALIZATION PARTIAL" not in output:
            raise SystemExit("FAILED: terminal state-view fault did not return a distinct partial diagnostic")
        if event_names(state_fault)[-1] != "finalization_succeeded":
            raise SystemExit("FAILED: terminal state-view fault did not preserve the committed journal event")
        state_before_read = (state_fault / "stage-status.json").read_bytes()
        read_only = subprocess.run(
            [sys.executable, str(plugin_root / "scripts/assert_finalized_workspace.py"), "--workspace-dir", str(state_fault)],
            cwd=plugin_root,
            capture_output=True,
            text=True,
        )
        if read_only.returncode == 0 or (state_fault / "stage-status.json").read_bytes() != state_before_read:
            raise SystemExit("FAILED: read-only finalization assertion repaired a partial state commit")
        check = subprocess.run(
            [
                sys.executable,
                str(plugin_root / "scripts/recover_audit_state.py"),
                "--workspace-dir",
                str(state_fault),
                "--check",
                "--json",
            ],
            cwd=plugin_root,
            capture_output=True,
            text=True,
        )
        diagnostic = json.loads(check.stdout)
        if diagnostic.get("ok") or not diagnostic.get("expected_state_derivable"):
            raise SystemExit("FAILED: partial terminal state was not explicitly rebuildable")
        run(
            [
                sys.executable,
                str(plugin_root / "scripts/recover_audit_state.py"),
                "--workspace-dir",
                str(state_fault),
                "--apply",
                "--expected-journal-digest",
                str(diagnostic["journal"]["digest"]),
                "--expected-state-digest",
                str(diagnostic["state"]["digest"]),
                "--json",
            ],
            plugin_root,
        )
        run(
            [sys.executable, str(plugin_root / "scripts/assert_finalized_workspace.py"), "--workspace-dir", str(state_fault)],
            plugin_root,
        )
        if not validate_handoff_state_current(state_fault, state_fault.parent).get("ok"):
            raise SystemExit("FAILED: rebuilt terminal state did not make projected handoff current")

    print("RH2 FINALIZATION SELFTEST PASSED: terminal-last, faults, idempotence, explicit rebuild")


if __name__ == "__main__":
    main()
