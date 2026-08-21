#!/usr/bin/env python3
"""Focused deterministic checks for the host-owned completion contract."""
from __future__ import annotations

import inspect
import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from docker_case_lifecycle import LifecycleError  # noqa: E402
from evidence_io import MAX_CAPTURE_BYTES, SafeEvidenceError, run_captured_command  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAILED: {message}")


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=20, check=False)


def test_capture_api(root: Path) -> None:
    parameters = inspect.signature(run_captured_command).parameters
    require("completion_marker" not in parameters, "completion marker remains in capture API")
    require("on_completion" not in parameters, "completion callback remains in capture API")

    for expected_exit, stdout, stderr in ((0, "OK\nMARKER:17\n", ""), (1, "MARKER:0\n", "failed\n"),
                                           (130, "success\nMARKER:0\n", "interrupted\n"), (143, "", "MARKER:0\n")):
        case = root / f"exit-{expected_exit}"
        case.mkdir()
        code = (
            "import sys; "
            f"sys.stdout.write({stdout!r}); sys.stderr.write({stderr!r}); "
            f"raise SystemExit({expected_exit})"
        )
        value = run_captured_command(
            case, case / "stdout.log", case / "stderr.log", [sys.executable, "-c", code],
            timeout=5, expected_oracle="MARKER",
        )
        require(value["exit_code"] == expected_exit, f"host exit {expected_exit} was rewritten")
        require(value["oracle_matched"] is True, "bounded stdout/stderr oracle was not observed")
        require(value["capture_integrity"] is True, "host capture identity was not preserved")

    flood = root / "flood"
    flood.mkdir()
    try:
        run_captured_command(
            flood, flood / "stdout.log", flood / "stderr.log",
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * (17 * 1024 * 1024))"],
            timeout=5, expected_oracle="MARKER",
        )
    except SafeEvidenceError as exc:
        require(exc.code == "EVIDENCE_SIZE_LIMIT", f"flood used unstable diagnostic: {exc.code}")
    else:
        raise SystemExit("FAILED: stdout flood was accepted")
    require((flood / "stdout.log").stat().st_size == MAX_CAPTURE_BYTES, "capture exceeded hard limit")


def test_signal_contract(root: Path) -> None:
    case = root / "signal"
    case.mkdir()
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True,
    )
    try:
        os.killpg(child.pid, signal.SIGTERM)
        child.wait(timeout=2)
        require(child.returncode != 0, "owned process group signal did not terminate child")
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=2)


def test_empty_command_before_docker(root: Path) -> None:
    log = root / "empty-command-docker.log"
    fake_docker = root / "empty-command-docker.py"
    fake_docker.write_text(
        "import pathlib\n"
        f"pathlib.Path({str(log)!r}).write_text('called\\n', encoding='utf-8')\n",
        encoding="utf-8",
    )
    env = {**os.environ, "PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}
    fake_docker.chmod(0o755)
    wrapper = ROOT / "scripts" / "run_verification_case.sh"
    result = run([
        "bash", str(wrapper), "--workspace-dir", str(root / "missing-workspace"),
        "--case-id", "empty", "--mode", "docker-run", "--image", "stub:local",
        "--timeout-seconds", "1", "--expected-oracle", "MARKER", "--docker-arg", "--log-driver",
    ], cwd=ROOT, env=env)
    require(result.returncode == 2 and "VERIFICATION_COMMAND_REQUIRED" in result.stderr, "empty command was not rejected")
    require(not log.exists(), "empty command reached Docker")


def test_historical_import_is_read_only(root: Path) -> None:
    lifecycle = ROOT / "scripts" / "docker_case_lifecycle.py"
    evidence_root = root / "historical"
    evidence_root.mkdir()
    docker_log = root / "docker.log"
    docker = root / "docker-stub.py"
    docker.write_text(
        "import pathlib, sys\n"
        f"pathlib.Path({str(docker_log)!r}).write_text('called\\n', encoding='utf-8')\n"
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    receipt = run([
        sys.executable, str(lifecycle), "prepare", "--evidence-root", str(evidence_root),
        "--case-id", "historical", "--mode", "docker-run",
    ], cwd=ROOT)
    require(receipt.returncode == 0, "historical fixture receipt could not be prepared")
    value = json.loads(receipt.stdout)
    output = evidence_root / "container-output"
    before = sorted(path.name for path in evidence_root.iterdir())
    rejected = run([
        sys.executable, str(lifecycle), "import-output", "--evidence-root", str(evidence_root),
        "--receipt", value["receipt_path"], "--receipt-sha256", value["receipt_sha256"],
        "--output-dir", str(output), "--docker", str(docker),
    ], cwd=ROOT)
    require(rejected.returncode != 0, "new execution still accepted container output import")
    require("CONTAINER_OUTPUT_HISTORICAL_ONLY" in rejected.stdout, "historical-only diagnostic missing")
    require(not docker_log.exists(), "historical-only compatibility invoked Docker")
    require(not output.exists(), "historical-only compatibility created output")
    require(before == sorted(path.name for path in evidence_root.iterdir()), "historical compatibility wrote evidence")


def test_lifecycle_policy_has_no_output_authority(root: Path) -> None:
    import docker_case_lifecycle as lifecycle

    require(not hasattr(lifecycle, "import_output"), "active output importer remains exported")
    require(not hasattr(lifecycle, "_stream_container_output"), "container tar stream remains active")
    try:
        lifecycle._output_root(root, root / "container-output")  # type: ignore[attr-defined]
    except (AttributeError, LifecycleError):
        pass
    else:
        raise SystemExit("FAILED: container output root remains a new execution API")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="zhulong-rh6-contraction-selftest-") as value:
        root = Path(value)
        test_capture_api(root)
        test_signal_contract(root)
        test_empty_command_before_docker(root)
        test_historical_import_is_read_only(root)
        test_lifecycle_policy_has_no_output_authority(root)
    print("HOST COMPLETION ORACLE CONTRACTION SELFTEST PASSED: foreground host outcome, bounded capture, historical-only output")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
