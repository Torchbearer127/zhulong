#!/usr/bin/env python3
"""Focused deterministic checks for the RH.6 output and signal boundary."""
from __future__ import annotations

import os
import json
import signal
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from docker_case_lifecycle import (  # noqa: E402
    OUTPUT_MAX_FILE_BYTES,
    OUTPUT_MAX_BYTES,
    LifecycleError,
    _validate_output_tree,
)
from evidence_io import MAX_CAPTURE_BYTES, SafeEvidenceError, run_captured_command  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAILED: {message}")


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=20, check=False)


def test_capture_bounds(root: Path) -> None:
    normal = root / "normal"
    normal.mkdir()
    value = run_captured_command(
        normal,
        normal / "stdout.log",
        normal / "stderr.log",
        [sys.executable, "-c", "print('RH6_ORACLE')"],
        timeout=5,
        expected_oracle="RH6_ORACLE",
    )
    require(value["oracle_matched"] is True and value["capture_integrity"] is True, "normal bounded capture failed")
    require((normal / "stdout.log").stat().st_size < MAX_CAPTURE_BYTES, "normal capture reached the hard limit")

    for stream, code in (("stdout", "import sys; sys.stdout.write('x' * (17 * 1024 * 1024))"),
                         ("stderr", "import sys; sys.stderr.write('x' * (17 * 1024 * 1024))")):
        case = root / f"{stream}-flood"
        case.mkdir()
        try:
            run_captured_command(
                case,
                case / "stdout.log",
                case / "stderr.log",
                [sys.executable, "-c", code],
                timeout=5,
                expected_oracle="RH6_ORACLE",
            )
        except SafeEvidenceError as exc:
            require(exc.code == "EVIDENCE_SIZE_LIMIT", f"{stream} flood used unstable code: {exc.code}")
        else:
            raise SystemExit(f"FAILED: {stream} flood was accepted")
        target = case / f"{stream}.log"
        require(target.stat().st_size == MAX_CAPTURE_BYTES, f"{stream} capture exceeded bounded size")


def test_output_tree(root: Path) -> None:
    valid = root / "valid"
    (valid / "nested").mkdir(parents=True)
    (valid / "nested" / "small.txt").write_text("safe\n", encoding="utf-8")
    total, entries = _validate_output_tree(valid)
    require(total == 5 and entries == 2, "valid nested output was rejected")

    symlink = root / "symlink"
    symlink.mkdir()
    (symlink / "escape").symlink_to("/etc", target_is_directory=True)
    try:
        _validate_output_tree(symlink)
    except LifecycleError as exc:
        require(exc.code == "EVIDENCE_OUTPUT_UNSAFE_ENTRY", "symlink output used an unstable code")
    else:
        raise SystemExit("FAILED: output symlink was accepted")

    hardlink = root / "hardlink"
    hardlink.mkdir()
    source = hardlink / "source.txt"
    source.write_text("hardlink\n", encoding="utf-8")
    os.link(source, hardlink / "copy.txt")
    try:
        _validate_output_tree(hardlink)
    except LifecycleError as exc:
        require(exc.code == "EVIDENCE_OUTPUT_UNSAFE_ENTRY", "hardlink output used an unstable code")
    else:
        raise SystemExit("FAILED: output hardlink was accepted")

    fifo = root / "fifo"
    fifo.mkdir()
    fifo_path = fifo / "named-pipe"
    os.mkfifo(fifo_path)
    try:
        try:
            _validate_output_tree(fifo)
        except LifecycleError as exc:
            require(exc.code == "EVIDENCE_OUTPUT_UNSAFE_ENTRY", "FIFO output used an unstable code")
        else:
            raise SystemExit("FAILED: output FIFO was accepted")
    finally:
        fifo_path.unlink(missing_ok=True)

    oversized = root / "oversized"
    oversized.mkdir()
    with (oversized / "large.bin").open("wb") as handle:
        handle.truncate(OUTPUT_MAX_FILE_BYTES + 1)
    try:
        _validate_output_tree(oversized)
    except LifecycleError as exc:
        require(exc.code == "EVIDENCE_OUTPUT_LIMIT", "oversized output used an unstable code")
    else:
        raise SystemExit("FAILED: oversized output was accepted")

    many = root / "many"
    many.mkdir()
    for index in range(4097):
        (many / f"entry-{index}").write_text("x", encoding="utf-8")
    try:
        _validate_output_tree(many)
    except LifecycleError as exc:
        require(exc.code == "EVIDENCE_OUTPUT_LIMIT", "entry-count overflow used an unstable code")
    else:
        raise SystemExit("FAILED: entry-count overflow was accepted")


def test_signal_group_contract(root: Path) -> None:
    case = root / "signal"
    case.mkdir()
    child = subprocess.Popen(
        [sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, lambda *_: time.sleep(30)); time.sleep(30)"],
        start_new_session=True,
    )
    try:
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=2)
        require(child.returncode != 0, "process-group signal did not terminate the child")
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=2)


def test_cli_output_import(root: Path) -> None:
    lifecycle = ROOT / "scripts" / "docker_case_lifecycle.py"
    evidence_root = root / "import-cli"
    evidence_root.mkdir()
    stub = root / "docker-cp-stub.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import os, pathlib, sys, tarfile, tempfile\n"
        "args = sys.argv[1:]\n"
        "if args and args[0] == 'exec':\n"
        "    with tempfile.TemporaryDirectory() as temp_value:\n"
        "        source = pathlib.Path(temp_value)\n"
        "        mode = os.environ.get('RH6_IMPORT_MODE', 'valid')\n"
        "        if mode == 'valid':\n"
        "            (source / 'nested').mkdir()\n"
        "            (source / 'nested' / 'attachment.txt').write_text('RH6_IMPORT\\n')\n"
        "        elif mode == 'symlink':\n"
        "            (source / 'escape').symlink_to('/etc', target_is_directory=True)\n"
        "        elif mode == 'oversized':\n"
        "            (source / 'oversized.bin').open('wb').truncate(16 * 1024 * 1024 + 1)\n"
        "        with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as archive:\n"
        "            archive.add(source, arcname='.', recursive=True)\n"
        "    raise SystemExit(0)\n"
        "destination = pathlib.Path(sys.argv[-1])\n"
        "destination.mkdir(parents=True, exist_ok=True)\n"
        "mode = os.environ.get('RH6_IMPORT_MODE', 'valid')\n"
        "if mode == 'valid':\n"
        "    (destination / 'nested').mkdir()\n"
        "    (destination / 'nested' / 'attachment.txt').write_text('RH6_IMPORT\\n')\n"
        "elif mode == 'symlink':\n"
        "    (destination / 'escape').symlink_to('/etc', target_is_directory=True)\n"
        "elif mode == 'oversized':\n"
        "    (destination / 'oversized.bin').open('wb').truncate(16 * 1024 * 1024 + 1)\n"
        "else:\n"
        "    raise SystemExit(3)\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    env = os.environ.copy()
    env["RH6_IMPORT_MODE"] = "valid"

    prepared = run([
        sys.executable, str(lifecycle), "prepare", "--evidence-root", str(evidence_root),
        "--case-id", "import-valid", "--mode", "docker-run",
    ], cwd=ROOT, env=env)
    require(prepared.returncode == 0, f"output-import receipt prepare failed: {prepared.stdout} {prepared.stderr}")
    receipt = json.loads(prepared.stdout)
    output = evidence_root / "container-output-valid"
    imported = run([
        sys.executable, str(lifecycle), "import-output", "--evidence-root", str(evidence_root),
        "--receipt", receipt["receipt_path"], "--receipt-sha256", receipt["receipt_sha256"],
        "--output-dir", str(output), "--docker", str(stub),
    ], cwd=ROOT, env=env)
    require(imported.returncode == 0 and (output / "nested" / "attachment.txt").read_text(encoding="utf-8") == "RH6_IMPORT\n", f"valid output import did not publish atomically: rc={imported.returncode} stdout={imported.stdout!r} stderr={imported.stderr!r}")
    require(not list(evidence_root.glob(".container-output-valid.import-*")), "valid output import left staging residue")

    for mode, expected_code in (("symlink", "EVIDENCE_OUTPUT_UNSAFE_ENTRY"), ("oversized", "EVIDENCE_OUTPUT_LIMIT")):
        env["RH6_IMPORT_MODE"] = mode
        prepared = run([
            sys.executable, str(lifecycle), "prepare", "--evidence-root", str(evidence_root),
            "--case-id", f"import-{mode}", "--mode", "docker-run",
        ], cwd=ROOT, env=env)
        require(prepared.returncode == 0, f"{mode} output receipt prepare failed")
        receipt = json.loads(prepared.stdout)
        output = evidence_root / f"container-output-{mode}"
        rejected = run([
            sys.executable, str(lifecycle), "import-output", "--evidence-root", str(evidence_root),
            "--receipt", receipt["receipt_path"], "--receipt-sha256", receipt["receipt_sha256"],
            "--output-dir", str(output), "--docker", str(stub),
        ], cwd=ROOT, env=env)
        require(rejected.returncode != 0 and expected_code in rejected.stdout, f"{mode} output import was not fail-closed: {rejected.stdout}")
        require(not output.exists() and not list(evidence_root.glob(f".container-output-{mode}.import-*")), f"{mode} output import left a published or staging path")
def main() -> int:
    with tempfile.TemporaryDirectory(prefix="zhulong-rh6-selftest-") as value:
        root = Path(value)
        test_capture_bounds(root)
        test_output_tree(root)
        test_cli_output_import(root)
        test_signal_group_contract(root)
    print("HOST OUTPUT QUOTA / SIGNAL CLOSURE SELFTEST PASSED: bounded capture, safe import tree, and process-group signal handling")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
