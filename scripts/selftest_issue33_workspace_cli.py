#!/usr/bin/env python3
"""Offline checks of generated workspace entrypoints, imports and replacement guards."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock


CLI_NAMES = ("finalize-audit-workspace.py", "extract_variant_seed.py", "find_variant_candidates.py")
MODULES = ("render_handoff_summary.py", "assert_finalized_workspace.py", "validate_report_bundle.py", "original_input_evidence.py",
           "dependency_resolution.py", "render_confirmed_vuln_docx.py")


def require(value: bool, message: str) -> None:
    if not value:
        raise SystemExit("FAILED: " + message)


def run(command: list[str], env: dict[str, str], *, expected: int = 0) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(command, env=env, capture_output=True, text=True, timeout=90)
    require(process.returncode == expected,
            f"{command!r}: exit {process.returncode}, expected {expected}\n{process.stdout}{process.stderr}")
    return process


def bootstrap(root: Path, repo: Path, env: dict[str, str], *, force: bool = False) -> Path:
    repo.mkdir(parents=True, exist_ok=True)
    command = ["bash", str(root / "scripts/bootstrap_verification_workspace.sh"), "--target-dir", str(repo),
               "--workspace-name", "security-research-cli"]
    run(command + (["--force"] if force else []), env)
    return repo / "security-research-cli"


def refresh(root: Path, workspace: Path, env: dict[str, str], *, expected: int = 0) -> subprocess.CompletedProcess[str]:
    return run(["bash", str(root / "scripts/refresh_workspace_helpers.sh"), "--workspace", str(workspace)],
               {**env, "SKILL_DIR": str(root)}, expected=expected)


def check_help(workspace: Path, env: dict[str, str]) -> None:
    failures = []
    for name in CLI_NAMES:
        process = subprocess.run([sys.executable, str(workspace / "bin" / name), "--help"], env=env,
                                 capture_output=True, text=True, timeout=30)
        print(f"{workspace.name}/bin/{name} --help: exit {process.returncode}", flush=True)
        if process.returncode:
            failures.append(process.stderr.strip())
    require(not failures, "generated CLI startup failed:\n" + "\n".join(failures))
    run(["bash", str(workspace / "scripts/finalize-audit-workspace.py"), "--help"], env)


def check_modules(root: Path, workspace: Path) -> None:
    for name in MODULES:
        require((workspace / "bin" / name).read_bytes() == (root / "scripts" / name).read_bytes(),
                "workspace module drift: " + name)


def check_evidence_paths(workspace: Path, env: dict[str, str]) -> None:
    bundle = workspace / "confirmed/synthetic-evidence"
    bundle.mkdir(parents=True)
    # Enter the validator CLI's delayed original-input reader, not just --help.
    process = run([sys.executable, str(workspace / "bin/validate-report-bundle.py"),
                   "--bundle-dir", str(bundle), "--require-original-input"], env, expected=1)
    require("ORIGINAL_INPUT_INVALID" in process.stdout + process.stderr,
            "validator did not reach its original-input evidence gate")
    code = """
import json
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from docx import Document
from PIL import Image
import original_input_evidence as original
root = Path(sys.argv[2])
(root / 'attachments').mkdir()
raw = b'synthetic original input\\r\\n'
(root / 'attachments/input.txt').write_bytes(raw)
Image.new('RGB', (80, 40), 'white').save(root / 'attachments/input.png')
spec = {'text_path': 'attachments/input.txt', 'screenshot_path': 'attachments/input.png',
        'title': 'Synthetic input', 'description': 'Offline test only', 'caption': 'Synthetic screenshot'}
manifest = original.prepare_original_input(root, spec, 'en-US')
(root / 'findings.json').write_text(json.dumps({'findings': [{'original_input': spec}]}), encoding='utf-8')
doc = Document()
original.render_original_input(doc, root, manifest)
doc.save(root / 'report.docx')
original.validate_original_input(root, required=True)
assert (root / 'attachments/input.txt').read_bytes() == raw
"""
    run([sys.executable, "-I", "-c", code, str(workspace / "bin"), str(bundle)], env)
    process = run([sys.executable, str(workspace / "bin/validate-report-bundle.py"),
                   "--bundle-dir", str(bundle), "--require-original-input"], env, expected=1)
    require("ORIGINAL_INPUT_INVALID" not in process.stdout + process.stderr
            and "ModuleNotFoundError" not in process.stdout + process.stderr,
            "valid synthetic input did not pass the CLI's original-input reader")
    (bundle / "compose.yml").write_text("services:\n  web:\n    build:\n      context: .\n      dockerfile: Dockerfile\n", encoding="utf-8")
    (bundle / "findings.json").write_text(json.dumps({"findings": [{"dependency_resolution": {
        "compose_file": {"path": "compose.yml"}, "service": "web", "dockerfile": {"path": "Dockerfile"}}}]}), encoding="utf-8")
    # Isolate imports to generated bin; malformed declarations must fail at the
    # real dependency gate rather than being hidden by a source-tree sys.path.
    code = (
        "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
        "import validate_report_bundle as v; "
        "v.validate_replay_compose_inputs(Path(sys.argv[2]), ['-f', 'compose.yml', 'build', 'wrong-service'], require_standalone=True)"
    )
    process = run([sys.executable, "-I", "-c", code, str(workspace / "bin"), str(bundle)], env, expected=1)
    require("DEPENDENCY_RESOLUTION_INVALID" in process.stdout + process.stderr,
            "validator did not reach its dependency-resolution gate")
    (bundle / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    code = (
        "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
        "import validate_report_bundle as v; "
        "v.validate_replay_compose_inputs(Path(sys.argv[2]), ['-f', 'compose.yml', 'up', '--build', '-d', 'web'], require_standalone=True)"
    )
    run([sys.executable, "-I", "-c", code, str(workspace / "bin"), str(bundle)], env)
    shutil.rmtree(bundle)
    print("generated validator: original-input positive/negative and dependency-resolution delayed imports passed", flush=True)


def check_finalization(root: Path, scratch: Path, env: dict[str, str]) -> None:
    sys.path.insert(0, str(root / "scripts"))
    from selftest_rh2_finalization import make_ready_workspace

    with mock.patch.dict(os.environ, env, clear=True):
        workspace = make_ready_workspace(root, scratch, "generated-cli")
    (workspace / "scripts").mkdir()
    helper = workspace / "bin/manage-docker-resources.py"
    substitute = helper.read_bytes()
    refresh(root, workspace, env)
    helper.write_bytes(substitute)
    helper.chmod(0o755)
    run([sys.executable, str(workspace / "bin/render-handoff-summary.py"), "--workspace-dir", str(workspace)], env)
    require("finalize-audit-workspace.py" in (workspace / "handoff-summary.md").read_text(encoding="utf-8"),
            "handoff no longer recommends the workspace finalization entry")
    run([sys.executable, str(workspace / "bin/finalize-audit-workspace.py"), "--help"], env)
    command = [sys.executable, str(workspace / "bin/finalize-audit-workspace.py"), "--workspace-dir", str(workspace),
               "--result", "completed_no_confirmed_findings", "--language", "en-US"]
    run(command, env)
    run(command, env)
    run([sys.executable, str(workspace / "bin/assert-finalized-workspace.py"), "--workspace-dir", str(workspace)], env)
    print("generated finalizer: synthetic R2 no-confirmed completion and assertion passed", flush=True)


def check_unsafe_targets(root: Path, workspace: Path, env: dict[str, str]) -> None:
    for operation in ("bootstrap", "refresh"):
        for name in MODULES:
            for kind in ("symlink", "hardlink", "fifo", "directory"):
                active = workspace
                if operation == "bootstrap":
                    active = workspace.parent / f"unsafe-{name}-{kind}" / workspace.name
                    (active / "bin").mkdir(parents=True)
                target = active / "bin" / name
                original = target.read_bytes() if target.exists() else None
                target.unlink(missing_ok=True)
                marker = active.parent / "outside-marker"
                marker.write_bytes(b"outside marker must not change\n")
                if kind == "symlink":
                    target.symlink_to(marker)
                elif kind == "hardlink":
                    os.link(marker, target)
                elif kind == "fifo":
                    os.mkfifo(target)
                else:
                    target.mkdir()
                before = target.lstat()
                if operation == "bootstrap":
                    command = ["bash", str(root / "scripts/bootstrap_verification_workspace.sh"), "--target-dir",
                               str(active.parent), "--workspace-name", active.name, "--force"]
                else:
                    command = ["bash", str(root / "scripts/refresh_workspace_helpers.sh"), "--workspace", str(active)]
                process = subprocess.run(command, env={**env, "SKILL_DIR": str(root)}, capture_output=True, text=True, timeout=90)
                require(process.returncode != 0 and "owned regular file or absent" in process.stderr,
                        f"{operation} accepted {kind} target {name}: {process.stdout}{process.stderr}")
                require(marker.read_bytes() == b"outside marker must not change\n", "unsafe target modified external bytes")
                after = target.lstat()
                require((after.st_ino, stat.S_IFMT(after.st_mode), after.st_nlink)
                        == (before.st_ino, stat.S_IFMT(before.st_mode), before.st_nlink), "unsafe target was replaced")
                target.rmdir() if kind == "directory" else target.unlink()
                if original is not None:
                    target.write_bytes(original)
                marker.unlink()
                if operation == "bootstrap":
                    shutil.rmtree(active.parent)
    print("bootstrap/refresh: symlink, hardlink, FIFO and directory targets rejected for all six modules", flush=True)


def main() -> int:
    sys.dont_write_bytecode = True
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--legacy-root", type=Path)
    parser.add_argument("--help-only", action="store_true")
    args = parser.parse_args()
    root = args.plugin_root.resolve()
    with tempfile.TemporaryDirectory(prefix="zhulong-issue33-") as raw:
        scratch = Path(raw)
        tools = scratch / "tools"
        tools.mkdir()
        (tools / "python3").symlink_to(sys.executable)
        denial_log = scratch / "denied-tools.log"
        for name in ("docker", "curl", "wget", "npm", "pip", "pip3", "obs"):
            path = tools / name
            path.write_text('#!/bin/sh\nprintf "%s\\n" "$0 $*" >> "$ZHULONG_DENIAL_LOG"\nexit 97\n', encoding="utf-8")
            path.chmod(0o755)
        home = scratch / "home"
        home.mkdir()
        env = {**os.environ, "HOME": str(home), "PATH": str(tools) + os.pathsep + os.environ["PATH"],
               "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "", "GIT_CONFIG_GLOBAL": os.devnull,
               "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_COUNT": "0",
               "GIT_CEILING_DIRECTORIES": str(scratch), "ZHULONG_DENIAL_LOG": str(denial_log)}
        workspace = bootstrap(root, scratch / "new-repo", env)
        check_help(workspace, env)
        if args.help_only:
            return 0
        check_modules(root, workspace)
        check_evidence_paths(workspace, env)
        legacy = bootstrap(args.legacy_root.resolve() if args.legacy_root else root, scratch / "legacy-repo", env)
        if not args.legacy_root:
            # Preserve the pre-fix generated layout even after this selftest is
            # installed from a fixed source tree.
            for name in ("render_handoff_summary.py", "assert_finalized_workspace.py", "validate_report_bundle.py"):
                (legacy / "bin" / name).unlink()
            for name in ("original_input_evidence.py", "dependency_resolution.py", "render_confirmed_vuln_docx.py"):
                (legacy / "bin" / name).unlink(missing_ok=True)
        refresh(root, legacy, env)
        check_help(legacy, env)
        check_modules(root, legacy)
        check_evidence_paths(legacy, env)
        check_finalization(root, scratch, env)
        check_unsafe_targets(root, workspace, env)
        denials = denial_log.read_text().splitlines() if denial_log.exists() else []
        expected_probe = str(tools / "docker") + " info --format {{json .}}"
        require(all(line == expected_probe for line in denials), "unexpected denied tool call: " + "\n".join(denials))
        print(f"denied read-only Docker availability probes: {len(denials)}; no real Docker or other denied tool ran", flush=True)
    print("ISSUE 33 WORKSPACE CLI SELFTEST PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
