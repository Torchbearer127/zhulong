#!/usr/bin/env python3
"""Offline generation regressions; anonymous fixtures are not runtime proof."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

if os.environ.get("ZHULONG_TEST_CORE"):
    sys.path.insert(0, str(Path(os.environ["ZHULONG_TEST_CORE"]) / "scripts"))

import build_confirmed_bundle as builder
import render_confirmed_vuln_docx as renderer
import selftest_plugin as fixtures
import validate_report_bundle as validator


class GenerationTests(unittest.TestCase):
    def make_bundle(self, root, commands=None):
        artifact = {"output_name": "run-demo.sh", "generator": "reviewer-recording-shell"}
        finding = fixtures.issue23_finding(commands or ["docker compose up --build -d app"], include_history=True)
        finding["bundle_root_artifacts"] = [artifact]
        (root / "findings.json").write_text(json.dumps({"findings": [finding]}))
        (root / "run-demo.sh").write_text(renderer.build_generated_recording_shell(finding, "en-US", {}, artifact))
        (root / "compose.yaml").write_text(json.dumps({"services": {"app": {
            "image": "anonymous-target:mutable", "build": ".", "healthcheck": {"test": ["CMD", "true"]}}}}))
        (root / "Dockerfile").write_text("FROM scratch\n")
        return finding, artifact

    def test_missing_copy_input_rejected_in_ordinary_and_strong_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_bundle(root)
            for instruction in ("COPY missing.txt /input.txt", "COPY\tmissing.txt /input.txt", "ADD\tmissing.txt /input.txt"):
                (root / "Dockerfile").write_text("FROM scratch\n" + instruction + "\n")
                for check in (lambda: validator.validate_compose_static_paths(root / "compose.yaml", root),
                              lambda: validator.validate_standalone_replay_inputs(root)):
                    with self.subTest(instruction=instruction), self.assertRaisesRegex(SystemExit, "REPLAY_INPUT_MISSING"):
                        check()

    def test_literal_inputs_and_internal_stage_preserve_delivered_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_bundle(root)
            source = root / "source.txt"
            source.write_bytes(b"anonymous input\r\n")
            before = source.read_bytes()
            (root / "Dockerfile").write_text('FROM scratch AS build\nCOPY ["source.txt", "/input.txt"]\nFROM scratch\nCOPY --from=build /input.txt /input.txt\n')
            validator.validate_standalone_replay_inputs(root)
            self.assertEqual(source.read_bytes(), before)

    def test_unsafe_nested_input_and_unsupported_copy_forms_fail_strong(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_bundle(root)
            (root / "source").mkdir()
            (root / "source/linked").symlink_to(root / "Dockerfile")
            cases = [("COPY source/ /app/", "REPLAY_INPUT_UNSAFE"),
                     ("COPY ../outside /app/", "REPLAY_INPUT_UNSAFE"),
                     ("COPY *.txt /app/", "REPLAY_PROVISIONING_UNSUPPORTED"),
                     ("COPY $SOURCE /app/", "REPLAY_PROVISIONING_UNSUPPORTED"),
                     ("COPY --from=external:mutable /x /x", "REPLAY_PROVISIONING_UNSUPPORTED"),
                     ("ADD https://example.invalid/source.tar /app/", "REPLAY_PROVISIONING_UNSUPPORTED"),
                     ("COPY <<EOF /app/", "REPLAY_PROVISIONING_UNSUPPORTED")]
            for instruction, diagnostic in cases:
                with self.subTest(instruction=instruction):
                    (root / "Dockerfile").write_text("FROM scratch\n" + instruction + "\n")
                    with self.assertRaisesRegex(SystemExit, diagnostic):
                        validator.validate_standalone_replay_inputs(root)

    def test_strong_startup_requires_build_but_immutable_image_route_stays_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_bundle(root, ["docker compose up -d app"])
            with self.assertRaisesRegex(SystemExit, "REPLAY_PROVISIONING_UNPINNED"):
                validator.validate_standalone_replay_inputs(root)
            (root / "compose.yaml").write_text(json.dumps({"services": {"app": {
                "image": "anonymous@sha256:" + "a" * 64, "healthcheck": {"test": ["CMD", "true"]}}}}))
            validator.validate_standalone_replay_inputs(root)

    def test_new_detached_docker_run_is_not_generated_as_ready(self):
        for command in ("docker run -d anonymous:mutable", "docker run --detach anonymous@sha256:" + "a" * 64,
                        "docker container run --name anonymous -d anonymous:mutable",
                        "docker run --health-start-interval 1s -d anonymous:mutable", "docker run --detach=1 anonymous:mutable",
                        "docker run --unknown-value value -d anonymous:mutable"):
            with self.subTest(command=command), self.assertRaisesRegex(SystemExit, "REPLAY_STARTUP_UNSUPPORTED"):
                renderer.replay_startup_command(command)
        command = "docker run --rm anonymous:mutable printf -d"
        self.assertEqual(renderer.replay_startup_command(command), command)
        command = "docker run --rm -- anonymous:mutable printf -d"
        self.assertEqual(renderer.replay_startup_command(command), command)

    def test_compose_startup_flag_variants_reject_without_changing_ordinary_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_bundle(root)
            (root / "findings.json").unlink()
            for flag in ("--detach=true", "--detach=1", "--detach=false", "--wait=true", "-d=true", "-Vd"):
                command = "docker compose up --build " + flag + " app"
                (root / "run-demo.sh").write_text("#!/bin/sh\n" + command + "\n")
                with self.subTest(flag=flag):
                    with self.assertRaisesRegex(SystemExit, "REPLAY_STARTUP_UNSUPPORTED"):
                        renderer.replay_startup_command(command)
                    with self.assertRaisesRegex(SystemExit, "REPLAY_PROVISIONING_UNSUPPORTED"):
                        validator.validate_standalone_replay_inputs(root)
                    validator.validate_replay_compose_inputs(root, ["up", "--build", flag, "app"])
            rewritten = renderer.replay_startup_command("docker compose up --no-deps --build -d app")
            self.assertIn('--wait --wait-timeout "$READY_TIMEOUT_SECONDS"', rewritten)
            self.assertIn("--no-deps", rewritten)

    def test_missing_python_fails_before_docker_or_next_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_bundle(root, ["printf SHOULD_NOT_EXECUTE"])
            fakebin = root / "bin"
            fakebin.mkdir()
            (fakebin / "dirname").symlink_to(shutil.which("dirname"))
            docker = fakebin / "docker"
            docker.write_text('#!/bin/sh\nprintf called > docker-called\nexit 0\n')
            docker.chmod(0o755)
            result = subprocess.run(["/bin/sh", str(root / "run-demo.sh"), "quick", "docker"], cwd=root,
                                    env=dict(os.environ, PATH=str(fakebin)), capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("REPLAY_TOOL_UNAVAILABLE", result.stderr)
            self.assertFalse((root / "docker-called").exists())
            self.assertFalse((root / "attachments/evidence/replay-runtime-output.log").exists())
            self.assertNotIn("CONFIRMED", result.stdout)

    def test_public_output_portability_and_raw_history_preservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            history = root / "historical.log"
            history.write_bytes(b"raw historical evidence\r\n")
            before = hashlib.sha256(history.read_bytes()).hexdigest()
            commands = ["printf '%s\\n' /Users/anonymous/private-checkout/input ISSUE23_SUCCESS_MARKER"]
            self.make_bundle(root, commands)
            result = self.run_generated(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            log = (root / "attachments/evidence/replay-runtime-output.log").read_text()
            self.assertNotIn("/Users/anonymous/", result.stdout + result.stderr + log)
            self.assertIn("ISSUE23_SUCCESS_MARKER", log)
            self.assertEqual(hashlib.sha256(history.read_bytes()).hexdigest(), before)

    def run_generated(self, root, startup_exit="0"):
        fakebin = root / "fakebin"
        fakebin.mkdir(exist_ok=True)
        docker = fakebin / "docker"
        docker.write_text('#!/bin/sh\ncase "$*" in\ninfo) exit 0;;\n*logs*) printf "%s\\n" /Users/anonymous/private-checkout/diagnostic; exit 0;;\n*up*) case "$*" in *"--wait --wait-timeout 2"*) exit ' + startup_exit + ';; *) exit 98;; esac;;\n*) exit 98;;\nesac\n')
        docker.chmod(0o755)
        env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ.get("PATH", ""),
                   REVIEWER_PAUSE_SHORT="0", REVIEWER_PAUSE_LONG="0", ZHULONG_READY_TIMEOUT_SECONDS="2")
        return subprocess.run(["sh", str(root / "run-demo.sh"), "quick", "docker"], cwd=root,
                              env=env, text=True, capture_output=True, timeout=15)

    def test_bounded_startup_failure_precedes_next_command_and_diagnostics_are_portable(self):
        for status in ("7", "9", "124"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.make_bundle(root, ["docker compose up --build -d app", "printf '%s\\n' ISSUE23_SUCCESS_MARKER > after-startup"])
                result = self.run_generated(root, status)
                self.assertEqual(result.returncode, int(status), result.stdout + result.stderr)
                self.assertFalse((root / "after-startup").exists())
                log = (root / "attachments/evidence/replay-runtime-output.log").read_text()
                self.assertIn("diagnostic", log)
                self.assertNotIn("/Users/anonymous/", result.stdout + result.stderr + log)

    def test_healthy_startup_with_zero_visual_pauses_reaches_next_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_bundle(root, ["docker compose up --build -d app", "printf '%s\\n' ISSUE23_SUCCESS_MARKER"])
            result = self.run_generated(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_builder_exposes_same_explicit_static_qualification_flag(self):
        plugin = Path(builder.__file__).resolve().parent.parent
        result = subprocess.run([sys.executable, str(plugin / "scripts/build_confirmed_bundle.py"), "--help"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("--require-standalone-replay", result.stdout)

    def test_formal_builder_forwards_qualification_without_changing_ordinary_mode(self):
        plugin = Path(builder.__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fakebin = root / "bin"
            fakebin.mkdir()
            docker = fakebin / "docker"
            docker.write_text('#!/bin/sh\ncase "$*" in "compose version"|*" config") exit 0;; *) exit 99;; esac\n')
            docker.chmod(0o755)
            env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ["PATH"])
            for strong in (False, True):
                repo, workspace = fixtures.new_build_wrapper_workspace(root, "strong" if strong else "ordinary")
                slug = fixtures.build_wrapper_source_finding(plugin, repo, workspace)
                source = workspace / "confirmed/findings.json"
                payload = json.loads(source.read_text())
                payload["findings"][0]["reproduction"][0]["commands"] = ["printf anonymous-unsupported-shell"]
                source.write_text(json.dumps(payload))
                contract = fixtures.build_wrapper_contract(workspace, slug)
                command = [sys.executable, str(plugin / "scripts/build_confirmed_bundle.py"), "--repo-root", str(repo),
                           "--workspace-dir", str(workspace), "--contract", str(contract)]
                if strong:
                    command.append("--require-standalone-replay")
                result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=90)
                if strong:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("REPLAY_PROVISIONING_UNSUPPORTED", result.stdout + result.stderr)
                    self.assertFalse((workspace / "confirmed" / slug).exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue((workspace / "confirmed" / slug).is_dir())

    def test_existing_resolution_digest_and_path_checks_are_reused(self):
        from dependency_resolution import checked_file
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "input.tar"
            source.write_bytes(b"anonymous build input")
            spec = {"path": source.name, "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
            self.assertEqual(checked_file(root, spec), source)
            for changed in (dict(spec, sha256="0" * 64), dict(spec, path="../input.tar")):
                with self.assertRaisesRegex(ValueError, "DEPENDENCY_RESOLUTION_INVALID"):
                    checked_file(root, changed)
            source.unlink()
            with self.assertRaisesRegex(ValueError, "missing"):
                checked_file(root, spec)

    def test_static_manifest_never_attests_runtime_and_ordinary_history_stays_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {"validation_status": "passed", "promote_status": "promoted",
                        "status": builder.build_phase_status("passed", "promoted")}
            validator.validate_build_manifest_status(manifest, root)
            validator.validate_build_manifest_status({"validation_status": "passed", "promote_status": "promoted"}, root)
            for phase in validator.BUILD_MANIFEST_RUNTIME_PHASES:
                changed = json.loads(json.dumps(manifest))
                changed["status"][phase] = "passed"
                with self.assertRaisesRegex(SystemExit, "cannot be passed"):
                    validator.validate_build_manifest_status(changed, root)


if __name__ == "__main__":
    unittest.main()
