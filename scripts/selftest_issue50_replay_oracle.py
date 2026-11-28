#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import render_confirmed_vuln_docx as renderer
import validate_report_bundle as validator


MARKER = "ISSUE50_LIVE_RESPONSE"


def finding(commands: list[str]) -> dict:
    return {
        "project_name": "replay-fixture", "version_affected": "1.0",
        "vulnerability_name": "Replay oracle regression",
        "vulnerability_name_zh": "\u56de\u653e\u5224\u636e\u56de\u5f52",
        "vuln_type": "Evidence integrity",
        "vuln_type_zh": "\u8bc1\u636e\u5b8c\u6574\u6027",
        "code_context": [{"location": "fixture.py:1", "snippet": "value = request.value",
                          "source": "request", "sink": "response", "summary": "Fixture context"}],
        "verification_evidence": {"oracle_token": MARKER, "finding_slug": "replay-fixture"},
        "reproduction": [{"title": "Check the response", "commands": commands,
                          "observed": [MARKER], "results": [MARKER]}],
    }


class ReplayOracleTests(unittest.TestCase):
    def replay(self, *, output: str = "no response marker", status: int = 0,
               language: str = "en-US", command: str | None = None):
        with tempfile.TemporaryDirectory(prefix="zhulong-replay-oracle-") as raw:
            root = Path(raw)
            evidence = root / "attachments/evidence"
            evidence.mkdir(parents=True)
            history = evidence / "replay-output.log"
            history.write_text(MARKER + "\nDIRECT_IMPACT_CONFIRMED\n", encoding="utf-8")
            before = history.read_bytes()
            # An old runtime result and descriptive strings must not prove this run.
            (evidence / "replay-runtime-output.log").write_text(MARKER + "\n", encoding="utf-8")
            fakebin = root / "bin"
            fakebin.mkdir()
            docker = fakebin / "docker"
            docker.write_text(
                "#!" + sys.executable + "\nimport json, os, sys\n"
                "with open(os.environ['CALL_LOG'], 'a') as f: f.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                "if 'run' in sys.argv[1:]:\n"
                "    print(os.environ['CASE_OUTPUT'])\n"
                "    sys.exit(int(os.environ['CASE_STATUS']))\n", encoding="utf-8")
            docker.chmod(0o755)
            script = root / "run-fixture.sh"
            script.write_text(renderer.build_generated_recording_shell(
                finding([command or "docker run --rm fixture:local true"]), language, {},
                {"generator_options": {"modes": ["quick"]}}), encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith("ZHULONG_RECORDING_")}
            env.update(PATH=str(fakebin) + os.pathsep + str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", ""),
                       CASE_OUTPUT=output, CASE_STATUS=str(status), CALL_LOG=str(root / "calls.jsonl"),
                       REVIEWER_PAUSE_SHORT="0", REVIEWER_PAUSE_LONG="0")
            result = subprocess.run(["/bin/sh", str(script), "quick", "docker"], env=env,
                                    cwd=root, text=True, capture_output=True, timeout=30)
            self.assertEqual(history.read_bytes(), before)
            calls = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
            return result, (evidence / "replay-runtime-output.log").read_text(), calls

    def test_descriptions_and_history_do_not_prove_success(self):
        for language in ("en-US", "zh-CN"):
            with self.subTest(language=language):
                result, runtime, _ = self.replay(language=language)
                self.assertNotEqual(result.returncode, 0, runtime)

    def test_command_text_is_not_observed_output(self):
        result, _, _ = self.replay(command=f"docker run --rm fixture:local echo {MARKER}")
        self.assertNotEqual(result.returncode, 0)

    def test_actual_success_does_not_fabricate_impact_evidence(self):
        result, runtime, _ = self.replay(output=MARKER)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(MARKER, runtime)
        self.assertNotIn("DIRECT_IMPACT_CONFIRMED", runtime)

    def test_nonzero_exit_cannot_be_overridden_by_marker(self):
        result, _, _ = self.replay(output=MARKER, status=7)
        self.assertEqual(result.returncode, 7)

    def test_compose_run_rebuilds_the_requested_image(self):
        result, _, calls = self.replay(output=MARKER,
                                      command="docker compose -f attachments/compose.yaml run --rm attacker")
        self.assertEqual(result.returncode, 0, result.stderr)
        run = next(args for args in calls if "run" in args)
        self.assertIn("--build", run)

    def test_historical_transcript_cannot_be_a_generated_proof_command(self):
        with self.assertRaisesRegex(SystemExit, "REPLAY_ORACLE_HISTORY_FORBIDDEN"):
            renderer.build_generated_recording_shell(
                finding([f"grep {MARKER} attachments/evidence/replay-output.log"]), "en-US", {},
                {"generator_options": {"modes": ["quick"]}})

    def test_shared_gate_rejects_legacy_self_attestation_and_old_log_checks(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            script = root / "run-fixture.sh"
            text = renderer.build_generated_recording_shell(
                finding(["docker run --rm fixture:local true"]), "en-US", {}, {})
            validator.validate_root_script_oracle_sources(script, root, text)
            for changed, message in (
                (text.replace('    marker="$1"\n    # Compatibility',
                              '    log_line "$DIRECT_IMPACT_MARKER"\n    marker="$1"\n    # Compatibility'), "display text"),
                (text.replace('    printf \'%s%s%s\\n\' "$C_GREEN" "$marker" "$C_RESET"',
                              '    printf \'%s\\n\' "$marker" >> attachments/evidence/replay-runtime-output.log'), "display text"),
                (text.replace('    printf \'%s%s%s\\n\' "$C_GREEN" "$marker" "$C_RESET"',
                              '    printf \'%s\\n\' "$marker" | tee -a attachments/evidence/replay-runtime-output.log >/dev/null'), "display text"),
                (text + '\ngrep -Fq marker attachments/evidence/replay-output.log\n', "historical transcripts"),
                (text + '\ngrep -F marker attachments/evidence/replay-output.log >/dev/null\n', "historical transcripts"),
                (text + '\ngrep --quiet -F marker attachments/evidence/replay-output.log\n', "historical transcripts"),
                (text + '\nHIST_LOG="$EVIDENCE_DIR/replay-output.log"\ngrep -Fq marker "$HIST_LOG"\n', "historical transcripts"),
                (text + '\ncat attachments/evidence/replay-output.log >> "$REPLAY_LOG"\n', "historical transcripts"),
                (text.replace('if [ "$marker" = "$SUCCESS_MARKER" ] && [ "$OBSERVED_SUCCESS" -eq 1 ]; then',
                              'if grep -Fq -- "$marker" "$REPLAY_LOG"; then'), "display text"),
                (text.replace('if [ "$marker" = "$SUCCESS_MARKER" ] && [ "$OBSERVED_SUCCESS" -eq 1 ]; then',
                              'if grep -Fq -- "$marker" "$REPLAY_LOG"; then')
                     .replace('    log_line "$1"\n', ''), "display text"),
                (text.replace('if [ "$marker" = "$SUCCESS_MARKER" ] && [ "$OBSERVED_SUCCESS" -eq 1 ]; then',
                              'if grep -Fq -- "$marker" "$REPLAY_LOG"; then')
                     .replace('    log_line "$1"\n', '    printf \'%s\\n\' "$1" >> "$REPLAY_LOG"\n'), "display text"),
            ):
                with self.subTest(message=message), self.assertRaisesRegex(SystemExit, message):
                    validator.validate_root_script_oracle_sources(script, root, changed)
            # Pure display references to the historical transcript path remain allowed.
            validator.validate_root_script_oracle_sources(
                script, root, text + '\nprintf \'%s\\n\' "Historical proof: attachments/evidence/replay-output.log" >&2\n'
            )

    def test_mixed_log_oracles_are_rejected_in_every_scope(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            script = root / "run-fixture.sh"
            text = renderer.build_generated_recording_shell(
                finding(["docker run --rm fixture:local true"]), "en-US", {}, {})
            for log in ('"$REPLAY_LOG"', '"${REPLAY_LOG}"',
                        'attachments/evidence/replay-runtime-output.log'):
                for check in ('grep -Fq -- "$SUCCESS_MARKER"',
                              'grep --quiet -F -- "$SUCCESS_MARKER"'):
                    oracle = f'{check} {log} && OBSERVED_SUCCESS=1'
                    for suffix in (oracle, f'boost_observed() {{\n    {oracle}\n}}\nboost_observed'):
                        with self.subTest(suffix=suffix), self.assertRaisesRegex(
                                SystemExit, "replay success must come from observed command output"):
                            validator.validate_root_script_oracle_sources(script, root, text + '\n' + suffix + '\n')
            # Displaying the path and appending fresh output remain legitimate.
            validator.validate_root_script_oracle_sources(
                script, root, text + '\nprintf \'%s\\n\' "$REPLAY_LOG" >&2\n'
                'cat "$command_stdout" >> "$REPLAY_LOG"\n')

    def test_build_is_a_run_option_not_a_container_argument(self):
        command = "docker compose run --rm attacker echo --build"
        tokens = renderer.replay_startup_command(command).split()
        self.assertEqual(tokens[3], "--build")
        self.assertEqual(
            renderer.replay_startup_command("docker compose run --rm --build attacker"),
            "docker compose run --rm --build attacker",
        )
        with self.assertRaisesRegex(SystemExit, "REPLAY_STARTUP_INVALID"):
            renderer.replay_startup_command("docker compose run --rm --no-build attacker")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "attachments/poc").mkdir(parents=True)
            (root / "attachments/compose.yaml").write_text(
                "services:\n  attacker:\n    build:\n      context: ./poc\n      dockerfile: Dockerfile\n",
                encoding="utf-8",
            )
            (root / "attachments/poc/Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            for bad_cmd in (
                "docker compose -f attachments/compose.yaml run --rm attacker echo --build",
                "docker compose -f attachments/compose.yaml run -e --build attacker true",
                "docker compose -f attachments/compose.yaml run --build --rm --no-build attacker",
            ):
                (root / "run-handwritten.sh").write_text(f"#!/bin/sh\nset -eu\n{bad_cmd}\n", encoding="utf-8")
                with self.subTest(bad_cmd=bad_cmd), self.assertRaisesRegex(SystemExit, "REPLAY_PROVISIONING_UNPINNED"):
                    validator.validate_standalone_replay_inputs(root)
            (root / "run-handwritten.sh").write_text(
                "#!/bin/sh\nset -eu\ndocker compose -f attachments/compose.yaml run --rm --build attacker\n",
                encoding="utf-8",
            )
            validator.validate_standalone_replay_inputs(root)

    def test_compose_run_allows_quoted_container_payload_and_rejects_host_operators(self):
        for valid_cmd in (
            "docker compose -f attachments/compose.yaml run --rm attacker python3 -c 'import os; print(1)'",
            "docker compose -f attachments/compose.yaml run --rm attacker sh -c 'echo hi | cat'",
            "docker compose -f attachments/compose.yaml run --rm attacker sh -c 'echo $TARGET'",
        ):
            with self.subTest(valid_cmd=valid_cmd):
                rewritten = renderer.replay_startup_command(valid_cmd)
                self.assertIn("run --build --rm attacker", rewritten)
        for invalid_cmd in (
            "docker compose -f attachments/compose.yaml run --rm attacker; true",
            "docker compose -f attachments/compose.yaml run --rm attacker | cat",
            'docker compose -f attachments/compose.yaml run --rm "$SERVICE"',
            "docker compose -f attachments/compose.yaml run --rm attacker > out.log",
        ):
            with self.subTest(invalid_cmd=invalid_cmd), self.assertRaisesRegex(SystemExit, "REPLAY_STARTUP_INVALID"):
                renderer.replay_startup_command(invalid_cmd)


if __name__ == "__main__":
    unittest.main()
