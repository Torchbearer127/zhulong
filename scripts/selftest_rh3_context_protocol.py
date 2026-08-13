#!/usr/bin/env python3
"""Deterministic RH.3 context CLI and phase-vocabulary regression."""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

from audit_transition_policy import STAGES


EXPECTED_PHASE_MODULE = {
    "intake": "phase-intake-recon",
    "recon": "phase-intake-recon",
    "candidate_generation": "phase-candidate-triage",
    "triage": "phase-candidate-triage",
    "verification": "phase-verification",
    "severity_escalation": "phase-verification",
    "variant_discovery": "phase-variant-discovery",
    "packaging": "phase-packaging-finalization",
    "finalization": "phase-packaging-finalization",
    "recording": "phase-recording",
}


def run(command: list[str], cwd: Path, *, expect_success: bool = True) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    if expect_success and proc.returncode != 0:
        raise SystemExit(
            "FAILED: command returned nonzero:\n"
            + " ".join(command)
            + "\nstdout:\n"
            + proc.stdout
            + "\nstderr:\n"
            + proc.stderr
        )
    if not expect_success and proc.returncode == 0:
        raise SystemExit("FAILED: command unexpectedly succeeded: " + " ".join(command))
    return proc


def skill_paths(skill_root: Path) -> list[Path]:
    source = skill_root / "skills/zhulong/SKILL.md"
    template = skill_root / "templates/claude-skill/SKILL.md"
    if source.is_file() and template.is_file():
        return [source, template]
    installed = skill_root / "SKILL.md"
    if installed.is_file():
        return [installed]
    raise SystemExit("FAILED: Skill contract is unavailable")


def command_from_skill(skill_text: str, script_name: str) -> list[str]:
    blocks = re.findall(r"```bash\s*\n(.*?)\n```", skill_text, flags=re.DOTALL)
    matches = [block for block in blocks if f"/{script_name}" in block]
    if len(matches) != 1:
        raise SystemExit(f"FAILED: Skill must contain exactly one {script_name} bash block")
    command = re.sub(r"\\\s*\n\s*", " ", matches[0]).strip()
    try:
        return shlex.split(command)
    except ValueError as exc:
        raise SystemExit(f"FAILED: Skill {script_name} command cannot be parsed") from exc


def materialize_command(tokens: list[str], values: dict[str, str]) -> list[str]:
    result: list[str] = []
    for index, token in enumerate(tokens):
        rendered = token
        for placeholder, value in values.items():
            rendered = rendered.replace(placeholder, value)
        result.append(sys.executable if index == 0 and rendered == "python3" else rendered)
    return result


def exercise_skill_commands(skill_root: Path, temp_root: Path) -> None:
    skill_text = skill_paths(skill_root)[0].read_text(encoding="utf-8")
    target = skill_root / "assets/fixtures/context-planning/generic-recon"
    workspace = temp_root / "skill-command-workspace"
    workspace.mkdir()
    replacements = {
        "<skill-root>": str(skill_root),
        "<target-repo>": str(target),
        "<audit-workspace>": str(workspace),
    }
    planner = materialize_command(command_from_skill(skill_text, "plan_audit_context.py"), replacements)
    validator = materialize_command(command_from_skill(skill_text, "validate_context_plan.py"), replacements)
    run(planner, skill_root)
    output = workspace / "context-plan.json"
    if not output.is_file() or output.is_symlink():
        raise SystemExit("FAILED: Skill planner command did not publish a regular context plan")
    run(validator, skill_root)
    plan = json.loads(output.read_text(encoding="utf-8"))
    if plan.get("phase") != "recon" or plan.get("authority") != "recommended_context_only":
        raise SystemExit("FAILED: Skill command produced the wrong phase or authority")


def exercise_all_stages(skill_root: Path, temp_root: Path) -> None:
    planner = skill_root / "scripts/plan_audit_context.py"
    validator = skill_root / "scripts/validate_context_plan.py"
    catalog = skill_root / "assets/context-catalog.json"
    target = skill_root / "assets/fixtures/context-planning/generic-recon"
    if tuple(EXPECTED_PHASE_MODULE) != STAGES:
        raise SystemExit("FAILED: focused phase oracle does not match the authoritative lifecycle order")
    for stage in STAGES:
        output = temp_root / f"stage-{stage}.json"
        run(
            [
                sys.executable,
                str(planner),
                "--target-dir",
                str(target),
                "--phase",
                stage,
                "--output",
                str(output),
            ],
            skill_root,
        )
        run(
            [
                sys.executable,
                str(validator),
                "--skill-root",
                str(skill_root),
                "--catalog",
                str(catalog),
                "--plan",
                str(output),
                "--json",
            ],
            skill_root,
        )
        plan = json.loads(output.read_text(encoding="utf-8"))
        mandatory_ids = {
            item.get("id")
            for item in plan.get("mandatory", [])
            if isinstance(item, dict)
        }
        if plan.get("phase") != stage or EXPECTED_PHASE_MODULE[stage] not in mandatory_ids:
            raise SystemExit(f"FAILED: {stage} did not select its direct phase reference")
        if plan.get("authority") != "recommended_context_only" or len(plan.get("non_claims", [])) != 4:
            raise SystemExit(f"FAILED: {stage} weakened the advisory-only contract")

    invalid_output = temp_root / "invalid-stage.json"
    invalid = run(
        [
            sys.executable,
            str(planner),
            "--target-dir",
            str(target),
            "--phase",
            "not_a_stage",
            "--output",
            str(invalid_output),
        ],
        skill_root,
        expect_success=False,
    )
    if invalid_output.exists() or "invalid choice" not in invalid.stderr:
        raise SystemExit("FAILED: invalid planner phase did not fail before output")

    for legacy_flag in ("--skill-root", "--repo-root"):
        legacy_output = temp_root / f"legacy-{legacy_flag[2:]}.json"
        legacy = run(
            [
                sys.executable,
                str(planner),
                "--target-dir",
                str(target),
                "--phase",
                "recon",
                "--output",
                str(legacy_output),
                legacy_flag,
                str(skill_root),
            ],
            skill_root,
            expect_success=False,
        )
        if legacy_output.exists() or "unrecognized arguments" not in legacy.stderr:
            raise SystemExit(f"FAILED: planner did not reject legacy argument {legacy_flag}")


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def exercise_meta_conformance(skill_root: Path, temp_root: Path) -> None:
    mutation_root = temp_root / "mutation-layout"
    shutil.copytree(
        skill_root,
        mutation_root,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "*.pyo"),
    )
    validator = mutation_root / "scripts/validate_context_catalog.py"
    catalog = mutation_root / "assets/context-catalog.json"

    def validate_failure(expected_code: str) -> None:
        proc = run(
            [
                sys.executable,
                str(validator),
                "--skill-root",
                str(mutation_root),
                "--catalog",
                str(catalog),
                "--json",
            ],
            mutation_root,
            expect_success=False,
        )
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise SystemExit("FAILED: conformance mutation did not return JSON") from exc
        if expected_code not in payload.get("issue_codes", []):
            raise SystemExit(
                f"FAILED: conformance mutation did not report {expected_code}: {payload.get('issue_codes', [])}"
            )

    def mutate_files(
        paths: list[Path],
        mutation: Callable[[], None],
        expected_code: str,
    ) -> None:
        originals = {path: path.read_bytes() for path in paths}
        try:
            mutation()
            validate_failure(expected_code)
        finally:
            for path, raw in originals.items():
                path.write_bytes(raw)

    policy = mutation_root / "scripts/audit_transition_policy.py"

    def mutate_policy() -> None:
        text = policy.read_text(encoding="utf-8")
        changed = text.replace('    "recording",\n)', ')', 1)
        if changed == text:
            raise SystemExit("FAILED: FSM mutation anchor is stale")
        policy.write_text(changed, encoding="utf-8")

    mutate_files([policy], mutate_policy, "CONTEXT_PHASE_SCHEMA_DRIFT")

    for label, relative in (
        ("audit-event", "assets/schemas/audit-event.schema.json"),
        ("stage-status", "assets/schemas/stage-status.schema.json"),
    ):
        path = mutation_root / relative

        def mutate_state_schema(path: Path = path) -> None:
            value = json.loads(path.read_text(encoding="utf-8"))
            value["$defs"]["stage"]["enum"].remove("recording")
            write_json(path, value)

        mutate_files([path], mutate_state_schema, "CONTEXT_PHASE_SCHEMA_DRIFT")

    context_catalog_schema = mutation_root / "assets/schemas/context-catalog.schema.json"

    def mutate_catalog_schema() -> None:
        value = json.loads(context_catalog_schema.read_text(encoding="utf-8"))
        value["$defs"]["module"]["properties"]["phases"]["items"]["enum"].remove("triage")
        write_json(context_catalog_schema, value)

    mutate_files([context_catalog_schema], mutate_catalog_schema, "CONTEXT_PHASE_SCHEMA_DRIFT")

    context_plan_schema = mutation_root / "assets/schemas/context-plan.schema.json"

    def mutate_plan_schema() -> None:
        value = json.loads(context_plan_schema.read_text(encoding="utf-8"))
        value["properties"]["phase"]["enum"].append("invented_stage")
        write_json(context_plan_schema, value)

    mutate_files([context_plan_schema], mutate_plan_schema, "CONTEXT_PHASE_SCHEMA_DRIFT")

    def mutate_candidate_phase() -> None:
        value = json.loads(catalog.read_text(encoding="utf-8"))
        module = next(item for item in value["modules"] if item["id"] == "phase-candidate-triage")
        module["phases"].remove("triage")
        write_json(catalog, value)

    mutate_files([catalog], mutate_candidate_phase, "CONTEXT_PHASE_REFERENCE_DRIFT")

    def mutate_recording_phase() -> None:
        value = json.loads(catalog.read_text(encoding="utf-8"))
        module = next(item for item in value["modules"] if item["id"] == "phase-recording")
        module["phases"] = ["finalization"]
        write_json(catalog, value)

    mutate_files([catalog], mutate_recording_phase, "CONTEXT_PHASE_REFERENCE_DRIFT")

    planner = mutation_root / "scripts/plan_audit_context.py"

    def mutate_planner_choices() -> None:
        text = planner.read_text(encoding="utf-8")
        changed = text.replace("choices=PHASES)", "choices=PHASES[:-1])", 1)
        if changed == text:
            raise SystemExit("FAILED: planner mutation anchor is stale")
        planner.write_text(changed, encoding="utf-8")

    mutate_files([planner], mutate_planner_choices, "CONTEXT_PLANNER_PHASE_CHOICES_DRIFT")

    skills = skill_paths(mutation_root)

    def mutate_skill_command() -> None:
        for path in skills:
            text = path.read_text(encoding="utf-8")
            changed = text.replace("--target-dir <target-repo>", "--repo-root <target-repo>", 1)
            if changed == text:
                raise SystemExit("FAILED: Skill command mutation anchor is stale")
            path.write_text(changed, encoding="utf-8")

    mutate_files(skills, mutate_skill_command, "CONTEXT_SKILL_COMMAND_DRIFT")

    def mutate_skill_phases() -> None:
        for path in skills:
            text = path.read_text(encoding="utf-8")
            changed = text.replace(", `recording`.", ".", 1)
            if changed == text:
                raise SystemExit("FAILED: Skill phase mutation anchor is stale")
            path.write_text(changed, encoding="utf-8")

    mutate_files(skills, mutate_skill_phases, "CONTEXT_SKILL_PHASE_DRIFT")

    if len(skills) == 2:
        def mutate_skill_parity() -> None:
            skills[1].write_bytes(skills[1].read_bytes() + b"\n")

        mutate_files(skills, mutate_skill_parity, "CONTEXT_SKILL_PARITY_DRIFT")


def main() -> int:
    skill_root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="zhulong-rh3-context-") as tempdir:
        temp_root = Path(tempdir)
        exercise_skill_commands(skill_root, temp_root)
        exercise_all_stages(skill_root, temp_root)
        exercise_meta_conformance(skill_root, temp_root)
    print(
        "RH3 CONTEXT PROTOCOL SELFTEST PASSED: "
        "Skill CLI, ten-stage plans, and meta-conformance mutations"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
