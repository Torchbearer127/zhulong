#!/usr/bin/env python3
"""Focused RH.3.1 Tool Registry lifecycle-stage binding regression."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

from audit_transition_policy import STAGES


DRIFT_CODE = "TOOL_REGISTRY_STAGE_SCHEMA_DRIFT"


def invoke(skill_root: Path, schema_path: Path) -> tuple[subprocess.CompletedProcess[str], dict]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(
        [
            sys.executable,
            str(skill_root / "scripts/validate_tool_registry.py"),
            "--skill-root",
            str(skill_root),
            "--registry",
            str(skill_root / "assets/tool-registry.json"),
            "--schema",
            str(schema_path),
            "--json",
        ],
        cwd=skill_root,
        env=env,
        capture_output=True,
        text=True,
    )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"FAILED: registry validator did not emit JSON: {proc.stdout!r} {proc.stderr!r}"
        ) from exc
    return proc, payload


def main() -> int:
    skill_root = Path(__file__).resolve().parent.parent
    registry_path = skill_root / "assets/tool-registry.json"
    schema_path = skill_root / "assets/schemas/tool-registry.schema.json"
    registry_before = registry_path.read_bytes()
    schema_before = schema_path.read_bytes()
    canonical_schema = json.loads(schema_before)
    if canonical_schema.get("$defs", {}).get("stage", {}).get("enum") != list(STAGES):
        raise SystemExit("FAILED: canonical Tool Registry stage enum does not match STAGES")

    canonical_proc, canonical_payload = invoke(skill_root, schema_path)
    if canonical_proc.returncode != 0 or canonical_payload.get("ok") is not True:
        raise SystemExit(f"FAILED: canonical Tool Registry rejected: {canonical_payload}")
    if canonical_payload.get("tool_count") != 39:
        raise SystemExit("FAILED: canonical Tool Registry must contain exactly 39 tools")
    if canonical_payload.get("authority") != "tool_metadata_only":
        raise SystemExit("FAILED: canonical Tool Registry authority changed")

    def delete_stage(stages: list[str]) -> None:
        stages.remove("recording")

    def rename_stage(stages: list[str]) -> None:
        stages[stages.index("recording")] = "recording_drift"

    def reorder_stages(stages: list[str]) -> None:
        first = stages.index("finalization")
        second = stages.index("recording")
        stages[first], stages[second] = stages[second], stages[first]

    def add_stage(stages: list[str]) -> None:
        stages.append("exploitation")

    mutations: tuple[tuple[str, Callable[[list[str]], None]], ...] = (
        ("delete", delete_stage),
        ("rename", rename_stage),
        ("reorder", reorder_stages),
        ("add", add_stage),
    )
    with tempfile.TemporaryDirectory(prefix="zhulong-rh3-1-stage-binding-") as tempdir:
        temp_root = Path(tempdir)
        for label, mutate in mutations:
            document = json.loads(schema_before)
            mutate(document["$defs"]["stage"]["enum"])
            mutated_path = temp_root / f"{label}.schema.json"
            mutated_path.write_text(
                json.dumps(document, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            observations: list[tuple[int, tuple[str, ...]]] = []
            for _attempt in range(2):
                proc, payload = invoke(skill_root, mutated_path)
                codes = tuple(payload.get("issue_codes", []))
                observations.append((proc.returncode, codes))
                if proc.returncode == 0 or payload.get("ok") is not False:
                    raise SystemExit(f"FAILED: {label} stage mutation was accepted")
                if codes != (DRIFT_CODE,):
                    raise SystemExit(
                        f"FAILED: {label} stage mutation returned unstable issue codes: {codes}"
                    )
                if payload.get("tool_count") != 39 or payload.get("authority") != "tool_metadata_only":
                    raise SystemExit(f"FAILED: {label} mutation changed registry metadata projection")
                if str(temp_root) in json.dumps(payload, ensure_ascii=False):
                    raise SystemExit(f"FAILED: {label} mutation leaked its temporary path")
            if observations[0] != observations[1]:
                raise SystemExit(f"FAILED: {label} mutation result was not deterministic")

    if registry_path.read_bytes() != registry_before or schema_path.read_bytes() != schema_before:
        raise SystemExit("FAILED: RH.3.1 selftest modified canonical registry bytes")
    print(
        "RH3.1 TOOL REGISTRY STAGE BINDING SELFTEST PASSED: "
        "canonical 39 tools and four deterministic schema mutations"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
