#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


CONFIRMED_BUNDLE_SUCCESS = "completed_with_confirmed_bundles"
NO_CONFIRMED_SUCCESS = "completed_no_confirmed_findings"


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _jsonl_count(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            count += 1
    return count


def _rel(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return str(path)


def _script_path(workspace: Path, workspace_name: str, source_name: str) -> Path | None:
    candidates = [
        workspace / "bin" / workspace_name,
        Path(__file__).resolve().parent / source_name,
    ]
    return next((path for path in candidates if path.exists()), None)


def confirmed_bundle_dirs(confirmed_dir: Path) -> list[Path]:
    if not confirmed_dir.exists() or not confirmed_dir.is_dir():
        return []
    return sorted(
        path for path in confirmed_dir.iterdir()
        if path.is_dir() and not path.name.startswith(".")
    )


def _run_validate_all(
    workspace: Path,
    confirmed_dir: Path,
    language: str,
) -> dict[str, Any]:
    validator = _script_path(
        workspace,
        "validate-all-report-bundles.py",
        "validate_all_report_bundles.py",
    )
    if validator is None:
        return {"error": "validate_all_report_bundles.py not found"}
    proc = subprocess.run(
        [
            sys.executable,
            str(validator),
            "--confirmed-dir",
            str(confirmed_dir),
            "--language",
            language,
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    try:
        payload = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return {
            "error": "validator did not produce valid JSON",
            "exit_code": proc.returncode,
            "output": ((proc.stdout or "") + (proc.stderr or "")).strip()[:800],
        }
    payload["exit_code"] = proc.returncode
    if proc.stderr:
        payload["stderr"] = proc.stderr.strip()[:800]
    return payload


def inspect_confirmed_bundles(
    workspace: Path,
    *,
    confirmed_dir: Path | None = None,
    language: str = "auto",
) -> dict[str, Any]:
    confirmed_root = confirmed_dir or workspace / "confirmed"
    dirs = confirmed_bundle_dirs(confirmed_root)
    empty_counts = {
        "bundle_validated": 0,
        "partial_confirmed_bundle": 0,
        "validation_failed": 0,
        "ignored_helper_file": 0,
    }
    if not dirs:
        return {
            "confirmed_dir": str(confirmed_root),
            "confirmed_bundle_dirs_total": 0,
            "validated_confirmed_bundle_count": 0,
            "invalid_or_partial_confirmed_bundle_count": 0,
            "partial_confirmed_bundle_count": 0,
            "validation_failed_bundle_count": 0,
            "results": [],
            "validator_summary": empty_counts,
            "validator_error": "",
        }

    payload = _run_validate_all(workspace, confirmed_root, language)
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    validated = int(summary.get("bundle_validated") or 0)
    partial = int(summary.get("partial_confirmed_bundle") or 0)
    failed = int(summary.get("validation_failed") or 0)
    return {
        "confirmed_dir": str(confirmed_root),
        "confirmed_bundle_dirs_total": len(dirs),
        "validated_confirmed_bundle_count": validated,
        "invalid_or_partial_confirmed_bundle_count": partial + failed,
        "partial_confirmed_bundle_count": partial,
        "validation_failed_bundle_count": failed,
        "results": payload.get("results") if isinstance(payload.get("results"), list) else [],
        "validator_summary": summary or empty_counts,
        "validator_error": str(payload.get("error") or ""),
        "validator_exit_code": payload.get("exit_code"),
    }


def detect_docker_evidence_only(workspace: Path) -> dict[str, Any]:
    evidence_root = workspace / "evidence"
    if not evidence_root.exists():
        return {"docker_evidence_only_count": 0, "paths": []}

    paths: set[str] = set()
    evidence_names = {
        "verification-evidence.json",
        "verifier-verdict.json",
        "docker-evidence.json",
        "docker-verification.json",
    }
    ignored_parts = {"initial-probes", "variant-analysis"}
    for path in evidence_root.rglob("*"):
        if any(part in ignored_parts for part in path.relative_to(evidence_root).parts):
            continue
        lowered_parts = [part.lower() for part in path.parts]
        is_docker_named = any("docker" in part or "verification" in part for part in lowered_parts)
        is_evidence_file = path.is_file() and path.name in evidence_names
        if not is_docker_named and not is_evidence_file:
            continue
        evidence_dir = path if path.is_dir() else path.parent
        if evidence_dir == evidence_root:
            continue
        paths.add(_rel(evidence_dir, workspace))
    return {
        "docker_evidence_only_count": len(paths),
        "paths": sorted(paths),
    }


def _run_report_validator(workspace: Path, flag: str, path: Path) -> dict[str, Any]:
    validator = _script_path(workspace, "validate-report-bundle.py", "validate_report_bundle.py")
    if validator is None:
        return {"ok": False, "error": "validate_report_bundle.py not found"}
    proc = subprocess.run(
        [sys.executable, str(validator), "--workspace-dir", str(workspace), flag, str(path)],
        capture_output=True,
        text=True,
    )
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "output": output[:1000],
    }


def inspect_formal_variant_analysis(
    workspace: Path,
    *,
    validated_confirmed_bundle_count: int,
) -> dict[str, Any]:
    variant_dir = workspace / "evidence" / "variant-analysis"
    seeds_path = variant_dir / "seeds.jsonl"
    candidates_path = variant_dir / "variant-candidates.jsonl"
    errors: list[str] = []
    seed_validation: dict[str, Any] = {}
    candidate_validation: dict[str, Any] = {}

    if validated_confirmed_bundle_count <= 0:
        status = "not_applicable_no_validated_confirmed_bundle"
        if seeds_path.exists() or candidates_path.exists():
            status = "invalid_no_validated_confirmed_bundle"
            errors.append(
                "formal seeded variant discovery requires at least one validated confirmed bundle"
            )
        return {
            "formal_variant_analysis_status": status,
            "completed": False,
            "errors": errors,
            "variant_dir": "evidence/variant-analysis",
            "seeds": "evidence/variant-analysis/seeds.jsonl",
            "variant_candidates": "evidence/variant-analysis/variant-candidates.jsonl",
            "seed_count": _jsonl_count(seeds_path),
            "candidate_count": _jsonl_count(candidates_path),
            "seed_validation": seed_validation,
            "candidate_validation": candidate_validation,
        }

    if not variant_dir.is_dir():
        errors.append("missing evidence/variant-analysis/")
    if not seeds_path.is_file():
        errors.append("missing evidence/variant-analysis/seeds.jsonl")
    if not candidates_path.is_file():
        errors.append("missing evidence/variant-analysis/variant-candidates.jsonl")

    if seeds_path.is_file():
        seed_validation = _run_report_validator(workspace, "--variant-seed-card", seeds_path)
        if not seed_validation.get("ok"):
            errors.append(
                "variant seed validation failed: "
                + str(seed_validation.get("error") or seed_validation.get("output") or "unknown error")
            )
    if candidates_path.is_file():
        candidate_validation = _run_report_validator(workspace, "--variant-candidates", candidates_path)
        if not candidate_validation.get("ok"):
            errors.append(
                "variant candidates validation failed: "
                + str(candidate_validation.get("error") or candidate_validation.get("output") or "unknown error")
            )

    if errors:
        status = "invalid" if seed_validation or candidate_validation else "not_executed"
    else:
        status = "completed"
    return {
        "formal_variant_analysis_status": status,
        "completed": status == "completed",
        "errors": errors,
        "variant_dir": "evidence/variant-analysis",
        "seeds": "evidence/variant-analysis/seeds.jsonl",
        "variant_candidates": "evidence/variant-analysis/variant-candidates.jsonl",
        "seed_count": _jsonl_count(seeds_path),
        "candidate_count": _jsonl_count(candidates_path),
        "seed_validation": seed_validation,
        "candidate_validation": candidate_validation,
    }


def inspect_workspace_state(
    workspace: Path,
    *,
    confirmed_dir: Path | None = None,
    language: str = "auto",
) -> dict[str, Any]:
    bundle_state = inspect_confirmed_bundles(workspace, confirmed_dir=confirmed_dir, language=language)
    docker_state = detect_docker_evidence_only(workspace)
    variant_state = inspect_formal_variant_analysis(
        workspace,
        validated_confirmed_bundle_count=int(bundle_state["validated_confirmed_bundle_count"]),
    )
    state = {
        **bundle_state,
        **docker_state,
        **variant_state,
    }
    if (
        state["validated_confirmed_bundle_count"] == 0
        and state["docker_evidence_only_count"] > 0
    ):
        state["handoff_state"] = "docker_evidence_collected_but_no_bundle"
    elif state["validated_confirmed_bundle_count"] > 0:
        state["handoff_state"] = "validated_confirmed_bundle_available"
    else:
        state["handoff_state"] = "no_validated_confirmed_bundle"
    return state


def _status_completion_result(status: dict[str, Any]) -> str:
    return str(status.get("result") or status.get("completion_result") or "").strip()


def _unsafe_claim_lines(text: str, *, validated_count: int) -> list[str]:
    issues: list[str] = []
    if validated_count > 0:
        return issues
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        lowered = line.lower()
        safe_negative = any(
            phrase in lowered
            for phrase in (
                "not applicable",
                "not executed",
                "not ready",
                "no validated",
                "no confirmed",
                "cannot",
                "must not",
                "not a confirmed",
                "不是",
                "不能",
                "不得",
                "未完成",
                "未执行",
            )
        )
        if CONFIRMED_BUNDLE_SUCCESS in line:
            issues.append(f"handoff-summary.md:{line_no}: claims {CONFIRMED_BUNDLE_SUCCESS} with zero validated bundles")
            continue
        if re.search(r"\b(?:validated\s+)?confirmed\s+bundles?\s*:\s*[1-9]\d*\b", lowered):
            issues.append(f"handoff-summary.md:{line_no}: claims nonzero confirmed bundle count with zero validated bundles")
            continue
        if not safe_negative and re.search(
            r"(?:confirmed\s+bundles?.{0,60}(?:completed|complete|passed|ready)|"
            r"(?:completed|complete|passed|ready).{0,60}confirmed\s+bundles?)",
            lowered,
        ):
            issues.append(f"handoff-summary.md:{line_no}: claims confirmed bundle completion with zero validated bundles")
            continue
        if not safe_negative and re.search(
            r"(?:formal\s+)?seeded\s+variant\s+discovery.{0,80}(?:completed|complete|passed|ready|can run|runnable)|"
            r"(?:completed|complete|passed|ready|can run|runnable).{0,80}(?:formal\s+)?seeded\s+variant\s+discovery",
            lowered,
        ):
            issues.append(f"handoff-summary.md:{line_no}: claims formal seeded variant discovery completion/readiness with zero validated bundles")
            continue
        if not safe_negative and "docker" in lowered and "evidence" in lowered and "confirmed bundle" in lowered:
            issues.append(f"handoff-summary.md:{line_no}: describes Docker evidence as a confirmed bundle")
            continue
        if not safe_negative and re.search(r"\bbundle[- ]ready\b|bundle generation ready|ready for bundle generation", lowered):
            issues.append(f"handoff-summary.md:{line_no}: claims bundle readiness with zero validated bundles")
            continue
    return issues


def validate_handoff_status_consistency(
    workspace: Path,
    *,
    status: dict[str, Any] | None = None,
    handoff_path: Path | None = None,
    state: dict[str, Any] | None = None,
    language: str = "auto",
) -> dict[str, Any]:
    inspected = state or inspect_workspace_state(workspace, language=language)
    status_doc = status if status is not None else _load_json(workspace / "stage-status.json")
    handoff = handoff_path or workspace / "handoff-summary.md"
    errors: list[str] = []
    warnings: list[str] = []
    validated_count = int(inspected.get("validated_confirmed_bundle_count") or 0)

    result = _status_completion_result(status_doc)
    if result == CONFIRMED_BUNDLE_SUCCESS and validated_count == 0:
        errors.append(
            "stage-status.json declares completed_with_confirmed_bundles but validated_confirmed_bundle_count=0"
        )
    if result == CONFIRMED_BUNDLE_SUCCESS and inspected.get("formal_variant_analysis_status") != "completed":
        errors.append(
            "stage-status.json declares completed_with_confirmed_bundles but formal seeded variant discovery is not completed"
        )
    if result == NO_CONFIRMED_SUCCESS and validated_count > 0:
        errors.append(
            "stage-status.json declares completed_no_confirmed_findings but validated confirmed bundles exist"
        )

    if handoff.exists():
        text = handoff.read_text(encoding="utf-8", errors="ignore")
        errors.extend(_unsafe_claim_lines(text, validated_count=validated_count))
    else:
        warnings.append("handoff-summary.md is missing")

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "state": inspected,
    }
