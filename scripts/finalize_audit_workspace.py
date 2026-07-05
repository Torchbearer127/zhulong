#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audit_disposition import (
    LEDGER_FILENAME,
    synthesize_disposition_ledger,
    validate_disposition_ledger,
    write_disposition_ledger,
)
from blocked_verification import detect_blocked_verification
from workspace_state import (
    inspect_workspace_state,
    validate_handoff_status_consistency,
)


VALID_RESULTS = {
    "completed_with_confirmed_bundles",
    "completed_no_confirmed_findings",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def write_event(
    workspace: Path,
    event: str,
    stage: str,
    status: str,
    event_status: str,
    message: str,
    blocker: str = "",
    resume_step: str = "",
    **details: Any,
) -> None:
    writer = workspace / "bin" / "write-audit-event.py"
    if not writer.exists():
        writer = Path(__file__).resolve().parent / "write_audit_event.py"
    if not writer.exists():
        print(
            f"WARNING: audit event writer not found; event not recorded: {event}",
            file=sys.stderr,
        )
        return
    cmd = [
        sys.executable, str(writer),
        "--workspace-dir", str(workspace),
        "--event", event,
        "--stage", stage,
        "--status", status,
        "--event-status", event_status,
        "--message", message,
    ]
    if blocker:
        cmd.extend(["--blocker", blocker])
    if resume_step:
        cmd.extend(["--resume-step", resume_step])
    if details:
        cmd.extend(["--details-json", json.dumps(details, ensure_ascii=False)])
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        output = ((proc.stdout or "") + (proc.stderr or "")).strip()
        if len(output) > 500:
            output = output[:500] + "..."
        print(
            f"WARNING: audit event writer failed for event {event}: {output}",
            file=sys.stderr,
        )


def run_bundle_validator(workspace: Path, confirmed_dir: Path,
                         language: str) -> dict[str, Any]:
    validator = workspace / "bin" / "validate-all-report-bundles.py"
    if not validator.exists():
        validator = Path(__file__).resolve().parent / "validate_all_report_bundles.py"
    if not validator.exists():
        return {"error": "validate_all_report_bundles.py not found"}
    cmd = [
        sys.executable, str(validator),
        "--confirmed-dir", str(confirmed_dir),
        "--language", language,
        "--json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return {
            "error": "validator did not produce valid JSON",
            "exit_code": proc.returncode,
            "output": ((proc.stdout or "") + (proc.stderr or "")).strip()[:500],
        }


def find_report_validator(workspace: Path) -> Path | None:
    validator = workspace / "bin" / "validate-report-bundle.py"
    if validator.exists():
        return validator
    validator = Path(__file__).resolve().parent / "validate_report_bundle.py"
    if validator.exists():
        return validator
    return None


def run_single_report_validator(workspace: Path, flag: str, path: Path) -> dict[str, Any]:
    validator = find_report_validator(workspace)
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
        "output": output[:800],
    }


def validate_seeded_variant_discovery(workspace: Path) -> dict[str, Any]:
    variant_dir = workspace / "evidence" / "variant-analysis"
    seeds_path = variant_dir / "seeds.jsonl"
    candidates_path = variant_dir / "variant-candidates.jsonl"
    errors: list[str] = []

    if not variant_dir.is_dir():
        errors.append(
            "missing evidence/variant-analysis/; run seeded variant discovery from a validated confirmed bundle before finalization."
        )
    if not seeds_path.is_file():
        errors.append(
            "missing evidence/variant-analysis/seeds.jsonl; run extract_variant_seed.py and validate the final seed card."
        )
    if not candidates_path.is_file():
        errors.append(
            "missing evidence/variant-analysis/variant-candidates.jsonl; run find_variant_candidates.py and validate candidate-only output."
        )

    seed_validation: dict[str, Any] = {}
    candidate_validation: dict[str, Any] = {}
    if seeds_path.is_file():
        seed_validation = run_single_report_validator(workspace, "--variant-seed-card", seeds_path)
        if not seed_validation.get("ok"):
            errors.append(
                "variant seed validation failed: "
                + str(seed_validation.get("error") or seed_validation.get("output") or "unknown error")
            )
    if candidates_path.is_file():
        candidate_validation = run_single_report_validator(workspace, "--variant-candidates", candidates_path)
        if not candidate_validation.get("ok"):
            errors.append(
                "variant candidates validation failed: "
                + str(candidate_validation.get("error") or candidate_validation.get("output") or "unknown error")
            )

    return {
        "ok": not errors,
        "errors": errors,
        "variant_dir": "evidence/variant-analysis",
        "seeds": "evidence/variant-analysis/seeds.jsonl",
        "variant_candidates": "evidence/variant-analysis/variant-candidates.jsonl",
        "seed_validation": seed_validation,
        "candidate_validation": candidate_validation,
    }


def run_docker_verify_clean(workspace: Path, *, strict: bool) -> dict[str, Any]:
    if os.environ.get("ZHULONG_TEST_SKIP_DOCKER_CLEAN_CHECK") == "1":
        return {"clean": True, "skipped": True, "reason": "docker clean check skipped by test-only env var"}
    helper = workspace / "bin" / "manage-docker-resources.py"
    if not helper.exists():
        helper = Path(__file__).resolve().parent / "manage_docker_resources.py"
    if not helper.exists():
        return {"clean": False, "error": "manage_docker_resources.py not found"}
    baseline = workspace / "docker" / "docker-resource-baseline.json"
    if not baseline.exists():
        return {"clean": False, "error": "docker-resource-baseline.json missing; cannot verify Docker cleanliness"}
    cmd = [
        sys.executable, str(helper),
        "--workspace-dir", str(workspace),
        "--verify-clean",
    ]
    if strict:
        cmd.append("--strict")
    status_path = workspace / "docker" / "docker-cleanliness-status.json"
    status_mtime_before = status_path.stat().st_mtime_ns if status_path.exists() else None
    proc = subprocess.run(cmd, capture_output=True, text=True)
    status_refreshed = (
        status_path.exists()
        and (
            status_mtime_before is None
            or status_path.stat().st_mtime_ns != status_mtime_before
        )
    )
    if status_refreshed:
        return load_json(status_path)
    return {
        "clean": False,
        "exit_code": proc.returncode,
        "error": "Docker cleanliness helper did not refresh docker-cleanliness-status.json; refusing to trust stale status",
        "output": ((proc.stdout or "") + (proc.stderr or "")).strip()[:500],
    }


def refresh_handoff(workspace: Path, repo_root: Path) -> bool:
    renderer = workspace / "bin" / "render-handoff-summary.py"
    if not renderer.exists():
        renderer = Path(__file__).resolve().parent / "render_handoff_summary.py"
    if not renderer.exists():
        return False
    cmd = [
        sys.executable, str(renderer),
        "--workspace-dir", str(workspace),
        "--repo-root", str(repo_root),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode == 0


def runtime_hygiene_summary_line(workspace: Path, *, language: str) -> str:
    status = load_json(workspace / "runtime/runtime-hygiene-status.json")
    if not status:
        if language == "en-US":
            return "- OMC runtime hygiene: `not_recorded`; run `bin/check_omc_runtime.sh --json` before `/team` or `/ultrawork`.\n"
        return "- OMC runtime hygiene：`not_recorded`；使用 `/team` 或 `/ultrawork` 前运行 `bin/check_omc_runtime.sh --json`。\n"

    mode = str(status.get("recommended_mode") or "unknown")
    clean = bool(status.get("clean"))
    unresolved = status.get("unresolved_review_only")
    unresolved_count = len(unresolved) if isinstance(unresolved, list) else 0
    resume_step = str(status.get("resume_step") or "")
    attention_needed = mode == "cleanup_needed" or unresolved_count > 0 or not clean

    if language == "en-US":
        if attention_needed:
            return (
                f"- OMC runtime hygiene: `{mode}`; attention needed before `/team` or `/ultrawork`; "
                f"unresolved review-only: `{unresolved_count}`; teammate PID cleanup is manual outside Zhulong; "
                f"resume: {resume_step or '_none_'}\n"
            )
        return f"- OMC runtime hygiene: `{mode}`; clean: `{str(clean).lower()}`.\n"

    if attention_needed:
        return (
            f"- OMC runtime hygiene：`{mode}`；使用 `/team` 或 `/ultrawork` 前需要处理；"
            f"unresolved review-only：`{unresolved_count}`；teammate PID 只能由操作员在 Zhulong 外手动处理；"
            f"resume：{resume_step or '_none_'}\n"
        )
    return f"- OMC runtime hygiene：`{mode}`；clean：`{str(clean).lower()}`。\n"


def ensure_workspace_summary(
    workspace: Path,
    *,
    result: str,
    validated_count: int,
    docker_clean: bool,
    docker_strict: bool,
    language: str,
) -> Path:
    summary_path = workspace / "SUMMARY.md"
    placeholder_marker = "<!-- zhulong_completion_summary_placeholder: 1 -->"
    if summary_path.exists() and placeholder_marker not in summary_path.read_text(encoding="utf-8", errors="ignore"):
        return summary_path
    config = load_json(workspace / "asr-config.json")
    configured_language = str(config.get("summary_language") or config.get("output_language") or "").strip()
    effective_language = configured_language if language == "auto" and configured_language else language
    runtime_line = runtime_hygiene_summary_line(workspace, language=effective_language)
    if effective_language == "en-US":
        content = (
            f"{placeholder_marker}\n"
            "# Audit Summary\n\n"
            "This workspace passed the Zhulong completion gate. This file is a stable workspace-level "
            "summary placeholder; expand it with the final human-facing audit summary after finalization.\n\n"
            f"- Result: `{result}`\n"
            f"- Validated confirmed bundles: `{validated_count}`\n"
            f"- Docker clean: `{str(docker_clean).lower()}`\n"
            f"- Docker strict clean: `{str(docker_strict).lower()}`\n"
            f"{runtime_line}"
            "- Confirmed-output guardrail: scanner-only, dependency-only, static-only, unverified, blocked, "
            "or timed-out findings are not confirmed vulnerabilities.\n"
        )
    else:
        content = (
            f"{placeholder_marker}\n"
            "# 审计总结\n\n"
            "该工作区已通过 Zhulong 完成门控。本文件是稳定的 workspace-level 总结占位；"
            "最终化后请在这里补充面向人的审计总结，不要只保留在聊天或终端日志中。\n\n"
            f"- 完成结果：`{result}`\n"
            f"- 已验证 confirmed bundles：`{validated_count}`\n"
            f"- Docker clean：`{str(docker_clean).lower()}`\n"
            f"- Docker strict clean：`{str(docker_strict).lower()}`\n"
            f"{runtime_line}"
            "- confirmed-only 约束：scanner-only、dependency-only、static-only、unverified、blocked、"
            "timed-out 结果都不是确认漏洞。\n"
        )
    summary_path.write_text(content, encoding="utf-8")
    return summary_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Zhulong audit workspace completion gate. "
            "Validates that bundle state, Docker cleanliness, stage-status.json, "
            "and handoff-summary.md are consistent before declaring an audit finished."
        ),
    )
    parser.add_argument("--workspace-dir", required=True,
                        help="Path to the Zhulong audit workspace.")
    parser.add_argument("--language", choices=["zh-CN", "en-US", "auto"], default="auto",
                        help="Language for bundle validation.")
    parser.add_argument("--result", required=True,
                        choices=sorted(VALID_RESULTS),
                        help="Expected completion result.")
    parser.add_argument("--confirmed-dir", default="",
                        help="Path to confirmed/ directory. Defaults to <workspace>/confirmed.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    workspace = Path(args.workspace_dir).expanduser().resolve()
    if not workspace.is_dir():
        print(f"FINALIZATION FAILED: workspace does not exist: {workspace}", file=sys.stderr)
        return 1
    if not (workspace / "asr-config.json").exists():
        print(f"FINALIZATION FAILED: not a Zhulong audit workspace: {workspace}", file=sys.stderr)
        return 1

    repo_root = workspace.parent.resolve()
    confirmed_dir = Path(args.confirmed_dir).expanduser().resolve() if args.confirmed_dir else workspace / "confirmed"
    result = args.result
    language = args.language
    errors: list[str] = []
    blocked_summary: dict[str, Any] = {}

    write_event(workspace, "finalization_started", "finalization", "running",
                "started", f"Completion gate started with result={result}.",
                expected_result=result)

    # --- Step 1: Bundle validation ---
    inspected_state = inspect_workspace_state(
        workspace,
        confirmed_dir=confirmed_dir,
        language=language,
    )
    bundle_summary: dict[str, Any] = {
        "summary": inspected_state.get("validator_summary", {}),
        "results": inspected_state.get("results", []),
    }
    validated_count = int(inspected_state.get("validated_confirmed_bundle_count") or 0)
    partial_count = int(inspected_state.get("partial_confirmed_bundle_count") or 0)
    failed_count = int(inspected_state.get("validation_failed_bundle_count") or 0)
    if inspected_state.get("validator_error"):
        errors.append(f"Bundle validation error: {inspected_state['validator_error']}")

    write_event(workspace, "bundle_validation_outcome", "finalization", "running",
                "ok" if not errors else "warning",
                f"Bundles: validated={validated_count}, partial={partial_count}, failed={failed_count}.",
                validated=validated_count, partial=partial_count, failed=failed_count)

    # --- Step 2: Check result vs bundle state ---
    if result == "completed_with_confirmed_bundles":
        if validated_count == 0:
            errors.append(
                "result=completed_with_confirmed_bundles requires at least one validated confirmed bundle, "
                f"but found {validated_count}."
            )
        if partial_count > 0:
            errors.append(
                f"Cannot finalize: {partial_count} partial confirmed bundle(s) exist. "
                "Complete or remove them before finalizing."
            )
        if failed_count > 0:
            errors.append(
                f"Cannot finalize: {failed_count} bundle(s) failed validation. "
                "Fix or remove them before finalizing."
            )
        if validated_count > 0 and partial_count == 0 and failed_count == 0:
            variant_summary = {
                "ok": inspected_state.get("formal_variant_analysis_status") == "completed",
                "errors": inspected_state.get("errors", []),
                "variant_dir": inspected_state.get("variant_dir"),
                "seeds": inspected_state.get("seeds"),
                "variant_candidates": inspected_state.get("variant_candidates"),
                "seed_validation": inspected_state.get("seed_validation", {}),
                "candidate_validation": inspected_state.get("candidate_validation", {}),
            }
            if not variant_summary.get("ok"):
                for error in variant_summary.get("errors", []):
                    errors.append(f"Seeded variant discovery gate: {error}")
            write_event(
                workspace,
                "seeded_variant_discovery_outcome",
                "finalization",
                "running",
                "ok" if variant_summary.get("ok") else "warning",
                (
                    "Seeded variant discovery artifacts checked: "
                    f"ok={str(bool(variant_summary.get('ok'))).lower()}."
                ),
                variant_summary=variant_summary,
            )
    elif result == "completed_no_confirmed_findings":
        if validated_count > 0:
            errors.append(
                f"result=completed_no_confirmed_findings but {validated_count} validated bundle(s) exist. "
                "Use completed_with_confirmed_bundles instead."
            )
        if partial_count > 0:
            errors.append(
                f"Cannot finalize with no-confirmed-findings: {partial_count} partial confirmed bundle(s) exist. "
                "Complete or remove them before finalizing."
            )
        if failed_count > 0:
            errors.append(
                f"Cannot finalize with no-confirmed-findings: {failed_count} bundle(s) failed validation. "
                "Fix or remove them before finalizing."
            )
        blocked_summary = detect_blocked_verification(workspace)
        if blocked_summary.get("blocked"):
            resume_step = str(blocked_summary.get("resume_step") or "")
            evidence = blocked_summary.get("findings") or []
            first_evidence = ""
            if evidence and isinstance(evidence[0], dict):
                first_evidence = (
                    f"{evidence[0].get('source')}:{evidence[0].get('line')} "
                    f"{evidence[0].get('excerpt')}"
                )
            errors.append(
                "Blocked Docker/runtime verification prevents completed_no_confirmed_findings. "
                "This is blocked_verification, not a terminal no-confirmed state. "
                f"Resume step: {resume_step or 'resolve the Docker/runtime blocker and rerun Docker verification.'} "
                f"Evidence: {first_evidence or 'see candidate-findings.md, unverified-leads.md, or attack-surface.md.'}"
            )

    # --- Step 3: Audit disposition ledger ---
    if not blocked_summary:
        blocked_summary = detect_blocked_verification(workspace)
    disposition_ledger = synthesize_disposition_ledger(
        workspace,
        blocked_summary=blocked_summary,
    )
    write_disposition_ledger(workspace, disposition_ledger)
    disposition_validation = validate_disposition_ledger(
        workspace,
        result=result,
        ledger=disposition_ledger,
        bundle_summary=bundle_summary,
        language=language,
    )
    disposition_summary = disposition_validation.get("summary", {})
    if not disposition_validation.get("ok"):
        for error in disposition_validation.get("errors", []):
            errors.append(f"{LEDGER_FILENAME}: {error}")

    write_event(
        workspace,
        "audit_disposition_outcome",
        "finalization",
        "running",
        "ok" if disposition_validation.get("ok") else "warning",
        (
            f"Audit disposition ledger: items={disposition_summary.get('item_count', 0)}, "
            f"unresolved={disposition_summary.get('unresolved_count', 0)}."
        ),
        ledger=LEDGER_FILENAME,
        validation_ok=bool(disposition_validation.get("ok")),
        disposition_summary=disposition_summary,
    )

    # --- Step 4: Docker strict cleanliness ---
    docker_status = run_docker_verify_clean(workspace, strict=True)
    docker_clean = docker_status.get("clean", False)
    if not docker_clean:
        docker_error = docker_status.get("error", "")
        if docker_error:
            errors.append(f"Docker cleanliness check failed: {docker_error}")
        else:
            errors.append(
                "Docker strict cleanliness check failed. "
                "Run manage-docker-resources.py --cleanup-created --apply and --verify-clean --strict."
            )

    # --- Step 5: Decide pass/fail ---
    if errors:
        error_text = "; ".join(errors)
        if blocked_summary.get("blocked"):
            blocker = "blocked_verification"
            resume_step = str(blocked_summary.get("resume_step") or "Resolve the Docker/runtime blocker and rerun Docker verification.")
            write_event(
                workspace,
                "finalization_failed",
                "verification",
                "blocked",
                "failed",
                f"Completion gate failed: {error_text}",
                blocker=blocker,
                resume_step=resume_step,
                errors=errors,
                expected_result=result,
                blocked_verification=blocked_summary,
            )
        else:
            write_event(workspace, "finalization_failed", "finalization", "running",
                        "failed", f"Completion gate failed: {error_text}",
                        errors=errors, expected_result=result)
        print(f"FINALIZATION FAILED: {error_text}", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        if blocked_summary.get("blocked"):
            print("  - blocked_verification resume_step: " + str(blocked_summary.get("resume_step") or ""), file=sys.stderr)
        refresh_handoff(workspace, repo_root)
        return 1

    # --- Step 6: Update stage-status.json to completed ---
    write_event(workspace, "finalization_succeeded", "completed", "completed",
                "ok", f"Audit finalized as {result}.",
                result=result, validated_bundles=validated_count,
                docker_clean=docker_clean,
                docker_skipped=docker_status.get("skipped", False))

    docker_strict = bool(docker_status.get("strict", True))
    summary_path = ensure_workspace_summary(
        workspace,
        result=result,
        validated_count=validated_count,
        docker_clean=bool(docker_clean),
        docker_strict=docker_strict,
        language=language,
    )

    # --- Step 7: Refresh and validate handoff-summary.md ---
    refreshed = refresh_handoff(workspace, repo_root)
    refreshed_state = inspect_workspace_state(
        workspace,
        confirmed_dir=confirmed_dir,
        language=language,
    )
    consistency = validate_handoff_status_consistency(
        workspace,
        state=refreshed_state,
        language=language,
    )
    if not refreshed or not consistency.get("ok"):
        consistency_errors = consistency.get("errors") or []
        error_text = (
            "handoff-summary.md refresh failed"
            if not refreshed
            else "; ".join(str(error) for error in consistency_errors)
        )
        write_event(
            workspace,
            "finalization_failed",
            "finalization",
            "running",
            "failed",
            f"Completion gate failed after handoff consistency check: {error_text}",
            errors=[error_text],
            expected_result=result,
        )
        print(f"FINALIZATION FAILED: {error_text}", file=sys.stderr)
        return 1

    # --- Output ---
    print(f"result={result}")
    print(f"validated_bundles={validated_count}")
    print(f"docker_clean={str(docker_clean).lower()}")
    print(f"summary={summary_path.relative_to(workspace).as_posix()}")
    print(f"stage=completed")
    print(f"FINALIZATION PASSED: {workspace}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
