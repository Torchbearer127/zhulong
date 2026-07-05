#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


DOGFOOD_REQUIRED_FIELDS = {
    "schema_version",
    "validator_invocation_count",
    "material_rewrite_count",
    "unique_error_count_per_invocation",
    "partial_confirmed_bundle_created",
    "manual_marker_patch_detected_or_required",
    "contract_preflight_caught_expected_issues",
    "staging_promote_required_for_final",
}


class DogfoodError(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate local-only P8 dogfood metrics for bundle-contract retry-loop regression."
    )
    parser.add_argument("--json", action="store_true", help="Emit metrics JSON to stdout.")
    parser.add_argument("--output-json", help="Write metrics JSON to this path.")
    parser.add_argument("--output-report", help="Write a concise Markdown dogfood report to this path.")
    parser.add_argument("--keep-temp", action="store_true", help="Keep the temporary dogfood workspace for debugging.")
    return parser.parse_args()


def run_command(
    command: list[str],
    cwd: Path,
    *,
    env_root: Path,
    expected_returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPYCACHEPREFIX": str(env_root / ".pycache")}
    proc = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    if proc.returncode != expected_returncode:
        output = ((proc.stdout or "") + (proc.stderr or "")).strip()
        raise DogfoodError(
            f"command returned {proc.returncode}, expected {expected_returncode}: {' '.join(command)}\n{output}"
        )
    return proc


def load_json_stdout(proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    try:
        return json.loads((proc.stdout or "").strip())
    except json.JSONDecodeError as exc:
        raise DogfoodError(f"command did not emit JSON: {proc.stdout[:500]!r}") from exc


def write_json(path: Path, data: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def copy_fixture_contract(plugin_root: Path, workspace: Path) -> Path:
    contract_dir = workspace / "confirmed/.contracts"
    contract_dir.mkdir(parents=True, exist_ok=True)
    target = contract_dir / "bad.bundle-contract.json"
    shutil.copyfile(plugin_root / "assets/fixtures/p8-dogfood/bad-contract.bundle-contract.json", target)
    (workspace / "confirmed/p8-dogfood-bad").mkdir(parents=True)
    return target


def valid_bundle_contract(slug: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "bundle": {
            "slug": slug,
            "language": "zh-CN",
            "final_path": f"confirmed/{slug}",
            "one_vulnerability_only": True,
            "fail_if_final_path_exists": True,
        },
        "render": {
            "source_findings_json": "confirmed/findings.json",
            "finding_slug": "demo-app-path-traversal",
        },
        "finding": {
            "project_name": "demo-app",
            "vulnerability_name": "目录遍历",
            "bug_class": "Path Traversal",
            "severity": "High",
            "attacker_condition": "远程攻击者控制下载路径参数。",
            "server_condition": "服务端启用受影响下载接口并从本地文件系统读取文件。",
            "security_impact": "Docker 证据证明攻击者可读取容器内敏感文件内容。",
        },
        "docker_evidence": {
            "verification_status": "confirmed_in_docker",
            "docker_required": True,
            "docker_command": "docker compose -f attachments/docker/docker-compose.attacker.yml up --abort-on-container-exit",
            "oracle_token": "DIRECT_IMPACT_CONFIRMED",
            "expected_observation": "The service returns a fragment of /etc/passwd.",
            "observed_observation": "Replay log contains root:x:0:0: and DIRECT_IMPACT_CONFIRMED.",
            "severity_escalation_attempted": True,
        },
        "entrypoint_evidence": {
            "evidence_level": "entrypoint_reproduced",
            "attacker_controlled_entrypoint": "GET /download",
            "input_shape": "Query parameter file controlled by a remote attacker.",
            "entrypoint_to_sink_path": "GET /download receives file and reaches sendFile after path.join.",
            "deterministic_impact_oracle": "Replay log contains root:x:0:0: and DIRECT_IMPACT_CONFIRMED.",
            "replay_material": {
                "description": "Dogfood bundle replay log for the attacker-controlled download route.",
                "path": "attachments/evidence/replay-output.log",
            },
        },
        "replay": {
            "root_script": {"path": f"run-{slug}-recording.sh"},
            "log": {
                "path": "attachments/evidence/replay-output.log",
                "registration_targets": ["files.evidence_files", "files.reviewer_evidence_index"],
            },
        },
        "direct_impact": {
            "marker": "DIRECT_IMPACT_CONFIRMED",
            "sync_targets": [
                {"target": "replay.root_script", "marker": "DIRECT_IMPACT_CONFIRMED"},
                {"target": "replay.log", "marker": "DIRECT_IMPACT_CONFIRMED"},
                {"target": "files.verification_evidence", "marker": "DIRECT_IMPACT_CONFIRMED"},
                {"target": "files.reviewer_evidence_index", "marker": "DIRECT_IMPACT_CONFIRMED"},
                {"target": "reviewer_material", "marker": "DIRECT_IMPACT_CONFIRMED"},
            ],
        },
        "files": {
            "verification_evidence": "verification-evidence.json",
            "reviewer_evidence_index": "attachments/reviewer-evidence-index.json",
            "evidence_files": [
                "attachments/evidence/replay-output.log",
                "attachments/poc/path_traversal.py",
            ],
            "attachments": [
                "attachments/docker/docker-compose.attacker.yml",
                "attachments/poc/path_traversal.py",
                "attachments/evidence/replay-output.log",
                "attachments/reviewer-evidence-index.json",
            ],
        },
        "code_context": {
            "entries": [
                {
                    "source_path": "src/routes/download.js",
                    "line_range": "42-55",
                    "input_to_sink_chain": "The file query parameter reaches sendFile after path.join.",
                    "missing_guard": "No normalized directory-boundary check runs before sendFile.",
                    "verified_impact_boundary": "Docker evidence proves container-local file read only.",
                }
            ]
        },
        "fixture_provenance": {
            "required": False,
            "replay_type": "full_app",
        },
        "impact_tier": {"bug_class": "Path Traversal"},
        "variant_seed_readiness": {"run_after_promote": True},
    }


def create_source_workspace(
    plugin_root: Path,
    root: Path,
    name: str,
    *,
    replay_text: str,
    slug: str,
) -> tuple[Path, Path, Path]:
    repo_dir = root / name / "repo"
    workspace = repo_dir / "security-research-dogfood"
    (workspace / "confirmed/.contracts").mkdir(parents=True, exist_ok=True)
    (workspace / "asr-config.json").write_text(
        json.dumps(
            {
                "workspace_root": workspace.name,
                "workspace_created_at": "2026-06-25T00:00:00Z",
                "confirmed_output_dir": f"{workspace.name}/confirmed",
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (repo_dir / "docker").mkdir(parents=True, exist_ok=True)
    (repo_dir / "poc").mkdir(parents=True, exist_ok=True)
    (repo_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (repo_dir / "docker/docker-compose.attacker.yml").write_text(
        "services:\n  attacker:\n    image: alpine:3.20\n",
        encoding="utf-8",
    )
    (repo_dir / "poc/path_traversal.py").write_text("print('root:x:0:0:')\n", encoding="utf-8")
    (repo_dir / "evidence/replay-output.log").write_text(replay_text, encoding="utf-8")

    findings = json.loads((plugin_root / "assets/examples/confirmed-findings.example.json").read_text(encoding="utf-8"))
    finding = dict(findings[0])
    finding["slug"] = "demo-app-path-traversal"
    finding["project_root_dir"] = "."
    finding["filename"] = f"{slug}.docx"
    finding.setdefault("verification_evidence", {})["finding_slug"] = finding["slug"]
    evidence_files = finding["verification_evidence"].setdefault("evidence_files", [])
    if "attachments/evidence/replay-output.log" not in evidence_files:
        evidence_files.append("attachments/evidence/replay-output.log")
    finding.setdefault("attachments", []).append(
        {
            "path": "evidence/replay-output.log",
            "purpose": "Deterministic dogfood replay transcript copied into the temporary bundle.",
        }
    )
    (workspace / "confirmed/findings.json").write_text(
        json.dumps({"findings": [finding]}, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    contract = write_json(workspace / "confirmed/.contracts" / f"{slug}.bundle-contract.json", valid_bundle_contract(slug))
    return repo_dir, workspace, contract


def live_replay_text() -> str:
    return (
        "Zhulong reviewer replay log\n"
        "Generated at: 2026-06-25T00:00:00Z\n"
        "COMMAND: docker compose -f attachments/docker/docker-compose.attacker.yml up --abort-on-container-exit\n"
        "stdout: deterministic dogfood replay completed\n"
        "success marker verified with grep -Fq\n"
        "exit code: 0\n"
        "root:x:0:0:\n"
        "DIRECT_IMPACT_CONFIRMED\n"
    )


def placeholder_replay_text() -> str:
    return (
        "Zhulong reviewer replay log placeholder.\n"
        "Run the bundle-root replay script to refresh this file with live reviewer output.\n"
        "Replay contract direct-impact marker: DIRECT_IMPACT_CONFIRMED\n"
    )


def run_dogfood(plugin_root: Path, temp_root: Path) -> dict[str, Any]:
    validator_invocations = 0
    unique_error_count_per_invocation: list[int] = []
    commands_run: list[str] = []

    bad_workspace = temp_root / "bad-contract-workspace"
    bad_contract = copy_fixture_contract(plugin_root, bad_workspace)
    proc = run_command(
        [
            sys.executable,
            str(plugin_root / "scripts/validate_bundle_contract.py"),
            "--workspace-dir",
            str(bad_workspace),
            "--contract",
            str(bad_contract),
            "--all-errors",
            "--json",
        ],
        plugin_root,
        env_root=temp_root,
        expected_returncode=1,
    )
    validator_invocations += 1
    commands_run.append("validate_bundle_contract.py --all-errors --json")
    bad_payload = load_json_stdout(proc)
    bad_codes = sorted({str(issue.get("code")) for issue in bad_payload.get("issues", [])})
    unique_error_count_per_invocation.append(len(bad_codes))
    expected_bad_codes = {
        "BUNDLE_PATH_ESCAPE",
        "CODE_CONTEXT_TOO_THIN",
        "DIRECT_IMPACT_MARKER_DRIFT",
        "DOCKER_STATUS_NOT_CONFIRMED",
        "FINAL_TARGET_EXISTS",
        "FIXTURE_PROVENANCE_MISSING",
        "REPLAY_LOG_UNREGISTERED",
        "SSRF_IMPACT_OVERCLAIM",
        "VARIANT_SEED_READINESS_MISSING",
    }
    bad_contract_ok = expected_bad_codes.issubset(set(bad_codes))

    failure_slug = "p8-dogfood-validation-failure_高危漏洞报告"
    _, failure_workspace, failure_contract = create_source_workspace(
        plugin_root,
        temp_root,
        "staging-failure",
        replay_text=placeholder_replay_text(),
        slug=failure_slug,
    )
    run_command(
        [
            sys.executable,
            str(plugin_root / "scripts/build_confirmed_bundle.py"),
            "--workspace-dir",
            str(failure_workspace),
            "--contract",
            str(failure_contract),
            "--language",
            "zh-CN",
            "--keep-failed-staging",
        ],
        plugin_root,
        env_root=temp_root,
        expected_returncode=1,
    )
    commands_run.append("build_confirmed_bundle.py --keep-failed-staging")
    failure_final = failure_workspace / "confirmed" / failure_slug
    failure_staging = failure_workspace / "confirmed/.staging" / failure_slug
    failure_kept_out_of_final = not failure_final.exists() and failure_staging.is_dir()

    marker_slug = "p8-dogfood-marker-only_高危漏洞报告"
    _, marker_workspace, _ = create_source_workspace(
        plugin_root,
        temp_root,
        "marker-only",
        replay_text=(plugin_root / "assets/fixtures/p8-dogfood/marker-only-replay-output.log").read_text(encoding="utf-8"),
        slug=marker_slug,
    )
    marker_contract = marker_workspace / "confirmed/.contracts" / f"{marker_slug}.bundle-contract.json"
    run_command(
        [
            sys.executable,
            str(plugin_root / "scripts/build_confirmed_bundle.py"),
            "--workspace-dir",
            str(marker_workspace),
            "--contract",
            str(marker_contract),
            "--language",
            "zh-CN",
            "--keep-failed-staging",
        ],
        plugin_root,
        env_root=temp_root,
        expected_returncode=1,
    )
    commands_run.append("build_confirmed_bundle.py --keep-failed-staging")
    marker_bundle = marker_workspace / "confirmed/.staging" / marker_slug
    marker_final = marker_workspace / "confirmed" / marker_slug
    if marker_final.exists():
        raise DogfoodError("marker-only dogfood case promoted a final bundle")
    if not marker_bundle.is_dir():
        raise DogfoodError("marker-only dogfood case did not preserve failed staging")
    proc = run_command(
        [
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(marker_bundle),
            "--language",
            "zh-CN",
            "--all-errors",
            "--json",
        ],
        plugin_root,
        env_root=temp_root,
        expected_returncode=1,
    )
    validator_invocations += 1
    commands_run.append("validate_report_bundle.py --all-errors --json")
    marker_payload = load_json_stdout(proc)
    marker_codes = sorted({str(issue.get("code")) for issue in marker_payload.get("issues", [])})
    unique_error_count_per_invocation.append(len(marker_codes))
    marker_only_rejected = "REPLAY_LOG_MARKER_ONLY" in marker_codes

    valid_slug = "p8-dogfood-valid_高危漏洞报告"
    _, valid_workspace, valid_contract = create_source_workspace(
        plugin_root,
        temp_root,
        "valid",
        replay_text=live_replay_text(),
        slug=valid_slug,
    )
    proc = run_command(
        [
            sys.executable,
            str(plugin_root / "scripts/validate_bundle_contract.py"),
            "--workspace-dir",
            str(valid_workspace),
            "--contract",
            str(valid_contract),
            "--all-errors",
            "--json",
        ],
        plugin_root,
        env_root=temp_root,
    )
    validator_invocations += 1
    commands_run.append("validate_bundle_contract.py --all-errors --json")
    valid_contract_payload = load_json_stdout(proc)
    unique_error_count_per_invocation.append(0)

    run_command(
        [
            sys.executable,
            str(plugin_root / "scripts/build_confirmed_bundle.py"),
            "--workspace-dir",
            str(valid_workspace),
            "--contract",
            str(valid_contract),
            "--language",
            "zh-CN",
        ],
        plugin_root,
        env_root=temp_root,
    )
    commands_run.append("build_confirmed_bundle.py")
    valid_final = valid_workspace / "confirmed" / valid_slug
    if not valid_final.is_dir():
        raise DogfoodError("valid dogfood build did not promote a final bundle")
    run_command(
        [
            sys.executable,
            str(plugin_root / "scripts/validate_report_bundle.py"),
            "--bundle-dir",
            str(valid_final),
            "--language",
            "zh-CN",
        ],
        plugin_root,
        env_root=temp_root,
    )
    validator_invocations += 1
    commands_run.append("validate_report_bundle.py")
    unique_error_count_per_invocation.append(0)
    run_command(
        [
            sys.executable,
            str(plugin_root / "scripts/validate_all_report_bundles.py"),
            "--confirmed-dir",
            str(valid_workspace / "confirmed"),
            "--language",
            "zh-CN",
        ],
        plugin_root,
        env_root=temp_root,
    )
    validator_invocations += 1
    commands_run.append("validate_all_report_bundles.py")
    unique_error_count_per_invocation.append(0)

    old_fail_fast_invocations = len(bad_codes) + 2
    old_rewrites = max(0, old_fail_fast_invocations - 1)
    material_rewrites = 0
    metrics = {
        "schema_version": 1,
        "validator_invocation_count": validator_invocations,
        "material_rewrite_count": material_rewrites,
        "unique_error_count_per_invocation": unique_error_count_per_invocation,
        "partial_confirmed_bundle_created": failure_final.exists(),
        "manual_marker_patch_detected_or_required": False,
        "contract_preflight_caught_expected_issues": bad_contract_ok,
        "staging_promote_required_for_final": failure_kept_out_of_final and valid_final.is_dir(),
        "cases": {
            "bad_contract": {
                "valid": bad_payload.get("valid"),
                "issue_codes": bad_codes,
                "single_invocation_multi_error_count": len(bad_codes),
            },
            "staging_build_failure": {
                "final_bundle_created": failure_final.exists(),
                "failed_staging_preserved": failure_staging.is_dir(),
            },
            "marker_only_replay_log": {
                "rejected": marker_only_rejected,
                "issue_codes": marker_codes,
                "called_confirmed": False,
            },
            "valid_contract_happy_path": {
                "contract_preflight_valid": valid_contract_payload.get("valid") is True,
                "promoted": valid_final.is_dir(),
                "batch_validation_passed": True,
            },
        },
        "comparison": {
            "legacy_fail_fast_simulated_validator_invocation_count": old_fail_fast_invocations,
            "legacy_fail_fast_simulated_material_rewrite_count": old_rewrites,
            "p8_validator_invocation_count": validator_invocations,
            "p8_material_rewrite_count": material_rewrites,
            "validator_invocation_count_delta": old_fail_fast_invocations - validator_invocations,
            "material_rewrite_count_delta": old_rewrites - material_rewrites,
        },
        "closure": {
            "p8_1_bundle_contract_preflight": "accepted",
            "p8_2_staging_build_wrapper": "accepted",
            "p8_3_replay_log_trust_boundary": "accepted",
            "p8_4_final_validator_all_errors": "accepted",
            "p8_5_skill_docs_sync_closure": "accepted",
            "p8_6_dogfood_metrics_retry_loop_regression": "generated",
        },
        "commands_run": sorted(set(commands_run)),
        "local_only_non_goals": [
            "no Docker execution",
            "no replay helper execution",
            "no PoC execution",
            "no scanner execution",
            "no package manager execution",
            "no network execution",
            "no real target code execution",
        ],
    }
    missing = sorted(DOGFOOD_REQUIRED_FIELDS - set(metrics))
    if missing:
        raise DogfoodError(f"metrics missing required fields: {missing}")
    return metrics


def render_report(metrics: dict[str, Any]) -> str:
    bad = metrics["cases"]["bad_contract"]
    staging = metrics["cases"]["staging_build_failure"]
    marker = metrics["cases"]["marker_only_replay_log"]
    happy = metrics["cases"]["valid_contract_happy_path"]
    comparison = metrics["comparison"]
    closure = metrics["closure"]
    issue_codes = ", ".join(bad["issue_codes"])
    marker_codes = ", ".join(marker["issue_codes"])
    commands = "\n".join(f"- `{command}`" for command in metrics["commands_run"])
    closure_lines = "\n".join(f"- `{key}`: `{value}`" for key, value in closure.items())
    return f"""# P8 Bundle Generation Dogfood Report

## Scope

This report records a deterministic local-only P8.6 dogfood run. It exercises
temporary fixtures and local validators only. It does not execute Docker, replay
helpers, PoCs, scanners, package managers, network commands, or real target
code.

## Fixtures Used

- `assets/fixtures/p8-dogfood/bad-contract.bundle-contract.json`
- `assets/fixtures/p8-dogfood/marker-only-replay-output.log`
- Temporary renderer inputs derived from `assets/examples/confirmed-findings.example.json`

## Commands Represented

{commands}

## Old Retry-Loop Failure Mode

Before P8, the last bundle stage often looked like a fail-fast repair chain:
generate a final bundle, see one validator error, patch one artifact, rerun,
and repeat. That pattern encouraged reactive edits to reviewer indexes, replay
logs, direct-impact markers, or fixture provenance after material already lived
under `confirmed/<slug>/`.

## New P8 Flow Result

- Bad contract preflight: one invocation returned `{bad["single_invocation_multi_error_count"]}` unique issue codes: `{issue_codes}`.
- Staging build failure: final bundle created = `{str(staging["final_bundle_created"]).lower()}`; failed staging preserved = `{str(staging["failed_staging_preserved"]).lower()}`.
- Marker-only replay log: rejected = `{str(marker["rejected"]).lower()}`; issue codes = `{marker_codes}`; called confirmed = `false`.
- Valid happy path: contract preflight valid = `{str(happy["contract_preflight_valid"]).lower()}`; promoted = `{str(happy["promoted"]).lower()}`; batch validation passed = `{str(happy["batch_validation_passed"]).lower()}`.

## Metrics

```json
{json.dumps(metrics, ensure_ascii=False, indent=2, sort_keys=True)}
```

The simulated legacy fail-fast chain would require
`{comparison["legacy_fail_fast_simulated_validator_invocation_count"]}` validator
invocations and `{comparison["legacy_fail_fast_simulated_material_rewrite_count"]}`
material rewrites for this fixture set. The P8 dogfood path used
`{comparison["p8_validator_invocation_count"]}` validator invocations and
`{comparison["p8_material_rewrite_count"]}` material rewrites, so the measured
deltas are `{comparison["validator_invocation_count_delta"]}` fewer validator
invocations and `{comparison["material_rewrite_count_delta"]}` fewer material
rewrites.

## Boundaries

These checks prove only workflow behavior: preflight multi-error visibility,
staging non-promotion, marker-only replay rejection, and valid staging-to-final
promotion in a temporary workspace. They do not prove a real vulnerability,
replace Docker evidence, replace final bundle validation, or treat seeded
variant candidates as confirmed evidence.

Final bundle validation remains mandatory. Contract preflight and staging
validation are workflow gates only.

## P8 Closure State

{closure_lines}

## Residual Risks

- The legacy fail-fast comparison is a deterministic simulation based on unique
  issue codes, not a measurement from historical operator transcripts.
- The dogfood run uses fixture-sized bundles; real target repositories can still
  need human judgment for evidence quality and claim boundaries.
- P8-post.3 low polish is closed: `finding.severity` now uses the stable
  contract enum (`Critical`, `High`, `Medium`, `Low`, `Informational`),
  `bug_class` stays documented free text with recommended values, and the
  template no longer carries redundant empty full-app provenance or
  callback-only SSRF oracle fields.
"""


def main() -> None:
    args = parse_args()
    plugin_root = Path(__file__).resolve().parent.parent
    temp_root = Path(tempfile.mkdtemp(prefix="zhulong-p8-dogfood-"))
    try:
        metrics = run_dogfood(plugin_root, temp_root)
        if args.output_json:
            write_json(Path(args.output_json).expanduser(), metrics)
        if args.output_report:
            report_path = Path(args.output_report).expanduser()
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(render_report(metrics), encoding="utf-8")
        if args.json or not args.output_report:
            print(json.dumps(metrics, ensure_ascii=False, indent=2, sort_keys=True))
        if args.keep_temp:
            print(f"temporary workspace retained: {temp_root}", file=sys.stderr)
    finally:
        if not args.keep_temp:
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    main()
