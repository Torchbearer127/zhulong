#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from validate_candidate import (
    ValidationError as CandidateValidationError,
    load_candidate,
    validate_candidate,
)
from candidate_identity import file_sha256
from validate_target_contract import (
    ValidationError as TargetValidationError,
    load_contract,
    validate_target,
)
from validate_verifier_verdict import (
    ValidationError as VerdictValidationError,
    cross_check_candidate,
    load_verdict,
    validate_verdict,
)


SUPPORTED_ORACLES = {
    "exit_code_zero",
    "http_response_contains",
    "log_pattern",
    "callback_observed",
    "file_marker_created",
    "process_crash",
    "manual_blocked",
}
VERDICTS = {"blocked", "false_positive", "unverified", "confirmed_in_docker"}
RUNTIME_TYPES = {"docker", "docker-compose", "manual-blocked"}
DEFAULT_RUN_ID = "verifier-run-001"


class VerifierError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a Zhulong target/candidate pair and write an independent "
            "verifier-verdict.json. R1 defaults to no host-side execution."
        )
    )
    parser.add_argument("--target-config", required=True, help="Path to zhulong-target.yaml")
    parser.add_argument("--candidate", required=True, help="Path to candidate.json")
    parser.add_argument("--workspace", required=True, help="Zhulong audit workspace directory")
    parser.add_argument("--out", help="Output verifier-verdict.json path. Defaults under <workspace>/verifier/<candidate_id>.")
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID, help=f"Verifier run id. Default: {DEFAULT_RUN_ID}")
    parser.add_argument("--dry-run", action="store_true", help="Do not execute Docker or PoC commands.")
    parser.add_argument("--no-execute", action="store_true", help="Do not execute Docker or PoC commands.")
    parser.add_argument("--allow-execute", action="store_true", help="Allow Docker-only execution when implemented.")
    parser.add_argument(
        "--dry-run-result",
        choices=sorted(VERDICTS),
        help=(
            "Fixture-only oracle simulation result for selftests. "
            "confirmed_in_docker is marked as simulated and must not be used as real evidence."
        ),
    )
    return parser.parse_args()


def safe_run_id(value: str) -> str:
    if not re.fullmatch(r"[0-9A-Za-z._-]+", value):
        raise VerifierError("--run-id may only contain letters, numbers, dot, underscore, and dash")
    return value


def require_under(path: Path, root: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise VerifierError(f"{label} must stay under the workspace") from exc
    return resolved


def workspace_rel(path: Path, workspace: Path) -> str:
    return path.resolve().relative_to(workspace.resolve()).as_posix()


def load_candidate_identity(candidate_path: Path) -> dict[str, Any]:
    try:
        data = load_candidate(candidate_path)
    except CandidateValidationError as exc:
        raise VerifierError(f"invalid candidate: {exc}") from exc
    candidate_id = data.get("candidate_id")
    target_ref = data.get("target_ref")
    if not isinstance(candidate_id, str) or not re.fullmatch(r"CAND-[0-9A-Za-z._-]+", candidate_id):
        raise VerifierError("invalid candidate: missing stable candidate_id")
    if not isinstance(target_ref, dict):
        raise VerifierError("invalid candidate: missing target_ref")
    if not isinstance(target_ref.get("target_config"), str) or not isinstance(target_ref.get("tested_ref"), str):
        raise VerifierError("invalid candidate: target_ref must include target_config and tested_ref")
    return data


def target_config_aliases(target_path: Path, workspace: Path) -> set[str]:
    resolved = target_path.expanduser().resolve()
    aliases = {target_path.as_posix(), resolved.as_posix(), resolved.name}
    for base in (Path.cwd().resolve(), workspace.resolve(), workspace.resolve().parent):
        try:
            aliases.add(resolved.relative_to(base).as_posix())
        except ValueError:
            pass
    return aliases


def cross_check_target_ref(target_path: Path, workspace: Path, target_doc: dict[str, Any], candidate: dict[str, Any]) -> str | None:
    target_ref = candidate["target_ref"]
    candidate_target_config = str(target_ref["target_config"])
    if candidate_target_config not in target_config_aliases(target_path, workspace):
        return "candidate target_ref.target_config does not match provided target config"
    tested_ref = target_doc.get("target", {}).get("tested_ref")
    if target_ref.get("tested_ref") != tested_ref:
        return "candidate target_ref.tested_ref does not match target tested_ref"
    return None


def target_runtime_type(target_doc: dict[str, Any] | None) -> str:
    runtime_type = ""
    if isinstance(target_doc, dict):
        runtime = target_doc.get("runtime")
        if isinstance(runtime, dict):
            runtime_type = str(runtime.get("type") or "")
    return runtime_type if runtime_type in RUNTIME_TYPES else "manual-blocked"


def egress_policy(target_doc: dict[str, Any] | None) -> str:
    if isinstance(target_doc, dict):
        verify = target_doc.get("verify")
        if isinstance(verify, dict) and isinstance(verify.get("allowed_network"), str) and verify["allowed_network"].strip():
            return verify["allowed_network"]
    return "not-executed"


def expected_oracle(candidate: dict[str, Any]) -> str:
    oracle = candidate.get("poc", {}).get("expected_oracle", {}).get("type")
    return str(oracle or "")


def negative_checks(reason: str, *, target_valid: bool, candidate_valid: bool, target_ref_matches: bool) -> list[dict[str, Any]]:
    checks = [
        {"check": "target contract validated", "passed": target_valid},
        {"check": "candidate contract validated", "passed": candidate_valid},
        {"check": "candidate target_ref matches provided target", "passed": target_ref_matches},
        {"check": "finder notes ignored as confirmation evidence", "passed": True},
        {"check": "agent transcripts ignored as confirmation evidence", "passed": True},
        {"check": "host-side PoC execution disabled", "passed": True},
    ]
    for check in checks:
        if not check["passed"]:
            check["reason"] = reason
    return checks


def base_verdict(
    *,
    candidate: dict[str, Any],
    target_doc: dict[str, Any] | None,
    verdict: str,
    oracle_type: str,
    oracle_success: bool,
    reason: str,
    commands: list[dict[str, Any]] | None = None,
    artifacts: list[str] | None = None,
    target_valid: bool = True,
    candidate_valid: bool = True,
    target_ref_matches: bool = True,
    evidence_level: str | None = None,
    attacker_entrypoint: dict[str, Any] | None = None,
    replay_material: dict[str, Any] | None = None,
    candidate_path: Path | None = None,
) -> dict[str, Any]:
    runtime_type = target_runtime_type(target_doc)
    if evidence_level is None:
        evidence_level = "confirmed_in_docker" if verdict == "confirmed_in_docker" else "blocked_entrypoint_verification"
    doc: dict[str, Any] = {
        "schema_version": 1,
        "candidate_id": candidate["candidate_id"],
        "verdict": verdict,
        "verification_status": verdict,
        "evidence_level": evidence_level,
        "target_ref": candidate["target_ref"],
        "environment": {
            "fresh_container": verdict == "confirmed_in_docker",
            "runtime_type": runtime_type,
            "host_network": False,
            "privileged": False,
            "docker_socket_mounted": False,
            "credential_paths_mounted": False,
            "egress_policy": egress_policy(target_doc),
        },
        "commands": commands or [],
        "oracle_result": {
            "type": oracle_type or "unknown",
            "success": oracle_success,
            "summary": reason,
        },
        "disposition_recommendation": verdict,
        "negative_checks": negative_checks(
            reason,
            target_valid=target_valid,
            candidate_valid=candidate_valid,
            target_ref_matches=target_ref_matches,
        ),
        "artifacts": artifacts or [],
        "reason": reason,
        "verified_at": utc_now(),
    }
    if attacker_entrypoint is not None:
        doc["attacker_entrypoint"] = attacker_entrypoint
    if replay_material is not None:
        doc["replay_material"] = replay_material
    try:
        checked = validate_candidate(candidate)
    except CandidateValidationError:
        checked = {"protocol_mode": "invalid"}
    if checked.get("protocol_mode") == "r2":
        if candidate_path is None:
            raise VerifierError("R2 candidate verdict construction requires the exact candidate path")
        doc["candidate_binding"] = {
            "protocol_mode": "r2",
            "candidate_sha256": file_sha256(candidate_path),
            "fingerprint": checked["fingerprint"],
        }
    return doc


def write_log(run_dir: Path, message: str) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / "verifier.log"
    log_path.write_text(message.rstrip() + "\n", encoding="utf-8")
    return log_path


def write_fixture_artifact(run_dir: Path, verdict: str, oracle_type: str) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    artifact = run_dir / "fixture-oracle.json"
    artifact.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "mode": "dry-run-fixture",
                "simulated_verdict": verdict,
                "oracle_type": oracle_type,
                "real_docker_execution": False,
                "usable_for_confirmed_bundle": False,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return artifact


def validate_output(verdict_path: Path, candidate_path: Path) -> None:
    try:
        verdict_doc = load_verdict(verdict_path)
        validate_verdict(verdict_doc)
        cross_check_candidate(candidate_path, verdict_doc)
    except VerdictValidationError as exc:
        raise VerifierError(f"generated verifier verdict failed validation: {exc}") from exc


def write_and_validate(verdict: dict[str, Any], out_path: Path, candidate_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(verdict, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    validate_output(out_path, candidate_path)


def build_verdict(
    *,
    args: argparse.Namespace,
    workspace: Path,
    run_dir: Path,
    target_doc: dict[str, Any],
    candidate: dict[str, Any],
    candidate_path: Path,
) -> dict[str, Any]:
    oracle_type = expected_oracle(candidate)
    runtime_type = target_runtime_type(target_doc)

    if runtime_type == "manual-blocked":
        reason = "target runtime is manual-blocked and non-confirmable by automatic verifier"
        write_log(run_dir, reason)
        return base_verdict(candidate=candidate, target_doc=target_doc, verdict="blocked", oracle_type=oracle_type, oracle_success=False, reason=reason, candidate_path=candidate_path)

    if oracle_type not in SUPPORTED_ORACLES:
        reason = f"unsupported oracle type: {oracle_type}"
        write_log(run_dir, reason)
        return base_verdict(candidate=candidate, target_doc=target_doc, verdict="blocked", oracle_type=oracle_type, oracle_success=False, reason=reason, candidate_path=candidate_path)

    if oracle_type == "manual_blocked":
        reason = "manual_blocked oracle is non-confirmable by automatic verifier"
        write_log(run_dir, reason)
        return base_verdict(candidate=candidate, target_doc=target_doc, verdict="blocked", oracle_type=oracle_type, oracle_success=False, reason=reason, candidate_path=candidate_path)

    if args.dry_run_result:
        fixture_artifact = write_fixture_artifact(run_dir, args.dry_run_result, oracle_type)
        log_path = write_log(run_dir, f"dry-run fixture result selected: {args.dry_run_result}")
        if args.dry_run_result == "confirmed_in_docker":
            reason = (
                "SIMULATED dry-run fixture reached a code-level oracle only; no attacker entrypoint, "
                "Docker, PoC, replay, or network execution occurred, so this is blocked entrypoint verification"
            )
            return base_verdict(
                candidate=candidate,
                target_doc=target_doc,
                verdict="blocked",
                oracle_type=oracle_type,
                oracle_success=False,
                reason=reason,
                artifacts=[workspace_rel(log_path, workspace), workspace_rel(fixture_artifact, workspace)],
                evidence_level="blocked_entrypoint_verification",
                candidate_path=candidate_path,
            )
        reason = f"dry-run fixture produced {args.dry_run_result}; no Docker, PoC, replay, or network execution occurred"
        return base_verdict(
            candidate=candidate,
            target_doc=target_doc,
            verdict=args.dry_run_result,
            oracle_type=oracle_type,
            oracle_success=False,
            reason=reason,
            artifacts=[workspace_rel(log_path, workspace), workspace_rel(fixture_artifact, workspace)]
            if args.dry_run_result != "blocked"
            else [],
            candidate_path=candidate_path,
        )

    if args.allow_execute:
        reason = "Docker execution is not implemented in R1 verifier; no host-side PoC fallback was attempted"
        write_log(run_dir, reason)
        return base_verdict(candidate=candidate, target_doc=target_doc, verdict="blocked", oracle_type=oracle_type, oracle_success=False, reason=reason, candidate_path=candidate_path)

    reason = "execution not requested; R1 verifier defaulted to dry-run/no-execute and did not prove the oracle"
    write_log(run_dir, reason)
    return base_verdict(candidate=candidate, target_doc=target_doc, verdict="unverified", oracle_type=oracle_type, oracle_success=False, reason=reason, candidate_path=candidate_path)


def main() -> int:
    args = parse_args()
    target_path = Path(args.target_config)
    candidate_path = Path(args.candidate)
    workspace = Path(args.workspace).expanduser().resolve()
    run_id = safe_run_id(args.run_id)

    try:
        candidate = load_candidate_identity(candidate_path)
        candidate_id = candidate["candidate_id"]
        verifier_root = require_under(workspace / "verifier" / candidate_id, workspace, "verifier directory")
        run_dir = require_under(verifier_root / "runs" / run_id, workspace, "verifier run directory")
        out_path = Path(args.out).expanduser() if args.out else verifier_root / "verifier-verdict.json"
        out_path = require_under(out_path if out_path.is_absolute() else Path.cwd() / out_path, workspace, "verifier verdict output")

        try:
            target_doc = load_contract(target_path)
            validate_target(target_doc)
        except TargetValidationError as exc:
            reason = f"invalid target: {exc}"
            write_log(run_dir, reason)
            verdict = base_verdict(
                candidate=candidate,
                target_doc=None,
                verdict="blocked",
                oracle_type=expected_oracle(candidate),
                oracle_success=False,
                reason=reason,
                target_valid=False,
                candidate_path=candidate_path,
            )
            write_and_validate(verdict, out_path, candidate_path)
            print(f"verdict=blocked")
            print(f"verifier_verdict={out_path}")
            return 1

        try:
            validate_candidate(candidate)
        except CandidateValidationError as exc:
            reason = f"invalid candidate: {exc}"
            write_log(run_dir, reason)
            verdict = base_verdict(
                candidate=candidate,
                target_doc=target_doc,
                verdict="blocked",
                oracle_type=expected_oracle(candidate),
                oracle_success=False,
                reason=reason,
                candidate_valid=False,
                candidate_path=candidate_path,
            )
            write_and_validate(verdict, out_path, candidate_path)
            print(f"verdict=blocked")
            print(f"verifier_verdict={out_path}")
            return 1

        mismatch = cross_check_target_ref(target_path, workspace, target_doc, candidate)
        if mismatch:
            write_log(run_dir, mismatch)
            verdict = base_verdict(
                candidate=candidate,
                target_doc=target_doc,
                verdict="blocked",
                oracle_type=expected_oracle(candidate),
                oracle_success=False,
                reason=mismatch,
                target_ref_matches=False,
                candidate_path=candidate_path,
            )
            write_and_validate(verdict, out_path, candidate_path)
            print("verdict=blocked")
            print(f"verifier_verdict={out_path}")
            return 1

        verdict = build_verdict(args=args, workspace=workspace, run_dir=run_dir, target_doc=target_doc, candidate=candidate, candidate_path=candidate_path)
        write_and_validate(verdict, out_path, candidate_path)
    except VerifierError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"verdict={verdict['verdict']}")
    print(f"verifier_verdict={out_path}")
    return 0 if verdict["verdict"] == "confirmed_in_docker" else 1


if __name__ == "__main__":
    raise SystemExit(main())
