#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from validate_candidate import (
    ValidationError as CandidateValidationError,
    load_candidate,
    scan_security_text,
    validate_candidate,
)
from candidate_identity import IdentityError, file_sha256, normalize_entrypoint, safe_relative_path
from validate_target_contract import (
    ValidationError as TargetValidationError,
    load_contract,
    validate_target,
)
from audit_state_io import AuditStateError, read_workspace_snapshot
from docker_case_lifecycle import LifecycleError, validate_receipt
from evidence_io import (
    MAX_CAPTURE_BYTES,
    MAX_CONTROL_BYTES,
    SafeEvidenceError,
    assert_publish_target_safe,
    atomic_write_bytes,
    atomic_write_json,
    ensure_host_directory,
    safe_read_bytes,
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
MAX_SNAPSHOT_FILES = 10_000
MAX_SNAPSHOT_FILE_BYTES = 16 * 1024 * 1024
MAX_SNAPSHOT_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ORACLE_PATTERN_BYTES = 256
WRAPPER_TIMEOUT_SECONDS = 330


class VerifierError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a Zhulong target/candidate pair. R1 defaults to an "
            "unexecuted diagnostic; fresh R2 verdict publication is opt-in."
        )
    )
    parser.add_argument("--target-config", required=True, help="Path to zhulong-target.yaml")
    parser.add_argument("--candidate", required=True, help="Path to candidate.json")
    parser.add_argument("--workspace", required=True, help="Zhulong audit workspace directory")
    parser.add_argument("--out", help="Output JSON path. Non-execution defaults to a candidate-scoped diagnostic path.")
    parser.add_argument("--run-id", help=f"Verifier run id. Default: {DEFAULT_RUN_ID}")
    parser.add_argument("--dry-run", action="store_true", help="Do not execute Docker or PoC commands.")
    parser.add_argument("--no-execute", action="store_true", help="Do not execute Docker or PoC commands.")
    parser.add_argument("--allow-execute", action="store_true", help="Allow Docker-only execution when implemented.")
    parser.add_argument(
        "--repo-root",
        help="Fresh execution Git root (prefer an absolute path); target.repo_root must be '.' in this mode.",
    )
    parser.add_argument(
        "--execution-input",
        help="Workspace-relative strict input for one fresh restricted R2 Docker execution.",
    )
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
    if value in {".", ".."} or not re.fullmatch(r"[0-9A-Za-z._-]+", value):
        raise VerifierError("--run-id may use only letters, numbers, dot, underscore, and dash, but not '.' or '..'")
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


def _write_exclusive_text(path: Path, text: str, label: str) -> None:
    try:
        with path.open("x", encoding="utf-8") as stream:
            stream.write(text)
    except FileExistsError as exc:
        raise VerifierError(f"{label} destination already exists") from exc
    except OSError as exc:
        raise VerifierError(f"{label} could not be written safely") from exc


def write_log(run_dir: Path, message: str) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / "verifier.log"
    _write_exclusive_text(log_path, message.rstrip() + "\n", "verifier diagnostic log")
    return log_path


def write_fixture_artifact(run_dir: Path, verdict: str, oracle_type: str) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    artifact = run_dir / "fixture-oracle.json"
    _write_exclusive_text(
        artifact,
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
        "verifier diagnostic artifact",
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
    _write_exclusive_text(
        out_path,
        json.dumps(verdict, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        "verifier diagnostic",
    )
    validate_output(out_path, candidate_path)


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _parse_json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise VerifierError(f"{label} must be strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise VerifierError(f"{label} must be a JSON object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unknown = sorted(set(value) - expected)
        raise VerifierError(f"{label} fields are invalid (missing={missing}, unknown={unknown})")


def _safe_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise VerifierError(f"{label} must be sha256:<64 lowercase hex>")
    return value


def _safe_relative(value: Any, label: str) -> str:
    try:
        return safe_relative_path(value, label)
    except (IdentityError, TypeError) as exc:
        raise VerifierError(f"{label} must be a safe normalized workspace-relative POSIX path") from exc


def _safe_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise VerifierError(f"{label} must be a non-empty string")
    try:
        scan_security_text(value, label)
    except CandidateValidationError as exc:
        raise VerifierError(f"{label} contains non-portable or unsafe text") from exc
    return value


def _execution_input_bytes(workspace: Path, path: str) -> tuple[dict[str, Any], bytes, Path]:
    relative = _safe_relative(path, "--execution-input")
    input_path = workspace / PurePosixPath(relative)
    try:
        raw = safe_read_bytes(workspace, input_path)
    except SafeEvidenceError as exc:
        raise VerifierError(f"execution input cannot be read safely ({exc.code})") from exc
    value = _parse_json_object(raw, "execution input")
    required = {
        "schema_version", "candidate_sha256", "target_config_sha256", "tested_commit", "image_ref",
        "poc_sha256", "oracle", "source_refs", "review",
    }
    _exact_keys(value, required, "execution input")
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise VerifierError("execution input schema_version must be 1")
    for key in ("candidate_sha256", "target_config_sha256", "poc_sha256"):
        _safe_digest(value.get(key), f"execution input {key}")
    tested_commit = value.get("tested_commit")
    if not isinstance(tested_commit, str) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", tested_commit):
        raise VerifierError("execution input tested_commit must be a full lowercase Git commit ID")
    image_ref = value.get("image_ref")
    if not isinstance(image_ref, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_ref):
        raise VerifierError("execution input image_ref must be a local sha256 image ID")

    oracle = value.get("oracle")
    if not isinstance(oracle, dict):
        raise VerifierError("execution input oracle must be an object")
    _exact_keys(oracle, {"type", "pattern"}, "execution input oracle")
    if oracle.get("type") != "log_pattern":
        raise VerifierError("fresh execution supports only oracle.type=log_pattern")
    pattern = oracle.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        raise VerifierError("execution input oracle.pattern must be non-empty")
    try:
        pattern_bytes = pattern.encode("utf-8")
        compiled = re.compile(pattern, flags=re.MULTILINE)
    except (UnicodeError, re.error) as exc:
        raise VerifierError("execution input oracle.pattern must be valid UTF-8 regular expression text") from exc
    if len(pattern_bytes) > MAX_ORACLE_PATTERN_BYTES:
        raise VerifierError("execution input oracle.pattern exceeds 256 UTF-8 bytes")
    if compiled.search("") is not None:
        raise VerifierError("execution input oracle.pattern must not match the empty string")

    source_refs = value.get("source_refs")
    if not isinstance(source_refs, list) or not source_refs:
        raise VerifierError("execution input source_refs must be a non-empty array")
    seen_ids: set[str] = set()
    for index, source_ref in enumerate(source_refs):
        label = f"execution input source_refs[{index}]"
        if not isinstance(source_ref, dict):
            raise VerifierError(f"{label} must be an object")
        _exact_keys(source_ref, {"id", "path", "sha256", "line_start", "line_end", "token"}, label)
        ref_id = _safe_text(source_ref.get("id"), f"{label}.id")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", ref_id) or ref_id in seen_ids:
            raise VerifierError(f"{label}.id must be unique and stable")
        seen_ids.add(ref_id)
        source_ref["path"] = _safe_relative(source_ref.get("path"), f"{label}.path")
        _safe_digest(source_ref.get("sha256"), f"{label}.sha256")
        start, end = source_ref.get("line_start"), source_ref.get("line_end")
        if type(start) is not int or start < 1 or type(end) is not int or end < start:
            raise VerifierError(f"{label} line range must be positive and ordered")
        source_ref["token"] = _safe_text(source_ref.get("token"), f"{label}.token")

    review = value.get("review")
    if not isinstance(review, dict):
        raise VerifierError("execution input review must be an object")
    _exact_keys(
        review,
        {"entrypoint_ref", "sink_ref", "input_shape", "source_to_sink", "replay_material", "impact_interpretation", "observation"},
        "execution input review",
    )
    ref_ids = {ref["id"] for ref in source_refs}
    for key in ("entrypoint_ref", "sink_ref"):
        ref_id = review.get(key)
        if not isinstance(ref_id, str) or ref_id not in ref_ids:
            raise VerifierError(f"execution input review.{key} must name a source_refs id")
    for key in ("input_shape", "source_to_sink", "replay_material", "impact_interpretation"):
        review[key] = _safe_text(review.get(key), f"execution input review.{key}")
    observation = review.get("observation")
    if not isinstance(observation, dict):
        raise VerifierError("execution input review.observation must be an object")
    _exact_keys(observation, {"stream", "exact"}, "execution input review.observation")
    stream = observation.get("stream")
    if not isinstance(stream, str) or stream not in {"stdout", "stderr"}:
        raise VerifierError("execution input review.observation.stream must be stdout or stderr")
    observation["exact"] = _safe_text(observation.get("exact"), "execution input review.observation.exact")
    if compiled.search(observation["exact"]) is None:
        raise VerifierError("execution input oracle.pattern must match the reviewed exact observation")
    return value, raw, input_path


def _canonical_owned_directory(path: Path, label: str) -> Path:
    lexical = Path(path).expanduser().absolute()
    try:
        info = os.lstat(lexical)
        resolved = lexical.resolve(strict=True)
    except OSError as exc:
        raise VerifierError(f"{label} directory is unavailable") from exc
    if (
        resolved != lexical
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
    ):
        raise VerifierError(f"{label} directory must be a real current-user-owned directory")
    return lexical


def _cli_file_under_workspace(value: str, workspace: Path, label: str) -> Path:
    raw = Path(value).expanduser()
    absolute = (raw if raw.is_absolute() else Path.cwd() / raw).absolute()
    try:
        relative = absolute.relative_to(workspace)
    except ValueError as exc:
        raise VerifierError(f"{label} must be inside the workspace for fresh execution") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise VerifierError(f"{label} path is unsafe")
    return absolute


def _load_fresh_inputs(args: argparse.Namespace, workspace: Path) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes, Path, Path, dict[str, str]]:
    candidate_path = _cli_file_under_workspace(args.candidate, workspace, "candidate")
    try:
        candidate_raw = safe_read_bytes(workspace, candidate_path)
    except SafeEvidenceError as exc:
        raise VerifierError(f"candidate cannot be read safely ({exc.code})") from exc
    candidate = _parse_json_object(candidate_raw, "candidate")
    try:
        checked_candidate = validate_candidate(candidate)
    except CandidateValidationError as exc:
        raise VerifierError(f"invalid candidate: {exc}") from exc
    candidate_id = candidate.get("candidate_id")
    if checked_candidate.get("protocol_mode") != "r2":
        raise VerifierError("fresh execution requires a Candidate R2 candidate")
    expected_candidate_path = workspace / "candidates" / str(candidate_id) / "candidate.json"
    if candidate_path != expected_candidate_path:
        raise VerifierError("fresh execution requires the canonical candidates/<ID>/candidate.json path")

    target_path = _cli_file_under_workspace(args.target_config, workspace, "target configuration")
    try:
        target_raw = safe_read_bytes(workspace, target_path)
    except SafeEvidenceError as exc:
        raise VerifierError(f"target configuration cannot be read safely ({exc.code})") from exc
    try:
        target_doc = yaml.safe_load(target_raw.decode("utf-8"))
    except (UnicodeError, yaml.YAMLError) as exc:
        raise VerifierError("target configuration must be valid UTF-8 YAML") from exc
    if not isinstance(target_doc, dict):
        raise VerifierError("target configuration root must be a mapping")
    try:
        validate_target(target_doc)
    except TargetValidationError as exc:
        raise VerifierError(f"invalid target: {exc}") from exc
    mismatch = cross_check_target_ref(target_path, workspace, target_doc, candidate)
    if mismatch:
        raise VerifierError(mismatch)
    return target_doc, candidate, target_raw, candidate_raw, target_path, candidate_path, checked_candidate


def _target_repo_root(
    target_path: Path,
    target_doc: dict[str, Any],
    explicit_repo_root: str | None = None,
) -> Path:
    repo_value = target_doc.get("target", {}).get("repo_root")
    if explicit_repo_root is not None:
        if not explicit_repo_root:
            raise VerifierError("--repo-root must name a Git worktree root")
        if repo_value != ".":
            raise VerifierError("--repo-root requires target.repo_root to be '.'")
        repo_root = _canonical_owned_directory(Path(explicit_repo_root), "target repository")
    else:
        if repo_value == ".":
            relative = "."
        else:
            relative = _safe_relative(repo_value, "target.repo_root")
        lexical = (target_path.parent / relative).absolute()
        repo_root = _canonical_owned_directory(lexical, "target repository")
    try:
        top_level = _git(repo_root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    except (VerifierError, UnicodeError) as exc:
        raise VerifierError("target repo_root must identify an existing Git worktree") from exc
    if Path(top_level).absolute() != repo_root:
        raise VerifierError("target repo_root must be the Git worktree root")
    return repo_root


def _git(
    repo_root: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    max_output_bytes: int = 64 * 1024 * 1024,
) -> bytes:
    if type(max_output_bytes) is not int or max_output_bytes < 0:
        raise VerifierError("Git output bound is invalid")
    env = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    command = [
        "git", "-C", str(repo_root),
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false",
        *arguments,
    ]
    try:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
        )
    except OSError as exc:
        raise VerifierError("Git could not be invoked for the fresh source snapshot") from exc

    writer: threading.Thread | None = None
    if input_bytes is not None:
        def send_input() -> None:
            try:
                assert proc.stdin is not None
                proc.stdin.write(input_bytes)
            except BrokenPipeError:
                pass
            finally:
                if proc.stdin is not None:
                    try:
                        proc.stdin.close()
                    except BrokenPipeError:
                        pass

        writer = threading.Thread(target=send_input, daemon=True)
        writer.start()

    output = bytearray()
    oversized = False
    assert proc.stdout is not None
    while len(output) <= max_output_bytes:
        chunk = proc.stdout.read(min(65536, max_output_bytes + 1 - len(output)))
        if not chunk:
            break
        output.extend(chunk)
    if len(output) > max_output_bytes:
        oversized = True
        proc.kill()
    returncode = proc.wait()
    if writer is not None:
        writer.join()
    proc.stdout.close()
    if oversized:
        raise VerifierError("Git output exceeded the verifier bound")
    if returncode != 0:
        raise VerifierError("Git rejected the fresh source identity or object read")
    return bytes(output)


def _resolve_commit(repo_root: Path, revision: str) -> str:
    if not isinstance(revision, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", revision):
        raise VerifierError("target tested_ref is not a safe Git revision name")
    if any(part in {".", ".."} for part in revision.split("/")) or "@{" in revision:
        raise VerifierError("target tested_ref contains an unsafe Git revision component")
    resolved = _git(repo_root, "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}").decode("ascii", "strict").strip()
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", resolved):
        raise VerifierError("target tested_ref did not resolve to a full Git commit ID")
    return resolved


@dataclass(frozen=True)
class _GitTreeEntry:
    git_mode: str
    raw: bytes


def _read_git_tree(repo_root: Path, commit: str) -> dict[str, _GitTreeEntry]:
    tree = _git(
        repo_root,
        "ls-tree",
        "-r",
        "-z",
        "-l",
        "--full-tree",
        commit,
        max_output_bytes=64 * 1024 * 1024,
    )
    entries: list[tuple[str, str, str, int]] = []
    seen_paths: set[str] = set()
    folded_paths: set[str] = set()
    total_declared = 0
    records = tree.split(b"\x00")
    if records and records[-1] == b"":
        records.pop()
    for record in records:
        try:
            header, path_raw = record.split(b"\t", 1)
            fields = header.decode("ascii").split()
            mode, object_type, object_id = fields[:3]
            path = path_raw.decode("utf-8", "strict")
        except (ValueError, UnicodeError) as exc:
            raise VerifierError("Git source tree contains a malformed entry") from exc
        normalized = _safe_relative(path, "Git source tree path")
        if normalized != path or ".git" in PurePosixPath(path).parts or len(path_raw) > 4096:
            raise VerifierError("Git source tree contains an unsafe path")
        if any(len(part.encode("utf-8")) > 255 for part in PurePosixPath(path).parts):
            raise VerifierError("Git source tree contains a path component unsupported by the filesystem")
        if path in seen_paths:
            raise VerifierError("Git source tree contains duplicate paths")
        seen_paths.add(path)
        if mode not in {"100644", "100755"} or object_type != "blob":
            raise VerifierError("Git source tree contains a symlink, gitlink, or non-regular file")
        folded = path.casefold()
        if folded in folded_paths:
            raise VerifierError("Git source tree contains paths that alias on a case-insensitive filesystem")
        folded_paths.add(folded)
        if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", object_id):
            raise VerifierError("Git source tree contains an invalid blob identity")
        if len(fields) != 4 or not fields[3].isdigit():
            raise VerifierError("Git source tree is missing a regular blob size")
        size = int(fields[3])
        if size > MAX_SNAPSHOT_FILE_BYTES:
            raise VerifierError("Git source tree contains a file exceeding the 16 MiB limit")
        total_declared += size
        if total_declared > MAX_SNAPSHOT_TOTAL_BYTES:
            raise VerifierError("Git source tree exceeds the 256 MiB total limit")
        entries.append((path, mode, object_id, size))
        if len(entries) > MAX_SNAPSHOT_FILES:
            raise VerifierError("Git source tree exceeds the 10,000-file limit")

    object_input = b"".join(object_id.encode("ascii") + b"\n" for _path, _mode, object_id, _size in entries)
    if not entries:
        return {}
    batch = _git(
        repo_root,
        "cat-file",
        "--batch",
        input_bytes=object_input,
        max_output_bytes=MAX_SNAPSHOT_TOTAL_BYTES + MAX_SNAPSHOT_FILES * 128,
    )
    contents: dict[str, _GitTreeEntry] = {}
    offset = 0
    total = 0
    for path, git_mode, expected_id, expected_size in entries:
        header_end = batch.find(b"\n", offset)
        if header_end < 0:
            raise VerifierError("Git returned a truncated source blob header")
        try:
            object_id, object_type, size_text = batch[offset:header_end].decode("ascii").split(" ")
            size = int(size_text)
        except (ValueError, UnicodeError) as exc:
            raise VerifierError("Git returned a malformed source blob header") from exc
        offset = header_end + 1
        if object_id != expected_id or object_type != "blob" or size != expected_size:
            raise VerifierError("Git source blob identity, type, or size is invalid")
        end = offset + size
        if end >= len(batch) or batch[end:end + 1] != b"\n":
            raise VerifierError("Git returned a truncated source blob")
        content = batch[offset:end]
        total += len(content)
        contents[path] = _GitTreeEntry(git_mode=git_mode, raw=content)
        offset = end + 1
    if total != total_declared:
        raise VerifierError("Git source blob sizes do not match the bounded tree listing")
    if offset != len(batch):
        raise VerifierError("Git returned unaccounted source blob bytes")
    return contents


def _validate_source_refs(
    repo_root: Path,
    contents: dict[str, _GitTreeEntry],
    source_refs: list[dict[str, Any]],
) -> None:
    for source_ref in source_refs:
        path = source_ref["path"]
        entry = contents.get(path)
        if entry is None:
            raise VerifierError("reviewed source reference is not a regular file in the tested Git tree")
        content = entry.raw
        if _sha256(content) != source_ref["sha256"]:
            raise VerifierError("reviewed source reference content digest does not match the tested Git blob")
        try:
            lines = content.decode("utf-8", "strict").splitlines()
        except UnicodeError as exc:
            raise VerifierError("reviewed source reference is not UTF-8 text") from exc
        start, end = source_ref["line_start"], source_ref["line_end"]
        if end > len(lines) or source_ref["token"] not in "\n".join(lines[start - 1:end]):
            raise VerifierError("reviewed source reference line range or token does not match the tested blob")
        try:
            worktree = safe_read_bytes(repo_root, repo_root / PurePosixPath(path), max_bytes=MAX_SNAPSHOT_FILE_BYTES)
        except SafeEvidenceError as exc:
            raise VerifierError(f"reviewed source worktree file is unsafe ({exc.code})") from exc
        if worktree != content:
            raise VerifierError("reviewed source worktree bytes differ from the tested Git blob")


def _match_target_entrypoint(target_doc: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    scope = target_doc.get("scope")
    entries = scope.get("entrypoints") if isinstance(scope, dict) else None
    if not isinstance(entries, list):
        raise VerifierError("target contract has no valid entrypoint scope")
    try:
        expected = normalize_entrypoint(candidate.get("entrypoint"))
    except IdentityError as exc:
        raise VerifierError("candidate entrypoint cannot be normalized") from exc
    matches: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        try:
            normalized = normalize_entrypoint({key: entry.get(key) for key in ("id", "kind", "route")})
        except IdentityError:
            continue
        if normalized == expected:
            matches.append(entry)
    if len(matches) != 1:
        raise VerifierError("candidate entrypoint must match exactly one target scope entry")
    return matches[0]


def _assert_absent_destination(root: Path, path: Path, label: str) -> None:
    try:
        relative = path.absolute().relative_to(root.absolute())
    except ValueError as exc:
        raise VerifierError(f"{label} must stay inside the workspace") from exc
    current = root
    for component in relative.parts[:-1]:
        current = current / component
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise VerifierError(f"{label} ancestors cannot be inspected") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise VerifierError(f"{label} ancestor is not a real owned directory")
    leaf = current / relative.parts[-1]
    try:
        os.lstat(leaf)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise VerifierError(f"{label} destination cannot be inspected") from exc
    raise VerifierError(f"{label} destination already exists; fresh verifier runs cannot be resumed or overwritten")


def _create_fresh_directory(root: Path, path: Path, label: str) -> None:
    try:
        ensure_host_directory(root, path.parent)
        os.mkdir(path, 0o700)
        info = os.lstat(path)
    except (OSError, SafeEvidenceError) as exc:
        if isinstance(exc, SafeEvidenceError):
            code = exc.code
        else:
            code = type(exc).__name__
        raise VerifierError(f"{label} could not be created exclusively ({code})") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise VerifierError(f"{label} is not a real owned directory")


@dataclass
class _FreshReservation:
    root: Path
    path: Path
    parent_fd: int
    parent_device: int
    parent_inode: int
    parent_uid: int
    parent_mode: int
    file_identity: tuple[int, int, int, int, int]
    file_size: int
    file_mtime_ns: int
    file_ctime_ns: int
    active: bool = True


def _reservation_stat_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_nlink, info.st_uid, info.st_mode


def _reservation_matches(reservation: _FreshReservation, info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and info.st_size == 0
        and _reservation_stat_identity(info) == reservation.file_identity
        and info.st_size == reservation.file_size
        and info.st_mtime_ns == reservation.file_mtime_ns
        and info.st_ctime_ns == reservation.file_ctime_ns
    )


def _write_empty_reservation(root: Path, path: Path, reservations: list[_FreshReservation], *, mode: int) -> None:
    parent_fd = -1
    file_fd = -1
    verify_fd = -1
    reservation: _FreshReservation | None = None
    created_file = False
    try:
        ensure_host_directory(root, path.parent)
        parent_path_info = os.lstat(path.parent)
        parent_fd = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        parent_info = os.fstat(parent_fd)
        if (
            stat.S_ISLNK(parent_path_info.st_mode)
            or not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.geteuid()
            or (parent_path_info.st_dev, parent_path_info.st_ino) != (parent_info.st_dev, parent_info.st_ino)
        ):
            raise VerifierError("fresh verifier reservation parent changed during creation")

        file_fd = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
            dir_fd=parent_fd,
        )
        created_file = True
        created = os.fstat(file_fd)
        reservation = _FreshReservation(
            root=root,
            path=path,
            parent_fd=parent_fd,
            parent_device=parent_info.st_dev,
            parent_inode=parent_info.st_ino,
            parent_uid=parent_info.st_uid,
            parent_mode=stat.S_IMODE(parent_info.st_mode),
            file_identity=_reservation_stat_identity(created),
            file_size=created.st_size,
            file_mtime_ns=created.st_mtime_ns,
            file_ctime_ns=created.st_ctime_ns,
        )
        reservations.append(reservation)
        if not stat.S_ISREG(created.st_mode) or created.st_uid != os.geteuid() or created.st_nlink != 1 or created.st_size != 0:
            raise VerifierError("fresh verifier reservation is not an owned empty regular file")
        os.fchmod(file_fd, mode)
        created = os.fstat(file_fd)
        reservation.file_identity = _reservation_stat_identity(created)
        reservation.file_size = created.st_size
        reservation.file_mtime_ns = created.st_mtime_ns
        reservation.file_ctime_ns = created.st_ctime_ns
        if not _reservation_matches(reservation, created):
            raise VerifierError("fresh verifier reservation changed during creation")
        os.fsync(file_fd)

        linked = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        verify_fd = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        opened = os.fstat(verify_fd)
        if not _reservation_matches(reservation, linked) or not _reservation_matches(reservation, opened):
            raise VerifierError("fresh verifier reservation changed during creation")
        if os.read(verify_fd, 1):
            raise VerifierError("fresh verifier reservation is not empty")
        os.fsync(parent_fd)
    except FileExistsError as exc:
        raise VerifierError("fresh verifier destination appeared after preflight; nothing was overwritten") from exc
    except (OSError, SafeEvidenceError) as exc:
        if isinstance(exc, SafeEvidenceError):
            code = exc.code
        else:
            code = type(exc).__name__
        raise VerifierError(f"fresh verifier file could not be created exclusively ({code})") from exc
    finally:
        for fd in (verify_fd, file_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if reservation is None and parent_fd >= 0:
            if created_file:
                print(
                    "WARNING: fresh verifier reservation could not be safely released; leaving it untouched",
                    file=sys.stderr,
                )
            try:
                os.close(parent_fd)
            except OSError:
                pass


def _write_exclusive_bytes(
    root: Path,
    path: Path,
    raw: bytes,
    *,
    mode: int = 0o600,
    reservations: list[_FreshReservation] | None = None,
) -> None:
    if reservations is not None:
        if raw or mode != 0o600:
            raise VerifierError("fresh verifier reservations must be empty mode-0600 files")
        _write_empty_reservation(root, path, reservations, mode=mode)
        return
    try:
        ensure_host_directory(root, path.parent)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    except FileExistsError as exc:
        raise VerifierError("fresh verifier destination appeared after preflight; nothing was overwritten") from exc
    except (OSError, SafeEvidenceError) as exc:
        if isinstance(exc, SafeEvidenceError):
            code = exc.code
        else:
            code = type(exc).__name__
        raise VerifierError(f"fresh verifier file could not be created exclusively ({code})") from exc
    try:
        os.fchmod(fd, mode)
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise VerifierError("fresh verifier file write was incomplete")
            offset += written
        os.fsync(fd)
    except OSError as exc:
        raise VerifierError("fresh verifier file could not be written durably") from exc
    finally:
        os.close(fd)
    try:
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        persisted = safe_read_bytes(root, path, max_bytes=max(len(raw), 1))
    except (OSError, SafeEvidenceError) as exc:
        raise VerifierError("fresh verifier file could not be verified after write") from exc
    if persisted != raw:
        raise VerifierError("fresh verifier file changed during creation")


def _reservation_identity(reservations: list[_FreshReservation], path: Path) -> tuple[int, int, int, int, int]:
    for reservation in reservations:
        if reservation.active and reservation.path == path:
            return reservation.file_identity
    raise VerifierError("fresh verifier publication has no owned empty reservation")


def _adopt_verified_rollback_identity(
    reservations: list[_FreshReservation],
    path: Path,
    rollback_stats: list[os.stat_result],
) -> bool:
    matches = [item for item in reservations if item.active and item.path == path]
    if len(matches) != 1 or len(rollback_stats) != 1:
        return False
    reservation = matches[0]
    witness = rollback_stats[0]
    verify_fd = -1
    try:
        root = reservation.root.absolute()
        parent_parts = reservation.path.parent.absolute().relative_to(root).parts
        current = root
        parent_path_info = os.lstat(current)
        if (
            stat.S_ISLNK(parent_path_info.st_mode)
            or not stat.S_ISDIR(parent_path_info.st_mode)
            or parent_path_info.st_uid != os.geteuid()
        ):
            return False
        for part in parent_parts:
            current = current / part
            parent_path_info = os.lstat(current)
            if (
                stat.S_ISLNK(parent_path_info.st_mode)
                or not stat.S_ISDIR(parent_path_info.st_mode)
                or parent_path_info.st_uid != os.geteuid()
            ):
                return False
        parent_info = os.fstat(reservation.parent_fd)
        if (
            (parent_path_info.st_dev, parent_path_info.st_ino) != (reservation.parent_device, reservation.parent_inode)
            or (parent_info.st_dev, parent_info.st_ino) != (reservation.parent_device, reservation.parent_inode)
            or parent_info.st_uid != reservation.parent_uid
            or stat.S_IMODE(parent_info.st_mode) != reservation.parent_mode
        ):
            return False

        def matches_witness(info: os.stat_result) -> bool:
            return (
                stat.S_ISREG(info.st_mode)
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == os.geteuid()
                and info.st_nlink == 1
                and info.st_size == 0
                and _reservation_stat_identity(info) == _reservation_stat_identity(witness)
                and info.st_mtime_ns == witness.st_mtime_ns
                and info.st_ctime_ns == witness.st_ctime_ns
            )

        linked = os.stat(reservation.path.name, dir_fd=reservation.parent_fd, follow_symlinks=False)
        if not matches_witness(linked):
            return False
        verify_fd = os.open(
            reservation.path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=reservation.parent_fd,
        )
        opened = os.fstat(verify_fd)
        if not matches_witness(opened) or os.read(verify_fd, 1):
            return False
        linked_again = os.stat(reservation.path.name, dir_fd=reservation.parent_fd, follow_symlinks=False)
        if not matches_witness(linked_again):
            return False
    except (OSError, SafeEvidenceError, ValueError):
        return False
    finally:
        if verify_fd >= 0:
            try:
                os.close(verify_fd)
            except OSError:
                pass

    reservation.file_identity = _reservation_stat_identity(witness)
    reservation.file_size = witness.st_size
    reservation.file_mtime_ns = witness.st_mtime_ns
    reservation.file_ctime_ns = witness.st_ctime_ns
    return True


def _mark_reservation_published(reservations: list[_FreshReservation], path: Path) -> None:
    for reservation in reservations:
        if reservation.active and reservation.path == path:
            reservation.active = False
            return


def _release_fresh_reservations(reservations: list[_FreshReservation]) -> None:
    for reservation in reservations:
        if not reservation.active:
            continue
        try:
            root = reservation.root.absolute()
            try:
                parent_parts = reservation.path.parent.absolute().relative_to(root).parts
            except ValueError as exc:
                raise VerifierError("reservation parent is outside the workspace") from exc
            current = root
            parent_path_info = os.lstat(current)
            if (
                stat.S_ISLNK(parent_path_info.st_mode)
                or not stat.S_ISDIR(parent_path_info.st_mode)
                or parent_path_info.st_uid != os.geteuid()
            ):
                raise VerifierError("reservation root identity changed")
            for part in parent_parts:
                current = current / part
                parent_path_info = os.lstat(current)
                if (
                    stat.S_ISLNK(parent_path_info.st_mode)
                    or not stat.S_ISDIR(parent_path_info.st_mode)
                    or parent_path_info.st_uid != os.geteuid()
                ):
                    raise VerifierError("reservation parent or ancestor changed")
            parent_info = os.fstat(reservation.parent_fd)
            if (
                not stat.S_ISDIR(parent_info.st_mode)
                or (parent_path_info.st_dev, parent_path_info.st_ino) != (reservation.parent_device, reservation.parent_inode)
                or (parent_info.st_dev, parent_info.st_ino) != (reservation.parent_device, reservation.parent_inode)
                or parent_info.st_uid != reservation.parent_uid
                or stat.S_IMODE(parent_info.st_mode) != reservation.parent_mode
            ):
                raise VerifierError("reservation parent identity changed")
            linked = os.stat(reservation.path.name, dir_fd=reservation.parent_fd, follow_symlinks=False)
            if not _reservation_matches(reservation, linked):
                raise VerifierError("reservation file identity changed")
            fd = os.open(
                reservation.path.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=reservation.parent_fd,
            )
            try:
                opened = os.fstat(fd)
                if not _reservation_matches(reservation, opened) or os.read(fd, 1):
                    raise VerifierError("reservation contents or identity changed")
            finally:
                os.close(fd)
            linked_again = os.stat(reservation.path.name, dir_fd=reservation.parent_fd, follow_symlinks=False)
            if not _reservation_matches(reservation, linked_again):
                raise VerifierError("reservation changed before cleanup")
            os.unlink(reservation.path.name, dir_fd=reservation.parent_fd)
            reservation.active = False
            try:
                os.fsync(reservation.parent_fd)
            except OSError:
                try:
                    print(
                        "WARNING: fresh verifier reservation was removed, but directory durability is unconfirmed",
                        file=sys.stderr,
                    )
                except OSError:
                    pass
        except (OSError, SafeEvidenceError, VerifierError):
            if reservation.active:
                print(
                    "WARNING: fresh verifier reservation could not be safely released; leaving it untouched",
                    file=sys.stderr,
                )


def _close_reservation_directories(reservations: list[_FreshReservation]) -> None:
    for reservation in reservations:
        try:
            os.close(reservation.parent_fd)
        except OSError:
            pass


def execute_fresh_verification(
    args: argparse.Namespace,
    target: dict[str, Any],
    candidate: dict[str, Any],
) -> int:
    reservations: list[_FreshReservation] = []
    try:
        return _execute_fresh_verification(args, target, candidate, reservations)
    except BaseException:
        _release_fresh_reservations(reservations)
        raise
    finally:
        _close_reservation_directories(reservations)


def _case_id_for(candidate_digest: str, run_id: str) -> str:
    seed = f"{candidate_digest}\0{run_id}".encode("utf-8")
    return "verifier-" + hashlib.sha256(seed).hexdigest()[:32]


def _snapshot_git_tree(
    workspace: Path,
    run_id: str,
    contents: dict[str, _GitTreeEntry],
) -> tuple[Path, list[dict[str, str]]]:
    snapshot_root = workspace / "poc" / run_id
    source_root = snapshot_root / "source"
    _create_fresh_directory(workspace, snapshot_root, "fresh snapshot directory")
    _create_fresh_directory(workspace, source_root, "source snapshot directory")
    manifest: list[dict[str, str]] = []
    snapshot_modes = {"100644": 0o444, "100755": 0o555}
    for relative in sorted(contents):
        entry = contents[relative]
        mode = snapshot_modes.get(entry.git_mode)
        if mode is None:
            raise VerifierError("Git source tree contains an unsupported regular-file mode")
        destination = source_root / PurePosixPath(relative)
        _write_exclusive_bytes(workspace, destination, entry.raw, mode=mode)
        manifest.append(
            {
                "path": relative,
                "git_mode": entry.git_mode,
                "snapshot_mode": format(mode, "04o"),
                "sha256": _sha256(entry.raw),
            }
        )
    for directory in sorted((path for path in source_root.rglob("*") if path.is_dir()), key=lambda item: len(item.parts), reverse=True):
        os.chmod(directory, 0o500)
    os.chmod(source_root, 0o500)
    return source_root, manifest


def _run_wrapper(command: list[str]) -> tuple[int, bytes, bytes, bool]:
    try:
        process = subprocess.Popen(
            command,
            cwd=Path(__file__).resolve().parent.parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise VerifierError("the production verification wrapper could not be started") from exc
    try:
        stdout, stderr = process.communicate(timeout=WRAPPER_TIMEOUT_SECONDS)
        return int(process.returncode), stdout, stderr, False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except OSError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            stdout, stderr = process.communicate()
        return int(process.returncode if process.returncode is not None else -signal.SIGKILL), stdout, stderr, True


def _checked_wrapper_result(
    workspace: Path,
    case_id: str,
    command_argv: list[str],
    regex: re.Pattern[str],
    observation: dict[str, str],
    wrapper_result_raw: bytes,
    command_raw: bytes,
    stdout_raw: bytes,
    stderr_raw: bytes,
    receipt_raw: bytes,
) -> tuple[dict[str, Any], dict[str, Any]]:
    result = _parse_json_object(wrapper_result_raw, "wrapper verification result")
    expected_result_keys = {
        "schema_version", "case_id", "mode", "status", "classification_reason", "exit_code", "oracle_matched",
        "docker_invoked", "poc_command_invoked", "expected_oracle", "timeout_seconds", "workspace_dir", "evidence_dir",
        "stdout_path", "stderr_path", "command", "docker_boundary_only", "host_poc_execution_allowed", "image",
        "image_policy", "network", "finished_at", "docker_case_lifecycle", "wrapper_status", "authority_event_committed",
        "resource_limits",
    }
    if set(result) != expected_result_keys:
        raise VerifierError("wrapper result has an unsupported or incomplete shape")
    if (
        type(result.get("schema_version")) is not int
        or result.get("schema_version") != 1
        or result.get("case_id") != case_id
        or result.get("mode") != "docker-run"
        or result.get("status") != "confirmed_in_docker"
        or type(result.get("exit_code")) is not int
        or result.get("exit_code") != 0
        or result.get("oracle_matched") is not True
        or result.get("docker_invoked") is not True
        or result.get("poc_command_invoked") is not True
        or result.get("authority_event_committed") is not True
        or result.get("wrapper_status") != "completed"
        or type(result.get("timeout_seconds")) is not int
        or result.get("timeout_seconds") != 300
        or result.get("network") != "none"
        or result.get("docker_boundary_only") is not True
        or result.get("host_poc_execution_allowed") is not False
    ):
        raise VerifierError("wrapper result does not prove a successful restricted Docker execution")
    if not isinstance(result.get("expected_oracle"), str) or result["expected_oracle"] != regex.pattern:
        raise VerifierError("wrapper result oracle does not match the reviewed execution input")
    if not isinstance(result.get("classification_reason"), str) or not result["classification_reason"].strip():
        raise VerifierError("wrapper result classification reason is missing")
    if result.get("image_policy") != "prefer_local_or_cached_image; pull_only_when_explicitly_requested_with_pull_if_missing":
        raise VerifierError("wrapper result image policy is unsupported")
    if not isinstance(result.get("finished_at"), str):
        raise VerifierError("wrapper result finished_at must be a string")
    try:
        finished_at = datetime.fromisoformat(result["finished_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise VerifierError("wrapper result finished_at must be an ISO-8601 timestamp") from exc
    if finished_at.tzinfo is None:
        raise VerifierError("wrapper result finished_at must include a timezone")
    if not isinstance(result.get("image"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", result["image"]):
        raise VerifierError("wrapper result image must be a local sha256 image ID")
    if result.get("workspace_dir") != workspace.name or result.get("evidence_dir") != f"evidence/{case_id}":
        raise VerifierError("wrapper result paths do not bind the expected workspace case")
    if not isinstance(result.get("stdout_path"), str) or not isinstance(result.get("stderr_path"), str):
        raise VerifierError("wrapper result output paths must be strings")

    resource_limits = result.get("resource_limits")
    if not isinstance(resource_limits, dict) or set(resource_limits) != {
        "policy_version", "memory", "cpus", "pids_limit", "read_only_rootfs", "managed_by_host_policy",
    }:
        raise VerifierError("wrapper resource limits have an unsupported shape")
    if (
        resource_limits.get("policy_version") != "docker-case-policy-v2"
        or resource_limits.get("memory") != "512m"
        or resource_limits.get("cpus") != "1"
        or type(resource_limits.get("pids_limit")) is not int
        or resource_limits.get("pids_limit") != 256
        or resource_limits.get("read_only_rootfs") is not True
        or resource_limits.get("managed_by_host_policy") is not True
    ):
        raise VerifierError("wrapper resource limits do not match the current host policy")

    lifecycle = result.get("docker_case_lifecycle")
    if not isinstance(lifecycle, dict) or set(lifecycle) != {
        "receipt_sha256", "cleanup_attempted", "cleanup_verified", "residue_counts_before",
        "residue_counts_after", "settlement_checks", "resource_policy",
    }:
        raise VerifierError("wrapper lifecycle result has an unsupported shape")
    if (
        lifecycle.get("cleanup_attempted") is not True
        or lifecycle.get("cleanup_verified") is not True
        or not isinstance(lifecycle.get("receipt_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", lifecycle["receipt_sha256"])
    ):
        raise VerifierError("wrapper cleanup was not verified")
    before_counts = lifecycle.get("residue_counts_before")
    counts = lifecycle.get("residue_counts_after")
    if (
        not isinstance(before_counts, dict)
        or set(before_counts) != {"containers", "networks", "volumes"}
        or any(type(value) is not int or value < 0 for value in before_counts.values())
        or not isinstance(counts, dict)
        or set(counts) != {"containers", "networks", "volumes"}
        or any(type(value) is not int or value != 0 for value in counts.values())
        or type(lifecycle.get("settlement_checks")) is not int
        or lifecycle["settlement_checks"] < 3
    ):
        raise VerifierError("wrapper cleanup did not verify zero Docker residue")
    resource_policy = lifecycle.get("resource_policy")
    if not isinstance(resource_policy, dict) or resource_policy.get("network_mode") != "none":
        raise VerifierError("Docker receipt did not bind network none")

    try:
        command_record = json.loads(command_raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise VerifierError("wrapper command record must be strict UTF-8 JSON") from exc
    if not isinstance(command_record, list) or not all(isinstance(item, str) for item in command_record):
        raise VerifierError("wrapper command record must be an argument array")
    if result.get("command") != command_record:
        raise VerifierError("wrapper result command does not match its command record")

    try:
        receipt_doc = _parse_json_object(receipt_raw, "Docker lifecycle receipt")
        if type(receipt_doc.get("schema_version")) is not int:
            raise VerifierError("Docker lifecycle receipt schema_version must be an integer")
        checked_receipt = validate_receipt(receipt_doc)
    except (VerifierError, LifecycleError) as exc:
        raise VerifierError("Docker lifecycle receipt is invalid") from exc
    if checked_receipt.get("case_id") != case_id or checked_receipt.get("mode") != "docker-run":
        raise VerifierError("Docker lifecycle receipt does not identify the fresh docker-run case")
    if checked_receipt.get("policy", {}).get("network_mode") != "none":
        raise VerifierError("Docker lifecycle receipt does not bind network none")
    if resource_policy != checked_receipt.get("policy"):
        raise VerifierError("wrapper resource policy differs from the validated lifecycle receipt")
    if lifecycle.get("receipt_sha256") != hashlib.sha256(receipt_raw).hexdigest():
        raise VerifierError("wrapper result does not bind the exact Docker lifecycle receipt bytes")

    expected_command = [
        "docker", "run",
        "--name", checked_receipt["container_name"],
        "--label", "org.zhulong.managed=true",
        "--label", f"org.zhulong.case={checked_receipt['token']}",
        "--label", "org.zhulong.policy=docker-case-policy-v2",
        "--label", f"org.zhulong.project={checked_receipt['project_name']}",
        "--label", f"org.zhulong.workspace={workspace.name}",
        "--memory", "512m",
        "--memory-swap", "512m",
        "--cpus", "1",
        "--pids-limit", "256",
        "--restart", "no",
        "--log-driver", "none",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--mount", "type=bind,source=<audit-workspace>/poc,target=/workspace/poc,readonly",
        "--mount", "type=bind,source=<evidence-dir>,target=/workspace/evidence,readonly",
        "--tmpfs", "/workspace/output:rw,nosuid,nodev,noexec,size=64m",
        "--workdir", "/workspace/poc",
        result["image"],
        *command_argv,
    ]
    if command_record != expected_command:
        raise VerifierError("wrapper command does not match the fixed restricted docker-run policy")

    try:
        stdout_text = stdout_raw.decode("utf-8", "strict")
        stderr_text = stderr_raw.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise VerifierError("captured oracle output must be valid UTF-8") from exc
    selected = stdout_text if observation["stream"] == "stdout" else stderr_text
    combined = stdout_text + "\n" + stderr_text
    if observation["exact"] not in selected or regex.search(combined) is None:
        raise VerifierError("captured output did not independently match the reviewed observation and oracle")
    return result, checked_receipt


def _event_case_id(event: dict[str, Any]) -> str | None:
    details = event.get("details")
    metadata = details.get("metadata") if isinstance(details, dict) else None
    if isinstance(metadata, list):
        for item in metadata:
            if isinstance(item, dict) and item.get("key") == "case_id" and isinstance(item.get("value"), str):
                return item["value"]
    return None


def _verify_journal_suffix(
    workspace: Path,
    baseline: Any,
    case_id: str,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    try:
        final = read_workspace_snapshot(workspace, mode_policy="r2")
    except AuditStateError as exc:
        raise VerifierError(f"post-run journal/state validation failed ({exc.code})") from exc
    baseline_raw = baseline.journal.raw_bytes
    final_raw = final.journal.raw_bytes
    baseline_revision = int(baseline.state["state_revision"]) if isinstance(baseline.state, dict) else -1
    if not final_raw.startswith(baseline_raw):
        raise VerifierError("audit journal prefix changed during fresh execution")
    if final.state is None or final.state.get("stage") != "verification" or final.state.get("status") != "running":
        raise VerifierError("post-run verification state is not synchronized at verification/running")
    if final.state.get("state_revision") != baseline_revision + 2 or len(final.journal.events) != len(baseline.journal.events) + 2:
        raise VerifierError("audit journal contains missing or unaccounted events")
    suffix = final.journal.events[-2:]
    start, completion = suffix
    baseline_run_id = baseline.journal.events[-1].get("run_id") if baseline.journal.events else None
    if (
        start.get("event_name") != "verification_case_started"
        or start.get("stage") != "verification"
        or start.get("transition_kind") != "observe"
        or start.get("to_status") != "running"
        or start.get("seq") != baseline_revision + 1
        or start.get("expected_state_revision") != baseline_revision
        or start.get("run_id") != baseline_run_id
        or f"verification:{case_id}" not in start.get("subjects", [])
        or f"evidence/{case_id}/command.json" not in start.get("evidence_refs", [])
        or _event_case_id(start) != case_id
    ):
        raise VerifierError("audit journal start event does not uniquely bind this verification case")
    if (
        completion.get("event_name") != "verification_case_completed"
        or completion.get("stage") not in {"verification", "candidate_verifying"}
        or completion.get("transition_kind") != "observe"
        or completion.get("to_status") != "running"
        or completion.get("seq") != baseline_revision + 2
        or completion.get("expected_state_revision") != baseline_revision + 1
        or completion.get("run_id") != baseline_run_id
        or f"verification:{case_id}" not in completion.get("subjects", [])
        or f"evidence/{case_id}/verification-result.json" not in completion.get("evidence_refs", [])
        or _event_case_id(completion) != case_id
    ):
        raise VerifierError("audit journal completion event does not uniquely bind this verification case")
    prefix_digest = _sha256(final_raw[:len(baseline_raw)])
    if final.state.get("event_log_digest") != _sha256(final_raw):
        raise VerifierError("post-run state view does not bind the final journal bytes")
    return start, completion, prefix_digest


def _verify_snapshot_unchanged(
    workspace: Path,
    source_root: Path,
    manifest: list[dict[str, str]],
) -> None:
    snapshot_modes = {"100644": "0444", "100755": "0555"}
    expected: dict[str, tuple[str, str]] = {}
    for item in manifest:
        path = item.get("path")
        git_mode = item.get("git_mode")
        snapshot_mode = item.get("snapshot_mode")
        digest = item.get("sha256")
        if (
            not isinstance(path, str)
            or not isinstance(git_mode, str)
            or git_mode not in snapshot_modes
            or snapshot_mode != snapshot_modes[git_mode]
            or not isinstance(digest, str)
            or path in expected
        ):
            raise VerifierError("source snapshot manifest has an invalid path or mode binding")
        expected[path] = (digest, snapshot_mode)
    found: dict[str, str] = {}
    for path in source_root.rglob("*"):
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise VerifierError("source snapshot changed or became unavailable") from exc
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise VerifierError("source snapshot contains a symlink, hardlink, or non-regular file")
        relative = path.relative_to(source_root).as_posix()
        expected_entry = expected.get(relative)
        actual_mode = format(stat.S_IMODE(info.st_mode), "04o")
        if expected_entry is None or actual_mode != expected_entry[1]:
            raise VerifierError("source snapshot file mode changed during execution")
        try:
            raw = safe_read_bytes(workspace, path, max_bytes=MAX_SNAPSHOT_FILE_BYTES)
        except SafeEvidenceError as exc:
            raise VerifierError(f"source snapshot file is unsafe ({exc.code})") from exc
        found[relative] = _sha256(raw)
    if found != {path: item[0] for path, item in expected.items()}:
        raise VerifierError("source snapshot manifest changed during execution")


def _execute_fresh_verification(
    args: argparse.Namespace,
    target: dict[str, Any],
    candidate: dict[str, Any],
    reservations: list[_FreshReservation],
) -> int:
    """Own the complete opt-in R2 execution path and never fall through to R1 writing."""
    workspace = _canonical_owned_directory(Path(args.workspace), "workspace")
    if not args.run_id:
        raise VerifierError("fresh execution requires an explicit --run-id")
    run_id = safe_run_id(args.run_id)
    if not args.execution_input:
        raise VerifierError("--execution-input is required with --allow-execute")

    execution_input, input_raw, input_path = _execution_input_bytes(workspace, args.execution_input)
    target_doc, candidate_doc, target_raw, candidate_raw, target_path, candidate_path, checked_candidate = _load_fresh_inputs(args, workspace)
    if target != target_doc or candidate != candidate_doc:
        raise VerifierError("fresh verifier inputs changed between dispatch and execution")
    if _sha256(candidate_raw) != execution_input["candidate_sha256"]:
        raise VerifierError("execution input candidate_sha256 does not match the canonical candidate")
    if _sha256(target_raw) != execution_input["target_config_sha256"]:
        raise VerifierError("execution input target_config_sha256 does not match the target configuration")
    if checked_candidate.get("protocol_mode") != "r2" or candidate_doc.get("identity", {}).get("target_commit") != execution_input["tested_commit"]:
        raise VerifierError("execution input tested_commit does not match the Candidate R2 identity")
    if expected_oracle(candidate_doc) != "log_pattern":
        raise VerifierError("Candidate R2 expected_oracle.type must be log_pattern for fresh execution")
    if target_runtime_type(target_doc) != "docker":
        raise VerifierError("fresh execution currently supports only the ordinary docker runtime")
    _match_target_entrypoint(target_doc, candidate_doc)

    explicit_repo_root = getattr(args, "repo_root", None)
    repo_root = _target_repo_root(target_path, target_doc, explicit_repo_root)
    if explicit_repo_root is not None:
        try:
            workspace.relative_to(repo_root)
        except ValueError as exc:
            raise VerifierError("workspace must be inside the target repository root") from exc
        if workspace == repo_root:
            raise VerifierError("workspace may not equal the target repository root")
    tested_commit = execution_input["tested_commit"]
    head_commit = _resolve_commit(repo_root, "HEAD")
    target_commit = _resolve_commit(repo_root, target_doc.get("target", {}).get("tested_ref"))
    if tested_commit != head_commit or tested_commit != target_commit:
        raise VerifierError("tested_commit must equal Candidate R2 identity, resolved target tested_ref, and checked-out HEAD")

    contents = _read_git_tree(repo_root, tested_commit)
    _validate_source_refs(repo_root, contents, execution_input["source_refs"])
    poc_relative = _safe_relative(candidate_doc.get("poc", {}).get("path"), "candidate poc.path")
    if PurePosixPath(poc_relative).suffix != ".py":
        raise VerifierError("fresh execution requires a regular .py candidate PoC")
    poc_original_path = workspace / PurePosixPath(poc_relative)
    try:
        poc_raw = safe_read_bytes(workspace, poc_original_path)
    except SafeEvidenceError as exc:
        raise VerifierError(f"candidate PoC cannot be read safely ({exc.code})") from exc
    if _sha256(poc_raw) != execution_input["poc_sha256"]:
        raise VerifierError("execution input poc_sha256 does not match the candidate PoC")

    try:
        baseline = read_workspace_snapshot(workspace, mode_policy="r2")
    except AuditStateError as exc:
        raise VerifierError(f"fresh execution requires a valid synchronized R2 journal/state ({exc.code})") from exc
    if baseline.mode != "r2" or baseline.state is None:
        raise VerifierError("fresh execution requires an R2 workspace state")
    if baseline.state.get("stage") != "verification" or baseline.state.get("status") != "running":
        raise VerifierError("fresh execution requires synchronized verification/running state")
    baseline_revision = baseline.state.get("state_revision")
    if type(baseline_revision) is not int or baseline_revision != len(baseline.journal.events):
        raise VerifierError("fresh execution journal revision is inconsistent")
    baseline_digest = _sha256(baseline.journal.raw_bytes)

    candidate_id = candidate_doc["candidate_id"]
    verdict_root = workspace / "verifier" / candidate_id
    out_path = verdict_root / "verifier-verdict.json"
    if args.out:
        explicit_out = _cli_file_under_workspace(args.out, workspace, "verifier verdict output")
        if explicit_out != out_path:
            raise VerifierError("fresh execution --out must resolve to the canonical verifier verdict path")
    candidate_digest = execution_input["candidate_sha256"]
    case_id = _case_id_for(candidate_digest, run_id)
    run_dir = verdict_root / "runs" / run_id
    case_dir = workspace / "evidence" / case_id
    snapshot_dir = workspace / "poc" / run_id
    for path, label in (
        (out_path, "verifier verdict"),
        (run_dir, "verifier run"),
        (case_dir, "Docker case evidence"),
        (snapshot_dir, "PoC snapshot"),
    ):
        _assert_absent_destination(workspace, path, label)

    _create_fresh_directory(workspace, run_dir, "verifier run directory")
    _create_fresh_directory(workspace, case_dir, "Docker case directory")
    source_root, snapshot_manifest = _snapshot_git_tree(workspace, run_id, contents)
    snapshot_poc_dir = snapshot_dir / "poc"
    _create_fresh_directory(workspace, snapshot_poc_dir, "PoC snapshot directory")
    snapshot_poc = snapshot_poc_dir / "reproduce.py"
    _write_exclusive_bytes(workspace, snapshot_poc, poc_raw, mode=0o444)
    os.chmod(snapshot_poc_dir, 0o500)

    input_copy_dir = run_dir / "inputs"
    _create_fresh_directory(workspace, input_copy_dir, "pre-run input directory")
    execution_input_copy_path = input_copy_dir / "execution-input.json"
    input_copies = {
        "execution-input.json": input_raw,
        "candidate.json": candidate_raw,
        "target-config.raw": target_raw,
        "poc.py": poc_raw,
    }
    for name, raw in input_copies.items():
        _write_exclusive_bytes(workspace, input_copy_dir / name, raw)
    manifest_doc = {
        "schema_version": 1,
        "tested_commit": tested_commit,
        "files": snapshot_manifest,
    }
    manifest_raw = (json.dumps(manifest_doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    manifest_path = run_dir / "source-manifest.json"
    _write_exclusive_bytes(workspace, manifest_path, manifest_raw)

    run_binding_path = run_dir / "run-binding.json"
    _write_exclusive_bytes(workspace, run_binding_path, b"", reservations=reservations)
    _write_exclusive_bytes(workspace, out_path, b"", reservations=reservations)
    assert_publish_target_safe(workspace, run_binding_path)
    assert_publish_target_safe(workspace, out_path)

    container_poc = f"/workspace/poc/{run_id}/poc/reproduce.py"
    container_source = f"/workspace/poc/{run_id}/source"
    container_argv = ["python3", "-I", container_poc, "--source-root", container_source]
    wrapper = Path(__file__).resolve().parent / "run_verification_case.sh"
    wrapper_command = [
        "bash", str(wrapper),
        "--workspace-dir", str(workspace),
        "--case-id", case_id,
        "--mode", "docker-run",
        "--image", execution_input["image_ref"],
        "--timeout-seconds", "300",
        "--expected-oracle", execution_input["oracle"]["pattern"],
        "--network", "none",
        "--", *container_argv,
    ]
    wrapper_exit, _wrapper_stdout, _wrapper_stderr, wrapper_timed_out = _run_wrapper(wrapper_command)
    if wrapper_timed_out or wrapper_exit != 0:
        raise VerifierError("production Docker wrapper did not return a clean zero exit")

    expected_case_paths = {
        "command": case_dir / "command.json",
        "result": case_dir / "verification-result.json",
        "stdout": case_dir / "stdout.log",
        "stderr": case_dir / "stderr.log",
    }
    try:
        output_raw = {
            key: safe_read_bytes(
                workspace,
                path,
                max_bytes=MAX_CAPTURE_BYTES if key in {"stdout", "stderr"} else MAX_CONTROL_BYTES,
            )
            for key, path in expected_case_paths.items()
        }
    except SafeEvidenceError as exc:
        raise VerifierError(f"wrapper output is missing or unsafe ({exc.code})") from exc
    receipt_paths = sorted(case_dir.glob("docker-case-receipt-*.json"))
    if len(receipt_paths) != 1:
        raise VerifierError("Docker wrapper did not produce exactly one lifecycle receipt")
    receipt_path = receipt_paths[0]
    try:
        receipt_raw = safe_read_bytes(workspace, receipt_path)
    except SafeEvidenceError as exc:
        raise VerifierError(f"Docker lifecycle receipt is unsafe ({exc.code})") from exc
    regex = re.compile(execution_input["oracle"]["pattern"], flags=re.MULTILINE)
    result_doc, receipt_doc = _checked_wrapper_result(
        workspace,
        case_id,
        container_argv,
        regex,
        execution_input["review"]["observation"],
        output_raw["result"],
        output_raw["command"],
        output_raw["stdout"],
        output_raw["stderr"],
        receipt_raw,
    )
    if result_doc.get("image") != execution_input["image_ref"] or receipt_doc.get("case_id") != case_id:
        raise VerifierError("wrapper result or receipt does not bind the requested local image and case")
    if result_doc.get("stdout_path") != f"evidence/{case_id}/stdout.log" or result_doc.get("stderr_path") != f"evidence/{case_id}/stderr.log":
        raise VerifierError("wrapper result output paths do not match the fresh case")

    # Re-read every authority input and the entire read-only source snapshot.
    try:
        candidate_after = safe_read_bytes(workspace, candidate_path)
        target_after = safe_read_bytes(workspace, target_path)
        input_after = safe_read_bytes(workspace, input_path)
        poc_after = safe_read_bytes(workspace, poc_original_path)
        input_copy_after = safe_read_bytes(workspace, execution_input_copy_path)
    except SafeEvidenceError as exc:
        raise VerifierError(f"a bound input changed or became unsafe during execution ({exc.code})") from exc
    if (candidate_after, target_after, input_after, poc_after, input_copy_after) != (
        candidate_raw, target_raw, input_raw, poc_raw, input_raw,
    ):
        raise VerifierError("candidate, target, execution input, preserved input copy, or original PoC changed during execution")
    _validate_source_refs(repo_root, contents, execution_input["source_refs"])
    _verify_snapshot_unchanged(workspace, source_root, snapshot_manifest)
    start_event, completion_event, journal_prefix_sha256 = _verify_journal_suffix(workspace, baseline, case_id)

    run_binding = {
        "schema_version": 1,
        "run_id": run_id,
        "case_id": case_id,
        "candidate_path": candidate_path.relative_to(workspace).as_posix(),
        "candidate_sha256": _sha256(candidate_raw),
        "target_config_path": target_path.relative_to(workspace).as_posix(),
        "target_config_sha256": _sha256(target_raw),
        "execution_input_path": input_path.relative_to(workspace).as_posix(),
        "execution_input_sha256": _sha256(input_raw),
        "poc_sha256": _sha256(poc_raw),
        "tested_commit": tested_commit,
        "source_snapshot": {
            "path": source_root.relative_to(workspace).as_posix(),
            "manifest_path": manifest_path.relative_to(workspace).as_posix(),
            "manifest_sha256": _sha256(manifest_raw),
        },
        "container_argv": container_argv,
        "journal": {
            "baseline_revision": baseline_revision,
            "baseline_sha256": baseline_digest,
            "start_seq": start_event["seq"],
            "completion_seq": completion_event["seq"],
            "validated_prefix_sha256": journal_prefix_sha256,
        },
        "output_digests": {
            expected_case_paths[key].relative_to(workspace).as_posix(): _sha256(raw)
            for key, raw in output_raw.items()
        } | {receipt_path.relative_to(workspace).as_posix(): _sha256(receipt_raw)},
    }
    binding_rollback_stats: list[os.stat_result] = []
    try:
        atomic_write_json(
            workspace,
            run_binding_path,
            run_binding,
            expected_target_identity=_reservation_identity(reservations, run_binding_path),
            rollback_stat_sink=binding_rollback_stats,
        )
        _mark_reservation_published(reservations, run_binding_path)
        binding_disk = safe_read_bytes(workspace, run_binding_path)
    except SafeEvidenceError as exc:
        _adopt_verified_rollback_identity(reservations, run_binding_path, binding_rollback_stats)
        raise VerifierError(f"run binding could not be published safely ({exc.code})") from exc
    binding_doc = _parse_json_object(binding_disk, "run binding")
    if binding_doc != run_binding:
        raise VerifierError("durable run binding bytes do not match the verified inputs")

    review = execution_input["review"]
    refs_summary = "; ".join(
        f"{item['id']} ({item['path']}:{item['line_start']}-{item['line_end']}, token {item['token']})"
        for item in execution_input["source_refs"]
    )
    observation = review["observation"]
    attacker_entrypoint = {
        "id": candidate_doc["entrypoint"]["id"],
        "kind": candidate_doc["entrypoint"]["kind"],
        "route": normalize_entrypoint(candidate_doc["entrypoint"])["route"],
        "input_shape": review["input_shape"],
        "entrypoint_to_sink_path": f"Reviewed source references: {refs_summary}. {review['source_to_sink']}",
        "deterministic_impact_oracle": (
            f"The reviewed log_pattern {json.dumps(execution_input['oracle']['pattern'], ensure_ascii=False)} matched "
            f"{observation['stream']} observation "
            f"{observation['exact']!r}. {review['impact_interpretation']}"
        ),
    }
    artifacts = [
        run_binding_path.relative_to(workspace).as_posix(),
        manifest_path.relative_to(workspace).as_posix(),
        execution_input_copy_path.relative_to(workspace).as_posix(),
        snapshot_poc.relative_to(workspace).as_posix(),
        *[path.relative_to(workspace).as_posix() for path in expected_case_paths.values()],
        receipt_path.relative_to(workspace).as_posix(),
    ]
    verdict = base_verdict(
        target_doc=target_doc,
        candidate=candidate_doc,
        candidate_path=candidate_path,
        verdict="confirmed_in_docker",
        oracle_type="log_pattern",
        oracle_success=True,
        reason="One fresh network-none Docker execution matched the reviewed observation; source semantics remain reviewer judgment.",
        commands=[{"name": "fresh Docker PoC command", "command": json.dumps(container_argv, ensure_ascii=False), "exit_code": 0}],
        artifacts=artifacts,
        evidence_level="confirmed_in_docker",
        attacker_entrypoint=attacker_entrypoint,
        replay_material={
            "description": review["replay_material"],
            "path": snapshot_poc.relative_to(workspace).as_posix(),
        },
    )
    verdict["environment"]["egress_policy"] = "none"
    verdict_raw = (json.dumps(verdict, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")

    def validate_published(raw: bytes) -> None:
        checked = _parse_json_object(raw, "published verifier verdict")
        try:
            validate_verdict(checked)
            cross_check_candidate(candidate_path, checked)
        except VerdictValidationError as exc:
            raise VerifierError(f"published verifier verdict failed validation: {exc}") from exc

    verdict_rollback_stats: list[os.stat_result] = []
    try:
        atomic_write_bytes(
            workspace,
            out_path,
            verdict_raw,
            expected_target_identity=_reservation_identity(reservations, out_path),
            post_write_validator=validate_published,
            rollback_stat_sink=verdict_rollback_stats,
        )
        _mark_reservation_published(reservations, out_path)
        verdict_disk = safe_read_bytes(workspace, out_path)
    except (SafeEvidenceError, VerifierError) as exc:
        _adopt_verified_rollback_identity(reservations, out_path, verdict_rollback_stats)
        code = exc.code if isinstance(exc, SafeEvidenceError) else "VERDICT_INVALID"
        raise VerifierError(f"fresh verifier verdict publication failed ({code})") from exc
    if verdict_disk != verdict_raw:
        raise VerifierError("published verifier verdict differs from the validated bytes")
    validate_published(verdict_disk)
    print("verdict=confirmed_in_docker")
    print(f"verifier_verdict={out_path}")
    return 0


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

    if args.repo_root is not None and not (args.allow_execute and args.execution_input):
        print("ERROR: --repo-root is only supported with fresh --allow-execute", file=sys.stderr)
        return 1

    if args.allow_execute or args.execution_input:
        try:
            if args.dry_run or args.no_execute or args.dry_run_result:
                raise VerifierError("fresh execution cannot be combined with dry-run, no-execute, or dry-run-result")
            if not args.allow_execute:
                raise VerifierError("--execution-input requires --allow-execute")
            if not args.execution_input:
                raise VerifierError("--execution-input is required with --allow-execute")
            if not args.run_id:
                raise VerifierError("fresh execution requires an explicit --run-id")
            workspace = _canonical_owned_directory(Path(args.workspace), "workspace")
            args.workspace = str(workspace)
            target_doc, candidate, *_rest = _load_fresh_inputs(args, workspace)
            return execute_fresh_verification(args, target_doc, candidate)
        except VerifierError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    workspace = Path(args.workspace).expanduser().resolve()
    run_id = safe_run_id(args.run_id or DEFAULT_RUN_ID)

    try:
        candidate = load_candidate_identity(candidate_path)
        candidate_id = candidate["candidate_id"]
        verifier_root = require_under(workspace / "verifier" / candidate_id, workspace, "verifier directory")
        run_dir = require_under(verifier_root / "diagnostics" / run_id, workspace, "verifier diagnostic directory")
        out_path = Path(args.out).expanduser() if args.out else run_dir / "verifier-diagnostic.json"
        out_path = require_under(out_path if out_path.is_absolute() else Path.cwd() / out_path, workspace, "verifier verdict output")
        if args.out and out_path.name == "verifier-verdict.json":
            raise VerifierError("non-execution --out cannot name an authority artifact")
        try:
            _create_fresh_directory(workspace, run_dir, "verifier diagnostic directory")
        except VerifierError as exc:
            if "FileExistsError" in str(exc):
                raise VerifierError("diagnostic destination already exists") from exc
            raise

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
            print(f"verifier_diagnostic={out_path}")
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
            print(f"verifier_diagnostic={out_path}")
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
            print(f"verifier_diagnostic={out_path}")
            return 1

        verdict = build_verdict(args=args, workspace=workspace, run_dir=run_dir, target_doc=target_doc, candidate=candidate, candidate_path=candidate_path)
        write_and_validate(verdict, out_path, candidate_path)
    except VerifierError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"verdict={verdict['verdict']}")
    print(f"verifier_diagnostic={out_path}")
    return 0 if verdict["verdict"] == "confirmed_in_docker" else 1


if __name__ == "__main__":
    raise SystemExit(main())
