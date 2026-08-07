"""Deterministic, advisory-only next-action derivation for a Zhulong workspace.

This module deliberately has no process execution path.  It consumes the
current handoff snapshot and the already validated structured candidate,
verdict, Recon and journal material.  Its output is an index of suggestions,
not an audit state transition or any kind of confirmation authority.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from audit_state_io import AuditStateError, read_normalized_workspace_events
from workspace_state import (
    HANDOFF_STATE_FILENAME,
    _atomic_write_contract,
    _canonical_json_bytes,
    _safe_workspace_path,
    derive_handoff_state,
    read_handoff_state,
    validate_handoff_state_current,
)


NEXT_ACTIONS_FILENAME = "next-actions.json"
SCHEMA_VERSION = 1
BLOCKING_CODES = (
    "HANDOFF_STALE", "ENTRYPOINT_CHAIN_INCOMPLETE", "TRUST_BOUNDARY_REVIEW_INCOMPLETE",
    "VERDICT_MISSING", "DOCKER_ORACLE_UNPROVEN", "REPLAY_MATERIAL_MISSING",
    "SEVERITY_ESCALATION_PENDING", "SEEDED_VARIANT_DISCOVERY_PENDING",
    "DOCKER_CLEANUP_INCOMPLETE", "FINALIZATION_EVENT_MISSING",
)
ENTRYPOINTS = {
    "render_handoff_state", "validate_recon_result", "verify_candidate",
    "validate_report_bundle", "validate_all_report_bundles", "extract_variant_seed",
    "find_variant_candidates", "manage_docker_resources_review",
    "finalize_audit_workspace", "manual_review",
}
_PRIORITY = {
    "HANDOFF_STALE": "critical", "ENTRYPOINT_CHAIN_INCOMPLETE": "high",
    "TRUST_BOUNDARY_REVIEW_INCOMPLETE": "high", "VERDICT_MISSING": "high",
    "DOCKER_ORACLE_UNPROVEN": "high", "REPLAY_MATERIAL_MISSING": "high",
    "SEVERITY_ESCALATION_PENDING": "normal", "SEEDED_VARIANT_DISCOVERY_PENDING": "normal",
    "DOCKER_CLEANUP_INCOMPLETE": "high", "FINALIZATION_EVENT_MISSING": "normal",
}


class NextActionsError(AuditStateError):
    """Stable fail-closed error for next-action derivation."""


def _error(code: str, message: str) -> NextActionsError:
    return NextActionsError(code, message)


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load_authoritative_json(workspace: Path, relative: str) -> tuple[dict[str, Any], str]:
    path = _safe_workspace_path(workspace, relative, field=relative, allow_missing=False, expected="file")
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise _error("AUTHORITY_INVALID", "structured authority artifact is unreadable") from exc
    if not isinstance(value, dict):
        raise _error("AUTHORITY_INVALID", "structured authority artifact must be an object")
    return value, _sha256(raw)


def _fact(path: str, digest: str, fact: str) -> dict[str, str]:
    return {"fact": fact, "path": path, "sha256": digest}


def _entrypoint(name: str, parameters: list[dict[str, str]] | None = None) -> dict[str, Any]:
    if name not in ENTRYPOINTS:
        raise _error("ENTRYPOINT_UNSAFE", "suggested entrypoint is not allowlisted")
    params = parameters or []
    return {"name": name, "parameters": sorted(params, key=lambda item: (item["name"], item["value"]))}


def _action(
    code: str, subject: dict[str, Any], *, entrypoint: str, outputs: list[dict[str, str]],
    facts: list[dict[str, str]], evidence: list[str], parameters: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    if code not in BLOCKING_CODES:
        raise _error("BLOCKING_CODE_INVALID", "unknown blocking code")
    subject_key = f"{subject['kind']}:{subject['id']}:{subject.get('path') or ''}"
    action_id = "ACT-" + code + "-" + hashlib.sha256(subject_key.encode("utf-8")).hexdigest()[:16]
    return {
        "action_id": action_id,
        "subject": subject,
        "blocking_code": code,
        "priority": _PRIORITY[code],
        "required_outputs": sorted(outputs, key=lambda item: (item["kind"], item["path"])),
        "suggested_entrypoint": _entrypoint(entrypoint, parameters),
        "fact_basis": sorted(facts, key=lambda item: (item["fact"], item["path"], item["sha256"])),
        "evidence_refs": sorted(set(evidence)),
    }


def _candidate_facts(workspace: Path, handoff: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Revalidate only handoff-indexed candidate/verdict inputs for per-ID facts."""
    artifacts = handoff.get("artifacts")
    if not isinstance(artifacts, list):
        raise _error("AUTHORITY_INVALID", "handoff artifact index is invalid")
    candidate_docs: dict[str, dict[str, Any]] = {}
    verdict_docs: dict[str, dict[str, Any]] = {}
    for item in artifacts:
        if not isinstance(item, dict) or item.get("kind") not in {"candidate", "verdict"}:
            continue
        relative = item.get("path")
        digest = item.get("sha256")
        if not isinstance(relative, str) or not isinstance(digest, str):
            raise _error("AUTHORITY_INVALID", "candidate or verdict artifact index is invalid")
        document, actual_digest = _load_authoritative_json(workspace, relative)
        if actual_digest != digest:
            raise _error("AUTHORITY_DRIFT", "candidate or verdict artifact digest drifted")
        try:
            if item["kind"] == "candidate":
                from validate_candidate import validate_candidate
                checked = validate_candidate(document)
                candidate_docs[str(checked["candidate_id"])] = {"path": relative, "sha256": digest, "document": document}
            else:
                from validate_verifier_verdict import validate_verdict
                checked = validate_verdict(document)
                verdict_docs[str(checked["candidate_id"])] = {"path": relative, "sha256": digest, "document": document}
        except Exception as exc:
            raise _error("AUTHORITY_INVALID", "candidate or verifier verdict failed its existing validator") from exc
    for candidate_id, verdict in verdict_docs.items():
        candidate = candidate_docs.get(candidate_id)
        if candidate is None:
            raise _error("AUTHORITY_INVALID", "verifier verdict lacks an indexed candidate")
        try:
            from validate_verifier_verdict import cross_check_candidate
            cross_check_candidate(workspace / candidate["path"], verdict["document"])
        except Exception as exc:
            raise _error("AUTHORITY_INVALID", "candidate and verifier verdict disagree") from exc
    return {candidate_id: {**candidate, "verdict": verdict_docs.get(candidate_id)} for candidate_id, candidate in candidate_docs.items()}


def _recon_actions(workspace: Path, handoff: dict[str, Any]) -> list[dict[str, Any]]:
    recon = handoff.get("recon") if isinstance(handoff.get("recon"), dict) else {}
    if recon.get("status") not in {"partial", "blocked"} or not isinstance(recon.get("path"), str) or not isinstance(recon.get("sha256"), str):
        return []
    document, digest = _load_authoritative_json(workspace, recon["path"])
    if digest != recon["sha256"] or not isinstance(document.get("coverage"), dict):
        raise _error("AUTHORITY_DRIFT", "validated Recon material drifted")
    recon_id = str(document.get("recon_id") or "RECON-UNKNOWN")
    base = [_fact(recon["path"], digest, "validated_recon_result")]
    subject = {"kind": "recon", "id": recon_id, "path": recon["path"]}
    actions: list[dict[str, Any]] = []
    coverage = document["coverage"]
    if isinstance(coverage.get("public_entrypoints"), dict) and coverage["public_entrypoints"].get("status") == "unknown":
        actions.append(_action("ENTRYPOINT_CHAIN_INCOMPLETE", subject, entrypoint="validate_recon_result", outputs=[{"kind": "recon_result", "path": recon["path"]}], facts=base, evidence=[recon["path"]]))
    if isinstance(coverage.get("trust_boundaries"), dict) and coverage["trust_boundaries"].get("status") == "unknown":
        actions.append(_action("TRUST_BOUNDARY_REVIEW_INCOMPLETE", subject, entrypoint="validate_recon_result", outputs=[{"kind": "recon_result", "path": recon["path"]}], facts=base, evidence=[recon["path"]]))
    return actions


def _derive_actions(workspace: Path, handoff: dict[str, Any]) -> list[dict[str, Any]]:
    if handoff.get("integrity", {}).get("overall") != "valid":
        raise _error("AUTHORITY_INVALID", "current authority has unresolved integrity issues")
    actions = _recon_actions(workspace, handoff)
    candidates = _candidate_facts(workspace, handoff)
    for candidate_id in sorted(candidates):
        candidate = candidates[candidate_id]
        subject = {"kind": "candidate", "id": candidate_id, "path": candidate["path"]}
        candidate_fact = _fact(candidate["path"], candidate["sha256"], "validated_candidate")
        verdict = candidate["verdict"]
        if verdict is None:
            actions.append(_action("VERDICT_MISSING", subject, entrypoint="verify_candidate", outputs=[{"kind": "verifier_verdict", "path": "evidence/verification/" + candidate_id + "/verifier-verdict.json"}], facts=[candidate_fact], evidence=[candidate["path"]], parameters=[{"name": "candidate_id", "value": candidate_id}]))
            continue
        verdict_doc = verdict["document"]
        verdict_fact = _fact(verdict["path"], verdict["sha256"], "validated_verifier_verdict")
        if verdict_doc.get("evidence_level") in {"code_level_reproduced", "blocked_entrypoint_verification"} or verdict_doc.get("verification_status") == "blocked":
            actions.append(_action("DOCKER_ORACLE_UNPROVEN", subject, entrypoint="verify_candidate", outputs=[{"kind": "verifier_verdict", "path": verdict["path"]}], facts=[candidate_fact, verdict_fact], evidence=[candidate["path"], verdict["path"]], parameters=[{"name": "candidate_id", "value": candidate_id}]))
        if verdict_doc.get("verdict") == "confirmed_in_docker":
            _status, events, _mode = read_normalized_workspace_events(workspace)
            if not any(event.get("stage") == "severity_escalation" and event.get("status") == "completed" for event in events):
                actions.append(_action("SEVERITY_ESCALATION_PENDING", subject, entrypoint="manual_review", outputs=[{"kind": "severity_evidence", "path": "evidence/verification/" + candidate_id + "/"}], facts=[candidate_fact, verdict_fact], evidence=[candidate["path"], verdict["path"]]))
            replay = verdict_doc.get("replay_material")
            if not isinstance(replay, dict) or not isinstance(replay.get("path"), str):
                actions.append(_action("REPLAY_MATERIAL_MISSING", subject, entrypoint="manual_review", outputs=[{"kind": "replay_material", "path": "evidence/verification/" + candidate_id + "/"}], facts=[candidate_fact, verdict_fact], evidence=[candidate["path"], verdict["path"]]))
    counts = handoff.get("counts") if isinstance(handoff.get("counts"), dict) else {}
    variant = handoff.get("variant_analysis") if isinstance(handoff.get("variant_analysis"), dict) else {}
    if int(counts.get("validated_confirmed_bundles") or 0) > 0 and variant.get("status") in {"not_executed", "invalid"}:
        actions.append(_action("SEEDED_VARIANT_DISCOVERY_PENDING", {"kind": "workspace", "id": "WORKSPACE", "path": None}, entrypoint="extract_variant_seed", outputs=[{"kind": "variant_seed", "path": "evidence/variant-analysis/seeds.jsonl"}, {"kind": "variant_candidates", "path": "evidence/variant-analysis/variant-candidates.jsonl"}], facts=[_fact(str(variant.get("path") or "confirmed"), str(variant.get("sha256") or handoff["integrity"]["authoritative_digest"]), "validated_confirmed_bundle_count")], evidence=["confirmed"],))
    docker = handoff.get("docker") if isinstance(handoff.get("docker"), dict) else {}
    if docker.get("status") in {"dirty", "unclean", "failed"}:
        actions.append(_action("DOCKER_CLEANUP_INCOMPLETE", {"kind": "workspace", "id": "WORKSPACE", "path": None}, entrypoint="manage_docker_resources_review", outputs=[{"kind": "docker_cleanliness", "path": "docker/docker-cleanliness-status.json"}], facts=[_fact(str(docker.get("path") or "docker/docker-cleanliness-status.json"), str(docker.get("sha256") or handoff["integrity"]["authoritative_digest"]), "strict_docker_cleanliness")], evidence=[str(docker.get("path") or "docker/docker-cleanliness-status.json")]))
    finalization = handoff.get("finalization") if isinstance(handoff.get("finalization"), dict) else {}
    verdict_complete = all(item["verdict"] is not None for item in candidates.values())
    if handoff.get("stage") == "finalization" and handoff.get("status") == "running" and verdict_complete and handoff.get("disposition", {}).get("status") == "valid" and docker.get("status") == "clean" and finalization.get("status") == "not_finalized":
        actions.append(_action("FINALIZATION_EVENT_MISSING", {"kind": "workspace", "id": "WORKSPACE", "path": None}, entrypoint="finalize_audit_workspace", outputs=[{"kind": "finalization_event", "path": "audit-events.jsonl"}], facts=[_fact("audit-events.jsonl", handoff["integrity"]["journal_digest"], "authoritative_event_journal"), _fact("audit-disposition.json", str(handoff["disposition"].get("sha256")), "validated_disposition"), _fact(str(docker.get("path")), str(docker.get("sha256")), "strict_docker_cleanliness")], evidence=["audit-events.jsonl", "audit-disposition.json", str(docker.get("path"))]))
    return sorted(actions, key=lambda item: (_PRIORITY[item["blocking_code"]], item["blocking_code"], item["subject"]["kind"], item["subject"]["id"], item["action_id"]))


def derive_next_actions(workspace: Path, repo_root: Path | None = None) -> dict[str, Any]:
    workspace = workspace.absolute()
    repo_root = (repo_root or workspace.parent).absolute()
    handoff = read_handoff_state(workspace)
    actions = _derive_actions(workspace, handoff)
    raw_handoff = (workspace / HANDOFF_STATE_FILENAME).read_bytes()
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_from_revision": handoff["generated_from_revision"],
        "generated_from_event_sequence": handoff["generated_from_event_sequence"],
        "tested_ref": handoff["tested_ref"],
        "protocol_mode": handoff["protocol_mode"],
        "handoff_state_sha256": _sha256(raw_handoff),
        "classification": "action_required" if actions else "no_action",
        "actions": actions,
        "integrity": {"journal_digest": handoff["integrity"]["journal_digest"], "state_digest": handoff["integrity"]["state_digest"], "authoritative_digest": handoff["integrity"]["authoritative_digest"], "snapshot_consistent": True},
    }


def _stale_document(workspace: Path, repo_root: Path) -> dict[str, Any]:
    current = derive_handoff_state(workspace, repo_root)
    if current.get("integrity", {}).get("overall") != "valid":
        raise _error("AUTHORITY_INVALID", "authority is invalid; stale handoff cannot be safely repaired")
    raw = (workspace / HANDOFF_STATE_FILENAME).read_bytes() if (workspace / HANDOFF_STATE_FILENAME).is_file() else b""
    action = _action("HANDOFF_STALE", {"kind": "workspace", "id": "WORKSPACE", "path": None}, entrypoint="render_handoff_state", outputs=[{"kind": "handoff_state", "path": HANDOFF_STATE_FILENAME}], facts=[_fact("audit-events.jsonl", current["integrity"]["journal_digest"], "authoritative_event_journal"), _fact("stage-status.json", current["integrity"]["state_digest"], "derived_state_view")], evidence=["audit-events.jsonl", "stage-status.json"])
    return {"schema_version": SCHEMA_VERSION, "generated_from_revision": current["generated_from_revision"], "generated_from_event_sequence": current["generated_from_event_sequence"], "tested_ref": current["tested_ref"], "protocol_mode": current["protocol_mode"], "handoff_state_sha256": _sha256(raw), "classification": "action_required", "actions": [action], "integrity": {"journal_digest": current["integrity"]["journal_digest"], "state_digest": current["integrity"]["state_digest"], "authoritative_digest": current["integrity"]["authoritative_digest"], "snapshot_consistent": True}}


def generate_next_actions(workspace: Path, repo_root: Path | None = None, *, write: bool = True) -> dict[str, Any]:
    workspace = workspace.absolute(); repo_root = (repo_root or workspace.parent).absolute()
    check = validate_handoff_state_current(workspace, repo_root)
    stale_codes = {"HANDOFF_STATE_MISSING", "HANDOFF_STALE_REVISION", "HANDOFF_STALE_EVENT_SEQUENCE", "HANDOFF_TESTED_REF_DRIFT", "HANDOFF_ARTIFACT_DIGEST_DRIFT", "HANDOFF_COUNT_ID_DRIFT", "HANDOFF_JOURNAL_DIGEST_DRIFT", "HANDOFF_STATE_DIGEST_DRIFT", "HANDOFF_DERIVED_FIELD_DRIFT"}
    if check.get("ok"):
        document = derive_next_actions(workspace, repo_root)
        after = validate_handoff_state_current(workspace, repo_root)
        if not after.get("ok"):
            raise _error("CONCURRENT_STATE_CHANGED", "authority changed during next-action derivation")
    elif set(check.get("issue_codes") or []) & stale_codes:
        document = _stale_document(workspace, repo_root)
    else:
        raise _error("AUTHORITY_INVALID", "handoff or authority inputs are not safely verifiable")
    if write:
        _atomic_write_contract(workspace / NEXT_ACTIONS_FILENAME, _canonical_json_bytes(document), workspace, fault_prefix="NEXT_ACTIONS")
    return document


def validate_next_actions_current(workspace: Path, repo_root: Path | None = None) -> dict[str, Any]:
    workspace = workspace.absolute(); repo_root = (repo_root or workspace.parent).absolute()
    try:
        path = _safe_workspace_path(workspace, NEXT_ACTIONS_FILENAME, field=NEXT_ACTIONS_FILENAME, allow_missing=False, expected="file")
        actual = json.loads(path.read_text(encoding="utf-8"))
        expected = generate_next_actions(workspace, repo_root, write=False)
    except (AuditStateError, OSError, UnicodeError, ValueError) as exc:
        return {
            "ok": False,
            "issue_codes": [getattr(exc, "code", "NEXT_ACTIONS_UNVERIFIABLE")],
            "issues": [{"code": getattr(exc, "code", "NEXT_ACTIONS_UNVERIFIABLE")}],
        }
    if actual != expected:
        return {"ok": False, "issue_codes": ["NEXT_ACTIONS_DRIFT"], "issues": [{"code": "NEXT_ACTIONS_DRIFT"}]}
    return {"ok": True, "issue_codes": [], "issues": []}
