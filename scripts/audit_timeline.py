#!/usr/bin/env python3
"""Deterministic, derived-only audit timeline projection and static renderer."""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import stat
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

from audit_text_safety import first_sensitive_r2_event_text, sensitive_value_kind
from audit_state_io import AuditStateError, normalize_event, read_workspace_snapshot, workspace_lock
from workspace_state import (
    HANDOFF_STATE_FILENAME,
    _canonical_json_bytes,
    _discover_named_files,
    _safe_workspace_path,
    derive_handoff_state,
    inspect_confirmed_bundles,
    validate_handoff_state_current,
)


SCHEMA_VERSION = 1
PROJECTION_KIND = "derived_read_only_audit_timeline"
NON_AUTHORITY_STATEMENT = (
    "This offline timeline is a derived review view. It is not an authority source "
    "and grants no confirmation, disposition, execution, promotion, or finalization permission."
)
NON_CLAIMS = [
    "It does not prove that an Agent read any referenced material.",
    "It does not contain hidden reasoning or conversation content.",
    "It does not run Docker, PoC, replay, scanners, network requests, models, or Agents.",
    "Confirmed status still requires the existing verdict, disposition, Docker, and bundle validators.",
]
JSON_BASENAME = "audit-timeline.json"
HTML_BASENAME = "audit-timeline.html"
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "assets/schemas/audit-timeline.schema.json"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,159}$")
ISSUE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,79}$")
URI_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
WINDOWS_RE = re.compile(r"^[A-Za-z]:[\\/]")
BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
DANGEROUS_MARKUP_RE = re.compile(
    r"(?:<\s*/?\s*(?:script|style|iframe|object|embed|form)\b|javascript\s*:|"
    r"data\s*:\s*text/html|on(?:error|load|click|focus)\s*=)",
    re.I,
)
PROHIBITED_KEYS = {
    "prompt", "prompts", "chat", "conversation", "reasoning", "thought",
    "transcript", "token_usage", "environment", "credentials", "secret",
    "session_id", "model_name", "hostname", "username", "cwd", "pid",
}
HTML_ALLOWED_TAGS = {
    "a", "body", "br", "code", "dd", "dl", "dt", "h1", "h2", "head",
    "html", "li", "main", "meta", "ol", "p", "span", "strong", "style",
    "table", "tbody", "td", "th", "thead", "title", "tr", "ul",
}
HTML_ALLOWED_ATTRIBUTES = {
    "a": {"href"},
    "html": {"lang"},
    "meta": {"charset", "content", "http-equiv", "name"},
    "ol": {"class"},
    "p": {"class"},
    "span": {"class"},
    "td": {"class", "colspan"},
    "th": {"colspan"},
}
HTML_URI_ATTRIBUTES = {"href", "src", "action", "formaction", "poster", "data"}
HTML_VOID_TAGS = {"br", "meta"}
HTML_EXTERNAL_TAGS = {
    "applet", "audio", "base", "embed", "form", "frame", "iframe", "img",
    "link", "object", "video",
}
EXPECTED_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
    "base-uri 'none'; form-action 'none'"
)


class TimelineError(AuditStateError):
    """Stable fail-closed error for timeline derivation and publication."""


def _error(code: str, message: str, **fields: Any) -> TimelineError:
    return TimelineError(code, message, **fields)


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _issue(code: str, message: str, path: str | None = None) -> dict[str, Any]:
    return {"code": code, "message": message, "path": path}


def _safe_text(value: Any, field: str, *, limit: int = 240, allow_markup: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _error("TIMELINE_TEXT_INVALID", f"{field} must be non-empty text")
    text = value.strip()
    if len(text) > limit:
        raise _error("TIMELINE_TEXT_INVALID", f"{field} exceeds its length limit")
    if "\x00" in text or BIDI_RE.search(text):
        raise _error("TIMELINE_TEXT_UNSAFE", f"{field} contains unsafe control text")
    sensitive_kind = sensitive_value_kind(text)
    if sensitive_kind is not None:
        raise _error(
            "TIMELINE_SENSITIVE_TEXT",
            f"{field} contains sensitive material of category {sensitive_kind}",
        )
    if not allow_markup and DANGEROUS_MARKUP_RE.search(text):
        raise _error("TIMELINE_HTML_INJECTION", f"{field} contains active-markup-like text")
    return text


def _safe_optional_text(value: Any, field: str, *, limit: int = 240) -> str | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    return _safe_text(value, field, limit=limit)


def _safe_path_text(value: Any, field: str, *, allow_dot: bool = False) -> str:
    if not isinstance(value, str) or not value:
        raise _error("TIMELINE_PATH_UNSAFE", f"{field} must be a non-empty relative path")
    if value == "." and allow_dot:
        return value
    if (
        value.startswith(("/", "~", "//"))
        or WINDOWS_RE.match(value)
        or URI_RE.match(value)
        or "\\" in value
        or "\x00" in value
    ):
        raise _error("TIMELINE_PATH_UNSAFE", f"{field} must be a POSIX workspace-relative path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise _error("TIMELINE_PATH_UNSAFE", f"{field} contains an unsafe path segment")
    return value


def _safe_existing_file(workspace: Path, relative: str, field: str) -> Path:
    _safe_path_text(relative, field)
    try:
        return _safe_workspace_path(
            workspace, relative, field=field, allow_missing=False, expected="file"
        )
    except AuditStateError as exc:
        raise _error("TIMELINE_EVIDENCE_UNSAFE", f"{field} is not a safe regular file") from exc


def _binding(
    workspace: Path,
    relative: str,
    *,
    kind: str,
    validator: str,
    status: str = "validated",
) -> dict[str, str]:
    path = _safe_existing_file(workspace, relative, "source binding")
    return {
        "path": relative,
        "sha256": _sha(path.read_bytes()),
        "kind": kind,
        "validator": validator,
        "status": status,
    }


def _target_summary(
    workspace: Path, handoff: dict[str, Any], bindings: list[dict[str, str]]
) -> dict[str, Any]:
    tested = handoff.get("tested_ref")
    if not isinstance(tested, dict) or tested.get("verified") is not True:
        raise _error("TIMELINE_TARGET_UNVERIFIABLE", "tested ref lacks a validated target contract")
    paths = tested.get("source_paths")
    target_paths = [item for item in paths if isinstance(item, str) and item.endswith("zhulong-target.yaml")]
    if len(target_paths) != 1:
        raise _error("TIMELINE_TARGET_UNVERIFIABLE", "exactly one validated target contract is required")
    target_path = target_paths[0]
    if not any(item["path"] == target_path for item in bindings):
        bindings.append(
            _binding(
                workspace,
                target_path,
                kind="target_contract",
                validator="validate_target_contract.py",
            )
        )
    try:
        import yaml  # type: ignore

        document = yaml.safe_load(_safe_existing_file(workspace, target_path, "target contract").read_text("utf-8"))
    except Exception as exc:
        raise _error("TIMELINE_TARGET_UNVERIFIABLE", "validated target contract cannot be summarized") from exc
    target = document.get("target") if isinstance(document, dict) else None
    if not isinstance(target, dict):
        raise _error("TIMELINE_TARGET_UNVERIFIABLE", "target identity is unavailable")
    return {
        "name": _safe_text(target.get("name"), "target.name", limit=120),
        "tested_ref": _safe_text(tested.get("value"), "target.tested_ref", limit=160),
        "contract_path": target_path,
        "contract_sha256": next(item["sha256"] for item in bindings if item["path"] == target_path),
        "validator_status": "validated",
    }


def _event_projection(workspace: Path, raw: dict[str, Any], protocol_mode: str) -> dict[str, Any]:
    if protocol_mode == "r2":
        sensitive_text = first_sensitive_r2_event_text(raw)
        if sensitive_text is not None:
            field, category = sensitive_text
            raise _error(
                "TIMELINE_SENSITIVE_TEXT",
                f"{field} contains sensitive material of category {category}",
            )
    normalized = normalize_event(raw)
    evidence: list[str] = []
    for index, value in enumerate(raw.get("evidence_refs") or []):
        relative = _safe_path_text(value, f"events.evidence_refs[{index}]")
        _safe_existing_file(workspace, relative, "event evidence")
        evidence.append(relative)
    subjects = sorted(
        {
            _safe_text(value, "event subject", limit=160)
            for value in raw.get("subjects") or []
        }
    )
    details = normalized.get("details") if isinstance(normalized.get("details"), dict) else {}
    revision = raw.get("expected_state_revision")
    return {
        "seq": raw.get("seq") if protocol_mode == "r2" else None,
        "revision": revision + 1 if protocol_mode == "r2" and type(revision) is int else None,
        "stage": _safe_text(normalized.get("stage"), "event.stage", limit=64),
        "event_type": _safe_text(normalized.get("event_type"), "event.event_type", limit=64),
        "event_name": _safe_text(normalized.get("event_name"), "event.event_name", limit=120),
        "transition_kind": _safe_optional_text(raw.get("transition_kind"), "event.transition_kind", limit=32),
        "from_status": raw.get("from_status"),
        "to_status": _safe_text(normalized.get("to_status"), "event.to_status", limit=32),
        "reason_code": _safe_text(raw.get("reason_code") or "legacy_observation", "event.reason_code", limit=80),
        "subjects": subjects,
        "evidence_refs": sorted(set(evidence)),
        "blocker": _safe_optional_text(raw.get("blocker"), "event.blocker"),
        "resume_step": _safe_optional_text(raw.get("resume_step"), "event.resume_step"),
        "summary": _safe_optional_text(details.get("summary"), "event.summary"),
    }


def _load_validated_flows(
    workspace: Path,
    repo_root: Path,
    bindings: list[dict[str, str]],
    bundle_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: dict[str, tuple[str, dict[str, Any], dict[str, Any]]] = {}
    for relative, path in _discover_named_files(workspace, "candidate.json"):
        if "confirmed/" in f"{relative}/" or "/examples/" in f"/{relative}/":
            continue
        try:
            document = json.loads(path.read_text("utf-8"))
            from validate_candidate import validate_candidate

            checked = validate_candidate(document, repo_root=repo_root)
        except Exception as exc:
            raise _error("TIMELINE_CANDIDATE_INVALID", "candidate failed its production validator") from exc
        candidate_id = str(checked["candidate_id"])
        if candidate_id in candidates:
            raise _error("TIMELINE_CANDIDATE_DUPLICATE", "candidate_id is not unique")
        candidates[candidate_id] = (relative, document, checked)
        bindings.append(
            _binding(workspace, relative, kind="candidate", validator="validate_candidate.py")
        )

    verdicts: dict[str, tuple[str, dict[str, Any]]] = {}
    for relative, path in _discover_named_files(workspace, "verifier-verdict.json"):
        if "confirmed/" in f"{relative}/" or "/examples/" in f"/{relative}/":
            continue
        try:
            document = json.loads(path.read_text("utf-8"))
            from validate_verifier_verdict import cross_check_candidate, validate_verdict

            checked = validate_verdict(document)
            candidate_id = str(checked["candidate_id"])
            if candidate_id not in candidates:
                raise ValueError("missing candidate")
            cross_check_candidate(workspace / candidates[candidate_id][0], document)
        except Exception as exc:
            raise _error("TIMELINE_VERDICT_INVALID", "verdict failed its production cross-check") from exc
        if candidate_id in verdicts:
            raise _error("TIMELINE_VERDICT_DUPLICATE", "candidate has multiple verifier verdicts")
        verdicts[candidate_id] = (relative, document)
        bindings.append(
            _binding(
                workspace, relative, kind="verdict", validator="validate_verifier_verdict.py"
            )
        )

    ledger: dict[str, Any] = {}
    dispositions: dict[str, dict[str, Any]] = {}
    ledger_path = workspace / "audit-disposition.json"
    if ledger_path.exists():
        try:
            ledger = json.loads(_safe_existing_file(workspace, "audit-disposition.json", "disposition ledger").read_text("utf-8"))
            from audit_disposition import validate_disposition_ledger

            if not validate_disposition_ledger(workspace, ledger=ledger, language="auto").get("ok"):
                raise ValueError("rejected")
        except Exception as exc:
            raise _error("TIMELINE_DISPOSITION_INVALID", "disposition ledger failed its production validator") from exc
        bindings.append(
            _binding(
                workspace,
                "audit-disposition.json",
                kind="disposition",
                validator="audit_disposition.py",
            )
        )
        for record in ledger.get("candidate_dispositions", []):
            if isinstance(record, dict) and isinstance(record.get("candidate_id"), str):
                dispositions[record["candidate_id"]] = record

    confirmed_ledger_items = [
        item
        for item in ledger.get("items", [])
        if isinstance(item, dict) and item.get("state") == "confirmed"
    ]
    validated_bundle_items = [
        item for item in bundle_items
        if item.get("classification") == "bundle_validated"
    ]
    confirmed_disposition_ids = sorted(
        candidate_id
        for candidate_id, record in dispositions.items()
        if record.get("status") == "confirmed_in_docker"
    )
    confirmed_links: dict[str, dict[str, Any]] = {}
    confirmed_counts = (
        len(confirmed_disposition_ids),
        len(confirmed_ledger_items),
        len(validated_bundle_items),
    )
    if any(confirmed_counts):
        if confirmed_counts != (1, 1, 1):
            raise _error(
                "TIMELINE_CONFIRMED_FLOW_AMBIGUOUS",
                "authoritative files do not prove one-to-one confirmed candidate and bundle linkage; review separately or add an explicit protocol",
            )
        candidate_id = confirmed_disposition_ids[0]
        verdict_entry = verdicts.get(candidate_id)
        if (
            candidate_id not in candidates
            or verdict_entry is None
            or verdict_entry[1].get("verdict") != "confirmed_in_docker"
        ):
            raise _error(
                "TIMELINE_CONFIRMED_FLOW_INVALID",
                "confirmed disposition lacks a production-validated confirmed candidate and verdict chain",
            )
        ledger_bundle_path = str(
            confirmed_ledger_items[0].get("confirmed_bundle_path") or ""
        )
        bundle = validated_bundle_items[0]
        if ledger_bundle_path != bundle.get("path"):
            raise _error(
                "TIMELINE_CONFIRMED_FLOW_AMBIGUOUS",
                "authoritative files do not prove one-to-one confirmed candidate and bundle linkage; review separately or add an explicit protocol",
            )
        confirmed_links[candidate_id] = bundle

    flows: list[dict[str, Any]] = []
    for candidate_id in sorted(candidates):
        candidate_path, _candidate_doc, checked = candidates[candidate_id]
        verdict_entry = verdicts.get(candidate_id)
        disposition = dispositions.get(candidate_id)
        bundle = confirmed_links.get(candidate_id)
        flows.append(
            {
                "candidate_id": candidate_id,
                "candidate_path": candidate_path,
                "candidate_sha256": next(item["sha256"] for item in bindings if item["path"] == candidate_path),
                "candidate_fingerprint": checked.get("fingerprint"),
                "verdict": {
                    "status": str(verdict_entry[1].get("verdict")) if verdict_entry else "not_present",
                    "path": verdict_entry[0] if verdict_entry else None,
                    "sha256": next(
                        (item["sha256"] for item in bindings if verdict_entry and item["path"] == verdict_entry[0]),
                        None,
                    ),
                },
                "disposition": {
                    "status": str(disposition.get("status")) if disposition else "not_present",
                    "path": "audit-disposition.json" if disposition else None,
                    "sha256": next(
                        (item["sha256"] for item in bindings if item["path"] == "audit-disposition.json"),
                        None,
                    ),
                },
                "bundle": {
                    "classification": bundle.get("classification") if bundle else "not_present",
                    "path": bundle.get("path") if bundle else None,
                    "evidence_sha256": bundle.get("evidence_sha256") if bundle else None,
                    "link_basis": (
                        "validated_single_confirmed_flow_and_bundle"
                        if bundle else "not_present"
                    ),
                },
            }
        )
    return flows


def _bundle_projection(workspace: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    summary = inspect_confirmed_bundles(workspace, language="auto")
    if summary.get("validator_error"):
        raise _error("TIMELINE_BUNDLE_VALIDATOR_FAILED", "bundle validator did not return a usable result")
    items: list[dict[str, Any]] = []
    for raw in summary.get("results", []):
        if not isinstance(raw, dict) or raw.get("classification") == "ignored_helper_file":
            continue
        path = f"confirmed/{raw.get('path')}"
        _safe_path_text(path, "bundle.path")
        bundle_path = workspace / path
        if bundle_path.is_symlink() or not bundle_path.is_dir():
            raise _error("TIMELINE_BUNDLE_PATH_UNSAFE", "bundle path is not a real directory")
        evidence = bundle_path / "verification-evidence.json"
        evidence_digest = _sha(evidence.read_bytes()) if evidence.is_file() and not evidence.is_symlink() else None
        items.append(
            {
                "bundle_id": _safe_text(raw.get("name"), "bundle.id", limit=120),
                "path": path,
                "classification": raw.get("classification"),
                "evidence_sha256": evidence_digest,
            }
        )
    items.sort(key=lambda item: (item["classification"], item["bundle_id"], item["path"]))
    counts = summary.get("validator_summary") or {}
    return {
        "validated": int(counts.get("bundle_validated") or 0),
        "partial": int(counts.get("partial_confirmed_bundle") or 0),
        "failed": int(counts.get("validation_failed") or 0),
        "items": items,
    }, items


def _derived_statuses(workspace: Path, repo_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    handoff_path = workspace / HANDOFF_STATE_FILENAME
    if handoff_path.exists():
        result = validate_handoff_state_current(workspace, repo_root)
        if not result.get("ok"):
            raise _error("TIMELINE_HANDOFF_INVALID", "handoff-state.json is stale or invalid")
        handoff = {
            "status": "validated",
            "path": HANDOFF_STATE_FILENAME,
            "sha256": _sha(handoff_path.read_bytes()),
            "integrity": result.get("state", {}).get("integrity", {}).get("overall", "unknown"),
        }
    else:
        handoff = {"status": "not_present", "path": None, "sha256": None, "integrity": "not_present"}

    next_path = workspace / "next-actions.json"
    if next_path.exists():
        try:
            from next_actions import validate_next_actions_current

            result = validate_next_actions_current(workspace, repo_root)
        except Exception as exc:
            raise _error("TIMELINE_NEXT_ACTIONS_INVALID", "next-actions validator failed") from exc
        if not result.get("ok"):
            raise _error("TIMELINE_NEXT_ACTIONS_INVALID", "next-actions.json is stale or invalid")
        document = json.loads(next_path.read_text("utf-8"))
        codes = sorted(
            {
                str(item.get("blocking_code"))
                for item in document.get("actions", [])
                if isinstance(item, dict) and item.get("blocking_code")
            }
        )
        next_actions = {
            "status": "validated",
            "path": "next-actions.json",
            "sha256": _sha(next_path.read_bytes()),
            "classification": document.get("classification"),
            "blocking_codes": codes,
        }
    else:
        next_actions = {
            "status": "not_present",
            "path": None,
            "sha256": None,
            "classification": "not_present",
            "blocking_codes": [],
        }
    return handoff, next_actions


def derive_timeline(workspace: Path, repo_root: Path | None = None) -> dict[str, Any]:
    """Derive one canonical timeline without reading notes or writing the workspace."""
    workspace = workspace.absolute()
    repo_root = (repo_root or workspace.parent).absolute()
    snapshot = read_workspace_snapshot(workspace)
    if snapshot.state is None or not snapshot.journal.events:
        raise _error("TIMELINE_AUTHORITY_MISSING", "a validated journal and state view are required")
    handoff = derive_handoff_state(
        workspace, repo_root, include_advisory_notes=False
    )
    issues = handoff.get("integrity", {}).get("issues")
    if issues:
        codes = sorted(
            {str(item.get("code")) for item in issues if isinstance(item, dict) and item.get("code")}
        )
        raise _error(
            "TIMELINE_AUTHORITY_INVALID",
            "authoritative inputs failed existing validators",
            issue_codes=codes,
        )

    bindings: list[dict[str, str]] = [
        _binding(
            workspace,
            "audit-events.jsonl",
            kind="journal",
            validator="audit_state_io.py+audit_transition_policy.py",
        ),
        _binding(
            workspace,
            "stage-status.json",
            kind="state",
            validator="audit_state_io.py",
        ),
    ]
    for artifact in handoff.get("artifacts", []):
        if not isinstance(artifact, dict):
            continue
        relative = artifact.get("path")
        if (
            not isinstance(relative, str)
            or relative in {"audit-events.jsonl", "stage-status.json", "agent-notes.md"}
        ):
            continue
        kind = str(artifact.get("kind") or "other")
        validator = {
            "candidate": "validate_candidate.py",
            "verdict": "validate_verifier_verdict.py",
            "disposition": "audit_disposition.py",
            "target_contract": "validate_target_contract.py",
            "recon": "validate_recon_result.py",
            "triage": "validate_triage_batch.py",
            "docker": "workspace_state.py",
            "runtime": "workspace_state.py",
            "bundle": "validate_all_report_bundles.py",
            "recording": "validate_recording_evidence.py",
            "other": "workspace_state.py",
        }.get(kind, "workspace_state.py")
        bindings.append(
            _binding(workspace, relative, kind=kind, validator=validator)
        )

    target = _target_summary(workspace, handoff, bindings)
    bundles, bundle_items = _bundle_projection(workspace)
    flows = _load_validated_flows(workspace, repo_root, bindings, bundle_items)
    bindings = sorted(
        {item["path"]: item for item in bindings}.values(),
        key=lambda item: (item["kind"], item["path"]),
    )
    events = [
        _event_projection(workspace, raw, snapshot.mode)
        for raw in snapshot.journal.events
    ]
    blockers = [
        {
            "seq": event["seq"],
            "active": index == len(events) - 1 and event["to_status"] in {"blocked", "paused"},
            "reason_code": event["reason_code"],
            "summary": event["blocker"],
            "resume_step": event["resume_step"],
            "evidence_refs": event["evidence_refs"],
        }
        for index, event in enumerate(events)
        if event["to_status"] in {"blocked", "paused"}
    ]
    handoff_status, next_actions = _derived_statuses(workspace, repo_root)
    state = snapshot.state
    verdict_statuses = {
        flow["verdict"]["status"]
        for flow in flows
        if flow["verdict"]["status"] != "not_present"
    }
    docker = {
        "verification_status": (
            "confirmed_verdict_present"
            if "confirmed_in_docker" in verdict_statuses
            else "verdict_present"
            if verdict_statuses
            else "evidence_only_present"
            if int(handoff.get("counts", {}).get("docker_evidence_only") or 0) > 0
            else "not_present"
        ),
        "hygiene_status": handoff.get("docker", {}).get("status", "not_present"),
        "hygiene_path": handoff.get("docker", {}).get("path"),
        "hygiene_sha256": handoff.get("docker", {}).get("sha256"),
        "baseline_status": handoff.get("docker_baseline", {}).get("status", "not_present"),
        "baseline_path": handoff.get("docker_baseline", {}).get("path"),
        "baseline_sha256": handoff.get("docker_baseline", {}).get("sha256"),
    }
    finalization = {
        "status": handoff.get("finalization", {}).get("status", "not_finalized"),
        "path": handoff.get("finalization", {}).get("path"),
        "sha256": handoff.get("finalization", {}).get("sha256"),
    }
    authority_digest = _sha(
        json.dumps(
            bindings, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    )
    document = {
        "schema_version": SCHEMA_VERSION,
        "projection_kind": PROJECTION_KIND,
        "non_authority_statement": NON_AUTHORITY_STATEMENT,
        "protocol_mode": snapshot.mode,
        "target": target,
        "source_bindings": bindings,
        "events": events,
        "current_state": {
            "run_id": _safe_text(state.get("run_id"), "current_state.run_id", limit=160)
            if snapshot.mode == "r2"
            else None,
            "revision": state.get("state_revision") if snapshot.mode == "r2" else None,
            "event_sequence": state.get("last_event_seq") if snapshot.mode == "r2" else None,
            "stage": _safe_text(state.get("stage"), "current_state.stage", limit=64),
            "status": _safe_text(state.get("status"), "current_state.status", limit=32),
            "blocker": _safe_optional_text(state.get("blocker"), "current_state.blocker"),
            "resume_step": _safe_optional_text(state.get("resume_step"), "current_state.resume_step"),
        },
        "blockers": blockers,
        "candidate_flows": flows,
        "docker": docker,
        "bundles": bundles,
        "finalization": finalization,
        "handoff": handoff_status,
        "next_actions": next_actions,
        "integrity": {
            "status": "valid",
            "authority_digest": authority_digest,
            "issue_codes": [],
        },
        "non_claims": list(NON_CLAIMS),
    }
    issues = validate_document(document)
    if issues:
        raise _error(
            "TIMELINE_SCHEMA_INVALID",
            "derived timeline failed its strict contract",
            issues=issues,
        )
    return document


def _expect_object(
    value: Any,
    path: str,
    required: set[str],
    issues: list[dict[str, Any]],
    *,
    optional: set[str] | None = None,
) -> bool:
    if not isinstance(value, dict):
        issues.append(_issue("TIMELINE_SCHEMA_INVALID", f"{path} must be an object", path))
        return False
    allowed = required | set(optional or ())
    missing = sorted(required - set(value))
    extra = sorted(set(value) - allowed)
    if missing:
        issues.append(_issue("TIMELINE_SCHEMA_INVALID", f"{path} is missing required fields", path))
    if extra:
        issues.append(_issue("TIMELINE_SCHEMA_INVALID", f"{path} contains unsupported fields", path))
    return not missing and not extra


def _walk_security(value: Any, path: str, issues: list[dict[str, Any]]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in PROHIBITED_KEYS:
                issues.append(_issue("TIMELINE_PROHIBITED_FIELD", "prohibited field is present", f"{path}.{key}"))
            _walk_security(item, f"{path}.{key}", issues)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk_security(item, f"{path}[{index}]", issues)
    elif isinstance(value, str):
        if "\x00" in value or BIDI_RE.search(value):
            issues.append(_issue("TIMELINE_TEXT_UNSAFE", "unsafe control text is present", path))
        sensitive_kind = sensitive_value_kind(value)
        if sensitive_kind is not None:
            issues.append(_issue(
                "TIMELINE_SENSITIVE_TEXT",
                f"sensitive material of category {sensitive_kind} is present",
                path,
            ))
        if DANGEROUS_MARKUP_RE.search(value):
            issues.append(_issue("TIMELINE_HTML_INJECTION", "active-markup-like text is present", path))


def _schema_errors(
    value: Any,
    rule: dict[str, Any],
    root: dict[str, Any],
    path: str = "$",
) -> list[tuple[str, str]]:
    """Validate the JSON Schema subset used by the committed timeline contract."""
    if "$ref" in rule:
        ref = rule["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/$defs/"):
            return [(path, "uses an unsupported schema reference")]
        resolved: Any = root
        try:
            for part in ref[2:].split("/"):
                resolved = resolved[part]
        except (KeyError, TypeError):
            return [(path, "references a missing schema definition")]
        if not isinstance(resolved, dict):
            return [(path, "references a non-object schema definition")]
        return _schema_errors(value, resolved, root, path)

    branches = rule.get("oneOf")
    if isinstance(branches, list):
        matches = [
            branch
            for branch in branches
            if isinstance(branch, dict) and not _schema_errors(value, branch, root, path)
        ]
        if len(matches) != 1:
            return [(path, "must match exactly one allowed schema shape")]
        return []

    expected = rule.get("type")
    type_matches = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": type(value) is int,
        "boolean": type(value) is bool,
        "null": value is None,
    }
    if isinstance(expected, str) and not type_matches.get(expected, False):
        return [(path, f"must be {expected}")]
    if isinstance(expected, list) and not any(
        isinstance(item, str) and type_matches.get(item, False) for item in expected
    ):
        return [(path, "has an unsupported type")]

    errors: list[tuple[str, str]] = []
    if "const" in rule and value != rule["const"]:
        errors.append((path, "does not match the required constant"))
    if "enum" in rule and value not in rule["enum"]:
        errors.append((path, "has an unsupported value"))
    if isinstance(value, dict):
        properties = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
        for key in rule.get("required", []):
            if key not in value:
                errors.append((f"{path}.{key}", "is required"))
        if rule.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    errors.append((f"{path}.{key}", "is not allowed"))
        for key, child in properties.items():
            if key in value and isinstance(child, dict):
                errors.extend(_schema_errors(value[key], child, root, f"{path}.{key}"))
    elif isinstance(value, list):
        if "minItems" in rule and len(value) < int(rule["minItems"]):
            errors.append((path, "contains too few items"))
        if "maxItems" in rule and len(value) > int(rule["maxItems"]):
            errors.append((path, "contains too many items"))
        if rule.get("uniqueItems") is True:
            for index, item in enumerate(value):
                if any(item == prior for prior in value[:index]):
                    errors.append((path, "contains duplicate items"))
                    break
        child = rule.get("items")
        if isinstance(child, dict):
            for index, item in enumerate(value):
                errors.extend(_schema_errors(item, child, root, f"{path}[{index}]"))
    elif isinstance(value, str):
        if "minLength" in rule and len(value) < int(rule["minLength"]):
            errors.append((path, "is shorter than allowed"))
        if "maxLength" in rule and len(value) > int(rule["maxLength"]):
            errors.append((path, "is longer than allowed"))
        if "pattern" in rule and re.fullmatch(str(rule["pattern"]), value) is None:
            errors.append((path, "does not match the required pattern"))
    elif type(value) is int:
        if "minimum" in rule and value < int(rule["minimum"]):
            errors.append((path, "is below the minimum"))
        if "maximum" in rule and value > int(rule["maximum"]):
            errors.append((path, "is above the maximum"))
    return errors


def _validate_schema(document: Any) -> list[dict[str, Any]]:
    try:
        schema = json.loads(SCHEMA_PATH.read_text("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return [_issue("TIMELINE_SCHEMA_UNAVAILABLE", "timeline schema is unavailable", "$schema")]
    if not isinstance(schema, dict):
        return [_issue("TIMELINE_SCHEMA_UNAVAILABLE", "timeline schema root is invalid", "$schema")]
    return [
        _issue("TIMELINE_SCHEMA_INVALID", message, path)
        for path, message in _schema_errors(document, schema, schema)
    ]


def validate_document(document: Any) -> list[dict[str, Any]]:
    """Validate the committed JSON Schema and the closed semantic contract."""
    issues: list[dict[str, Any]] = _validate_schema(document)
    top = {
        "schema_version", "projection_kind", "non_authority_statement", "protocol_mode",
        "target", "source_bindings", "events", "current_state", "blockers",
        "candidate_flows", "docker", "bundles", "finalization", "handoff",
        "next_actions", "integrity", "non_claims",
    }
    if not _expect_object(document, "$", top, issues):
        _walk_security(document, "$", issues)
        return sorted(issues, key=lambda item: (item["code"], str(item.get("path") or ""), item["message"]))
    if document.get("schema_version") != SCHEMA_VERSION:
        issues.append(_issue("TIMELINE_SCHEMA_INVALID", "unsupported schema_version", "schema_version"))
    if document.get("projection_kind") != PROJECTION_KIND:
        issues.append(_issue("TIMELINE_SCHEMA_INVALID", "projection_kind is not canonical", "projection_kind"))
    if document.get("non_authority_statement") != NON_AUTHORITY_STATEMENT:
        issues.append(_issue("TIMELINE_NON_AUTHORITY_DRIFT", "non-authority statement drifted", "non_authority_statement"))
    if document.get("protocol_mode") not in {"r2", "legacy_r1"}:
        issues.append(_issue("TIMELINE_SCHEMA_INVALID", "protocol_mode is unsupported", "protocol_mode"))

    target = document.get("target")
    if _expect_object(target, "target", {"name", "tested_ref", "contract_path", "contract_sha256", "validator_status"}, issues):
        if target.get("validator_status") != "validated":
            issues.append(_issue("TIMELINE_TARGET_UNVERIFIABLE", "target must be validated", "target"))
        for key in ("name", "tested_ref"):
            if not isinstance(target.get(key), str) or not target[key]:
                issues.append(_issue("TIMELINE_SCHEMA_INVALID", f"target.{key} must be non-empty", f"target.{key}"))
        try:
            _safe_path_text(target.get("contract_path"), "target.contract_path")
        except TimelineError as exc:
            issues.append(_issue(exc.code, exc.message, "target.contract_path"))
        if not SHA256_RE.fullmatch(str(target.get("contract_sha256") or "")):
            issues.append(_issue("TIMELINE_SCHEMA_INVALID", "target digest is invalid", "target.contract_sha256"))

    bindings = document.get("source_bindings")
    if not isinstance(bindings, list) or len(bindings) < 3:
        issues.append(_issue("TIMELINE_SCHEMA_INVALID", "source_bindings must contain journal, state, and target", "source_bindings"))
        bindings = []
    seen_paths: set[str] = set()
    prior_binding: tuple[str, str] | None = None
    for index, item in enumerate(bindings):
        path = f"source_bindings[{index}]"
        if not _expect_object(item, path, {"path", "sha256", "kind", "validator", "status"}, issues):
            continue
        try:
            _safe_path_text(item.get("path"), f"{path}.path")
        except TimelineError as exc:
            issues.append(_issue(exc.code, exc.message, f"{path}.path"))
        if item.get("path") in seen_paths:
            issues.append(_issue("TIMELINE_BINDING_DUPLICATE", "source path is duplicated", f"{path}.path"))
        seen_paths.add(str(item.get("path")))
        if not SHA256_RE.fullmatch(str(item.get("sha256") or "")):
            issues.append(_issue("TIMELINE_SCHEMA_INVALID", "source digest is invalid", f"{path}.sha256"))
        if item.get("status") != "validated":
            issues.append(_issue("TIMELINE_SOURCE_UNVALIDATED", "source binding is not validated", path))
        current = (str(item.get("kind")), str(item.get("path")))
        if prior_binding is not None and current < prior_binding:
            issues.append(_issue("TIMELINE_ORDER_INVALID", "source bindings are not stably sorted", "source_bindings"))
        prior_binding = current

    events = document.get("events")
    if not isinstance(events, list) or not events:
        issues.append(_issue("TIMELINE_SCHEMA_INVALID", "events must be non-empty", "events"))
        events = []
    event_keys = {
        "seq", "revision", "stage", "event_type", "event_name", "transition_kind",
        "from_status", "to_status", "reason_code", "subjects", "evidence_refs",
        "blocker", "resume_step", "summary",
    }
    last_seq = 0
    last_revision = 0
    for index, event in enumerate(events):
        path = f"events[{index}]"
        if not _expect_object(event, path, event_keys, issues):
            continue
        if document.get("protocol_mode") == "r2":
            if event.get("to_status") not in {"running", "paused", "blocked", "completed"}:
                issues.append(_issue("TIMELINE_SCHEMA_INVALID", "R2 event status is unsupported", f"{path}.to_status"))
            if event.get("from_status") not in {None, "running", "paused", "blocked", "completed"}:
                issues.append(_issue("TIMELINE_SCHEMA_INVALID", "R2 source status is unsupported", f"{path}.from_status"))
            if type(event.get("seq")) is not int or event["seq"] != last_seq + 1:
                issues.append(_issue("TIMELINE_EVENT_SEQUENCE_INVALID", "R2 event seq is not contiguous", f"{path}.seq"))
            if type(event.get("revision")) is not int or event["revision"] != last_revision + 1:
                issues.append(_issue("TIMELINE_EVENT_REVISION_INVALID", "R2 revision is not contiguous", f"{path}.revision"))
            last_seq = int(event.get("seq") or last_seq)
            last_revision = int(event.get("revision") or last_revision)
        elif event.get("seq") is not None or event.get("revision") is not None:
            issues.append(_issue("TIMELINE_LEGACY_FACT_INVENTED", "legacy events must not invent seq/revision", path))
        for list_key in ("subjects", "evidence_refs"):
            values = event.get(list_key)
            if not isinstance(values, list) or values != sorted(set(values)):
                issues.append(_issue("TIMELINE_ORDER_INVALID", f"{path}.{list_key} must be sorted and unique", f"{path}.{list_key}"))
        for ref in event.get("evidence_refs") if isinstance(event.get("evidence_refs"), list) else []:
            try:
                _safe_path_text(ref, f"{path}.evidence_refs")
            except TimelineError as exc:
                issues.append(_issue(exc.code, exc.message, f"{path}.evidence_refs"))

    state = document.get("current_state")
    state_keys = {"run_id", "revision", "event_sequence", "stage", "status", "blocker", "resume_step"}
    if _expect_object(state, "current_state", state_keys, issues):
        if document.get("protocol_mode") == "r2":
            if state.get("status") not in {"running", "paused", "blocked", "completed"}:
                issues.append(_issue("TIMELINE_SCHEMA_INVALID", "R2 current status is unsupported", "current_state.status"))
            if type(state.get("revision")) is not int or state.get("revision") != len(events):
                issues.append(_issue("TIMELINE_STATE_MISMATCH", "current revision does not match events", "current_state.revision"))
            if state.get("event_sequence") != (events[-1].get("seq") if events else None):
                issues.append(_issue("TIMELINE_STATE_MISMATCH", "current event sequence does not match events", "current_state.event_sequence"))
        elif any(state.get(key) is not None for key in ("run_id", "revision", "event_sequence")):
            issues.append(_issue("TIMELINE_LEGACY_FACT_INVENTED", "legacy state must not invent R2 identity", "current_state"))
        if (
            document.get("protocol_mode") == "r2"
            and events
            and (state.get("stage"), state.get("status"))
            != (events[-1].get("stage"), events[-1].get("to_status"))
        ):
            issues.append(_issue("TIMELINE_STATE_MISMATCH", "current state differs from the final event", "current_state"))

    blockers = document.get("blockers")
    if not isinstance(blockers, list):
        issues.append(_issue("TIMELINE_SCHEMA_INVALID", "blockers must be a list", "blockers"))
    else:
        for index, item in enumerate(blockers):
            _expect_object(item, f"blockers[{index}]", {"seq", "active", "reason_code", "summary", "resume_step", "evidence_refs"}, issues)
            if not isinstance(item, dict) or type(item.get("active")) is not bool:
                issues.append(_issue("TIMELINE_SCHEMA_INVALID", "blocker active must be boolean", f"blockers[{index}].active"))

    flows = document.get("candidate_flows")
    if not isinstance(flows, list):
        issues.append(_issue("TIMELINE_SCHEMA_INVALID", "candidate_flows must be a list", "candidate_flows"))
        flows = []
    flow_ids: list[str] = []
    validated_flow_links: list[tuple[str, str, str]] = []
    for index, flow in enumerate(flows):
        path = f"candidate_flows[{index}]"
        if not _expect_object(flow, path, {"candidate_id", "candidate_path", "candidate_sha256", "candidate_fingerprint", "verdict", "disposition", "bundle"}, issues):
            continue
        flow_ids.append(str(flow.get("candidate_id")))
        for key in ("candidate_path",):
            try:
                _safe_path_text(flow.get(key), f"{path}.{key}")
            except TimelineError as exc:
                issues.append(_issue(exc.code, exc.message, f"{path}.{key}"))
        if not SHA256_RE.fullmatch(str(flow.get("candidate_sha256") or "")):
            issues.append(_issue("TIMELINE_SCHEMA_INVALID", "candidate digest is invalid", f"{path}.candidate_sha256"))
        for key, required in (
            ("verdict", {"status", "path", "sha256"}),
            ("disposition", {"status", "path", "sha256"}),
            ("bundle", {"classification", "path", "evidence_sha256", "link_basis"}),
        ):
            _expect_object(flow.get(key), f"{path}.{key}", required, issues)
        verdict = flow.get("verdict") if isinstance(flow.get("verdict"), dict) else {}
        disposition = flow.get("disposition") if isinstance(flow.get("disposition"), dict) else {}
        bundle = flow.get("bundle") if isinstance(flow.get("bundle"), dict) else {}
        classification = bundle.get("classification")
        if disposition.get("status") == "confirmed_in_docker" and (
            verdict.get("status") != "confirmed_in_docker"
            or classification != "bundle_validated"
        ):
            issues.append(_issue(
                "TIMELINE_CONFIRMED_FLOW_INVALID",
                "confirmed disposition lacks a confirmed verdict and validated bundle",
                path,
            ))
        if classification == "bundle_validated":
            bundle_path = bundle.get("path")
            evidence_sha256 = bundle.get("evidence_sha256")
            if (
                verdict.get("status") != "confirmed_in_docker"
                or disposition.get("status") != "confirmed_in_docker"
                or bundle.get("link_basis")
                != "validated_single_confirmed_flow_and_bundle"
            ):
                issues.append(_issue(
                    "TIMELINE_CONFIRMED_FLOW_INVALID",
                    "validated bundle lacks the complete confirmed flow",
                    path,
                ))
            try:
                _safe_path_text(bundle_path, f"{path}.bundle.path")
            except TimelineError as exc:
                issues.append(_issue(exc.code, exc.message, f"{path}.bundle.path"))
            if not SHA256_RE.fullmatch(str(evidence_sha256 or "")):
                issues.append(_issue(
                    "TIMELINE_CONFIRMED_FLOW_INVALID",
                    "validated bundle evidence digest is missing or invalid",
                    f"{path}.bundle.evidence_sha256",
                ))
            if isinstance(bundle_path, str) and isinstance(evidence_sha256, str):
                validated_flow_links.append((bundle_path, evidence_sha256, path))
        elif (
            classification != "not_present"
            or bundle.get("path") is not None
            or bundle.get("evidence_sha256") is not None
            or bundle.get("link_basis") != "not_present"
        ):
            issues.append(_issue(
                "TIMELINE_CONFIRMED_FLOW_INVALID",
                "non-validated candidate flow must not claim a bundle link",
                path,
            ))
    if flow_ids != sorted(set(flow_ids)):
        issues.append(_issue("TIMELINE_ORDER_INVALID", "candidate flows must be sorted and unique", "candidate_flows"))

    simple_shapes = {
        "docker": {"verification_status", "hygiene_status", "hygiene_path", "hygiene_sha256", "baseline_status", "baseline_path", "baseline_sha256"},
        "bundles": {"validated", "partial", "failed", "items"},
        "finalization": {"status", "path", "sha256"},
        "handoff": {"status", "path", "sha256", "integrity"},
        "next_actions": {"status", "path", "sha256", "classification", "blocking_codes"},
        "integrity": {"status", "authority_digest", "issue_codes"},
    }
    for key, required in simple_shapes.items():
        _expect_object(document.get(key), key, required, issues)
    bundles = document.get("bundles") if isinstance(document.get("bundles"), dict) else {}
    for key in ("validated", "partial", "failed"):
        if type(bundles.get(key)) is not int or bundles.get(key, -1) < 0:
            issues.append(_issue("TIMELINE_SCHEMA_INVALID", "bundle counts must be non-negative integers", f"bundles.{key}"))
    bundle_items = bundles.get("items")
    validated_summary_items: dict[str, str] = {}
    if not isinstance(bundle_items, list):
        issues.append(_issue("TIMELINE_SCHEMA_INVALID", "bundle items must be a list", "bundles.items"))
    else:
        for index, item in enumerate(bundle_items):
            path = f"bundles.items[{index}]"
            if not _expect_object(item, path, {"bundle_id", "path", "classification", "evidence_sha256"}, issues):
                continue
            try:
                _safe_path_text(item.get("path"), f"{path}.path")
            except TimelineError as exc:
                issues.append(_issue(exc.code, exc.message, f"{path}.path"))
            if item.get("classification") == "bundle_validated":
                item_path = item.get("path")
                digest = item.get("evidence_sha256")
                if not SHA256_RE.fullmatch(str(digest or "")):
                    issues.append(_issue(
                        "TIMELINE_CONFIRMED_FLOW_INVALID",
                        "validated bundle summary item lacks an evidence digest",
                        f"{path}.evidence_sha256",
                    ))
                if isinstance(item_path, str) and isinstance(digest, str):
                    if item_path in validated_summary_items:
                        issues.append(_issue(
                            "TIMELINE_CONFIRMED_FLOW_INVALID",
                            "validated bundle summary path is duplicated",
                            f"{path}.path",
                        ))
                    validated_summary_items[item_path] = digest
    if bundles.get("validated") != len(validated_summary_items):
        issues.append(_issue(
            "TIMELINE_CONFIRMED_FLOW_INVALID",
            "validated bundle summary count does not match its items",
            "bundles.validated",
        ))
    linked_paths: set[str] = set()
    for bundle_path, digest, flow_path in validated_flow_links:
        if bundle_path in linked_paths:
            issues.append(_issue(
                "TIMELINE_CONFIRMED_FLOW_INVALID",
                "validated bundle is linked by more than one candidate flow",
                flow_path,
            ))
        linked_paths.add(bundle_path)
        if validated_summary_items.get(bundle_path) != digest:
            issues.append(_issue(
                "TIMELINE_CONFIRMED_FLOW_INVALID",
                "candidate flow bundle link differs from the validated bundle summary",
                flow_path,
            ))
    if linked_paths != set(validated_summary_items):
        issues.append(_issue(
            "TIMELINE_CONFIRMED_FLOW_INVALID",
            "validated bundle summary contains an orphan or missing candidate flow link",
            "bundles.items",
        ))
    if len(validated_flow_links) != bundles.get("validated"):
        issues.append(_issue(
            "TIMELINE_CONFIRMED_FLOW_INVALID",
            "validated flow count does not match bundles.validated",
            "bundles.validated",
        ))
    integrity = document.get("integrity") if isinstance(document.get("integrity"), dict) else {}
    if integrity.get("status") != "valid" or integrity.get("issue_codes") != []:
        issues.append(_issue("TIMELINE_INTEGRITY_INVALID", "published timeline integrity must be valid", "integrity"))
    if not SHA256_RE.fullmatch(str(integrity.get("authority_digest") or "")):
        issues.append(_issue("TIMELINE_SCHEMA_INVALID", "authority digest is invalid", "integrity.authority_digest"))
    if document.get("non_claims") != NON_CLAIMS:
        issues.append(_issue("TIMELINE_NON_CLAIMS_DRIFT", "non-claims list drifted", "non_claims"))
    _walk_security(document, "$", issues)
    return sorted(issues, key=lambda item: (item["code"], str(item.get("path") or ""), item["message"]))


def validate_against_workspace(document: dict[str, Any], workspace: Path, repo_root: Path | None = None) -> list[dict[str, Any]]:
    issues = validate_document(document)
    if issues:
        return issues
    try:
        expected = derive_timeline(workspace, repo_root)
    except TimelineError as exc:
        return [_issue(exc.code, exc.message, None)]
    if document != expected:
        return [_issue("TIMELINE_AUTHORITY_DRIFT", "timeline differs from current validated authority", None)]
    return []


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _href(relative: str) -> str:
    _safe_path_text(relative, "HTML link")
    return quote(relative, safe="/-._~")


def _link(relative: str | None, label: str | None = None) -> str:
    if relative is None:
        return '<span class="muted">not present</span>'
    return f'<a href="{_href(relative)}">{_esc(label or relative)}</a>'


def render_html(document: dict[str, Any], workspace: Path | None = None) -> bytes:
    issues = validate_document(document)
    if issues:
        raise _error("TIMELINE_SCHEMA_INVALID", "HTML input failed timeline validation", issues=issues)
    if workspace is not None:
        for binding in document["source_bindings"]:
            _safe_existing_file(workspace, binding["path"], "HTML source link")
        for event in document["events"]:
            for relative in event["evidence_refs"]:
                _safe_existing_file(workspace, relative, "HTML evidence link")

    target = document["target"]
    current = document["current_state"]
    integrity = document["integrity"]
    lines = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; img-src &#39;none&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">',
        "<title>Zhulong Static Audit Timeline</title>",
        "<style>",
        ":root{color-scheme:light;--ink:#20231f;--muted:#666b64;--line:#d9ddd6;--paper:#fafbf8;--accent:#245b46;--warn:#8a4b13}",
        "*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 system-ui,sans-serif}",
        "main{max-width:1120px;margin:auto;padding:2rem 1.25rem 4rem}h1,h2{line-height:1.2}h2{margin-top:2.25rem;border-bottom:1px solid var(--line);padding-bottom:.4rem}",
        ".notice{border-left:4px solid var(--accent);padding:.8rem 1rem;background:#eef4ef}.muted{color:var(--muted)}.warn{color:var(--warn)}",
        "table{width:100%;border-collapse:collapse;margin:.8rem 0;display:block;overflow-x:auto}th,td{padding:.55rem .65rem;border:1px solid var(--line);text-align:left;vertical-align:top}th{background:#f0f2ee}",
        "code{font-family:ui-monospace,monospace;font-size:.92em;overflow-wrap:anywhere}a{color:var(--accent)}a:focus{outline:3px solid #efb35d;outline-offset:2px}",
        "ol.timeline{padding-left:1.4rem}.timeline li{margin:.65rem 0}.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:.05rem .45rem;font-size:.85em}",
        "</style>",
        "</head>",
        "<body>",
        "<main>",
        "<h1>Zhulong Static Audit Timeline</h1>",
        f'<p class="notice">{_esc(document["non_authority_statement"])}</p>',
        "<h2>Target and current integrity</h2>",
        "<dl>",
        f"<dt>Target</dt><dd>{_esc(target['name'])}</dd>",
        f"<dt>Tested ref</dt><dd><code>{_esc(target['tested_ref'])}</code></dd>",
        f"<dt>Target contract</dt><dd>{_link(target['contract_path'])} <code>{_esc(target['contract_sha256'])}</code></dd>",
        f"<dt>Protocol</dt><dd><code>{_esc(document['protocol_mode'])}</code></dd>",
        f"<dt>Current state</dt><dd><span class=\"pill\">{_esc(current['stage'])} / {_esc(current['status'])}</span></dd>",
        f"<dt>Integrity</dt><dd><strong>{_esc(integrity['status'])}</strong> <code>{_esc(integrity['authority_digest'])}</code></dd>",
        "</dl>",
        "<h2>Stage event sequence</h2>",
        '<ol class="timeline">',
    ]
    for event in document["events"]:
        evidence = ", ".join(_link(item) for item in event["evidence_refs"]) or '<span class="muted">none</span>'
        transition = event["transition_kind"] or "legacy"
        lines.extend(
            [
                "<li>",
                f"<strong>{_esc(event['stage'])}</strong> — <code>{_esc(event['event_name'])}</code>",
                f'<span class="pill">{_esc(transition)}</span>',
                f"<br>status: {_esc(event['from_status'])} → {_esc(event['to_status'])}; reason: <code>{_esc(event['reason_code'])}</code>",
                f"<br>summary: {_esc(event['summary'])}",
                f"<br>evidence: {evidence}",
                "</li>",
            ]
        )
    lines.extend(["</ol>", "<h2>Blockers, resume, return, and reopen</h2>"])
    if document["blockers"]:
        lines.append("<ul>")
        for blocker in document["blockers"]:
            state = "active" if blocker["active"] else "historical"
            refs = ", ".join(_link(item) for item in blocker["evidence_refs"]) or "none"
            lines.append(
                f"<li><strong>{_esc(state)}</strong>: <code>{_esc(blocker['reason_code'])}</code>; "
                f"{_esc(blocker['summary'])}; resume: {_esc(blocker['resume_step'])}; evidence: {refs}</li>"
            )
        lines.append("</ul>")
    else:
        lines.append('<p class="muted">No recorded blockers.</p>')
    special = [
        event for event in document["events"]
        if event["transition_kind"] in {"resume", "return", "reopen"}
    ]
    if special:
        lines.append("<ul>")
        for event in special:
            lines.append(
                f"<li><code>{_esc(event['transition_kind'])}</code> at {_esc(event['stage'])}: "
                f"<code>{_esc(event['reason_code'])}</code></li>"
            )
        lines.append("</ul>")

    lines.extend(
        [
            "<h2>Candidate → verdict → disposition → bundle</h2>",
            "<table><thead><tr><th>Candidate</th><th>Verdict</th><th>Disposition</th><th>Bundle</th></tr></thead><tbody>",
        ]
    )
    for flow in document["candidate_flows"]:
        lines.append(
            "<tr>"
            f"<td><code>{_esc(flow['candidate_id'])}</code><br>{_link(flow['candidate_path'])}<br><code>{_esc(flow['candidate_sha256'])}</code></td>"
            f"<td>{_esc(flow['verdict']['status'])}<br>{_link(flow['verdict']['path'])}</td>"
            f"<td>{_esc(flow['disposition']['status'])}<br>{_link(flow['disposition']['path'])}</td>"
            f"<td>{_esc(flow['bundle']['classification'])}<br>{_esc(flow['bundle']['path'])}</td>"
            "</tr>"
        )
    if not document["candidate_flows"]:
        lines.append('<tr><td colspan="4" class="muted">No validated candidate flows are present.</td></tr>')
    lines.extend(["</tbody></table>", "<h2>Docker and bundle validation</h2>", "<dl>"])
    docker = document["docker"]
    bundles = document["bundles"]
    lines.extend(
        [
            f"<dt>Docker verification</dt><dd>{_esc(docker['verification_status'])}</dd>",
            f"<dt>Docker hygiene</dt><dd>{_esc(docker['hygiene_status'])} {_link(docker['hygiene_path'])}</dd>",
            f"<dt>Bundle classification</dt><dd>validated={bundles['validated']}, partial={bundles['partial']}, failed={bundles['failed']}</dd>",
            "</dl>",
            "<h2>Finalization, handoff, and next actions</h2>",
            "<dl>",
            f"<dt>Finalization</dt><dd>{_esc(document['finalization']['status'])} {_link(document['finalization']['path'])}</dd>",
            f"<dt>Handoff integrity</dt><dd>{_esc(document['handoff']['status'])} / {_esc(document['handoff']['integrity'])} {_link(document['handoff']['path'])}</dd>",
            f"<dt>Next actions</dt><dd>{_esc(document['next_actions']['status'])} / {_esc(document['next_actions']['classification'])} {_link(document['next_actions']['path'])}</dd>",
            "</dl>",
            "<h2>Validated source bindings and safe evidence links</h2>",
            "<table><thead><tr><th>Kind</th><th>Path</th><th>SHA-256</th><th>Validator</th></tr></thead><tbody>",
        ]
    )
    for binding in document["source_bindings"]:
        lines.append(
            f"<tr><td>{_esc(binding['kind'])}</td><td>{_link(binding['path'])}</td>"
            f"<td><code>{_esc(binding['sha256'])}</code></td><td><code>{_esc(binding['validator'])}</code></td></tr>"
        )
    lines.extend(["</tbody></table>", "<h2>Non-claims</h2>", "<ul>"])
    lines.extend(f"<li>{_esc(item)}</li>" for item in document["non_claims"])
    lines.extend(["</ul>", "</main>", "</body>", "</html>", ""])
    raw = "\n".join(lines).encode("utf-8")
    html_issues = validate_html_bytes(raw)
    if html_issues:
        raise _error("TIMELINE_HTML_INVALID", "rendered HTML failed its safety contract", issues=html_issues)
    return raw


def _decoded_html_uri(value: str) -> str:
    decoded = value
    for _index in range(4):
        next_value = html.unescape(unquote(decoded))
        if next_value == decoded:
            return decoded
        decoded = next_value
    raise ValueError("URI decoding did not converge")


class _TimelineHTMLSafetyParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.issues: list[dict[str, Any]] = []
        self.stack: list[str] = []
        self.tag_counts: dict[str, int] = {}
        self.doctype_count = 0
        self.csp_count = 0
        self.style_depth = 0

    def add(self, code: str, message: str) -> None:
        self.issues.append(_issue(code, message, None))

    def handle_decl(self, decl: str) -> None:
        self.doctype_count += 1
        if decl.strip().lower() != "doctype html" or self.doctype_count != 1:
            self.add("TIMELINE_HTML_STRUCTURE_INVALID", "HTML declaration is not canonical")

    def unknown_decl(self, data: str) -> None:
        self.add("TIMELINE_HTML_STRUCTURE_INVALID", "unknown HTML declaration is present")

    def handle_comment(self, data: str) -> None:
        self.add("TIMELINE_HTML_STRUCTURE_INVALID", "HTML comments are not allowed")

    def _check_uri(self, value: str) -> None:
        if not value or value != value.strip() or any(ord(char) < 0x20 for char in value):
            self.add("TIMELINE_HTML_ACTIVE_URI", "URI-bearing attribute is not a canonical safe relative path")
            return
        try:
            decoded = _decoded_html_uri(value)
            if (
                decoded.startswith(("//", "#"))
                or URI_RE.match(decoded)
                or quote(decoded, safe="/-._~") != value
            ):
                raise ValueError("active or non-canonical URI")
            _safe_path_text(decoded, "HTML URI attribute")
        except (TimelineError, ValueError):
            self.add("TIMELINE_HTML_ACTIVE_URI", "URI-bearing attribute is not a canonical safe relative path")

    def _handle_start(self, tag: str, attrs: list[tuple[str, str | None]], *, closed: bool) -> None:
        tag = tag.lower()
        self.tag_counts[tag] = self.tag_counts.get(tag, 0) + 1
        if closed and tag not in HTML_VOID_TAGS:
            self.add("TIMELINE_HTML_STRUCTURE_INVALID", "non-void HTML element is self-closing")
        if tag == "script":
            self.add("TIMELINE_HTML_SCRIPT", "script elements are prohibited")
        elif tag in HTML_EXTERNAL_TAGS:
            self.add("TIMELINE_HTML_EXTERNAL_RESOURCE", "external-capability element is prohibited")
        elif tag not in HTML_ALLOWED_TAGS:
            self.add("TIMELINE_HTML_TAG_UNSAFE", "unsupported HTML element is present")

        names = [name.lower() for name, _value in attrs]
        if len(names) != len(set(names)):
            self.add("TIMELINE_HTML_DUPLICATE_ATTRIBUTE", "duplicate HTML attribute is present")
        allowed = HTML_ALLOWED_ATTRIBUTES.get(tag, set())
        attr_values: dict[str, str] = {}
        for raw_name, raw_value in attrs:
            name = raw_name.lower()
            value = raw_value or ""
            attr_values.setdefault(name, value)
            if name.startswith("on"):
                self.add("TIMELINE_HTML_EVENT_HANDLER", "event handler attribute is prohibited")
            if name in HTML_URI_ATTRIBUTES:
                self._check_uri(value)
            if name not in allowed:
                self.add("TIMELINE_HTML_ATTRIBUTE_UNSAFE", "unsupported HTML attribute is present")
            sensitive_kind = sensitive_value_kind(value)
            if sensitive_kind is not None:
                self.add(
                    "TIMELINE_HTML_SENSITIVE_TEXT",
                    f"HTML attribute contains sensitive material of category {sensitive_kind}",
                )
        if tag == "a" and names.count("href") != 1:
            self.add("TIMELINE_HTML_ATTRIBUTE_UNSAFE", "anchor must contain exactly one href")
        if tag == "meta":
            http_equiv = attr_values.get("http-equiv", "").strip().lower()
            if http_equiv == "refresh":
                self.add("TIMELINE_HTML_META_REFRESH", "meta refresh is prohibited")
            if http_equiv == "content-security-policy":
                self.csp_count += 1
                if attr_values.get("content") != EXPECTED_CSP:
                    self.add("TIMELINE_HTML_CSP_INVALID", "strict CSP meta is invalid")
        if tag == "style" and not closed:
            self.style_depth += 1
        if tag not in HTML_VOID_TAGS and not closed:
            self.stack.append(tag)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_start(tag, attrs, closed=False)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_start(tag, attrs, closed=True)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in HTML_VOID_TAGS or not self.stack or self.stack[-1] != tag:
            self.add("TIMELINE_HTML_STRUCTURE_INVALID", "HTML element nesting is invalid")
            return
        self.stack.pop()
        if tag == "style":
            self.style_depth = max(0, self.style_depth - 1)

    def handle_data(self, data: str) -> None:
        sensitive_kind = sensitive_value_kind(data)
        if sensitive_kind is not None:
            self.add(
                "TIMELINE_HTML_SENSITIVE_TEXT",
                f"HTML text contains sensitive material of category {sensitive_kind}",
            )
        if self.style_depth and re.search(
            r"(?:url\s*\(|@import|@font-face|expression\s*\()", data, re.I
        ):
            self.add("TIMELINE_HTML_CSS_RESOURCE", "prohibited CSS capability is present")

    def finish(self) -> list[dict[str, Any]]:
        if self.stack:
            self.add("TIMELINE_HTML_STRUCTURE_INVALID", "HTML contains unclosed elements")
        if self.doctype_count != 1:
            self.add("TIMELINE_HTML_STRUCTURE_INVALID", "canonical HTML doctype is missing")
        for tag in ("html", "head", "body", "main", "style"):
            if self.tag_counts.get(tag) != 1:
                self.add("TIMELINE_HTML_STRUCTURE_INVALID", f"HTML must contain exactly one {tag} element")
        if self.csp_count != 1:
            self.add("TIMELINE_HTML_CSP_INVALID", "exactly one strict CSP meta is required")
        return self.issues


def validate_html_bytes(raw: bytes) -> list[dict[str, Any]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return [_issue("TIMELINE_HTML_UTF8_INVALID", "HTML is not UTF-8", None)]
    parser = _TimelineHTMLSafetyParser()
    try:
        parser.feed(text)
        parser.close()
        issues = parser.finish()
    except Exception:
        issues = [_issue("TIMELINE_HTML_STRUCTURE_INVALID", "HTML parsing failed closed", None)]
    return sorted(
        issues,
        key=lambda item: (item["code"], str(item.get("path") or ""), item["message"]),
    )


def _output_path(workspace: Path, relative: str, suffix: str) -> Path:
    relative = _safe_path_text(relative, "timeline output")
    if not relative.endswith(suffix):
        raise _error("TIMELINE_OUTPUT_UNSAFE", f"timeline output must end in {suffix}")
    path = workspace / relative
    parent_relative = path.parent.absolute().relative_to(workspace.absolute()).as_posix()
    if parent_relative != ".":
        try:
            _safe_workspace_path(
                workspace,
                parent_relative,
                field="timeline output parent",
                allow_missing=False,
                expected="dir",
            )
        except AuditStateError as exc:
            raise _error("TIMELINE_OUTPUT_UNSAFE", "timeline output parent is unsafe") from exc
    if path.exists() or path.is_symlink():
        try:
            _safe_workspace_path(
                workspace,
                relative,
                field="timeline output",
                allow_missing=False,
                expected="file",
            )
        except AuditStateError as exc:
            raise _error("TIMELINE_OUTPUT_UNSAFE", "timeline output is not a regular file") from exc
    return path


def _stage_bytes(path: Path, payload: bytes, label: str) -> Path:
    fd, raw_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    staged = Path(raw_name)
    complete = False
    try:
        if os.environ.get("ZHULONG_TEST_FAIL_TIMELINE_WRITE") == label:
            raise OSError("injected timeline staging failure")
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(fd)
        os.close(fd)
        fd = -1
        complete = True
        return staged
    except OSError as exc:
        raise _error("TIMELINE_ATOMIC_WRITE_FAILED", "timeline staging failed") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if not complete:
            try:
                staged.unlink()
            except FileNotFoundError:
                pass


def _restore(path: Path, previous: bytes | None) -> None:
    if previous is None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    fd, raw_name = tempfile.mkstemp(prefix=f".{path.name}.rollback.", suffix=".tmp", dir=path.parent)
    temp = Path(raw_name)
    try:
        offset = 0
        while offset < len(previous):
            written = os.write(fd, previous[offset:])
            if written <= 0:
                raise OSError("short rollback write")
            offset += written
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temp, path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def publish_timeline(
    workspace: Path,
    repo_root: Path | None = None,
    *,
    json_output: str = JSON_BASENAME,
    html_output: str = HTML_BASENAME,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Stage, validate, and publish the JSON/HTML pair with explicit rollback."""
    workspace = workspace.absolute()
    repo_root = (repo_root or workspace.parent).absolute()
    json_path = _output_path(workspace, json_output, ".json")
    html_path = _output_path(workspace, html_output, ".html")
    if json_path == html_path:
        raise _error("TIMELINE_OUTPUT_UNSAFE", "JSON and HTML outputs must be distinct")

    document = derive_timeline(workspace, repo_root)
    json_bytes = _canonical_json_bytes(document)
    html_bytes = render_html(document, workspace)
    if os.environ.get("ZHULONG_TEST_FAIL_TIMELINE_VALIDATE") == "1":
        raise _error("TIMELINE_VALIDATION_FAILED", "injected timeline validation failure")
    if validate_document(document) or validate_html_bytes(html_bytes):
        raise _error("TIMELINE_VALIDATION_FAILED", "staged timeline pair failed validation")
    second = derive_timeline(workspace, repo_root)
    if second != document:
        raise _error("TIMELINE_CONCURRENT_AUTHORITY_CHANGE", "authority changed during timeline derivation")

    prior_json = json_path.read_bytes() if json_path.exists() else None
    prior_html = html_path.read_bytes() if html_path.exists() else None
    if prior_json == json_bytes and prior_html == html_bytes:
        return {
            "document": document,
            "json_path": json_output,
            "html_path": html_output,
            "json_sha256": _sha(json_bytes),
            "html_sha256": _sha(html_bytes),
            "idempotent": True,
        }
    if not overwrite and (prior_json is not None or prior_html is not None):
        raise _error(
            "TIMELINE_OVERWRITE_REQUIRED",
            "existing derived output differs; rerun with --overwrite",
        )

    staged_json: Path | None = None
    staged_html: Path | None = None
    json_replaced = False
    html_replaced = False
    try:
        staged_json = _stage_bytes(json_path, json_bytes, "json")
        staged_html = _stage_bytes(html_path, html_bytes, "html")
        staged_doc = json.loads(staged_json.read_text("utf-8"))
        if staged_doc != document or validate_document(staged_doc):
            raise _error("TIMELINE_VALIDATION_FAILED", "staged JSON differs from canonical timeline")
        if staged_html.read_bytes() != html_bytes or validate_html_bytes(staged_html.read_bytes()):
            raise _error("TIMELINE_VALIDATION_FAILED", "staged HTML differs from canonical render")
        if os.environ.get("ZHULONG_TEST_FAIL_TIMELINE_REPLACE") == "json":
            raise OSError("injected JSON replace failure")
        os.replace(staged_json, json_path)
        staged_json = None
        json_replaced = True
        if os.environ.get("ZHULONG_TEST_FAIL_TIMELINE_REPLACE") == "html":
            raise OSError("injected HTML replace failure")
        os.replace(staged_html, html_path)
        staged_html = None
        html_replaced = True
        try:
            dir_fd = os.open(json_path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except Exception as exc:
        try:
            if json_replaced:
                _restore(json_path, prior_json)
            if html_replaced:
                _restore(html_path, prior_html)
        finally:
            for staged in (staged_json, staged_html):
                if staged is not None:
                    try:
                        staged.unlink()
                    except FileNotFoundError:
                        pass
        if isinstance(exc, TimelineError):
            raise
        raise _error(
            "TIMELINE_ATOMIC_WRITE_FAILED",
            "timeline pair publication failed and previous outputs were restored",
        ) from exc

    return {
        "document": document,
        "json_path": json_output,
        "html_path": html_output,
        "json_sha256": _sha(json_bytes),
        "html_sha256": _sha(html_bytes),
        "idempotent": False,
    }


def validate_published(
    timeline_path: Path,
    *,
    workspace: Path | None = None,
    repo_root: Path | None = None,
    html_path: Path | None = None,
) -> dict[str, Any]:
    try:
        if timeline_path.is_symlink() or not timeline_path.is_file():
            raise _error("TIMELINE_PATH_UNSAFE", "timeline input must be a regular non-symlink file")
        document = json.loads(timeline_path.read_text("utf-8"))
        issues = validate_document(document)
        if workspace is not None and not issues:
            issues.extend(validate_against_workspace(document, workspace, repo_root))
        if html_path is not None:
            if html_path.is_symlink() or not html_path.is_file():
                issues.append(_issue("TIMELINE_HTML_PATH_UNSAFE", "HTML input must be a regular non-symlink file", None))
            else:
                actual_html = html_path.read_bytes()
                issues.extend(validate_html_bytes(actual_html))
                if not issues:
                    expected_html = render_html(document, workspace)
                    if actual_html != expected_html:
                        issues.append(_issue("TIMELINE_HTML_DRIFT", "HTML differs from canonical JSON render", None))
    except (OSError, UnicodeError, ValueError, TimelineError) as exc:
        issues = [_issue(getattr(exc, "code", "TIMELINE_JSON_INVALID"), str(getattr(exc, "message", exc)), None)]
        document = None
    return {
        "ok": not issues,
        "issue_codes": sorted({item["code"] for item in issues}),
        "issues": issues,
        "timeline": document if not issues else None,
    }
