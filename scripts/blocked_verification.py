#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any


BLOCKED_FILES = (
    "candidate-findings.md",
    "unverified-leads.md",
    "attack-surface.md",
    "stage-status.json",
)

PULL_BLOCKER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("docker_hub_rate_limit", re.compile(r"toomanyrequests|unauthenticated pull rate limit|docker hub rate limit", re.I)),
    ("pull_access_denied", re.compile(r"pull access denied|repository does not exist|may require ['\"]?docker login", re.I)),
    ("registry_auth_required", re.compile(r"authentication required|authorization failed|not authorized", re.I)),
    ("missing_image", re.compile(r"missing image|blocked_missing_image|no cached images?|image .* not found", re.I)),
    ("runtime_not_started", re.compile(r"runtime not started|running service target:\s*blocked|docker verification blocked", re.I)),
    ("stale_or_unresolved_image_pull", re.compile(r"running service target:\s*not started.*images? being pulled|image pull required", re.I)),
    ("network_timeout", re.compile(r"i/o timeout|context deadline exceeded|temporary failure in name resolution|no such host|network.*timeout|dns.*(timeout|failure|resolution)", re.I)),
    ("dangerous_sandbox_preflight", re.compile(r"rejected_unsafe_sandbox|dangerous_docker_config|dangerous_shell_flag|credential_exposure_risk", re.I)),
    ("missing_image", re.compile(r"(?:could not|unable to|failed to) (?:be )?pull(?:ed)?[^.\n]*\b(?:image|container image)\b|\brequired image\b[^.\n]*(?:could not|unable to|failed to) (?:be )?pull(?:ed)?", re.I)),
]

GENERIC_BLOCKED_PATTERN = re.compile(r"\bBLOCKED\b")
LOWER_BLOCKED_PATTERN = re.compile(r"\bblocked[_ -]no[_ -]docker\b|\bblocked[_ -]verification\b", re.I)
DOCKER_CONTEXT_PATTERN = re.compile(r"docker|runtime|verification|image|pull|registry|compose|service target", re.I)
HIGH_CONFIDENCE_YES_PATTERN = re.compile(
    r"high[- ]confidence[- ]unverified\?\s*(?:\||:)?\s*yes|\|\s*yes\s*(?:\([^|]*\))?\s*\|?\s*$",
    re.I,
)
MATERIALITY_MARKER_PATTERN = re.compile(
    r"material blocker\?|default runtime scope\?|why completion is still safe\?|materiality|non[- ]material|not material|optional integration|out[- ]of[- ]scope optional",
    re.I,
)
MATERIAL_NO_PATTERN = re.compile(r"material blocker\?\s*(?:\||:)?\s*no|\bnon[- ]material\b|\bnot material\b", re.I)
RESOLVED_TEXT_PATTERN = re.compile(
    r"\b(?:resolved|recovered|subsequently succeeded|no longer blocked|blocker cleared|verification completed)\b|"
    r"\bnot\s+(?:blocked|missing|timed out)\b",
    re.I,
)
STRUCTURED_BLOCKED_STATUSES = {
    "blocked_state_precondition",
    "blocked_authority_event_commit",
    "blocked_docker_unavailable",
    "blocked_missing_image",
    "failed_timeout",
    "failed_resource_limit",
    "rejected_unsafe_sandbox",
    "blocked",
    "unverified",
}
STRUCTURED_RESOLVED_STATUSES = {"confirmed_in_docker", "rejected_not_reproducible", "false_positive"}
MAX_STRUCTURED_BYTES = 2 * 1024 * 1024


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    if path.suffix == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return path.read_text(encoding="utf-8", errors="ignore")
        return json.dumps(data, ensure_ascii=False, sort_keys=True)
    text = path.read_text(encoding="utf-8", errors="ignore")
    if "\\n" in text and text.count("\n") <= 1:
        text = text.replace("\\n", "\n")
    return text


def classify_pull_blocker(text: str) -> tuple[str, str]:
    for label, pattern in PULL_BLOCKER_PATTERNS:
        if pattern.search(text):
            return label, recovery_step(label)
    if re.search(r"rate\s*limit", text, re.I) and DOCKER_CONTEXT_PATTERN.search(text):
        return "docker_hub_rate_limit", recovery_step("docker_hub_rate_limit")
    if GENERIC_BLOCKED_PATTERN.search(text) and DOCKER_CONTEXT_PATTERN.search(text):
        return "docker_verification_blocked", recovery_step("docker_verification_blocked")
    return "", ""


def recovery_step(label: str) -> str:
    if label == "docker_hub_rate_limit":
        return (
            "Docker Hub pull rate limit blocked runtime verification. Have the operator run `docker login`, "
            "pre-pull the required images, or configure an approved equivalent registry mirror, then rerun Docker verification."
        )
    if label in {"pull_access_denied", "registry_auth_required"}:
        return (
            "Image pull requires registry access. Verify credentials/permissions with the operator, pre-pull the required image, "
            "then rerun Docker verification; do not finalize yet."
        )
    if label == "missing_image":
        return (
            "Required Docker image is missing. Build or pre-pull the exact required image, record its digest/provenance, "
            "then rerun Docker verification."
        )
    if label == "high_confidence_blocked_without_materiality":
        return (
            "A high-confidence unverified lead still has blocked/no-Docker verification without materiality rationale. "
            "Add Material blocker?, Default runtime scope?, and Why completion is still safe? rationale, or resume Docker verification."
        )
    if label == "network_timeout":
        return (
            "Docker image pull appears blocked by network/DNS timeout. Fix network access or configure an approved mirror, "
            "then rerun Docker verification."
        )
    if label == "dangerous_sandbox_preflight":
        return (
            "Sandbox preflight rejected unsafe Docker configuration. Rewrite the verification container or script to avoid "
            "privileged/host/docker.sock/root-mount behavior, then rerun Docker verification."
        )
    return "Resolve the Docker/runtime blocker, start the target runtime, rerun Docker verification, and only then retry finalization."


def markdown_cells(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return []
    return [cell.strip() for cell in stripped.strip("|").split("|")]


def has_materiality_rationale(line: str) -> bool:
    normalized = line.strip()
    if MATERIAL_NO_PATTERN.search(normalized) and MATERIALITY_MARKER_PATTERN.search(normalized):
        return True
    cells = markdown_cells(normalized)
    if len(cells) >= 10:
        material = cells[7].lower()
        runtime_scope = cells[8].strip()
        rationale = cells[9].strip()
        return material in {"no", "n", "false"} and bool(runtime_scope) and bool(rationale)
    return False


def high_confidence_yes(line: str) -> bool:
    normalized = line.strip()
    if HIGH_CONFIDENCE_YES_PATTERN.search(normalized):
        return True
    cells = markdown_cells(normalized)
    if len(cells) >= 7:
        return cells[6].strip().lower().startswith("yes")
    return False


def interesting_line(line: str) -> tuple[str, str]:
    normalized = line.strip()
    if not normalized:
        return "", ""
    if normalized.lower().startswith(("example:", "for example:", "示例：", "例如：")) or RESOLVED_TEXT_PATTERN.search(normalized):
        return "", ""
    if LOWER_BLOCKED_PATTERN.search(normalized) and has_materiality_rationale(normalized):
        return "", ""
    if (
        LOWER_BLOCKED_PATTERN.search(normalized)
        and high_confidence_yes(normalized)
        and not has_materiality_rationale(normalized)
    ):
        return "high_confidence_blocked_without_materiality", recovery_step("high_confidence_blocked_without_materiality")
    label, step = classify_pull_blocker(normalized)
    if label:
        return label, step
    if LOWER_BLOCKED_PATTERN.search(normalized) and DOCKER_CONTEXT_PATTERN.search(normalized):
        return "docker_verification_blocked", recovery_step("docker_verification_blocked")
    if GENERIC_BLOCKED_PATTERN.search(normalized) and DOCKER_CONTEXT_PATTERN.search(normalized):
        return "docker_verification_blocked", recovery_step("docker_verification_blocked")
    return "", ""


def _safe_json_object(workspace: Path, path: Path) -> tuple[dict[str, Any] | None, str | None]:
    root = workspace.resolve()
    try:
        relative = path.relative_to(workspace).as_posix()
    except ValueError:
        return None, "STRUCTURED_PATH_ESCAPE"
    current = root
    for part in Path(relative).parts:
        current = current / part
        try:
            info = os.lstat(current)
        except OSError:
            return None, "STRUCTURED_PATH_MISSING"
        if stat.S_ISLNK(info.st_mode):
            return None, "STRUCTURED_PATH_SYMLINK"
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_STRUCTURED_BYTES:
            return None, "STRUCTURED_FILE_UNSAFE"
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino) or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                return None, "STRUCTURED_FILE_DRIFT"
            raw = b""
            while len(raw) <= MAX_STRUCTURED_BYTES:
                chunk = os.read(fd, min(65536, MAX_STRUCTURED_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw += chunk
        finally:
            os.close(fd)
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, "STRUCTURED_JSON_INVALID"
    return (value, None) if isinstance(value, dict) else (None, "STRUCTURED_JSON_INVALID")


def _named_regular_files(workspace: Path, filename: str) -> list[Path]:
    matches: list[Path] = []
    for root, dirs, files in os.walk(workspace, followlinks=False):
        safe_dirs: list[str] = []
        for name in dirs:
            try:
                if not stat.S_ISLNK(os.lstat(Path(root) / name).st_mode):
                    safe_dirs.append(name)
            except OSError:
                continue
        dirs[:] = safe_dirs
        if filename in files:
            matches.append(Path(root) / filename)
    return sorted(matches, key=lambda item: item.relative_to(workspace).as_posix())


def _structured_facts(workspace: Path) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], int]:
    states: dict[str, dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []
    fact_count = 0

    def apply(identity: str, blocked: bool, classification: str, source: str, *, resume_step: str = "") -> None:
        nonlocal fact_count
        fact_count += 1
        states[identity] = {
            "blocked": blocked,
            "classification": classification,
            "source": source,
            "resume_step": resume_step,
        }

    result_documents: list[tuple[str, str, dict[str, Any]]] = []
    for path in _named_regular_files(workspace, "verification-result.json"):
        relative = path.relative_to(workspace).as_posix()
        document, error = _safe_json_object(workspace, path)
        if error is not None or document is None:
            apply(f"artifact:{relative}", True, error or "STRUCTURED_JSON_INVALID", relative)
            continue
        case_id = str(document.get("case_id") or "").strip()
        status = str(document.get("wrapper_status") or document.get("status") or "").strip()
        if not case_id or not status:
            apply(f"artifact:{relative}", True, "STRUCTURED_RESULT_INCOMPLETE", relative)
            continue
        result_documents.append((str(document.get("finished_at") or ""), relative, document))
    for _finished_at, relative, document in sorted(result_documents):
        case_id = str(document.get("case_id") or "").strip()
        status = str(document.get("wrapper_status") or document.get("status") or "").strip()
        authority_failed = document.get("authority_event_committed") is False or status == "blocked_authority_event_commit"
        if authority_failed or status in STRUCTURED_BLOCKED_STATUSES or status.startswith("blocked_"):
            apply(f"case:{case_id}", True, status or "authority_event_commit_failure", relative, resume_step=str(document.get("resume_step") or ""))
        elif status in STRUCTURED_RESOLVED_STATUSES and document.get("authority_event_committed") is not False:
            apply(f"case:{case_id}", False, status, relative)

    verdict_documents: list[tuple[str, str, dict[str, Any]]] = []
    for path in _named_regular_files(workspace, "verifier-verdict.json"):
        relative = path.relative_to(workspace).as_posix()
        document, error = _safe_json_object(workspace, path)
        if error is not None or document is None:
            apply(f"artifact:{relative}", True, error or "STRUCTURED_JSON_INVALID", relative)
            continue
        candidate_id = str(document.get("candidate_id") or "").strip()
        status = str(document.get("verification_status") or document.get("verdict") or "").strip()
        if not candidate_id or not status:
            apply(f"artifact:{relative}", True, "STRUCTURED_VERDICT_INCOMPLETE", relative)
            continue
        verdict_documents.append((str(document.get("verified_at") or ""), relative, document))
    for _verified_at, relative, document in sorted(verdict_documents):
        candidate_id = str(document.get("candidate_id") or "").strip()
        status = str(document.get("verification_status") or document.get("verdict") or "").strip()
        apply(f"candidate:{candidate_id}", status in STRUCTURED_BLOCKED_STATUSES or status.startswith("blocked_"), status, relative)

    ledger_path = workspace / "audit-disposition.json"
    if ledger_path.exists() or ledger_path.is_symlink():
        document, error = _safe_json_object(workspace, ledger_path)
        if error is not None or document is None:
            apply("artifact:audit-disposition.json", True, error or "STRUCTURED_JSON_INVALID", "audit-disposition.json")
        else:
            for record in document.get("candidate_dispositions", []) if isinstance(document.get("candidate_dispositions"), list) else []:
                if not isinstance(record, dict):
                    continue
                candidate_id = str(record.get("candidate_id") or "").strip()
                status = str(record.get("status") or "").strip()
                if candidate_id and status:
                    apply(f"candidate:{candidate_id}", status in {"candidate", "blocked", "unverified"} or status.startswith("blocked_"), status, "audit-disposition.json")
            for item in document.get("items", []) if isinstance(document.get("items"), list) else []:
                if not isinstance(item, dict):
                    continue
                item_id = str(item.get("id") or "").strip()
                state = str(item.get("state") or "").strip()
                docker_status = str(item.get("docker_status") or "").strip()
                if item_id and (state or docker_status):
                    blocked = state in {"candidate", "blocked", "unverified"} or docker_status in {"blocked", "timed_out", "dirty_state"}
                    apply(f"disposition:{item_id}", blocked, docker_status or state, "audit-disposition.json")

    try:
        from audit_state_io import read_normalized_workspace_events
        _status, events, _mode = read_normalized_workspace_events(workspace)
    except Exception:
        events = []
    for event in events:
        name = str(event.get("event") or "")
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        case_id = str(details.get("case_id") or "").strip()
        if not case_id:
            subjects = event.get("subjects") if isinstance(event.get("subjects"), list) else []
            case_id = next((str(subject).split(":", 1)[1] for subject in subjects if isinstance(subject, str) and subject.startswith("verification:")), "")
        if name == "verification_case_blocked" or (event.get("stage") == "verification" and event.get("status") == "blocked"):
            apply(f"case:{case_id}" if case_id else "workspace:verification", True, str(details.get("legacy_event_status") or name), "audit-events.jsonl", resume_step=str(event.get("resume_step") or ""))
        elif name in {"verification_case_completed", "verification_case_rejected"} and case_id:
            apply(f"case:{case_id}", False, str(details.get("legacy_event_status") or name), "audit-events.jsonl")

    for identity, state in sorted(states.items()):
        if not state.get("blocked"):
            continue
        findings.append({
            "source": state["source"],
            "identity": identity,
            "classification": state["classification"],
            "structured": True,
        })
    return states, findings, fact_count


def detect_blocked_verification(workspace: Path) -> dict[str, Any]:
    structured_states, findings, structured_fact_count = _structured_facts(workspace)
    recovery_steps: list[str] = []
    labels: set[str] = {str(item.get("classification")) for item in findings}
    for state in structured_states.values():
        step = str(state.get("resume_step") or "")
        if state.get("blocked") and step and step not in recovery_steps:
            recovery_steps.append(step)
    if structured_fact_count == 0:
        for rel_path in BLOCKED_FILES:
            path = workspace / rel_path
            text = read_text(path)
            if not text:
                continue
            for line_no, line in enumerate(text.splitlines(), start=1):
                label, step = interesting_line(line)
                if not label:
                    continue
                excerpt = line.strip()
                if len(excerpt) > 240:
                    excerpt = excerpt[:237] + "..."
                findings.append({
                    "source": rel_path,
                    "line": line_no,
                    "classification": label,
                    "excerpt": excerpt,
                    "structured": False,
                })
                labels.add(label)
                if step and step not in recovery_steps:
                    recovery_steps.append(step)
                if len(findings) >= 20:
                    break
    blocked = bool(findings)
    return {
        "blocked": blocked,
        "classification": "blocked_verification" if blocked else "not_blocked",
        "labels": sorted(labels),
        "findings": findings,
        "structured_fact_count": structured_fact_count,
        "resolved_identities": sorted(identity for identity, state in structured_states.items() if not state.get("blocked")),
        "resume_step": recovery_steps[0] if recovery_steps else "",
        "recovery_steps": recovery_steps,
    }
