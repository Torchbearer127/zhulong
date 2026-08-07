#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from candidate_identity import file_sha256

from blocked_verification import detect_blocked_verification
from validate_candidate import (
    ValidationError as CandidateValidationError,
    load_candidate,
    validate_candidate,
)
from validate_verifier_verdict import (
    ValidationError as VerdictValidationError,
    cross_check_candidate,
    load_verdict,
    validate_verdict,
)


LEDGER_FILENAME = "audit-disposition.json"
SCHEMA_VERSION = 1

STATES = {
    "candidate",
    "confirmed",
    "false_positive",
    "blocked",
    "unverified",
    "not_applicable",
    "out_of_scope",
}
VERDICT_DISPOSITION_STATUSES = {"confirmed_in_docker", "false_positive", "unverified", "blocked"}
SOURCE_TYPES = {"scanner", "dependency", "static", "llm", "manual", "runtime", "hybrid"}
DOCKER_STATUSES = {
    "not_started",
    "reproduced",
    "not_applicable",
    "failed",
    "blocked",
    "timed_out",
    "dirty_state",
}
REASON_CODES = {
    "docker_reproduced",
    "scanner_only",
    "dependency_only",
    "static_only",
    "llm_only",
    "blocked_by_docker",
    "timed_out",
    "dirty_docker",
    "insufficient_evidence",
    "not_reproducible",
    "safe_config",
    "out_of_scope",
}
SOURCE_ONLY_TYPES = {"scanner", "dependency", "static", "llm"}
SOURCE_ONLY_REASON_CODES = {"scanner_only", "dependency_only", "static_only", "llm_only"}
MATERIAL_BLOCKING_DOCKER_STATUSES = {"blocked", "timed_out", "dirty_state"}
CONFIRMED_DIR = "confirmed"


class DispositionUpdateError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def load_disposition_ledger(workspace: Path) -> dict[str, Any]:
    return read_json(workspace / LEDGER_FILENAME)


def write_disposition_ledger(workspace: Path, ledger: dict[str, Any]) -> Path:
    path = workspace / LEDGER_FILENAME
    path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def read_markdown_text(path: Path) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="ignore")
    if "\\n" in text and text.count("\n") <= 1:
        text = text.replace("\\n", "\n")
    return text


def markdown_cells(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return []
    return [cell.strip() for cell in stripped.strip("|").split("|")]


def is_separator_row(cells: list[str]) -> bool:
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) for cell in cells)


def normalize_header(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def markdown_table_rows(path: Path) -> list[tuple[int, dict[str, str], list[str]]]:
    rows: list[tuple[int, dict[str, str], list[str]]] = []
    headers: list[str] = []
    for line_no, raw in enumerate(read_markdown_text(path).splitlines(), start=1):
        cells = markdown_cells(raw)
        if not cells:
            headers = []
            continue
        if is_separator_row(cells):
            continue
        if not headers:
            headers = cells
            continue
        mapping = {
            normalize_header(header): cells[index].strip() if index < len(cells) else ""
            for index, header in enumerate(headers)
        }
        rows.append((line_no, mapping, cells))
    return rows


def slugify(value: str, fallback: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.:-]+", "-", value.strip()).strip("-:.").lower()
    return slug or fallback


def first_value(mapping: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = str(mapping.get(normalize_header(key)) or "").strip()
        if value:
            return value
    return ""


def infer_source_type(text: str) -> str:
    lowered = text.lower()
    hits: set[str] = set()
    if re.search(r"\b(scanner|semgrep|gitleaks|trivy|grype|osv-scanner|scan result|scanner-only)\b", lowered):
        hits.add("scanner")
    if re.search(r"\b(dependency|package|lockfile|npm audit|pip-audit|cve|ghsa|snyk|dependency-only)\b", lowered):
        hits.add("dependency")
    if re.search(r"\b(static|source-to-sink|codeql|pattern match|grep|taint|static-only)\b", lowered):
        hits.add("static")
    if re.search(r"\b(llm|model|ai analysis|llm-only)\b", lowered):
        hits.add("llm")
    if re.search(r"\b(docker|runtime|poc|reproduced|confirmed_in_docker|curl|compose)\b", lowered):
        hits.add("runtime")
    if re.search(r"\b(manual|reviewed|human|triage)\b", lowered):
        hits.add("manual")
    if not hits:
        return "manual"
    if len(hits) == 1:
        return next(iter(hits))
    return "hybrid"


def infer_docker_status(text: str) -> str:
    lowered = text.lower()
    if re.search(r"dirty[_ -]?state|dirty docker|unclean docker", lowered):
        return "dirty_state"
    if re.search(r"timed?[-_ ]?out|timeout|failed_timeout", lowered):
        return "timed_out"
    if re.search(
        r"blocked|blocked_no_docker|blocked[_ -]verification|docker rate limit|pull access denied|"
        r"authentication required|missing image|runtime not started|image pull required|no cached image|"
        r"rejected_unsafe_sandbox|dangerous_docker_config|dangerous_shell_flag|credential_exposure_risk|unsafe sandbox",
        lowered,
    ):
        return "blocked"
    if re.search(r"confirmed_in_docker|docker[-_ ]confirmed|reproduced|confirmed in docker", lowered):
        return "reproduced"
    if re.search(r"not applicable|n/a|not_applicable|out of scope|out_of_scope|safe config|no docker needed", lowered):
        return "not_applicable"
    if re.search(r"failed|not reproducible|not_reproducible|rejected", lowered):
        return "failed"
    return "not_started"


def infer_state(default_state: str, text: str) -> str:
    lowered = text.lower()
    if re.search(r"out[_ -]of[_ -]scope", lowered):
        return "out_of_scope"
    if re.search(r"not[_ -]applicable|\bn/a\b", lowered):
        return "not_applicable"
    if re.search(r"rejected_unsafe_sandbox|dangerous_docker_config|dangerous_shell_flag|credential_exposure_risk|unsafe sandbox", lowered):
        return "blocked"
    if re.search(r"false[_ -]positive|non-security|not reproducible|safe config|rejected", lowered):
        return "false_positive"
    if infer_docker_status(text) in {"blocked", "timed_out", "dirty_state"}:
        return "blocked"
    if re.search(r"unverified|high-confidence-unverified|insufficient evidence", lowered):
        return "unverified"
    return default_state


def infer_reason_code(state: str, source_type: str, docker_status: str, text: str) -> str:
    lowered = text.lower()
    if state == "confirmed":
        return "docker_reproduced"
    if state == "out_of_scope" or "out of scope" in lowered or "out_of_scope" in lowered:
        return "out_of_scope"
    if docker_status == "blocked":
        return "blocked_by_docker"
    if docker_status == "timed_out":
        return "timed_out"
    if docker_status == "dirty_state":
        return "dirty_docker"
    if "safe config" in lowered:
        return "safe_config"
    if state == "false_positive" or docker_status == "failed":
        return "not_reproducible"
    if source_type in SOURCE_ONLY_TYPES:
        return f"{source_type}_only"
    return "insufficient_evidence"


def is_docker_applicable(text: str, docker_status: str, *, default: bool) -> bool:
    lowered = text.lower()
    if docker_status == "not_applicable":
        return False
    if re.search(r"not applicable|not_applicable|out of scope|out_of_scope|no docker needed", lowered):
        return False
    if re.search(r"docker|runtime|compose|poc|reproduce|verification", lowered):
        return True
    return default


def shorten(value: str, limit: int = 500) -> str:
    text = re.sub(r"\s+", " ", value).strip()
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def complete_item(item: dict[str, Any]) -> dict[str, Any]:
    text = " ".join(str(item.get(key) or "") for key in ("title", "materiality_rationale", "reason_code"))
    docker_status = str(item.get("docker_status") or infer_docker_status(text)).strip()
    state = str(item.get("state") or infer_state("candidate", text)).strip()
    source_type = str(item.get("source_type") or infer_source_type(text)).strip()
    reason_code = str(item.get("reason_code") or infer_reason_code(state, source_type, docker_status, text)).strip()
    return {
        "id": str(item.get("id") or "").strip(),
        "title": str(item.get("title") or item.get("id") or "").strip(),
        "state": state,
        "source_type": source_type,
        "docker_applicable": bool(item.get("docker_applicable", is_docker_applicable(text, docker_status, default=True))),
        "docker_status": docker_status,
        "reason_code": reason_code,
        "confirmed_bundle_path": str(item.get("confirmed_bundle_path") or "").strip(),
        "materiality_rationale": str(item.get("materiality_rationale") or "").strip(),
    }


def confirmed_bundle_dirs(workspace: Path) -> list[Path]:
    confirmed_dir = workspace / CONFIRMED_DIR
    if not confirmed_dir.exists() or not confirmed_dir.is_dir():
        return []
    return sorted(path for path in confirmed_dir.iterdir() if path.is_dir() and not path.name.startswith("."))


def confirmed_bundle_items(workspace: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for bundle_dir in confirmed_bundle_dirs(workspace):
        evidence = read_json(bundle_dir / "verification-evidence.json")
        finding_slug = str(evidence.get("finding_slug") or "").strip()
        title = finding_slug or bundle_dir.name
        rel_path = f"{CONFIRMED_DIR}/{bundle_dir.name}"
        items.append({
            "id": f"confirmed:{slugify(bundle_dir.name, 'bundle')}",
            "title": title,
            "state": "confirmed",
            "source_type": "hybrid",
            "docker_applicable": True,
            "docker_status": "reproduced",
            "reason_code": "docker_reproduced",
            "confirmed_bundle_path": rel_path,
            "materiality_rationale": "Confirmed bundle is expected to contain Docker reproduction evidence and pass bundle validation.",
        })
    return items


def workspace_relative(workspace: Path, path: Path) -> str:
    return path.resolve().relative_to(workspace.resolve()).as_posix()


def resolve_under_workspace(workspace: Path, raw_path: str, label: str) -> Path:
    if not raw_path:
        raise DispositionUpdateError(f"{label} is required")
    path, error = safe_workspace_path(workspace, raw_path, label=label)
    if error:
        raise DispositionUpdateError(error)
    if path is None or not path.is_file():
        raise DispositionUpdateError(f"{label} must reference an existing regular workspace file")
    return path


def disposition_record_from_candidate(
    workspace: Path,
    candidate_path: Path,
    candidate_doc: dict[str, Any],
    *,
    status: str = "candidate",
    source: str = "candidate-contract",
    verdict_path: Path | None = None,
    verdict_doc: dict[str, Any] | None = None,
) -> dict[str, Any]:
    oracle_result = verdict_doc.get("oracle_result") if isinstance(verdict_doc, dict) else {}
    oracle_summary = str(oracle_result.get("summary") or "") if isinstance(oracle_result, dict) else ""
    poc = candidate_doc.get("poc") if isinstance(candidate_doc.get("poc"), dict) else {}
    record: dict[str, Any] = {
        "candidate_id": str(candidate_doc.get("candidate_id") or ""),
        "status": status,
        "title": str(candidate_doc.get("title") or ""),
        "bug_class": str(candidate_doc.get("bug_class") or ""),
        "source": source,
        "candidate_path": workspace_relative(workspace, candidate_path),
        "target_ref": candidate_doc.get("target_ref", {}),
        "entrypoint": candidate_doc.get("entrypoint", {}),
        "claim": candidate_doc.get("claim", {}),
        "poc_path": str(poc.get("path") or ""),
        "oracle_summary": oracle_summary,
        "updated_at": utc_now(),
    }
    checked = validate_candidate(candidate_doc)
    if checked.get("protocol_mode") == "r2":
        record["candidate_protocol_mode"] = "r2"
        record["candidate_sha256"] = file_sha256(candidate_path)
        record["candidate_fingerprint"] = checked["fingerprint"]
    if verdict_path is not None:
        record["verdict_path"] = workspace_relative(workspace, verdict_path)
    if isinstance(verdict_doc, dict) and verdict_doc.get("evidence_level"):
        record["evidence_level"] = str(verdict_doc.get("evidence_level") or "").strip()
    if isinstance(verdict_doc, dict):
        record["verification_status"] = str(verdict_doc.get("verification_status") or "").strip()
        record["disposition_recommendation"] = str(verdict_doc.get("disposition_recommendation") or "").strip()
        record["verdict_candidate_id"] = str(verdict_doc.get("candidate_id") or "").strip()
    return record


def candidate_contract_disposition_records(workspace: Path) -> list[dict[str, Any]]:
    candidates_dir = workspace / "candidates"
    if not candidates_dir.exists() or not candidates_dir.is_dir():
        return []
    records: list[dict[str, Any]] = []
    for candidate_path in sorted(candidates_dir.glob("*/candidate.json")):
        try:
            candidate_doc = load_candidate(candidate_path)
            validate_candidate(candidate_doc)
        except CandidateValidationError:
            continue
        records.append(disposition_record_from_candidate(workspace, candidate_path, candidate_doc))
    return records


def merge_candidate_dispositions(
    existing_records: list[dict[str, Any]],
    synthesized_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {
        str(record.get("candidate_id") or ""): record
        for record in existing_records
        if isinstance(record, dict) and str(record.get("candidate_id") or "")
    }
    for record in synthesized_records:
        candidate_id = str(record.get("candidate_id") or "")
        if not candidate_id:
            continue
        old = merged.get(candidate_id)
        if old is None or str(old.get("status") or "") == "candidate":
            merged[candidate_id] = record
    return [merged[key] for key in sorted(merged)]


def candidate_disposition_records(ledger: dict[str, Any]) -> list[dict[str, Any]]:
    records = ledger.get("candidate_dispositions")
    if not isinstance(records, list):
        return []
    return [record for record in records if isinstance(record, dict)]


def triage_items_from_file(workspace: Path, filename: str, *, default_state: str) -> list[dict[str, Any]]:
    path = workspace / filename
    prefix = filename.removesuffix(".md")
    items: list[dict[str, Any]] = []
    for line_no, mapping, cells in markdown_table_rows(path):
        raw_id = first_value(mapping, "Candidate ID", "Lead ID", "ID") or (cells[0].strip() if cells else "")
        item_id = f"{prefix}:{slugify(raw_id, f'row-{line_no}')}"
        title = first_value(mapping, "Suspected Weakness", "Original Suspicion", "Title")
        if not title and len(cells) > 1:
            title = cells[1].strip()
        row_text = " | ".join(cells)
        docker_text = first_value(mapping, "Docker Verification Status", "Docker Confirmation Status", "Status")
        docker_status = infer_docker_status(docker_text or row_text)
        state = infer_state(default_state, row_text)
        source_type = infer_source_type(row_text)
        reason_code = infer_reason_code(state, source_type, docker_status, row_text)
        materiality_parts = []
        for label in (
            "Evidence So Far",
            "Rejection Reason",
            "Missing Evidence",
            "Safe Resume Step",
            "Material blocker?",
            "Default runtime scope?",
            "Why completion is still safe?",
            "Next Action",
            "Status",
        ):
            value = first_value(mapping, label)
            if value:
                materiality_parts.append(f"{label}: {value}")
        items.append({
            "id": item_id,
            "title": title or raw_id or f"{filename}:{line_no}",
            "state": state,
            "source_type": source_type,
            "docker_applicable": is_docker_applicable(row_text, docker_status, default=state not in {"false_positive", "not_applicable", "out_of_scope"}),
            "docker_status": docker_status,
            "reason_code": reason_code,
            "confirmed_bundle_path": "",
            "materiality_rationale": shorten("; ".join(materiality_parts) or row_text),
        })
    return items


def blocked_verification_items(workspace: Path, blocked_summary: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    summary = blocked_summary if isinstance(blocked_summary, dict) else detect_blocked_verification(workspace)
    findings = summary.get("findings") if isinstance(summary, dict) else []
    resume_step = str(summary.get("resume_step") or "") if isinstance(summary, dict) else ""
    items: list[dict[str, Any]] = []
    if not isinstance(findings, list):
        return items
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        source = str(finding.get("source") or "unknown").strip()
        line = str(finding.get("line") or "0").strip()
        classification = str(finding.get("classification") or "blocked_verification").strip()
        excerpt = str(finding.get("excerpt") or "").strip()
        status = infer_docker_status(" ".join([classification, excerpt]))
        if status not in MATERIAL_BLOCKING_DOCKER_STATUSES:
            status = "blocked"
        reason = "timed_out" if status == "timed_out" else "dirty_docker" if status == "dirty_state" else "blocked_by_docker"
        items.append({
            "id": f"blocked:{slugify(source, 'source')}:{slugify(line, 'line')}",
            "title": classification,
            "state": "blocked",
            "source_type": "runtime",
            "docker_applicable": True,
            "docker_status": status,
            "reason_code": reason,
            "confirmed_bundle_path": "",
            "materiality_rationale": shorten(f"{excerpt} Resume step: {resume_step}"),
        })
    return items


def ledger_items(ledger: dict[str, Any]) -> list[dict[str, Any]]:
    items = ledger.get("items")
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def merge_items(existing: list[dict[str, Any]], synthesized: list[dict[str, Any]]) -> list[dict[str, Any]]:
    existing_by_id = {str(item.get("id") or ""): item for item in existing if str(item.get("id") or "")}
    consumed: set[str] = set()
    merged: list[dict[str, Any]] = []
    generated_prefixes = (
        "confirmed:",
        "candidate-findings:",
        "false-positives:",
        "unverified-leads:",
        "blocked:",
    )
    for synthesized_item in synthesized:
        item_id = str(synthesized_item.get("id") or "")
        old_item = existing_by_id.get(item_id)
        if old_item is None:
            merged.append(complete_item(synthesized_item))
            continue
        if synthesized_item.get("state") == "confirmed" or synthesized_item.get("confirmed_bundle_path"):
            merged_item = {**old_item, **synthesized_item}
        else:
            merged_item = {**synthesized_item, **old_item}
            for key, value in synthesized_item.items():
                if merged_item.get(key) in {None, ""}:
                    merged_item[key] = value
        merged.append(complete_item(merged_item))
        consumed.add(item_id)
    for item_id, old_item in existing_by_id.items():
        if item_id not in consumed and not item_id.startswith(generated_prefixes):
            merged.append(complete_item(old_item))
    return merged


def synthesize_disposition_ledger(
    workspace: Path,
    *,
    existing_ledger: dict[str, Any] | None = None,
    blocked_summary: dict[str, Any] | None = None,
    merge_existing: bool = True,
) -> dict[str, Any]:
    workspace = workspace.resolve()
    synthesized: list[dict[str, Any]] = []
    synthesized.extend(confirmed_bundle_items(workspace))
    synthesized.extend(triage_items_from_file(workspace, "candidate-findings.md", default_state="candidate"))
    synthesized.extend(triage_items_from_file(workspace, "false-positives.md", default_state="false_positive"))
    synthesized.extend(triage_items_from_file(workspace, "unverified-leads.md", default_state="unverified"))
    synthesized.extend(blocked_verification_items(workspace, blocked_summary))

    existing = ledger_items(existing_ledger if existing_ledger is not None else load_disposition_ledger(workspace))
    items = merge_items(existing, synthesized) if merge_existing and existing else [complete_item(item) for item in synthesized]
    items.sort(key=lambda item: (str(item.get("state") != "confirmed"), str(item.get("id") or "")))
    existing_ledger_doc = existing_ledger if existing_ledger is not None else load_disposition_ledger(workspace)
    candidate_dispositions = merge_candidate_dispositions(
        candidate_disposition_records(existing_ledger_doc) if merge_existing else [],
        candidate_contract_disposition_records(workspace),
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "workspace": workspace.name,
        "candidate_dispositions": candidate_dispositions,
        "items": items,
    }


def safe_workspace_path(
    workspace: Path,
    value: str,
    *,
    label: str = "confirmed_bundle_path",
) -> tuple[Path | None, str | None]:
    """Resolve one workspace-relative path without following symlinks.

    ``Path.resolve()`` is deliberately not used for authority inputs: resolving
    first would make a symlink escape look like a legitimate in-workspace path.
    The caller decides whether the final object must be a file or directory;
    this helper only proves lexical containment and rejects symlink ancestors.
    Diagnostics contain the supplied workspace-relative value, never the local
    absolute workspace path.
    """
    raw_value = str(value or "").strip()
    if not raw_value:
        return None, None
    if "\\" in raw_value:
        return None, f"{label} must use a workspace-relative POSIX path: {raw_value}"
    raw = PurePosixPath(raw_value)
    if raw.is_absolute():
        return None, f"{label} must be workspace-relative: {raw_value}"
    parts = raw.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return None, f"{label} contains an unsafe path component: {raw_value}"

    workspace_root = workspace.resolve()
    current = workspace_root
    try:
        root_info = os.lstat(current)
    except OSError:
        return None, f"{label} workspace root is not accessible"
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        return None, f"{label} workspace root is not a real directory"

    for index, part in enumerate(parts):
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            # A missing tail is safe to report to the caller, which can then
            # distinguish a missing file from a missing directory or object.
            return current, None
        except OSError:
            return None, f"{label} cannot be inspected: {raw_value}"
        if stat.S_ISLNK(info.st_mode):
            return None, f"{label} must not traverse a symlink: {raw_value}"
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            return None, f"{label} has a non-directory ancestor: {raw_value}"
    return current, None


def rel_confirmed_path(path: Path, workspace: Path) -> str:
    return path.relative_to(workspace.resolve()).as_posix()


def validator_path(workspace: Path) -> Path | None:
    candidates = [
        workspace / "bin" / "validate-all-report-bundles.py",
        Path(__file__).resolve().parent / "validate_all_report_bundles.py",
        Path(__file__).resolve().parent / "validate-all-report-bundles.py",
    ]
    return next((path for path in candidates if path.exists()), None)


def run_bundle_validator(workspace: Path, language: str) -> dict[str, Any]:
    confirmed_dir = workspace / CONFIRMED_DIR
    if not confirmed_bundle_dirs(workspace):
        return {"summary": {"bundle_validated": 0, "partial_confirmed_bundle": 0, "validation_failed": 0}, "results": []}
    validator = validator_path(workspace)
    if validator is None:
        return {"error": "validate_all_report_bundles.py not found"}
    proc = subprocess.run(
        [sys.executable, str(validator), "--confirmed-dir", str(confirmed_dir), "--language", language, "--json"],
        capture_output=True,
        text=True,
    )
    try:
        data = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return {
            "error": "bundle validator did not produce valid JSON",
            "exit_code": proc.returncode,
            "output": ((proc.stdout or "") + (proc.stderr or "")).strip()[:500],
        }
    data["exit_code"] = proc.returncode
    return data


def load_valid_candidate_and_verdict(candidate_path: Path, verdict_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        candidate_doc = load_candidate(candidate_path)
        validate_candidate(candidate_doc)
    except CandidateValidationError as exc:
        raise DispositionUpdateError("candidate validation failed: production candidate validator rejected candidate.json") from exc
    try:
        verdict_doc = load_verdict(verdict_path)
        validate_verdict(verdict_doc)
        cross_check_candidate(candidate_path, verdict_doc)
    except (CandidateValidationError, VerdictValidationError) as exc:
        raise DispositionUpdateError("verifier verdict validation failed: production verifier validator rejected verifier-verdict.json") from exc
    verdict = str(verdict_doc.get("verdict") or "")
    if verdict not in VERDICT_DISPOSITION_STATUSES:
        raise DispositionUpdateError(f"verifier verdict cannot be mapped to disposition: {verdict or '<missing>'}")
    return candidate_doc, verdict_doc


def validate_candidate_disposition_record(
    workspace: Path,
    record: dict[str, Any],
) -> dict[str, Any]:
    """Validate one ledger record against production candidate/verdict files."""
    candidate_id = str(record.get("candidate_id") or "").strip()
    label = candidate_id or "candidate disposition"
    candidate_value = str(record.get("candidate_path") or "").strip()
    status = str(record.get("status") or "").strip()
    source = str(record.get("source") or "").strip()
    if not candidate_value:
        raise DispositionUpdateError(f"{label}: candidate_path is required")
    candidate_path, path_error = safe_workspace_path(workspace, candidate_value, label="candidate_path")
    if path_error:
        raise DispositionUpdateError(f"{label}: {path_error}")
    if candidate_path is None or not candidate_path.is_file():
        raise DispositionUpdateError(f"{label}: candidate_path must reference an existing regular file")
    try:
        candidate_doc = load_candidate(candidate_path)
        candidate_checked = validate_candidate(candidate_doc)
    except CandidateValidationError as exc:
        raise DispositionUpdateError(f"{label}: production candidate validator rejected candidate_path") from exc

    actual_candidate_id = str(candidate_doc.get("candidate_id") or "")
    if candidate_id != actual_candidate_id or candidate_checked.get("candidate_id") != candidate_id:
        raise DispositionUpdateError(f"{label}: candidate_id does not match candidate.json")
    if record.get("target_ref") != candidate_doc.get("target_ref"):
        raise DispositionUpdateError(f"{label}: target_ref does not match candidate.json")
    for field in ("title", "bug_class", "entrypoint", "claim"):
        if field in record and record.get(field) != candidate_doc.get(field):
            raise DispositionUpdateError(f"{label}: {field} does not match candidate.json")
    candidate_poc = candidate_doc.get("poc") if isinstance(candidate_doc.get("poc"), dict) else {}
    if "poc_path" in record and str(record.get("poc_path") or "") != str(candidate_poc.get("path") or ""):
        raise DispositionUpdateError(f"{label}: poc_path does not match candidate.json")

    if candidate_checked.get("protocol_mode") == "r2":
        if record.get("candidate_protocol_mode") != "r2":
            raise DispositionUpdateError(f"{label}: R2 candidate is missing candidate_protocol_mode=r2")
        if record.get("candidate_sha256") != file_sha256(candidate_path):
            raise DispositionUpdateError(f"{label}: candidate_sha256 does not match candidate.json")
        if record.get("candidate_fingerprint") != candidate_checked.get("fingerprint"):
            raise DispositionUpdateError(f"{label}: candidate_fingerprint does not match candidate.json")
    elif any(key in record for key in ("candidate_protocol_mode", "candidate_sha256", "candidate_fingerprint")):
        raise DispositionUpdateError(f"{label}: legacy R1 candidate must not claim Candidate R2 identity binding")

    verdict_path: Path | None = None
    verdict_doc: dict[str, Any] | None = None
    verdict_checked: dict[str, Any] | None = None
    verdict_value = str(record.get("verdict_path") or "").strip()
    if status != "candidate":
        if not verdict_value:
            raise DispositionUpdateError(f"{label}: non-candidate disposition requires verdict_path")
        verdict_path, path_error = safe_workspace_path(workspace, verdict_value, label="verdict_path")
        if path_error:
            raise DispositionUpdateError(f"{label}: {path_error}")
        if verdict_path is None or not verdict_path.is_file():
            raise DispositionUpdateError(f"{label}: verdict_path must reference an existing regular file")
        try:
            verdict_doc = load_verdict(verdict_path)
            verdict_checked = validate_verdict(verdict_doc)
            cross_check_candidate(candidate_path, verdict_doc)
        except (CandidateValidationError, VerdictValidationError) as exc:
            raise DispositionUpdateError(f"{label}: production verifier verdict validator rejected verdict_path") from exc
        verdict_id = str(verdict_doc.get("candidate_id") or "")
        if verdict_id != candidate_id or verdict_checked.get("candidate_id") != candidate_id:
            raise DispositionUpdateError(f"{label}: verdict candidate_id does not match candidate disposition")
        verdict_status = str(verdict_doc.get("verdict") or "")
        if status != verdict_status:
            raise DispositionUpdateError(f"{label}: ledger status does not match verifier verdict")
        if record.get("target_ref") != verdict_doc.get("target_ref"):
            raise DispositionUpdateError(f"{label}: target_ref does not match verifier verdict")
        expected_fields = {
            "verification_status": verdict_doc.get("verification_status"),
            "disposition_recommendation": verdict_doc.get("disposition_recommendation"),
            "verdict_candidate_id": verdict_id,
        }
        for field, expected in expected_fields.items():
            if field in record and record.get(field) != expected:
                raise DispositionUpdateError(f"{label}: {field} does not match verifier verdict")
        evidence_level = str(verdict_doc.get("evidence_level") or "").strip()
        if evidence_level and record.get("evidence_level") != evidence_level:
            raise DispositionUpdateError(f"{label}: evidence_level does not match verifier verdict")
        oracle = verdict_doc.get("oracle_result") if isinstance(verdict_doc.get("oracle_result"), dict) else {}
        oracle_summary = str(oracle.get("summary") or "")
        if oracle_summary and "oracle_summary" in record and str(record.get("oracle_summary") or "") != oracle_summary:
            raise DispositionUpdateError(f"{label}: oracle_summary does not match verifier verdict")
        if source != "verifier-verdict":
            raise DispositionUpdateError(f"{label}: terminal disposition source must be verifier-verdict")
    elif source != "candidate-contract":
        raise DispositionUpdateError(f"{label}: candidate status must use candidate-contract source")

    return {
        "candidate_path": candidate_path,
        "candidate": candidate_doc,
        "candidate_checked": candidate_checked,
        "verdict_path": verdict_path,
        "verdict": verdict_doc,
        "verdict_checked": verdict_checked,
        "candidate_id": candidate_id,
        "status": status,
        "source": source,
        "candidate_relative": candidate_path.relative_to(workspace.resolve()).as_posix(),
        "verdict_relative": verdict_path.relative_to(workspace.resolve()).as_posix() if verdict_path else "",
    }


def update_ledger_from_verdict(workspace: Path, candidate_path: Path, verdict_path: Path) -> dict[str, Any]:
    candidate_doc, verdict_doc = load_valid_candidate_and_verdict(candidate_path, verdict_path)
    existing_ledger = load_disposition_ledger(workspace)
    if existing_ledger:
        ledger = dict(existing_ledger)
        ledger.setdefault("schema_version", SCHEMA_VERSION)
        ledger.setdefault("workspace", workspace.name)
        ledger.setdefault("items", ledger_items(existing_ledger))
    else:
        ledger = synthesize_disposition_ledger(workspace, merge_existing=False)

    existing_records = candidate_disposition_records(ledger)
    candidate_id = str(candidate_doc.get("candidate_id") or "")
    updated_record = disposition_record_from_candidate(
        workspace,
        candidate_path,
        candidate_doc,
        status=str(verdict_doc["verdict"]),
        source="verifier-verdict",
        verdict_path=verdict_path,
        verdict_doc=verdict_doc,
    )
    next_records = [
        record for record in existing_records
        if str(record.get("candidate_id") or "") != candidate_id
    ]
    next_records.append(updated_record)
    next_records.sort(key=lambda record: str(record.get("candidate_id") or ""))
    ledger["schema_version"] = SCHEMA_VERSION
    ledger["generated_at"] = utc_now()
    ledger["workspace"] = workspace.name
    ledger["candidate_dispositions"] = next_records
    return ledger


def confirmed_bundle_gate_ready(record: dict[str, Any]) -> bool:
    return (
        str(record.get("status") or "") == "confirmed_in_docker"
        and str(record.get("source") or "") == "verifier-verdict"
        and bool(str(record.get("candidate_path") or ""))
        and bool(str(record.get("verdict_path") or ""))
    )


def bundle_result_map(bundle_summary: dict[str, Any]) -> dict[str, str]:
    results = bundle_summary.get("results")
    if not isinstance(results, list):
        return {}
    mapping: dict[str, str] = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or item.get("name") or "").strip()
        if not path:
            continue
        mapping[f"{CONFIRMED_DIR}/{path}".replace("//", "/")] = str(item.get("classification") or "")
    return mapping


def is_confirmed_path(path_value: str) -> bool:
    return path_value == CONFIRMED_DIR or path_value.startswith(f"{CONFIRMED_DIR}/")


def is_material_blocking_item(item: dict[str, Any]) -> bool:
    if str(item.get("docker_status") or "") not in MATERIAL_BLOCKING_DOCKER_STATUSES:
        return False
    if str(item.get("state") or "") in {"false_positive", "not_applicable", "out_of_scope"}:
        return False
    rationale = " ".join(str(item.get(key) or "") for key in ("title", "materiality_rationale", "reason_code")).lower()
    non_material_patterns = (
        r"material blocker\??\s*:?\s*no",
        r"\bnon[-_ ]?material\b",
        r"\bnot material\b",
        r"\bout[-_ ]of[-_ ]scope\b",
        r"\bnot[_ -]applicable\b",
        r"\bfalse[_ -]positive\b",
        r"\bsafe config\b",
    )
    return not any(re.search(pattern, rationale) for pattern in non_material_patterns)


def validate_disposition_ledger(
    workspace: Path,
    *,
    result: str = "",
    ledger: dict[str, Any] | None = None,
    bundle_summary: dict[str, Any] | None = None,
    language: str = "auto",
) -> dict[str, Any]:
    workspace = workspace.resolve()
    ledger_path = workspace / LEDGER_FILENAME
    if ledger is None:
        if not ledger_path.exists():
            return {"ok": False, "errors": [f"{LEDGER_FILENAME} is missing."], "summary": {"item_count": 0}}
        ledger = load_disposition_ledger(workspace)

    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(ledger, dict):
        errors.append(f"{LEDGER_FILENAME} must be a JSON object.")
        items: list[dict[str, Any]] = []
        candidate_records: list[dict[str, Any]] = []
    else:
        if ledger.get("schema_version") != SCHEMA_VERSION:
            errors.append(f"{LEDGER_FILENAME} schema_version must be {SCHEMA_VERSION}.")
        raw_items = ledger.get("items")
        if not isinstance(raw_items, list):
            errors.append(f"{LEDGER_FILENAME} items must be a list.")
            items = []
        else:
            items = [item for item in raw_items if isinstance(item, dict)]
            if len(items) != len(raw_items):
                errors.append(f"{LEDGER_FILENAME} items must contain only objects.")
        raw_candidate_records = ledger.get("candidate_dispositions", [])
        if raw_candidate_records is None:
            raw_candidate_records = []
        if not isinstance(raw_candidate_records, list):
            errors.append(f"{LEDGER_FILENAME} candidate_dispositions must be a list when present.")
            candidate_records = []
        else:
            candidate_records = [record for record in raw_candidate_records if isinstance(record, dict)]
            if len(candidate_records) != len(raw_candidate_records):
                errors.append(f"{LEDGER_FILENAME} candidate_dispositions must contain only objects.")

    if bundle_summary is None:
        bundle_summary = run_bundle_validator(workspace, language)
    if "error" in bundle_summary:
        errors.append(f"Bundle validation error while checking {LEDGER_FILENAME}: {bundle_summary['error']}")
    bundle_classifications = bundle_result_map(bundle_summary)

    seen_ids: set[str] = set()
    seen_candidate_ids: set[str] = set()
    validated_candidate_records: dict[str, dict[str, Any]] = {}
    confirmed_path_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {state: 0 for state in STATES}
    candidate_status_counts: dict[str, int] = {status: 0 for status in sorted(VERDICT_DISPOSITION_STATUSES | {"candidate"})}

    required_fields = {
        "id",
        "title",
        "state",
        "source_type",
        "docker_applicable",
        "docker_status",
        "reason_code",
        "confirmed_bundle_path",
        "materiality_rationale",
    }
    for index, item in enumerate(items, start=1):
        item_id = str(item.get("id") or "").strip()
        label = item_id or f"item[{index}]"
        missing = sorted(field for field in required_fields if field not in item)
        if missing:
            errors.append(f"{label}: missing required field(s): {', '.join(missing)}")
        if not item_id:
            errors.append(f"item[{index}]: id is required.")
        elif item_id in seen_ids:
            errors.append(f"duplicate disposition id: {item_id}")
        seen_ids.add(item_id)

        state = str(item.get("state") or "").strip()
        source_type = str(item.get("source_type") or "").strip()
        docker_status = str(item.get("docker_status") or "").strip()
        reason_code = str(item.get("reason_code") or "").strip()
        confirmed_bundle_path = str(item.get("confirmed_bundle_path") or "").strip()

        if state not in STATES:
            errors.append(f"{label}: invalid state={state!r}.")
        else:
            state_counts[state] += 1
        if source_type not in SOURCE_TYPES:
            errors.append(f"{label}: invalid source_type={source_type!r}.")
        if docker_status not in DOCKER_STATUSES:
            errors.append(f"{label}: invalid docker_status={docker_status!r}.")
        if reason_code not in REASON_CODES:
            errors.append(f"{label}: invalid reason_code={reason_code!r}.")
        if not isinstance(item.get("docker_applicable"), bool):
            errors.append(f"{label}: docker_applicable must be a boolean.")

        path, path_error = safe_workspace_path(workspace, confirmed_bundle_path)
        if path_error:
            errors.append(f"{label}: {path_error}")
        normalized_bundle_path = ""
        if path is not None:
            normalized_bundle_path = rel_confirmed_path(path, workspace)

        if state == "confirmed":
            if not confirmed_bundle_path:
                errors.append(f"{label}: state=confirmed requires confirmed_bundle_path.")
            elif path is not None:
                if not normalized_bundle_path.startswith(f"{CONFIRMED_DIR}/"):
                    errors.append(f"{label}: confirmed_bundle_path must point under confirmed/.")
                elif not path.exists() or not path.is_dir():
                    errors.append(f"{label}: confirmed_bundle_path does not exist as a directory: {confirmed_bundle_path}")
                elif bundle_classifications.get(normalized_bundle_path) != "bundle_validated":
                    classification = bundle_classifications.get(normalized_bundle_path) or "not_validated"
                    errors.append(f"{label}: state=confirmed requires a valid confirmed bundle ({normalized_bundle_path} is {classification}).")
                confirmed_path_counts[normalized_bundle_path] = confirmed_path_counts.get(normalized_bundle_path, 0) + 1
            if source_type in SOURCE_ONLY_TYPES:
                errors.append(f"{label}: source_type={source_type} cannot be confirmed without Docker/runtime evidence.")
            if reason_code in SOURCE_ONLY_REASON_CODES:
                errors.append(f"{label}: reason_code={reason_code} cannot be confirmed.")
            if item.get("docker_applicable") is not True:
                errors.append(f"{label}: state=confirmed requires docker_applicable=true.")
            if item.get("docker_applicable") is True and docker_status != "reproduced":
                errors.append(f"{label}: state=confirmed requires docker_status=reproduced when docker_applicable=true.")
        else:
            if normalized_bundle_path and is_confirmed_path(normalized_bundle_path):
                errors.append(f"{label}: non-confirmed items must not point into confirmed/.")

        if result == "completed_no_confirmed_findings" and state == "confirmed":
            errors.append(f"{label}: completed_no_confirmed_findings cannot include confirmed ledger items.")
        if result == "completed_no_confirmed_findings" and is_material_blocking_item(item):
            errors.append(
                f"{label}: docker_status={docker_status} on a material item blocks completed_no_confirmed_findings."
            )

    candidate_required_fields = {
        "candidate_id",
        "status",
        "title",
        "bug_class",
        "source",
        "candidate_path",
        "target_ref",
        "claim",
        "updated_at",
    }
    for index, record in enumerate(candidate_records, start=1):
        candidate_id = str(record.get("candidate_id") or "").strip()
        label = candidate_id or f"candidate_dispositions[{index}]"
        missing = sorted(field for field in candidate_required_fields if field not in record)
        if missing:
            errors.append(f"{label}: missing candidate disposition field(s): {', '.join(missing)}")
        if not candidate_id:
            errors.append(f"candidate_dispositions[{index}]: candidate_id is required.")
        elif candidate_id in seen_candidate_ids:
            errors.append(f"duplicate candidate disposition candidate_id: {candidate_id}")
        seen_candidate_ids.add(candidate_id)

        status = str(record.get("status") or "").strip()
        source = str(record.get("source") or "").strip()
        candidate_path = str(record.get("candidate_path") or "").strip()
        verdict_path = str(record.get("verdict_path") or "").strip()
        if status not in VERDICT_DISPOSITION_STATUSES | {"candidate"}:
            errors.append(f"{label}: invalid candidate disposition status={status!r}.")
        else:
            candidate_status_counts[status] += 1
        if source not in {"candidate-contract", "verifier-verdict"}:
            errors.append(f"{label}: invalid candidate disposition source={source!r}.")
        if source == "candidate-contract" and status != "candidate":
            errors.append(f"{label}: candidate-contract source cannot promote beyond candidate.")
        if status == "confirmed_in_docker" and not confirmed_bundle_gate_ready(record):
            errors.append(
                f"{label}: confirmed_in_docker requires candidate.json and verifier-verdict.json references from verifier-verdict source."
            )
        try:
            validated_record = validate_candidate_disposition_record(workspace, record)
            if candidate_id:
                validated_candidate_records[candidate_id] = validated_record
        except DispositionUpdateError as exc:
            errors.append(str(exc))

    for bundle_dir in confirmed_bundle_dirs(workspace):
        rel_path = rel_confirmed_path(bundle_dir, workspace)
        count = confirmed_path_counts.get(rel_path, 0)
        if count != 1:
            errors.append(f"{rel_path}: every folder under confirmed/ must have exactly one matching ledger item; found {count}.")

    unresolved = [
        item for item in items
        if str(item.get("state") or "") in {"candidate", "unverified", "blocked"}
        or str(item.get("docker_status") or "") in MATERIAL_BLOCKING_DOCKER_STATUSES
    ]
    unresolved.extend(
        record for record in candidate_records
        if str(record.get("status") or "") in {"candidate", "unverified", "blocked"}
    )
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "summary": {
            "item_count": len(items),
            "state_counts": {key: value for key, value in sorted(state_counts.items()) if value},
            "candidate_status_counts": {key: value for key, value in sorted(candidate_status_counts.items()) if value},
            "unresolved_count": len(unresolved),
            "confirmed_bundle_count": len(confirmed_bundle_dirs(workspace)),
        },
    }


def _validated_bundle_entries(
    workspace: Path,
    bundle_summary: dict[str, Any],
) -> tuple[list[tuple[str, Path]], list[str]]:
    entries: list[tuple[str, Path]] = []
    errors: list[str] = []
    results = bundle_summary.get("results") if isinstance(bundle_summary, dict) else []
    if not isinstance(results, list):
        return entries, ["bundle validator returned no structured results"]
    seen: set[str] = set()
    for item in results:
        if not isinstance(item, dict) or str(item.get("classification") or "") != "bundle_validated":
            continue
        raw = str(item.get("path") or item.get("name") or "").strip().replace("\\", "/")
        if raw.startswith("confirmed/"):
            relative = raw
        else:
            relative = f"{CONFIRMED_DIR}/{raw}"
        path, path_error = safe_workspace_path(workspace, relative, label="confirmed bundle path")
        if path_error or path is None or not path.is_dir():
            errors.append(f"validated bundle {relative or '<missing>'} is not a safe real directory")
            continue
        canonical = path.relative_to(workspace.resolve()).as_posix()
        if canonical in seen:
            errors.append(f"duplicate validated bundle path: {canonical}")
            continue
        seen.add(canonical)
        entries.append((canonical, path))
    return entries, errors


def _discover_candidate_documents(workspace: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    candidates_dir = workspace / "candidates"
    documents: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    if not candidates_dir.exists():
        return documents, errors
    if candidates_dir.is_symlink() or not candidates_dir.is_dir():
        return documents, ["candidates is not a safe real directory"]
    for path in sorted(candidates_dir.rglob("candidate.json")):
        relative = path.relative_to(workspace).as_posix()
        safe_path, path_error = safe_workspace_path(workspace, relative, label="candidate path")
        if path_error or safe_path is None or not safe_path.is_file():
            errors.append(f"{relative}: candidate path is not a safe regular file")
            continue
        try:
            document = load_candidate(safe_path)
            checked = validate_candidate(document)
        except CandidateValidationError:
            errors.append(f"{relative}: production candidate validator rejected candidate")
            continue
        candidate_id = str(checked.get("candidate_id") or document.get("candidate_id") or "")
        if candidate_id in documents:
            errors.append(f"duplicate candidate_id in candidate files: {candidate_id}")
            continue
        documents[candidate_id] = {
            "path": safe_path,
            "relative": relative,
            "document": document,
            "checked": checked,
        }
    return documents, errors


def _run_structured_validator(
    workspace: Path,
    validator_name: str,
    flag: str,
    relative: str,
) -> tuple[dict[str, Any] | None, str | None]:
    validator = workspace / "bin" / validator_name
    if not validator.exists():
        validator = Path(__file__).resolve().parent / validator_name
    path, path_error = safe_workspace_path(workspace, relative, label=relative)
    if path_error or path is None or not path.is_file():
        return None, f"{relative} is missing or unsafe"
    if not validator.is_file():
        return None, f"{validator_name} is missing"
    proc = subprocess.run(
        [
            sys.executable,
            str(validator),
            "--repo-root", str(workspace.parent),
            "--workspace-dir", str(workspace),
            flag, str(path),
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    try:
        payload = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return None, f"{relative} validator did not produce structured JSON"
    if proc.returncode != 0 or payload.get("ok") is not True:
        issue_codes = payload.get("issue_codes")
        if isinstance(issue_codes, list):
            stable_codes = sorted({str(code).strip() for code in issue_codes if str(code).strip()})
            if stable_codes:
                return payload, f"{relative} failed its production structured-result validator [{', '.join(stable_codes)}]"
        return payload, f"{relative} failed its production structured-result validator"
    return payload, None


def _zero_candidate_recon_triage_gate(workspace: Path) -> tuple[bool, list[str]]:
    errors: list[str] = []
    recon_payload, recon_error = _run_structured_validator(
        workspace,
        "validate_recon_result.py",
        "--recon-result",
        "recon-result.json",
    )
    if recon_error:
        errors.append(recon_error)
    else:
        recon_doc = read_json(workspace / "recon-result.json")
        if recon_payload is None or recon_payload.get("status") != "complete":
            errors.append("recon-result.json must be a production-valid complete coverage result")
        if recon_doc.get("coverage_gaps") or recon_doc.get("unresolved_blockers"):
            errors.append("recon-result.json must prove complete coverage with no gaps or blockers")
        focus_refs = recon_doc.get("focus_refs")
        if not isinstance(focus_refs, list) or not focus_refs:
            errors.append("recon-result.json must expose non-empty structured coverage focus references")

    # A complete Recon result is the authoritative zero-candidate proof.  A
    # Triage batch is optional because the production Triage contract is an
    # explicit batch of existing candidates and deliberately rejects an empty
    # inventory.  If one is present, it must still validate and may not be
    # used to smuggle an unrepresented candidate into the zero-candidate
    # branch.
    triage_path = workspace / "triage-batch.json"
    if triage_path.exists():
        triage_payload, triage_error = _run_structured_validator(
            workspace,
            "validate_triage_batch.py",
            "--triage-batch",
            "triage-batch.json",
        )
        if triage_error:
            errors.append(triage_error)
        else:
            triage_doc = read_json(triage_path)
            inventory = triage_doc.get("candidate_inventory")
            if triage_payload is None or triage_payload.get("status") != "complete":
                errors.append("triage-batch.json must be a production-valid complete structured result")
            if not isinstance(inventory, list) or inventory:
                errors.append("triage-batch.json cannot introduce candidates into the zero-candidate branch")
    return not errors, errors


def validate_workspace_confirmation_chain(
    workspace: Path,
    *,
    result: str,
    protocol_mode: str = "r2",
    ledger: dict[str, Any] | None = None,
    bundle_summary: dict[str, Any] | None = None,
    disposition_validation: dict[str, Any] | None = None,
    language: str = "auto",
) -> dict[str, Any]:
    """Validate the complete candidate -> verdict -> disposition -> bundle chain.

    This read-only helper is the completion authority consumed by the finalizer,
    handoff derivation, and the finalization assertion.  A standalone bundle
    validator remains necessary but is never sufficient for completion.
    """
    workspace = workspace.resolve()
    errors: list[str] = []
    if ledger is None:
        ledger = load_disposition_ledger(workspace)
    if not isinstance(ledger, dict):
        ledger = {}
    if bundle_summary is None:
        bundle_summary = run_bundle_validator(workspace, language)
    if disposition_validation is None:
        disposition_validation = validate_disposition_ledger(
            workspace,
            result=result,
            ledger=ledger,
            bundle_summary=bundle_summary,
            language=language,
        )
    if not disposition_validation.get("ok"):
        errors.extend(str(item) for item in disposition_validation.get("errors", []))

    records = candidate_disposition_records(ledger)
    validated_records: dict[str, dict[str, Any]] = {}
    for record in records:
        candidate_id = str(record.get("candidate_id") or "").strip()
        try:
            validated_records[candidate_id] = validate_candidate_disposition_record(workspace, record)
        except DispositionUpdateError as exc:
            errors.append(str(exc))

    bundle_entries, bundle_errors = _validated_bundle_entries(workspace, bundle_summary)
    errors.extend(bundle_errors)
    validated_bundle_paths = {relative for relative, _path in bundle_entries}
    items = ledger_items(ledger)
    confirmed_items: dict[str, int] = {}
    for item in items:
        if str(item.get("state") or "") != "confirmed":
            continue
        raw = str(item.get("confirmed_bundle_path") or "").strip()
        path, path_error = safe_workspace_path(workspace, raw, label="confirmed_bundle_path")
        if path_error or path is None:
            continue
        relative = path.relative_to(workspace.resolve()).as_posix()
        confirmed_items[relative] = confirmed_items.get(relative, 0) + 1

    confirmed_records = {
        candidate_id: value
        for candidate_id, value in validated_records.items()
        if value.get("status") == "confirmed_in_docker"
    }
    record_by_verdict: dict[str, tuple[str, dict[str, Any]]] = {}
    for candidate_id, value in confirmed_records.items():
        verdict_relative = str(value.get("verdict_relative") or "")
        if not verdict_relative:
            continue
        if verdict_relative in record_by_verdict:
            errors.append(f"duplicate confirmed disposition verdict path: {verdict_relative}")
        else:
            record_by_verdict[verdict_relative] = (candidate_id, value)

    bundle_verdicts: dict[str, str] = {}
    for bundle_relative, bundle_path in bundle_entries:
        review_path = bundle_path / "validity-review.json"
        review_relative = review_path.relative_to(workspace).as_posix()
        safe_review, review_error = safe_workspace_path(workspace, review_relative, label="validity-review path")
        if review_error or safe_review is None or not safe_review.is_file():
            errors.append(f"{bundle_relative}: validated bundle must contain a safe validity-review.json")
            continue
        review = read_json(safe_review)
        binding = review.get("source_binding") if isinstance(review, dict) else None
        materials = binding.get("materials") if isinstance(binding, dict) else None
        verdict_relative = str(materials.get("verifier_verdict") or "").strip() if isinstance(materials, dict) else ""
        if not verdict_relative:
            errors.append(f"{bundle_relative}: validity-review.json.source_binding.materials.verifier_verdict is required")
            continue
        verdict_path, verdict_error = safe_workspace_path(workspace, verdict_relative, label="verifier_verdict path")
        if verdict_error or verdict_path is None or not verdict_path.is_file():
            errors.append(f"{bundle_relative}: verifier verdict path is not a safe existing workspace file")
            continue
        canonical_verdict = verdict_path.relative_to(workspace.resolve()).as_posix()
        if canonical_verdict != verdict_relative:
            errors.append(f"{bundle_relative}: verifier verdict path is not canonical")
        if canonical_verdict in bundle_verdicts.values():
            errors.append(f"duplicate validated bundle verifier verdict path: {canonical_verdict}")
        bundle_verdicts[bundle_relative] = canonical_verdict
        match = record_by_verdict.get(canonical_verdict)
        if match is None:
            errors.append(f"{bundle_relative}: verifier verdict is not referenced by exactly one confirmed disposition")
            continue
        candidate_id, value = match
        verdict_doc = value.get("verdict") if isinstance(value.get("verdict"), dict) else {}
        candidate_doc = value.get("candidate") if isinstance(value.get("candidate"), dict) else {}
        if str(verdict_doc.get("candidate_id") or "") != candidate_id:
            errors.append(f"{bundle_relative}: verifier verdict candidate_id does not match disposition candidate_id")
        if str(verdict_doc.get("verdict") or "") != "confirmed_in_docker":
            errors.append(f"{bundle_relative}: bundle verifier verdict is not confirmed_in_docker")
        if str(candidate_doc.get("candidate_id") or "") != candidate_id:
            errors.append(f"{bundle_relative}: candidate.json candidate_id does not match disposition candidate_id")
        bundle_target_ref = {
            "target_config": str(materials.get("target_config") or "").strip(),
            "tested_ref": str(binding.get("tested_ref") or "").strip(),
        }
        if candidate_doc.get("target_ref") != bundle_target_ref:
            errors.append(f"{bundle_relative}: candidate target_ref does not match the bundle source binding")
        if verdict_doc.get("target_ref") != bundle_target_ref:
            errors.append(f"{bundle_relative}: verifier verdict target_ref does not match the bundle source binding")

    if result == "completed_with_confirmed_bundles":
        if not bundle_entries:
            errors.append("completed_with_confirmed_bundles requires at least one standalone-validated bundle")
        for bundle_relative in sorted(validated_bundle_paths):
            if confirmed_items.get(bundle_relative) != 1:
                errors.append(f"{bundle_relative}: validated bundle must map to exactly one confirmed legacy disposition item")
        for bundle_relative, count in sorted(confirmed_items.items()):
            if bundle_relative not in validated_bundle_paths or count != 1:
                errors.append(f"{bundle_relative}: confirmed legacy disposition item is orphaned or duplicated")
        for verdict_relative, (_candidate_id, _value) in sorted(record_by_verdict.items()):
            if verdict_relative not in bundle_verdicts.values():
                errors.append(f"{verdict_relative}: confirmed candidate disposition is orphaned from validated bundles")
        if len(bundle_entries) != len(confirmed_items) or len(bundle_entries) != len(record_by_verdict):
            errors.append("validated bundles, confirmed legacy disposition items, and confirmed candidate dispositions must be one-to-one")
    elif result == "completed_no_confirmed_findings":
        if bundle_entries:
            errors.append("completed_no_confirmed_findings cannot contain validated confirmed bundles")
        if confirmed_items:
            errors.append("completed_no_confirmed_findings cannot contain confirmed legacy disposition items")
        if confirmed_records:
            errors.append("completed_no_confirmed_findings cannot contain confirmed candidate dispositions")
        candidate_documents, candidate_errors = _discover_candidate_documents(workspace)
        errors.extend(candidate_errors)
        if candidate_documents:
            for candidate_id in sorted(candidate_documents):
                matches = [record for record in records if str(record.get("candidate_id") or "") == candidate_id]
                if len(matches) != 1:
                    errors.append(f"{candidate_id}: every candidate must have exactly one terminal verifier disposition")
                    continue
                status = str(matches[0].get("status") or "")
                if status != "false_positive":
                    errors.append(f"{candidate_id}: completed_no_confirmed_findings permits only false_positive terminal dispositions; found {status or 'missing'}")
            for record in records:
                if str(record.get("candidate_id") or "") not in candidate_documents:
                    errors.append(f"{record.get('candidate_id') or '<missing>'}: candidate disposition is orphaned from candidate files")
        else:
            for record in records:
                errors.append(f"{record.get('candidate_id') or '<missing>'}: candidate disposition is orphaned because no candidate file exists")
            if protocol_mode != "legacy_r1":
                zero_ok, zero_errors = _zero_candidate_recon_triage_gate(workspace)
                if not zero_ok:
                    errors.extend(zero_errors)
        unresolved = int((disposition_validation.get("summary") or {}).get("unresolved_count") or 0)
        if unresolved:
            errors.append(f"completed_no_confirmed_findings has {unresolved} unresolved disposition item(s)")

    return {
        "ok": not errors,
        "errors": errors,
        "summary": {
            "validated_bundle_count": len(bundle_entries),
            "confirmed_legacy_item_count": len(confirmed_items),
            "confirmed_candidate_disposition_count": len(confirmed_records),
            "candidate_file_count": len(_discover_candidate_documents(workspace)[0]) if result == "completed_no_confirmed_findings" else None,
            "bundle_verdict_paths": sorted(bundle_verdicts.values()),
        },
    }


def resume_hint(item: dict[str, Any]) -> str:
    rationale = str(item.get("materiality_rationale") or "")
    match = re.search(r"Resume step:\s*(.+)$", rationale, re.I)
    if match:
        return shorten(match.group(1), 180)
    docker_status = str(item.get("docker_status") or "")
    if docker_status == "blocked":
        return "Resolve the Docker/runtime blocker, rerun Docker verification, then refresh the ledger."
    if docker_status == "timed_out":
        return "Re-check runtime readiness, rerun the Docker PoC with a bounded timeout, then refresh the ledger."
    if docker_status == "dirty_state":
        return "Restore Docker strict-clean state before finalization."
    return "Continue Docker-only triage or record a false-positive/out-of-scope disposition."


def unresolved_disposition_items(workspace: Path, limit: int = 5) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    ledger_path = workspace / LEDGER_FILENAME
    if ledger_path.exists():
        ledger = load_disposition_ledger(workspace)
    else:
        ledger = synthesize_disposition_ledger(workspace, merge_existing=False)
    items = [
        item for item in ledger_items(ledger)
        if str(item.get("state") or "") in {"candidate", "unverified", "blocked"}
        or str(item.get("docker_status") or "") in MATERIAL_BLOCKING_DOCKER_STATUSES
    ]
    items.extend(
        record for record in candidate_disposition_records(ledger)
        if str(record.get("status") or "") in {"candidate", "unverified", "blocked"}
    )
    items.sort(key=lambda item: (str(item.get("state") or ""), str(item.get("id") or "")))
    return ledger, items[:limit]


def render_unresolved_disposition_lines(workspace: Path, limit: int = 5) -> list[str]:
    ledger_path = workspace / LEDGER_FILENAME
    ledger, items = unresolved_disposition_items(workspace, limit=limit)
    all_unresolved = [
        item for item in ledger_items(ledger)
        if str(item.get("state") or "") in {"candidate", "unverified", "blocked"}
        or str(item.get("docker_status") or "") in MATERIAL_BLOCKING_DOCKER_STATUSES
    ]
    all_unresolved.extend(
        record for record in candidate_disposition_records(ledger)
        if str(record.get("status") or "") in {"candidate", "unverified", "blocked"}
    )
    lines = [
        f"- Ledger: `{LEDGER_FILENAME}`" if ledger_path.exists() else f"- Ledger: `{LEDGER_FILENAME}` not written yet; synthesized preview below.",
        f"- Unresolved disposition items: `{len(all_unresolved)}`",
    ]
    if not all_unresolved:
        return lines
    for item in items:
        lines.append(
            "- "
            f"`{item.get('id')}` "
            f"state=`{item.get('state')}` docker=`{item.get('docker_status')}` "
            f"reason=`{item.get('reason_code')}` title={shorten(str(item.get('title') or ''), 120)}"
        )
        lines.append(f"  Resume: {resume_hint(item)}")
    if len(all_unresolved) > limit:
        lines.append(f"- ... {len(all_unresolved) - limit} more unresolved disposition item(s) omitted.")
    return lines


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate or synthesize a Zhulong audit-disposition.json ledger.")
    parser.add_argument("--workspace-dir", default="")
    parser.add_argument("--workspace", default="", help="Alias for --workspace-dir when updating from a verifier verdict.")
    parser.add_argument("--result", choices=["", "completed_with_confirmed_bundles", "completed_no_confirmed_findings"], default="")
    parser.add_argument("--language", choices=["zh-CN", "en-US", "auto"], default="auto")
    parser.add_argument("--write", action="store_true", help="Synthesize/refresh audit-disposition.json before validating it.")
    parser.add_argument("--candidate", default="", help="candidate.json path for --update-from-verdict.")
    parser.add_argument("--verdict", default="", help="verifier-verdict.json path for --update-from-verdict.")
    parser.add_argument(
        "--update-from-verdict",
        action="store_true",
        help="Explicitly update candidate disposition from a valid verifier-verdict.json.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable validation output.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    workspace_arg = args.workspace_dir or args.workspace
    if not workspace_arg:
        message = "--workspace-dir is required"
        if args.json:
            print(json.dumps({"ok": False, "errors": [message]}, ensure_ascii=False, indent=2))
        else:
            print(f"AUDIT DISPOSITION FAILED: {message}")
        return 1
    workspace = Path(workspace_arg).expanduser().resolve()
    if not workspace.is_dir():
        message = f"workspace directory does not exist: {workspace}"
        if args.json:
            print(json.dumps({"ok": False, "errors": [message]}, ensure_ascii=False, indent=2))
        else:
            print(f"AUDIT DISPOSITION FAILED: {message}")
        return 1

    if args.update_from_verdict:
        if not args.candidate or not args.verdict:
            message = "--candidate and --verdict are required with --update-from-verdict"
            if args.json:
                print(json.dumps({"ok": False, "errors": [message]}, ensure_ascii=False, indent=2))
            else:
                print(f"AUDIT DISPOSITION FAILED: {message}")
            return 1
        try:
            candidate_path = resolve_under_workspace(workspace, args.candidate, "candidate path")
            verdict_path = resolve_under_workspace(workspace, args.verdict, "verdict path")
            ledger = update_ledger_from_verdict(workspace, candidate_path, verdict_path)
            write_disposition_ledger(workspace, ledger)
        except DispositionUpdateError as exc:
            if args.json:
                print(json.dumps({"ok": False, "errors": [str(exc)]}, ensure_ascii=False, indent=2))
            else:
                print(f"AUDIT DISPOSITION FAILED: {exc}")
            return 1
    else:
        ledger = synthesize_disposition_ledger(workspace) if args.write else None
        if ledger is not None:
            write_disposition_ledger(workspace, ledger)

    validation = validate_disposition_ledger(workspace, result=args.result, ledger=ledger, language=args.language)
    if args.json:
        print(json.dumps(validation, ensure_ascii=False, indent=2, sort_keys=True))
    elif validation.get("ok"):
        summary = validation.get("summary") or {}
        print(f"AUDIT DISPOSITION OK: items={summary.get('item_count', 0)} unresolved={summary.get('unresolved_count', 0)}")
    else:
        print("AUDIT DISPOSITION FAILED:")
        for error in validation.get("errors", []):
            print(f"- {error}")
    return 0 if validation.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
