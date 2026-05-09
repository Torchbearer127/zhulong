#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from blocked_verification import detect_blocked_verification


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
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "workspace": workspace.name,
        "items": items,
    }


def safe_workspace_path(workspace: Path, value: str) -> tuple[Path | None, str | None]:
    if not value:
        return None, None
    raw = Path(value)
    if raw.is_absolute():
        return None, f"confirmed_bundle_path must be workspace-relative, got absolute path: {value}"
    resolved = (workspace / raw).resolve()
    try:
        resolved.relative_to(workspace.resolve())
    except ValueError:
        return None, f"confirmed_bundle_path escapes workspace: {value}"
    return resolved, None


def rel_confirmed_path(path: Path, workspace: Path) -> str:
    return path.resolve().relative_to(workspace.resolve()).as_posix()


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

    if bundle_summary is None:
        bundle_summary = run_bundle_validator(workspace, language)
    if "error" in bundle_summary:
        errors.append(f"Bundle validation error while checking {LEDGER_FILENAME}: {bundle_summary['error']}")
    bundle_classifications = bundle_result_map(bundle_summary)

    seen_ids: set[str] = set()
    confirmed_path_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {state: 0 for state in STATES}

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
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "summary": {
            "item_count": len(items),
            "state_counts": {key: value for key, value in sorted(state_counts.items()) if value},
            "unresolved_count": len(unresolved),
            "confirmed_bundle_count": len(confirmed_bundle_dirs(workspace)),
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
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--result", choices=["", "completed_with_confirmed_bundles", "completed_no_confirmed_findings"], default="")
    parser.add_argument("--language", choices=["zh-CN", "en-US", "auto"], default="auto")
    parser.add_argument("--write", action="store_true", help="Synthesize/refresh audit-disposition.json before validating it.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable validation output.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    workspace = Path(args.workspace_dir).expanduser().resolve()
    if not workspace.is_dir():
        message = f"workspace directory does not exist: {workspace}"
        if args.json:
            print(json.dumps({"ok": False, "errors": [message]}, ensure_ascii=False, indent=2))
        else:
            print(f"AUDIT DISPOSITION FAILED: {message}")
        return 1
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
