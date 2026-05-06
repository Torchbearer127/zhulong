#!/usr/bin/env python3
from __future__ import annotations

import json
import re
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


def detect_blocked_verification(workspace: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    recovery_steps: list[str] = []
    labels: set[str] = set()
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
        "resume_step": recovery_steps[0] if recovery_steps else "",
        "recovery_steps": recovery_steps,
    }
