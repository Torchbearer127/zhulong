#!/usr/bin/env python3
"""Public recording identity and path-safety primitives.

This module is intentionally small and dependency-free.  The bundle repository is
the source of truth for recording identity; the user-level skill copies this file
only as a compatibility installation.  A recording may not invent a target name,
version, finding, marker, or code path outside the source-bound bundle metadata.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping


IDENTITY_FIELDS = (
    "software_name",
    "tested_ref",
    "tested_ref_kind",
    "finding_slug",
    "direct_impact_marker",
    "oracle_marker",
    "code_context_identity",
    "trigger_context_identity",
)

RECORDING_IDENTITY_MISSING = "RECORDING_IDENTITY_MISSING"
RECORDING_IDENTITY_MISMATCH = "RECORDING_IDENTITY_MISMATCH"
RECORDING_TESTED_REF_MISMATCH = "RECORDING_TESTED_REF_MISMATCH"


class RecordingIdentityError(ValueError):
    """An error with a stable machine-readable recording gate code."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _nonempty(value: Any) -> str:
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return str(value).strip()
    return ""


def _first(*values: Any) -> str:
    for value in values:
        text = _nonempty(value)
        if text:
            return text
    return ""


def _walk_mappings(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, Mapping):
        current = dict(value)
        yield current
        for child in current.values():
            yield from _walk_mappings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_mappings(child)


def _source_binding_candidates(documents: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for document in documents:
        for item in _walk_mappings(document):
            value = item.get("source_binding")
            if isinstance(value, Mapping):
                candidates.append(dict(value))
            if item.get("source_bound_ref") or item.get("tested_ref") or item.get("tested_version"):
                candidates.append(item)
    return candidates


def _stable_ref(value: str) -> tuple[str, str]:
    text = value.strip()
    lowered = text.lower()
    suffix = lowered.split(":", 1)[1] if ":" in lowered else lowered
    if not text or lowered in {"latest", "current", "current version", "main", "master", "head", "tip"} or suffix in {"latest", "current", "current version", "main", "master", "head", "tip"}:
        return "", ""
    if re.fullmatch(r"[0-9a-f]{7,64}", text, re.IGNORECASE):
        return text, "commit"
    if lowered.startswith(("commit:", "sha:", "sha256:")):
        return text, "commit"
    if lowered.startswith(("branch:", "ref:", "tag:")):
        prefix = lowered.split(":", 1)[0]
        return text, {"branch": "branch", "ref": "ref", "tag": "tag"}[prefix]
    if re.fullmatch(r"v?\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?", text):
        return text, "version"
    if "/" in text or "-" in text or "_" in text:
        return text, "source_ref"
    return text, "source_ref"


def _pick_tested_ref(documents: list[Mapping[str, Any]]) -> tuple[str, str]:
    bindings = _source_binding_candidates(documents)
    fields = (
        "tested_ref",
        "source_bound_ref",
        "tested_version",
        "version_affected",
        "tested_branch",
        "branch",
        "tested_commit",
        "commit",
        "source_revision",
        "revision",
    )
    rejected: list[str] = []
    for binding in bindings:
        for field in fields:
            value = _nonempty(binding.get(field))
            if not value:
                continue
            ref, kind = _stable_ref(value)
            if ref:
                return ref, kind
            rejected.append(value)
    if rejected:
        raise RecordingIdentityError(
            RECORDING_IDENTITY_MISSING,
            "tested source reference is floating or unstable: " + ", ".join(sorted(set(rejected))),
        )
    return "", ""


def _project_name(documents: list[Mapping[str, Any]]) -> str:
    for document in documents:
        for item in _walk_mappings(document):
            value = _first(
                item.get("project_name"),
                item.get("software_name"),
                item.get("package_name"),
                item.get("project"),
            )
            if value:
                return value
    return ""


def _finding_slug(documents: list[Mapping[str, Any]]) -> str:
    values: list[str] = []
    for document in documents:
        for item in _walk_mappings(document):
            value = _first(item.get("finding_slug"), item.get("slug"))
            if value:
                values.append(value)
    if not values:
        return ""
    unique = sorted(set(values))
    if len(unique) > 1:
        raise RecordingIdentityError(
            RECORDING_IDENTITY_MISMATCH,
            "finding slug differs across source-bound recording inputs: " + ", ".join(unique),
        )
    return unique[0]


def _marker(documents: list[Mapping[str, Any]], names: tuple[str, ...]) -> str:
    for document in documents:
        for item in _walk_mappings(document):
            value = _first(*(item.get(name) for name in names))
            if value:
                return value
    return ""


def _code_context(documents: list[Mapping[str, Any]]) -> str:
    locations: list[str] = []
    sources: list[str] = []
    sinks: list[str] = []
    for document in documents:
        for item in _walk_mappings(document):
            if "code_context" in item and isinstance(item["code_context"], list):
                for context in item["code_context"]:
                    if isinstance(context, Mapping):
                        locations.append(_first(context.get("location"), context.get("path")))
                        sources.append(_first(context.get("source"), context.get("attacker_input"), context.get("summary")))
                        sinks.append(_first(context.get("sink"), context.get("dangerous_operation"), context.get("explanation")))
            locations.append(_first(item.get("code_location"), item.get("location"), item.get("source_path")))
            sources.append(_first(item.get("attacker_controlled_input"), item.get("source"), item.get("entrypoint")))
            sinks.append(_first(item.get("dangerous_sink"), item.get("sink"), item.get("dangerous_operation")))
    location = next((item for item in locations if item), "")
    source = next((item for item in sources if item), "")
    sink = next((item for item in sinks if item), "")
    if not location and not source and not sink:
        return ""
    return "location={};source={};sink={}".format(location, source, sink)


def _trigger_context(documents: list[Mapping[str, Any]]) -> str:
    values: list[str] = []
    for document in documents:
        for item in _walk_mappings(document):
            for field in (
                "trigger_context",
                "trigger_path",
                "entrypoint",
                "attacker_condition",
                "attacker_controlled_input",
                "endpoint",
                "route",
            ):
                value = _nonempty(item.get(field))
                if value:
                    values.append(value)
    return " | ".join(dict.fromkeys(values))


def _assert_consistent(documents: list[Mapping[str, Any]], field: str, value: str, *, ref_field: bool = False) -> None:
    observed: list[str] = []
    aliases = {
        "software_name": ("project_name", "software_name", "package_name", "project"),
        "finding_slug": ("finding_slug", "slug"),
        "direct_impact_marker": ("direct_impact_marker",),
        "oracle_marker": ("oracle_token", "oracle_marker"),
    }
    names = aliases.get(field, (field,))
    for document in documents:
        for item in _walk_mappings(document):
            item_value = _first(*(item.get(name) for name in names))
            if item_value:
                observed.append(item_value)
    if ref_field:
        refs = []
        for item in _source_binding_candidates(documents):
            for name in (
                "tested_ref",
                "source_bound_ref",
                "tested_version",
                "version_affected",
                "tested_branch",
                "branch",
                "tested_commit",
                "commit",
                "source_revision",
                "revision",
            ):
                raw = _nonempty(item.get(name))
                if raw:
                    normalized, _kind = _stable_ref(raw)
                    if normalized:
                        refs.append(normalized)
        observed = refs
    unique = sorted(set(observed))
    if len(unique) > 1:
        code = RECORDING_TESTED_REF_MISMATCH if ref_field else RECORDING_IDENTITY_MISMATCH
        raise RecordingIdentityError(code, f"{field} differs across source-bound inputs: {', '.join(unique)}")
    if value and unique and value not in unique:
        code = RECORDING_TESTED_REF_MISMATCH if ref_field else RECORDING_IDENTITY_MISMATCH
        raise RecordingIdentityError(code, f"canonical {field} does not match source-bound inputs")


def canonical_identity_from_documents(documents: list[Mapping[str, Any]]) -> dict[str, str]:
    """Build and cross-check the immutable identity used by every recording stage."""

    if not documents:
        raise RecordingIdentityError(RECORDING_IDENTITY_MISSING, "no source-bound JSON documents were provided")
    project = _project_name(documents)
    ref, ref_kind = _pick_tested_ref(documents)
    slug = _finding_slug(documents)
    direct = _marker(documents, ("direct_impact_marker",))
    oracle = _marker(documents, ("oracle_token", "oracle_marker"))
    code_context = _code_context(documents)
    trigger_context = _trigger_context(documents)
    missing = [
        name
        for name, value in (
            ("software_name", project),
            ("tested_ref", ref),
            ("finding_slug", slug),
            ("direct_impact_marker", direct),
            ("oracle_marker", oracle),
            ("code_context_identity", code_context),
            ("trigger_context_identity", trigger_context),
        )
        if not value
    ]
    if missing:
        raise RecordingIdentityError(RECORDING_IDENTITY_MISSING, "missing canonical fields: " + ", ".join(missing))
    identity = {
        "software_name": project,
        "tested_ref": ref,
        "tested_ref_kind": ref_kind,
        "finding_slug": slug,
        "direct_impact_marker": direct,
        "oracle_marker": oracle,
        "code_context_identity": code_context,
        "trigger_context_identity": trigger_context,
    }
    _assert_consistent(documents, "software_name", project)
    _assert_consistent(documents, "finding_slug", slug)
    _assert_consistent(documents, "direct_impact_marker", direct)
    _assert_consistent(documents, "oracle_marker", oracle)
    _assert_consistent(documents, "tested_ref", ref, ref_field=True)
    return identity


def load_json_documents(bundle_dir: Path) -> list[dict[str, Any]]:
    """Load the required source-bound inputs in deterministic order."""

    paths = [
        bundle_dir / "findings.json",
        bundle_dir / "validity-review.json",
        bundle_dir / "verification-evidence.json",
    ]
    documents: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_file():
            raise RecordingIdentityError(RECORDING_IDENTITY_MISSING, f"missing required identity source: {path.name}")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RecordingIdentityError(RECORDING_IDENTITY_MISSING, f"cannot read {path.name}: {exc}") from exc
        if not isinstance(value, Mapping):
            raise RecordingIdentityError(RECORDING_IDENTITY_MISSING, f"{path.name} must contain a JSON object")
        documents.append(dict(value))
    return documents


def parse_canonical_identity(bundle_dir: Path) -> dict[str, str]:
    return canonical_identity_from_documents(load_json_documents(bundle_dir))


def compare_identity(expected: Mapping[str, Any], actual: Mapping[str, Any], *, source: str = "recording") -> None:
    for field in IDENTITY_FIELDS:
        expected_value = _nonempty(expected.get(field))
        actual_value = _nonempty(actual.get(field))
        if not expected_value or not actual_value:
            raise RecordingIdentityError(RECORDING_IDENTITY_MISSING, f"{source} identity omits {field}")
        if expected_value != actual_value:
            code = RECORDING_TESTED_REF_MISMATCH if field in {"tested_ref", "tested_ref_kind"} else RECORDING_IDENTITY_MISMATCH
            raise RecordingIdentityError(code, f"{source} identity field {field} differs from canonical source")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def path_within(root: Path, candidate: Path, *, allow_missing: bool = False) -> bool:
    """Return true only for a relative, non-symlink path confined to root."""

    root_resolved = root.resolve()
    try:
        candidate_path = candidate if candidate.is_absolute() else root / candidate
        if not allow_missing and not candidate_path.exists():
            return False
        current = root_resolved
        relative = candidate_path if candidate_path.is_absolute() else candidate_path
        try:
            relative = relative.resolve(strict=False).relative_to(root_resolved)
        except ValueError:
            return False
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                return False
        return True
    except OSError:
        return False


def assert_relative_bundle_path(root: Path, value: Any, *, field: str, allow_missing: bool = False) -> Path:
    text = _nonempty(value)
    if not text or os.path.isabs(text) or "\\" in text:
        raise RecordingIdentityError(RECORDING_IDENTITY_MISMATCH, f"{field} must be a bundle-relative POSIX path")
    path = root / Path(text)
    if not path_within(root, path, allow_missing=allow_missing):
        raise RecordingIdentityError(RECORDING_IDENTITY_MISMATCH, f"{field} escapes the bundle root")
    return path
