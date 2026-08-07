#!/usr/bin/env python3
"""Pure Candidate R2 identity helpers.

This module never discovers candidates, executes target code, or grants verifier,
disposition, bundle, or finalization authority.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any


IDENTITY_VERSION = 1
NORMALIZATION_VERSION = 1
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
STABLE_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
OTHER_FAMILY_RE = re.compile(r"^other:[a-z0-9][a-z0-9._-]{0,63}$")
HTTP_ROUTE_RE = re.compile(r"^([A-Za-z]+)[ \t]+(/[^?#]*)$")
PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
SOURCE_KINDS = {"agent", "scanner", "manual_review", "seeded_variant", "imported_legacy"}
SINK_FAMILIES = {
    "command_execution", "file_read", "file_write", "path_resolution", "http_request",
    "deserialization", "template_render", "database_query", "code_loading", "authz_decision",
    "secret_exposure", "resource_exhaustion", "logging",
}
ROOT_CAUSE_FAMILIES = {
    "missing_validation", "insufficient_validation", "canonicalization_mismatch",
    "authorization_missing", "trust_boundary_confusion", "unsafe_default", "injection",
    "resource_limit_missing", "race_condition",
}
FORBIDDEN_PORTABLE_TEXT = re.compile(
    r"(?:^|[\s:=,'\"])(?:/Users/|/home/|[A-Za-z]:[\\/]|file://|https?://)|"
    r"(?:password|passwd|api[_-]?key|secret|credential|token)\s*[:=]|"
    r"(?:hidden[_ -]?reasoning|chain[_ -]?of[_ -]?thought|system[_ -]?prompt)",
    re.IGNORECASE,
)


class IdentityError(ValueError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def pretty_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _portable_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IdentityError(f"{label} must be a non-empty string")
    text = value.strip()
    if "\x00" in text or FORBIDDEN_PORTABLE_TEXT.search(text):
        raise IdentityError(f"{label} contains non-portable, secret-like, prompt, or hidden-reasoning material")
    return text


def safe_relative_path(value: Any, label: str) -> str:
    text = _portable_text(value, label)
    if text.startswith(("/", "~")) or "\\" in text or "://" in text:
        raise IdentityError(f"{label} must be a relative POSIX path")
    path = PurePosixPath(text)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise IdentityError(f"{label} must not contain empty, dot, or parent segments")
    normalized = path.as_posix()
    if normalized != text:
        raise IdentityError(f"{label} must already be normalized POSIX text")
    return normalized


def resolve_regular_file(root: Path, relative: str, label: str) -> Path:
    root = root.resolve(strict=True)
    candidate = root.joinpath(*safe_relative_path(relative, label).split("/"))
    try:
        info = os.lstat(candidate)
    except OSError as exc:
        raise IdentityError(f"{label} does not reference a readable regular file") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise IdentityError(f"{label} must reference a non-symlink regular file")
    try:
        candidate.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise IdentityError(f"{label} resolves outside its allowed root") from exc
    return candidate


def _stable_token(value: Any, label: str) -> str:
    text = _portable_text(value, label).lower()
    if not STABLE_TOKEN_RE.fullmatch(text):
        raise IdentityError(f"{label} must be a portable stable token")
    return text


def _family(value: Any, allowed: set[str], label: str) -> str:
    text = _portable_text(value, label).lower()
    if text not in allowed and not OTHER_FAMILY_RE.fullmatch(text):
        raise IdentityError(f"{label} is not in the controlled vocabulary")
    return text


def normalize_entrypoint(entrypoint: Any) -> dict[str, str]:
    if not isinstance(entrypoint, dict) or set(entrypoint) != {"id", "kind", "route"}:
        raise IdentityError("entrypoint must contain exactly id, kind, and route")
    kind = _stable_token(entrypoint.get("kind"), "entrypoint.kind")
    entry_id = _stable_token(entrypoint.get("id"), "entrypoint.id")
    route = _portable_text(entrypoint.get("route"), "entrypoint.route")
    if "\\" in route or "\x00" in route:
        raise IdentityError("entrypoint.route contains an ambiguous separator")
    if kind in {"http", "https", "web", "rest"}:
        match = HTTP_ROUTE_RE.fullmatch(route)
        if match is None:
            raise IdentityError("HTTP entrypoint.route must be 'METHOD /path' without authority, query, or fragment")
        method, raw_path = match.groups()
        if "//" in raw_path:
            raw_path = re.sub(r"/{2,}", "/", raw_path)
        segments = raw_path.split("/")
        if any(segment in {".", ".."} for segment in segments):
            raise IdentityError("HTTP entrypoint.route must not contain dot segments")
        encoded = PERCENT_RE.findall(raw_path)
        if encoded and any(token.lower() in {"%2f", "%5c", "%2e"} for token in encoded):
            raise IdentityError("HTTP entrypoint.route contains ambiguous encoded separators or dot segments")
        if "%" in PERCENT_RE.sub("", raw_path):
            raise IdentityError("HTTP entrypoint.route contains invalid percent encoding")
        if len(raw_path) > 1:
            raw_path = raw_path.rstrip("/")
        route = f"{method.upper()} {raw_path}"
    else:
        if any(token in route for token in ("?", "#", "://")):
            raise IdentityError("non-HTTP entrypoint.route must not contain URI authority, query, or fragment syntax")
        route = re.sub(r"[ \t]+", " ", route).strip()
        if not route:
            raise IdentityError("entrypoint.route is empty after normalization")
    return {"id": entry_id, "kind": kind, "route": route}


def identity_components(
    *, target_commit: Any, entrypoint: Any, trust_boundary_id: Any,
    sink_family: Any, root_cause_family: Any, primary_source_path: Any,
) -> dict[str, Any]:
    commit = _portable_text(target_commit, "identity.target_commit")
    boundary = None if trust_boundary_id is None else _stable_token(trust_boundary_id, "identity.trust_boundary_id")
    return {
        "normalization_version": NORMALIZATION_VERSION,
        "target_commit": commit,
        "normalized_entrypoint": normalize_entrypoint(entrypoint),
        "trust_boundary_id": boundary,
        "sink_family": _family(sink_family, SINK_FAMILIES, "identity.sink_family"),
        "root_cause_family": _family(root_cause_family, ROOT_CAUSE_FAMILIES, "identity.root_cause_family"),
        "primary_source_path": safe_relative_path(primary_source_path, "identity.primary_source_path"),
    }


def fingerprint_for_components(components: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(components))


def build_identity(candidate: dict[str, Any], identity_input: dict[str, Any]) -> dict[str, Any]:
    target_ref = candidate.get("target_ref") if isinstance(candidate.get("target_ref"), dict) else {}
    components = identity_components(
        target_commit=identity_input.get("target_commit"),
        entrypoint=candidate.get("entrypoint"),
        trust_boundary_id=identity_input.get("trust_boundary_id"),
        sink_family=identity_input.get("sink_family"),
        root_cause_family=identity_input.get("root_cause_family"),
        primary_source_path=identity_input.get("primary_source_path"),
    )
    if components["target_commit"] != target_ref.get("tested_ref"):
        raise IdentityError("identity.target_commit must exactly match target_ref.tested_ref")
    return {
        "identity_version": IDENTITY_VERSION,
        "normalization_version": NORMALIZATION_VERSION,
        "fingerprint": fingerprint_for_components(components),
        **components,
    }


def validate_identity(candidate: dict[str, Any], identity: Any) -> dict[str, Any]:
    if not isinstance(identity, dict):
        raise IdentityError("identity must be an object")
    allowed = {
        "identity_version", "normalization_version", "fingerprint", "target_commit",
        "normalized_entrypoint", "trust_boundary_id", "sink_family", "root_cause_family",
        "primary_source_path",
    }
    if set(identity) != allowed:
        raise IdentityError("identity has missing or unsupported fields")
    if identity.get("identity_version") != IDENTITY_VERSION or identity.get("normalization_version") != NORMALIZATION_VERSION:
        raise IdentityError("identity or normalization version is unsupported")
    rebuilt = build_identity(candidate, identity)
    if identity.get("normalized_entrypoint") != rebuilt["normalized_entrypoint"]:
        raise IdentityError("identity.normalized_entrypoint does not match the candidate entrypoint")
    for key in ("target_commit", "trust_boundary_id", "sink_family", "root_cause_family", "primary_source_path"):
        if identity.get(key) != rebuilt.get(key):
            raise IdentityError(f"identity.{key} is not canonical")
    if identity.get("fingerprint") != rebuilt["fingerprint"]:
        raise IdentityError("identity.fingerprint does not match independently recomputed components")
    return rebuilt


def normalize_provenance(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list) or not items:
        raise IdentityError("provenance must be a non-empty array")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise IdentityError(f"provenance[{index}] must be an object")
        allowed = {"source_kind", "source_id", "artifact_path", "artifact_sha256", "observed_at", "producer"}
        if not {"source_kind", "source_id", "artifact_path", "artifact_sha256"}.issubset(item) or set(item) - allowed:
            raise IdentityError(f"provenance[{index}] has missing or unsupported fields")
        source_kind = item.get("source_kind")
        if source_kind not in SOURCE_KINDS:
            raise IdentityError(f"provenance[{index}].source_kind is unsupported")
        current: dict[str, Any] = {
            "source_kind": source_kind,
            "source_id": _stable_token(item.get("source_id"), f"provenance[{index}].source_id"),
            "artifact_path": safe_relative_path(item.get("artifact_path"), f"provenance[{index}].artifact_path"),
            "artifact_sha256": item.get("artifact_sha256"),
        }
        if not isinstance(current["artifact_sha256"], str) or not SHA256_RE.fullmatch(current["artifact_sha256"]):
            raise IdentityError(f"provenance[{index}].artifact_sha256 must be sha256:<lowercase hex>")
        if "observed_at" in item:
            current["observed_at"] = _portable_text(item["observed_at"], f"provenance[{index}].observed_at")
            try:
                datetime.fromisoformat(current["observed_at"].replace("Z", "+00:00"))
            except ValueError as exc:
                raise IdentityError(f"provenance[{index}].observed_at must be an ISO-8601 date-time") from exc
        if "producer" in item:
            producer = item["producer"]
            if not isinstance(producer, dict) or set(producer) != {"name", "version"}:
                raise IdentityError(f"provenance[{index}].producer must contain exactly name and version")
            current["producer"] = {
                "name": _stable_token(producer.get("name"), f"provenance[{index}].producer.name"),
                "version": _portable_text(producer.get("version"), f"provenance[{index}].producer.version"),
            }
        normalized.append(current)
    ordered = sorted(normalized, key=lambda item: canonical_json_bytes(item))
    deduped: list[dict[str, Any]] = []
    for item in ordered:
        if not deduped or canonical_json_bytes(deduped[-1]) != canonical_json_bytes(item):
            deduped.append(item)
    return deduped


def atomic_publish(path: Path, payload: bytes) -> str:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = path.read_bytes()
        if existing == payload:
            return "unchanged"
        raise IdentityError("output already exists with different bytes")
    fd = -1
    temp_path: Path | None = None
    try:
        fd, raw = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temp_path = Path(raw)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temp_path, path)
        except FileExistsError:
            if path.read_bytes() == payload:
                return "unchanged"
            raise IdentityError("output appeared concurrently with different bytes")
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return "created"
    finally:
        if fd >= 0:
            os.close(fd)
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
