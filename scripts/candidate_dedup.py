#!/usr/bin/env python3
"""Shared deterministic Candidate R2 dedup-plan derivation."""
from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any

from candidate_identity import IdentityError, canonical_json_bytes, file_sha256, normalize_provenance, resolve_regular_file, safe_relative_path, sha256_bytes
from validate_candidate import ValidationError, load_candidate, validate_candidate


class DedupError(ValueError):
    pass


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DedupError(f"{label} is not readable JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise DedupError(f"{label} must be an object")
    return value


def _item_key(item: dict[str, Any]) -> tuple[bytes, bytes, bytes]:
    return (str(item["candidate_id"]).encode(), str(item["path"]).encode(), str(item["sha256"]).encode())


def load_inventory(repo_root: Path, workspace_dir: Path, inventory_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    repo_root = repo_root.resolve(strict=True)
    workspace_dir = workspace_dir.resolve(strict=True)
    inventory_path = inventory_path.resolve(strict=True)
    try:
        inventory_relative = inventory_path.relative_to(workspace_dir).as_posix()
    except ValueError as exc:
        raise DedupError("inventory must stay inside workspace-dir") from exc
    inventory = _load_object(inventory_path, "inventory")
    if set(inventory) != {"schema_version", "inventory_id", "candidates"} or inventory.get("schema_version") != 1:
        raise DedupError("inventory has missing, unsupported, or unknown-version fields")
    inventory_id = inventory.get("inventory_id")
    if not isinstance(inventory_id, str) or not inventory_id.startswith("INVENTORY-"):
        raise DedupError("inventory_id is invalid")
    raw_items = inventory.get("candidates")
    if not isinstance(raw_items, list) or len(raw_items) < 2:
        raise DedupError("inventory must explicitly list at least two candidates")
    loaded: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for index, item in enumerate(raw_items):
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "candidate_id", "fingerprint", "target_tested_ref"}:
            raise DedupError(f"inventory.candidates[{index}] has missing or unsupported fields")
        try:
            relative = safe_relative_path(item.get("path"), f"inventory.candidates[{index}].path")
            candidate_path = resolve_regular_file(workspace_dir, relative, f"inventory.candidates[{index}].path")
        except IdentityError as exc:
            raise DedupError(str(exc)) from exc
        candidate_id = item.get("candidate_id")
        if candidate_id in seen_ids or relative in seen_paths:
            raise DedupError("inventory contains a duplicate candidate ID or path")
        seen_ids.add(str(candidate_id)); seen_paths.add(relative)
        actual_digest = file_sha256(candidate_path)
        if item.get("sha256") != actual_digest:
            raise DedupError(f"candidate digest drift: {relative}")
        candidate = load_candidate(candidate_path)
        try:
            checked = validate_candidate(candidate, repo_root=repo_root)
        except ValidationError as exc:
            raise DedupError(f"candidate invalid: {relative}: {exc}") from exc
        target_ref = candidate.get("target_ref") if isinstance(candidate.get("target_ref"), dict) else {}
        fingerprint = checked.get("fingerprint")
        if item.get("candidate_id") != checked["candidate_id"] or item.get("target_tested_ref") != target_ref.get("tested_ref"):
            raise DedupError(f"candidate ID or tested-ref drift: {relative}")
        if item.get("fingerprint") != fingerprint:
            raise DedupError(f"candidate fingerprint drift: {relative}")
        if checked["protocol_mode"] == "r2":
            for pindex, provenance in enumerate(candidate["provenance"]):
                artifact = resolve_regular_file(workspace_dir, provenance["artifact_path"], f"{relative}.provenance[{pindex}].artifact_path")
                if file_sha256(artifact) != provenance["artifact_sha256"]:
                    raise DedupError(f"provenance artifact digest drift: {provenance['artifact_path']}")
        loaded.append({**item, "protocol_mode": checked["protocol_mode"], "document": candidate})
    loaded.sort(key=_item_key)
    _validate_relationship_graph(loaded)
    canonical_inventory = {
        "schema_version": 1,
        "inventory_id": inventory_id,
        "candidates": [
            {key: item[key] for key in ("path", "sha256", "candidate_id", "fingerprint", "target_tested_ref")}
            for item in loaded
        ],
    }
    return {**inventory, "_path": inventory_relative, "_sha256": sha256_bytes(canonical_json_bytes(canonical_inventory))}, loaded


def _validate_relationship_graph(candidates: list[dict[str, Any]]) -> None:
    known = {item["candidate_id"]: item for item in candidates}
    duplicate_edges: dict[str, str] = {}

    # Validate graph topology before digest bindings. A cyclic relationship
    # necessarily changes the bytes (and therefore the digest) of both ends;
    # checking bindings first would make the explicit cycle diagnostics
    # unreachable and obscure the more fundamental graph error.
    for item in candidates:
        if item["protocol_mode"] != "r2":
            continue
        relationships = item["document"]["relationships"]
        refs = list(relationships["merged_from"])
        duplicate = relationships["duplicate_of"]
        if duplicate is not None:
            refs.append(duplicate)
            duplicate_edges[item["candidate_id"]] = duplicate["candidate_id"]
        for ref in refs:
            if ref["candidate_id"] not in known:
                raise DedupError(f"relationship target is outside the explicit inventory: {ref['candidate_id']}")

    for source, target in sorted(duplicate_edges.items()):
        if duplicate_edges.get(target) == source:
            raise DedupError("bidirectional duplicate_of relationships are forbidden")
    for source in sorted(duplicate_edges):
        seen: set[str] = set()
        current = source
        while current in duplicate_edges:
            if current in seen:
                raise DedupError("duplicate_of relationship cycle detected")
            seen.add(current)
            current = duplicate_edges[current]

    for item in candidates:
        if item["protocol_mode"] != "r2":
            continue
        relationships = item["document"]["relationships"]
        refs = list(relationships["merged_from"])
        if relationships["duplicate_of"] is not None:
            refs.append(relationships["duplicate_of"])
        for ref in refs:
            target = known[ref["candidate_id"]]
            if (ref["path"], ref["sha256"], ref["fingerprint"]) != (target["path"], target["sha256"], target["fingerprint"]):
                raise DedupError(f"relationship target binding drift: {ref['candidate_id']}")
        duplicate = relationships["duplicate_of"]
        if duplicate is not None:
            target = known[duplicate["candidate_id"]]
            classification, _reason = _classify(item, target)
            if classification != "exact_duplicate":
                raise DedupError("duplicate_of is permitted only for an exact duplicate")
            if target["protocol_mode"] == "r2" and target["document"]["relationships"]["duplicate_of"] is not None:
                raise DedupError("canonical duplicate target must not itself be subordinate")
        merged = relationships["merged_from"]
        if merged:
            expected = list(item["document"]["provenance"])
            for ref in merged:
                target = known[ref["candidate_id"]]
                if target["protocol_mode"] != "r2":
                    raise DedupError("merged_from may reference only Candidate R2 records")
                expected.extend(target["document"]["provenance"])
            if normalize_provenance(expected) != item["document"]["provenance"]:
                raise DedupError("merged_from provenance union is incomplete")


def _classify(left: dict[str, Any], right: dict[str, Any]) -> tuple[str, str]:
    if left["target_tested_ref"] != right["target_tested_ref"]:
        return "distinct", "TARGET_COMMIT_DIFFERS"
    if left["protocol_mode"] != "r2" or right["protocol_mode"] != "r2":
        return "review_required", "LEGACY_IDENTITY_UNAVAILABLE"
    li = left["document"]["identity"]; ri = right["document"]["identity"]
    core = ("target_commit", "normalized_entrypoint", "trust_boundary_id", "sink_family", "root_cause_family", "primary_source_path")
    if left["fingerprint"] == right["fingerprint"] and all(li[key] == ri[key] for key in core):
        return "exact_duplicate", "ALL_IDENTITY_COMPONENTS_EQUAL"
    entry = li["normalized_entrypoint"] == ri["normalized_entrypoint"]
    source = li["primary_source_path"] == ri["primary_source_path"]
    sink = li["sink_family"] == ri["sink_family"]
    cause = li["root_cause_family"] == ri["root_cause_family"]
    if (entry and source) or (sink and cause and source) or (entry and sink and cause):
        return "review_required", "PARTIAL_STRUCTURED_IDENTITY_MATCH"
    return "distinct", "STRUCTURED_IDENTITY_DISTINCT"


def derive_plan(inventory: dict[str, Any], candidates: list[dict[str, Any]]) -> dict[str, Any]:
    public_candidates = [
        {key: item[key] for key in ("candidate_id", "path", "sha256", "protocol_mode", "fingerprint", "target_tested_ref")}
        for item in candidates
    ]
    classifications: list[dict[str, Any]] = []
    exact_by_fingerprint: dict[str, list[dict[str, Any]]] = {}
    for left, right in itertools.combinations(candidates, 2):
        classification, reason = _classify(left, right)
        canonical = min((left, right), key=_item_key)["candidate_id"] if classification == "exact_duplicate" else None
        classifications.append({
            "canonical_candidate_id": canonical, "classification": classification,
            "left_candidate_id": left["candidate_id"], "reason_code": reason,
            "right_candidate_id": right["candidate_id"],
        })
        if classification == "exact_duplicate":
            exact_by_fingerprint.setdefault(str(left["fingerprint"]), []).extend((left, right))
    groups: list[dict[str, Any]] = []
    for fingerprint, raw_members in sorted(exact_by_fingerprint.items()):
        members = {member["candidate_id"]: member for member in raw_members}
        ordered = sorted(members.values(), key=_item_key)
        provenance: list[dict[str, Any]] = []
        for member in ordered:
            provenance.extend(member["document"]["provenance"])
        groups.append({
            "canonical_candidate_id": ordered[0]["candidate_id"], "fingerprint": fingerprint,
            "member_candidate_ids": [item["candidate_id"] for item in ordered],
            "merged_provenance": normalize_provenance(provenance),
        })
    classifications.sort(key=lambda item: (item["left_candidate_id"].encode(), item["right_candidate_id"].encode()))
    body = {
        "schema_version": 1,
        "inventory": {"inventory_id": inventory["inventory_id"], "path": inventory["_path"], "sha256": inventory["_sha256"]},
        "candidates": public_candidates, "classifications": classifications, "exact_groups": groups,
        "authority": "candidate_advisory_only",
    }
    body["plan_id"] = "DEDUP-" + sha256_bytes(canonical_json_bytes(body)).removeprefix("sha256:")[:16]
    return body
