#!/usr/bin/env python3
"""Explicit, offline, non-overwriting Candidate R1 to R2 upgrade."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from candidate_identity import IdentityError, atomic_publish, build_identity, normalize_provenance, pretty_json_bytes, resolve_regular_file
from validate_candidate import ValidationError, load_candidate, validate_candidate


def load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IdentityError(f"{label} is not readable JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise IdentityError(f"{label} must be a JSON object")
    return value


def upgrade(candidate_path: Path, repo_root: Path, identity_input_path: Path, output: Path) -> tuple[dict[str, Any], str]:
    candidate_path = candidate_path.resolve(strict=True)
    identity_input_path = identity_input_path.resolve(strict=True)
    repo_root = repo_root.resolve(strict=True)
    output = output.resolve()
    if output == candidate_path:
        raise IdentityError("in-place candidate overwrite is forbidden")
    candidate_raw = candidate_path.read_bytes()
    identity_input_raw = identity_input_path.read_bytes()
    try:
        candidate = json.loads(candidate_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdentityError(f"candidate is not readable UTF-8 JSON: {exc}") from exc
    if not isinstance(candidate, dict):
        raise IdentityError("candidate must be a JSON object")
    checked = validate_candidate(candidate)
    if checked["protocol_mode"] != "legacy_r1":
        raise IdentityError("upgrade input must be a Candidate Contract R1 file")
    try:
        identity_input = json.loads(identity_input_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdentityError(f"identity input is not readable UTF-8 JSON: {exc}") from exc
    if not isinstance(identity_input, dict):
        raise IdentityError("identity input must be a JSON object")
    if set(identity_input) != {
        "schema_version", "target_commit", "trust_boundary_id", "sink_family",
        "root_cause_family", "primary_source_path", "provenance",
    } or identity_input.get("schema_version") != 1:
        raise IdentityError("identity input has missing, unsupported, or unknown-version fields")
    identity = build_identity(candidate, identity_input)
    resolve_regular_file(repo_root, identity["primary_source_path"], "identity.primary_source_path")
    upgraded = dict(candidate)
    upgraded["schema_version"] = 2
    upgraded["identity"] = identity
    upgraded["provenance"] = normalize_provenance(identity_input["provenance"])
    upgraded["relationships"] = {
        "duplicate_of": None,
        "legacy_id_mapping": [{"current_candidate_id": candidate["candidate_id"], "legacy_candidate_id": candidate["candidate_id"]}],
        "merged_from": [],
    }
    validate_candidate(upgraded, repo_root=repo_root)
    if candidate_path.read_bytes() != candidate_raw or identity_input_path.read_bytes() != identity_input_raw:
        raise IdentityError("upgrade input drifted during generation")
    status = atomic_publish(output, pretty_json_bytes(upgraded))
    return upgraded, status


def main() -> None:
    parser = argparse.ArgumentParser(description="Explicitly upgrade a Candidate R1 file to Candidate R2.")
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--identity-input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result, status = upgrade(Path(args.candidate), Path(args.repo_root), Path(args.identity_input), Path(args.output))
        payload = {"ok": True, "candidate_id": result["candidate_id"], "fingerprint": result["identity"]["fingerprint"], "output_status": status, "protocol_mode": "r2"}
    except (IdentityError, ValidationError, OSError) as exc:
        payload = {"ok": False, "error": str(exc)}
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print(f"OK: candidate upgraded; candidate_id={payload['candidate_id']} fingerprint={payload['fingerprint']} output={status}")


if __name__ == "__main__":
    main()
