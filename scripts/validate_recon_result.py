#!/usr/bin/env python3
"""Validate a portable Zhulong Recon coverage result without writing state.

The validator deliberately owns only Recon material.  It binds the result to a
workspace-local target contract and attack-surface digest, checks references
against the supplied repository/workspace, and never interprets the result as
a finding, verdict, disposition, bundle, or stage transition.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "assets/schemas/recon-result.schema.json"
TARGET_VALIDATOR_PATH = Path(__file__).resolve().parent / "validate_target_contract.py"

ROOT_REQUIRED = {
    "schema_version",
    "recon_id",
    "status",
    "target_binding",
    "attack_surface_binding",
    "technology_stack",
    "public_entrypoints",
    "trust_boundaries",
    "high_risk_sinks",
    "security_policy_explanations",
    "default_deployment_assumptions",
    "priority_areas",
    "deferred_areas",
    "coverage",
    "coverage_gaps",
    "unresolved_blockers",
    "focus_refs",
}

COVERAGE_CATEGORIES = (
    "technology_stack",
    "public_entrypoints",
    "trust_boundaries",
    "high_risk_sinks",
    "security_policy_explanations",
    "default_deployment_assumptions",
    "priority_areas",
    "deferred_areas",
)

ENTITY_CATEGORIES = {
    "technology_stack": "TECH-",
    "public_entrypoints": "ENTRY-",
    "trust_boundaries": "BOUNDARY-",
    "high_risk_sinks": "SINK-",
    "security_policy_explanations": "POLICY-",
    "default_deployment_assumptions": "ASSUME-",
    "priority_areas": "FOCUS-",
    "deferred_areas": "DEFER-",
}

FORBIDDEN_PERMISSION_FIELDS = {
    "confirmed",
    "confirmed_in_docker",
    "verdict",
    "disposition",
    "severity",
    "cvss",
    "bundle_ready",
    "confirmed_bundle_path",
    "promotion",
}

CANDIDATE_FIELDS = {
    "candidate",
    "candidate_id",
    "candidate_ids",
    "candidates",
}

NO_COVERAGE_EVIDENCE_RE = re.compile(
    r"^(?:未发现问题|未发现漏洞|没有发现问题|no issues found|no vulnerabilities found|no findings)\.?$",
    re.IGNORECASE,
)
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RECON_ID_RE = re.compile(r"^RECON-[0-9A-Za-z][0-9A-Za-z._-]*$")
STABLE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*-[0-9A-Za-z][0-9A-Za-z._-]*$")
STABLE_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")


class Issue:
    __slots__ = ("code", "path", "message", "action")

    def __init__(self, code: str, path: str, message: str, action: str) -> None:
        self.code = code
        self.path = path
        self.message = message
        self.action = action

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "path": self.path,
            "message": self.message,
            "action": self.action,
        }


class ValidationContext:
    def __init__(self, repo_root: Path, workspace_dir: Path) -> None:
        self.repo_root = repo_root
        self.workspace_dir = workspace_dir
        self.issues: list[Issue] = []
        self._issue_keys: set[tuple[str, str, str]] = set()
        self.known_ids: dict[str, str] = {}

    def add(self, code: str, path: str, message: str, action: str) -> None:
        key = (code, path, message)
        if key in self._issue_keys:
            return
        self._issue_keys.add(key)
        self.issues.append(Issue(code, path, message, action))

    def relative_file(
        self,
        root: Path,
        value: Any,
        path: str,
        *,
        root_label: str,
        repo_source: bool = False,
    ) -> Path | None:
        if not isinstance(value, str) or not value.strip():
            self.add(
                "SCHEMA_INVALID",
                path,
                "A non-empty relative path is required.",
                "Provide a workspace-relative or repository-relative path.",
            )
            return None
        if not is_safe_relative_text(value):
            self.add(
                "PATH_UNSAFE",
                path,
                "The reference uses an absolute path, URI, parent traversal, or backslash.",
                f"Use a {root_label}-relative POSIX path without '..' or symlink escape.",
            )
            return None

        root_real = root.resolve()
        candidate = root.joinpath(*value.split("/"))
        try:
            resolved = candidate.resolve(strict=False)
        except OSError:
            self.add(
                "PATH_UNSAFE",
                path,
                "The reference could not be resolved safely.",
                f"Keep the reference inside the supplied {root_label}.",
            )
            return None
        try:
            resolved.relative_to(root_real)
        except ValueError:
            self.add(
                "SYMLINK_ESCAPE",
                path,
                "The referenced path resolves outside the supplied root.",
                f"Replace the reference with a regular file inside the supplied {root_label}.",
            )
            return None
        if not candidate.exists():
            self.add(
                "FILE_MISSING",
                path,
                "The referenced file does not exist.",
                "Create the referenced evidence/source file or correct the relative path.",
            )
            return None
        if not candidate.is_file():
            self.add(
                "FILE_MISSING",
                path,
                "The reference does not resolve to a regular file.",
                "Reference a regular evidence or source file.",
            )
            return None
        return candidate

    def source_refs(self, value: Any, path: str) -> None:
        if not isinstance(value, list):
            return
        for index, ref in enumerate(value):
            ref_path = f"{path}[{index}]"
            if not isinstance(ref, dict):
                continue
            source_path = self.relative_file(
                self.repo_root,
                ref.get("path"),
                f"{ref_path}.path",
                root_label="repository",
                repo_source=True,
            )
            start = ref.get("start_line")
            end = ref.get("end_line")
            if start is not None and isinstance(start, int):
                if end is not None and isinstance(end, int) and end < start:
                    self.add(
                        "SOURCE_REFERENCE_INVALID",
                        ref_path,
                        "end_line must not be smaller than start_line.",
                        "Use a valid inclusive source line range.",
                    )
                if source_path is not None:
                    try:
                        line_count = len(source_path.read_text(encoding="utf-8").splitlines())
                    except (OSError, UnicodeError):
                        line_count = 0
                    last_referenced_line = end if isinstance(end, int) else start
                    if line_count and last_referenced_line > line_count:
                        self.add(
                            "SOURCE_REFERENCE_INVALID",
                            ref_path,
                            "The source line range exceeds the referenced file.",
                            "Update the source location to a line present in the checked-out repository.",
                        )

    def evidence_refs(self, value: Any, path: str) -> None:
        if not isinstance(value, list):
            return
        for index, ref in enumerate(value):
            ref_path = f"{path}[{index}]"
            if not isinstance(ref, dict):
                continue
            self.relative_file(
                self.workspace_dir,
                ref.get("path"),
                f"{ref_path}.path",
                root_label="workspace",
            )

    def basis(self, value: Any, path: str) -> None:
        if not isinstance(value, dict):
            return
        self.source_refs(value.get("source_refs"), f"{path}.source_refs")
        self.evidence_refs(value.get("evidence_refs"), f"{path}.evidence_refs")


def is_safe_relative_text(value: str) -> bool:
    if not value or value.strip() != value:
        return False
    if value.startswith(("/", "~", "file://", "http://", "https://")):
        return False
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return False
    if "\\" in value or "\x00" in value:
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def load_json(path: Path) -> tuple[Any | None, bytes | None, str | None]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return None, None, str(exc)
    try:
        return json.loads(raw.decode("utf-8")), raw, None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, raw, str(exc)


def load_schema() -> dict[str, Any]:
    data = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("schema root is not an object")
    return data


def resolve_schema_ref(schema: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/$defs/"):
        raise ValueError(f"unsupported schema reference: {ref}")
    value = schema
    for part in ref[len("#/") :].split("/"):
        value = value[part]
    if not isinstance(value, dict):
        raise ValueError(f"schema reference is not an object: {ref}")
    return value


def schema_errors(value: Any, rule: dict[str, Any], schema: dict[str, Any], path: str = "$") -> list[tuple[str, str]]:
    if "$ref" in rule:
        return schema_errors(value, resolve_schema_ref(schema, str(rule["$ref"])), schema, path)

    errors: list[tuple[str, str]] = []
    expected_type = rule.get("type")
    if expected_type == "object":
        if not isinstance(value, dict):
            return [(path, "must be an object")]
        required = rule.get("required", [])
        for key in required:
            if key not in value:
                errors.append((f"{path}.{key}", "is required"))
        properties = rule.get("properties", {})
        if rule.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    errors.append((f"{path}.{key}", "is not an allowed property"))
        for key, child_rule in properties.items():
            if key in value:
                errors.extend(schema_errors(value[key], child_rule, schema, f"{path}.{key}"))
    elif expected_type == "array":
        if not isinstance(value, list):
            return [(path, "must be an array")]
        minimum = rule.get("minItems")
        if minimum is not None and len(value) < int(minimum):
            errors.append((path, f"must contain at least {minimum} item(s)"))
        child_rule = rule.get("items")
        if isinstance(child_rule, dict):
            for index, child in enumerate(value):
                errors.extend(schema_errors(child, child_rule, schema, f"{path}[{index}]"))
    elif expected_type == "string":
        if not isinstance(value, str):
            return [(path, "must be a string")]
        if "minLength" in rule and len(value) < int(rule["minLength"]):
            errors.append((path, "must not be empty"))
        if "const" in rule and value != rule["const"]:
            errors.append((path, f"must equal {rule['const']!r}"))
        if "enum" in rule and value not in rule["enum"]:
            errors.append((path, "has an unsupported value"))
        if "pattern" in rule and re.fullmatch(str(rule["pattern"]), value) is None:
            errors.append((path, "has an invalid format"))
    elif expected_type == "integer":
        if type(value) is not int:
            return [(path, "must be an integer")]
        if "const" in rule and value != rule["const"]:
            errors.append((path, f"must equal {rule['const']!r}"))
        if "minimum" in rule and value < int(rule["minimum"]):
            errors.append((path, "is smaller than the allowed minimum"))
    elif expected_type is not None:
        return [(path, f"has unsupported schema type {expected_type!r}")]

    any_of = rule.get("anyOf")
    if isinstance(any_of, list):
        branch_ok = False
        for branch in any_of:
            if not schema_errors(value, branch, schema, path):
                branch_ok = True
                break
        if not branch_ok:
            errors.append((path, "does not satisfy the required structured route shape"))
    all_of = rule.get("allOf")
    if isinstance(all_of, list):
        for branch in all_of:
            errors.extend(schema_errors(value, branch, schema, path))
    return errors


def scan_non_authority(value: Any, ctx: ValidationContext, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            child_path = f"{path}.{key_text}"
            if lowered in FORBIDDEN_PERMISSION_FIELDS:
                ctx.add(
                    "FORBIDDEN_PERMISSION",
                    child_path,
                    "Recon material must not define a downstream authority field.",
                    "Remove the permission field; record only Recon observations and coverage.",
                )
            if lowered in CANDIDATE_FIELDS:
                ctx.add(
                    "CANDIDATE_MATERIAL",
                    child_path,
                    "Recon output must not contain candidate objects or candidate ID fields.",
                    "Keep candidate generation as a later consumer that references stable Recon focus IDs.",
                )
            scan_non_authority(child, ctx, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            if isinstance(child, str) and re.fullmatch(r"CAND-[0-9A-Za-z._-]+", child):
                ctx.add(
                    "CANDIDATE_MATERIAL",
                    f"{path}[{index}]",
                    "A candidate ID is not a valid Recon reference.",
                    "Use a FOCUS-* or DEFER-* Recon reference instead.",
                )
            scan_non_authority(child, ctx, f"{path}[{index}]")
    elif isinstance(value, str) and re.fullmatch(r"CAND-[0-9A-Za-z._-]+", value):
        ctx.add(
            "CANDIDATE_MATERIAL",
            path,
            "A candidate ID is not a valid Recon value.",
            "Do not create or embed candidate IDs in Recon output.",
        )


def digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def import_target_validator() -> Any:
    spec = importlib.util.spec_from_file_location("zhulong_target_contract_shared", TARGET_VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load target contract validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_target_binding(data: dict[str, Any], ctx: ValidationContext) -> None:
    binding = data.get("target_binding")
    if not isinstance(binding, dict):
        return
    target_path = ctx.relative_file(
        ctx.workspace_dir,
        binding.get("target_contract_path"),
        "$.target_binding.target_contract_path",
        root_label="workspace",
    )
    if target_path is None:
        return
    try:
        target_raw = target_path.read_bytes()
    except OSError:
        return
    expected_digest = binding.get("target_contract_sha256")
    actual_digest = digest_bytes(target_raw)
    if expected_digest != actual_digest:
        ctx.add(
            "DIGEST_MISMATCH_TARGET_CONTRACT",
            "$.target_binding.target_contract_sha256",
            "The target contract digest does not match the referenced file.",
            "Recompute the exact UTF-8 file digest and regenerate the binding.",
        )

    try:
        validator = import_target_validator()
        contract = validator.load_contract(target_path)
        validator.validate_target(contract)
    except SystemExit:
        ctx.add(
            "TARGET_CONTRACT_INVALID",
            "$.target_binding.target_contract_path",
            "The bound target contract is not accepted by validate_target_contract.py.",
            "Fix the target contract and rerun its existing validator.",
        )
        return
    except Exception:
        ctx.add(
            "TARGET_CONTRACT_INVALID",
            "$.target_binding.target_contract_path",
            "The bound target contract could not be validated by the shared target validator.",
            "Fix the target contract and rerun its existing validator.",
        )
        return

    target = contract.get("target") if isinstance(contract, dict) else None
    tested_ref = target.get("tested_ref") if isinstance(target, dict) else None
    if isinstance(tested_ref, str) and tested_ref != binding.get("tested_ref"):
        ctx.add(
            "TESTED_REF_MISMATCH",
            "$.target_binding.tested_ref",
            "The Recon tested_ref is not exactly equal to target.target.tested_ref.",
            "Regenerate Recon material from the same checked-out tested ref.",
        )


def validate_attack_surface_binding(data: dict[str, Any], ctx: ValidationContext) -> None:
    binding = data.get("attack_surface_binding")
    if not isinstance(binding, dict):
        return
    path_value = binding.get("path")
    if path_value != "attack-surface.md":
        ctx.add(
            "PATH_UNSAFE",
            "$.attack_surface_binding.path",
            "The attack-surface binding must use the workspace-root attack-surface.md path.",
            "Use the canonical workspace-relative path attack-surface.md.",
        )
        return
    surface_path = ctx.relative_file(
        ctx.workspace_dir,
        path_value,
        "$.attack_surface_binding.path",
        root_label="workspace",
    )
    if surface_path is None:
        return
    try:
        actual_digest = digest_bytes(surface_path.read_bytes())
    except OSError:
        return
    if binding.get("sha256") != actual_digest:
        ctx.add(
            "DIGEST_MISMATCH_ATTACK_SURFACE",
            "$.attack_surface_binding.sha256",
            "The attack-surface digest does not match the referenced file.",
            "Recompute the exact attack-surface.md digest and regenerate the binding.",
        )


def register_entities(data: dict[str, Any], ctx: ValidationContext) -> None:
    for category, expected_prefix in ENTITY_CATEGORIES.items():
        entries = data.get(category)
        if not isinstance(entries, list):
            continue
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            item_id = entry.get("id")
            if not isinstance(item_id, str):
                continue
            if not item_id.startswith(expected_prefix):
                ctx.add(
                    "SCHEMA_INVALID",
                    f"$.{category}[{index}].id",
                    "The stable ID prefix does not match its Recon category.",
                    f"Use an ID beginning with {expected_prefix}.",
                )
            if item_id in ctx.known_ids:
                ctx.add(
                    "DUPLICATE_ID",
                    f"$.{category}[{index}].id",
                    "The stable Recon ID is duplicated.",
                    "Assign a unique stable ID to every repeated Recon entity.",
                )
            else:
                ctx.known_ids[item_id] = f"$.{category}[{index}]"


def validate_entity_references(data: dict[str, Any], ctx: ValidationContext) -> None:
    for category in ENTITY_CATEGORIES:
        entries = data.get(category)
        if not isinstance(entries, list):
            continue
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            item_path = f"$.{category}[{index}]"
            ctx.source_refs(entry.get("source_refs"), f"{item_path}.source_refs")
            ctx.evidence_refs(entry.get("evidence_refs"), f"{item_path}.evidence_refs")

    for category in COVERAGE_CATEGORIES:
        record = data.get("coverage", {}).get(category) if isinstance(data.get("coverage"), dict) else None
        if isinstance(record, dict):
            ctx.basis(record.get("basis"), f"$.coverage.{category}.basis")

    gaps = data.get("coverage_gaps")
    if isinstance(gaps, list):
        for index, gap in enumerate(gaps):
            if isinstance(gap, dict):
                ctx.basis(gap.get("basis"), f"$.coverage_gaps[{index}].basis")
    blockers = data.get("unresolved_blockers")
    if isinstance(blockers, list):
        for index, blocker in enumerate(blockers):
            if isinstance(blocker, dict):
                ctx.basis(blocker.get("basis"), f"$.unresolved_blockers[{index}].basis")


def check_references(value: Any, ctx: ValidationContext, path: str) -> None:
    if not isinstance(value, list):
        return
    for index, item in enumerate(value):
        if not isinstance(item, str):
            continue
        if item not in ctx.known_ids:
            ctx.add(
                "DANGLING_REFERENCE",
                f"{path}[{index}]",
                "The stable Recon reference does not identify an entity in this result.",
                "Use an existing Recon ID or add the referenced structured entity.",
            )


def validate_cross_references(data: dict[str, Any], ctx: ValidationContext) -> None:
    focus_refs = data.get("focus_refs")
    if isinstance(focus_refs, list):
        for index, item in enumerate(focus_refs):
            if isinstance(item, str) and not (item.startswith("FOCUS-") or item.startswith("DEFER-")):
                ctx.add(
                    "DANGLING_REFERENCE",
                    f"$.focus_refs[{index}]",
                    "focus_refs may contain only FOCUS-* or DEFER-* Recon IDs.",
                    "Reference a stable priority or deferred area ID.",
                )
        check_references(focus_refs, ctx, "$.focus_refs")

    coverage = data.get("coverage")
    if isinstance(coverage, dict):
        for category in COVERAGE_CATEGORIES:
            record = coverage.get(category)
            if isinstance(record, dict):
                item_ids = record.get("item_ids")
                item_path = f"$.coverage.{category}.item_ids"
                check_references(item_ids, ctx, item_path)
                if isinstance(item_ids, list):
                    expected_prefix = ENTITY_CATEGORIES[category]
                    for index, item in enumerate(item_ids):
                        if isinstance(item, str) and not item.startswith(expected_prefix):
                            ctx.add(
                                "STATUS_SEMANTICS_INVALID",
                                f"{item_path}[{index}]",
                                "A coverage category may reference only entities from that Recon category.",
                                f"Use a stable {expected_prefix} ID from the {category} entity collection.",
                            )

    for collection_name in ("coverage_gaps", "unresolved_blockers"):
        collection = data.get(collection_name)
        if not isinstance(collection, list):
            continue
        for index, item in enumerate(collection):
            if isinstance(item, dict):
                check_references(
                    item.get("affected_coverage_ids"),
                    ctx,
                    f"$.{collection_name}[{index}].affected_coverage_ids",
                )


def validate_coverage_records(data: dict[str, Any], ctx: ValidationContext) -> None:
    coverage = data.get("coverage")
    if not isinstance(coverage, dict):
        return
    for category in COVERAGE_CATEGORIES:
        record = coverage.get(category)
        if not isinstance(record, dict):
            continue
        status = record.get("status")
        item_ids = record.get("item_ids")
        reason = record.get("reason")
        if status == "covered" and isinstance(item_ids, list) and not item_ids:
            ctx.add(
                "COVERAGE_TOO_THIN",
                f"$.coverage.{category}",
                "A covered category must name at least one structured Recon entity.",
                "Add structured coverage items or mark the category not_applicable with evidence-backed reason.",
            )
        if status == "not_applicable":
            if isinstance(item_ids, list) and item_ids:
                ctx.add(
                    "STATUS_SEMANTICS_INVALID",
                    f"$.coverage.{category}.item_ids",
                    "A not_applicable category cannot list covered entity IDs.",
                    "Use an empty item_ids list and an evidence-backed reason.",
                )
            if not isinstance(reason, str) or not reason.strip():
                ctx.add(
                    "NOT_APPLICABLE_UNJUSTIFIED",
                    f"$.coverage.{category}.reason",
                    "not_applicable requires a concrete reason.",
                    "Explain why this category is genuinely outside the target's Recon surface.",
                )
            basis = record.get("basis")
            if (
                not isinstance(basis, dict)
                or not isinstance(basis.get("source_refs"), list)
                or not basis.get("source_refs")
                or not isinstance(basis.get("evidence_refs"), list)
                or not basis.get("evidence_refs")
            ):
                ctx.add(
                    "NOT_APPLICABLE_UNJUSTIFIED",
                    f"$.coverage.{category}.basis",
                    "not_applicable requires non-empty source and workspace evidence references.",
                    "Provide evidence for the real not-applicable boundary; do not use an empty placeholder.",
                )
        if status == "covered" and isinstance(reason, str) and NO_COVERAGE_EVIDENCE_RE.fullmatch(reason.strip()):
            ctx.add(
                "COVERAGE_TOO_THIN",
                f"$.coverage.{category}.reason",
                "An absence claim is not coverage evidence.",
                "Record the structured surface examined and its source/evidence references.",
            )


def validate_gap_and_blocker_fields(data: dict[str, Any], ctx: ValidationContext) -> None:
    gaps = data.get("coverage_gaps")
    if isinstance(gaps, list):
        for index, gap in enumerate(gaps):
            if not isinstance(gap, dict):
                continue
            path = f"$.coverage_gaps[{index}]"
            code = gap.get("code")
            if not isinstance(code, str) or STABLE_CODE_RE.fullmatch(code) is None:
                ctx.add(
                    "STATUS_SEMANTICS_INVALID",
                    f"{path}.code",
                    "A coverage gap needs a stable uppercase reason code.",
                    "Use an uppercase stable code such as ENTRYPOINT_MAP_INCOMPLETE.",
                )
            action = gap.get("next_action")
            if not isinstance(action, dict) or not action.get("summary") or not action.get("completion_condition"):
                ctx.add(
                    "STATUS_SEMANTICS_INVALID",
                    f"{path}.next_action",
                    "Every coverage gap needs an executable next action and completion condition.",
                    "Add a structured ACTION-* next_action with an observable completion condition.",
                )

    blockers = data.get("unresolved_blockers")
    if isinstance(blockers, list):
        for index, blocker in enumerate(blockers):
            if not isinstance(blocker, dict):
                continue
            path = f"$.unresolved_blockers[{index}]"
            code = blocker.get("code")
            if not isinstance(code, str) or STABLE_CODE_RE.fullmatch(code) is None:
                ctx.add(
                    "STATUS_SEMANTICS_INVALID",
                    f"{path}.code",
                    "Every blocker needs a stable uppercase reason code.",
                    "Use an uppercase stable code such as RUNTIME_IMAGE_MISSING.",
                )
            if not blocker.get("recovery_condition"):
                ctx.add(
                    "STATUS_SEMANTICS_INVALID",
                    f"{path}.recovery_condition",
                    "Every blocker needs a concrete recovery condition.",
                    "State the fact that must become true before Recon can resume.",
                )
            action = blocker.get("resume_action")
            if not isinstance(action, dict) or not action.get("summary") or not action.get("completion_condition"):
                ctx.add(
                    "STATUS_SEMANTICS_INVALID",
                    f"{path}.resume_action",
                    "Every blocker needs a structured resume action and completion condition.",
                    "Add an ACTION-* resume_action with an observable completion condition.",
                )


def validate_status_semantics(data: dict[str, Any], ctx: ValidationContext) -> None:
    status = data.get("status")
    coverage = data.get("coverage")
    gaps = data.get("coverage_gaps")
    blockers = data.get("unresolved_blockers")
    focus_refs = data.get("focus_refs")
    if not isinstance(coverage, dict) or not isinstance(gaps, list) or not isinstance(blockers, list):
        return

    unknown_categories = [
        category
        for category in COVERAGE_CATEGORIES
        if isinstance(coverage.get(category), dict) and coverage[category].get("status") == "unknown"
    ]
    if status == "complete":
        if gaps or blockers:
            ctx.add(
                "STATUS_SEMANTICS_INVALID",
                "$.status",
                "complete cannot coexist with a coverage gap or unresolved blocker.",
                "Use partial or blocked until the gap/blocker is resolved.",
            )
        if unknown_categories:
            ctx.add(
                "STATUS_SEMANTICS_INVALID",
                "$.coverage",
                "complete cannot leave a required coverage category unknown.",
                "Cover the category or use evidence-backed not_applicable.",
            )
        if not isinstance(focus_refs, list) or not focus_refs:
            ctx.add(
                "COVERAGE_TOO_THIN",
                "$.focus_refs",
                "complete needs at least one stable Recon focus reference.",
                "Add a FOCUS-* or DEFER-* reference for downstream review planning.",
            )
        for category in COVERAGE_CATEGORIES:
            record = coverage.get(category)
            if isinstance(record, dict) and record.get("status") not in {"covered", "not_applicable"}:
                ctx.add(
                    "STATUS_SEMANTICS_INVALID",
                    f"$.coverage.{category}.status",
                    "complete requires covered or evidence-backed not_applicable status.",
                    "Resolve the category before declaring the Recon coverage contract complete.",
                )
        if not data.get("priority_areas") or not data.get("deferred_areas"):
            ctx.add(
                "COVERAGE_TOO_THIN",
                "$.priority_areas",
                "complete needs explicit priority and deferred review ranges.",
                "Record at least one prioritized area and one deferred area with reasons.",
            )
    elif status == "partial":
        if not gaps and not blockers:
            ctx.add(
                "STATUS_SEMANTICS_INVALID",
                "$.status",
                "partial requires at least one structured coverage gap or blocker.",
                "Add a gap/blocker with affected coverage, evidence, and a next action.",
            )
        if not unknown_categories and not gaps and not blockers:
            ctx.add(
                "STATUS_SEMANTICS_INVALID",
                "$.coverage",
                "partial must separate unfinished coverage from completed coverage.",
                "Mark unfinished categories unknown and record the corresponding gap.",
            )
    elif status == "blocked":
        if not blockers:
            ctx.add(
                "STATUS_SEMANTICS_INVALID",
                "$.unresolved_blockers",
                "blocked requires at least one substantive blocker.",
                "Record a blocker with code, affected coverage, evidence, recovery condition, and resume action.",
            )
    else:
        ctx.add(
            "SCHEMA_INVALID",
            "$.status",
            "status must be complete, partial, or blocked.",
            "Use one of the three Recon coverage statuses.",
        )


def validate_recon(data: Any, repo_root: Path, workspace_dir: Path) -> list[Issue]:
    ctx = ValidationContext(repo_root, workspace_dir)
    try:
        schema = load_schema()
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        ctx.add(
            "SCHEMA_INVALID",
            "$schema",
            "The installed Recon result schema could not be loaded.",
            "Restore assets/schemas/recon-result.schema.json before validation.",
        )
        return ctx.issues

    if isinstance(data, dict):
        scan_non_authority(data, ctx)
    errors = schema_errors(data, schema, schema, "$")
    for path, message in errors:
        ctx.add(
            "SCHEMA_INVALID",
            path,
            message,
            "Make the Recon result match recon-result.schema.json and remove unknown fields.",
        )
    if not isinstance(data, dict):
        return ctx.issues

    if data.get("schema_version") != SCHEMA_VERSION:
        ctx.add(
            "SCHEMA_INVALID",
            "$.schema_version",
            "schema_version must be 1.",
            "Regenerate the result with the current Recon result schema.",
        )
    recon_id = data.get("recon_id")
    if isinstance(recon_id, str) and RECON_ID_RE.fullmatch(recon_id) is None:
        ctx.add(
            "SCHEMA_INVALID",
            "$.recon_id",
            "recon_id must be a stable RECON-* identifier.",
            "Use a stable identifier beginning with RECON-.",
        )

    validate_target_binding(data, ctx)
    validate_attack_surface_binding(data, ctx)
    register_entities(data, ctx)
    validate_entity_references(data, ctx)
    validate_cross_references(data, ctx)
    validate_coverage_records(data, ctx)
    validate_gap_and_blocker_fields(data, ctx)
    validate_status_semantics(data, ctx)
    return ctx.issues


def resolve_root_argument(raw: str, label: str) -> tuple[Path | None, Issue | None]:
    try:
        path = Path(raw).expanduser().resolve()
    except (OSError, RuntimeError):
        return None, Issue(
            "PATH_UNSAFE",
            f"<{label}>",
            f"The supplied {label} could not be resolved safely.",
            f"Provide an existing {label} directory.",
        )
    if not path.exists() or not path.is_dir():
        return None, Issue(
            "FILE_MISSING",
            f"<{label}>",
            f"The supplied {label} directory does not exist.",
            f"Provide an existing {label} directory.",
        )
    return path, None


def resolve_result_path(raw: str, workspace_dir: Path) -> tuple[Path | None, Issue | None]:
    try:
        path = Path(raw).expanduser()
        resolved = path.resolve(strict=False)
        resolved.relative_to(workspace_dir.resolve())
    except (OSError, RuntimeError):
        return None, Issue(
            "PATH_UNSAFE",
            "<recon-result>",
            "The Recon result path could not be resolved safely inside the workspace.",
            "Place recon-result.json inside the supplied audit workspace.",
        )
    except ValueError:
        try:
            if Path(raw).expanduser().is_symlink():
                return None, Issue(
                    "SYMLINK_ESCAPE",
                    "<recon-result>",
                    "The Recon result symlink resolves outside the supplied audit workspace.",
                    "Use a regular recon-result.json file inside the audit workspace.",
                )
        except OSError:
            pass
        return None, Issue(
            "PATH_UNSAFE",
            "<recon-result>",
            "The Recon result path is outside the supplied audit workspace.",
            "Place recon-result.json inside the supplied audit workspace.",
        )
    if not path.exists() or not path.is_file():
        return None, Issue(
            "FILE_MISSING",
            "<recon-result>",
            "The Recon result file does not exist.",
            "Provide an existing recon-result.json inside the audit workspace.",
        )
    return path, None


def make_output(data: Any, issues: list[Issue]) -> dict[str, Any]:
    status = data.get("status") if isinstance(data, dict) and isinstance(data.get("status"), str) else None
    recon_id = data.get("recon_id") if isinstance(data, dict) and isinstance(data.get("recon_id"), str) else None
    codes: list[str] = []
    for issue in issues:
        if issue.code not in codes:
            codes.append(issue.code)
    ok = not issues
    if ok and status == "complete":
        message = (
            "Recon coverage contract complete and valid; "
            "this does not prove a vulnerability or end the Recon stage."
        )
    elif ok:
        message = (
            f"Recon coverage contract valid for status={status}; "
            "this does not prove a vulnerability or end the Recon stage."
        )
    else:
        message = "Recon coverage contract rejected; fix the listed issues before using its stable focus references."
    return {
        "ok": ok,
        "result": "recon_coverage_contract_valid" if ok else "recon_coverage_contract_invalid",
        "authority": "recon_coverage_only",
        "recon_id": recon_id,
        "status": status,
        "issue_codes": codes,
        "issues": [issue.as_dict() for issue in issues],
        "message": message,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline, read-only validation for a Zhulong Recon coverage result."
    )
    parser.add_argument("--repo-root", required=True, help="Checked-out target repository root.")
    parser.add_argument("--workspace-dir", required=True, help="Audit workspace containing the bound materials.")
    parser.add_argument("--recon-result", required=True, help="Workspace-local recon-result.json path.")
    parser.add_argument("--json", action="store_true", help="Emit stable machine-readable JSON.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    issues: list[Issue] = []
    repo_root, repo_issue = resolve_root_argument(args.repo_root, "repo-root")
    workspace_dir, workspace_issue = resolve_root_argument(args.workspace_dir, "workspace-dir")
    if repo_issue:
        issues.append(repo_issue)
    if workspace_issue:
        issues.append(workspace_issue)
    if repo_root is None or workspace_dir is None:
        output = make_output(None, issues)
        if args.json:
            print(json.dumps(output, ensure_ascii=False, indent=2))
        else:
            for issue in issues:
                print(f"ERROR [{issue.code}] {issue.message} ({issue.path})", file=sys.stderr)
        raise SystemExit(1)

    recon_path, recon_issue = resolve_result_path(args.recon_result, workspace_dir)
    if recon_issue:
        issues.append(recon_issue)
        output = make_output(None, issues)
        if args.json:
            print(json.dumps(output, ensure_ascii=False, indent=2))
        else:
            print(f"ERROR [{recon_issue.code}] {recon_issue.message} ({recon_issue.path})", file=sys.stderr)
        raise SystemExit(1)
    assert recon_path is not None

    data, _raw, load_error = load_json(recon_path)
    if load_error is not None:
        issues.append(
            Issue(
                "RECON_RESULT_JSON_INVALID",
                "<recon-result>",
                "The Recon result is not valid UTF-8 JSON.",
                "Write a UTF-8 JSON object and rerun the validator.",
            )
        )
    else:
        issues.extend(validate_recon(data, repo_root, workspace_dir))

    output = make_output(data, issues)
    if args.json:
        print(json.dumps(output, ensure_ascii=False, indent=2))
    elif issues:
        for issue in issues:
            print(f"ERROR [{issue.code}] {issue.message} ({issue.path})", file=sys.stderr)
    else:
        status = data.get("status") if isinstance(data, dict) else "unknown"
        prefix = "OK: Recon coverage contract complete; " if status == "complete" else "OK: Recon coverage contract valid; "
        print(
            prefix +
            f"status={status}; authority=recon-coverage-only; "
            "no finding, verdict, bundle, or stage-finalization authority."
        )
    raise SystemExit(0 if not issues else 1)


if __name__ == "__main__":
    main()
