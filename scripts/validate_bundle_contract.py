#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - exercised as a fail-closed runtime error
    yaml = None


PATH_KEYS = {
    "path",
    "final_path",
    "verification_evidence",
    "reviewer_evidence_index",
    "source_path",
    "source_findings_json",
    "evidence_path",
    "target_config",
    "verifier_verdict",
}
DIRECT_IMPACT_REQUIRED_TARGETS = {
    "replay.root_script",
    "replay.log",
    "files.verification_evidence",
    "files.reviewer_evidence_index",
    "reviewer_material",
}
FIXTURE_REPLAY_TYPES = {"minimal_fixture", "vendored_source", "fixture", "local_fixture"}
SSRF_STRONG_TIERS = {
    "response_content_exposure",
    "configuration_exposure",
    "credential_exposure",
    "sensitive_data_exposure",
}
SSRF_CALLBACK_TIER = "callback_reachability"
SEVERITY_LABELS = {"Critical", "High", "Medium", "Low", "Informational"}
ENTRYPOINT_BUNDLE_READY_LEVELS = {"entrypoint_reproduced", "confirmed_in_docker"}
SOURCE_REFERENCE_ROLES = {"entrypoint", "sink", "missing_guard", "prerequisite", "security_property"}
IMPACT_CATEGORIES = {
    "unauthorized_read",
    "unauthorized_write",
    "auth_bypass",
    "code_execution",
    "sensitive_data_exposure",
    "availability_impact",
    "network_reachability",
    "privilege_escalation",
    "security_boundary_bypass",
    "other_bounded_impact",
}
VALIDITY_VERDICTS = {"confirmed", "conditionally_confirmed", "not_valid", "withdrawn"}
PROMOTABLE_VALIDITY_VERDICTS = {"confirmed", "conditionally_confirmed"}
CLASSIFICATION_DECISIONS = {"unchanged", "downgraded", "reclassified"}
SEVERITY_ORDER = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
CVSS_SEVERITY_RANGES = {
    "Informational": (0.0, 0.0),
    "Low": (0.1, 3.9),
    "Medium": (4.0, 6.9),
    "High": (7.0, 8.9),
    "Critical": (9.0, 10.0),
}

ABSOLUTE_POSIX_RE = re.compile(r"^/")
ABSOLUTE_WINDOWS_RE = re.compile(r"^[A-Za-z]:[\\/]")
OPERATOR_LOCAL_RE = re.compile(
    r"(^|[\s:=,'\"])(?:/Users/[^/\s]+|/home/[^/\s]+|[A-Za-z]:[\\/][^\s`'\"<>]*)",
    re.IGNORECASE,
)
FILE_URL_RE = re.compile(r"file://", re.IGNORECASE)
STALE_WORKFLOW_NAME = "autonomous-security" + "-researcher"
PARENT_WORKSPACE_NAME = "oss-vulnerability" + "-research"
PARENT_CHECKOUT_RE = re.compile(
    r"\b(?:submitter-workspace|parent-audit-workspace|external-source-checkout|"
    + re.escape(PARENT_WORKSPACE_NAME)
    + r"|"
    + re.escape(STALE_WORKFLOW_NAME)
    + r")\b",
    re.IGNORECASE,
)
PATH_TRAVERSAL_RE = re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)")


@dataclass
class Issue:
    code: str
    severity: str
    path: str
    message: str
    fix: str

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity,
            "path": self.path,
            "message": self.message,
            "fix": self.fix,
        }


class IssueCollector:
    def __init__(self, *, all_errors: bool) -> None:
        self.all_errors = all_errors
        self.issues: list[Issue] = []

    def add(self, code: str, path: str, message: str, fix: str, *, severity: str = "error") -> None:
        self.issues.append(Issue(code=code, severity=severity, path=path, message=message, fix=fix))
        if not self.all_errors:
            raise StopValidation


class StopValidation(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a Zhulong bundle-contract.json preflight document.")
    parser.add_argument("--workspace-dir", required=True, help="Audit workspace directory containing confirmed/.")
    parser.add_argument("--repo-root", required=True, help="Target repository root containing the audit workspace.")
    parser.add_argument("--contract", required=True, help="Path to the bundle-contract JSON file.")
    parser.add_argument("--all-errors", action="store_true", default=True, help="Collect all issues. This is the default.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser.parse_args()


def load_json(path: Path, issues: IssueCollector) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        issues.add("CONTRACT_NOT_FOUND", "$", f"Contract file not found: {path}", "Create the bundle contract before preflight.")
        return {}
    except json.JSONDecodeError as exc:
        issues.add("CONTRACT_JSON_INVALID", "$", f"Invalid JSON: {exc}", "Fix JSON syntax before running preflight.")
        return {}
    if not isinstance(data, dict):
        issues.add("CONTRACT_SHAPE_INVALID", "$", "Bundle contract root must be a JSON object.", "Use the bundle contract template.")
        return {}
    return data


def as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def path_has_escape(value: str, *, path_field: bool) -> bool:
    if not value.strip():
        return False
    normalized = value.replace("\\", "/")
    if value.startswith("~") or FILE_URL_RE.search(value):
        return True
    if OPERATOR_LOCAL_RE.search(value) or PARENT_CHECKOUT_RE.search(value):
        return True
    if PATH_TRAVERSAL_RE.search(normalized) or any(part == ".." for part in normalized.split("/")):
        return True
    if path_field and (ABSOLUTE_POSIX_RE.match(value) or ABSOLUTE_WINDOWS_RE.match(value)):
        return True
    return False


def walk_portability(value: Any, issues: IssueCollector, path: str = "$", key: str = "") -> None:
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            walk_portability(child_value, issues, f"{path}.{child_key}", str(child_key))
    elif isinstance(value, list):
        for index, child_value in enumerate(value):
            walk_portability(child_value, issues, f"{path}[{index}]", key)
    elif isinstance(value, str):
        lowered = key.lower()
        is_path_field = lowered in PATH_KEYS or lowered.endswith("_path") or lowered.endswith("_file")
        if path_has_escape(value, path_field=is_path_field):
            issues.add(
                "BUNDLE_PATH_ESCAPE",
                path,
                "Contract contains an absolute, local, file://, parent-checkout, or escaping path.",
                "Use bundle-relative, workspace-relative, or project-relative paths that stay portable.",
            )


def check_required_string(mapping: dict[str, Any], key: str, path: str, issues: IssueCollector, code: str = "CONTRACT_REQUIRED_FIELD_MISSING") -> str:
    value = mapping.get(key)
    if not nonempty_string(value):
        issues.add(code, f"{path}.{key}", "Required non-empty string is missing.", "Fill this field before bundle generation.")
        return ""
    return str(value).strip()


def check_required_bool(mapping: dict[str, Any], key: str, path: str, issues: IssueCollector, code: str = "CONTRACT_REQUIRED_FIELD_MISSING") -> bool | None:
    value = mapping.get(key)
    if type(value) is not bool:
        issues.add(code, f"{path}.{key}", "Required boolean is missing.", "Set this field explicitly to true or false.")
        return None
    return value


def check_repo_workspace_boundary(repo_root: Path, workspace_dir: Path, issues: IssueCollector) -> bool:
    if not repo_root.exists() or not repo_root.is_dir():
        issues.add(
            "SOURCE_REF_MISMATCH",
            "--repo-root",
            "Target repository root does not exist or is not a directory.",
            "Pass the real target repository root with --repo-root.",
        )
        return False
    try:
        workspace_dir.relative_to(repo_root)
    except ValueError:
        issues.add(
            "SOURCE_REF_MISMATCH",
            "--workspace-dir",
            "Audit workspace must resolve inside the target repository root.",
            "Use a workspace directory contained by the repository passed to --repo-root.",
        )
        return False
    if workspace_dir == repo_root:
        issues.add(
            "SOURCE_REF_MISMATCH",
            "--workspace-dir",
            "Audit workspace may not equal the target repository root.",
            "Use the existing layout where the audit workspace is a child of the target repository.",
        )
        return False
    return True


def resolve_bounded_path(base: Path, raw: Any, *, label: str, issues: IssueCollector, code: str) -> Path | None:
    value = str(raw or "").strip()
    if not value or path_has_escape(value, path_field=True):
        issues.add(code, label, "Path must be a non-empty relative path without traversal.", "Use a portable relative path inside the declared root.")
        return None
    candidate = (base / Path(value)).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError:
        issues.add(code, label, "Path resolves outside its declared root, including through a symlink.", "Remove traversal or escaping symlinks and bind a file inside the declared root.")
        return None
    return candidate


def load_structured_material(path: Path, label: str, issues: IssueCollector) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        issues.add("SOURCE_REF_MISMATCH", label, f"Required tested-ref material is unreadable: {exc}", "Provide the target contract/verifier verdict file used for this finding.")
        return {}
    try:
        data = json.loads(text) if path.suffix.lower() == ".json" else (yaml.safe_load(text) if yaml is not None else None)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        issues.add("SOURCE_REF_MISMATCH", label, f"Tested-ref material is invalid: {exc}", "Fix the JSON/YAML material before promotion.")
        return {}
    if not isinstance(data, dict):
        issues.add("SOURCE_REF_MISMATCH", label, "Tested-ref material must contain an object.", "Use a valid target contract or verifier verdict object.")
        return {}
    return data


def git_resolved_head(repo_root: Path, tested_ref: str, issues: IssueCollector) -> str:
    def git(*args: str) -> str:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or "git ref lookup failed").strip())
        return (proc.stdout or "").strip()

    try:
        head = git("rev-parse", "HEAD^{commit}")
        resolved = git("rev-parse", f"{tested_ref}^{{commit}}")
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        issues.add("SOURCE_REF_MISMATCH", "source_binding.tested_ref", f"Unable to verify tested ref against the target repository: {exc}", "Use a checked-out Git repository and a tested ref that resolves to its current HEAD commit.")
        return ""
    if head != resolved:
        issues.add("SOURCE_REF_MISMATCH", "source_binding.tested_ref", f"Tested ref resolves to {resolved}, but target repository HEAD is {head}.", "Check out the exact tested ref before contract preflight.")
        return ""
    return head


def git_blob_at_commit(
    repo_root: Path,
    commit: str,
    repo_relative_path: str,
    *,
    label: str,
    issues: IssueCollector,
) -> bytes | None:
    if not commit:
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "cat-file", "blob", f"{commit}:{repo_relative_path}"],
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        issues.add(
            "SOURCE_FILE_MISMATCH",
            label,
            f"Unable to read the source file from the tested Git commit: {exc}",
            "Reference a tracked source file that exists at the tested ref.",
        )
        return None
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or b"Git object lookup failed").decode("utf-8", errors="replace").strip()
        issues.add(
            "SOURCE_FILE_MISMATCH",
            label,
            f"Source file is not a readable blob at the tested Git commit: {detail}",
            "Reference a tracked source file that exists at the tested ref.",
        )
        return None
    return proc.stdout


def normalize_entrypoint(value: Any) -> str:
    text = re.sub(r"\s+", " ", str(value or "").strip())
    match = re.fullmatch(r"([A-Za-z]+)\s+(.+)", text)
    if not match:
        return text.rstrip("/") or "/"
    method, target = match.groups()
    if target.startswith("/"):
        target = re.sub(r"/{2,}", "/", target)
        if len(target) > 1:
            target = target.rstrip("/")
    return f"{method.upper()} {target}"


def snippet_bytes(path: Path, start_line: int, end_line: int) -> tuple[bytes, str] | None:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    lines = text.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        return None
    snippet = "".join(lines[start_line - 1:end_line])
    return snippet.encode("utf-8"), snippet


def check_source_binding(
    contract: dict[str, Any],
    workspace_dir: Path,
    repo_root: Path,
    issues: IssueCollector,
) -> dict[str, dict[str, Any]]:
    binding = as_mapping(contract.get("source_binding"))
    if not binding:
        issues.add("SOURCE_BINDING_MISSING", "source_binding", "A source-bound contract is required before promotion.", "Add tested ref, entrypoint binding, source references, and tested material paths.")
        return {}
    tested_ref = check_required_string(binding, "tested_ref", "source_binding", issues, "SOURCE_REF_MISMATCH")
    attacker = check_required_string(binding, "attacker_entrypoint", "source_binding", issues, "SOURCE_ENTRYPOINT_MISMATCH")
    replay = check_required_string(binding, "replay_observed_entrypoint", "source_binding", issues, "SOURCE_ENTRYPOINT_MISMATCH")
    mode = str(binding.get("binding_mode") or "").strip()
    if mode not in {"exact", "composed"}:
        issues.add("SOURCE_ENTRYPOINT_MISMATCH", "source_binding.binding_mode", "binding_mode must be exact or composed.", "Use composed only when every static component can be source-bound.")
    if attacker and replay and normalize_entrypoint(attacker) != normalize_entrypoint(replay):
        issues.add("SOURCE_ENTRYPOINT_MISMATCH", "source_binding.replay_observed_entrypoint", "Replay observed entrypoint does not equal the contract attacker entrypoint after normalization.", "Bind the replay to the same real attacker-controlled entrypoint.")
    entrypoint_evidence = as_mapping(contract.get("entrypoint_evidence"))
    evidence_entrypoint = str(entrypoint_evidence.get("attacker_controlled_entrypoint") or "").strip()
    if attacker and normalize_entrypoint(attacker) != normalize_entrypoint(evidence_entrypoint):
        issues.add("SOURCE_ENTRYPOINT_MISMATCH", "entrypoint_evidence.attacker_controlled_entrypoint", "Entrypoint evidence does not match source_binding.attacker_entrypoint.", "Use one normalized attacker entrypoint across source binding and Docker evidence.")

    resolved_head = git_resolved_head(repo_root, tested_ref, issues) if tested_ref else ""
    materials = as_mapping(binding.get("materials"))
    target_path = resolve_bounded_path(workspace_dir, materials.get("target_config"), label="source_binding.materials.target_config", issues=issues, code="SOURCE_REF_MISMATCH")
    verdict_path = resolve_bounded_path(workspace_dir, materials.get("verifier_verdict"), label="source_binding.materials.verifier_verdict", issues=issues, code="SOURCE_REF_MISMATCH")
    target_doc = load_structured_material(target_path, "source_binding.materials.target_config", issues) if target_path and target_path.is_file() else {}
    verdict_doc = load_structured_material(verdict_path, "source_binding.materials.verifier_verdict", issues) if verdict_path and verdict_path.is_file() else {}
    target_tested_ref = str(as_mapping(target_doc.get("target")).get("tested_ref") or "").strip()
    verdict_tested_ref = str(as_mapping(verdict_doc.get("target_ref")).get("tested_ref") or "").strip()
    if tested_ref and (target_tested_ref != tested_ref or verdict_tested_ref != tested_ref):
        issues.add("SOURCE_REF_MISMATCH", "source_binding.materials", "source_binding, target contract, and verifier verdict tested refs are not identical.", "Regenerate all materials for the same tested ref.")
    verdict_entrypoint = str(as_mapping(verdict_doc.get("attacker_entrypoint")).get("route") or "").strip()
    if attacker and normalize_entrypoint(verdict_entrypoint) != normalize_entrypoint(attacker):
        issues.add("SOURCE_ENTRYPOINT_MISMATCH", "source_binding.materials.verifier_verdict", "Verifier attacker entrypoint does not match the source-bound attacker entrypoint.", "Use verifier material from the same entrypoint replay.")
    target_entrypoint_id = str(binding.get("target_entrypoint_id") or "").strip()
    target_entries = as_list(as_mapping(target_doc.get("scope")).get("entrypoints"))
    target_matches = [item for item in target_entries if isinstance(item, dict) and str(item.get("id") or "").strip() == target_entrypoint_id]
    if len(target_matches) != 1 or normalize_entrypoint(target_matches[0].get("route") if target_matches else "") != normalize_entrypoint(attacker):
        issues.add("SOURCE_ENTRYPOINT_MISMATCH", "source_binding.target_entrypoint_id", "Target contract does not contain exactly one matching entrypoint id and normalized route.", "Bind target_entrypoint_id to the tested target scope entrypoint.")

    refs: dict[str, dict[str, Any]] = {}
    for index, raw_ref in enumerate(as_list(binding.get("source_references"))):
        path_label = f"source_binding.source_references[{index}]"
        ref = as_mapping(raw_ref)
        ref_id = check_required_string(ref, "id", path_label, issues, "SOURCE_REF_MISMATCH")
        if not ref_id or ref_id in refs:
            issues.add("SOURCE_REF_MISMATCH", f"{path_label}.id", "Source reference ids must be non-empty and unique.", "Assign one stable id per exact source reference.")
            continue
        role = str(ref.get("role") or "").strip()
        if role not in SOURCE_REFERENCE_ROLES:
            issues.add("SOURCE_REF_MISMATCH", f"{path_label}.role", "Unknown source reference role.", "Use entrypoint, sink, missing_guard, prerequisite, or security_property.")
        source_path = resolve_bounded_path(repo_root, ref.get("path"), label=f"{path_label}.path", issues=issues, code="SOURCE_FILE_MISMATCH")
        if source_path is None or not source_path.is_file():
            issues.add("SOURCE_FILE_MISMATCH", f"{path_label}.path", "Source reference file does not exist as a regular file inside repo root.", "Reference an existing repo-relative source file.")
            continue
        try:
            working_tree_bytes = source_path.read_bytes()
        except OSError as exc:
            issues.add("SOURCE_FILE_MISMATCH", f"{path_label}.path", f"Source file is unreadable: {exc}", "Use a readable tracked source file.")
            continue
        git_blob = git_blob_at_commit(
            repo_root,
            resolved_head,
            str(ref.get("path") or ""),
            label=f"{path_label}.path",
            issues=issues,
        )
        if git_blob is not None and git_blob != working_tree_bytes:
            issues.add(
                "SOURCE_FILE_MISMATCH",
                f"{path_label}.path",
                "Working-tree source differs from the exact source blob at the tested ref.",
                "Restore or check out the tested ref; do not bind uncommitted source changes.",
            )
        start_line = ref.get("start_line")
        end_line = ref.get("end_line")
        if type(start_line) is not int or type(end_line) is not int:
            issues.add("SOURCE_REF_MISMATCH", path_label, "Source reference needs integer start_line and end_line.", "Bind an exact, valid line range.")
            continue
        selected = snippet_bytes(source_path, start_line, end_line)
        if selected is None:
            issues.add("SOURCE_REF_MISMATCH", path_label, "Source reference line range is invalid or source is not UTF-8.", "Use a valid UTF-8 line range inside the referenced file.")
            continue
        snippet_raw, snippet = selected
        hash_kind = str(ref.get("hash_kind") or "").strip()
        actual_hash = hashlib.sha256(working_tree_bytes if hash_kind == "file" else snippet_raw).hexdigest()
        if hash_kind not in {"file", "snippet"} or str(ref.get("sha256") or "").lower() != actual_hash:
            issues.add("SOURCE_FILE_MISMATCH", f"{path_label}.sha256", "SHA-256 does not match the current tested source file or exact snippet.", "Recompute the declared hash from the checked-out tested source.")
        exact_token = str(ref.get("exact_token") or "")
        if not exact_token or exact_token not in snippet:
            issues.add("SOURCE_REF_MISMATCH", f"{path_label}.exact_token", "Exact source token is absent from the bound line range.", "Copy an exact token from the referenced tested source snippet.")
        refs[ref_id] = {**ref, "snippet": snippet, "resolved_path": source_path, "resolved_head": resolved_head}

    if not refs:
        issues.add("SOURCE_BINDING_MISSING", "source_binding.source_references", "At least one valid source reference is required.", "Bind entrypoint and sink/guard source snippets.")
    if not any(ref.get("role") == "entrypoint" for ref in refs.values()):
        issues.add("SOURCE_BINDING_MISSING", "source_binding.source_references", "No source reference binds the attacker entrypoint.", "Add an entrypoint source reference.")
    if not any(ref.get("role") in {"sink", "missing_guard"} for ref in refs.values()):
        issues.add("SOURCE_SINK_PATH_UNBOUND", "source_binding.source_references", "No source reference binds the sink or critical missing guard.", "Bind the source sink or missing guard used by the impact claim.")

    if mode == "exact":
        defined = str(binding.get("source_defined_entrypoint") or "").strip()
        entry_refs = [ref for ref in refs.values() if ref.get("role") == "entrypoint"]
        if not defined or not any(defined in str(ref.get("exact_token") or "") for ref in entry_refs) or normalize_entrypoint(defined) != normalize_entrypoint(attacker):
            issues.add("SOURCE_ENTRYPOINT_MISMATCH", "source_binding.source_defined_entrypoint", "Exact source-defined entrypoint is not present in an entrypoint source token or does not match replay.", "Bind the exact static entrypoint value found in tested source.")
    elif mode == "composed":
        components = as_list(binding.get("components"))
        values: list[str] = []
        for index, raw_component in enumerate(components):
            component = as_mapping(raw_component)
            value = str(component.get("value") or "")
            ref_ids = [str(item) for item in as_list(component.get("source_reference_ids"))]
            if not value or not ref_ids or any(ref_id not in refs or value not in str(refs[ref_id].get("exact_token") or "") for ref_id in ref_ids):
                issues.add("SOURCE_REF_MISMATCH", f"source_binding.components[{index}]", "Each composed entrypoint component must occur in every bound exact source token.", "Bind every static component to one or more actual source snippets.")
            values.append(value)
        joiner = str(binding.get("component_joiner") or "")
        resolved = joiner.join(values)
        declared_resolved = str(binding.get("resolved_entrypoint") or "")
        if not components or resolved != declared_resolved or normalize_entrypoint(resolved) != normalize_entrypoint(attacker):
            issues.add("SOURCE_ENTRYPOINT_MISMATCH", "source_binding.resolved_entrypoint", "Composed source components do not resolve exactly to the attacker and replay entrypoint.", "Fix component order/joiner or keep the dynamic entrypoint blocked/conditional.")
    return refs


def check_fixture_security_boundary(contract: dict[str, Any], refs: dict[str, dict[str, Any]], issues: IssueCollector) -> None:
    provenance = as_mapping(contract.get("fixture_provenance"))
    properties = as_list(provenance.get("security_properties"))
    synthetic_present = provenance.get("synthetic_security_properties_present")
    if type(synthetic_present) is not bool or not isinstance(properties, list):
        issues.add("FIXTURE_SECURITY_BOUNDARY_MISSING", "fixture_provenance", "Fixture security-property judgment is missing.", "Record synthetic_security_properties_present and security_properties, including an empty list for full-app replay.")
        return
    property_ids: set[str] = set()
    actual_synthetic = False
    for index, raw_property in enumerate(properties):
        prop = as_mapping(raw_property)
        path = f"fixture_provenance.security_properties[{index}]"
        prop_id = check_required_string(prop, "id", path, issues, "FIXTURE_SECURITY_BOUNDARY_MISSING")
        check_required_string(prop, "meaning", path, issues, "FIXTURE_SECURITY_BOUNDARY_MISSING")
        origin = str(prop.get("origin") or "").strip()
        use = str(prop.get("use") or "").strip()
        if prop_id in property_ids:
            issues.add("FIXTURE_SECURITY_BOUNDARY_MISSING", f"{path}.id", "Security property ids must be unique.", "Use one stable property id per role/session/secret/object/config property.")
        property_ids.add(prop_id)
        if origin == "upstream_backed":
            source_ids = [str(item) for item in as_list(prop.get("source_reference_ids"))]
            if not source_ids or any(item not in refs for item in source_ids):
                issues.add("UPSTREAM_SECURITY_PROPERTY_UNBOUND", path, "Upstream-backed security property lacks valid source references.", "Bind the property to tested source/config references.")
        elif origin == "synthetic":
            actual_synthetic = True
            cannot_support = as_list(prop.get("cannot_support_impact_claim_ids"))
            if use != "oracle_only" or not check_nonempty_string_list(cannot_support):
                issues.add("SYNTHETIC_PROPERTY_SUPPORTS_IMPACT", path, "Synthetic properties may only serve a deterministic oracle and must list impacts they cannot support.", "Do not use fixture-created privilege, identity, session, secret, or sensitivity as real-world impact evidence.")
        else:
            issues.add("FIXTURE_SECURITY_BOUNDARY_MISSING", f"{path}.origin", "Security property origin must be upstream_backed or synthetic.", "Classify every fixture security property explicitly.")
    if bool(synthetic_present) != actual_synthetic:
        issues.add("FIXTURE_SECURITY_BOUNDARY_MISSING", "fixture_provenance.synthetic_security_properties_present", "Synthetic-property summary does not match the property list.", "Keep the explicit judgment synchronized with security_properties.")


def check_nonempty_string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(nonempty_string(item) for item in value)


def check_impact_and_validity(contract: dict[str, Any], refs: dict[str, dict[str, Any]], issues: IssueCollector) -> None:
    claims = as_list(contract.get("impact_claims"))
    prerequisites = as_list(contract.get("deployment_prerequisites"))
    review = as_mapping(contract.get("validity_review"))
    claim_map: dict[str, dict[str, Any]] = {}
    prerequisite_map: dict[str, dict[str, Any]] = {}
    properties = {
        str(item.get("id")): item
        for item in as_list(as_mapping(contract.get("fixture_provenance")).get("security_properties"))
        if isinstance(item, dict) and nonempty_string(item.get("id"))
    }
    docker = as_mapping(contract.get("docker_evidence"))
    entrypoint_evidence = as_mapping(contract.get("entrypoint_evidence"))
    direct = as_mapping(contract.get("direct_impact"))
    replay = as_mapping(contract.get("replay"))
    files = as_mapping(contract.get("files"))
    registered_evidence_paths = contract_file_values(files, "evidence_files")
    for value in (
        files.get("verification_evidence"),
        files.get("reviewer_evidence_index"),
        as_mapping(replay.get("log")).get("path"),
    ):
        if nonempty_string(value):
            registered_evidence_paths.add(str(value))
    for index, raw_prereq in enumerate(prerequisites):
        prereq = as_mapping(raw_prereq)
        path = f"deployment_prerequisites[{index}]"
        prereq_id = check_required_string(prereq, "id", path, issues, "DEPLOYMENT_PREREQUISITE_OMITTED")
        check_required_string(prereq, "description", path, issues, "DEPLOYMENT_PREREQUISITE_OMITTED")
        source_ids = [str(item) for item in as_list(prereq.get("source_reference_ids"))]
        if not prereq_id or prereq_id in prerequisite_map or not source_ids or any(item not in refs for item in source_ids) or prereq.get("reviewer_material_required") is not True:
            issues.add("DEPLOYMENT_PREREQUISITE_OMITTED", path, "Deployment prerequisite must be unique, source-bound, and reviewer-visible.", "Bind the prerequisite to tested source/config and set reviewer_material_required=true.")
        prerequisite_map[prereq_id] = prereq
    for index, raw_claim in enumerate(claims):
        claim = as_mapping(raw_claim)
        path = f"impact_claims[{index}]"
        claim_id = check_required_string(claim, "id", path, issues, "IMPACT_CLAIM_UNSUPPORTED")
        category = str(claim.get("category") or "").strip()
        if category not in IMPACT_CATEGORIES:
            issues.add("IMPACT_CLAIM_UNSUPPORTED", f"{path}.category", "Unknown impact claim category.", "Use a bounded generic impact category from the contract schema.")
        for field in ("statement", "severity_ceiling"):
            check_required_string(claim, field, path, issues, "IMPACT_CLAIM_UNSUPPORTED")
        ceiling = str(claim.get("severity_ceiling") or "")
        if ceiling not in SEVERITY_LABELS:
            issues.add("SEVERITY_EVIDENCE_MISMATCH", f"{path}.severity_ceiling", "Impact claim severity ceiling is invalid.", "Use a stable severity label.")
        supported_classes = as_list(claim.get("supported_bug_classes"))
        source_ids = [str(item) for item in as_list(claim.get("source_bound_prerequisite_ids"))]
        dependency_ids = [str(item) for item in as_list(claim.get("depends_on_security_property_ids"))]
        deployment_ids = [str(item) for item in as_list(claim.get("verified_deployment_prerequisite_ids"))]
        oracle = as_mapping(claim.get("deterministic_oracle"))
        oracle_token = str(oracle.get("token") or "").strip()
        oracle_path = str(oracle.get("evidence_path") or "").strip()
        if (
            not claim_id
            or claim_id in claim_map
            or not check_nonempty_string_list(supported_classes)
            or not source_ids
            or any(item not in refs for item in source_ids)
            or any(item not in properties for item in dependency_ids)
            or any(item not in prerequisite_map for item in deployment_ids)
            or not nonempty_string(oracle.get("token"))
            or not nonempty_string(oracle.get("evidence_path"))
            or not check_nonempty_string_list(claim.get("unsupported_stronger_impacts"))
        ):
            issues.add("IMPACT_CLAIM_UNSUPPORTED", path, "Impact claim lacks source-bound prerequisites, known property/deployment dependencies, deterministic oracle, or non-claims.", "Complete the generic impact evidence record and bind every dependency.")
        if (
            oracle_token != str(direct.get("marker") or "").strip()
            or oracle_token != str(docker.get("oracle_token") or "").strip()
            or oracle_token not in str(docker.get("observed_observation") or "")
            or oracle_token not in str(entrypoint_evidence.get("deterministic_impact_oracle") or "")
            or oracle_path not in registered_evidence_paths
        ):
            issues.add(
                "IMPACT_CLAIM_UNSUPPORTED",
                f"{path}.deterministic_oracle",
                "Impact oracle is not synchronized with Docker/direct-impact evidence and a registered evidence path.",
                "Use the observed direct-impact token and register the cited evidence artifact.",
            )
        for prop_id in dependency_ids:
            prop = properties.get(prop_id, {})
            if prop.get("origin") == "synthetic":
                issues.add("SYNTHETIC_PROPERTY_SUPPORTS_IMPACT", path, "An impact claim depends on a synthetic security property.", "Keep ordinary synthetic markers in the deterministic oracle only; source-bind every real impact prerequisite.")
        claim_map[claim_id] = claim
    if not claim_map:
        issues.add("IMPACT_CLAIM_UNSUPPORTED", "impact_claims", "At least one supported generic impact claim is required.", "Add an artifact-backed impact claim before promotion.")
    for prop_id, prop in properties.items():
        if prop.get("origin") != "synthetic":
            continue
        unsupported_ids = [str(item) for item in as_list(prop.get("cannot_support_impact_claim_ids"))]
        if any(item not in claim_map for item in unsupported_ids):
            issues.add(
                "FIXTURE_SECURITY_BOUNDARY_MISSING",
                f"fixture_provenance.security_properties.{prop_id}.cannot_support_impact_claim_ids",
                "Synthetic-property non-support references an unknown impact claim.",
                "List stable impact claim ids from this contract.",
            )

    verdict = str(review.get("validity_verdict") or "").strip()
    decision = str(review.get("classification_decision") or "").strip()
    if verdict not in VALIDITY_VERDICTS:
        issues.add("VALIDITY_VERDICT_NOT_PROMOTABLE", "validity_review.validity_verdict", "Unknown validity verdict.", "Use confirmed, conditionally_confirmed, not_valid, or withdrawn.")
    elif verdict not in PROMOTABLE_VALIDITY_VERDICTS:
        issues.add("VALIDITY_VERDICT_NOT_PROMOTABLE", "validity_review.validity_verdict", f"{verdict} findings may never be promoted.", "Keep the finding outside confirmed/.")
    if decision not in CLASSIFICATION_DECISIONS:
        issues.add("BUG_CLASS_EVIDENCE_MISMATCH", "validity_review.classification_decision", "Unknown classification decision.", "Use unchanged, downgraded, or reclassified.")
    final_class = check_required_string(review, "final_bug_class", "validity_review", issues, "BUG_CLASS_EVIDENCE_MISMATCH")
    final_severity = check_required_string(review, "final_severity", "validity_review", issues, "SEVERITY_EVIDENCE_MISMATCH")
    supported_ids = [str(item) for item in as_list(review.get("supported_impact_claim_ids"))]
    deployment_ids = [str(item) for item in as_list(review.get("deployment_prerequisite_ids"))]
    if not supported_ids or any(item not in claim_map for item in supported_ids):
        issues.add("IMPACT_CLAIM_UNSUPPORTED", "validity_review.supported_impact_claim_ids", "Validity review cites missing or unsupported impact claims.", "Cite only validated impact claim ids.")
    if any(item not in prerequisite_map for item in deployment_ids):
        issues.add("DEPLOYMENT_PREREQUISITE_OMITTED", "validity_review.deployment_prerequisite_ids", "Validity review cites an unknown deployment prerequisite.", "Cite source-bound deployment prerequisites.")
    if verdict == "conditionally_confirmed" and not deployment_ids:
        issues.add("DEPLOYMENT_PREREQUISITE_OMITTED", "validity_review.deployment_prerequisite_ids", "Conditional confirmation requires explicit source-bound deployment conditions.", "List every condition that must appear in reviewer-facing materials.")
    if final_class and any(final_class not in as_list(claim_map[item].get("supported_bug_classes")) for item in supported_ids if item in claim_map):
        issues.add("BUG_CLASS_EVIDENCE_MISMATCH", "validity_review.final_bug_class", "Final bug class is not supported by every cited impact claim.", "Reclassify conservatively or cite claims that support the final class.")
    ceilings = [str(claim_map[item].get("severity_ceiling") or "") for item in supported_ids if item in claim_map]
    max_ceiling = max((SEVERITY_ORDER.get(item, -1) for item in ceilings), default=-1)
    if final_severity not in SEVERITY_LABELS or SEVERITY_ORDER.get(final_severity, 99) > max_ceiling:
        issues.add("SEVERITY_EVIDENCE_MISMATCH", "validity_review.final_severity", "Final severity exceeds the ceiling supported by verified impact claims.", "Lower severity or add stronger source-bound Docker evidence.")
    finding = as_mapping(contract.get("finding"))
    impact_tier = as_mapping(contract.get("impact_tier"))
    if final_class and (finding.get("bug_class") != final_class or impact_tier.get("bug_class") != final_class):
        issues.add("BUG_CLASS_EVIDENCE_MISMATCH", "finding.bug_class", "Finding, impact tier, and final validity review bug classes differ.", "Use the final reviewed bug class everywhere.")
    if final_severity and finding.get("severity") != final_severity:
        issues.add("SEVERITY_EVIDENCE_MISMATCH", "finding.severity", "Finding severity differs from the final validity review.", "Use the final reviewed severity everywhere.")
    original_class = str(review.get("original_bug_class") or "").strip()
    original_severity = str(review.get("original_severity") or "").strip()
    if decision == "unchanged" and (original_class != final_class or original_severity != final_severity):
        issues.add("BUG_CLASS_EVIDENCE_MISMATCH", "validity_review.classification_decision", "unchanged decision conflicts with original/final classification.", "Use downgraded/reclassified or restore the original classification.")
    if decision == "downgraded" and (original_class != final_class or SEVERITY_ORDER.get(final_severity, 99) >= SEVERITY_ORDER.get(original_severity, -1)):
        issues.add("SEVERITY_EVIDENCE_MISMATCH", "validity_review.classification_decision", "downgraded must preserve bug class and lower severity.", "Record a real severity downgrade.")
    if decision == "reclassified" and original_class == final_class:
        issues.add("BUG_CLASS_EVIDENCE_MISMATCH", "validity_review.classification_decision", "reclassified requires a changed bug class.", "Use unchanged/downgraded or change the final class.")
    check_required_string(review, "rationale", "validity_review", issues, "IMPACT_CLAIM_UNSUPPORTED")
    if not check_nonempty_string_list(review.get("stronger_impacts_not_claimed")):
        issues.add("IMPACT_CLAIM_UNSUPPORTED", "validity_review.stronger_impacts_not_claimed", "Validity review must disclose unsupported stronger impacts.", "List stronger impacts that the evidence does not support.")
    cvss = as_mapping(review.get("cvss"))
    if cvss:
        version = str(cvss.get("version") or "").strip()
        vector = str(cvss.get("vector") or "").strip()
        try:
            score = float(cvss.get("score"))
        except (TypeError, ValueError):
            score = -1.0
        prefix = "CVSS:4.0/" if version == "4.0" else "CVSS:3.1/" if version == "3.1" else ""
        low, high = CVSS_SEVERITY_RANGES.get(final_severity, (-1.0, -1.0))
        if not prefix or not vector.startswith(prefix) or not (low <= score <= high):
            issues.add("SEVERITY_EVIDENCE_MISMATCH", "validity_review.cvss", "CVSS version/vector/score does not match final severity.", "Use CVSS 4.0 or 3.1 and a score consistent with the evidence-bounded final severity.")


def check_final_path(contract: dict[str, Any], workspace_dir: Path, issues: IssueCollector) -> None:
    bundle = as_mapping(contract.get("bundle"))
    slug = check_required_string(bundle, "slug", "bundle", issues)
    final_path = check_required_string(bundle, "final_path", "bundle", issues, "BUNDLE_PATH_ESCAPE")
    if not slug or not final_path:
        return
    if path_has_escape(final_path, path_field=True):
        issues.add(
            "BUNDLE_PATH_ESCAPE",
            "bundle.final_path",
            "Final bundle path is not portable.",
            "Use confirmed/<slug> without absolute paths, file:// URLs, or parent traversal.",
        )
        return
    parts = PurePosixPath(final_path.replace("\\", "/")).parts
    if len(parts) < 2 or parts[0] != "confirmed" or parts[1] != slug:
        issues.add(
            "BUNDLE_PATH_ESCAPE",
            "bundle.final_path",
            "Final path must stay under confirmed/<slug>.",
            "Set bundle.final_path to confirmed/<slug> or a child path under that directory.",
        )
        return
    final_abs = (workspace_dir / final_path).resolve()
    confirmed_slug = (workspace_dir / "confirmed" / slug).resolve()
    if final_abs != confirmed_slug and confirmed_slug not in final_abs.parents:
        issues.add(
            "BUNDLE_PATH_ESCAPE",
            "bundle.final_path",
            "Final path resolves outside confirmed/<slug>.",
            "Keep final_path inside the one-vulnerability confirmed bundle directory.",
        )
    policy = bundle.get("fail_if_final_path_exists", True)
    if final_abs.exists() and policy is not False:
        issues.add(
            "FINAL_TARGET_EXISTS",
            "bundle.final_path",
            "Final confirmed bundle path already exists.",
            "Use a fresh slug or remove/review the existing final bundle before generation.",
        )


def check_core_fields(contract: dict[str, Any], issues: IssueCollector) -> None:
    if contract.get("schema_version") != 1:
        issues.add("CONTRACT_SCHEMA_VERSION", "schema_version", "schema_version must be 1.", "Use the R1 bundle contract template.")
    bundle = as_mapping(contract.get("bundle"))
    check_required_string(bundle, "language", "bundle", issues)
    one_vuln = check_required_bool(bundle, "one_vulnerability_only", "bundle", issues)
    if one_vuln is not True:
        issues.add(
            "ONE_VULNERABILITY_REQUIRED",
            "bundle.one_vulnerability_only",
            "Confirmed bundle contract must represent exactly one vulnerability.",
            "Split multiple findings into separate contracts and final bundles.",
        )

    finding = as_mapping(contract.get("finding"))
    for key in (
        "project_name",
        "vulnerability_name",
        "bug_class",
        "attacker_condition",
        "server_condition",
        "security_impact",
    ):
        check_required_string(finding, key, "finding", issues)
    severity = check_required_string(finding, "severity", "finding", issues)
    if severity and severity not in SEVERITY_LABELS:
        issues.add(
            "SEVERITY_ENUM_INVALID",
            "finding.severity",
            "finding.severity must use one stable contract label.",
            "Use one of: Critical, High, Medium, Low, Informational. Renderers may localize the label in final reports.",
        )


def check_render(contract: dict[str, Any], issues: IssueCollector) -> None:
    render = as_mapping(contract.get("render"))
    check_required_string(render, "source_findings_json", "render", issues)
    check_required_string(render, "finding_slug", "render", issues)


def check_docker_evidence(contract: dict[str, Any], issues: IssueCollector) -> None:
    docker = as_mapping(contract.get("docker_evidence"))
    if docker.get("verification_status") != "confirmed_in_docker":
        issues.add(
            "DOCKER_STATUS_NOT_CONFIRMED",
            "docker_evidence.verification_status",
            "verification_status must be confirmed_in_docker.",
            "Only Docker-confirmed evidence may feed final confirmed bundle generation.",
        )
    if docker.get("docker_required") is not True:
        issues.add(
            "DOCKER_REQUIRED_NOT_TRUE",
            "docker_evidence.docker_required",
            "docker_required must be true.",
            "Record the Docker or Docker Compose reproduction path before generation.",
        )
    for key in ("docker_command", "oracle_token", "expected_observation", "observed_observation"):
        check_required_string(docker, key, "docker_evidence", issues)
    if type(docker.get("severity_escalation_attempted")) is not bool:
        issues.add(
            "SEVERITY_ESCALATION_MISSING",
            "docker_evidence.severity_escalation_attempted",
            "severity_escalation_attempted must be present.",
            "Run or explicitly record the Docker severity-escalation pass before final scoring.",
        )


def check_entrypoint_evidence(contract: dict[str, Any], issues: IssueCollector) -> None:
    evidence = as_mapping(contract.get("entrypoint_evidence"))
    if not evidence:
        issues.add(
            "ENTRYPOINT_EVIDENCE_MISSING",
            "entrypoint_evidence",
            "Bundle-ready proof must describe attacker-entrypoint reproduction.",
            "Add entrypoint_evidence with evidence_level, attacker-controlled entrypoint, input shape, entrypoint-to-sink path, impact oracle, and replay material.",
        )
        return
    evidence_level = str(evidence.get("evidence_level") or "").strip()
    if evidence_level == "code_level_reproduced":
        issues.add(
            "CODE_LEVEL_ONLY_NOT_BUNDLE_READY",
            "entrypoint_evidence.evidence_level",
            "Code-level or function-level reproduction is supporting evidence only.",
            "Keep the code-level run as supporting evidence and verify a real attacker-controlled entrypoint before bundle generation.",
        )
    elif evidence_level == "blocked_entrypoint_verification":
        issues.add(
            "ENTRYPOINT_EVIDENCE_MISSING",
            "entrypoint_evidence.evidence_level",
            "Entrypoint verification is blocked, so this finding is not bundle-ready.",
            "Route the finding to blocked or unverified notes until Docker/Compose entrypoint verification succeeds.",
        )
    elif evidence_level not in ENTRYPOINT_BUNDLE_READY_LEVELS:
        issues.add(
            "ENTRYPOINT_EVIDENCE_MISSING",
            "entrypoint_evidence.evidence_level",
            "Missing or unknown evidence level for attacker-entrypoint reproduction.",
            "Use entrypoint_reproduced or confirmed_in_docker only when Docker/Compose evidence reaches the attacker-controlled entrypoint.",
        )

    for key in ("attacker_controlled_entrypoint", "input_shape"):
        check_required_string(evidence, key, "entrypoint_evidence", issues, "ENTRYPOINT_EVIDENCE_MISSING")
    if not nonempty_string(evidence.get("entrypoint_to_sink_path")):
        issues.add(
            "ENTRYPOINT_TO_SINK_PATH_MISSING",
            "entrypoint_evidence.entrypoint_to_sink_path",
            "Bundle-ready proof must explain how the attacker entrypoint reaches the sink.",
            "Record the route/API/CLI/RPC/UI path, propagation step, and sink reached in the Docker/Compose proof.",
        )
    if not nonempty_string(evidence.get("deterministic_impact_oracle")):
        issues.add(
            "IMPACT_ORACLE_MISSING",
            "entrypoint_evidence.deterministic_impact_oracle",
            "Bundle-ready proof must name a deterministic impact oracle.",
            "Record the response, log, callback, file, crash, or marker that proves impact in Docker/Compose.",
        )
    replay = evidence.get("replay_material")
    if isinstance(replay, dict):
        replay_path = replay.get("path")
        replay_generation = replay.get("generation_command")
        replay_description = replay.get("description")
        if not nonempty_string(replay_description) or not (
            nonempty_string(replay_path) or nonempty_string(replay_generation)
        ):
            issues.add(
                "REPLAY_MATERIAL_MISSING",
                "entrypoint_evidence.replay_material",
                "Reviewer-facing replay material is incomplete.",
                "Provide a replay path or generation command plus a short description.",
            )
    else:
        issues.add(
            "REPLAY_MATERIAL_MISSING",
            "entrypoint_evidence.replay_material",
            "Bundle-ready proof must include reviewer-facing replay material.",
            "Register a replay log/helper path or a command that can generate reviewer replay material.",
        )


def contract_file_values(files: dict[str, Any], target_name: str) -> set[str]:
    values: set[str] = set()
    value = files.get(target_name)
    if isinstance(value, str):
        values.add(value)
    elif isinstance(value, list):
        values.update(item for item in value if isinstance(item, str))
    return values


def check_replay_registration(contract: dict[str, Any], issues: IssueCollector) -> None:
    replay = as_mapping(contract.get("replay"))
    root_script = as_mapping(replay.get("root_script"))
    replay_log = as_mapping(replay.get("log"))
    check_required_string(root_script, "path", "replay.root_script", issues)
    log_path = check_required_string(replay_log, "path", "replay.log", issues)
    registration_targets = [item for item in as_list(replay_log.get("registration_targets")) if isinstance(item, str)]
    files = as_mapping(contract.get("files"))
    evidence_files = contract_file_values(files, "evidence_files")
    reviewer_index_path = files.get("reviewer_evidence_index")
    registered_by_evidence = "files.evidence_files" in registration_targets and log_path in evidence_files
    registered_by_reviewer_index = "files.reviewer_evidence_index" in registration_targets and nonempty_string(reviewer_index_path)
    if not registration_targets or not (registered_by_evidence or registered_by_reviewer_index):
        issues.add(
            "REPLAY_LOG_UNREGISTERED",
            "replay.log.registration_targets",
            "Replay log is not listed in a registration target.",
            "Add the log to files.evidence_files or register it through files.reviewer_evidence_index.",
        )


def check_direct_impact(contract: dict[str, Any], issues: IssueCollector) -> None:
    direct = as_mapping(contract.get("direct_impact"))
    marker = check_required_string(direct, "marker", "direct_impact", issues)
    sync_targets = as_list(direct.get("sync_targets"))
    seen_targets: set[str] = set()
    for index, item in enumerate(sync_targets):
        item_path = f"direct_impact.sync_targets[{index}]"
        if isinstance(item, dict):
            target = item.get("target")
            item_marker = item.get("marker")
            if isinstance(target, str):
                seen_targets.add(target)
            if marker and item_marker != marker:
                issues.add(
                    "DIRECT_IMPACT_MARKER_DRIFT",
                    f"{item_path}.marker",
                    "Direct-impact marker differs between contract sync targets.",
                    "Use the same direct-impact marker across replay helper, replay log, evidence JSON, and reviewer material.",
                )
        elif isinstance(item, str):
            seen_targets.add(item)
        else:
            issues.add(
                "DIRECT_IMPACT_MARKER_DRIFT",
                item_path,
                "direct_impact.sync_targets entries must be strings or objects.",
                "Use target/marker entries so drift can be checked before generation.",
            )
    missing = sorted(DIRECT_IMPACT_REQUIRED_TARGETS - seen_targets)
    if missing:
        issues.add(
            "DIRECT_IMPACT_MARKER_DRIFT",
            "direct_impact.sync_targets",
            "Direct-impact marker sync targets are incomplete.",
            "Include replay helper, replay log, verification evidence, and reviewer-facing material sync targets.",
        )


def check_files(contract: dict[str, Any], issues: IssueCollector) -> None:
    files = as_mapping(contract.get("files"))
    check_required_string(files, "verification_evidence", "files", issues)
    check_required_string(files, "reviewer_evidence_index", "files", issues)
    for key in ("evidence_files", "attachments"):
        values = as_list(files.get(key))
        if not values or any(not nonempty_string(item) for item in values):
            issues.add(
                "CONTRACT_REQUIRED_FIELD_MISSING",
                f"files.{key}",
                "Required file list is missing or contains an empty entry.",
                "List the bundle-relative files that will be copied into the final bundle.",
            )


def check_code_context(contract: dict[str, Any], issues: IssueCollector) -> None:
    context = as_mapping(contract.get("code_context"))
    entries = as_list(context.get("entries"))
    if not entries:
        issues.add(
            "CODE_CONTEXT_TOO_THIN",
            "code_context.entries",
            "Code context must include at least one entry.",
            "Add source path, line metadata or unavailable reason, chain summary, missing guard, and impact boundary.",
        )
        return
    for index, entry_value in enumerate(entries):
        item = as_mapping(entry_value)
        item_path = f"code_context.entries[{index}]"
        has_source = nonempty_string(item.get("source_path")) or nonempty_string(item.get("source_unavailable_reason"))
        has_line = (
            type(item.get("start_line")) is int
            or nonempty_string(item.get("line_range"))
            or nonempty_string(item.get("line_unavailable_reason"))
        )
        required_text = (
            ("input_to_sink_chain", "input-to-sink chain summary"),
            ("missing_guard", "missing guard"),
            ("verified_impact_boundary", "verified impact boundary"),
        )
        missing_parts = []
        if not has_source:
            missing_parts.append("source path or explicit unavailable reason")
        if not has_line:
            missing_parts.append("line/range metadata or explicit unavailable reason")
        for key, label in required_text:
            if not nonempty_string(item.get(key)):
                missing_parts.append(label)
        if missing_parts:
            issues.add(
                "CODE_CONTEXT_TOO_THIN",
                item_path,
                "Code context is missing: " + ", ".join(missing_parts) + ".",
                "Fill code_context before rendering reviewer-facing report material.",
            )


def check_fixture_provenance(contract: dict[str, Any], issues: IssueCollector) -> None:
    provenance = as_mapping(contract.get("fixture_provenance"))
    replay_type = provenance.get("replay_type")
    required = provenance.get("required")
    if required is not True and replay_type not in FIXTURE_REPLAY_TYPES:
        return
    missing = []
    if not as_list(provenance.get("upstream_sources")):
        missing.append("upstream_sources")
    for key in ("preserved_behavior", "sufficiency_reason", "consumer_boundary"):
        if not nonempty_string(provenance.get(key)):
            missing.append(key)
    if not as_list(provenance.get("non_claims")):
        missing.append("non_claims")
    if missing:
        issues.add(
            "FIXTURE_PROVENANCE_MISSING",
            "fixture_provenance",
            "Fixture or vendored replay contract lacks source-grounded provenance.",
            "Record upstream source, preserved behavior, sufficiency rationale, consuming boundary, and non-claims.",
        )


def check_ssrf_impact(contract: dict[str, Any], issues: IssueCollector) -> None:
    finding = as_mapping(contract.get("finding"))
    impact_tier = as_mapping(contract.get("impact_tier"))
    bug_class = str(impact_tier.get("bug_class") or finding.get("bug_class") or "")
    if "ssrf" not in bug_class.lower():
        return
    ssrf = as_mapping(impact_tier.get("ssrf"))
    tier = ssrf.get("tier")
    if not nonempty_string(tier):
        issues.add(
            "SSRF_IMPACT_OVERCLAIM",
            "impact_tier.ssrf.tier",
            "SSRF findings must declare a bounded impact tier.",
            "Choose callback_reachability or an artifact-backed stronger exposure tier.",
        )
        return
    claimed = set(item for item in as_list(ssrf.get("claimed_exposures")) if isinstance(item, str))
    if tier == SSRF_CALLBACK_TIER:
        stronger_claims = sorted((claimed | {str(tier)}) & SSRF_STRONG_TIERS)
        required_nonclaims = SSRF_STRONG_TIERS
        nonclaims = set(item for item in as_list(ssrf.get("stronger_impacts_not_claimed")) if isinstance(item, str))
        if stronger_claims or not required_nonclaims.issubset(nonclaims):
            issues.add(
                "SSRF_IMPACT_OVERCLAIM",
                "impact_tier.ssrf",
                "Callback/reachability SSRF tier may not claim response, config, credential, or sensitive-data exposure.",
                "Bound the claim to reachability and list stronger tiers as not claimed unless artifact-backed evidence exists.",
            )
    elif tier in SSRF_STRONG_TIERS:
        oracle = as_mapping(ssrf.get("artifact_backed_oracle"))
        if not nonempty_string(oracle.get("evidence_path")) or not nonempty_string(oracle.get("oracle_token")):
            issues.add(
                "SSRF_IMPACT_OVERCLAIM",
                "impact_tier.ssrf.artifact_backed_oracle",
                "Stronger SSRF exposure tiers must name artifact-backed oracle evidence.",
                "Add evidence_path and oracle_token that prove the claimed exposure.",
            )
    else:
        issues.add(
            "SSRF_IMPACT_OVERCLAIM",
            "impact_tier.ssrf.tier",
            "Unknown SSRF impact tier.",
            "Use callback_reachability, response_content_exposure, configuration_exposure, credential_exposure, or sensitive_data_exposure.",
        )


def check_variant_seed_readiness(contract: dict[str, Any], issues: IssueCollector) -> None:
    readiness = as_mapping(contract.get("variant_seed_readiness"))
    if readiness.get("run_after_promote") is not True:
        issues.add(
            "VARIANT_SEED_READINESS_MISSING",
            "variant_seed_readiness.run_after_promote",
            "Variant seed readiness must explicitly run after promote.",
            "Set run_after_promote=true so the post-bundle seed pass is not lost.",
        )


def validate_contract(
    contract: dict[str, Any],
    workspace_dir: Path,
    repo_root: Path,
    issues: IssueCollector,
) -> None:
    walk_portability(contract, issues)
    boundary_ok = check_repo_workspace_boundary(repo_root, workspace_dir, issues)
    check_core_fields(contract, issues)
    check_final_path(contract, workspace_dir, issues)
    check_render(contract, issues)
    check_docker_evidence(contract, issues)
    check_entrypoint_evidence(contract, issues)
    check_replay_registration(contract, issues)
    check_direct_impact(contract, issues)
    check_files(contract, issues)
    check_code_context(contract, issues)
    check_fixture_provenance(contract, issues)
    source_refs = check_source_binding(contract, workspace_dir, repo_root, issues) if boundary_ok else {}
    check_fixture_security_boundary(contract, source_refs, issues)
    check_impact_and_validity(contract, source_refs, issues)
    check_ssrf_impact(contract, issues)
    check_variant_seed_readiness(contract, issues)


def emit_json(contract_path: Path, issues: list[Issue]) -> None:
    payload = {
        "schema_version": 1,
        "valid": not any(issue.severity == "error" for issue in issues),
        "contract": str(contract_path),
        "issues": [issue.as_dict() for issue in issues],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


def emit_text(contract_path: Path, issues: list[Issue]) -> None:
    if not issues:
        print(f"OK: bundle contract valid: {contract_path}")
        return
    print(f"FAILED: bundle contract preflight found {len(issues)} issue(s): {contract_path}")
    for issue in issues:
        print(f"[{issue.severity}] {issue.code} at {issue.path}")
        print(f"  {issue.message}")
        print(f"  fix: {issue.fix}")


def main() -> None:
    args = parse_args()
    workspace_dir = Path(args.workspace_dir).expanduser().resolve()
    repo_root = Path(args.repo_root).expanduser().resolve()
    contract_path = Path(args.contract).expanduser()
    issues = IssueCollector(all_errors=args.all_errors)
    try:
        contract = load_json(contract_path, issues)
        if contract:
            validate_contract(contract, workspace_dir, repo_root, issues)
    except StopValidation:
        pass

    if args.json:
        emit_json(contract_path, issues.issues)
    else:
        emit_text(contract_path, issues.issues)
    if any(issue.severity == "error" for issue in issues.issues):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
