#!/usr/bin/env python3
"""Offline validation for the Zhulong Tool Registry R2 contract.

The registry is a local declaration consumed by Zhulong's planner and narrow
wrappers.  It is not an operating-system sandbox and does not intercept native
Agent Read/Glob/Grep/Shell calls.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Issue:
    code: str
    path: str
    message: str
    action: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message, "action": self.action}


def add_issue(issues: list[Issue], code: str, path: str, message: str, action: str) -> None:
    issue = Issue(code, path, message, action)
    if issue not in issues:
        issues.append(issue)


def default_schema_path(registry: Path) -> Path:
    if registry.parent.name == "assets":
        return registry.parent / "schemas" / "tool-registry.schema.json"
    return registry.parent / "tool-registry.schema.json"


def load_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, str(exc)


def resolve_ref(schema: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/$defs/"):
        raise ValueError(f"unsupported schema reference: {ref}")
    value: Any = schema
    for part in ref[2:].split("/"):
        value = value[part]
    if not isinstance(value, dict):
        raise ValueError(f"schema reference is not an object: {ref}")
    return value


def matches_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return type(value) is int
    if expected == "boolean":
        return type(value) is bool
    if expected == "null":
        return value is None
    return False


def schema_errors(value: Any, rule: dict[str, Any], schema: dict[str, Any], path: str = "$") -> list[tuple[str, str]]:
    if "$ref" in rule:
        return schema_errors(value, resolve_ref(schema, str(rule["$ref"])), schema, path)
    errors: list[tuple[str, str]] = []
    for item in rule.get("allOf", []):
        if isinstance(item, dict):
            errors.extend(schema_errors(value, item, schema, path))
    condition = rule.get("if")
    if isinstance(condition, dict):
        branch = rule.get("then") if not schema_errors(value, condition, schema, path) else rule.get("else")
        if isinstance(branch, dict):
            errors.extend(schema_errors(value, branch, schema, path))
    expected = rule.get("type")
    if isinstance(expected, list):
        if not any(matches_type(value, item) for item in expected if isinstance(item, str)):
            return errors + [(path, "has an unsupported type")]
    elif isinstance(expected, str) and not matches_type(value, expected):
        return errors + [(path, f"must be a {expected}")]
    if "const" in rule and value != rule["const"]:
        errors.append((path, f"must equal {rule['const']!r}"))
    if "enum" in rule and value not in rule["enum"]:
        errors.append((path, "has an unsupported value"))
    if isinstance(value, dict):
        properties = rule.get("properties", {})
        required = rule.get("required", [])
        for key in required:
            if key not in value:
                errors.append((f"{path}.{key}", "is required"))
        if rule.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    errors.append((f"{path}.{key}", "is not an allowed property"))
        for key, child in properties.items():
            if key in value and isinstance(child, dict):
                errors.extend(schema_errors(value[key], child, schema, f"{path}.{key}"))
    elif isinstance(value, list):
        if "minItems" in rule and len(value) < int(rule["minItems"]):
            errors.append((path, f"must contain at least {rule['minItems']} item(s)"))
        if rule.get("uniqueItems") is True:
            seen: list[Any] = []
            for item in value:
                if any(item == previous for previous in seen):
                    errors.append((path, "must not contain duplicate items"))
                    break
                seen.append(item)
        child = rule.get("items")
        if isinstance(child, dict):
            for index, item in enumerate(value):
                errors.extend(schema_errors(item, child, schema, f"{path}[{index}]"))
    elif isinstance(value, str):
        if "minLength" in rule and len(value) < int(rule["minLength"]):
            errors.append((path, "must not be empty"))
        if "pattern" in rule and re.fullmatch(str(rule["pattern"]), value) is None:
            errors.append((path, "has an invalid format"))
    return errors


def is_safe_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or value.startswith(("/", "~")):
        return False
    if "\\" in value or "://" in value or "\x00" in value or re.match(r"^[A-Za-z]:", value):
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def safe_regular_wrapper(root: Path, wrapper: dict[str, Any], *, workspace_layout: bool, issues: list[Issue], path: str) -> None:
    raw_path = wrapper.get("workspace_adapter") if workspace_layout else wrapper.get("path")
    field = "workspace_adapter" if workspace_layout else "path"
    if not is_safe_relative_path(raw_path):
        add_issue(issues, "WRAPPER_PATH_UNSAFE", f"{path}.{field}", "Controlled wrapper paths must be safe relative POSIX paths.", "Use a regular file inside the skill root without URI, absolute path, backslash, or '..'.")
        return
    candidate = root.joinpath(*str(raw_path).split("/"))
    try:
        info = os.lstat(candidate)
    except FileNotFoundError:
        add_issue(issues, "WRAPPER_MISSING", f"{path}.{field}", "The controlled wrapper does not exist.", "Ship the referenced wrapper in the same skill layout.")
        return
    except OSError:
        add_issue(issues, "WRAPPER_PATH_UNSAFE", f"{path}.{field}", "The controlled wrapper cannot be inspected safely.", "Use a regular wrapper file inside the skill root.")
        return
    if stat.S_ISLNK(info.st_mode):
        add_issue(issues, "WRAPPER_SYMLINK", f"{path}.{field}", "Controlled wrapper symlinks are not accepted.", "Use a regular file owned by the skill layout.")
        return
    if not stat.S_ISREG(info.st_mode):
        add_issue(issues, "WRAPPER_TYPE_INVALID", f"{path}.{field}", "Controlled wrapper must be a regular file.", "Reference a regular script or Python helper.")
        return
    try:
        candidate.resolve(strict=True).relative_to(root.resolve())
    except (OSError, ValueError):
        add_issue(issues, "WRAPPER_PATH_UNSAFE", f"{path}.{field}", "Controlled wrapper resolves outside the skill root.", "Keep the wrapper inside the selected skill root.")
        return
    marker = wrapper.get("contract_marker")
    try:
        snippet = candidate.read_text(encoding="utf-8", errors="strict")[:16384]
    except OSError:
        snippet = ""
    if not isinstance(marker, str) or marker not in snippet:
        add_issue(issues, "WRAPPER_MARKER_MISSING", f"{path}.contract_marker", "The wrapper does not expose the declared stable contract marker.", "Add the exact static marker to the controlled wrapper or correct the registry declaration.")


def flatten_tools(registry: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    pairs: list[tuple[str, dict[str, Any]]] = []
    for tier in registry.get("tiers", []):
        if isinstance(tier, dict) and isinstance(tier.get("name"), str):
            for tool in tier.get("tools", []):
                if isinstance(tool, dict):
                    pairs.append((tier["name"], tool))
    return pairs


def validate_registry(registry: Any, schema: dict[str, Any], skill_root: Path) -> list[Issue]:
    issues: list[Issue] = []
    for path, message in schema_errors(registry, schema, schema):
        add_issue(issues, "SCHEMA_INVALID", path, message, "Correct the registry to the strict Tool Registry schema.")
    if not isinstance(registry, dict):
        return issues
    workspace_layout = (skill_root / "asr-config.json").is_file()
    tier_names: set[str] = set()
    tool_names: set[str] = set()
    high_risk_boundaries = {"docker_exec", "external_network", "target_repo_write"}
    docker_effects = {"docker_container_start", "docker_cli_invocation"}
    scanner_kinds = {"scanner", "static_analysis", "dependency", "sbom", "secret_scanner", "dast"}
    for tier_index, tier in enumerate(registry.get("tiers", [])):
        tier_path = f"$.tiers[{tier_index}]"
        if not isinstance(tier, dict):
            continue
        tier_name = tier.get("name")
        if isinstance(tier_name, str):
            if tier_name in tier_names:
                add_issue(issues, "DUPLICATE_TIER", f"{tier_path}.name", "Tier names must be unique.", "Rename the duplicate tier.")
            tier_names.add(tier_name)
        for tool_index, tool in enumerate(tier.get("tools", [])):
            tool_path = f"{tier_path}.tools[{tool_index}]"
            if not isinstance(tool, dict):
                continue
            name = tool.get("name")
            if isinstance(name, str):
                if name in tool_names:
                    add_issue(issues, "DUPLICATE_TOOL", f"{tool_path}.name", "Tool names must be unique across tiers.", "Rename or remove the duplicate tool.")
                tool_names.add(name)
            boundary_values = tool.get("execution_boundaries", []) if isinstance(tool.get("execution_boundaries"), list) else []
            boundaries = set(boundary_values)
            effects = set(tool.get("effects", [])) if isinstance(tool.get("effects"), list) else set()
            authority = tool.get("confirmation_authority")
            wrapper = tool.get("controlled_wrapper")
            network_scope = tool.get("network_scope")
            has_external_boundary = "external_network" in boundaries
            has_external_effect = "external_network_access" in effects
            has_external_scope = network_scope in {"restricted_external", "public_external"}
            contains_prohibited = "prohibited" in boundaries or tool.get("planner_status") == "prohibited"
            prohibited = boundaries == {"prohibited"} and len(boundary_values) == 1
            if "prohibited" in boundaries and not prohibited:
                add_issue(issues, "PROHIBITED_BOUNDARY_EXCLUSIVE", f"{tool_path}.execution_boundaries", "The prohibited boundary must be the only execution boundary and must not be repeated.", "Declare exactly one prohibited boundary.")
            if contains_prohibited and effects:
                add_issue(issues, "PROHIBITED_EFFECTS_FORBIDDEN", f"{tool_path}.effects", "A prohibited tool cannot declare active effects.", "Use an empty effects list.")
            if contains_prohibited and wrapper is not None:
                add_issue(issues, "PROHIBITED_WRAPPER_FORBIDDEN", f"{tool_path}.controlled_wrapper", "A prohibited tool cannot declare a controlled wrapper.", "Set controlled_wrapper to null.")
            if contains_prohibited and authority != "none":
                add_issue(issues, "PROHIBITED_AUTHORITY_FORBIDDEN", f"{tool_path}.confirmation_authority", "A prohibited tool cannot declare confirmation authority.", "Set confirmation_authority to none.")
            if "prohibited" in boundaries and tool.get("planner_status") != "prohibited":
                add_issue(issues, "PROHIBITED_PLANNER_STATUS_REQUIRED", f"{tool_path}.planner_status", "The prohibited boundary requires planner_status=prohibited.", "Keep planner and execution boundary status aligned.")
            if tool.get("planner_status") == "prohibited" and not prohibited:
                add_issue(issues, "PROHIBITED_PLANNER_CONTRADICTION", f"{tool_path}.planner_status", "planner_status=prohibited cannot coexist with an active or ambiguous execution boundary.", "Declare exactly one prohibited boundary or use a non-prohibited planner status.")
            if contains_prohibited and (network_scope not in {None, "none"} or has_external_boundary or has_external_effect):
                add_issue(issues, "PROHIBITED_NETWORK_FORBIDDEN", f"{tool_path}.network_scope", "A prohibited tool cannot declare network scope, boundary, or effects.", "Remove all active network capability declarations.")
            if not contains_prohibited:
                if has_external_effect and (not has_external_boundary or not has_external_scope):
                    add_issue(issues, "NETWORK_BOUNDARY_MISSING", tool_path, "External-network effects require external_network boundary and non-none network scope.", "Declare the conservative network boundary and scope.")
                if has_external_boundary != has_external_scope:
                    add_issue(issues, "NETWORK_SCOPE_BOUNDARY_CONFLICT", tool_path, "External-network boundary and external network scope must be declared together.", "Use restricted_external/public_external with external_network, or remove both declarations.")
                if (has_external_boundary or has_external_scope) and not has_external_effect:
                    add_issue(issues, "NETWORK_EFFECT_MISSING", tool_path, "An external-network boundary or scope requires the external_network_access effect.", "Declare the external-network effect or remove the network boundary and scope.")
                if tool.get("kind") == "dast":
                    has_local_target_contract = network_scope == "local_target_only" and "local_target_access" in effects
                    if not (has_external_boundary and has_external_scope and has_external_effect) and not has_local_target_contract:
                        add_issue(issues, "DAST_NETWORK_BOUNDARY_MISSING", tool_path, "Active DAST requires an explicit external-network or local-target access contract.", "Declare a controlled network boundary/scope/effect or keep the DAST tool prohibited.")
                if effects & docker_effects and "docker_exec" not in boundaries:
                    add_issue(issues, "DOCKER_BOUNDARY_MISSING", tool_path, "Docker effects require the docker_exec boundary.", "Declare docker_exec or remove the Docker effect.")
                if "target_code_execute" in effects and "docker_exec" not in boundaries:
                    add_issue(issues, "CODE_EXEC_BOUNDARY_MISSING", tool_path, "Target code execution must remain inside the Docker execution boundary.", "Declare docker_exec or remove the target-code execution effect.")
                if "target_repo_write" in effects and "target_repo_write" not in boundaries:
                    add_issue(issues, "TARGET_WRITE_BOUNDARY_MISSING", tool_path, "Target-repository writes require target_repo_write boundary.", "Declare target_repo_write or remove the effect.")
                if "workspace_evidence_write" in effects and not tool.get("evidence_outputs"):
                    add_issue(issues, "WORKSPACE_EVIDENCE_MISSING", tool_path, "Workspace writes require an explicit evidence output contract.", "Declare workspace-relative evidence output families.")
                needs_wrapper = bool(boundaries & high_risk_boundaries) or tool.get("kind") == "dast" or authority == "docker_oracle_material_only"
                if needs_wrapper and not isinstance(wrapper, dict):
                    add_issue(issues, "WRAPPER_REQUIRED", tool_path, "This active tool capability requires a controlled wrapper.", "Bind a real controlled wrapper or mark the tool prohibited/planning-only.")
            if isinstance(wrapper, dict):
                safe_regular_wrapper(skill_root, wrapper, workspace_layout=workspace_layout, issues=issues, path=f"{tool_path}.controlled_wrapper")
                if tool.get("timeout_policy") == "wrapper_enforced" and "timeout=mandatory" not in str(wrapper.get("contract_marker", "")):
                    add_issue(issues, "TIMEOUT_CONTRACT_MISSING", f"{tool_path}.timeout_policy", "wrapper_enforced timeout requires a mandatory timeout contract marker.", "Use caller_required/not_enforced or expose a mandatory timeout marker in the wrapper.")
                if authority == "docker_oracle_material_only" and "sandbox-preflight=mandatory" not in str(wrapper.get("contract_marker", "")):
                    add_issue(issues, "SANDBOX_CONTRACT_MISSING", f"{tool_path}.controlled_wrapper.contract_marker", "Docker oracle material requires a mandatory sandbox-preflight contract marker.", "Expose the sandbox-preflight capability in the fixed wrapper marker.")
            if authority == "docker_oracle_material_only" and ("docker_exec" not in boundaries or "target_code_execute" not in effects):
                add_issue(issues, "ORACLE_AUTHORITY_CONTRACT_INVALID", tool_path, "Docker oracle authority requires Docker execution and target-code execution effects.", "Use the fixed Docker verification wrapper metadata or reduce authority.")
            if tool.get("kind") in scanner_kinds and authority not in {"none", "candidate_only"}:
                add_issue(issues, "SCANNER_AUTHORITY_FORBIDDEN", tool_path, "Scanner, static, dependency, SBOM, secret, and DAST tools may be candidate-only at most.", "Set confirmation_authority to none or candidate_only.")
            if name == "docker" and authority == "docker_oracle_material_only":
                add_issue(issues, "RAW_DOCKER_AUTHORITY_FORBIDDEN", tool_path, "Raw Docker CLI cannot produce oracle authority.", "Use only the controlled verification wrapper for oracle material.")
            for output_index, output in enumerate(tool.get("evidence_outputs", [])):
                output_path = f"{tool_path}.evidence_outputs[{output_index}].path_family"
                family = output.get("path_family") if isinstance(output, dict) else None
                if not isinstance(family, str) or not is_safe_relative_path(family.replace("*", "x")) or not family.startswith(("evidence/", "runtime/")):
                    add_issue(issues, "EVIDENCE_PATH_UNSAFE", output_path, "Evidence output families must be safe workspace-relative evidence/runtime paths.", "Use a non-URI relative path without traversal or absolute prefixes.")
    return issues


def load_validated_registry(skill_root: Path, registry_path: Path, schema_path: Path | None = None) -> tuple[dict[str, Any] | None, list[Issue]]:
    issues: list[Issue] = []
    registry, error = load_json(registry_path)
    if error is not None:
        add_issue(issues, "REGISTRY_JSON_INVALID", "<registry>", "The registry is not valid UTF-8 JSON.", "Write valid JSON and rerun the validator.")
        return None, issues
    selected_schema = schema_path or default_schema_path(registry_path)
    schema, schema_error = load_json(selected_schema)
    if schema_error is not None or not isinstance(schema, dict):
        add_issue(issues, "SCHEMA_FILE_INVALID", "<schema>", "The Tool Registry schema cannot be loaded.", "Ship a valid strict schema beside the registry.")
        return None, issues
    issues.extend(validate_registry(registry, schema, skill_root))
    return registry if isinstance(registry, dict) else None, issues


def make_output(registry: dict[str, Any] | None, issues: list[Issue], declared_tool: str | None = None) -> dict[str, Any]:
    codes: list[str] = []
    for issue in issues:
        if issue.code not in codes:
            codes.append(issue.code)
    return {
        "ok": not issues,
        "result": "tool_registry_valid" if not issues else "tool_registry_invalid",
        "authority": "tool_metadata_only",
        "tool": declared_tool,
        "tool_count": len(flatten_tools(registry)) if registry else 0,
        "issue_codes": codes,
        "issues": [issue.as_dict() for issue in issues],
        "message": "Tool registry is valid; this does not execute a tool, create a candidate, verify a finding, or confirm a vulnerability." if not issues else "Tool registry rejected; fix the listed issues before planning or wrapper execution."
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline, read-only validation for Zhulong Tool Registry R2.")
    parser.add_argument("--skill-root", required=True, help="Source or installed skill root, or a bootstrapped workspace root.")
    parser.add_argument("--registry", required=True, help="Canonical tool-registry.json path.")
    parser.add_argument("--schema", help="Optional strict schema path; defaults beside the registry.")
    parser.add_argument("--tool", help="Validate a declared use for one tool name.")
    parser.add_argument("--stage", help="Declared audit stage for --tool.")
    parser.add_argument("--boundary", help="Declared execution boundary for --tool.")
    parser.add_argument("--effect", help="Declared effect for --tool.")
    parser.add_argument("--json", action="store_true", help="Emit stable machine-readable JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.skill_root).expanduser().resolve()
    issues: list[Issue] = []
    if not root.is_dir():
        add_issue(issues, "SKILL_ROOT_INVALID", "--skill-root", "Skill root must be an existing directory.", "Pass the source, installed, or bootstrapped workspace root.")
        registry = None
    else:
        registry, issues = load_validated_registry(root, Path(args.registry).expanduser().resolve(), Path(args.schema).expanduser().resolve() if args.schema else None)
    declared = args.tool
    declared_args = [args.stage, args.boundary, args.effect]
    if any(value is not None for value in declared_args) and not declared:
        add_issue(issues, "DECLARED_USE_TOOL_MISSING", "--tool", "Declared stage/boundary/effect checks require --tool.", "Pass a tool name with all declared-use fields.")
    if declared and registry is not None:
        tool = next((entry for _tier, entry in flatten_tools(registry) if entry.get("name") == declared), None)
        if tool is None:
            add_issue(issues, "TOOL_UNKNOWN", "--tool", "The declared tool is not present in the registry.", "Use a canonical registered tool name.")
        else:
            if args.stage is not None and args.stage not in tool.get("allowed_stages", []):
                add_issue(issues, "TOOL_STAGE_FORBIDDEN", "--stage", "The tool is not declared for this audit stage.", "Use an allowed stage or select another tool.")
            if args.boundary is not None and args.boundary not in tool.get("execution_boundaries", []):
                add_issue(issues, "TOOL_BOUNDARY_FORBIDDEN", "--boundary", "The boundary is not declared for this tool.", "Use a declared boundary or correct the registry.")
            if args.effect is not None and args.effect not in tool.get("effects", []):
                add_issue(issues, "TOOL_EFFECT_FORBIDDEN", "--effect", "The effect is not declared for this tool.", "Use a declared effect or correct the registry.")
    output = make_output(registry, issues, declared)
    if args.json:
        print(json.dumps(output, ensure_ascii=False, sort_keys=True, indent=2))
    elif issues:
        for issue in issues:
            print(f"ERROR [{issue.code}] {issue.message} ({issue.path})", file=sys.stderr)
    else:
        print("OK: Tool registry valid; authority=tool-metadata-only; no execution or confirmation authority.")
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
