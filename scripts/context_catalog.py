"""Shared, offline helpers for the advisory context catalog and plan."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PHASES = ("intake", "recon", "candidate_generation", "verification", "severity_escalation", "packaging", "finalization", "variant_discovery")
STACKS = ("generic", "node", "python", "rust", "go", "java", "php", "docker")
SURFACES = ("api", "auth", "cmd", "controller", "controllers", "docker-compose", "go-web", "graphql", "http-api", "java-web", "node-library", "node-web", "php", "php-swoole", "php-web", "python-library", "python-web", "route", "router", "routes", "ssrf-sinks")
BUG_CLASSES = ("ssrf", "path-traversal", "prototype-pollution")
NON_CLAIMS = [
    "does not prove an Agent read or used a module",
    "does not execute tools or references",
    "does not create evidence or confirm findings",
    "does not replace validators, gates, or root Skill constraints",
]
NON_AUTHORITY_STATEMENT = (
    "This catalog recommends local reading context only. It does not grant read, execution, "
    "confirmation, promotion, or completion authority."
)


@dataclass(frozen=True)
class Issue:
    code: str
    path: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


def add(issues: list[Issue], code: str, path: str, message: str) -> None:
    issue = Issue(code, path, message)
    if issue not in issues:
        issues.append(issue)


def load_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, str(exc)


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def safe_reference_path(raw: Any) -> bool:
    if not isinstance(raw, str) or not raw.startswith("assets/references/"):
        return False
    if raw.startswith(("/", "~")) or "\\" in raw or "://" in raw or "\x00" in raw or re.match(r"^[A-Za-z]:", raw):
        return False
    parts = raw.split("/")
    return all(part not in {"", ".", ".."} for part in parts)


def reference_scope_category(raw: str) -> str | None:
    """Return the closed forbidden category for a safe reference basename, if any."""
    basename = raw.rsplit("/", 1)[-1].lower()
    if re.search(r"(?:^|[-_.])dogfood(?:$|[-_.])", basename):
        return "dogfood artifact"
    if basename.endswith(("-template.md", "-template.json")):
        return "machine-input template"
    if basename.endswith(".example.json"):
        return "example JSON"
    return None


def schema_errors(value: Any, rule: dict[str, Any], schema: dict[str, Any], path: str = "$") -> list[tuple[str, str]]:
    if "$ref" in rule:
        ref = str(rule["$ref"])
        if not ref.startswith("#/$defs/"):
            return [(path, "uses an unsupported schema reference")]
        return schema_errors(value, schema["$defs"][ref.rsplit("/", 1)[-1]], schema, path)
    errors: list[tuple[str, str]] = []
    typ = rule.get("type")
    types = typ if isinstance(typ, list) else [typ]
    if typ is not None:
        matches = {"object": isinstance(value, dict), "array": isinstance(value, list), "string": isinstance(value, str), "integer": type(value) is int, "boolean": type(value) is bool}
        if not any(matches.get(item, False) for item in types):
            return [(path, "has an unsupported type")]
    if "const" in rule and value != rule["const"]:
        errors.append((path, "has an unsupported value"))
    if "enum" in rule and value not in rule["enum"]:
        errors.append((path, "has an unsupported value"))
    if isinstance(value, dict):
        props = rule.get("properties", {})
        for key in rule.get("required", []):
            if key not in value:
                errors.append((f"{path}.{key}", "is required"))
        if rule.get("additionalProperties") is False:
            for key in value:
                if key not in props:
                    errors.append((f"{path}.{key}", "is not an allowed property"))
        for key, child in props.items():
            if key in value and isinstance(child, dict):
                errors.extend(schema_errors(value[key], child, schema, f"{path}.{key}"))
    if isinstance(value, list):
        if len(value) < int(rule.get("minItems", 0)):
            errors.append((path, "has too few items"))
        if rule.get("uniqueItems") and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            errors.append((path, "contains duplicate items"))
        if isinstance(rule.get("items"), dict):
            for index, item in enumerate(value):
                errors.extend(schema_errors(item, rule["items"], schema, f"{path}[{index}]"))
    if isinstance(value, str):
        if len(value) < int(rule.get("minLength", 0)):
            errors.append((path, "is too short"))
        if "pattern" in rule and re.fullmatch(str(rule["pattern"]), value) is None:
            errors.append((path, "has an invalid format"))
    return errors


def validate_catalog(catalog: Any, schema: dict[str, Any], skill_root: Path) -> list[Issue]:
    issues: list[Issue] = []
    for path, message in schema_errors(catalog, schema, schema):
        add(issues, "CONTEXT_CATALOG_SCHEMA_INVALID", path, message)
    if not isinstance(catalog, dict):
        return issues
    if catalog.get("authority") != "recommended_context_only":
        add(issues, "CONTEXT_CATALOG_AUTHORITY_INVALID", "$.authority", "Catalog authority must be recommendation-only.")
    if catalog.get("non_authority_statement") != NON_AUTHORITY_STATEMENT:
        add(issues, "CONTEXT_CATALOG_AUTHORITY_INVALID", "$.non_authority_statement", "Catalog must state its non-authority boundary.")
    seen_ids: set[str] = set(); seen_paths: set[str] = set()
    root_real = skill_root.resolve()
    for index, module in enumerate(catalog.get("modules", [])):
        path = f"$.modules[{index}]"
        if not isinstance(module, dict):
            continue
        module_id = module.get("id"); ref = module.get("path")
        if isinstance(module_id, str):
            if module_id in seen_ids: add(issues, "CONTEXT_CATALOG_DUPLICATE_ID", f"{path}.id", "Module IDs must be globally unique.")
            seen_ids.add(module_id)
        if isinstance(ref, str):
            if ref in seen_paths: add(issues, "CONTEXT_CATALOG_DUPLICATE_PATH", f"{path}.path", "Module paths must be unique.")
            seen_paths.add(ref)
        if not safe_reference_path(ref):
            add(issues, "CONTEXT_REFERENCE_PATH_UNSAFE", f"{path}.path", "Reference paths must be safe assets/references relative POSIX paths.")
            continue
        category = reference_scope_category(ref)
        if category is not None:
            add(issues, "CONTEXT_REFERENCE_SCOPE_FORBIDDEN", f"{path}.path", f"Reference basename is a forbidden {category}.")
            continue
        candidate = skill_root.joinpath(*ref.split("/"))
        try: info = os.lstat(candidate)
        except FileNotFoundError:
            add(issues, "CONTEXT_REFERENCE_MISSING", f"{path}.path", "Catalog reference does not exist in the skill layout."); continue
        except OSError:
            add(issues, "CONTEXT_REFERENCE_PATH_UNSAFE", f"{path}.path", "Catalog reference cannot be inspected safely."); continue
        if stat.S_ISLNK(info.st_mode):
            add(issues, "CONTEXT_REFERENCE_SYMLINK", f"{path}.path", "Catalog references may not be symlinks."); continue
        if not stat.S_ISREG(info.st_mode):
            add(issues, "CONTEXT_REFERENCE_TYPE_INVALID", f"{path}.path", "Catalog references must be regular files."); continue
        try: candidate.resolve(strict=True).relative_to(root_real)
        except (OSError, ValueError): add(issues, "CONTEXT_REFERENCE_PATH_UNSAFE", f"{path}.path", "Catalog reference resolves outside the skill root.")
        if module.get("authority") != "recommended_context_only":
            add(issues, "CONTEXT_MODULE_AUTHORITY_INVALID", f"{path}.authority", "Modules must remain recommendation-only.")
    return issues


def load_validated_catalog(skill_root: Path, catalog_path: Path, schema_path: Path) -> tuple[dict[str, Any] | None, list[Issue]]:
    catalog, catalog_error = load_json(catalog_path); schema, schema_error = load_json(schema_path); issues: list[Issue] = []
    if catalog_error: add(issues, "CONTEXT_CATALOG_JSON_INVALID", "$", "Catalog JSON cannot be read.")
    if schema_error or not isinstance(schema, dict): add(issues, "CONTEXT_CATALOG_SCHEMA_UNAVAILABLE", "$", "Catalog schema cannot be read.")
    if issues: return None, issues
    issues.extend(validate_catalog(catalog, schema, skill_root))
    return (catalog if isinstance(catalog, dict) and not issues else None), issues
