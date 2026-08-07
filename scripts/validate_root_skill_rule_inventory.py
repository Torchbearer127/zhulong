#!/usr/bin/env python3
"""Offline, read-only validation for the root Skill rule-carrier inventory."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any


PRODUCTION_TYPES = {
    "production_schema",
    "production_validator",
    "production_gate",
    "fixed_wrapper",
}
CATALOG_PATH = "assets/context-catalog.json"
SCHEMA_PATH = "assets/schemas/root-skill-rule-inventory.schema.json"
ALLOWED_PATH = re.compile(
    r"^(?:skills/zhulong/SKILL\.md|"
    r"assets/references/[A-Za-z0-9][A-Za-z0-9._-]*|"
    r"assets/schemas/[A-Za-z0-9][A-Za-z0-9._-]*|"
    r"scripts/[A-Za-z0-9][A-Za-z0-9._-]*|"
    r"docs/runner-contracts/[A-Za-z0-9][A-Za-z0-9._-]*)$"
)


def issue(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def safe_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or "://" in value:
        return False
    pure = PurePosixPath(value)
    return (
        not pure.is_absolute()
        and ".." not in pure.parts
        and "." not in pure.parts
        and ALLOWED_PATH.fullmatch(value) is not None
    )


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def carrier_file(root: Path, relative: str) -> Path:
    """Resolve the canonical source Skill path in source or installed layouts."""
    if relative == "skills/zhulong/SKILL.md" and not (root / relative).exists() and (root / "SKILL.md").exists():
        return root / "SKILL.md"
    return root / relative


def schema_shape_errors(data: object) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    if not isinstance(data, dict) or set(data) != {"schema_version", "inventory_id", "rules"}:
        return [issue("ROOT_RULE_INVENTORY_SCHEMA_INVALID", "$", "Inventory root fields are invalid.")]
    if data.get("schema_version") != 1 or data.get("inventory_id") != "zhulong-root-skill-rules":
        errors.append(issue("ROOT_RULE_INVENTORY_SCHEMA_INVALID", "$", "Inventory identity is invalid."))
    rules = data.get("rules")
    if not isinstance(rules, list) or len(rules) < 14:
        errors.append(issue("ROOT_RULE_INVENTORY_SCHEMA_INVALID", "$.rules", "At least 14 rule records are required."))
        return errors
    allowed_rule = {
        "rule_id", "source_scope", "rule_class", "disposition", "target",
        "carriers", "rationale", "residual_boundary",
    }
    allowed_carrier = {"type", "path", "symbol"}
    allowed_types = PRODUCTION_TYPES | {"root_kernel", "reference", "selftest"}
    for index, rule in enumerate(rules):
        base = f"$.rules[{index}]"
        if not isinstance(rule, dict) or set(rule) != allowed_rule:
            errors.append(issue("ROOT_RULE_INVENTORY_SCHEMA_INVALID", base, "Rule fields are invalid."))
            continue
        if not re.fullmatch(r"ZR-[A-Z0-9][A-Z0-9-]{2,39}", str(rule.get("rule_id", ""))):
            errors.append(issue("ROOT_RULE_INVENTORY_SCHEMA_INVALID", f"{base}.rule_id", "Rule id is invalid."))
        if rule.get("rule_class") not in {"hard_constraint", "phase_protocol", "operational_guidance"}:
            errors.append(issue("ROOT_RULE_INVENTORY_SCHEMA_INVALID", f"{base}.rule_class", "Rule class is invalid."))
        if rule.get("disposition") not in {"retain_kernel", "move_to_reference"}:
            errors.append(issue("ROOT_RULE_INVENTORY_SCHEMA_INVALID", f"{base}.disposition", "Disposition is invalid."))
        for field, minimum, maximum in (
            ("source_scope", 3, 240),
            ("rationale", 8, 500),
            ("residual_boundary", 8, 500),
        ):
            value = rule.get(field)
            if not isinstance(value, str) or not minimum <= len(value) <= maximum:
                errors.append(issue("ROOT_RULE_INVENTORY_SCHEMA_INVALID", f"{base}.{field}", "Rule text field is invalid."))
        target = rule.get("target")
        if not isinstance(target, dict) or set(target) != {"path", "section"}:
            errors.append(issue("ROOT_RULE_INVENTORY_SCHEMA_INVALID", f"{base}.target", "Target is invalid."))
        elif not isinstance(target.get("section"), str) or not 2 <= len(target["section"]) <= 160:
            errors.append(issue("ROOT_RULE_INVENTORY_SCHEMA_INVALID", f"{base}.target.section", "Target section is invalid."))
        carriers = rule.get("carriers")
        if not isinstance(carriers, list) or not carriers:
            errors.append(issue("ROOT_RULE_INVENTORY_EMPTY_CARRIERS", f"{base}.carriers", "At least one carrier is required."))
            continue
        for carrier_index, carrier in enumerate(carriers):
            carrier_path = f"{base}.carriers[{carrier_index}]"
            if not isinstance(carrier, dict) or not set(carrier).issubset(allowed_carrier) or not {"type", "path"}.issubset(carrier):
                errors.append(issue("ROOT_RULE_INVENTORY_SCHEMA_INVALID", carrier_path, "Carrier fields are invalid."))
                continue
            if carrier.get("type") not in allowed_types:
                errors.append(issue("ROOT_RULE_INVENTORY_UNKNOWN_CARRIER", f"{carrier_path}.type", "Carrier type is invalid."))
            if carrier.get("type") in PRODUCTION_TYPES and not carrier.get("symbol"):
                errors.append(issue("ROOT_RULE_INVENTORY_SYMBOL_REQUIRED", f"{carrier_path}.symbol", "Production carrier symbol is required."))
            if "symbol" in carrier and (not isinstance(carrier["symbol"], str) or not 2 <= len(carrier["symbol"]) <= 200):
                errors.append(issue("ROOT_RULE_INVENTORY_SCHEMA_INVALID", f"{carrier_path}.symbol", "Carrier symbol is invalid."))
    return errors


def validate(skill_root: Path, inventory_path: Path) -> tuple[list[dict[str, str]], int]:
    errors: list[dict[str, str]] = []
    try:
        data = load_json(inventory_path)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return [issue("ROOT_RULE_INVENTORY_JSON_INVALID", "$", "Inventory JSON could not be read.")], 0
    errors.extend(schema_shape_errors(data))
    if errors:
        return errors, len(data.get("rules", [])) if isinstance(data, dict) and isinstance(data.get("rules"), list) else 0

    root = skill_root.resolve(strict=True)
    catalog_paths: set[str] = set()
    try:
        catalog = load_json(root / CATALOG_PATH)
        catalog_paths = {module["path"] for module in catalog["modules"]}
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        errors.append(issue("ROOT_RULE_INVENTORY_CATALOG_INVALID", "$", "Context catalog could not be read."))

    seen: set[str] = set()
    rules = data["rules"]
    for index, rule in enumerate(rules):
        base = f"$.rules[{index}]"
        rule_id = rule["rule_id"]
        if rule_id in seen:
            errors.append(issue("ROOT_RULE_INVENTORY_DUPLICATE_ID", f"{base}.rule_id", "Rule id must be unique."))
        seen.add(rule_id)

        target = rule["target"]
        if not safe_relative_path(target["path"]):
            errors.append(issue("ROOT_RULE_INVENTORY_PATH_UNSAFE", f"{base}.target.path", "Target path is unsafe."))
        expected_path = "skills/zhulong/SKILL.md" if rule["disposition"] == "retain_kernel" else target["path"]
        if target["path"] != expected_path:
            errors.append(issue("ROOT_RULE_INVENTORY_DISPOSITION_CONFLICT", f"{base}.target.path", "Disposition and target path conflict."))
        if rule["disposition"] == "move_to_reference" and target["path"] not in catalog_paths:
            errors.append(issue("ROOT_RULE_INVENTORY_REFERENCE_NOT_CATALOGED", f"{base}.target.path", "Moved rule reference is not in the context catalog."))

        carrier_types = {carrier["type"] for carrier in rule["carriers"]}
        if rule["disposition"] == "retain_kernel" and "root_kernel" not in carrier_types:
            errors.append(issue("ROOT_RULE_INVENTORY_KERNEL_CARRIER_MISSING", f"{base}.carriers", "Retained rule requires a root kernel carrier."))
        if rule["disposition"] == "move_to_reference" and "reference" not in carrier_types:
            errors.append(issue("ROOT_RULE_INVENTORY_REFERENCE_CARRIER_MISSING", f"{base}.carriers", "Moved rule requires a reference carrier."))
        if rule["rule_class"] == "hard_constraint" and rule["disposition"] == "move_to_reference" and not (carrier_types & PRODUCTION_TYPES):
            errors.append(issue("ROOT_RULE_INVENTORY_PRODUCTION_CARRIER_MISSING", f"{base}.carriers", "Moved hard constraint requires a production carrier."))

        for carrier_index, carrier in enumerate(rule["carriers"]):
            rel = carrier["path"]
            carrier_base = f"{base}.carriers[{carrier_index}]"
            if not safe_relative_path(rel):
                errors.append(issue("ROOT_RULE_INVENTORY_PATH_UNSAFE", f"{carrier_base}.path", "Carrier path is unsafe."))
                continue
            candidate = carrier_file(root, rel)
            try:
                if candidate.is_symlink():
                    raise ValueError
                resolved = candidate.resolve(strict=True)
                if os.path.commonpath([str(root), str(resolved)]) != str(root) or not resolved.is_file():
                    raise ValueError
            except (OSError, ValueError):
                errors.append(issue("ROOT_RULE_INVENTORY_CARRIER_INVALID", f"{carrier_base}.path", "Carrier must be a regular in-root file."))
                continue
            symbol = carrier.get("symbol")
            if symbol:
                try:
                    text = resolved.read_text(encoding="utf-8")
                except (OSError, UnicodeError):
                    errors.append(issue("ROOT_RULE_INVENTORY_CARRIER_INVALID", f"{carrier_base}.path", "Carrier must be readable text."))
                    continue
                if symbol not in text:
                    errors.append(issue("ROOT_RULE_INVENTORY_SYMBOL_MISSING", f"{carrier_base}.symbol", "Declared carrier symbol was not found."))
    return errors, len(rules)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skill-root", required=True)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    skill_root = Path(args.skill_root)
    inventory_path = Path(args.inventory)
    if not inventory_path.is_absolute():
        inventory_path = skill_root / inventory_path
    errors, count = validate(skill_root, inventory_path)
    result = {
        "ok": not errors,
        "rule_count": count,
        "issue_codes": sorted({item["code"] for item in errors}),
        "issues": errors,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    elif errors:
        for item in errors:
            print(f"{item['code']} {item['path']}: {item['message']}", file=sys.stderr)
    else:
        print(f"Root Skill rule inventory valid: {count} rules")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
