#!/usr/bin/env python3
"""Create a deterministic, advisory-only context plan from local repo facts."""
from __future__ import annotations
import argparse, json, os, tempfile
from pathlib import Path
from typing import Any
from context_catalog import BUG_CLASSES, NON_CLAIMS, PHASES, canonical_digest, load_validated_catalog
from plan_security_toolchain import detect_attack_surface, detect_stack

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plan recommended Zhulong reference context without loading references.")
    parser.add_argument("--target-dir", required=True); parser.add_argument("--phase", required=True, choices=PHASES)
    parser.add_argument("--bug-class", action="append", default=[]); parser.add_argument("--catalog")
    parser.add_argument("--output"); parser.add_argument("--overwrite", action="store_true"); parser.add_argument("--json", action="store_true")
    return parser.parse_args()

def locations(catalog_override: str | None) -> tuple[Path, Path, Path]:
    root = Path(__file__).resolve().parent.parent; catalog = Path(catalog_override).expanduser() if catalog_override else root / "assets/context-catalog.json"
    return root, catalog, root / "assets/schemas/context-catalog.schema.json"

def normalized_bug_classes(values: list[str]) -> list[str]:
    result = sorted(set(value.strip().lower() for value in values if value.strip()))
    unknown = sorted(set(result) - set(BUG_CLASSES))
    if unknown: raise ValueError("unknown bug class: " + ", ".join(unknown))
    return result

def matches(module: dict[str, Any], facts: dict[str, list[str]]) -> list[str]:
    result: list[str] = []
    for key, prefix in (("stacks", "stack"), ("attack_surface_hints", "attack_surface"), ("bug_classes", "bug_class")):
        configured = set(module.get(key, []))
        matched = sorted(configured & set(facts["detected_stack" if key == "stacks" else key]))
        for value in matched:
            result.append(f"{prefix}:{value}")
    return result

def item(module: dict[str, Any], reason_code: str, matched: list[str]) -> dict[str, Any]:
    return {"id": module["id"], "path": module["path"], "reason_code": reason_code, "matched_selectors": matched}

def build_plan(catalog: dict[str, Any], phase: str, facts: dict[str, list[str]]) -> dict[str, Any]:
    groups = {"mandatory": [], "optional": [], "deferred": []}
    for module in catalog["modules"]:
        if phase not in module["phases"]: continue
        if module["selection_policy"] == "baseline": groups["mandatory"].append(item(module, "PHASE_BASELINE", [])); continue
        selected = matches(module, facts)
        if selected: groups["optional"].append(item(module, module["reason_code"], selected))
        else: groups["deferred"].append(item(module, "PHASE_RELEVANT_NO_SELECTOR_MATCH", []))
    for values in groups.values(): values.sort(key=lambda value: (value["id"], value["path"]))
    return {"schema_version": 1, "authority": "recommended_context_only", "phase": phase,
            "catalog": {"id": catalog["catalog_id"], "version": catalog["catalog_version"], "digest": canonical_digest(catalog)},
            "input_facts": facts, **groups, "non_claims": NON_CLAIMS}

def atomic_write(path: Path, data: bytes, overwrite: bool) -> None:
    if path.is_symlink(): raise ValueError("output path must not be a symlink")
    if path.exists() and not overwrite: raise ValueError("output already exists; use --overwrite to replace it")
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink(): raise ValueError("output parent must be an existing non-symlink directory")
    descriptor, temp_name = tempfile.mkstemp(prefix=".context-plan.", dir=parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try: os.unlink(temp_name)
        except FileNotFoundError: pass
        raise

def main() -> int:
    args = parse_args(); target = Path(args.target_dir).expanduser().resolve()
    if not target.is_dir(): raise SystemExit("target directory does not exist")
    try: bugs = normalized_bug_classes(args.bug_class)
    except ValueError as exc: raise SystemExit(str(exc))
    root, catalog_path, schema_path = locations(args.catalog); catalog, issues = load_validated_catalog(root, catalog_path, schema_path)
    if issues or catalog is None: raise SystemExit("Context Catalog validation failed closed: " + ", ".join(item.code for item in issues))
    facts = {"detected_stack": detect_stack(target), "attack_surface_hints": detect_attack_surface(target), "bug_classes": bugs}
    plan = build_plan(catalog, args.phase, facts); encoded = (json.dumps(plan, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if args.output:
        try: atomic_write(Path(args.output).expanduser(), encoded, args.overwrite)
        except ValueError as exc: raise SystemExit(str(exc))
    if args.json or not args.output: print(encoded.decode("utf-8"), end="")
    return 0
if __name__ == "__main__": raise SystemExit(main())
