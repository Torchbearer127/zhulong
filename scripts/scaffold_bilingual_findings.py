#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any


LANGUAGE_ALIASES = {
    "zh": "zh-CN",
    "zh-cn": "zh-CN",
    "zh-hans": "zh-CN",
    "cn": "zh-CN",
    "chinese": "zh-CN",
    "中文": "zh-CN",
    "en": "en-US",
    "en-us": "en-US",
    "en-gb": "en-US",
    "english": "en-US",
    "英文": "en-US",
}


def normalize_language(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "zh-CN"
    key = text.lower()
    normalized = LANGUAGE_ALIASES.get(key, text)
    if normalized not in {"zh-CN", "en-US"}:
        raise SystemExit(f"Unsupported language: {value}. Use zh-CN or en-US.")
    return normalized


def localized_key(base_key: str, language: str) -> str:
    return f"{base_key}_{'en' if language == 'en-US' else 'zh'}"


def copy_localized_field(data: dict[str, Any], key: str, language: str) -> None:
    if key not in data:
        return
    target_key = localized_key(key, language)
    if target_key in data:
        return
    data[target_key] = copy.deepcopy(data[key])


def maybe_add_placeholder(data: dict[str, Any], key: str, language: str) -> None:
    target_key = localized_key(key, language)
    if target_key in data:
        return
    value = data.get(key)
    if isinstance(value, list):
        data[target_key] = []
    else:
        data[target_key] = ""


def scaffold_finding(
    finding: dict[str, Any],
    primary_language: str,
    add_secondary_placeholders: bool,
) -> dict[str, Any]:
    result = copy.deepcopy(finding)
    secondary_language = "en-US" if primary_language == "zh-CN" else "zh-CN"
    result["report_language"] = primary_language

    top_level_fields = [
        "title",
        "filename",
        "vuln_type",
        "description",
        "analysis",
        "final_verdict",
    ]
    for key in top_level_fields:
        copy_localized_field(result, key, primary_language)
        if add_secondary_placeholders:
            maybe_add_placeholder(result, key, secondary_language)

    impact = result.get("impact")
    if isinstance(impact, dict):
        for key in ("affected_versions", "extra"):
            copy_localized_field(impact, key, primary_language)
            if add_secondary_placeholders:
                maybe_add_placeholder(impact, key, secondary_language)

    cvss = result.get("cvss")
    if isinstance(cvss, dict):
        copy_localized_field(cvss, "rationale", primary_language)
        if add_secondary_placeholders:
            maybe_add_placeholder(cvss, "rationale", secondary_language)

    for item in result.get("code_context", []):
        if isinstance(item, dict):
            for key in ("summary", "explanation"):
                copy_localized_field(item, key, primary_language)
                if add_secondary_placeholders:
                    maybe_add_placeholder(item, key, secondary_language)

    for item in result.get("reproduction", []):
        if isinstance(item, dict):
            for key in ("title", "details", "detail", "expected", "observed", "notes", "note", "results", "result"):
                copy_localized_field(item, key, primary_language)
                if add_secondary_placeholders:
                    maybe_add_placeholder(item, key, secondary_language)

    for item in result.get("environment_files", []):
        if isinstance(item, dict):
            for key in ("purpose", "note"):
                copy_localized_field(item, key, primary_language)
                if add_secondary_placeholders:
                    maybe_add_placeholder(item, key, secondary_language)

    for item in result.get("attachments", []):
        if isinstance(item, dict):
            for key in ("purpose", "note"):
                copy_localized_field(item, key, primary_language)
                if add_secondary_placeholders:
                    maybe_add_placeholder(item, key, secondary_language)

    return result


def transform_payload(payload: Any, primary_language: str, add_secondary_placeholders: bool) -> Any:
    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        new_payload = copy.deepcopy(payload)
        new_payload["findings"] = [
            scaffold_finding(item, primary_language, add_secondary_placeholders)
            if isinstance(item, dict) else item
            for item in payload["findings"]
        ]
        if isinstance(new_payload.get("report_language"), str) or "report_language" not in new_payload:
            new_payload["report_language"] = primary_language
        if isinstance(new_payload.get("output_language"), str) or "output_language" not in new_payload:
            new_payload["output_language"] = primary_language
        return new_payload
    if isinstance(payload, list):
        return [
            scaffold_finding(item, primary_language, add_secondary_placeholders)
            if isinstance(item, dict) else item
            for item in payload
        ]
    if isinstance(payload, dict):
        return scaffold_finding(payload, primary_language, add_secondary_placeholders)
    raise SystemExit("Input JSON must be an object, an array, or an object with a findings array.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Copy the current-language findings fields into bilingual-ready *_zh or *_en keys."
    )
    parser.add_argument("--input", required=True, help="Path to the source findings JSON.")
    parser.add_argument("--output", required=True, help="Path to write the scaffolded JSON.")
    parser.add_argument(
        "--primary-language",
        default="zh-CN",
        help="Language of the existing generic content: zh-CN or en-US.",
    )
    parser.add_argument(
        "--add-secondary-placeholders",
        action="store_true",
        help="Also create empty placeholder fields for the opposite language.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()
    primary_language = normalize_language(args.primary_language)

    payload = json.loads(input_path.read_text(encoding="utf-8"))
    transformed = transform_payload(payload, primary_language, args.add_secondary_placeholders)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(transformed, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote bilingual-ready findings JSON to {output_path}")


if __name__ == "__main__":
    main()
