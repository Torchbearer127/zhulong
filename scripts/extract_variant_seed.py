#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, NamedTuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from validate_report_bundle import validate_variant_seed_card  # type: ignore


FINAL_REQUIRED_FIELDS = ("root_cause", "source_pattern", "sink_pattern", "docker_success_oracle")
ABSOLUTE_TEXT_PATTERNS = [
    re.compile(r"/Users/[^/\s`'\"<>]+(?:/[^\s`'\"<>]+)*"),
    re.compile(r"/home/[^/\s`'\"<>]+(?:/[^\s`'\"<>]+)*"),
    re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/][^\s`'\"<>]*"),
    re.compile(r"file://[^\s`'\"<>]+"),
]
SPACE_PATTERN = re.compile(r"\s+")
SLUG_SAFE_PATTERN = re.compile(r"[^A-Za-z0-9_.-]+")

FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "bug_class": (
        "bug_class",
        "vulnerability_type",
        "vulnerability_class",
        "category",
        "cwe",
        "weakness",
        "title",
    ),
    "root_cause": (
        "root_cause",
        "root_cause_en",
        "root_cause_zh",
        "cause",
        "analysis.root_cause",
        "technical_root_cause",
    ),
    "source_pattern": (
        "source_pattern",
        "attacker_controlled_source",
        "attacker_input",
        "source",
        "input_source",
        "user_input",
        "attack_source",
    ),
    "propagation_pattern": (
        "propagation_pattern",
        "propagation_path",
        "trigger_path",
        "call_chain",
        "data_flow",
        "flow",
    ),
    "sink_pattern": (
        "sink_pattern",
        "sink",
        "sink_family",
        "dangerous_sink",
        "dangerous_behavior",
        "affected_sink",
    ),
    "missing_constraint_pattern": (
        "missing_constraint_pattern",
        "missing_constraint",
        "missing_validation",
        "missing_check",
        "validation_gap",
        "mitigation_gap",
    ),
    "trigger_condition": (
        "trigger_condition",
        "attack_precondition",
        "precondition",
        "exploit_condition",
        "conditions",
    ),
}

HEADING_ALIASES: dict[str, tuple[str, ...]] = {
    "root_cause": (
        "root cause",
        "technical root cause",
        "cause",
        "漏洞根因",
        "根因",
        "漏洞原因",
    ),
    "source_pattern": (
        "attacker input",
        "attacker-controlled input",
        "controllable input",
        "source pattern",
        "source",
        "攻击者输入",
        "攻击者可控",
        "可控输入",
        "入口",
        "来源",
    ),
    "propagation_pattern": (
        "propagation",
        "trigger path",
        "call chain",
        "data flow",
        "传播路径",
        "触发路径",
        "触发链",
        "调用链",
        "数据流",
    ),
    "sink_pattern": (
        "sink",
        "sink pattern",
        "dangerous sink",
        "dangerous operation",
        "dangerous behavior",
        "危险函数",
        "危险操作",
        "危险行为",
        "汇聚点",
        "危险 API",
        "危险API",
    ),
    "missing_constraint_pattern": (
        "missing constraint",
        "missing validation",
        "missing check",
        "validation gap",
        "缺失约束",
        "缺少校验",
        "缺失校验",
    ),
    "trigger_condition": (
        "trigger condition",
        "precondition",
        "attack condition",
        "利用条件",
        "触发条件",
        "攻击条件",
        "前提条件",
    ),
}

NATURAL_LANGUAGE_FIELDS = ("analysis", "analysis_en")
CODE_CONTEXT_SUMMARY_FIELDS = ("summary", "summary_en")
PREFIX_PATTERN = re.compile(r"^\s*(?:[-*]\s*)?(?P<label>[^:：]{1,80})[:：]\s*(?P<body>.+?)\s*$")
SOURCE_CONTROL_PATTERN = re.compile(
    r"\b(attacker|attacker-controlled|user[- ]controlled|controlled by (?:the )?user|"
    r"untrusted|external input|request|http|upload|webhook|low[- ]privilege|"
    r"authenticated user|anonymous user|cli argument|command[- ]line argument|user input)\b|"
    r"攻击者|用户(?:完全)?控制|用户可控|不可信|外部输入|请求|上传|低权限|匿名用户|命令行参数",
    re.IGNORECASE,
)
ROOT_CAUSE_SIGNAL_PATTERN = re.compile(
    r"\b(root cause|missing|lack(?:s|ing)?|without|unchecked|unvalidated|unsafe|"
    r"no canonicali[sz]ation|no validation|fails? to validate|trusts? .* input|"
    r"attacker-controlled .* reaches?)\b|"
    r"根因|缺失|缺少|未(?:对|进行|限制|校验|验证)|没有|直接(?:传递|调用|合并|信任)|校验(?:缺失|不足)",
    re.IGNORECASE,
)
SINK_SIGNAL_PATTERN = re.compile(
    r"\b(sink|api|exec|command|shell|fetch|request|http client|open-url|filesystem|"
    r"file read|file write|readfilesync|require\s*\(|eval|deseriali[sz]e|template|sql|"
    r"query|redirect|path traversal|dangerous (?:operation|behavior|sink))\b|"
    r"危险(?:函数|操作|行为|API)|汇聚点|文件读|文件写|任意文件|命令执行|代码执行|反序列化|模板|查询|重定向",
    re.IGNORECASE,
)
PROPAGATION_SIGNAL_PATTERN = re.compile(
    r"\b(trigger path|call chain|data flow|propagation|reaches?|passes? .* to|flows? .* to|"
    r"supplies? .* ->)\b|->|"
    r"触发路径|调用链|数据流|传播路径|传递给|流向|到达",
    re.IGNORECASE,
)
MISSING_CONSTRAINT_SIGNAL_PATTERN = re.compile(
    r"\b(missing validation|missing constraint|validation gap|missing check|without .* validation|"
    r"no .* check|does not (?:validate|restrict|canonicali[sz]e))\b|"
    r"缺失校验|缺少校验|缺失约束|未(?:校验|验证|限制|规范化)|没有.*检查|边界检查",
    re.IGNORECASE,
)
TRIGGER_CONDITION_SIGNAL_PATTERN = re.compile(
    r"\b(trigger condition|precondition|attack condition|when |if |enabled|authenticated)\b|"
    r"触发条件|利用条件|前提条件|需要|启用|认证",
    re.IGNORECASE,
)
BUG_CLASS_OR_TITLE_LABEL_PATTERN = re.compile(
    r"\b(bug[_ -]?class|vulnerability (?:type|class)|weakness|category|title)\b|"
    r"漏洞类型|漏洞类别|标题|题目",
    re.IGNORECASE,
)
BARE_BUG_CLASS_PATTERN = re.compile(
    r"^\s*(?:path traversal|ssrf|prototype pollution|redos|dos|xss|sqli|sql injection|"
    r"code execution|rce|arbitrary file read|arbitrary file write|路径遍历|原型污染|拒绝服务|代码执行)\s*$",
    re.IGNORECASE,
)


class NaturalHint(NamedTuple):
    field: str
    text: str
    source: str


class UnmappedHint(NamedTuple):
    source: str
    text: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Extract one Zhulong P6.2 Variant Seed Card from an existing confirmed "
            "bundle without searching for variants or running PoCs."
        )
    )
    parser.add_argument("--workspace-dir", required=True, help="Audit workspace root.")
    parser.add_argument("--bundle-dir", required=True, help="Bundle under <workspace-dir>/confirmed/.")
    parser.add_argument("--output", required=True, help="Final seed-card JSONL output path.")
    parser.add_argument("--draft-output", help="Optional draft JSONL path for incomplete extraction.")
    parser.add_argument("--seed-note-output", help="Optional seed-<slug>.md note path for incomplete extraction.")
    parser.add_argument("--allow-draft", action="store_true", help="Allow draft JSONL when final extraction is incomplete.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing output files.")
    return parser.parse_args()


def fail(message: str) -> None:
    raise SystemExit(f"EXTRACT VARIANT SEED FAILED: {message}")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def stable_slug(value: str) -> str:
    slug = SLUG_SAFE_PATTERN.sub("-", value.strip()).strip("-._").lower()
    return slug or "bundle"


def sanitize_text(value: str, *, max_len: int = 500) -> str:
    text = value.strip()
    for pattern in ABSOLUTE_TEXT_PATTERNS:
        text = pattern.sub("<local-absolute-path>", text)
    text = SPACE_PATTERN.sub(" ", text).strip()
    if len(text) > max_len:
        text = text[: max_len - 3].rstrip() + "..."
    return text


def scalar_text(value: Any) -> str:
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, (int, float, bool)):
        return sanitize_text(str(value))
    if isinstance(value, list):
        parts = [scalar_text(item) for item in value]
        return sanitize_text("; ".join(part for part in parts if part))
    if isinstance(value, dict):
        parts = [scalar_text(item) for item in value.values()]
        return sanitize_text("; ".join(part for part in parts if part))
    return ""


def value_at_path(data: Any, dotted: str) -> Any:
    current = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def extract_from_aliases(source: dict[str, Any], aliases: tuple[str, ...]) -> str:
    for alias in aliases:
        value = value_at_path(source, alias)
        text = scalar_text(value)
        if text:
            return text
    return ""


def iter_dicts(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        out = [value]
        for nested in value.values():
            out.extend(iter_dicts(nested))
        return out
    if isinstance(value, list):
        out: list[dict[str, Any]] = []
        for nested in value:
            out.extend(iter_dicts(nested))
        return out
    return []


def find_matching_finding(data: Any, verification: dict[str, Any], bundle_dir: Path) -> dict[str, Any]:
    candidates = iter_dicts(data)
    finding_slug = scalar_text(verification.get("finding_slug"))
    bundle_name = bundle_dir.name
    for candidate in candidates:
        candidate_slug = scalar_text(candidate.get("finding_slug") or candidate.get("slug") or candidate.get("id"))
        if finding_slug and candidate_slug == finding_slug:
            return candidate
    for candidate in candidates:
        candidate_slug = scalar_text(candidate.get("finding_slug") or candidate.get("slug") or candidate.get("id"))
        title = scalar_text(candidate.get("title") or candidate.get("title_en") or candidate.get("title_zh"))
        haystack = f"{candidate_slug} {title}"
        if finding_slug and finding_slug in haystack:
            return candidate
        if bundle_name and bundle_name in haystack:
            return candidate
    if isinstance(data, dict):
        return data
    return {}


def load_finding_sources(workspace_dir: Path, bundle_dir: Path, verification: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    sources: list[str] = []
    merged: dict[str, Any] = {}
    for path in (bundle_dir / "findings.json", workspace_dir / "confirmed" / "findings.json"):
        if not path.is_file():
            continue
        data = load_json(path)
        matched = find_matching_finding(data, verification, bundle_dir)
        if matched:
            merged.update(matched)
            sources.append(str(path.relative_to(workspace_dir)))
    return merged, sources


def parse_heading_sections(text: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        heading = ""
        if line.startswith("#"):
            heading = line.lstrip("#").strip(" :：")
        elif len(line) <= 80 and line.endswith((":", "：")):
            heading = line[:-1].strip()
        if heading:
            lowered = heading.lower()
            current = ""
            for field, aliases in HEADING_ALIASES.items():
                if any(alias.lower() in lowered for alias in aliases):
                    current = field
                    sections.setdefault(field, [])
                    break
            continue
        if current:
            sections.setdefault(current, []).append(line)
    return {field: sanitize_text(" ".join(lines)) for field, lines in sections.items() if lines}


def matching_heading_fields(label: str) -> list[str]:
    lowered = label.lower()
    matches: list[str] = []
    for field, aliases in HEADING_ALIASES.items():
        if any(alias.lower() in lowered for alias in aliases):
            matches.append(field)
    return matches


def normalize_hint_value(field: str, text: str, *, signal_text: str | None = None) -> str:
    value = sanitize_text(text, max_len=900)
    signal = sanitize_text(signal_text if signal_text is not None else text, max_len=900)
    if field == "source_pattern" and not SOURCE_CONTROL_PATTERN.search(signal):
        return ""
    if field == "sink_pattern" and not SINK_SIGNAL_PATTERN.search(signal):
        return ""
    if field == "root_cause" and not ROOT_CAUSE_SIGNAL_PATTERN.search(signal):
        return ""
    if field == "propagation_pattern" and not PROPAGATION_SIGNAL_PATTERN.search(signal):
        return ""
    if field == "missing_constraint_pattern" and not MISSING_CONSTRAINT_SIGNAL_PATTERN.search(signal):
        return ""
    if field == "trigger_condition" and not TRIGGER_CONDITION_SIGNAL_PATTERN.search(signal):
        return ""
    if field == "sink_pattern" and not re.search(
        r"\b(sink|api|dangerous behavior|file read|file write|path traversal|exec|command|fetch|request|"
        r"filesystem|redirect|eval|template|query)\b|危险行为|文件读|文件写|命令执行|重定向",
        value,
        re.IGNORECASE,
    ):
        value = "Sink/API dangerous behavior: " + value
    if field == "source_pattern" and not re.search(
        r"\b(attacker|user[- ]controlled|untrusted|request|http|upload|webhook|"
        r"low[- ]privilege|authenticated user|anonymous user|cli argument|user input)\b|"
        r"攻击者|用户可控|不可信|外部输入|请求|上传|低权限|匿名用户|命令行参数",
        value,
        re.IGNORECASE,
    ):
        value = "Attacker-controlled input: " + value
    return value


def classify_unprefixed_hint(text: str) -> list[str]:
    matches: list[str] = []
    if ROOT_CAUSE_SIGNAL_PATTERN.search(text):
        matches.append("root_cause")
    if SOURCE_CONTROL_PATTERN.search(text):
        matches.append("source_pattern")
    if SINK_SIGNAL_PATTERN.search(text):
        matches.append("sink_pattern")
    if PROPAGATION_SIGNAL_PATTERN.search(text):
        matches.append("propagation_pattern")
    if MISSING_CONSTRAINT_SIGNAL_PATTERN.search(text):
        matches.append("missing_constraint_pattern")
    if TRIGGER_CONDITION_SIGNAL_PATTERN.search(text):
        matches.append("trigger_condition")
    return matches


def classify_natural_hint(raw_text: str, source: str) -> tuple[NaturalHint | None, UnmappedHint | None]:
    text = sanitize_text(raw_text, max_len=900)
    if not text:
        return None, None

    prefixed = PREFIX_PATTERN.match(text)
    if prefixed:
        label = prefixed.group("label").strip()
        body = prefixed.group("body").strip()
        if BUG_CLASS_OR_TITLE_LABEL_PATTERN.search(label):
            return None, UnmappedHint(source, text)
        fields = matching_heading_fields(label)
        if len(fields) == 1:
            field = fields[0]
            value = normalize_hint_value(field, text, signal_text=body)
            if value:
                return NaturalHint(field, value, source), None
            if any(
                pattern.search(text)
                for pattern in (
                    ROOT_CAUSE_SIGNAL_PATTERN,
                    SOURCE_CONTROL_PATTERN,
                    SINK_SIGNAL_PATTERN,
                    PROPAGATION_SIGNAL_PATTERN,
                    MISSING_CONSTRAINT_SIGNAL_PATTERN,
                    TRIGGER_CONDITION_SIGNAL_PATTERN,
                )
            ):
                return None, UnmappedHint(source, text)
            return None, None
        if len(fields) > 1:
            return None, UnmappedHint(source, text)
        if body and any(alias.lower() in label.lower() for aliases in HEADING_ALIASES.values() for alias in aliases):
            return None, UnmappedHint(source, text)

    if BARE_BUG_CLASS_PATTERN.match(text):
        return None, UnmappedHint(source, text)

    fields = classify_unprefixed_hint(text)
    if len(fields) == 1:
        field = fields[0]
        value = normalize_hint_value(field, text)
        if value:
            return NaturalHint(field, value, source), None
    if len(fields) > 1:
        return None, UnmappedHint(source, text)
    if BUG_CLASS_OR_TITLE_LABEL_PATTERN.search(text):
        return None, UnmappedHint(source, text)
    return None, None


def collect_natural_language_hints(finding: dict[str, Any]) -> tuple[dict[str, str], list[UnmappedHint]]:
    hints: dict[str, str] = {}
    unmapped: list[UnmappedHint] = []

    def add(raw: Any, source: str) -> None:
        text = scalar_text(raw)
        if not text:
            return
        hint, missed = classify_natural_hint(text, source)
        if hint and hint.field not in hints:
            hints[hint.field] = hint.text
        elif missed:
            unmapped.append(missed)

    for field in NATURAL_LANGUAGE_FIELDS:
        value = finding.get(field)
        if isinstance(value, list):
            for index, item in enumerate(value):
                add(item, f"findings.json:{field}[{index}]")
        elif value is not None:
            add(value, f"findings.json:{field}")

    code_context = finding.get("code_context")
    if isinstance(code_context, list):
        for index, item in enumerate(code_context):
            if not isinstance(item, dict):
                continue
            for summary_field in CODE_CONTEXT_SUMMARY_FIELDS:
                add(item.get(summary_field), f"findings.json:code_context[{index}].{summary_field}")
    elif isinstance(code_context, dict):
        for summary_field in CODE_CONTEXT_SUMMARY_FIELDS:
            add(code_context.get(summary_field), f"findings.json:code_context.{summary_field}")

    return hints, unmapped


def load_markdown_hints(workspace_dir: Path, bundle_dir: Path) -> tuple[dict[str, str], list[str]]:
    hints: dict[str, str] = {}
    sources: list[str] = []
    preferred_markers = (
        "reproduction",
        "supplement",
        "attachment",
        "index",
        "reviewer",
        "evidence",
        "impact",
        "复现",
        "补充",
        "附件",
        "目录",
        "审核",
        "证据",
        "影响",
    )
    for path in sorted(bundle_dir.glob("*.md")) + sorted((bundle_dir / "attachments").glob("*.md")):
        lowered = path.name.lower()
        if not any(marker in lowered for marker in preferred_markers):
            continue
        sections = parse_heading_sections(path.read_text(encoding="utf-8", errors="ignore"))
        if sections:
            for field, value in sections.items():
                hints.setdefault(field, value)
            sources.append(str(path.relative_to(workspace_dir)))
    return hints, sources


def default_negative_filters() -> list[str]:
    return [
        "tests/",
        "docs/",
        "examples/",
        "fixtures/",
        "generated workspaces such as security-research-*/",
        "confirmed/",
        "call sites with canonical validation or authorization before the sink",
        "already-mitigated call sites",
    ]


def build_oracle(verification: dict[str, Any]) -> str:
    pieces = ["Docker verification-evidence.json records verification_status=confirmed_in_docker"]
    for key in ("oracle_token", "observed_observation", "expected_observation"):
        text = scalar_text(verification.get(key))
        if text:
            pieces.append(f"{key}={text}")
    evidence_files = verification.get("evidence_files")
    if isinstance(evidence_files, list) and evidence_files:
        files = [scalar_text(item) for item in evidence_files[:5]]
        files = [item for item in files if item]
        if files:
            pieces.append("evidence_files=" + ", ".join(files))
    if len(pieces) == 1:
        return ""
    return sanitize_text("; ".join(pieces), max_len=900)


def build_seed_card(
    workspace_dir: Path,
    bundle_dir: Path,
    verification: dict[str, Any],
    finding: dict[str, Any],
    markdown_hints: dict[str, str],
) -> tuple[dict[str, Any], list[UnmappedHint]]:
    bundle_rel = bundle_dir.relative_to(workspace_dir).as_posix()
    finding_slug = scalar_text(verification.get("finding_slug")) or bundle_dir.name
    card: dict[str, Any] = {
        "schema_version": 1,
        "seed_id": f"seed-confirmed-{stable_slug(finding_slug)}",
        "confirmed_bundle_path": bundle_rel,
        "bug_class": "security vulnerability",
        "root_cause": "unknown",
        "source_pattern": "unknown",
        "propagation_pattern": "unknown",
        "sink_pattern": "unknown",
        "missing_constraint_pattern": "unknown",
        "trigger_condition": "unknown",
        "docker_success_oracle": build_oracle(verification) or "unknown",
        "search_scope": {
            "repository": "same-target-repository",
            "default": "exclude generated outputs and confirmed bundles",
        },
        "negative_filters": default_negative_filters(),
    }

    for field, aliases in FIELD_ALIASES.items():
        text = extract_from_aliases(finding, aliases)
        if text:
            card[field] = text
    for field, text in markdown_hints.items():
        if card.get(field) == "unknown" and text:
            card[field] = text

    natural_hints, unmapped_hints = collect_natural_language_hints(finding)
    for field, text in natural_hints.items():
        if card.get(field) == "unknown" and text:
            card[field] = text

    if not scalar_text(card.get("bug_class")) or card.get("bug_class") == "unknown":
        card["bug_class"] = scalar_text(finding.get("title")) or "security vulnerability"
    return card, unmapped_hints


def validate_final(card: dict[str, Any]) -> tuple[bool, str]:
    missing = [field for field in FINAL_REQUIRED_FIELDS if scalar_text(card.get(field)).lower() == "unknown"]
    if missing:
        return False, "missing final field(s): " + ", ".join(missing)
    try:
        validate_variant_seed_card(card, final=True)
    except SystemExit as exc:
        return False, str(exc)
    return True, ""


def write_jsonl(path: Path, records: list[dict[str, Any]], *, force: bool) -> None:
    if path.exists() and not force:
        fail(f"refusing to overwrite existing file without --force: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records)
    path.write_text(text, encoding="utf-8")


def write_draft_note(
    path: Path,
    card: dict[str, Any],
    verification: dict[str, Any],
    missing_reason: str,
    evidence_sources: list[str],
    unmapped_hints: list[UnmappedHint],
    *,
    force: bool,
) -> None:
    if path.exists() and not force:
        fail(f"refusing to overwrite existing file without --force: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    missing = [field for field in FINAL_REQUIRED_FIELDS if scalar_text(card.get(field)).lower() == "unknown"]
    lines = [
        f"# Variant Seed Draft: {card['seed_id']}",
        "",
        "Status: draft-only; no variant can be confirmed from this note.",
        "",
        f"Confirmed bundle path: `{card['confirmed_bundle_path']}`",
        "",
        "## Verification Evidence Summary",
        "",
        f"- verification_status: `{verification.get('verification_status')}`",
        f"- finding_slug: `{scalar_text(verification.get('finding_slug')) or 'unknown'}`",
        f"- oracle_token: `{scalar_text(verification.get('oracle_token')) or 'unknown'}`",
        f"- observed_observation: `{scalar_text(verification.get('observed_observation')) or 'unknown'}`",
        "",
        "## Missing Or Incomplete Fields",
        "",
        *(f"- `{field}`" for field in (missing or [missing_reason])),
        "",
        "## Candidate Evidence Sources",
        "",
        *(f"- `{source}`" for source in (evidence_sources or ["verification-evidence.json"])),
        "",
        "## Possible Unmapped Hints",
        "",
        *(
            f"- `{hint.source}`: {hint.text}"
            for hint in unmapped_hints[:8]
        ),
        *([] if unmapped_hints else ["- None recorded."]),
        "",
        "## Completion Checklist",
        "",
        "- Fill root cause from confirmed evidence, not vulnerability type alone.",
        "- Fill attacker-controlled source with explicit attacker/user/untrusted control.",
        "- Fill sink pattern with sink family/API or dangerous behavior.",
        "- Keep search scope bounded to the same target repository.",
        "- Validate the final card with `validate_report_bundle.py --variant-seed-card`.",
        "- Do not treat this draft as a confirmed variant or confirmed finding.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    args = parse_args()
    workspace_dir = Path(args.workspace_dir).expanduser().resolve()
    bundle_dir = Path(args.bundle_dir).expanduser().resolve()
    confirmed_dir = workspace_dir / "confirmed"
    if not workspace_dir.is_dir():
        fail(f"workspace directory does not exist: {workspace_dir}")
    if not is_relative_to(bundle_dir, confirmed_dir.resolve()) or bundle_dir == confirmed_dir.resolve():
        fail("bundle-dir must be inside workspace confirmed/ directory")
    if not bundle_dir.is_dir():
        fail(f"bundle directory does not exist: {bundle_dir}")

    verification_path = bundle_dir / "verification-evidence.json"
    if not verification_path.is_file():
        fail("missing verification-evidence.json")
    verification = load_json(verification_path)
    if not isinstance(verification, dict):
        fail("verification-evidence.json must be a JSON object")
    if verification.get("verification_status") != "confirmed_in_docker":
        fail("verification_status must be confirmed_in_docker")

    finding, finding_sources = load_finding_sources(workspace_dir, bundle_dir, verification)
    markdown_hints, markdown_sources = load_markdown_hints(workspace_dir, bundle_dir)
    evidence_sources = ["confirmed/" + bundle_dir.name + "/verification-evidence.json", *finding_sources, *markdown_sources]
    card, unmapped_hints = build_seed_card(workspace_dir, bundle_dir, verification, finding, markdown_hints)
    final_ok, final_reason = validate_final(card)

    output_path = Path(args.output).expanduser()
    if final_ok:
        write_jsonl(output_path, [card], force=args.force)
        print(f"VARIANT SEED EXTRACTION PASSED: {output_path}")
        print("mode=final")
        return

    note_path = Path(args.seed_note_output).expanduser() if args.seed_note_output else output_path.parent / f"seed-{stable_slug(bundle_dir.name)}.md"
    write_draft_note(note_path, card, verification, final_reason, evidence_sources, unmapped_hints, force=args.force)
    if args.allow_draft and args.draft_output:
        draft_path = Path(args.draft_output).expanduser()
        write_jsonl(draft_path, [card], force=args.force)
        print(f"VARIANT SEED EXTRACTION DRAFT WRITTEN: {draft_path}")
    elif args.allow_draft and not args.draft_output:
        print("WARN: --allow-draft was set without --draft-output; wrote only the draft note.")
    print(f"VARIANT SEED EXTRACTION INCOMPLETE: {note_path}")
    print(f"reason={final_reason}")


if __name__ == "__main__":
    main()
