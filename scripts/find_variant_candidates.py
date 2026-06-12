#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from validate_report_bundle import load_variant_seed_cards, validate_variant_seed_card  # type: ignore


MAX_FILE_BYTES = 1_000_000
BINARY_PROBE_BYTES = 4096
DEFAULT_MIN_SCORE = 4
FINAL_WORD_PATTERNS = [
    re.compile(r"confirmed_in_docker", re.IGNORECASE),
    re.compile(r"vulnerability confirmed", re.IGNORECASE),
    re.compile(r"\bconfirmed\b", re.IGNORECASE),
    re.compile(r"漏洞已确认"),
    re.compile(r"已确认"),
]
ABSOLUTE_TEXT_PATTERNS = [
    re.compile(r"/Users/[^/\s`'\"<>]+(?:/[^\s`'\"<>]+)*"),
    re.compile(r"/home/[^/\s`'\"<>]+(?:/[^\s`'\"<>]+)*"),
    re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/][^\s`'\"<>]*"),
    re.compile(r"file://[^\s`'\"<>]+"),
]
SPACE_PATTERN = re.compile(r"\s+")
TOKEN_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,}")
GENERATED_WORKSPACE_PATTERN = re.compile(r"^security-research-.+")

HARD_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    "target",
    "tmp",
    "temp",
    "runtime",
    "confirmed",
    "attachments",
}
LOW_PRIORITY_DIRS = {
    "test",
    "tests",
    "docs",
    "doc",
    "documentation",
    "example",
    "examples",
    "fixture",
    "fixtures",
}
SKIP_FILE_SUFFIXES = {
    ".7z",
    ".bz2",
    ".class",
    ".dylib",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".lock",
    ".mov",
    ".mp4",
    ".o",
    ".pdf",
    ".png",
    ".pyc",
    ".so",
    ".tar",
    ".webp",
    ".xz",
    ".zip",
}
STOP_WORDS = {
    "about",
    "after",
    "again",
    "also",
    "and",
    "api",
    "are",
    "before",
    "body",
    "but",
    "can",
    "check",
    "code",
    "condition",
    "data",
    "default",
    "does",
    "file",
    "flow",
    "from",
    "helper",
    "input",
    "into",
    "missing",
    "network",
    "path",
    "pattern",
    "request",
    "root",
    "server",
    "side",
    "sink",
    "source",
    "that",
    "the",
    "this",
    "through",
    "user",
    "url",
    "with",
    "without",
}

SOURCE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "generic": (
        "request",
        "req.",
        "params",
        "query",
        "body",
        "headers",
        "cookie",
        "upload",
        "webhook",
        "argv",
        "stdin",
        "env",
        "config",
        "user input",
        "untrusted",
        "external",
    ),
    "nodejs": (
        "req.body",
        "req.query",
        "req.params",
        "req.headers",
        "request.body",
        "request.query",
        "ctx.request",
        "ctx.query",
        "process.argv",
        "process.env",
        "multer",
        "webhook",
    ),
    "python": (
        "request.args",
        "request.form",
        "request.json",
        "request.get_json",
        "request.files",
        "request.headers",
        "request.query_params",
        "request.GET",
        "request.POST",
        "sys.argv",
        "os.environ",
        "argparse",
        "click.option",
        "webhook",
    ),
}

SINK_FAMILIES: dict[str, dict[str, tuple[str, ...]]] = {
    "http-fetch": {
        "clues": (
            "ssrf",
            "server-side request",
            "http fetch",
            "open-url",
            "open url",
            "fetch",
            "url fetch",
            "metadata",
            "internal network",
        ),
        "keywords": (
            "fetch(",
            "axios.",
            "axios(",
            "got(",
            "request(",
            "http.get",
            "https.get",
            "undici",
            "urlopen(",
            "urllib.request",
            "requests.get",
            "requests.post",
            "httpx.",
            "aiohttp",
            "open_url",
            "openurl",
        ),
    },
    "filesystem-path": {
        "clues": (
            "path traversal",
            "filesystem",
            "file read",
            "file write",
            "open path",
            "directory traversal",
        ),
        "keywords": (
            "readfile",
            "writefile",
            "createreadstream",
            "createwritestream",
            "fs.",
            "path.join",
            "send_file",
            "fileresponse",
            "open(",
            "pathlib",
            "os.path.join",
        ),
    },
    "command-exec": {
        "clues": ("command", "shell", "exec", "rce", "process execution"),
        "keywords": (
            "child_process",
            "exec(",
            "execfile",
            "spawn(",
            "subprocess.",
            "os.system",
            "popen(",
            "shell=true",
        ),
    },
    "sql-query": {
        "clues": ("sql", "query", "injection", "database"),
        "keywords": (
            ".query(",
            "execute(",
            "executemany(",
            "$queryraw",
            "raw(",
            "select ",
            "insert ",
            "update ",
        ),
    },
    "redirect": {
        "clues": ("redirect", "open redirect", "location header"),
        "keywords": ("redirect(", "res.redirect", "response.redirect", "location.href", "location:"),
    },
    "template-eval": {
        "clues": ("template", "eval", "expression", "deserialize", "deserialization"),
        "keywords": (
            "eval(",
            "function(",
            "render_template_string",
            "template(",
            "pickle.loads",
            "yaml.load",
            "deserialize",
        ),
    },
}

MITIGATION_INDICATORS = (
    "allowlist",
    "allow-list",
    "whitelist",
    "denylist",
    "deny-list",
    "canonical",
    "canonicalize",
    "normalize",
    "realpath",
    "resolve(",
    "sanitize",
    "validate",
    "validator",
    "schema.validate",
    "parameterized",
    "prepared statement",
    "escape",
    "revalidate",
    "privateaddress",
    "private address",
    "isprivate",
    "is_private",
    "cidr",
    "net.isip",
    "authz",
    "authorize",
    "permission",
    "bounds",
    "length check",
)


@dataclass(frozen=True)
class TextMatch:
    keyword: str
    line: int
    snippet: str
    family: str = ""


@dataclass
class CandidateDraft:
    rel_path: str
    entry: str
    source_match: TextMatch
    sink_match: TextMatch
    root_cause_similarity: list[str]
    negative_evidence: list[str]
    evidence_basis: list[str]
    score: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Find same-repository Zhulong variant candidates from one final Variant "
            "Seed Card. This helper ranks candidates only; it never verifies or confirms them."
        )
    )
    parser.add_argument("--repo-root", required=True, help="Target repository root to scan.")
    parser.add_argument("--workspace-dir", required=True, help="Current audit workspace under repo-root.")
    parser.add_argument("--seed-card", required=True, help="Seed-card JSON/JSONL under evidence/variant-analysis/.")
    parser.add_argument("--seed-id", required=True, help="Seed card seed_id to use.")
    parser.add_argument("--output", required=True, help="Output JSONL under evidence/variant-analysis/.")
    parser.add_argument("--limit", type=int, default=20, help="Maximum candidates to write. Default: 20.")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing output file.")
    parser.add_argument(
        "--language",
        choices=("generic", "nodejs", "python"),
        default="generic",
        help="Tune built-in source/sink keyword families. Default: generic.",
    )
    parser.add_argument("--include-glob", action="append", default=[], help="Repo-relative include glob.")
    parser.add_argument("--exclude-glob", action="append", default=[], help="Repo-relative exclude glob.")
    parser.add_argument("--min-score", type=int, default=DEFAULT_MIN_SCORE, help=f"Minimum candidate score. Default: {DEFAULT_MIN_SCORE}.")
    return parser.parse_args()


def fail(message: str) -> None:
    raise SystemExit(f"FIND VARIANT CANDIDATES FAILED: {message}")


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def resolved_output_path(raw_path: str) -> Path:
    path = Path(raw_path).expanduser()
    if path.exists():
        return path.resolve()
    return path.parent.resolve() / path.name


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")


def scalar_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return " ".join(scalar_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join(scalar_text(item) for item in value.values())
    return ""


def safe_text(value: str, *, max_len: int = 180) -> str:
    text = value.strip()
    for pattern in ABSOLUTE_TEXT_PATTERNS:
        text = pattern.sub("<local-absolute-path>", text)
    for pattern in FINAL_WORD_PATTERNS:
        text = pattern.sub("<confirmation-word-redacted>", text)
    text = SPACE_PATTERN.sub(" ", text).strip()
    if len(text) > max_len:
        text = text[: max_len - 3].rstrip() + "..."
    return text


def stable_tokens(text: str, *, limit: int = 32) -> list[str]:
    seen: set[str] = set()
    tokens: list[str] = []
    for match in TOKEN_PATTERN.finditer(text.lower()):
        token = match.group(0)
        if len(token) < 4 or token in STOP_WORDS or token in seen:
            continue
        seen.add(token)
        tokens.append(token)
        if len(tokens) >= limit:
            break
    return tokens


def language_source_keywords(language: str) -> list[str]:
    keywords = list(SOURCE_KEYWORDS["generic"])
    if language != "generic":
        keywords.extend(SOURCE_KEYWORDS[language])
    return dedupe_keywords(keywords)


def dedupe_keywords(keywords: list[str] | tuple[str, ...]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for keyword in keywords:
        token = keyword.strip().lower()
        if not token or token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def seed_search_text(seed: dict[str, Any]) -> str:
    fields = (
        "bug_class",
        "root_cause",
        "source_pattern",
        "propagation_pattern",
        "sink_pattern",
        "missing_constraint_pattern",
        "trigger_condition",
    )
    return " ".join(scalar_text(seed.get(field)) for field in fields)


def select_sink_families(seed: dict[str, Any]) -> list[str]:
    text = seed_search_text(seed).lower()
    selected = [
        family
        for family, config in SINK_FAMILIES.items()
        if any(clue in text for clue in config["clues"])
    ]
    if selected:
        return selected
    return ["http-fetch", "filesystem-path", "command-exec", "sql-query", "redirect", "template-eval"]


def sink_keywords(seed: dict[str, Any], families: list[str]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for family in families:
        for keyword in SINK_FAMILIES[family]["keywords"]:
            pairs.append((family, keyword.lower()))
    for token in stable_tokens(scalar_text(seed.get("sink_pattern")), limit=12):
        if token not in STOP_WORDS:
            pairs.append(("seed-sink", token.lower()))
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for pair in pairs:
        if pair in seen:
            continue
        seen.add(pair)
        out.append(pair)
    return out


def wrapper_tokens(seed: dict[str, Any]) -> list[str]:
    text = " ".join(
        scalar_text(seed.get(field))
        for field in ("root_cause", "propagation_pattern", "trigger_condition", "sink_pattern")
    )
    return [
        token
        for token in stable_tokens(text, limit=24)
        if token not in {"attacker", "authenticated", "controlled", "submitted", "without"}
    ]


def mitigation_hits(text: str) -> list[str]:
    lowered = text.lower().replace("_", "")
    hits = []
    for indicator in MITIGATION_INDICATORS:
        token = indicator.lower().replace("_", "")
        if token in lowered:
            hits.append(indicator)
    return dedupe_keywords(hits)[:6]


def oracle_is_sparse(seed: dict[str, Any]) -> bool:
    oracle = scalar_text(seed.get("docker_success_oracle")).strip().lower()
    if len(stable_tokens(oracle, limit=20)) < 5:
        return True
    sparse_markers = (
        "verification-evidence.json records verification_status",
        "docker verification-evidence.json records verification_status",
    )
    return any(marker in oracle for marker in sparse_markers) and len(oracle) < 120


def path_matches_globs(rel_path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch("/" + rel_path, pattern) for pattern in patterns)


def include_mentions_low_priority(include_globs: list[str], dir_name: str) -> bool:
    if not include_globs:
        return False
    return any(dir_name in pattern for pattern in include_globs)


def should_skip_dir(path: Path, repo_root: Path, workspace_dir: Path, include_globs: list[str]) -> bool:
    name = path.name
    if name in HARD_SKIP_DIRS or GENERATED_WORKSPACE_PATTERN.match(name):
        return True
    if path.resolve() == workspace_dir:
        return True
    if name in LOW_PRIORITY_DIRS and not include_mentions_low_priority(include_globs, name):
        return True
    rel = path.relative_to(repo_root).as_posix()
    return rel == "evidence/variant-analysis" or rel.endswith("/evidence/variant-analysis")


def is_low_priority_path(rel_path: str) -> bool:
    parts = {part.lower() for part in Path(rel_path).parts}
    return bool(parts & LOW_PRIORITY_DIRS)


def iter_source_files(repo_root: Path, workspace_dir: Path, include_globs: list[str], exclude_globs: list[str]):
    stack = [repo_root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda item: item.name)
        except OSError:
            continue
        dirs: list[Path] = []
        for entry in entries:
            path = Path(entry.path)
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                if not should_skip_dir(path, repo_root, workspace_dir, include_globs):
                    dirs.append(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                continue
            rel = path.relative_to(repo_root).as_posix()
            if include_globs and not path_matches_globs(rel, include_globs):
                continue
            if exclude_globs and path_matches_globs(rel, exclude_globs):
                continue
            if path.suffix.lower() in SKIP_FILE_SUFFIXES:
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path, rel
        stack.extend(reversed(dirs))


def read_text_file(path: Path) -> str | None:
    try:
        with path.open("rb") as handle:
            probe = handle.read(BINARY_PROBE_BYTES)
            if b"\x00" in probe:
                return None
            rest = handle.read(MAX_FILE_BYTES + 1)
        data = probe + rest
        if len(data) > MAX_FILE_BYTES:
            return None
        return data.decode("utf-8", errors="ignore")
    except OSError:
        return None


def find_text_match(lines: list[str], keywords: list[str], *, family: str = "") -> TextMatch | None:
    lowered_keywords = dedupe_keywords(keywords)
    for line_number, line in enumerate(lines, start=1):
        lowered = line.lower()
        for keyword in lowered_keywords:
            if keyword in lowered:
                return TextMatch(keyword=keyword, line=line_number, snippet=safe_text(line), family=family)
    return None


def find_sink_match(lines: list[str], keyword_pairs: list[tuple[str, str]]) -> TextMatch | None:
    for line_number, line in enumerate(lines, start=1):
        lowered = line.lower()
        for family, keyword in keyword_pairs:
            if keyword in lowered:
                return TextMatch(keyword=keyword, line=line_number, snippet=safe_text(line), family=family)
    return None


def route_entry(line: str) -> str:
    route = re.search(r"\b(?:app|router|server)\.(get|post|put|patch|delete|all)\s*\(\s*['\"]([^'\"]+)", line)
    if route:
        return f"route {route.group(1).upper()} {safe_text(route.group(2), max_len=80)}"
    return ""


def function_entry(line: str) -> str:
    patterns = (
        r"\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
        r"\b(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\b",
        r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>",
        r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*(?:async\s*)?\([^)]*\)\s*=>",
    )
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return f"function {safe_text(match.group(1), max_len=80)}"
    return ""


def infer_entry(lines: list[str], source_line: int, sink_line: int) -> str:
    limit = max(1, min(source_line, sink_line))
    last_entry = ""
    for line in lines[:limit]:
        entry = route_entry(line) or function_entry(line)
        if entry:
            last_entry = entry
    if last_entry:
        return last_entry
    for line in lines[limit - 1 : min(len(lines), limit + 4)]:
        entry = route_entry(line) or function_entry(line)
        if entry:
            return entry
    return "file"


def similar_directory_score(seed: dict[str, Any], rel_path: str) -> tuple[int, str]:
    path_parts = {part.lower() for part in Path(rel_path).parts}
    categories = {
        "route": {"route", "routes", "router", "api", "handlers", "handler", "controllers", "controller", "views"},
        "service": {"service", "services", "lib", "libs", "client", "clients", "integrations"},
        "cli": {"cli", "cmd", "commands", "bin"},
    }
    seed_text = seed_search_text(seed).lower()
    for label, names in categories.items():
        if path_parts & names and (label in seed_text or label in {"route", "service"}):
            return 2, f"similar {label}/handler/service directory"
    return 0, ""


def naming_similarity(seed_tokens: list[str], rel_path: str, entry: str) -> tuple[int, str]:
    haystack = f"{rel_path} {entry}".lower()
    for token in seed_tokens:
        if token in haystack:
            return 1, f"similar name token: {safe_text(token, max_len=40)}"
    return 0, ""


def wrapper_similarity(seed_tokens: list[str], rel_path: str, entry: str) -> tuple[int, str]:
    haystack = f"{rel_path} {entry}".lower()
    for token in seed_tokens:
        if token in haystack:
            return 3, f"same wrapper/service token: {safe_text(token, max_len=40)}"
    return 0, ""


def missing_constraint_similarity(seed: dict[str, Any], text: str, mitigations: list[str]) -> tuple[int, str]:
    if mitigations:
        return 0, ""
    missing_text = scalar_text(seed.get("missing_constraint_pattern"))
    concepts = [
        token
        for token in stable_tokens(missing_text, limit=10)
        if token in {
            "allowlist",
            "canonicalization",
            "canonicalize",
            "private",
            "denylist",
            "validation",
            "authorization",
            "bounds",
            "parameterization",
            "revalidation",
            "sanitize",
        }
    ]
    if concepts:
        return 2, "candidate lacks visible mitigation for seed constraint concept(s): " + ", ".join(concepts[:3])
    if "missing" in missing_text.lower() or "缺" in missing_text:
        return 2, "candidate lacks visible mitigation aligned with seed missing-constraint pattern"
    return 0, ""


def score_file(
    seed: dict[str, Any],
    rel_path: str,
    text: str,
    *,
    language: str,
    source_keywords: list[str],
    sink_keyword_pairs: list[tuple[str, str]],
    seed_wrapper_tokens: list[str],
    sparse_oracle: bool,
) -> CandidateDraft | None:
    lines = text.splitlines()
    source_match = find_text_match(lines, source_keywords, family="source")
    sink_match = find_sink_match(lines, sink_keyword_pairs)
    if source_match is None or sink_match is None:
        return None

    entry = infer_entry(lines, source_match.line, sink_match.line)
    score = 0
    root_cause_similarity: list[str] = []
    negative_evidence: list[str] = []
    evidence_basis = ["source and sink signals matched in the same repository file"]

    if sink_match.family in select_sink_families(seed) or sink_match.family == "seed-sink":
        score += 3
        root_cause_similarity.append(f"same sink family: {safe_text(sink_match.family, max_len=60)}")

    wrapper_score, wrapper_note = wrapper_similarity(seed_wrapper_tokens, rel_path, entry)
    if wrapper_score:
        score += wrapper_score
        root_cause_similarity.append(wrapper_note)

    score += 2
    root_cause_similarity.append("attacker-controlled source indicator present")

    directory_score, directory_note = similar_directory_score(seed, rel_path)
    if directory_score:
        score += directory_score
        root_cause_similarity.append(directory_note)

    mitigations = mitigation_hits(text)
    missing_score, missing_note = missing_constraint_similarity(seed, text, mitigations)
    if missing_score:
        score += missing_score
        root_cause_similarity.append(missing_note)

    naming_score, naming_note = naming_similarity(seed_wrapper_tokens, rel_path, entry)
    if naming_score:
        score += naming_score
        root_cause_similarity.append(naming_note)

    if is_low_priority_path(rel_path):
        score -= 3
        negative_evidence.append("test/docs/examples/fixtures context")

    if mitigations:
        score -= 3
        negative_evidence.append("mitigation indicator(s) present: " + ", ".join(safe_text(item, max_len=40) for item in mitigations))

    if sparse_oracle:
        score -= 1
        evidence_basis.append("seed runtime oracle is sparse; ranking confidence lowered and Docker verification remains required")

    if language != "generic":
        evidence_basis.append(f"language keyword family: {language}")

    return CandidateDraft(
        rel_path=rel_path,
        entry=entry,
        source_match=source_match,
        sink_match=sink_match,
        root_cause_similarity=root_cause_similarity,
        negative_evidence=negative_evidence,
        evidence_basis=evidence_basis,
        score=score,
    )


def candidate_id(seed_id: str, draft: CandidateDraft) -> str:
    payload = json.dumps(
        {
            "seed_id": seed_id,
            "file": draft.rel_path,
            "entry": draft.entry,
            "source": draft.source_match.keyword,
            "sink": draft.sink_match.keyword,
        },
        sort_keys=True,
    )
    return "candidate-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def match_to_json(match: TextMatch) -> dict[str, object]:
    return {
        "family": safe_text(match.family, max_len=80),
        "keyword": safe_text(match.keyword, max_len=80),
        "line": match.line,
        "snippet": match.snippet,
    }


def draft_to_record(seed: dict[str, Any], draft: CandidateDraft, rank: int) -> dict[str, object]:
    seed_id = scalar_text(seed.get("seed_id"))
    return {
        "schema_version": 1,
        "candidate_id": candidate_id(seed_id, draft),
        "variant_of": seed_id,
        "bug_class": safe_text(scalar_text(seed.get("bug_class")), max_len=100),
        "file": draft.rel_path,
        "entry": safe_text(draft.entry, max_len=120),
        "source_match": match_to_json(draft.source_match),
        "sink_match": match_to_json(draft.sink_match),
        "root_cause_similarity": [safe_text(item, max_len=180) for item in draft.root_cause_similarity],
        "negative_evidence": [safe_text(item, max_len=180) for item in draft.negative_evidence],
        "rank": rank,
        "score": draft.score,
        "status": "candidate",
        "recommended_next_step": (
            "Candidate only. Run independent Docker or Docker Compose verification "
            "and bundle validation before any confirmation decision."
        ),
        "evidence_basis": [safe_text(item, max_len=180) for item in draft.evidence_basis],
    }


def write_jsonl(path: Path, records: list[dict[str, object]], *, force: bool) -> None:
    if path.exists() and not force:
        fail(f"refusing to overwrite existing file without --force: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records)
    path.write_text(payload, encoding="utf-8")


def load_selected_seed(seed_card_path: Path, seed_id: str) -> dict[str, Any]:
    cards = load_variant_seed_cards(seed_card_path)
    matches = [card for card in cards if card.get("seed_id") == seed_id]
    if not matches:
        fail(f"seed_id not found in seed-card file: {seed_id}")
    if len(matches) > 1:
        fail(f"seed_id appears multiple times in seed-card file: {seed_id}")
    seed = dict(matches[0])
    validate_variant_seed_card(seed, final=True)
    scope = seed.get("search_scope")
    if not isinstance(scope, dict) or scope.get("repository") != "same-target-repository":
        fail("seed search_scope.repository must be same-target-repository")
    return seed


def validate_boundaries(args: argparse.Namespace) -> tuple[Path, Path, Path, Path]:
    repo_root = Path(args.repo_root).expanduser().resolve()
    if not repo_root.is_dir():
        fail(f"repo-root must be an existing directory: {repo_root}")
    workspace_dir = Path(args.workspace_dir).expanduser().resolve()
    if not workspace_dir.is_dir():
        fail(f"workspace-dir must be an existing directory: {workspace_dir}")
    if not is_relative_to(workspace_dir, repo_root) or workspace_dir == repo_root:
        fail("workspace-dir must be inside repo-root")

    variant_dir = (workspace_dir / "evidence" / "variant-analysis").resolve()
    seed_card_path = Path(args.seed_card).expanduser().resolve()
    if not seed_card_path.is_file():
        fail(f"seed-card file does not exist: {seed_card_path}")
    if not is_relative_to(seed_card_path, variant_dir):
        fail("seed-card must be inside workspace evidence/variant-analysis/")

    output_path = resolved_output_path(args.output)
    if not is_relative_to(output_path, variant_dir):
        fail("output must be inside workspace evidence/variant-analysis/")
    return repo_root, workspace_dir, seed_card_path, output_path


def validate_seed_bundle(seed: dict[str, Any], workspace_dir: Path) -> None:
    raw_path = scalar_text(seed.get("confirmed_bundle_path")).strip()
    if not raw_path:
        fail("seed confirmed_bundle_path is empty")
    bundle_dir = (workspace_dir / raw_path).resolve()
    confirmed_dir = (workspace_dir / "confirmed").resolve()
    if not is_relative_to(bundle_dir, confirmed_dir) or bundle_dir == confirmed_dir:
        fail("seed confirmed_bundle_path must resolve inside workspace confirmed/")
    if not bundle_dir.is_dir():
        fail(f"seed confirmed_bundle_path does not exist: {raw_path}")
    verification_path = bundle_dir / "verification-evidence.json"
    if not verification_path.is_file():
        fail("seed confirmed bundle is missing verification-evidence.json")
    verification = load_json(verification_path)
    if not isinstance(verification, dict):
        fail("seed verification-evidence.json must be a JSON object")
    if verification.get("verification_status") != "confirmed_in_docker":
        fail("seed confirmed bundle verification_status must be confirmed_in_docker")


def find_candidates(args: argparse.Namespace, repo_root: Path, workspace_dir: Path, seed: dict[str, Any]) -> list[CandidateDraft]:
    selected_families = select_sink_families(seed)
    source_keywords = language_source_keywords(args.language)
    sink_keyword_pairs = sink_keywords(seed, selected_families)
    seed_wrappers = wrapper_tokens(seed)
    sparse_oracle = oracle_is_sparse(seed)
    drafts: list[CandidateDraft] = []
    for path, rel_path in iter_source_files(repo_root, workspace_dir, args.include_glob, args.exclude_glob):
        if any(pattern.search(rel_path) for pattern in FINAL_WORD_PATTERNS):
            continue
        text = read_text_file(path)
        if text is None:
            continue
        draft = score_file(
            seed,
            rel_path,
            text,
            language=args.language,
            source_keywords=source_keywords,
            sink_keyword_pairs=sink_keyword_pairs,
            seed_wrapper_tokens=seed_wrappers,
            sparse_oracle=sparse_oracle,
        )
        if draft is not None and draft.score >= args.min_score:
            drafts.append(draft)
    drafts.sort(key=lambda item: (-item.score, item.rel_path, item.entry, item.source_match.line, item.sink_match.line))
    return drafts[: max(args.limit, 0)]


def main() -> None:
    args = parse_args()
    if args.limit < 0:
        fail("--limit must be non-negative")
    repo_root, workspace_dir, seed_card_path, output_path = validate_boundaries(args)
    seed = load_selected_seed(seed_card_path, args.seed_id)
    validate_seed_bundle(seed, workspace_dir)
    drafts = find_candidates(args, repo_root, workspace_dir, seed)
    records = [draft_to_record(seed, draft, rank=index + 1) for index, draft in enumerate(drafts)]
    write_jsonl(output_path, records, force=args.force)
    print(f"VARIANT CANDIDATE FINDER PASSED: {output_path}")
    print(f"candidates={len(records)}")


if __name__ == "__main__":
    main()
