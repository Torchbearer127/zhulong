#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


PATH_KEYS = {
    "path",
    "final_path",
    "verification_evidence",
    "reviewer_evidence_index",
    "source_path",
    "source_findings_json",
    "evidence_path",
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


def validate_contract(contract: dict[str, Any], workspace_dir: Path, issues: IssueCollector) -> None:
    walk_portability(contract, issues)
    check_core_fields(contract, issues)
    check_final_path(contract, workspace_dir, issues)
    check_render(contract, issues)
    check_docker_evidence(contract, issues)
    check_replay_registration(contract, issues)
    check_direct_impact(contract, issues)
    check_files(contract, issues)
    check_code_context(contract, issues)
    check_fixture_provenance(contract, issues)
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
    contract_path = Path(args.contract).expanduser()
    issues = IssueCollector(all_errors=args.all_errors)
    try:
        contract = load_json(contract_path, issues)
        if contract:
            validate_contract(contract, workspace_dir, issues)
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
