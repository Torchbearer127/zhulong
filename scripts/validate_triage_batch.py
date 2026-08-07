#!/usr/bin/env python3
"""Validate a read-only Zhulong triage batch contract.

Triage records a bounded, explicit set of already-existing candidate findings.
It is intentionally advisory: successful validation neither verifies a
candidate nor writes a verifier verdict, disposition, bundle, audit event, or
state view.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

from validate_recon_result import (
    Issue,
    ValidationContext,
    digest_bytes,
    import_target_validator,
    is_safe_relative_text,
    load_json,
    schema_errors,
)


SCHEMA_VERSION = 1
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "assets/schemas/triage-batch.schema.json"
CANDIDATE_VALIDATOR_PATH = Path(__file__).resolve().parent / "validate_candidate.py"
DEDUP_PLAN_VALIDATOR_PATH = Path(__file__).resolve().parent / "validate_candidate_dedup_plan.py"
RECON_VALIDATOR_PATH = Path(__file__).resolve().parent / "validate_recon_result.py"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FORBIDDEN_AUTHORITY_FIELDS = {
    "confirmed",
    "confirmed_in_docker",
    "severity",
    "cvss",
    "verdict",
    "verification_status",
    "disposition",
    "disposition_recommendation",
    "audit_disposition",
    "bundle_ready",
    "confirmed_bundle_path",
    "audit_complete",
    "promotion",
}


class TriageContext(ValidationContext):
    """Validation context with no writes and strict regular-file resolution."""

    def regular_file(self, root: Path, value: Any, path: str, *, root_label: str) -> Path | None:
        if not isinstance(value, str) or not value.strip() or not is_safe_relative_text(value):
            self.add(
                "PATH_UNSAFE",
                path,
                "The reference must be a safe relative POSIX path.",
                f"Use a regular file inside the supplied {root_label} without '..', URI, or symlink escape.",
            )
            return None
        candidate = root.joinpath(*value.split("/"))
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            self.add("FILE_MISSING", path, "The referenced file does not exist.", "Create the referenced regular file.")
            return None
        except OSError:
            self.add("PATH_UNSAFE", path, "The referenced path cannot be inspected safely.", "Use a regular file.")
            return None
        if stat.S_ISLNK(info.st_mode):
            self.add("SYMLINK_ESCAPE", path, "Symlink references are not accepted by this contract.", "Use a regular file.")
            return None
        if not stat.S_ISREG(info.st_mode):
            self.add("FILE_MISSING", path, "The reference is not a regular file.", "Use a regular file.")
            return None
        try:
            candidate.resolve(strict=True).relative_to(root.resolve())
        except ValueError:
            self.add("SYMLINK_ESCAPE", path, "The reference resolves outside the supplied root.", "Use a regular file inside the root.")
            return None
        except OSError:
            self.add("PATH_UNSAFE", path, "The referenced path cannot be resolved safely.", "Use a regular file.")
            return None
        return candidate


def load_schema() -> dict[str, Any]:
    value = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("triage schema root is not an object")
    return value


def run_json_validator(command: list[str]) -> tuple[dict[str, Any] | None, str | None]:
    """Run an existing production validator without executing candidate material."""
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    output = (proc.stdout or "").strip()
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        parsed = None
    if proc.returncode != 0 or not isinstance(parsed, dict) or parsed.get("ok") is not True:
        return None, output or (proc.stderr or "").strip() or "validator rejected input"
    return parsed, None


def run_candidate_validator(path: Path) -> str | None:
    try:
        proc = subprocess.run(
            [sys.executable, str(CANDIDATE_VALIDATOR_PATH), str(path)],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return str(exc)
    if proc.returncode == 0:
        return None
    return ((proc.stdout or "") + (proc.stderr or "")).strip() or "candidate validator rejected input"


def scan_forbidden_authority(value: Any, ctx: TriageContext, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}"
            if key_text.lower() in FORBIDDEN_AUTHORITY_FIELDS:
                ctx.add(
                    "FORBIDDEN_AUTHORITY_FIELD",
                    child_path,
                    "Triage may not define confirmation, verdict, disposition, severity, bundle, or audit-completion authority.",
                    "Remove the downstream-authority field and keep an advisory recommendation only.",
                )
            scan_forbidden_authority(child, ctx, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            scan_forbidden_authority(child, ctx, f"{path}[{index}]")


def validate_target_binding(data: dict[str, Any], ctx: TriageContext) -> None:
    binding = data.get("target_binding")
    if not isinstance(binding, dict):
        return
    target_path = ctx.regular_file(
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
        ctx.add("FILE_MISSING", "$.target_binding.target_contract_path", "The target contract cannot be read.", "Restore it.")
        return
    if binding.get("target_contract_sha256") != digest_bytes(target_raw):
        ctx.add(
            "DIGEST_MISMATCH_TARGET_CONTRACT",
            "$.target_binding.target_contract_sha256",
            "The target contract digest does not match its referenced file.",
            "Recompute the exact digest from the bound contract.",
        )
    try:
        validator = import_target_validator()
        contract = validator.load_contract(target_path)
        validator.validate_target(contract)
    except Exception:
        ctx.add(
            "TARGET_CONTRACT_INVALID",
            "$.target_binding.target_contract_path",
            "The bound target contract is not accepted by validate_target_contract.py.",
            "Fix the target contract before triage.",
        )
        return
    target = contract.get("target") if isinstance(contract, dict) else None
    tested_ref = target.get("tested_ref") if isinstance(target, dict) else None
    if tested_ref != binding.get("tested_ref"):
        ctx.add(
            "TESTED_REF_MISMATCH",
            "$.target_binding.tested_ref",
            "The triage tested_ref does not exactly match target.target.tested_ref.",
            "Regenerate the batch for the bound target contract.",
        )


def validate_recon_binding(data: dict[str, Any], ctx: TriageContext) -> None:
    binding = data.get("recon_binding")
    if not isinstance(binding, dict):
        return
    result_path = ctx.regular_file(ctx.workspace_dir, binding.get("path"), "$.recon_binding.path", root_label="workspace")
    if result_path is None:
        return
    try:
        raw = result_path.read_bytes()
    except OSError:
        return
    if binding.get("sha256") != digest_bytes(raw):
        ctx.add("DIGEST_MISMATCH_RECON", "$.recon_binding.sha256", "The Recon digest drifted.", "Recompute the exact digest.")
    payload, error = run_json_validator([
        sys.executable, str(RECON_VALIDATOR_PATH), "--repo-root", str(ctx.repo_root), "--workspace-dir", str(ctx.workspace_dir),
        "--recon-result", str(result_path), "--json",
    ])
    if error is not None:
        ctx.add("RECON_BINDING_INVALID", "$.recon_binding.path", "The bound Recon result failed its production validator.", "Fix the Recon result first.")
        return
    if payload.get("recon_id") != binding.get("recon_id"):
        ctx.add("RECON_ID_MISMATCH", "$.recon_binding.recon_id", "The bound Recon ID does not match the result.", "Use the exact recon_id.")


def validate_dedup_plan_binding(data: dict[str, Any], ctx: TriageContext) -> None:
    binding = data.get("dedup_plan_binding")
    if not isinstance(binding, dict):
        return
    plan_path = ctx.regular_file(ctx.workspace_dir, binding.get("path"), "$.dedup_plan_binding.path", root_label="workspace")
    if plan_path is None:
        return
    try:
        raw = plan_path.read_bytes()
    except OSError:
        return
    if binding.get("sha256") != digest_bytes(raw):
        ctx.add("DIGEST_MISMATCH_DEDUP_PLAN", "$.dedup_plan_binding.sha256", "The advisory dedup plan digest drifted.", "Rebind the exact validated plan.")
    payload, error = run_json_validator([
        sys.executable, str(DEDUP_PLAN_VALIDATOR_PATH), "--repo-root", str(ctx.repo_root),
        "--workspace-dir", str(ctx.workspace_dir), "--plan", str(plan_path), "--json",
    ])
    if error is not None:
        ctx.add("DEDUP_PLAN_INVALID", "$.dedup_plan_binding.path", "The advisory dedup plan failed its production validator.", "Fix or remove the advisory plan reference.")
    elif payload.get("plan_id") != binding.get("plan_id"):
        ctx.add("DEDUP_PLAN_ID_MISMATCH", "$.dedup_plan_binding.plan_id", "The plan ID does not match the validated plan.", "Use the exact plan_id.")


def validate_inventory(data: dict[str, Any], ctx: TriageContext) -> dict[str, dict[str, Any]]:
    inventory = data.get("candidate_inventory")
    known: dict[str, dict[str, Any]] = {}
    seen_paths: set[str] = set()
    seen_digests: set[str] = set()
    binding = data.get("target_binding") if isinstance(data.get("target_binding"), dict) else {}
    target_path = binding.get("target_contract_path") if isinstance(binding, dict) else None
    tested_ref = binding.get("tested_ref") if isinstance(binding, dict) else None
    if not isinstance(inventory, list):
        return known
    if not inventory:
        ctx.add("EMPTY_INVENTORY", "$.candidate_inventory", "An empty inventory cannot be finalized as triage.", "Record a non-empty explicit batch.")
    for index, item in enumerate(inventory):
        item_path = f"$.candidate_inventory[{index}]"
        if not isinstance(item, dict):
            continue
        candidate_id = item.get("candidate_id")
        path_value = item.get("path")
        digest = item.get("sha256")
        if isinstance(candidate_id, str):
            if candidate_id in known:
                ctx.add("DUPLICATE_CANDIDATE_ID", f"{item_path}.candidate_id", "candidate_id is duplicated in the inventory.", "List each candidate once.")
            else:
                known[candidate_id] = item
        if isinstance(path_value, str):
            if path_value in seen_paths:
                ctx.add("DUPLICATE_CANDIDATE_PATH", f"{item_path}.path", "candidate path is duplicated in the inventory.", "List each file once.")
            seen_paths.add(path_value)
        if isinstance(digest, str):
            if digest in seen_digests:
                ctx.add("DUPLICATE_CANDIDATE_DIGEST", f"{item_path}.sha256", "candidate digest is duplicated in the inventory.", "Do not bind one candidate file to multiple items.")
            seen_digests.add(digest)
        candidate_path = ctx.regular_file(ctx.workspace_dir, path_value, f"{item_path}.path", root_label="workspace")
        if candidate_path is None:
            continue
        try:
            raw = candidate_path.read_bytes()
        except OSError:
            continue
        actual_digest = digest_bytes(raw)
        if digest != actual_digest:
            ctx.add("DIGEST_MISMATCH_CANDIDATE", f"{item_path}.sha256", "The candidate digest does not match the referenced file.", "Recompute the binding or restore the candidate.")
        validator_error = run_candidate_validator(candidate_path)
        if validator_error is not None:
            ctx.add("CANDIDATE_INVALID", f"{item_path}.path", "The candidate failed validate_candidate.py.", "Fix the original candidate contract.")
            continue
        candidate_doc, _raw, load_error = load_json(candidate_path)
        if load_error is not None or not isinstance(candidate_doc, dict):
            ctx.add("CANDIDATE_INVALID", f"{item_path}.path", "The candidate JSON cannot be read after validation.", "Restore the candidate file.")
            continue
        if candidate_doc.get("candidate_id") != candidate_id:
            ctx.add("CANDIDATE_ID_PATH_SWAP", f"{item_path}.candidate_id", "The inventory candidate_id does not match candidate.json.", "Bind each ID to its exact candidate path.")
        identity = candidate_doc.get("identity") if candidate_doc.get("schema_version") == 2 else None
        actual_fingerprint = identity.get("fingerprint") if isinstance(identity, dict) else None
        if "fingerprint" in item and item.get("fingerprint") != actual_fingerprint:
            ctx.add("CANDIDATE_FINGERPRINT_MISMATCH", f"{item_path}.fingerprint", "The advisory fingerprint does not match the validated candidate protocol mode and identity.", "Use null for R1 or the recomputed R2 fingerprint.")
        target_ref = candidate_doc.get("target_ref")
        if not isinstance(target_ref, dict) or target_ref.get("tested_ref") != tested_ref:
            ctx.add("CANDIDATE_TESTED_REF_MISMATCH", f"{item_path}.candidate_id", "Candidate tested_ref does not match the batch target binding.", "Use candidates from the same tested ref.")
        if not isinstance(target_ref, dict) or target_ref.get("target_config") != target_path:
            ctx.add("CANDIDATE_TARGET_CONTRACT_MISMATCH", f"{item_path}.candidate_id", "Candidate target_config does not match the batch target contract path.", "Use the same target contract binding.")
    return known


def _decision_allowed_fields(recommendation: str) -> set[str]:
    base = {"candidate_id", "recommendation", "reason_code", "evidence", "next_action"}
    extra = {
        "recommend_verification": {"verification_reason", "docker_applicability", "required_evidence", "verification_order"},
        "unverified": {"missing_evidence"},
        "blocked": {"blocker_code", "recovery_condition", "resume_action"},
        "false_positive": {"counterevidence"},
        "duplicate": {"duplicate_of_candidate_id"},
    }
    return base | extra.get(recommendation, set())


def validate_decisions(data: dict[str, Any], known: dict[str, dict[str, Any]], ctx: TriageContext) -> tuple[set[str], set[str]]:
    decisions = data.get("decisions")
    unprocessed = data.get("unprocessed_candidates")
    decision_ids: set[str] = set()
    unprocessed_ids: set[str] = set()
    duplicate_edges: dict[str, str] = {}
    orders: set[int] = set()
    if isinstance(decisions, list):
        for index, decision in enumerate(decisions):
            base = f"$.decisions[{index}]"
            if not isinstance(decision, dict):
                continue
            candidate_id = decision.get("candidate_id")
            recommendation = decision.get("recommendation")
            if isinstance(candidate_id, str):
                if candidate_id in decision_ids:
                    ctx.add("DUPLICATE_DECISION", f"{base}.candidate_id", "A candidate may have exactly one triage decision.", "Remove the duplicate decision.")
                decision_ids.add(candidate_id)
                if candidate_id not in known:
                    ctx.add("DECISION_CANDIDATE_UNKNOWN", f"{base}.candidate_id", "Decision references a candidate outside the explicit inventory.", "Reference an inventory candidate only.")
            if isinstance(recommendation, str):
                unexpected = set(decision) - _decision_allowed_fields(recommendation)
                if unexpected:
                    ctx.add("DECISION_FIELD_FORBIDDEN", base, "A recommendation contains fields belonging to another recommendation type.", "Keep only fields defined for this advisory outcome.")
                required = {
                    "recommend_verification": {"verification_reason", "docker_applicability", "required_evidence", "verification_order"},
                    "unverified": {"missing_evidence"},
                    "blocked": {"blocker_code", "recovery_condition", "resume_action"},
                    "false_positive": {"counterevidence"},
                    "duplicate": {"duplicate_of_candidate_id"},
                }.get(recommendation, set())
                if required - set(decision):
                    ctx.add("DECISION_SEMANTICS_INVALID", base, "The advisory outcome is missing its required evidence or recovery facts.", "Add the required structured facts for this outcome.")
                if recommendation == "recommend_verification":
                    order = decision.get("verification_order")
                    if type(order) is int:
                        if order in orders:
                            ctx.add("DUPLICATE_VERIFICATION_ORDER", f"{base}.verification_order", "Verification order must be unique and explicit.", "Assign a unique positive order.")
                        orders.add(order)
                if recommendation == "duplicate" and isinstance(candidate_id, str):
                    target = decision.get("duplicate_of_candidate_id")
                    if target == candidate_id:
                        ctx.add("DUPLICATE_SELF_REFERENCE", f"{base}.duplicate_of_candidate_id", "A duplicate may not refer to itself.", "Reference another inventory candidate.")
                    if isinstance(target, str):
                        if target not in known:
                            ctx.add("DUPLICATE_TARGET_UNKNOWN", f"{base}.duplicate_of_candidate_id", "Duplicate target is not in the inventory.", "Reference another inventory candidate.")
                        duplicate_edges[candidate_id] = target
    if isinstance(unprocessed, list):
        for index, item in enumerate(unprocessed):
            base = f"$.unprocessed_candidates[{index}]"
            if not isinstance(item, dict):
                continue
            candidate_id = item.get("candidate_id")
            if isinstance(candidate_id, str):
                if candidate_id in unprocessed_ids:
                    ctx.add("DUPLICATE_UNPROCESSED", f"{base}.candidate_id", "An unprocessed candidate is listed more than once.", "List it once.")
                unprocessed_ids.add(candidate_id)
                if candidate_id not in known:
                    ctx.add("UNPROCESSED_CANDIDATE_UNKNOWN", f"{base}.candidate_id", "Unprocessed item is outside the inventory.", "Reference an inventory candidate only.")
    overlap = decision_ids & unprocessed_ids
    for candidate_id in sorted(overlap):
        ctx.add("PROCESSED_UNPROCESSED_OVERLAP", "$.unprocessed_candidates", f"{candidate_id} is both decided and unprocessed.", "Keep the two sets disjoint.")
    for candidate_id in sorted(known):
        if candidate_id not in decision_ids and candidate_id not in unprocessed_ids:
            ctx.add("CANDIDATE_DECISION_OMITTED", "$.decisions", f"{candidate_id} has neither a decision nor an unprocessed record.", "Classify it or record why it is unprocessed.")
    for source in sorted(duplicate_edges):
        seen: set[str] = set()
        current = source
        while current in duplicate_edges:
            if current in seen:
                ctx.add("DUPLICATE_CYCLE", "$.decisions", "Duplicate recommendations must not form a cycle.", "Point the chain to a non-duplicate candidate.")
                break
            seen.add(current)
            current = duplicate_edges[current]
    return decision_ids, unprocessed_ids


def validate_batch_context(data: dict[str, Any], known: dict[str, dict[str, Any]], ctx: TriageContext) -> None:
    for collection_name in ("batch_gaps", "batch_blockers"):
        collection = data.get(collection_name)
        if not isinstance(collection, list):
            continue
        seen_codes: set[str] = set()
        for index, item in enumerate(collection):
            if not isinstance(item, dict):
                continue
            code = item.get("code")
            if isinstance(code, str):
                if code in seen_codes:
                    ctx.add("DUPLICATE_BATCH_CODE", f"$.{collection_name}[{index}].code", "Batch gap/blocker code is duplicated.", "Use one record per code.")
                seen_codes.add(code)
            affected = item.get("affected_candidate_ids")
            if isinstance(affected, list):
                for candidate_id in affected:
                    if isinstance(candidate_id, str) and candidate_id not in known:
                        ctx.add("AFFECTED_CANDIDATE_UNKNOWN", f"$.{collection_name}[{index}]", "Batch context references a candidate outside the inventory.", "Reference inventory candidates only.")


def validate_status(data: dict[str, Any], known: dict[str, dict[str, Any]], decision_ids: set[str], unprocessed_ids: set[str], ctx: TriageContext) -> None:
    status = data.get("status")
    gaps = data.get("batch_gaps")
    blockers = data.get("batch_blockers")
    if not isinstance(gaps, list) or not isinstance(blockers, list):
        return
    if status == "complete":
        if not known:
            ctx.add("EMPTY_INVENTORY", "$.candidate_inventory", "An empty triage batch cannot be complete or finalized.", "Use a non-empty explicit batch.")
        if set(known) != decision_ids or unprocessed_ids or gaps or blockers:
            ctx.add("BATCH_COMPLETENESS_INVALID", "$.status", "complete requires exactly one decision per inventory candidate and no unfinished material.", "Use partial or blocked until all work is represented.")
    elif status == "partial":
        if not (unprocessed_ids or gaps or blockers):
            ctx.add("BATCH_COMPLETENESS_INVALID", "$.status", "partial requires an unprocessed candidate, batch gap, or blocker.", "Record the incomplete material and a next action.")
    elif status == "blocked":
        if not blockers:
            ctx.add("BATCH_BLOCKER_REQUIRED", "$.batch_blockers", "blocked requires at least one substantive batch blocker.", "Record code, affected candidates, evidence, recovery condition, and resume action.")


def validate_triage(data: Any, repo_root: Path, workspace_dir: Path) -> list[Issue]:
    ctx = TriageContext(repo_root, workspace_dir)
    try:
        schema = load_schema()
    except (OSError, json.JSONDecodeError, ValueError):
        ctx.add("SCHEMA_INVALID", "$schema", "The triage schema cannot be loaded.", "Restore triage-batch.schema.json.")
        return ctx.issues
    if not isinstance(data, dict):
        ctx.add("SCHEMA_INVALID", "$", "The triage batch must be a JSON object.", "Write an object matching the schema.")
        return ctx.issues
    scan_forbidden_authority(data, ctx)
    for path, message in schema_errors(data, schema, schema):
        ctx.add("SCHEMA_INVALID", path, message, "Match triage-batch.schema.json and remove unknown fields.")
    if data.get("schema_version") != SCHEMA_VERSION:
        ctx.add("SCHEMA_INVALID", "$.schema_version", "schema_version must be 1.", "Use the current triage schema.")
    validate_target_binding(data, ctx)
    validate_recon_binding(data, ctx)
    validate_dedup_plan_binding(data, ctx)
    known = validate_inventory(data, ctx)
    decision_ids, unprocessed_ids = validate_decisions(data, known, ctx)
    validate_batch_context(data, known, ctx)
    validate_status(data, known, decision_ids, unprocessed_ids, ctx)
    return ctx.issues


def resolve_root(raw: str, label: str) -> tuple[Path | None, Issue | None]:
    try:
        path = Path(raw).expanduser().resolve()
    except (OSError, RuntimeError):
        return None, Issue("PATH_UNSAFE", f"<{label}>", f"The supplied {label} cannot be resolved safely.", "Provide an existing directory.")
    if not path.is_dir():
        return None, Issue("FILE_MISSING", f"<{label}>", f"The supplied {label} is not a directory.", "Provide an existing directory.")
    return path, None


def resolve_batch(raw: str, workspace_dir: Path) -> tuple[Path | None, Issue | None]:
    ctx = TriageContext(workspace_dir, workspace_dir)
    supplied = Path(raw).expanduser()
    if supplied.is_absolute():
        try:
            supplied.resolve(strict=True).relative_to(workspace_dir.resolve())
            relative = supplied.relative_to(workspace_dir).as_posix()
        except ValueError:
            ctx.add("PATH_UNSAFE", "<triage-batch>", "The batch path is outside the workspace.", "Use a file inside the workspace.")
            relative = ""
        except OSError:
            ctx.add("PATH_UNSAFE", "<triage-batch>", "The batch path cannot be resolved safely.", "Use a regular workspace file.")
            relative = ""
    else:
        relative = raw
    path = ctx.regular_file(workspace_dir, relative, "<triage-batch>", root_label="workspace") if relative else None
    return path, ctx.issues[0] if ctx.issues else None


def make_output(data: Any, issues: list[Issue]) -> dict[str, Any]:
    document = data if isinstance(data, dict) else {}
    codes: list[str] = []
    for issue in issues:
        if issue.code not in codes:
            codes.append(issue.code)
    return {
        "ok": not issues,
        "result": "triage_batch_contract_valid" if not issues else "triage_batch_contract_invalid",
        "authority": "triage_advisory_only",
        "batch_id": document.get("batch_id"),
        "status": document.get("status"),
        "issue_codes": codes,
        "issues": [issue.as_dict() for issue in issues],
        "message": "Triage is advisory only and does not create a verdict, disposition, confirmation, bundle, or audit completion claim." if not issues else "Triage batch rejected; fix the listed issues.",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline, read-only validation for a Zhulong triage batch.")
    parser.add_argument("--repo-root", required=True, help="Checked-out target repository root.")
    parser.add_argument("--workspace-dir", required=True, help="Audit workspace containing the batch.")
    parser.add_argument("--triage-batch", required=True, help="Workspace-relative triage-batch.json path.")
    parser.add_argument("--json", action="store_true", help="Emit stable machine-readable JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    issues: list[Issue] = []
    repo_root, repo_issue = resolve_root(args.repo_root, "repo-root")
    workspace_dir, workspace_issue = resolve_root(args.workspace_dir, "workspace-dir")
    if repo_issue:
        issues.append(repo_issue)
    if workspace_issue:
        issues.append(workspace_issue)
    data: Any = None
    if repo_root is not None and workspace_dir is not None:
        batch_path, batch_issue = resolve_batch(args.triage_batch, workspace_dir)
        if batch_issue:
            issues.append(batch_issue)
        elif batch_path is not None:
            data, _raw, error = load_json(batch_path)
            if error is not None:
                issues.append(Issue("TRIAGE_BATCH_JSON_INVALID", "<triage-batch>", "The batch is not valid UTF-8 JSON.", "Write valid JSON."))
            else:
                issues.extend(validate_triage(data, repo_root, workspace_dir))
    output = make_output(data, issues)
    if args.json:
        print(json.dumps(output, ensure_ascii=False, indent=2))
    elif issues:
        for issue in issues:
            print(f"ERROR [{issue.code}] {issue.message} ({issue.path})", file=sys.stderr)
    else:
        print("OK: triage batch valid; authority=triage-advisory-only; no verdict, disposition, or confirmation created.")
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
