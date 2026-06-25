#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from validate_bundle_contract import IssueCollector, StopValidation, load_json, validate_contract
from validate_report_bundle import classify_replay_transcript


class BuildError(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build one confirmed bundle through staging, validation, and atomic promote."
    )
    parser.add_argument("--workspace-dir", required=True, help="Audit workspace directory containing confirmed/.")
    parser.add_argument("--contract", required=True, help="confirmed/.contracts/<slug>.bundle-contract.json")
    parser.add_argument("--language", choices=["zh-CN", "en-US"], default="zh-CN")
    parser.add_argument(
        "--replace-existing-validated-bundle",
        action="store_true",
        help="Validate/classify an existing final target, move it to .staging/.trash, then promote.",
    )
    parser.add_argument(
        "--keep-failed-staging",
        action="store_true",
        help="Keep failed staging output for local debugging. It remains under confirmed/.staging/.",
    )
    parser.add_argument(
        "--replace-failed-staging",
        action="store_true",
        help="Replace an owned failed staging directory for this slug before building.",
    )
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable build summary.")
    return parser.parse_args()


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def rel(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return str(path)


def resolve_under(base: Path, value: str, label: str) -> Path:
    raw = str(value or "").strip()
    if not raw:
        raise BuildError(f"{label} is required")
    if raw.startswith("~") or raw.startswith("file://"):
        raise BuildError(f"{label} must be workspace-relative, not {raw!r}")
    path = Path(raw)
    if path.is_absolute():
        resolved = path.resolve()
    else:
        resolved = (base / path).resolve()
    try:
        resolved.relative_to(base.resolve())
    except ValueError as exc:
        raise BuildError(f"{label} resolves outside workspace: {raw}") from exc
    return resolved


def validate_contract_for_build(
    contract_path: Path,
    workspace_dir: Path,
    *,
    allow_existing_final: bool,
) -> dict[str, Any]:
    issues = IssueCollector(all_errors=True)
    try:
        contract = load_json(contract_path, issues)
        if contract:
            validate_contract(contract, workspace_dir, issues)
    except StopValidation:
        contract = {}
    effective_issues = issues.issues
    if allow_existing_final:
        effective_issues = [
            issue for issue in effective_issues
            if issue.code != "FINAL_TARGET_EXISTS"
        ]
    if any(issue.severity == "error" for issue in effective_issues):
        details = "; ".join(f"{issue.code} at {issue.path}: {issue.message}" for issue in effective_issues)
        raise BuildError(f"bundle contract preflight failed: {details}")
    if not contract:
        raise BuildError("bundle contract could not be loaded")
    return contract


def final_path_from_contract(contract: dict[str, Any], workspace_dir: Path) -> tuple[str, Path, Path]:
    bundle = contract.get("bundle") if isinstance(contract.get("bundle"), dict) else {}
    slug = str(bundle.get("slug") or "").strip()
    final_rel = str(bundle.get("final_path") or "").strip()
    if not slug:
        raise BuildError("bundle.slug is required")
    if PurePosixPath(final_rel.replace("\\", "/")).parts != ("confirmed", slug):
        raise BuildError("bundle.final_path must be exactly confirmed/<slug> for staged promotion")
    confirmed_dir = (workspace_dir / "confirmed").resolve()
    final_path = resolve_under(workspace_dir, final_rel, "bundle.final_path")
    try:
        final_path.relative_to(confirmed_dir)
    except ValueError as exc:
        raise BuildError("final target must stay under the workspace confirmed/ directory") from exc
    return slug, confirmed_dir, final_path


def render_config(contract: dict[str, Any], workspace_dir: Path) -> tuple[Path, str]:
    render = contract.get("render") if isinstance(contract.get("render"), dict) else {}
    source = str(render.get("source_findings_json") or "").strip()
    finding_slug = str(render.get("finding_slug") or "").strip()
    if not source or not finding_slug:
        raise BuildError("contract render.source_findings_json and render.finding_slug are required")
    return resolve_under(workspace_dir, source, "render.source_findings_json"), finding_slug


def load_findings_document(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BuildError(f"renderer source findings JSON not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BuildError(f"renderer source findings JSON is invalid: {exc}") from exc
    defaults: dict[str, Any] = {}
    findings: list[dict[str, Any]]
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        defaults = {key: value for key, value in data.items() if key != "findings"}
        findings = [item for item in data["findings"] if isinstance(item, dict)]
    elif isinstance(data, dict):
        findings = [data]
    elif isinstance(data, list):
        findings = [item for item in data if isinstance(item, dict)]
    else:
        raise BuildError("renderer source findings JSON must be an object, array, or object with findings[]")
    if not findings:
        raise BuildError("renderer source findings JSON contains no finding objects")
    return defaults, findings


def finding_match_keys(finding: dict[str, Any]) -> set[str]:
    keys = {
        str(finding.get("slug") or "").strip(),
        Path(str(finding.get("filename") or "")).stem,
        Path(str(finding.get("report_file") or "")).stem,
    }
    evidence = finding.get("verification_evidence")
    if isinstance(evidence, dict):
        keys.add(str(evidence.get("finding_slug") or "").strip())
    return {key for key in keys if key}


def select_one_finding(source_path: Path, finding_slug: str) -> tuple[dict[str, Any], dict[str, Any]]:
    defaults, findings = load_findings_document(source_path)
    matches = [finding for finding in findings if finding_slug in finding_match_keys(finding)]
    if not matches:
        raise BuildError(f"no finding matched render.finding_slug={finding_slug!r}")
    if len(matches) != 1:
        raise BuildError(
            f"render.finding_slug={finding_slug!r} selected {len(matches)} findings; exactly one is required"
        )
    return defaults, dict(matches[0])


def write_one_finding_input(
    input_path: Path,
    defaults: dict[str, Any],
    finding: dict[str, Any],
    *,
    language: str,
) -> Path:
    if not str(finding.get("project_root_dir") or finding.get("project_root") or "").strip():
        finding["project_root_dir"] = "."
    payload = dict(defaults)
    payload["report_language"] = language
    payload["output_language"] = language
    payload["findings"] = [finding]
    input_path.parent.mkdir(parents=True, exist_ok=True)
    input_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return input_path


def run_command(command: list[str], cwd: Path) -> str:
    proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if proc.returncode != 0:
        raise BuildError(f"command failed: {' '.join(command)}\n{output}")
    return output


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_json_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        strings: list[str] = []
        for nested in value.values():
            strings.extend(collect_json_strings(nested))
        return strings
    if isinstance(value, list):
        strings = []
        for nested in value:
            strings.extend(collect_json_strings(nested))
        return strings
    return []


def collect_reviewer_index_log_paths(value: Any, key: str = "") -> set[str]:
    paths: set[str] = set()
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            normalized = str(child_key).strip().lower()
            if normalized.endswith(("_path", "_paths", "_file", "_files", "_artifact", "_artifacts")):
                paths.update(item for item in collect_json_strings(child_value) if item.strip().endswith(".log"))
            else:
                paths.update(collect_reviewer_index_log_paths(child_value, normalized))
    elif isinstance(value, list):
        for item in value:
            paths.update(collect_reviewer_index_log_paths(item, key))
    return paths


def registered_replay_logs(bundle_dir: Path) -> list[str]:
    logs: set[str] = set()
    evidence_path = bundle_dir / "verification-evidence.json"
    if evidence_path.exists():
        try:
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            evidence = {}
        if isinstance(evidence, dict) and isinstance(evidence.get("evidence_files"), list):
            logs.update(str(item).strip() for item in evidence["evidence_files"] if str(item).strip().endswith(".log"))
    reviewer_index_path = bundle_dir / "attachments/reviewer-evidence-index.json"
    if reviewer_index_path.exists():
        try:
            reviewer_index = json.loads(reviewer_index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            reviewer_index = {}
        logs.update(collect_reviewer_index_log_paths(reviewer_index))
    return sorted(Path(item).as_posix() for item in logs if item)


def replay_log_manifest_entries(
    bundle_dir: Path,
    *,
    workspace_dir: Path,
    renderer_input_path: Path,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for rel_path in registered_replay_logs(bundle_dir):
        path = bundle_dir / rel_path
        if not path.is_file():
            continue
        classification = classify_replay_transcript(path.read_text(encoding="utf-8", errors="ignore"))
        entries.append(
            {
                "path": rel_path,
                "source_kind": "copied_successful_transcript",
                "trust_classification": classification.get("classification", "unknown"),
                "sha256": sha256_file(path),
                "source_path": rel(renderer_input_path, workspace_dir),
                "provenance": "Copied into the staged bundle from the selected renderer input evidence.",
                "notes": "Wrapper did not execute replay; transcript was validated from bundled evidence.",
            }
        )
    return entries


def owned_failed_staging(path: Path, final_path: Path, workspace_dir: Path) -> bool:
    manifest = path / "bundle-build-manifest.json"
    if not path.is_dir() or not manifest.is_file():
        return False
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    return (
        data.get("schema_version") == 1
        and str(data.get("final_path") or "") == rel(final_path, workspace_dir)
        and data.get("promote_status") != "promoted"
    )


def prepare_staging_target(
    staging_path: Path,
    final_path: Path,
    workspace_dir: Path,
    *,
    replace_failed_staging: bool,
) -> None:
    if not staging_path.exists():
        return
    if replace_failed_staging and owned_failed_staging(staging_path, final_path, workspace_dir):
        trash = staging_path.parent / ".trash" / f"{staging_path.name}-failed-staging-{utc_timestamp()}"
        trash.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(staging_path), str(trash))
        return
    raise BuildError(
        f"staging target already exists: {staging_path}. "
        "Use --replace-failed-staging only for an owned failed staging directory."
    )


def write_manifest(
    staging_path: Path,
    *,
    contract_path: Path,
    workspace_dir: Path,
    renderer_input_path: Path,
    final_path: Path,
    validation_status: str,
    promote_status: str,
) -> None:
    payload = {
        "schema_version": 1,
        "contract_path": rel(contract_path, workspace_dir),
        "staging_path": rel(staging_path, workspace_dir),
        "final_path": rel(final_path, workspace_dir),
        "renderer_input_path": rel(renderer_input_path, workspace_dir),
        "validation_status": validation_status,
        "promote_status": promote_status,
        "docker_replay_note": "The staging build wrapper did not execute Docker, replay scripts, PoCs, scanners, network calls, or package managers.",
        "replay_logs": replay_log_manifest_entries(
            staging_path,
            workspace_dir=workspace_dir,
            renderer_input_path=renderer_input_path,
        ),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    (staging_path / "bundle-build-manifest.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def classify_existing_final(
    final_path: Path,
    confirmed_dir: Path,
    *,
    language: str,
    script_dir: Path,
) -> None:
    if not final_path.exists():
        return
    validator = script_dir / "validate_all_report_bundles.py"
    output = run_command(
        [
            sys.executable,
            str(validator),
            "--confirmed-dir",
            str(confirmed_dir),
            "--language",
            language,
            "--json",
        ],
        script_dir.parent,
    )
    data = json.loads(output)
    matches = [item for item in data.get("results", []) if item.get("name") == final_path.name]
    if not matches or matches[0].get("classification") != "bundle_validated":
        raise BuildError("existing final target is not a validated bundle; refusing replacement")


def move_existing_to_trash(final_path: Path, staging_dir: Path) -> Path:
    trash_dir = staging_dir / ".trash"
    trash_dir.mkdir(parents=True, exist_ok=True)
    target = trash_dir / f"{final_path.name}-{utc_timestamp()}"
    if target.exists():
        raise BuildError(f"trash target already exists: {target}")
    shutil.move(str(final_path), str(target))
    return target


def build(args: argparse.Namespace) -> dict[str, Any]:
    script_dir = Path(__file__).resolve().parent
    workspace_dir = Path(args.workspace_dir).expanduser().resolve()
    contract_path = Path(args.contract).expanduser().resolve()
    contract = validate_contract_for_build(
        contract_path,
        workspace_dir,
        allow_existing_final=args.replace_existing_validated_bundle,
    )
    slug, confirmed_dir, final_path = final_path_from_contract(contract, workspace_dir)
    source_findings_path, finding_slug = render_config(contract, workspace_dir)
    if final_path.exists() and not args.replace_existing_validated_bundle:
        raise BuildError("final target already exists; rerun with --replace-existing-validated-bundle only after review")
    staging_dir = confirmed_dir / ".staging"
    staging_path = staging_dir / slug
    prepare_staging_target(
        staging_path,
        final_path,
        workspace_dir,
        replace_failed_staging=args.replace_failed_staging,
    )
    work_dir = staging_dir / ".work" / f"{slug}-{utc_timestamp()}"
    work_confirmed = work_dir / "confirmed"
    work_confirmed.mkdir(parents=True, exist_ok=False)

    defaults, finding = select_one_finding(source_findings_path, finding_slug)
    renderer_input_path = write_one_finding_input(
        staging_dir / ".inputs" / f"{slug}-{utc_timestamp()}.renderer-input.json",
        defaults,
        finding,
        language=args.language,
    )
    promoted = False
    trashed_existing = ""
    try:
        renderer = script_dir / "render_confirmed_vuln_docx.py"
        run_command(
            [
                sys.executable,
                str(renderer),
                "--input",
                str(renderer_input_path),
                "--output-dir",
                str(work_confirmed),
                "--language",
                args.language,
            ],
            workspace_dir.parent,
        )
        rendered_dirs = [
            path for path in work_confirmed.iterdir()
            if path.is_dir() and not path.name.startswith(".")
        ]
        if len(rendered_dirs) != 1:
            raise BuildError(f"renderer produced {len(rendered_dirs)} bundle directories; expected exactly one")
        rendered = rendered_dirs[0]
        if rendered.name != slug:
            raise BuildError(f"renderer output slug mismatch: expected {slug}, got {rendered.name}")
        staging_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(rendered), str(staging_path))
        write_manifest(
            staging_path,
            contract_path=contract_path,
            workspace_dir=workspace_dir,
            renderer_input_path=renderer_input_path,
            final_path=final_path,
            validation_status="pending",
            promote_status="not_promoted",
        )
        run_command(
            [
                sys.executable,
                str(script_dir / "validate_report_bundle.py"),
                "--bundle-dir",
                str(staging_path),
                "--language",
                args.language,
            ],
            script_dir.parent,
        )
        write_manifest(
            staging_path,
            contract_path=contract_path,
            workspace_dir=workspace_dir,
            renderer_input_path=renderer_input_path,
            final_path=final_path,
            validation_status="passed",
            promote_status="not_promoted",
        )
        if args.replace_existing_validated_bundle and final_path.exists():
            classify_existing_final(final_path, confirmed_dir, language=args.language, script_dir=script_dir)
            trashed_existing = str(move_existing_to_trash(final_path, staging_dir))
        if final_path.exists():
            raise BuildError("final target appeared before promote; refusing to overwrite")
        shutil.move(str(staging_path), str(final_path))
        promoted = True
        write_manifest(
            final_path,
            contract_path=contract_path,
            workspace_dir=workspace_dir,
            renderer_input_path=renderer_input_path,
            final_path=final_path,
            validation_status="passed",
            promote_status="promoted",
        )
        run_command(
            [
                sys.executable,
                str(script_dir / "validate_all_report_bundles.py"),
                "--confirmed-dir",
                str(confirmed_dir),
                "--language",
                args.language,
            ],
            script_dir.parent,
        )
        return {
            "schema_version": 1,
            "status": "promoted",
            "slug": slug,
            "final_path": str(final_path),
            "staging_path": str(staging_path),
            "renderer_input_path": str(renderer_input_path),
            "trashed_existing": trashed_existing,
        }
    except Exception:
        if staging_path.exists() and not promoted:
            try:
                write_manifest(
                    staging_path,
                    contract_path=contract_path,
                    workspace_dir=workspace_dir,
                    renderer_input_path=renderer_input_path,
                    final_path=final_path,
                    validation_status="failed",
                    promote_status="failed",
                )
            except Exception:
                pass
            if not args.keep_failed_staging:
                shutil.rmtree(staging_path, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def main() -> None:
    args = parse_args()
    try:
        result = build(args)
    except BuildError as exc:
        if args.json:
            print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False, indent=2))
        else:
            print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"PROMOTED: {result['final_path']}")


if __name__ == "__main__":
    main()
