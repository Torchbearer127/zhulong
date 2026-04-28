#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


IGNORED_HELPER_FILES = {
    "findings.example.json",
    "confirmed-vuln-report-template.docx",
}


@dataclass
class Classification:
    name: str
    path: str
    classification: str
    missing_artifacts: list[str] = field(default_factory=list)
    reason: str = ""
    validation_output: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "path": self.path,
            "classification": self.classification,
            "missing_artifacts": self.missing_artifacts,
            "reason": self.reason,
            "validation_output": self.validation_output,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate every per-vulnerability report bundle under the current audit workspace confirmed/ directory."
    )
    parser.add_argument("--confirmed-dir", required=True, help="Path to the confirmed/ directory.")
    parser.add_argument("--language", choices=["zh-CN", "en-US", "auto"], default="auto")
    parser.add_argument("--with-libreoffice", action="store_true")
    parser.add_argument("--with-markitdown", action="store_true")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable bundle classifications instead of the text report.",
    )
    return parser.parse_args()


def relpath(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.name


def is_ignored_helper(path: Path) -> bool:
    if path.name.startswith("."):
        return True
    if path.is_file() and path.name in IGNORED_HELPER_FILES:
        return True
    if path.is_file() and path.name == "findings.json":
        # Renderer input may live at confirmed/findings.json; it is not a bundle.
        return True
    return False


def artifact_state(bundle_dir: Path) -> dict[str, bool]:
    markdown_files = [path for path in bundle_dir.glob("*.md") if path.is_file()]
    scripts = [
        path for path in bundle_dir.glob("*.sh")
        if path.is_file() and path.name.startswith("run-")
    ]
    attachments = bundle_dir / "attachments"
    return {
        "docx report": any(path.is_file() for path in bundle_dir.glob("*.docx")),
        "attachment index markdown": any(
            "附件目录说明" in path.name
            or "attachment_index" in path.name
            or "attachment-index" in path.name
            for path in markdown_files
        ),
        "reproduction supplement markdown": any(
            "补充复现说明" in path.name
            or "reproduction_note" in path.name
            or "reproduction-note" in path.name
            or "reproduction" in path.name
            for path in markdown_files
        ),
        "attachments/": attachments.exists()
        and attachments.is_dir()
        and any(path.is_file() for path in attachments.rglob("*")),
        "bundle-root reproduction helper": bool(scripts),
        "verification-evidence.json": (bundle_dir / "verification-evidence.json").is_file(),
    }


def classify_bundle(
    bundle_dir: Path,
    confirmed_dir: Path,
    validator: Path,
    args: argparse.Namespace,
) -> Classification:
    state = artifact_state(bundle_dir)
    missing = [name for name, present in state.items() if not present]
    looks_like_finding = (
        (bundle_dir / "verification-evidence.json").exists()
        or (bundle_dir / "findings.json").exists()
        or any(path.is_file() for path in bundle_dir.glob("*.docx"))
        or any(path.is_file() for path in bundle_dir.glob("*.md"))
        or (bundle_dir / "attachments").exists()
    )
    if missing:
        label = "partial confirmed bundle" if looks_like_finding else "incomplete confirmed directory"
        return Classification(
            name=bundle_dir.name,
            path=relpath(bundle_dir, confirmed_dir),
            classification="partial_confirmed_bundle",
            missing_artifacts=missing,
            reason=f"{label}: missing {', '.join(missing)}",
        )

    command = [sys.executable, str(validator), "--bundle-dir", str(bundle_dir), "--language", args.language]
    if args.with_libreoffice:
        command.append("--with-libreoffice")
    if args.with_markitdown:
        command.append("--with-markitdown")
    proc = subprocess.run(command, capture_output=True, text=True)
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if proc.returncode != 0:
        return Classification(
            name=bundle_dir.name,
            path=relpath(bundle_dir, confirmed_dir),
            classification="validation_failed",
            reason="bundle artifacts are present but validate_report_bundle.py failed",
            validation_output=output,
        )
    return Classification(
        name=bundle_dir.name,
        path=relpath(bundle_dir, confirmed_dir),
        classification="bundle_validated",
        validation_output=output,
    )


def build_report(confirmed_dir: Path, validator: Path, args: argparse.Namespace) -> list[Classification]:
    results: list[Classification] = []
    for entry in sorted(confirmed_dir.iterdir(), key=lambda path: path.name):
        if is_ignored_helper(entry):
            results.append(
                Classification(
                    name=entry.name,
                    path=relpath(entry, confirmed_dir),
                    classification="ignored_helper_file",
                    reason="known confirmed/ helper, template, input file, dotfile, or hidden directory",
                )
            )
            continue
        if not entry.is_dir():
            results.append(
                Classification(
                    name=entry.name,
                    path=relpath(entry, confirmed_dir),
                    classification="ignored_helper_file",
                    reason="non-directory entry under confirmed/ is not a per-vulnerability bundle",
                )
            )
            continue
        results.append(classify_bundle(entry, confirmed_dir, validator, args))
    return results


def summary_counts(results: list[Classification]) -> dict[str, int]:
    keys = (
        "bundle_validated",
        "partial_confirmed_bundle",
        "ignored_helper_file",
        "validation_failed",
    )
    return {key: sum(1 for item in results if item.classification == key) for key in keys}


def emit_json(confirmed_dir: Path, results: list[Classification]) -> None:
    payload = {
        "confirmed_dir": str(confirmed_dir),
        "summary": summary_counts(results),
        "results": [item.as_dict() for item in results],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


def emit_text(confirmed_dir: Path, results: list[Classification]) -> None:
    counts = summary_counts(results)
    print(f"confirmed_dir={confirmed_dir}")
    print("summary:")
    for key, value in counts.items():
        print(f"- {key}: {value}")
    print("")
    for item in results:
        print(f"[{item.classification}] {item.name}")
        if item.missing_artifacts:
            print(f"missing_artifacts={', '.join(item.missing_artifacts)}")
        if item.reason:
            print(f"reason={item.reason}")
        if item.validation_output:
            print(item.validation_output)
        print("")


def main() -> None:
    args = parse_args()
    confirmed_dir = Path(args.confirmed_dir).expanduser().resolve()
    if not confirmed_dir.exists() or not confirmed_dir.is_dir():
        raise SystemExit(f"confirmed directory does not exist: {confirmed_dir}")

    script_dir = Path(__file__).resolve().parent
    validator_candidates = [
        script_dir / "validate_report_bundle.py",
        script_dir / "validate-report-bundle.py",
    ]
    validator = next((path for path in validator_candidates if path.exists()), None)
    if validator is None:
        candidates = ", ".join(str(path) for path in validator_candidates)
        raise SystemExit(f"validator script not found; checked: {candidates}")

    results = build_report(confirmed_dir, validator, args)
    counts = summary_counts(results)
    if args.json:
        emit_json(confirmed_dir, results)
    else:
        emit_text(confirmed_dir, results)

    failed = [
        item.name for item in results
        if item.classification in {"partial_confirmed_bundle", "validation_failed"}
    ]
    if failed:
        raise SystemExit(
            "VALIDATION FAILED: partial confirmed bundle or validation failure detected: "
            + ", ".join(failed)
        )

    if counts["bundle_validated"] == 0:
        raise SystemExit(f"VALIDATION FAILED: no validated bundle directories found under {confirmed_dir}")

    if not args.json:
        print(f"VALIDATION PASSED for all bundles under {confirmed_dir}")


if __name__ == "__main__":
    main()
