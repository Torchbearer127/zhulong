#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate every per-vulnerability report bundle under the current audit workspace confirmed/ directory."
    )
    parser.add_argument("--confirmed-dir", required=True, help="Path to the confirmed/ directory.")
    parser.add_argument("--language", choices=["zh-CN", "en-US", "auto"], default="auto")
    parser.add_argument("--with-libreoffice", action="store_true")
    parser.add_argument("--with-markitdown", action="store_true")
    return parser.parse_args()


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

    bundle_dirs = sorted(
        path for path in confirmed_dir.iterdir()
        if path.is_dir() and not path.name.startswith(".")
    )
    if not bundle_dirs:
        raise SystemExit(f"no bundle directories found under {confirmed_dir}")

    failures: list[str] = []
    for bundle_dir in bundle_dirs:
        command = [sys.executable, str(validator), "--bundle-dir", str(bundle_dir), "--language", args.language]
        if args.with_libreoffice:
            command.append("--with-libreoffice")
        if args.with_markitdown:
            command.append("--with-markitdown")
        proc = subprocess.run(command, capture_output=True, text=True)
        output = ((proc.stdout or "") + (proc.stderr or "")).strip()
        print(f"[bundle] {bundle_dir.name}")
        if output:
            print(output)
        if proc.returncode != 0:
            failures.append(bundle_dir.name)
        print("")

    if failures:
        raise SystemExit(f"VALIDATION FAILED for bundles: {', '.join(failures)}")

    print(f"VALIDATION PASSED for all bundles under {confirmed_dir}")


if __name__ == "__main__":
    main()
