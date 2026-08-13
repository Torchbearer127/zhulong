#!/usr/bin/env python3
"""Focused RH.S1 source and installed-layout secret-fixture hygiene regression."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

from audit_text_safety import sensitive_value_kind


ISSUE_CODE = "AWS_ACCESS_KEY_ID_LITERAL"
AWS_ACCESS_KEY_ID_LITERAL_RE = re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}")
IGNORED_RUNTIME_DIRS = {".git", ".omc", ".pytest_cache", "__pycache__"}


def synthetic_aws_access_key_id(prefix: str) -> str:
    if prefix not in {"AKIA", "ASIA"}:
        raise ValueError("unsupported synthetic AWS access key ID prefix")
    suffix = "".join(chr(ord("A") + ((index * 7 + 3) % 26)) for index in range(16))
    return prefix + suffix


def candidate_paths(skill_root: Path) -> list[Path]:
    if (skill_root / ".git").exists():
        proc = subprocess.run(
            [
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            cwd=skill_root,
            capture_output=True,
        )
        if proc.returncode != 0:
            raise SystemExit("FAILED: RH.S1 could not enumerate the Git commit candidate")
        paths = []
        for raw_path in proc.stdout.split(b"\0"):
            if not raw_path:
                continue
            path = skill_root / os.fsdecode(raw_path)
            if path.exists() or path.is_symlink():
                paths.append(path)
        return sorted(paths, key=lambda path: path.relative_to(skill_root).as_posix())

    paths = []
    for path in skill_root.rglob("*"):
        relative = path.relative_to(skill_root)
        if any(part in IGNORED_RUNTIME_DIRS for part in relative.parts):
            continue
        if path.is_file() or path.is_symlink():
            paths.append(path)
    return sorted(paths, key=lambda path: path.relative_to(skill_root).as_posix())


def path_bytes(path: Path) -> bytes:
    try:
        if path.is_symlink():
            return os.fsencode(os.readlink(path))
        return path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"FAILED: RH.S1 could not read candidate path {path.name}") from exc


def scan_root(skill_root: Path) -> tuple[int, list[tuple[str, int]]]:
    scanned = 0
    matches: list[tuple[str, int]] = []
    for path in candidate_paths(skill_root):
        scanned += 1
        count = len(AWS_ACCESS_KEY_ID_LITERAL_RE.findall(path_bytes(path)))
        if count:
            matches.append((path.relative_to(skill_root).as_posix(), count))
    return scanned, matches


def format_diagnostic(matches: list[tuple[str, int]]) -> str:
    locations = ", ".join(f"{path}:{count}" for path, count in matches)
    return f"{ISSUE_CODE}: {locations}"


def main() -> int:
    skill_root = Path(__file__).resolve().parent.parent
    scanned, matches = scan_root(skill_root)
    if matches:
        raise SystemExit(f"FAILED: {format_diagnostic(matches)}")

    synthetic_values = tuple(
        synthetic_aws_access_key_id(prefix) for prefix in ("AKIA", "ASIA")
    )
    for value in synthetic_values:
        if AWS_ACCESS_KEY_ID_LITERAL_RE.fullmatch(value.encode("ascii")) is None:
            raise SystemExit("FAILED: runtime AWS access key ID fixture has the wrong shape")
        if sensitive_value_kind(value) != "aws_access_key_id":
            raise SystemExit("FAILED: runtime AWS access key ID fixture was not classified")

    with tempfile.TemporaryDirectory(prefix="zhulong-rhs1-secret-hygiene-") as raw:
        mutation_root = Path(raw)
        injected_path = mutation_root / "injected.txt"
        injected_path.write_text(synthetic_values[0], encoding="ascii")
        _, injected_matches = scan_root(mutation_root)
        if injected_matches != [("injected.txt", 1)]:
            raise SystemExit("FAILED: RH.S1 static hygiene gate accepted an injected literal")
        diagnostic = format_diagnostic(injected_matches)
        if synthetic_values[0] in diagnostic or ISSUE_CODE not in diagnostic:
            raise SystemExit("FAILED: RH.S1 static hygiene diagnostic exposed a matched value")

        injected_path.write_text(r"(?:AKIA|ASIA)[A-Z0-9]{16}", encoding="ascii")
        _, guard_matches = scan_root(mutation_root)
        if guard_matches:
            raise SystemExit("FAILED: RH.S1 static hygiene gate rejected its guard regex")

    print(
        "RHS1 SECRET FIXTURE HYGIENE SELFTEST PASSED: "
        f"{scanned} candidate files, zero literals, two runtime prefix cases"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
