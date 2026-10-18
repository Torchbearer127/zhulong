#!/usr/bin/env python3
"""Regression tests for the boundary between paths and portable free text."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import hashlib
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from candidate_identity import (
    IdentityError,
    _portable_text,
    build_identity,
    normalize_provenance,
    resolve_regular_file,
    safe_relative_path,
    validate_identity,
)
from verify_candidate import _read_git_tree, _validate_source_refs


VALID_PROMPT_PATHS = (
    "test/server/system-prompt-extraction.unit.test.ts",
    "src/system_prompt_policy.py",
    "routes/login.ts",
)

INVALID_PATHS = (
    "../escape.py",
    "/tmp/local.py",
    "~/local.py",
    "file://local.py",
    "https://example.test/local.py",
    "C:/local.py",
    r"C:\\local.py",
    r"src\\local.py",
    "a//b",
    "a/./b",
    "",
    "bad\x00name.py",
    "bad\nname.py",
)


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def test_prompt_named_paths_are_structurally_valid() -> None:
    for value in VALID_PROMPT_PATHS:
        assert safe_relative_path(value, "test path") == value

    with tempfile.TemporaryDirectory(prefix="zhulong-path-semantics-") as raw_root:
        root = Path(raw_root)
        source = root / "src" / "system_prompt_policy.py"
        source.parent.mkdir(parents=True)
        source.write_text("POLICY = True\n", encoding="utf-8")
        assert resolve_regular_file(root, "src/system_prompt_policy.py", "source path").resolve() == source.resolve()


def test_git_tree_accepts_prompt_named_regular_files() -> None:
    with tempfile.TemporaryDirectory(prefix="zhulong-git-tree-") as raw_root:
        repo = Path(raw_root)
        for relative, contents in {
            VALID_PROMPT_PATHS[0]: "export const ok = true;\n",
            VALID_PROMPT_PATHS[1]: "POLICY = True\n",
            VALID_PROMPT_PATHS[2]: "export const login = true;\n",
        }.items():
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        run_git(repo, "init", "-q")
        run_git(repo, "config", "user.email", "zhulong-selftest@example.invalid")
        run_git(repo, "config", "user.name", "Zhulong selftest")
        run_git(repo, "add", "--all")
        run_git(repo, "commit", "-q", "-m", "path semantics fixture", "--no-gpg-sign")
        commit = run_git(repo, "rev-parse", "HEAD")
        tree = _read_git_tree(repo, commit)
        assert set(VALID_PROMPT_PATHS).issubset(tree)
        assert tree[VALID_PROMPT_PATHS[0]].raw == b"export const ok = true;\n"
        source_bytes = tree[VALID_PROMPT_PATHS[0]].raw
        _validate_source_refs(
            repo,
            tree,
            [
                {
                    "path": VALID_PROMPT_PATHS[0],
                    "sha256": "sha256:" + hashlib.sha256(source_bytes).hexdigest(),
                    "line_start": 1,
                    "line_end": 1,
                    "token": "export const ok",
                }
            ],
        )


def test_candidate_identity_and_provenance_accept_prompt_named_paths() -> None:
    tested_ref = "fixture-ref-001"
    candidate = {
        "target_ref": {"tested_ref": tested_ref},
        "entrypoint": {"id": "login", "kind": "http", "route": "POST /login"},
    }
    identity = build_identity(
        candidate,
        {
            "target_commit": tested_ref,
            "trust_boundary_id": "public",
            "sink_family": "database_query",
            "root_cause_family": "injection",
            "primary_source_path": "src/system_prompt_policy.py",
        },
    )
    assert validate_identity(candidate, identity) == identity
    normalized = normalize_provenance(
        [
            {
                "source_kind": "manual_review",
                "source_id": "review.1",
                "artifact_path": VALID_PROMPT_PATHS[0],
                "artifact_sha256": "sha256:" + "a" * 64,
            }
        ]
    )
    assert normalized[0]["artifact_path"] == VALID_PROMPT_PATHS[0]


def test_unsafe_paths_remain_rejected() -> None:
    for value in INVALID_PATHS:
        try:
            safe_relative_path(value, "unsafe path")
        except IdentityError:
            continue
        raise AssertionError(f"unsafe path was accepted: {value!r}")


def test_free_text_filter_remains_strict() -> None:
    for value in ("system_prompt", "hidden reasoning", "token=fixture-value"):
        try:
            _portable_text(value, "free text")
        except IdentityError:
            continue
        raise AssertionError(f"sensitive free text was accepted: {value!r}")


def main() -> None:
    test_prompt_named_paths_are_structurally_valid()
    test_git_tree_accepts_prompt_named_regular_files()
    test_candidate_identity_and_provenance_accept_prompt_named_paths()
    test_unsafe_paths_remain_rejected()
    test_free_text_filter_remains_strict()
    print("source path semantics selftest: PASS")


if __name__ == "__main__":
    main()
