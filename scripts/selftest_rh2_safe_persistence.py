#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

import evidence_io
from audit_disposition import validate_disposition_ledger, write_disposition_ledger
from evidence_io import SafeEvidenceError, atomic_write_bytes, safe_read_json


def ledger(workspace: Path, generated_at: str) -> dict:
    return {
        "schema_version": 1,
        "generated_at": generated_at,
        "workspace": workspace.name,
        "candidate_dispositions": [],
        "items": [],
    }


def require_failure(callable_object, label: str) -> Exception:
    try:
        callable_object()
    except Exception as exc:
        return exc
    raise SystemExit(f"FAILED: {label} unexpectedly succeeded")


def require_clean_temps(path: Path, label: str) -> None:
    leftovers = [
        item.name
        for item in path.parent.iterdir()
        if item.name.startswith(f".{path.name}.tmp-")
        or item.name.startswith(f".{path.name}.rollback-")
    ]
    if leftovers:
        raise SystemExit(f"FAILED: {label} left temporary files: {leftovers}")


def require_old_bytes(path: Path, expected: bytes, label: str) -> None:
    if path.read_bytes() != expected:
        raise SystemExit(f"FAILED: {label} changed the old ledger bytes")
    require_clean_temps(path, label)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="zhulong-rh2-safe-write-") as raw_temp:
        root = Path(raw_temp)
        workspace = root / "workspace"
        workspace.mkdir()
        (workspace / "confirmed").mkdir()
        path = workspace / "audit-disposition.json"
        old = ledger(workspace, "2026-08-08T00:00:00Z")
        new = ledger(workspace, "2026-08-08T00:00:01Z")
        path.write_text(json.dumps(old, sort_keys=True) + "\n", encoding="utf-8")
        old_raw = path.read_bytes()

        original_write_all = evidence_io._write_all
        with mock.patch.object(evidence_io, "_write_all", side_effect=OSError("injected write failure")):
            require_failure(lambda: write_disposition_ledger(workspace, new), "write fault")
        require_old_bytes(path, old_raw, "write fault")

        original_fsync = evidence_io.os.fsync
        fsync_calls = 0

        def fail_first_fsync(fd: int) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 1:
                raise OSError("injected file fsync failure")
            original_fsync(fd)

        with mock.patch.object(evidence_io.os, "fsync", side_effect=fail_first_fsync):
            require_failure(lambda: write_disposition_ledger(workspace, new), "file fsync fault")
        require_old_bytes(path, old_raw, "file fsync fault")

        with mock.patch.object(evidence_io.os, "replace", side_effect=OSError("injected replace failure")):
            require_failure(lambda: write_disposition_ledger(workspace, new), "replace fault")
        require_old_bytes(path, old_raw, "replace fault")

        original_directory_fsync = evidence_io._fsync_directory
        directory_fsync_calls = 0

        def fail_first_directory_fsync(directory: Path) -> None:
            nonlocal directory_fsync_calls
            directory_fsync_calls += 1
            if directory_fsync_calls == 1:
                raise OSError("injected directory fsync failure")
            original_directory_fsync(directory)

        with mock.patch.object(evidence_io, "_fsync_directory", side_effect=fail_first_directory_fsync):
            require_failure(lambda: write_disposition_ledger(workspace, new), "directory fsync fault")
        require_old_bytes(path, old_raw, "directory fsync fault")

        with mock.patch.object(
            evidence_io,
            "_require_unchanged_target",
            side_effect=SafeEvidenceError("EVIDENCE_TARGET_DRIFT", "injected CAS failure"),
        ):
            require_failure(lambda: write_disposition_ledger(workspace, new), "CAS fault")
        require_old_bytes(path, old_raw, "CAS fault")

        invalid = dict(new)
        invalid["schema_version"] = 999
        require_failure(lambda: write_disposition_ledger(workspace, invalid), "post-write validation fault")
        require_old_bytes(path, old_raw, "post-write validation fault")

        def tamper_after_write(_raw: bytes) -> None:
            path.write_bytes(b"tampered\n")
            raise SafeEvidenceError("EVIDENCE_POST_WRITE_DRIFT", "injected post-write tamper")

        require_failure(
            lambda: atomic_write_bytes(workspace, path, b"published\n", post_write_validator=tamper_after_write),
            "post-write tamper",
        )
        require_old_bytes(path, old_raw, "post-write tamper")

        empty_path = workspace / "empty-reservation.json"
        empty_path.touch(mode=0o600)
        os.chmod(empty_path, 0o600)
        empty_stat = os.lstat(empty_path)
        empty_identity = (
            empty_stat.st_dev,
            empty_stat.st_ino,
            empty_stat.st_nlink,
            empty_stat.st_uid,
            empty_stat.st_mode,
        )
        rollback_stats: list[os.stat_result] = []

        def reject_empty_publication(_raw: bytes) -> None:
            raise SafeEvidenceError("INJECTED_VALIDATOR_FAILURE", "fixture")

        require_failure(
            lambda: atomic_write_bytes(
                workspace,
                empty_path,
                b"published\n",
                expected_target_identity=empty_identity,
                post_write_validator=reject_empty_publication,
                rollback_stat_sink=rollback_stats,
            ),
            "verified empty reservation rollback",
        )
        rollback_info = os.lstat(empty_path)
        if (
            len(rollback_stats) != 1
            or rollback_info.st_ino == empty_stat.st_ino
            or rollback_info.st_size != 0
            or empty_path.read_bytes() != b""
            or (rollback_info.st_dev, rollback_info.st_ino) != (rollback_stats[0].st_dev, rollback_stats[0].st_ino)
            or (rollback_info.st_nlink, rollback_info.st_uid, rollback_info.st_mode)
            != (rollback_stats[0].st_nlink, rollback_stats[0].st_uid, rollback_stats[0].st_mode)
        ):
            raise SystemExit("FAILED: writer did not verify and return its new empty rollback identity")
        require_clean_temps(empty_path, "verified empty reservation rollback")

        unverified_path = workspace / "unverified-empty-reservation.json"
        unverified_path.touch(mode=0o600)
        os.chmod(unverified_path, 0o600)
        unverified_stat = os.lstat(unverified_path)
        unverified_identity = (
            unverified_stat.st_dev,
            unverified_stat.st_ino,
            unverified_stat.st_nlink,
            unverified_stat.st_uid,
            unverified_stat.st_mode,
        )
        unverified_rollback_stats: list[os.stat_result] = []
        original_fsync_directory = evidence_io._fsync_directory
        fsync_directory_calls = 0

        def fail_rollback_directory_fsync(directory: Path) -> None:
            nonlocal fsync_directory_calls
            fsync_directory_calls += 1
            if fsync_directory_calls == 2:
                raise OSError("injected rollback directory fsync failure")
            original_fsync_directory(directory)

        with mock.patch.object(evidence_io, "_fsync_directory", side_effect=fail_rollback_directory_fsync):
            require_failure(
                lambda: atomic_write_bytes(
                    workspace,
                    unverified_path,
                    b"published\n",
                    expected_target_identity=unverified_identity,
                    post_write_validator=reject_empty_publication,
                    rollback_stat_sink=unverified_rollback_stats,
                ),
                "unverified empty reservation rollback",
            )
        if unverified_rollback_stats or unverified_path.read_bytes() != b"":
            raise SystemExit("FAILED: writer returned an identity without durable rollback verification")
        require_clean_temps(unverified_path, "unverified empty reservation rollback")

        original_require = evidence_io._require_unchanged_target
        race_injected = False

        def replace_before_cas(target: Path, expected) -> None:
            nonlocal race_injected
            if not race_injected:
                race_injected = True
                replacement = target.with_name("race-replacement")
                replacement.write_bytes(b"race-winner\n")
                os.replace(replacement, target)
            original_require(target, expected)

        with mock.patch.object(evidence_io, "_require_unchanged_target", side_effect=replace_before_cas):
            require_failure(lambda: write_disposition_ledger(workspace, new), "target replacement race")
        if path.read_bytes() != b"race-winner\n":
            raise SystemExit("FAILED: target replacement race overwrote the replacement object")
        require_clean_temps(path, "target replacement race")
        path.write_bytes(old_raw)

        marker = workspace / "outside-marker"
        marker.write_bytes(b"outside\n")
        path.unlink()
        path.symlink_to(marker)
        require_failure(lambda: write_disposition_ledger(workspace, new), "target symlink")
        if marker.read_bytes() != b"outside\n":
            raise SystemExit("FAILED: target symlink changed its external marker")
        path.unlink()

        os.link(marker, path)
        require_failure(lambda: write_disposition_ledger(workspace, new), "target hardlink")
        if marker.read_bytes() != b"outside\n":
            raise SystemExit("FAILED: target hardlink changed its marker")
        path.unlink()

        os.mkfifo(path)
        require_failure(lambda: write_disposition_ledger(workspace, new), "target FIFO")
        path.unlink()
        path.mkdir()
        require_failure(lambda: write_disposition_ledger(workspace, new), "target directory")
        path.rmdir()

        real_parent = workspace / "real-parent"
        real_parent.mkdir()
        ancestor_marker = real_parent / "ledger.json"
        ancestor_marker.write_bytes(b"ancestor-marker\n")
        alias = workspace / "alias"
        alias.symlink_to(real_parent, target_is_directory=True)
        require_failure(
            lambda: atomic_write_bytes(workspace, alias / "ledger.json", b"new\n"),
            "ancestor symlink",
        )
        if ancestor_marker.read_bytes() != b"ancestor-marker\n":
            raise SystemExit("FAILED: ancestor symlink changed its marker")

        path.write_bytes(old_raw)
        write_disposition_ledger(workspace, new)
        disk = safe_read_json(workspace, path)
        if disk != new:
            raise SystemExit("FAILED: successful disposition write did not survive safe disk readback")
        validation = validate_disposition_ledger(workspace, ledger=disk)
        if not validation.get("ok"):
            raise SystemExit(f"FAILED: durable disposition validation failed: {validation.get('errors')}")
        require_clean_temps(path, "successful write")

        if original_write_all is not evidence_io._write_all:
            raise SystemExit("FAILED: write fault patch leaked outside its context")

    print("RH2 SAFE PERSISTENCE SELFTEST PASSED: filesystem, fault, rollback, disk readback")


if __name__ == "__main__":
    main()
