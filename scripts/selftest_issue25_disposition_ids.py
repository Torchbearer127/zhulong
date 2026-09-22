#!/usr/bin/env python3
"""Focused offline regression checks for issue #25 disposition identities."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_ROOT))

import audit_disposition as disposition_module  # noqa: E402
from audit_disposition import (  # noqa: E402
    DispositionUpdateError,
    blocked_verification_items,
    synthesize_disposition_ledger,
    write_disposition_ledger,
)
from blocked_verification import detect_blocked_verification  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAILED: {message}")


def structured(identity: str, *, classification: str = "blocked", excerpt: str = "runtime blocked") -> dict[str, object]:
    return {
        "source": "audit-disposition.json",
        "identity": identity,
        "classification": classification,
        "excerpt": excerpt,
        "structured": True,
    }


TRIAGE_TABLE = "| Candidate ID | Suspected Weakness | Status |\n| --- | --- | --- |\n| C-1 | triage note | pending |\n"


def run_disposition_write(workspace: Path) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(SCRIPT_ROOT / "audit_disposition.py"), "--workspace-dir", str(workspace), "--write"]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(command, cwd=SCRIPT_ROOT.parent, env=env, capture_output=True, text=True)


def test_structured_identity_ids() -> None:
    findings = [structured("lead/a"), structured("lead-a")]
    forward = blocked_verification_items(Path("/nonexistent"), {"findings": findings})
    reverse = blocked_verification_items(Path("/nonexistent"), {"findings": list(reversed(findings))})
    forward_ids = [item["id"] for item in forward]
    reverse_ids = [item["id"] for item in reverse]
    require(len(set(forward_ids)) == 2, "structured identities must not collide after slug normalization")
    require(
        {finding["identity"]: item["id"] for finding, item in zip(findings, forward)}
        == {finding["identity"]: item["id"] for finding, item in zip(reversed(findings), reverse)},
        "structured IDs must be stable across input order",
    )


def test_duplicate_and_conflicting_identity() -> None:
    duplicate = structured("lead-1")
    items = blocked_verification_items(Path("/nonexistent"), {"findings": [duplicate, dict(duplicate)]})
    require(len(items) == 1, "identical structured duplicate must be idempotent")
    try:
        blocked_verification_items(
            Path("/nonexistent"),
            {"findings": [structured("lead-1"), structured("lead-1", classification="timed_out")]},
        )
    except DispositionUpdateError as exc:
        require("STRUCTURED_IDENTITY_CONFLICT" in str(exc), "identity conflict must have a stable error code")
    else:
        raise SystemExit("FAILED: conflicting structured identity was accepted")

    sensitive = structured("path=/tmp/private?token=redacted")
    item = blocked_verification_items(Path("/nonexistent"), {"findings": [sensitive]})[0]
    require("redacted" not in item["materiality_rationale"], "structured rationale leaked the raw identity")
    try:
        blocked_verification_items(
            Path("/nonexistent"),
            {"findings": [sensitive, structured(sensitive["identity"], classification="timed_out")]},
        )
    except DispositionUpdateError as exc:
        require("STRUCTURED_IDENTITY_CONFLICT" in str(exc), "structured conflict lost its stable error code")
        require("redacted" not in str(exc), "structured conflict leaked the raw identity")
    else:
        raise SystemExit("FAILED: sensitive structured identity conflict was accepted")


def test_missing_identity_and_legacy_line() -> None:
    try:
        blocked_verification_items(
            Path("/nonexistent"),
            {"findings": [{"source": "verification-result.json", "classification": "blocked", "structured": True}]},
        )
    except DispositionUpdateError as exc:
        require("STRUCTURED_IDENTITY_MISSING" in str(exc), "missing structured identity must be explicit")
    else:
        raise SystemExit("FAILED: missing structured identity was silently accepted")

    try:
        blocked_verification_items(
            Path("/nonexistent"),
            {"findings": [structured("lead-\x00malformed")]},
        )
    except DispositionUpdateError as exc:
        require("STRUCTURED_IDENTITY_INVALID" in str(exc), "malformed structured identity must be explicit")
    else:
        raise SystemExit("FAILED: malformed structured identity was silently accepted")

    try:
        blocked_verification_items(
            Path("/nonexistent"),
            {"findings": [{"source": "verification-result.json", "classification": "blocked"}]},
        )
    except DispositionUpdateError as exc:
        require("LEGACY_FINDING_LINE_MISSING" in str(exc), "unstructured finding without a line was silently accepted")
    else:
        raise SystemExit("FAILED: unstructured finding without identity or line was silently accepted")

    legacy = blocked_verification_items(
        Path("/nonexistent"),
        {"findings": [{"source": "unverified-leads.md", "line": 7, "classification": "docker_verification_blocked"}]},
    )
    require(legacy[0]["id"] == "blocked:unverified-leads.md:7", "legacy line-number ID format changed")


def test_ledger_self_reference_does_not_expand() -> None:
    with tempfile.TemporaryDirectory(prefix="zhulong-issue25-identity-") as raw:
        workspace = Path(raw)
        (workspace / "unverified-leads.md").write_text("BLOCKED docker verification\n", encoding="utf-8")
        first_summary = detect_blocked_verification(workspace)
        first = synthesize_disposition_ledger(workspace, blocked_summary=first_summary, merge_existing=False)
        (workspace / "audit-disposition.json").write_text(json.dumps(first, sort_keys=True) + "\n", encoding="utf-8")
        second_summary = detect_blocked_verification(workspace)
        second = synthesize_disposition_ledger(workspace, blocked_summary=second_summary, merge_existing=False)
        first_ids = [item["id"] for item in first["items"]]
        second_ids = [item["id"] for item in second["items"]]
        require(first_ids == second_ids, "reading the generated ledger must not change blocked IDs")
        require(len(second_ids) == len(set(second_ids)), "self-reference must not create duplicate IDs")


def test_generated_structured_ledger_remains_blocking() -> None:
    with tempfile.TemporaryDirectory(prefix="zhulong-issue25-generated-ledger-") as raw:
        workspace = Path(raw)
        first = synthesize_disposition_ledger(
            workspace,
            blocked_summary={"findings": [structured("case:only-ledger")]},
            merge_existing=False,
        )
        write_disposition_ledger(workspace, first)
        feedback = detect_blocked_verification(workspace)
        require(feedback["blocked"] is True, "ledger-only generated structured item was ignored")
        require(
            any(item["identity"] == f"disposition:{first['items'][0]['id']}" for item in feedback["findings"]),
            "ledger-only generated structured identity was not read back",
        )
        second = synthesize_disposition_ledger(workspace, blocked_summary=feedback, merge_existing=False)
        require(
            [item["id"] for item in second["items"]] == [item["id"] for item in first["items"]],
            "ledger-only generated structured item changed identity on refresh",
        )


def test_ledger_facts_and_unsafe_paths_remain_blocking() -> None:
    with tempfile.TemporaryDirectory(prefix="zhulong-issue25-ledger-facts-") as raw:
        workspace = Path(raw)
        ledger_path = workspace / "audit-disposition.json"

        ledger_path.write_text(
            json.dumps({"candidate_dispositions": [{"candidate_id": "manual-candidate", "status": "blocked"}]}) + "\n",
            encoding="utf-8",
        )
        candidate_summary = detect_blocked_verification(workspace)
        require(candidate_summary["blocked"] is True, "ledger-only blocked candidate was ignored")
        require(any(item["identity"] == "candidate:manual-candidate" for item in candidate_summary["findings"]), "blocked candidate identity missing")

        ledger_path.write_text(
            json.dumps(
                {"items": [{"id": "blocked:manual", "state": "blocked", "source_type": "manual", "docker_status": "blocked"}]}
            )
            + "\n",
            encoding="utf-8",
        )
        manual_summary = detect_blocked_verification(workspace)
        require(manual_summary["blocked"] is True, "ledger-only manual blocked item was ignored")
        require(any(item["identity"] == "disposition:blocked:manual" for item in manual_summary["findings"]), "manual item identity missing")

        ledger_path.write_text("{not-json\n", encoding="utf-8")
        invalid_summary = detect_blocked_verification(workspace)
        require(invalid_summary["blocked"] is True, "invalid ledger was not blocking")
        require(any(item["identity"] == "artifact:audit-disposition.json" for item in invalid_summary["findings"]), "invalid ledger fact missing")

        target = workspace / "ledger-target.json"
        target.write_text(json.dumps({"items": []}) + "\n", encoding="utf-8")
        ledger_path.unlink()
        ledger_path.symlink_to(target.name)
        symlink_summary = detect_blocked_verification(workspace)
        require(symlink_summary["blocked"] is True, "symlink ledger was not blocking")
        require(any(item["identity"] == "artifact:audit-disposition.json" for item in symlink_summary["findings"]), "symlink ledger fact missing")


def test_cli_write_read_write_keeps_structured_ids() -> None:
    with tempfile.TemporaryDirectory(prefix="zhulong-issue25-cli-") as raw:
        workspace = Path(raw)
        for case_id in ("CLI-A", "CLI-B"):
            result_path = workspace / "evidence" / case_id / "verification-result.json"
            result_path.parent.mkdir(parents=True, exist_ok=True)
            result_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "case_id": case_id,
                        "wrapper_status": "blocked_missing_image",
                        "authority_event_committed": True,
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

        command = [sys.executable, str(SCRIPT_ROOT / "audit_disposition.py"), "--workspace-dir", str(workspace), "--write"]
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        first = subprocess.run(command, cwd=SCRIPT_ROOT.parent, env=env, capture_output=True, text=True)
        require(first.returncode == 0, f"first production --write failed: {first.stdout} {first.stderr}")
        first_doc = json.loads((workspace / "audit-disposition.json").read_text(encoding="utf-8"))
        first_ids = [item["id"] for item in first_doc["items"]]
        require(len(first_ids) == 2 and len(set(first_ids)) == 2, "first CLI write did not retain both structured findings")

        second = subprocess.run(command, cwd=SCRIPT_ROOT.parent, env=env, capture_output=True, text=True)
        require(second.returncode == 0, f"second production --write failed: {second.stdout} {second.stderr}")
        second_doc = json.loads((workspace / "audit-disposition.json").read_text(encoding="utf-8"))
        second_ids = [item["id"] for item in second_doc["items"]]
        require(second_ids == first_ids, "production CLI write/read/write expanded or reordered structured IDs")


def test_cli_preserves_manual_blocked_ledger_fact() -> None:
    with tempfile.TemporaryDirectory(prefix="zhulong-issue25-manual-cli-") as raw:
        workspace = Path(raw)
        (workspace / "audit-disposition.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "candidate_dispositions": [],
                    "items": [
                        {
                            "id": "blocked:manual",
                            "title": "Manual blocker",
                            "state": "blocked",
                            "source_type": "manual",
                            "docker_applicable": True,
                            "docker_status": "blocked",
                            "reason_code": "blocked_by_docker",
                            "confirmed_bundle_path": "",
                            "materiality_rationale": "Manual review blocker",
                        }
                    ],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        command = [sys.executable, str(SCRIPT_ROOT / "audit_disposition.py"), "--workspace-dir", str(workspace), "--write"]
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        for attempt in range(2):
            proc = subprocess.run(command, cwd=SCRIPT_ROOT.parent, env=env, capture_output=True, text=True)
            require(proc.returncode == 0, f"manual ledger CLI write {attempt + 1} failed: {proc.stdout} {proc.stderr}")
            document = json.loads((workspace / "audit-disposition.json").read_text(encoding="utf-8"))
            ids = [item["id"] for item in document["items"]]
            require("blocked:manual" in ids, "manual blocked ledger item was dropped by synthesis")


def test_triage_feedback_is_deduplicated_at_synthesis_boundary() -> None:
    for filename, expected_state in (("candidate-findings.md", "candidate"), ("unverified-leads.md", "unverified")):
        with tempfile.TemporaryDirectory(prefix="zhulong-issue25-triage-") as raw:
            workspace = Path(raw)
            source = workspace / filename
            source.write_text(TRIAGE_TABLE, encoding="utf-8")
            first = run_disposition_write(workspace)
            require(first.returncode == 0, f"{filename} first production write failed: {first.stdout} {first.stderr}")
            first_doc = json.loads((workspace / "audit-disposition.json").read_text(encoding="utf-8"))
            first_ids = [item["id"] for item in first_doc["items"]]
            require(first_ids == [f"{filename.removesuffix('.md')}:c-1"], f"{filename} first ID was not preserved")
            require(first_doc["items"][0]["state"] == expected_state, f"{filename} source state changed on first write")

            for attempt in (2, 3):
                proc = run_disposition_write(workspace)
                require(proc.returncode == 0, f"{filename} feedback write {attempt} failed: {proc.stdout} {proc.stderr}")
                document = json.loads((workspace / "audit-disposition.json").read_text(encoding="utf-8"))
                require([item["id"] for item in document["items"]] == first_ids, f"{filename} feedback expanded IDs")
                require(document["items"][0]["state"] == expected_state, f"{filename} feedback changed source state")

            source.unlink()
            for attempt in (4, 5):
                proc = run_disposition_write(workspace)
                require(proc.returncode == 0, f"{filename} ledger-only write {attempt} failed: {proc.stdout} {proc.stderr}")
                document = json.loads((workspace / "audit-disposition.json").read_text(encoding="utf-8"))
                require([item["id"] for item in document["items"]] == first_ids, f"{filename} ledger-only ID changed")

    with tempfile.TemporaryDirectory(prefix="zhulong-issue25-triage-mixed-") as raw:
        workspace = Path(raw)
        (workspace / "candidate-findings.md").write_text(TRIAGE_TABLE, encoding="utf-8")
        result_path = workspace / "evidence" / "CASE-TRIAGE" / "verification-result.json"
        result_path.parent.mkdir(parents=True)
        result_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "case_id": "CASE-TRIAGE",
                    "wrapper_status": "blocked_missing_image",
                    "authority_event_committed": True,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        expected_ids = None
        for attempt in (1, 2, 3):
            proc = run_disposition_write(workspace)
            require(proc.returncode == 0, f"mixed triage write {attempt} failed: {proc.stdout} {proc.stderr}")
            document = json.loads((workspace / "audit-disposition.json").read_text(encoding="utf-8"))
            ids = [item["id"] for item in document["items"]]
            expected_ids = ids if expected_ids is None else expected_ids
            require(ids == expected_ids and len(ids) == 2, "mixed triage feedback changed item IDs or count")
            triage_item = next(item for item in document["items"] if item["id"] == "candidate-findings:c-1")
            structured_item = next(item for item in document["items"] if item["id"].startswith("blocked:structured:"))
            require(triage_item["state"] == "candidate", "triage source was changed to blocked by ledger feedback")
            require(structured_item["state"] == "blocked", "real structured blocked fact was dropped")


def test_duplicate_triage_source_rejects_without_overwriting_ledger() -> None:
    with tempfile.TemporaryDirectory(prefix="zhulong-issue25-triage-duplicate-") as raw:
        workspace = Path(raw)
        source = workspace / "candidate-findings.md"
        source.write_text(TRIAGE_TABLE, encoding="utf-8")
        first = run_disposition_write(workspace)
        require(first.returncode == 0, f"duplicate fixture seed write failed: {first.stdout} {first.stderr}")
        ledger_path = workspace / "audit-disposition.json"
        before = ledger_path.read_bytes()
        source.write_text(TRIAGE_TABLE + "| C-1 | repeated triage note | pending |\n", encoding="utf-8")
        duplicate = run_disposition_write(workspace)
        require(duplicate.returncode == 1, "duplicate triage row was silently accepted")
        require("TRIAGE_ITEM_ID_CONFLICT" in duplicate.stdout, "duplicate triage row lacked stable error code")
        require(ledger_path.read_bytes() == before, "duplicate triage failure changed old ledger bytes")


def test_existing_blocked_triage_identity_is_not_downgraded() -> None:
    with tempfile.TemporaryDirectory(prefix="zhulong-issue25-triage-blocked-") as raw:
        workspace = Path(raw)
        (workspace / "candidate-findings.md").write_text(TRIAGE_TABLE, encoding="utf-8")
        (workspace / "audit-disposition.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "candidate_dispositions": [],
                    "items": [
                        {
                            "id": "candidate-findings:c-1",
                            "title": "Existing manual blocker",
                            "state": "blocked",
                            "source_type": "manual",
                            "docker_applicable": True,
                            "docker_status": "blocked",
                            "reason_code": "blocked_by_docker",
                            "confirmed_bundle_path": "",
                            "materiality_rationale": "Existing blocked fact",
                        }
                    ],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        proc = run_disposition_write(workspace)
        require(proc.returncode == 0, f"existing blocked triage write failed: {proc.stdout} {proc.stderr}")
        document = json.loads((workspace / "audit-disposition.json").read_text(encoding="utf-8"))
        item = next(item for item in document["items"] if item["id"] == "candidate-findings:c-1")
        require(item["state"] == "blocked", "existing blocked triage identity was downgraded")
        require(item["source_type"] == "manual", "existing blocked triage source type was replaced")


def test_preview_failure_does_not_report_zero_unresolved() -> None:
    original = disposition_module.synthesize_disposition_ledger

    def fail_preview(*args: object, **kwargs: object) -> dict[str, object]:
        raise DispositionUpdateError("STRUCTURED_IDENTITY_CONFLICT: preview fixture")

    disposition_module.synthesize_disposition_ledger = fail_preview  # type: ignore[assignment]
    try:
        lines = disposition_module.render_unresolved_disposition_lines(Path("/nonexistent"))
    finally:
        disposition_module.synthesize_disposition_ledger = original  # type: ignore[assignment]
    rendered = "\n".join(lines)
    require("Ledger synthesis failed:" in rendered, "preview synthesis failure was not surfaced")
    require("Unresolved disposition items:" not in rendered, "preview failure fabricated an unresolved count")


def test_duplicate_write_preserves_old_bytes() -> None:
    with tempfile.TemporaryDirectory(prefix="zhulong-issue25-write-") as raw:
        workspace = Path(raw)
        old_ledger = synthesize_disposition_ledger(
            workspace,
            blocked_summary={"findings": []},
            merge_existing=False,
        )
        write_disposition_ledger(workspace, old_ledger)
        ledger_path = workspace / "audit-disposition.json"
        before = ledger_path.read_bytes()
        item = blocked_verification_items(Path("/nonexistent"), {"findings": [structured("write-id")]})[0]
        invalid = dict(old_ledger)
        invalid["items"] = [item, dict(item)]
        try:
            write_disposition_ledger(workspace, invalid)
        except DispositionUpdateError as exc:
            require("duplicate disposition id" in str(exc), "duplicate write must retain validator rejection")
        else:
            raise SystemExit("FAILED: duplicate disposition write was accepted")
        require(ledger_path.read_bytes() == before, "failed disposition write changed the old ledger bytes")


def main() -> int:
    test_structured_identity_ids()
    test_duplicate_and_conflicting_identity()
    test_missing_identity_and_legacy_line()
    test_ledger_self_reference_does_not_expand()
    test_generated_structured_ledger_remains_blocking()
    test_ledger_facts_and_unsafe_paths_remain_blocking()
    test_cli_write_read_write_keeps_structured_ids()
    test_cli_preserves_manual_blocked_ledger_fact()
    test_triage_feedback_is_deduplicated_at_synthesis_boundary()
    test_duplicate_triage_source_rejects_without_overwriting_ledger()
    test_existing_blocked_triage_identity_is_not_downgraded()
    test_preview_failure_does_not_report_zero_unresolved()
    test_duplicate_write_preserves_old_bytes()
    print("ISSUE 25 DISPOSITION ID SELFTEST PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
