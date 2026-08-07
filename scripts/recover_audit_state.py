#!/usr/bin/env python3
"""Read-only audit-state diagnostics and explicit CAS-protected state rebuild."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from audit_state_io import AuditStateError, inspect_workspace_recovery, rebuild_state_view


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspect journal/state consistency or explicitly rebuild only stage-status.json."
    )
    parser.add_argument("--workspace-dir", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Read-only check (the default).")
    mode.add_argument("--apply", action="store_true", help="Atomically rebuild only stage-status.json.")
    mode.add_argument("--migration-preflight", action="store_true", help="Read-only R1 migration preflight.")
    parser.add_argument("--expected-journal-digest", default="")
    # These are intentionally parsed independently.  argparse's mutually
    # exclusive group exits before this command can emit its documented JSON
    # error envelope, which made a meaningful CAS-intent conflict look like a
    # syntax error to automation.
    parser.add_argument("--expected-state-digest", default="")
    parser.add_argument("--expect-state-missing", action="store_true")
    parser.add_argument("--lock-timeout-seconds", type=float, default=10.0)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def _redacted(value: Any) -> dict[str, Any]:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"classification": "redacted_protocol_text", "sha256": hashlib.sha256(raw).hexdigest()}


def public_diagnostic(payload: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(json.dumps(payload, ensure_ascii=False))
    expected = result.get("expected_state")
    if isinstance(expected, dict):
        for field in ("blocker", "resume_step"):
            if expected.get(field) is not None:
                expected[field] = _redacted(expected[field])
    for item in result.get("drift") or []:
        if isinstance(item, dict) and item.get("field") in {"blocker", "resume_step"}:
            if "expected" in item:
                item["expected"] = _redacted(item["expected"])
            if "actual" in item:
                item["actual"] = _redacted(item["actual"])
    return result


def emit(payload: dict[str, Any], *, as_json: bool, error: bool = False) -> None:
    target = sys.stderr if error else sys.stdout
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")), file=target)
        return
    if payload.get("ok"):
        print(f"ok=true mode={payload.get('protocol_mode', 'r2')} rebuildability={payload.get('rebuildability', 'applied')}", file=target)
    else:
        print(f"ERROR [{payload.get('code', 'STATE_RECOVERY_CHECK_FAILED')}]: {payload.get('message', 'audit-state diagnostic failed')}", file=target)


def main() -> int:
    args = parse_args()
    if args.expected_state_digest and args.expect_state_missing:
        emit(
            {
                "ok": False,
                "code": "STATE_CAS_INTENT_CONFLICT",
                "message": "--expected-state-digest and --expect-state-missing cannot be combined",
            },
            as_json=args.json,
            error=True,
        )
        return 1
    workspace = Path(args.workspace_dir).expanduser().resolve()
    if not workspace.is_dir():
        emit({"ok": False, "code": "WORKSPACE_INVALID", "message": "workspace directory does not exist"}, as_json=args.json, error=True)
        return 1
    try:
        if args.apply:
            if not args.expected_journal_digest:
                raise AuditStateError("JOURNAL_CAS_INTENT_REQUIRED", "--apply requires --expected-journal-digest from a prior check")
            payload = rebuild_state_view(
                workspace,
                expected_journal_digest=args.expected_journal_digest,
                expected_state_digest=args.expected_state_digest or None,
                expect_state_missing=args.expect_state_missing,
                lock_timeout_seconds=args.lock_timeout_seconds,
            )
            emit(payload, as_json=args.json)
            return 0
        diagnostic = public_diagnostic(inspect_workspace_recovery(workspace))
        if args.migration_preflight:
            payload = {
                "ok": bool(diagnostic["r1_migration_preflight"].get("available")),
                "protocol_mode": diagnostic["protocol_mode"],
                "r1_migration_preflight": diagnostic["r1_migration_preflight"],
            }
            emit(payload, as_json=args.json, error=not payload["ok"])
            return 0 if payload["ok"] else 1
        emit(diagnostic, as_json=args.json, error=False)
        return 0 if diagnostic.get("ok") else 1
    except AuditStateError as exc:
        payload: dict[str, Any] = {"ok": False, "code": exc.code, "message": exc.message}
        payload.update(exc.fields)
        emit(payload, as_json=args.json, error=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
