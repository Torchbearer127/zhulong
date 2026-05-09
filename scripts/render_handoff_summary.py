#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audit_disposition import (
    LEDGER_FILENAME,
    render_unresolved_disposition_lines,
    validate_disposition_ledger,
)
from blocked_verification import detect_blocked_verification


MAX_ROWS = 5


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render a lightweight Zhulong handoff-summary.md from workspace state files."
    )
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--repo-root", default="")
    parser.add_argument("--output", default="")
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def read_jsonl_tail(path: Path, limit: int = 5) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            events.append(data)
    return events[-limit:]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            events.append(data)
    return events


def rel(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.name


def rel_workspace(path: Path, workspace: Path) -> str:
    return rel(path, workspace)


def rel_repo(path: Path, repo_root: Path) -> str:
    return rel(path, repo_root)


def file_status(path: Path, workspace: Path) -> str:
    if path.exists():
        return f"`{rel_workspace(path, workspace)}`"
    return "_missing_"


def read_markdown_text(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="ignore")
    if "\\n" in text and text.count("\n") <= 1:
        text = text.replace("\\n", "\n")
    return text


def markdown_table_rows(path: Path) -> list[list[str]]:
    if not path.exists():
        return []
    rows: list[list[str]] = []
    for raw in read_markdown_text(path).splitlines():
        line = raw.strip()
        if not line.startswith("|") or not line.endswith("|"):
            continue
        if set(line.replace("|", "").replace(" ", "")) <= {"-"}:
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if not cells:
            continue
        if all(cell.startswith("---") or not cell for cell in cells):
            continue
        rows.append(cells)
    if rows:
        return rows[1:]
    return []


def summarize_table_file(path: Path, workspace: Path, empty_message: str) -> list[str]:
    rows = markdown_table_rows(path)
    lines = [f"- Source: {file_status(path, workspace)}"]
    if not rows:
        lines.append(f"- Rows: 0 ({empty_message})")
        return lines
    lines.append(f"- Rows: {len(rows)}")
    for row in rows[:MAX_ROWS]:
        cells = [cell or "-" for cell in row[:4]]
        lines.append(f"- {' | '.join(cells)}")
    if len(rows) > MAX_ROWS:
        lines.append(f"- ... {len(rows) - MAX_ROWS} more row(s) omitted; open the source file if needed.")
    return lines


def heading_names(path: Path, max_items: int = 8) -> list[str]:
    if not path.exists():
        return []
    headings: list[str] = []
    for raw in read_markdown_text(path).splitlines():
        line = raw.strip()
        if line.startswith("## "):
            headings.append(line[3:].strip())
        if len(headings) >= max_items:
            break
    return headings


def initial_probe_lines(path: Path, workspace: Path) -> list[str]:
    lines = [f"- Source: {file_status(path, workspace)}"]
    data = read_json(path)
    probes = data.get("probes")
    if not isinstance(probes, list) or not probes:
        lines.append("- Status: no structured initial probe summary yet.")
        return lines
    counts = Counter(str(probe.get("status", "unknown")) for probe in probes if isinstance(probe, dict))
    counts_text = ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
    lines.append(f"- Status counts: {counts_text}")
    priority_names = {"osv-scanner", "semgrep", "gitleaks", "trivy", "syft", "grype"}
    priority = [
        probe for probe in probes
        if isinstance(probe, dict) and str(probe.get("name", "")).strip() in priority_names
    ]
    if priority:
        lines.append("- Priority probe statuses:")
        for probe in priority:
            name = str(probe.get("name", "")).strip() or "unknown"
            status = str(probe.get("status", "")).strip() or "unknown"
            lines.append(f"  - {name}: {status}")
    for probe in probes[:MAX_ROWS]:
        if not isinstance(probe, dict):
            continue
        name = str(probe.get("name", "")).strip() or "unknown"
        status = str(probe.get("status", "")).strip() or "unknown"
        reason = str(probe.get("reason", "")).strip()
        if len(reason) > 140:
            reason = reason[:137] + "..."
        lines.append(f"- {name}: {status} - {reason}")
    if len(probes) > MAX_ROWS:
        lines.append(f"- ... {len(probes) - MAX_ROWS} more probe(s) omitted; inspect the summary JSON first, not raw logs.")
    return lines


def event_details(event: dict[str, Any] | None) -> dict[str, Any]:
    if not event:
        return {}
    raw = event.get("details")
    return raw if isinstance(raw, dict) else {}


def latest_finalization(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    for event in reversed(events):
        if event.get("event") in {"finalization_succeeded", "finalization_failed"}:
            return event
    return None


def latest_success(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    for event in reversed(events):
        if event.get("event") == "finalization_succeeded":
            return event
    return None


def completion_claimed(status: dict[str, Any]) -> bool:
    result = str(status.get("result") or status.get("completion_result") or "").strip()
    return (
        str(status.get("stage") or "").strip() == "completed"
        or str(status.get("status") or "").strip() == "completed"
        or result in {"completed_with_confirmed_bundles", "completed_no_confirmed_findings"}
        or bool(status.get("completed_at"))
    )


def finalization_integrity_lines(workspace: Path, status: dict[str, Any]) -> list[str]:
    events = read_jsonl(workspace / "audit-events.jsonl")
    latest = latest_finalization(events)
    success = latest_success(events)
    docker_status = read_json(workspace / "docker/docker-cleanliness-status.json")
    blocked_summary = detect_blocked_verification(workspace)
    claimed = completion_claimed(status)
    issues: list[str] = []

    if claimed and success is None:
        issues.append("stage-status claims completed but audit-events.jsonl has no finalization_succeeded event")
    if claimed and latest and latest.get("event") == "finalization_failed":
        issues.append("latest finalization event is finalization_failed")
    if claimed and docker_status and docker_status.get("clean") is False:
        issues.append("docker-cleanliness-status.json has clean=false")
    if claimed and docker_status and docker_status.get("strict") is not True:
        issues.append("Docker strict cleanliness status is not strict=true")
    if success:
        details = event_details(success)
        if details.get("docker_clean") is True and (
            not docker_status or docker_status.get("clean") is not True or docker_status.get("strict") is not True
        ):
            issues.append("finalization_succeeded claims docker_clean=true but Docker strict cleanliness does not agree")
    result = str(event_details(success).get("result") or status.get("result") or "").strip()
    if result == "completed_no_confirmed_findings" and blocked_summary.get("blocked"):
        issues.append("blocked Docker/runtime verification exists; no-confirmed completion is not terminal")
    if claimed:
        disposition_validation = validate_disposition_ledger(workspace, result=result, language="auto")
        if not disposition_validation.get("ok"):
            errors = disposition_validation.get("errors", [])
            first = str(errors[0]) if errors else "unknown ledger validation error"
            issues.append(f"{LEDGER_FILENAME} validation failed: {first}")

    if issues:
        return [
            "- Finalization integrity: `blocked`",
            "- Completion gate passed: `false`",
            "- Reason: " + "; ".join(issues),
            "- Next action: rerun `assert-finalized-workspace.py`, resolve the blocker, then rerun `finalize-audit-workspace.py`.",
        ]
    if claimed and success:
        result = str(event_details(success).get("result") or status.get("result") or "").strip() or "completed"
        return [
            "- Finalization integrity: `ok`",
            "- Completion gate passed: `true`",
            f"- Finalization result: `{result}`",
        ]
    return [
        "- Finalization integrity: `not_finalized`",
        "- Completion gate passed: `false`",
        "- Next action: keep auditing or run `finalize-audit-workspace.py` only when bundle and Docker strict-clean gates are ready.",
    ]


def confirmed_bundle_lines(workspace: Path) -> list[str]:
    confirmed_dir = workspace / "confirmed"
    lines = [f"- Directory: {file_status(confirmed_dir, workspace)}"]
    if not confirmed_dir.exists():
        lines.append("- Bundles: 0")
        lines.append("- No confirmed vulnerabilities.")
        return lines
    bundles = sorted(path for path in confirmed_dir.iterdir() if path.is_dir() and not path.name.startswith("."))
    if not bundles:
        lines.append("- Bundles: 0")
        lines.append("- No confirmed vulnerabilities.")
        return lines
    lines.append(f"- Bundle-like directories: {len(bundles)}")
    lines.append("- Treat a directory as a confirmed deliverable only after `validate-all-report-bundles.py` passes.")
    for bundle in bundles[:MAX_ROWS]:
        evidence = bundle / "verification-evidence.json"
        status = read_json(evidence).get("verification_status", "unknown") if evidence.exists() else "missing verification-evidence.json"
        missing = []
        if not any(path.is_file() for path in bundle.glob("*.docx")):
            missing.append("docx")
        if not any(("附件目录说明" in path.name or "attachment" in path.name) for path in bundle.glob("*.md")):
            missing.append("attachment-index")
        if not any(("补充复现说明" in path.name or "reproduction" in path.name) for path in bundle.glob("*.md")):
            missing.append("reproduction-supplement")
        attachments = bundle / "attachments"
        if not attachments.exists() or not attachments.is_dir() or not any(path.is_file() for path in attachments.rglob("*")):
            missing.append("attachments")
        if not any(path.is_file() and path.name.startswith("run-") for path in bundle.glob("*.sh")):
            missing.append("bundle-root-run-script")
        if missing:
            lines.append(
                f"- `{rel_workspace(bundle, workspace)}` ({status}; partial_confirmed_bundle missing: {', '.join(missing)})"
            )
        else:
            lines.append(f"- `{rel_workspace(bundle, workspace)}` ({status}; bundle artifacts present, validation still required)")
    if len(bundles) > MAX_ROWS:
        lines.append(f"- ... {len(bundles) - MAX_ROWS} more bundle(s) omitted.")
    return lines


def blocked_verification_lines(workspace: Path) -> list[str]:
    summary = detect_blocked_verification(workspace)
    if not summary.get("blocked"):
        return [
            "- Blocked verification: `none_detected`",
        ]
    lines = [
        "- Blocked verification: `blocked_verification`",
        f"- Resume step: {summary.get('resume_step') or 'Resolve Docker/runtime blocker and rerun Docker verification.'}",
    ]
    findings = summary.get("findings") or []
    if isinstance(findings, list):
        for item in findings[:MAX_ROWS]:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- `{item.get('source')}:{item.get('line')}` {item.get('classification')}: {item.get('excerpt')}"
            )
        if len(findings) > MAX_ROWS:
            lines.append(f"- ... {len(findings) - MAX_ROWS} more blocked-verification signal(s) omitted.")
    return lines


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def runtime_hygiene_lines(workspace: Path) -> list[str]:
    path = workspace / "runtime/runtime-hygiene-status.json"
    lines = [f"- Source: {file_status(path, workspace)}"]
    data = read_json(path)
    if not data:
        lines.append("- Runtime hygiene: `not_recorded`")
        lines.append("- Resume step: run `bin/check_omc_runtime.sh --json` before using `/team` or `/ultrawork`.")
        return lines

    mode = str(data.get("recommended_mode") or "unknown")
    clean = data.get("clean")
    teams_enabled = data.get("teams_enabled")
    heartbeat_seen = data.get("heartbeat_seen")
    lines.append(f"- Recommended mode: `{mode}`")
    lines.append(f"- Clean: `{str(bool(clean)).lower()}`")
    lines.append(f"- Teams enabled: `{str(bool(teams_enabled)).lower()}`")
    lines.append(f"- Heartbeat/live swarm seen: `{str(bool(heartbeat_seen)).lower()}`")

    suspect_pids = _string_list(data.get("suspect_teammate_pids"))
    ignored_pids = _string_list(data.get("ignored_current_session_teammate_pids"))
    stale_sockets = _string_list(data.get("stale_swarm_sockets"))
    live_sockets = _string_list(data.get("live_swarm_sockets"))
    unresolved = data.get("unresolved_review_only")
    suspect_processes = data.get("suspect_teammate_processes")

    lines.append("- Suspect teammate PIDs: " + (", ".join(f"`{pid}`" for pid in suspect_pids) if suspect_pids else "`none`"))
    if suspect_pids:
        lines.append("- Suspect teammate PID handling: `review-only`; Zhulong does not signal teammate PIDs. Inspect the owning terminal/session before using `/team` or `/ultrawork`.")
    if isinstance(suspect_processes, list) and suspect_processes:
        lines.append("- Suspect teammate process metadata:")
        for item in suspect_processes[:MAX_ROWS]:
            if not isinstance(item, dict):
                continue
            pid = str(item.get("pid") or "")
            ppid = str(item.get("ppid") or "")
            pgid = str(item.get("pgid") or "")
            sess = str(item.get("sess") or "")
            tty = str(item.get("tty") or "")
            stat = str(item.get("stat") or "")
            command = str(item.get("command") or "")
            uncertain = str(bool(item.get("active_session_uncertain"))).lower()
            lines.append(
                f"  - pid=`{pid}` ppid=`{ppid}` pgid=`{pgid}` sess=`{sess}` tty=`{tty}` stat=`{stat}` "
                f"active_session_uncertain=`{uncertain}` command=`{command}`"
            )
    lines.append("- Ignored current-session teammate PIDs: " + (", ".join(f"`{pid}`" for pid in ignored_pids) if ignored_pids else "`none`"))
    lines.append("- Stale swarm sockets: " + (", ".join(f"`{sock}`" for sock in stale_sockets) if stale_sockets else "`none`"))
    lines.append("- Live swarm sockets: " + (", ".join(f"`{sock}`" for sock in live_sockets) if live_sockets else "`none`"))

    if isinstance(unresolved, list) and unresolved:
        lines.append("- Unresolved review-only items:")
        for item in unresolved[:MAX_ROWS]:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind") or "unknown")
            value = str(item.get("value") or "")
            reason = str(item.get("reason") or "")
            resume = str(item.get("resume_step") or "")
            lines.append(f"  - `{kind}` `{value}`: {reason}; resume: {resume}")
        if len(unresolved) > MAX_ROWS:
            lines.append(f"- ... {len(unresolved) - MAX_ROWS} more runtime hygiene item(s) omitted.")
    else:
        lines.append("- Unresolved review-only items: `none`")

    resume_step = str(data.get("resume_step") or "")
    lines.append(f"- Exact resume step: {resume_step or '_none_'}")
    return lines


def render(workspace: Path, repo_root: Path, output: Path) -> str:
    status = read_json(workspace / "stage-status.json")
    events_path = workspace / "audit-events.jsonl"
    events = read_jsonl_tail(events_path)
    attack_surface = workspace / "attack-surface.md"
    initial_probes = workspace / "evidence/initial-probes/initial-probes-summary.json"
    candidate = workspace / "candidate-findings.md"
    false_positive = workspace / "false-positives.md"
    unverified = workspace / "unverified-leads.md"

    target_repo = status.get("target_repo") or repo_root.name
    if isinstance(target_repo, str) and target_repo:
        target_label = rel_repo(Path(target_repo).expanduser(), repo_root) if Path(target_repo).expanduser().is_absolute() else target_repo
    else:
        target_label = repo_root.name

    stage = str(status.get("stage") or "unknown")
    state = str(status.get("status") or "unknown")
    blocker = str(status.get("blocker") or "")
    resume_step = str(status.get("resume_step") or "")
    last_message = str(status.get("last_message") or "")

    lines: list[str] = [
        "<!-- schema_version: 1 -->",
        "# Handoff Summary",
        "",
        "This is a lightweight continuation packet. It is not a vulnerability report, not raw scanner output, not a source for DOCX generation, and not a substitute for confirmed bundles.",
        "",
        "## Target and Workspace",
        "",
        f"- Target repository: `{target_label}`",
        f"- Workspace: `{rel_repo(workspace, repo_root)}`",
        f"- Generated at: `{utc_now()}`",
        f"- Renderer output: `{rel_workspace(output, workspace)}`",
        "",
        "## Current Stage / Status",
        "",
        f"- Stage: `{stage}`",
        f"- Status: `{state}`",
        f"- Last message: {last_message or '_none_'}",
        f"- Blocker: {blocker or '_none_'}",
        f"- Resume step: {resume_step or '_none_'}",
        *finalization_integrity_lines(workspace, status),
        "",
        "## Recommended First Reads",
        "",
        f"- {file_status(workspace / 'stage-status.json', workspace)}",
        f"- {file_status(workspace / 'attack-surface.md', workspace)}",
        f"- {file_status(initial_probes, workspace)}",
        f"- {file_status(workspace / 'runtime/runtime-hygiene-status.json', workspace)}",
        f"- {file_status(candidate, workspace)}",
        f"- {file_status(false_positive, workspace)}",
        f"- {file_status(unverified, workspace)}",
        "",
        "## Context-Slimming Rules",
        "",
        "- Read lightweight files first: this handoff, stage-status.json, attack-surface.md, initial-probes-summary.json, and triage tables.",
        "- Avoid default-reading full raw logs. Open heavy logs only when a specific candidate, probe, or blocker requires it.",
        "- Keep new notes concise and append pointers instead of pasting scanner output.",
        "",
        "## Attack-Surface Highlights",
        "",
        f"- Source: {file_status(attack_surface, workspace)}",
    ]
    headings = heading_names(attack_surface)
    if headings:
        lines.append("- Sections present: " + ", ".join(headings))
    else:
        lines.append("- Sections present: none yet")

    lines.extend([
        "",
        "## Initial Probe Summary",
        "",
        *initial_probe_lines(initial_probes, workspace),
        "",
        "## Blocked Verification Status",
        "",
        *blocked_verification_lines(workspace),
        "",
        "## OMC Runtime Hygiene",
        "",
        *runtime_hygiene_lines(workspace),
        "",
        "## Audit Disposition Ledger",
        "",
        *render_unresolved_disposition_lines(workspace),
        "",
        "## Candidate Findings",
        "",
        *summarize_table_file(candidate, workspace, "no candidates recorded"),
        "",
        "## False Positives / Non-Security Defects",
        "",
        *summarize_table_file(false_positive, workspace, "no false positives recorded"),
        "",
        "## Unverified Leads",
        "",
        *summarize_table_file(unverified, workspace, "no unverified leads recorded"),
        "",
        "## Confirmed Bundle Pointers",
        "",
        *confirmed_bundle_lines(workspace),
        "",
        "## Recent Audit Events",
        "",
    ])
    if events:
        for event in events:
            event_name = str(event.get("event", "unknown"))
            event_status = str(event.get("status", "unknown"))
            message = str(event.get("message", ""))
            lines.append(f"- {event_name}: {event_status} - {message}")
    else:
        lines.append("- No audit events recorded yet.")

    lines.extend([
        "",
        "## Heavy Logs To Avoid Unless Needed",
        "",
        "- `evidence/initial-probes/*.log`",
        "- `audit-log.md` Docker/OMC diagnostic blocks",
        "- Raw scanner output, dependency trees, SBOM dumps, and large evidence captures",
        "- Open these only for a concrete candidate, blocker, or reproduction question.",
        "",
        "## Next Safe Steps",
        "",
        f"1. If status is blocked or paused, follow the resume step above: {resume_step or '<none recorded>'}",
        "2. Refresh attack-surface.md and triage tables with concise pointers, not raw logs.",
        "3. Run PoCs only through Docker or Docker Compose after the Docker gate is ready.",
        "4. Confirmed output must be generated only after Docker reproduction succeeds and bundle validation passes.",
        "",
        "## Confirmed-Only Routing Guardrails",
        "",
        "- Confirmed vulnerabilities belong only under `confirmed/<one-folder-per-vulnerability>/`.",
        "- Unverified leads, handoff hypotheses, scanner results, and timed-out or blocked verification cases are not confirmed vulnerabilities.",
        "- Do not generate DOCX reports from handoff content, attack-surface hypotheses, initial probe output, or unverified leads.",
        "- Do not copy raw scanner logs into this handoff; keep logs as referenced evidence files.",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    workspace = Path(args.workspace_dir).expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"workspace directory does not exist: {workspace}")
    if not (workspace / "asr-config.json").exists():
        raise SystemExit(f"not a Zhulong audit workspace: {workspace}")
    repo_root = Path(args.repo_root).expanduser().resolve() if args.repo_root else workspace.parent.resolve()
    output = Path(args.output).expanduser().resolve() if args.output else workspace / "handoff-summary.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(workspace, repo_root, output), encoding="utf-8")
    print(f"handoff_summary={rel_workspace(output, workspace)}")


if __name__ == "__main__":
    main()
