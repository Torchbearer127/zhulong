#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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


def render(workspace: Path, repo_root: Path, output: Path) -> str:
    status = read_json(workspace / "stage-status.json")
    events = read_jsonl_tail(workspace / "audit-events.jsonl")
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
        "",
        "## Recommended First Reads",
        "",
        f"- {file_status(workspace / 'stage-status.json', workspace)}",
        f"- {file_status(workspace / 'attack-surface.md', workspace)}",
        f"- {file_status(initial_probes, workspace)}",
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
