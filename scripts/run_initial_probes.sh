#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/run_initial_probes.sh --repo-root <repo-root> [--workspace-dir <dir>] [--output-dir <dir>]

Purpose:
  Run first-pass local scanners with stable paths, non-fatal handling, and a
  structured initial-probes-summary.json classification file.
EOF
}

REPO_ROOT=""
WORKSPACE_DIR=""
OUTPUT_DIR=""
PROBES_RUN=0
PROBES_SKIPPED=0
PROBE_STATUS_LABELS="ran_ok skipped_tool_missing skipped_no_package_sources failed_nonfatal failed_fatal"

find_state_writer() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -f "$script_dir/write_audit_event.py" ]]; then
    printf '%s\n' "$script_dir/write_audit_event.py"
    return
  fi
  if [[ -f "$script_dir/write-audit-event.py" ]]; then
    printf '%s\n' "$script_dir/write-audit-event.py"
    return
  fi
  if [[ -f "$script_dir/../bin/write-audit-event.py" ]]; then
    printf '%s\n' "$script_dir/../bin/write-audit-event.py"
    return
  fi
}

write_state_event() {
  local writer
  [[ -n "${WORKSPACE_DIR:-}" ]] || return 0
  writer="$(find_state_writer)"
  [[ -n "$writer" ]] || return 0
  python3 "$writer" "$@" --workspace-dir "$WORKSPACE_DIR" --target-repo "$REPO_ROOT" || \
    echo "[zhulong] WARNING: state write failed (non-fatal)." >&2
}

launcher_hint() {
  local script_dir="$1"
  if [[ -f "$script_dir/asr_start.sh" ]]; then
    printf '%s\n' "$script_dir/asr_start.sh"
  elif [[ -f "$script_dir/asr-start.sh" ]]; then
    printf '%s\n' "$script_dir/asr-start.sh"
  elif [[ -f "$script_dir/../bin/asr-start.sh" ]]; then
    printf '%s\n' "$script_dir/../bin/asr-start.sh"
  else
    printf '%s\n' "path/to/zhulong/scripts/asr_start.sh"
  fi
}

is_valid_workspace_dir() {
  local candidate="${1:-}"
  [[ -n "$candidate" ]] || return 1
  [[ -f "$candidate/asr-config.json" ]] || return 1
  python3 - <<'PY' "$candidate" >/dev/null
import json
import sys
from pathlib import Path

workspace = Path(sys.argv[1]).expanduser().resolve()
config_path = workspace / "asr-config.json"
try:
    data = json.loads(config_path.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(1)

if not isinstance(data, dict):
    raise SystemExit(1)

workspace_root = str(data.get("workspace_root", "")).strip()
workspace_created_at = str(data.get("workspace_created_at", "")).strip()
confirmed_output_dir = str(data.get("confirmed_output_dir", "")).strip()

if workspace_root != workspace.name:
    raise SystemExit(1)
if not workspace_created_at:
    raise SystemExit(1)
if confirmed_output_dir != f"{workspace.name}/confirmed":
    raise SystemExit(1)
PY
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root)
      REPO_ROOT="${2:-}"
      shift 2
      ;;
    --workspace-dir)
      WORKSPACE_DIR="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$REPO_ROOT" ]]; then
  echo "--repo-root is required." >&2
  usage >&2
  exit 1
fi

REPO_ROOT="${REPO_ROOT/#\~/$HOME}"
REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"

infer_workspace_dir() {
  local repo_root="$1"
  local script_dir inferred latest_name latest_dir

  if [[ -n "${WORKSPACE_DIR:-}" ]]; then
    local explicit="${WORKSPACE_DIR/#\~/$HOME}"
    if is_valid_workspace_dir "$explicit"; then
      printf '%s\n' "$explicit"
      return
    fi
    echo "Explicit workspace is not a valid per-audit workspace: $explicit" >&2
    exit 1
  fi

  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  inferred="$(cd "$script_dir/.." && pwd)"
  if is_valid_workspace_dir "$inferred"; then
    printf '%s\n' "$inferred"
    return
  fi

  if [[ -f "$repo_root/.asr-latest-workspace" ]]; then
    latest_name="$(tr -d '\n' < "$repo_root/.asr-latest-workspace")"
    if [[ -n "$latest_name" ]] && is_valid_workspace_dir "$repo_root/$latest_name"; then
      printf '%s\n' "$repo_root/$latest_name"
      return
    fi
  fi

  latest_dir="$(find "$repo_root" -maxdepth 1 -type d -name 'security-research-*' -exec test -f '{}/asr-config.json' ';' -print 2>/dev/null | sort | tail -n 1 || true)"
  if [[ -n "$latest_dir" ]]; then
    if is_valid_workspace_dir "$latest_dir"; then
      printf '%s\n' "$latest_dir"
      return
    fi
  fi

  echo "No valid per-audit workspace was found under $repo_root." >&2
  echo "Run: bash $(launcher_hint "$script_dir") --repo-root $repo_root" >&2
  exit 1
}

if [[ -z "$OUTPUT_DIR" ]]; then
  WORKSPACE_DIR="$(infer_workspace_dir "$REPO_ROOT")"
  OUTPUT_DIR="$WORKSPACE_DIR/evidence/initial-probes"
elif [[ -n "$WORKSPACE_DIR" ]]; then
  WORKSPACE_DIR="${WORKSPACE_DIR/#\~/$HOME}"
  WORKSPACE_DIR="$(cd "$WORKSPACE_DIR" && pwd)"
fi
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
RECORDS_FILE="$OUTPUT_DIR/probes.jsonl"
SUMMARY_JSON="$OUTPUT_DIR/initial-probes-summary.json"
: > "$SUMMARY_FILE"
: > "$RECORDS_FILE"

relative_path() {
  local value="${1:-}"
  [[ -n "$value" ]] || return 0
  python3 - <<'PY' "$value" "${WORKSPACE_DIR:-}" "$REPO_ROOT"
import sys
from pathlib import Path

path = Path(sys.argv[1]).expanduser().resolve()
workspace = Path(sys.argv[2]).expanduser().resolve() if sys.argv[2] else None
repo = Path(sys.argv[3]).expanduser().resolve()

for base, prefix in ((workspace, ""), (repo, "")):
    if base is None:
        continue
    try:
        rel = path.relative_to(base).as_posix()
    except ValueError:
        continue
    print(rel or ".")
    raise SystemExit(0)
print(path.name)
PY
}

summary_path_value() {
  local value="${1:-}"
  [[ -n "$value" ]] || return 0
  python3 - <<'PY' "$value" "${WORKSPACE_DIR:-}" "$REPO_ROOT"
import sys
from pathlib import Path

path = Path(sys.argv[1]).expanduser().resolve()
workspace = Path(sys.argv[2]).expanduser().resolve() if sys.argv[2] else None
repo = Path(sys.argv[3]).expanduser().resolve()

if path == repo:
    print(".")
    raise SystemExit(0)
if workspace is not None and path == workspace:
    print(workspace.name)
    raise SystemExit(0)
for base in (workspace, repo):
    if base is None:
        continue
    try:
        print(path.relative_to(base).as_posix())
        raise SystemExit(0)
    except ValueError:
        pass
print(path.name)
PY
}

append_probe_record() {
  local name="$1"
  local status="$2"
  local command_display="$3"
  local exit_code="$4"
  local log_path="$5"
  local reason="$6"
  local next_action="$7"
  local metadata_path="${8:-}"
  local log_value=""
  command_display="${command_display//$REPO_ROOT/<repo-root>}"
  if [[ -n "${WORKSPACE_DIR:-}" ]]; then
    command_display="${command_display//$WORKSPACE_DIR/<audit-workspace>}"
  fi
  command_display="${command_display//$OUTPUT_DIR/<initial-probes-output>}"
  [[ -n "$log_path" ]] && log_value="$(relative_path "$log_path")"
  python3 - <<'PY' "$RECORDS_FILE" "$name" "$status" "$command_display" "$exit_code" "$log_value" "$reason" "$next_action" "$metadata_path"
import json
import sys
from pathlib import Path

records_path = Path(sys.argv[1])
exit_code = None if sys.argv[5] == "" else int(sys.argv[5])
record = {
    "name": sys.argv[2],
    "status": sys.argv[3],
    "command": sys.argv[4],
    "exit_code": exit_code,
    "log_path": sys.argv[6],
    "reason": sys.argv[7],
    "next_action": sys.argv[8],
}
metadata_path = Path(sys.argv[9]) if len(sys.argv) > 9 and sys.argv[9] else None
if metadata_path and metadata_path.exists():
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if isinstance(metadata, dict):
        record["summary"] = metadata
with records_path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
PY
}

write_summary_json() {
  local repo_value workspace_value output_value
  repo_value="$(summary_path_value "$REPO_ROOT")"
  workspace_value="$(summary_path_value "${WORKSPACE_DIR:-}")"
  output_value="$(summary_path_value "$OUTPUT_DIR")"
  python3 - <<'PY' "$RECORDS_FILE" "$SUMMARY_JSON" "$repo_value" "$workspace_value" "$output_value"
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

records_path = Path(sys.argv[1])
summary_path = Path(sys.argv[2])
probes = []
if records_path.exists():
    for line in records_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            probes.append(json.loads(line))

data = {
    "schema_version": 1,
    "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    "repo_root": sys.argv[3],
    "workspace_dir": sys.argv[4],
    "output_dir": sys.argv[5],
    "stable_status_labels": [
        "ran_ok",
        "skipped_tool_missing",
        "skipped_no_package_sources",
        "failed_nonfatal",
        "failed_fatal",
    ],
    "probes": probes,
}
summary_path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

write_state_event \
  --event initial_probe_started \
  --stage initial_probing \
  --status running \
  --event-status ok \
  --message "Initial probes started." \
  --detail "output_dir=$OUTPUT_DIR"

run_probe() {
  local name="$1"
  shift
  local logfile="$OUTPUT_DIR/${name}.log"
  local statusfile="$OUTPUT_DIR/${name}.status"
  local command_display="$*"
  local code
  local status
  local reason
  local next_action

  PROBES_RUN=$((PROBES_RUN + 1))
  printf '[%s] running\n' "$name" >>"$SUMMARY_FILE"
  if "$@" >"$logfile" 2>&1; then
    printf 'ran_ok\n' >"$statusfile"
    printf '[%s] ran_ok\n' "$name" >>"$SUMMARY_FILE"
    append_probe_record "$name" "ran_ok" "$command_display" "0" "$logfile" "Probe completed with exit code 0." "Review the log only if this probe is relevant to a candidate."
    return 0
  else
    code=$?
  fi

  status="failed_nonfatal"
  reason="Probe exited non-zero; preserve the log for manual review. Scanner findings are candidates only, not confirmed vulnerabilities."
  next_action="Read the log, record useful leads in candidate-findings.md or unverified-leads.md, and continue Docker-only verification for any candidate."
  if [[ "$code" -eq 127 ]]; then
    status="failed_fatal"
    reason="Probe command could not be executed after the tool check passed; this indicates broken script state or an invalid runtime assumption."
    next_action="Fix the probe command or runtime assumption before relying on initial probe coverage."
  fi
  {
    printf '%s\n' "$status"
    printf 'exit_code=%s\n' "$code"
  } >"$statusfile"
  printf '[%s] %s exit=%s\n' "$name" "$status" "$code" >>"$SUMMARY_FILE"
  append_probe_record "$name" "$status" "$command_display" "$code" "$logfile" "$reason" "$next_action"
  return 0
}

run_osv_probe() {
  local name="osv-scanner"
  local logfile="$OUTPUT_DIR/${name}.log"
  local statusfile="$OUTPUT_DIR/${name}.status"
  local code
  local command_display="osv-scanner scan source -r <repo-root>"

  PROBES_RUN=$((PROBES_RUN + 1))
  printf '[%s] running\n' "$name" >>"$SUMMARY_FILE"
  if osv-scanner scan source -r "$REPO_ROOT" >"$logfile" 2>&1; then
    {
      printf 'ran_ok\n'
      printf 'exit_code=0\n'
    } >"$statusfile"
    printf '[%s] ran_ok\n' "$name" >>"$SUMMARY_FILE"
    append_probe_record "$name" "ran_ok" "$command_display" "0" "$logfile" "OSV Scanner completed with exit code 0." "Review dependency results as candidate evidence only; do not report as confirmed without Docker verification."
    return 0
  else
    code=$?
  fi

  if grep -qi 'No package sources found' "$logfile"; then
    {
      printf 'skipped_no_package_sources\n'
      printf 'exit_code=%s\n' "$code"
      printf 'reason=osv-scanner found no supported package lockfile, manifest, or SBOM source in this repository snapshot.\n'
      printf 'note=This is not a scanner crash and not a vulnerability finding. Continue source review and Docker verification.\n'
    } >"$statusfile"
    printf '[%s] skipped: no package sources found\n' "$name" >>"$SUMMARY_FILE"
    append_probe_record "$name" "skipped_no_package_sources" "$command_display" "$code" "$logfile" "osv-scanner found no supported package lockfile, manifest, or SBOM source in this repository snapshot. This is not a scanner crash and not a vulnerability." "Continue source review and Docker-only verification; do not treat this as an audit failure."
    return 0
  fi

  {
    printf 'failed_nonfatal\n'
    printf 'exit_code=%s\n' "$code"
  } >"$statusfile"
  printf '[%s] failed_nonfatal exit=%s\n' "$name" "$code" >>"$SUMMARY_FILE"
  append_probe_record "$name" "failed_nonfatal" "$command_display" "$code" "$logfile" "osv-scanner exited non-zero for a reason other than no package sources. Preserve the log for manual review." "Review the log and continue; only Docker reproduction can confirm a vulnerability."
  return 0
}

write_gitleaks_metadata() {
  local report_json="$1"
  local metadata_json="$2"
  local logfile="$3"
  local report_rel
  local log_rel
  report_rel="$(relative_path "$report_json")"
  log_rel="$(relative_path "$logfile")"
  python3 - <<'PY' "$report_json" "$metadata_json" "$log_rel" "$report_rel" "$REPO_ROOT"
import hashlib
import json
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
metadata_path = Path(sys.argv[2])
log_rel = sys.argv[3]
report_rel = sys.argv[4]
repo_root = Path(sys.argv[5]).expanduser().resolve()

def as_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("findings", "Findings", "leaks", "Leaks", "results", "Results"):
            nested = value.get(key)
            if isinstance(nested, list):
                return nested
    return []

def short_text(value, limit=160):
    if value is None:
        return ""
    text = str(value).replace("\n", " ").replace("\r", " ").strip()
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text

def safe_path(value):
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    path = Path(text).expanduser()
    try:
        resolved = path.resolve()
        return resolved.relative_to(repo_root).as_posix()
    except Exception:
        return text.replace("\\", "/")

def first_present(item, keys):
    for key in keys:
        if key in item and item.get(key) not in (None, ""):
            return item.get(key)
    return None

try:
    report_data = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else []
except Exception:
    report_data = []

findings = [item for item in as_list(report_data) if isinstance(item, dict)]
samples = []
for item in findings[:5]:
    sample = {
        "rule_id": short_text(first_present(item, ("RuleID", "RuleId", "rule_id", "ruleID", "rule"))),
        "description": short_text(first_present(item, ("Description", "description"))),
        "file": safe_path(first_present(item, ("File", "file", "Path", "path"))),
        "line": first_present(item, ("StartLine", "Line", "line", "LineNumber", "line_number")),
        "commit": short_text(first_present(item, ("Commit", "commit")), 40),
    }
    secret_material = first_present(item, ("Secret", "secret", "Match", "match"))
    if secret_material not in (None, ""):
        secret_text = str(secret_material)
        sample["secret_redacted"] = f"<redacted length={len(secret_text)}>"
        sample["secret_sha256_12"] = hashlib.sha256(secret_text.encode("utf-8", errors="ignore")).hexdigest()[:12]
    samples.append({key: value for key, value in sample.items() if value not in (None, "")})

metadata = {
    "finding_count": len(findings),
    "sample_limit": 5,
    "sample_findings": samples,
    "raw_log_path": log_rel,
    "json_report_path": report_rel if report_path.exists() else "",
    "redaction": "Full Secret and Match values are omitted; summaries include only metadata and optional short hashes.",
    "candidate_only": True,
}
metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

run_gitleaks_probe() {
  local name="gitleaks"
  local logfile="$OUTPUT_DIR/${name}.log"
  local statusfile="$OUTPUT_DIR/${name}.status"
  local report_json="$OUTPUT_DIR/${name}.json"
  local metadata_json="$OUTPUT_DIR/${name}-summary.json"
  local command_display="gitleaks detect -s <repo-root> --report-format json --report-path <initial-probes-output>/gitleaks.json"
  local code
  local status
  local reason
  local next_action

  PROBES_RUN=$((PROBES_RUN + 1))
  printf '[%s] running\n' "$name" >>"$SUMMARY_FILE"
  if gitleaks detect -s "$REPO_ROOT" --report-format json --report-path "$report_json" >"$logfile" 2>&1; then
    code=0
    status="ran_ok"
    reason="gitleaks completed with exit code 0."
    next_action="Review the sanitized gitleaks summary first; scanner findings remain candidates only until Docker verification confirms impact."
  else
    code=$?
    if [[ "$code" -eq 127 ]]; then
      status="failed_fatal"
      reason="gitleaks command could not be executed after the tool check passed; this indicates broken script state or an invalid runtime assumption."
      next_action="Fix the probe command or runtime assumption before relying on initial probe coverage."
    else
      status="failed_nonfatal"
      reason="gitleaks exited non-zero, commonly because leaks were found. Findings are candidates only and full secret values are not copied into the structured summary."
      next_action="Read the sanitized gitleaks summary before opening raw logs; triage examples/tests/false positives and verify any security impact separately."
    fi
  fi

  write_gitleaks_metadata "$report_json" "$metadata_json" "$logfile"
  {
    printf '%s\n' "$status"
    printf 'exit_code=%s\n' "$code"
  } >"$statusfile"
  printf '[%s] %s exit=%s\n' "$name" "$status" "$code" >>"$SUMMARY_FILE"
  append_probe_record "$name" "$status" "$command_display" "$code" "$logfile" "$reason" "$next_action" "$metadata_json"
  return 0
}

note_skip() {
  local name="$1"
  local reason="$2"
  local status="${3:-skipped_tool_missing}"
  local next_action="${4:-Install or enable the optional tool only if this probe is important for the target stack; continue with source review and Docker verification.}"
  PROBES_SKIPPED=$((PROBES_SKIPPED + 1))
  printf '%s\nreason=%s\n' "$status" "$reason" >"$OUTPUT_DIR/${name}.status"
  printf '[%s] %s: %s\n' "$name" "$status" "$reason" >>"$SUMMARY_FILE"
  append_probe_record "$name" "$status" "(not executed)" "" "" "$reason" "$next_action"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

if has_cmd semgrep; then
  run_probe semgrep semgrep scan --config auto "$REPO_ROOT"
else
  note_skip semgrep "missing semgrep"
fi

if has_cmd gitleaks; then
  run_gitleaks_probe
else
  note_skip gitleaks "missing gitleaks"
fi

if has_cmd npm; then
  if [[ -f "$REPO_ROOT/package-lock.json" || -f "$REPO_ROOT/npm-shrinkwrap.json" ]]; then
    run_probe npm-audit bash -lc "cd \"$REPO_ROOT\" && npm audit"
  elif [[ -f "$REPO_ROOT/package.json" ]]; then
    note_skip npm-audit "node repo without package-lock.json or npm-shrinkwrap.json" "skipped_no_package_sources" "Use npm audit only after a lockfile exists; continue source review and Docker verification."
  else
    note_skip npm-audit "not a node repo" "skipped_no_package_sources" "No Node package source was detected for npm audit; continue with relevant probes."
  fi
else
  note_skip npm-audit "missing npm"
fi

if [[ -f "$REPO_ROOT/pom.xml" ]]; then
  if has_cmd mvn; then
    run_probe maven-dependency-tree bash -lc "cd \"$REPO_ROOT\" && mvn -q -DskipTests dependency:tree"
  else
    note_skip maven-dependency-tree "java repo with pom.xml but missing mvn"
  fi
elif [[ -f "$REPO_ROOT/build.gradle" || -f "$REPO_ROOT/build.gradle.kts" ]]; then
  if [[ -x "$REPO_ROOT/gradlew" ]]; then
    run_probe gradle-dependencies bash -lc "cd \"$REPO_ROOT\" && ./gradlew dependencies --no-daemon"
  elif has_cmd gradle; then
    run_probe gradle-dependencies bash -lc "cd \"$REPO_ROOT\" && gradle dependencies --no-daemon"
  else
    note_skip gradle-dependencies "java repo with Gradle files but missing gradle or executable ./gradlew"
  fi
else
  note_skip java-dependency-tree "not a maven or gradle repo" "skipped_no_package_sources" "No Maven or Gradle source was detected; continue with probes relevant to the detected stack."
fi

if has_cmd dependency-check; then
  if [[ -f "$REPO_ROOT/pom.xml" || -f "$REPO_ROOT/build.gradle" || -f "$REPO_ROOT/build.gradle.kts" ]]; then
    run_probe dependency-check dependency-check --scan "$REPO_ROOT" --out "$OUTPUT_DIR/dependency-check"
  else
    note_skip dependency-check "not a java dependency-check target"
  fi
elif has_cmd dependency-check.sh; then
  if [[ -f "$REPO_ROOT/pom.xml" || -f "$REPO_ROOT/build.gradle" || -f "$REPO_ROOT/build.gradle.kts" ]]; then
    run_probe dependency-check dependency-check.sh --scan "$REPO_ROOT" --out "$OUTPUT_DIR/dependency-check"
  else
    note_skip dependency-check "not a java dependency-check target"
  fi
else
  note_skip dependency-check "missing dependency-check"
fi

if [[ -f "$REPO_ROOT/go.mod" ]]; then
  if has_cmd go; then
    run_probe go-list-modules bash -lc "cd \"$REPO_ROOT\" && go list -m all"
  else
    note_skip go-list-modules "go repo but missing go"
  fi

  if has_cmd govulncheck; then
    run_probe govulncheck bash -lc "cd \"$REPO_ROOT\" && govulncheck ./..."
  else
    note_skip govulncheck "missing govulncheck"
  fi

  if has_cmd gosec; then
    run_probe gosec bash -lc "cd \"$REPO_ROOT\" && gosec ./..."
  else
    note_skip gosec "missing gosec"
  fi

  if has_cmd golangci-lint; then
    run_probe golangci-lint bash -lc "cd \"$REPO_ROOT\" && golangci-lint run"
  else
    note_skip golangci-lint "missing golangci-lint"
  fi
else
  note_skip go-list-modules "not a go module" "skipped_no_package_sources" "No go.mod source was detected; continue with probes relevant to the detected stack."
  note_skip govulncheck "not a go module" "skipped_no_package_sources" "No go.mod source was detected; continue with probes relevant to the detected stack."
  note_skip gosec "not a go module" "skipped_no_package_sources" "No go.mod source was detected; continue with probes relevant to the detected stack."
  note_skip golangci-lint "not a go module" "skipped_no_package_sources" "No go.mod source was detected; continue with probes relevant to the detected stack."
fi

if has_cmd osv-scanner; then
  run_osv_probe
else
  note_skip osv-scanner "missing osv-scanner"
fi

if has_cmd trivy; then
  run_probe trivy trivy fs "$REPO_ROOT"
else
  note_skip trivy "missing trivy"
fi

if has_cmd syft; then
  run_probe syft syft "dir:$REPO_ROOT"
else
  note_skip syft "missing syft"
fi

if has_cmd grype; then
  run_probe grype grype "dir:$REPO_ROOT"
else
  note_skip grype "missing grype"
fi

write_summary_json

if [[ "$PROBES_RUN" -gt 0 ]]; then
  write_state_event \
    --event initial_probe_completed \
    --stage initial_probing \
    --status running \
    --event-status ok \
    --message "Initial probes completed." \
    --detail "output_dir=$OUTPUT_DIR" \
    --detail "summary_json=$SUMMARY_JSON" \
    --detail "probes_run=$PROBES_RUN" \
    --detail "probes_skipped=$PROBES_SKIPPED"
else
  write_state_event \
    --event initial_probe_skipped \
    --stage initial_probing \
    --status running \
    --event-status skipped \
    --message "All initial probes were skipped." \
    --detail "output_dir=$OUTPUT_DIR" \
    --detail "summary_json=$SUMMARY_JSON" \
    --detail "probes_skipped=$PROBES_SKIPPED"
fi

cat <<EOF
Initial probes completed.
Repository root:
  $REPO_ROOT
Evidence directory:
  $OUTPUT_DIR
Structured summary:
  $SUMMARY_JSON
Summary:
$(cat "$SUMMARY_FILE")
EOF
