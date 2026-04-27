#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/run_initial_probes.sh --repo-root <repo-root> [--workspace-dir <dir>] [--output-dir <dir>]

Purpose:
  Run first-pass local scanners with stable absolute paths and non-fatal handling.
EOF
}

REPO_ROOT=""
WORKSPACE_DIR=""
OUTPUT_DIR=""

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
  echo "Run: bash /Users/torchbearer/Documents/oss-vulnerability-research/plugins/zhulong-plugin/scripts/asr_start.sh --repo-root $repo_root" >&2
  exit 1
}

if [[ -z "$OUTPUT_DIR" ]]; then
  WORKSPACE_DIR="$(infer_workspace_dir "$REPO_ROOT")"
  OUTPUT_DIR="$WORKSPACE_DIR/evidence/initial-probes"
fi
mkdir -p "$OUTPUT_DIR"

SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
: > "$SUMMARY_FILE"

run_probe() {
  local name="$1"
  shift
  local logfile="$OUTPUT_DIR/${name}.log"
  local statusfile="$OUTPUT_DIR/${name}.status"

  printf '[%s] running\n' "$name" >>"$SUMMARY_FILE"
  if "$@" >"$logfile" 2>&1; then
    printf 'ok\n' >"$statusfile"
    printf '[%s] ok\n' "$name" >>"$SUMMARY_FILE"
    return 0
  fi

  local code=$?
  printf 'exit_code=%s\n' "$code" >"$statusfile"
  printf '[%s] non_fatal_exit=%s\n' "$name" "$code" >>"$SUMMARY_FILE"
  return 0
}

run_osv_probe() {
  local name="osv-scanner"
  local logfile="$OUTPUT_DIR/${name}.log"
  local statusfile="$OUTPUT_DIR/${name}.status"
  local code

  printf '[%s] running\n' "$name" >>"$SUMMARY_FILE"
  if osv-scanner scan source -r "$REPO_ROOT" >"$logfile" 2>&1; then
    printf 'ok\n' >"$statusfile"
    printf '[%s] ok\n' "$name" >>"$SUMMARY_FILE"
    return 0
  fi

  code=$?
  if grep -qi 'No package sources found' "$logfile"; then
    {
      printf 'skipped_no_package_sources\n'
      printf 'exit_code=%s\n' "$code"
      printf 'reason=osv-scanner found no supported package lockfile, manifest, or SBOM source in this repository snapshot.\n'
      printf 'note=This is not a scanner crash and not a vulnerability finding. Continue source review and Docker verification.\n'
    } >"$statusfile"
    printf '[%s] skipped: no package sources found\n' "$name" >>"$SUMMARY_FILE"
    return 0
  fi

  printf 'exit_code=%s\n' "$code" >"$statusfile"
  printf '[%s] non_fatal_exit=%s\n' "$name" "$code" >>"$SUMMARY_FILE"
  return 0
}

note_skip() {
  local name="$1"
  local reason="$2"
  printf '%s\n' "$reason" >"$OUTPUT_DIR/${name}.status"
  printf '[%s] skipped: %s\n' "$name" "$reason" >>"$SUMMARY_FILE"
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
  run_probe gitleaks gitleaks detect -s "$REPO_ROOT"
else
  note_skip gitleaks "missing gitleaks"
fi

if has_cmd npm; then
  if [[ -f "$REPO_ROOT/package-lock.json" || -f "$REPO_ROOT/npm-shrinkwrap.json" ]]; then
    run_probe npm-audit bash -lc "cd \"$REPO_ROOT\" && npm audit"
  elif [[ -f "$REPO_ROOT/package.json" ]]; then
    note_skip npm-audit "node repo without package-lock.json or npm-shrinkwrap.json"
  else
    note_skip npm-audit "not a node repo"
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
  note_skip java-dependency-tree "not a maven or gradle repo"
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
  note_skip go-list-modules "not a go module"
  note_skip govulncheck "not a go module"
  note_skip gosec "not a go module"
  note_skip golangci-lint "not a go module"
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

cat <<EOF
Initial probes completed.
Repository root:
  $REPO_ROOT
Evidence directory:
  $OUTPUT_DIR
Summary:
$(cat "$SUMMARY_FILE")
EOF
