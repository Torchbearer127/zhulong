#!/usr/bin/env bash

set -euo pipefail

SKILL_DIR="${SKILL_DIR:-$HOME/.claude/skills/zhulong}"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/refresh_workspace_helpers.sh --workspace <repo/<audit-workspace>>
  bash scripts/refresh_workspace_helpers.sh --repo-root <repo-root>

Description:
  Refresh helper scripts inside an already-bootstrapped audit workspace
  from the currently installed Claude skill.
EOF
}

WORKSPACE_DIR=""

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
    --workspace)
      WORKSPACE_DIR="$2"
      shift 2
      ;;
    --repo-root)
      REPO_ROOT="${2/#\~/$HOME}"
      if [[ -f "$REPO_ROOT/.asr-latest-workspace" ]]; then
        latest_name="$(tr -d '\n' < "$REPO_ROOT/.asr-latest-workspace")"
        if [[ -n "$latest_name" ]] && is_valid_workspace_dir "$REPO_ROOT/$latest_name"; then
          WORKSPACE_DIR="$REPO_ROOT/$latest_name"
        fi
      fi
      if [[ -z "$WORKSPACE_DIR" ]]; then
        latest_dir="$(find "$REPO_ROOT" -maxdepth 1 -type d -name 'security-research-*' -exec test -f '{}/asr-config.json' ';' -print 2>/dev/null | sort | tail -n 1 || true)"
        if [[ -n "$latest_dir" ]] && is_valid_workspace_dir "$latest_dir"; then
          WORKSPACE_DIR="$latest_dir"
        fi
      fi
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

if [[ -z "$WORKSPACE_DIR" ]]; then
  echo "No valid per-audit workspace was found." >&2
  echo "Run: bash scripts/asr_start.sh --repo-root <repo-root>" >&2
  exit 1
fi

if [[ ! -d "$WORKSPACE_DIR/bin" || ! -d "$WORKSPACE_DIR/scripts" || ! -f "$WORKSPACE_DIR/asr-config.json" ]]; then
  echo "Not a bootstrapped audit workspace: $WORKSPACE_DIR" >&2
  exit 1
fi

if ! is_valid_workspace_dir "$WORKSPACE_DIR"; then
  echo "Refusing to refresh a legacy or inconsistent audit workspace: $WORKSPACE_DIR" >&2
  echo "Create or resume a valid per-audit workspace via asr_start.sh first." >&2
  exit 1
fi

if [[ ! -d "$SKILL_DIR/scripts" ]]; then
  echo "Installed Claude skill not found: $SKILL_DIR" >&2
  exit 1
fi

copy_helper() {
  local src="$1"
  local dst="$2"
  cp "$src" "$dst"
  chmod +x "$dst"
}

copy_helper_if_present() {
  local src="$1"
  local dst="$2"
  if [[ -f "$src" ]]; then
    copy_helper "$src" "$dst"
  fi
}

copy_helper "$SKILL_DIR/scripts/asr_start.sh" "$WORKSPACE_DIR/bin/asr-start.sh"
copy_helper "$SKILL_DIR/scripts/asr_exec.sh" "$WORKSPACE_DIR/bin/asr-exec.sh"
copy_helper "$SKILL_DIR/scripts/check_docker_gate.sh" "$WORKSPACE_DIR/bin/check-docker-gate.sh"
copy_helper "$SKILL_DIR/scripts/check_omc_runtime.sh" "$WORKSPACE_DIR/bin/check_omc_runtime.sh"
copy_helper "$SKILL_DIR/scripts/check_security_tooling.sh" "$WORKSPACE_DIR/bin/check_security_tooling.sh"
copy_helper "$SKILL_DIR/scripts/run_initial_probes.sh" "$WORKSPACE_DIR/bin/run-initial-probes.sh"
copy_helper "$SKILL_DIR/scripts/plan_security_toolchain.py" "$WORKSPACE_DIR/bin/plan-security-toolchain.py"
copy_helper "$SKILL_DIR/scripts/scaffold_bilingual_findings.py" "$WORKSPACE_DIR/bin/scaffold-bilingual-findings.py"
copy_helper "$SKILL_DIR/scripts/validate_report_bundle.py" "$WORKSPACE_DIR/bin/validate-report-bundle.py"
copy_helper "$SKILL_DIR/scripts/validate_all_report_bundles.py" "$WORKSPACE_DIR/bin/validate-all-report-bundles.py"
copy_helper_if_present "$SKILL_DIR/scripts/write_audit_event.py" "$WORKSPACE_DIR/bin/write-audit-event.py"
copy_helper_if_present "$SKILL_DIR/scripts/validate_workspace_state.py" "$WORKSPACE_DIR/bin/validate-workspace-state.py"

if [[ -f "$WORKSPACE_DIR/bin/write-audit-event.py" ]]; then
  python3 "$WORKSPACE_DIR/bin/write-audit-event.py" \
    --workspace-dir "$WORKSPACE_DIR" \
    --target-repo "$(cd "$WORKSPACE_DIR/.." && pwd)" \
    --event workspace_helpers_refreshed \
    --stage workspace_preparing \
    --status running \
    --event-status ok \
    --message "Workspace helper scripts refreshed." || true
fi

cat <<EOF
Workspace helpers refreshed successfully:
  $WORKSPACE_DIR
EOF
