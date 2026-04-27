#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/check_docker_gate.sh --repo-root <repo-root> [--workspace-dir <dir>] [--note "<text>"]

Purpose:
  Enforce the Docker-only verification rule.
  If Docker is unavailable, append an audit log under the current audit workspace,
  summarize collected artifacts, and exit non-zero so the audit pauses safely instead of
  falling back to host-local verification.
EOF
}

REPO_ROOT=""
WORKSPACE_DIR=""
NOTE=""

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
  writer="$(find_state_writer)"
  [[ -n "$writer" ]] || return 0
  python3 "$writer" "$@" || \
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
    --note)
      NOTE="${2:-}"
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

WORKSPACE_DIR="$(infer_workspace_dir "$REPO_ROOT")"
LOG_FILE="$WORKSPACE_DIR/audit-log.md"
WORKSPACE_REL="$(python3 - <<'PY' "$REPO_ROOT" "$WORKSPACE_DIR"
from pathlib import Path
import sys
repo = Path(sys.argv[1]).resolve()
workspace = Path(sys.argv[2]).resolve()
try:
    print(workspace.relative_to(repo).as_posix())
except Exception:
    print(workspace.name)
PY
)"

TMP_OUT="$(mktemp -t asr-docker-gate.XXXXXX)"
if docker info >"$TMP_OUT" 2>&1; then
  write_state_event \
    --workspace-dir "$WORKSPACE_DIR" \
    --target-repo "$REPO_ROOT" \
    --event docker_gate_ready \
    --stage environment_checking \
    --status running \
    --event-status ok \
    --message "Docker gate is ready."
  echo "docker_gate=ready"
  rm -f "$TMP_OUT"
  exit 0
fi

timestamp="$(date '+%Y-%m-%d %H:%M:%S %z')"
docker_reason="$(head -n 1 "$TMP_OUT" | tr -d '\r' | sed 's/[[:space:]]*$//')"
if [[ -z "$docker_reason" ]]; then
  docker_reason="docker info failed; Docker daemon or socket is unavailable."
fi
resume_step="Fix Docker/OrbStack, then run: bash $WORKSPACE_DIR/bin/check-docker-gate.sh --repo-root $REPO_ROOT"
{
  echo ""
  echo "## $timestamp"
  echo ""
  echo "- 状态：Docker 不可用，验证已暂停。"
  echo "- 规则：严禁转去宿主机本地执行 PoC 或验证步骤。"
  if [[ -n "$NOTE" ]]; then
    echo "- 备注：$NOTE"
  fi
  echo "- 建议：先检查 \`docker info\`、镜像拉取、网络连通性与 Docker 守护进程状态；修复后从当前仓库继续审计。"
  echo ""
  echo "### 当前已收集材料"
  if [[ -f "$WORKSPACE_DIR/fingerprint.md" ]]; then
    echo "- \`$WORKSPACE_REL/fingerprint.md\`"
  fi
  if [[ -f "$WORKSPACE_DIR/candidate-findings.md" ]]; then
    echo "- \`$WORKSPACE_REL/candidate-findings.md\`"
  fi
  if [[ -f "$WORKSPACE_DIR/false-positives.md" ]]; then
    echo "- \`$WORKSPACE_REL/false-positives.md\`"
  fi
  if [[ -d "$WORKSPACE_DIR/poc" ]]; then
    find "$WORKSPACE_DIR/poc" -type f | sed "s#^$REPO_ROOT/##" | sed 's#^#- `#; s#$#`#'
  fi
  if [[ -d "$WORKSPACE_DIR/evidence" ]]; then
    find "$WORKSPACE_DIR/evidence" -type f | sed "s#^$REPO_ROOT/##" | sed 's#^#- `#; s#$#`#'
  fi
  if [[ -d "$WORKSPACE_DIR/confirmed" ]]; then
    find "$WORKSPACE_DIR/confirmed" -maxdepth 3 -type f | sed "s#^$REPO_ROOT/##" | sed 's#^#- `#; s#$#`#'
  fi
  echo ""
  echo "### docker info 报错"
  echo '```text'
  cat "$TMP_OUT"
  echo '```'
} >>"$LOG_FILE"

write_state_event \
  --workspace-dir "$WORKSPACE_DIR" \
  --target-repo "$REPO_ROOT" \
  --event docker_gate_blocked \
  --stage environment_checking \
  --status blocked \
  --event-status blocked \
  --message "Docker gate blocked verification." \
  --blocker "$docker_reason" \
  --resume-step "$resume_step" \
  --detail "audit_log=$LOG_FILE"

cat <<EOF
============================================================
Zhulong Docker Gate Blocked
============================================================
Repository: $REPO_ROOT
Workspace:  $WORKSPACE_DIR
Reason:     $docker_reason
Rule:       Do not verify PoCs or exploit traffic on the host.
Audit log:  $LOG_FILE
Next:       $resume_step
============================================================
docker_gate=blocked
audit_log=$LOG_FILE
message=Docker is unavailable. Progress has been logged. Do not verify on the host. Check Docker and resume later.
EOF

rm -f "$TMP_OUT"
exit 1
