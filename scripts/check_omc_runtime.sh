#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  check_omc_runtime.sh [--cleanup-stale] [--force-kill-suspect-teammates] [--workspace-dir <dir>] [--json]

Purpose:
  Detect whether OMC multi-agent execution is safe to use in the current Claude Code session.

Modes:
  - native_team_ready: Claude Code native teams are enabled and no stale tmux swarm residue was found.
  - cleanup_needed: stale teammate/tmux residue was found; clean it before starting a new audit.
  - single_agent_only: native teams are not enabled; do not force /team or ultrawork.

Notes:
  - This script never starts OMC workers.
  - With --cleanup-stale, it removes only stale claude-swarm sockets.
  - Suspect `claude --teammate-mode tmux` processes are never killed automatically.
    If teammate-mode processes are detected without a live swarm socket, inspect them
    manually before terminating anything.
  - The current Claude session's own teammate-mode ancestor is excluded automatically
    and must never be treated as stale residue.
EOF
}

CLEANUP_STALE=0
FORCE_KILL_SUSPECT_TEAMMATES=0
JSON_OUTPUT=0
WORKSPACE_DIR=""

is_valid_workspace_dir() {
  local candidate="${1:-}"
  [[ -n "$candidate" ]] || return 1
  [[ -f "$candidate/asr-config.json" ]] || return 1
}

infer_workspace_dir() {
  local script_dir inferred
  if [[ -n "${WORKSPACE_DIR:-}" ]]; then
    local explicit="${WORKSPACE_DIR/#\~/$HOME}"
    if is_valid_workspace_dir "$explicit"; then
      cd "$explicit" && pwd
      return
    fi
    return 1
  fi
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  inferred="$(cd "$script_dir/.." && pwd)"
  if is_valid_workspace_dir "$inferred"; then
    printf '%s\n' "$inferred"
    return
  fi
  return 1
}

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

find_handoff_renderer() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -f "$script_dir/render_handoff_summary.py" ]]; then
    printf '%s\n' "$script_dir/render_handoff_summary.py"
    return
  fi
  if [[ -f "$script_dir/render-handoff-summary.py" ]]; then
    printf '%s\n' "$script_dir/render-handoff-summary.py"
    return
  fi
  if [[ -f "$script_dir/../bin/render-handoff-summary.py" ]]; then
    printf '%s\n' "$script_dir/../bin/render-handoff-summary.py"
    return
  fi
}

write_state_event() {
  local workspace writer
  workspace="$(infer_workspace_dir 2>/dev/null || true)"
  [[ -n "$workspace" ]] || return 0
  writer="$(find_state_writer)"
  [[ -n "$writer" ]] || return 0
  python3 "$writer" "$@" --workspace-dir "$workspace" --target-repo "$(cd "$workspace/.." && pwd)" || \
    echo "[zhulong] WARNING: state write failed (non-fatal)." >&2
}

collect_current_session_teammate_ancestors() {
  local current="$1"
  local depth=0
  local max_depth=20
  local line parent cmd pid

  while [[ -n "$current" && "$current" =~ ^[0-9]+$ && "$current" -gt 1 && "$depth" -lt "$max_depth" ]]; do
    line="$(ps -p "$current" -o pid=,ppid=,command= 2>/dev/null | sed 's/^[[:space:]]*//')"
    [[ -n "$line" ]] || break
    pid="$(printf '%s\n' "$line" | awk '{print $1}')"
    parent="$(printf '%s\n' "$line" | awk '{print $2}')"
    cmd="$(printf '%s\n' "$line" | cut -d' ' -f3-)"

    if [[ "$cmd" == *"claude --teammate-mode tmux"* ]]; then
      printf '%s\n' "$pid"
    fi

    current="$parent"
    depth=$((depth + 1))
  done
}

array_count() {
  case "$1" in
    teammate_pids)
      if declare -p teammate_pids >/dev/null 2>&1; then
        echo "${#teammate_pids[@]}"
      else
        echo 0
      fi
      ;;
    stale_sockets)
      if declare -p stale_sockets >/dev/null 2>&1; then
        echo "${#stale_sockets[@]}"
      else
        echo 0
      fi
      ;;
    live_sockets)
      if declare -p live_sockets >/dev/null 2>&1; then
        echo "${#live_sockets[@]}"
      else
        echo 0
      fi
      ;;
    *)
      echo 0
      ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cleanup-stale)
      CLEANUP_STALE=1
      shift
      ;;
    --force-kill-suspect-teammates)
      FORCE_KILL_SUSPECT_TEAMMATES=1
      shift
      ;;
    --workspace-dir)
      WORKSPACE_DIR="${2:-}"
      shift 2
      ;;
    --json)
      JSON_OUTPUT=1
      shift
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

CLAUDE_SETTINGS="$HOME/.claude/settings.json"
TMUX_DIR="/private/tmp/tmux-$(id -u)"

teams_enabled=0
if [[ -f "$CLAUDE_SETTINGS" ]]; then
  teams_val="$(python3 - <<'PY' "$CLAUDE_SETTINGS"
import json
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(data.get("env", {}).get("CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS", ""))
except Exception:
    print("")
PY
)"
  if [[ "$teams_val" == "1" || "$teams_val" == "true" ]]; then
    teams_enabled=1
  fi
fi

if [[ "${CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS:-}" == "1" || "${CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS:-}" == "true" ]]; then
  teams_enabled=1
fi

teammate_pids=()
while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  teammate_pids+=("$line")
done < <(ps -Ao pid=,command= | awk '/claude --teammate-mode tmux/ && $0 !~ /awk/ {print $1}')

current_session_teammate_pids=()
while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  current_session_teammate_pids+=("$line")
done < <(collect_current_session_teammate_ancestors "$$")
ignored_current_session_teammate_pids=()

if (( ${#current_session_teammate_pids[@]} > 0 && ${#teammate_pids[@]} > 0 )); then
  filtered_teammates=()
  for pid in "${teammate_pids[@]}"; do
    skip_pid=0
    for current_pid in "${current_session_teammate_pids[@]}"; do
      if [[ "$pid" == "$current_pid" ]]; then
        skip_pid=1
        ignored_current_session_teammate_pids+=("$pid")
        break
      fi
    done
    if [[ "$skip_pid" != "1" ]]; then
      filtered_teammates+=("$pid")
    fi
  done
  teammate_pids=("${filtered_teammates[@]}")
fi

stale_sockets=()
live_sockets=()
orphan_teammate_pids=()
suspect_teammate_pids=()

if [[ -d "$TMUX_DIR" ]]; then
  while IFS= read -r sock; do
    [[ -n "$sock" ]] || continue
    name="$(basename "$sock")"
    if tmux -L "$name" ls >/dev/null 2>&1; then
      live_sockets+=("$sock")
    else
      stale_sockets+=("$sock")
    fi
  done < <(find "$TMUX_DIR" -maxdepth 1 -name 'claude-swarm-*' -print 2>/dev/null || true)
fi

if (( $(array_count teammate_pids) > 0 )); then
  if (( $(array_count live_sockets) == 0 )); then
    suspect_teammate_pids=("${teammate_pids[@]}")
  fi
fi

if [[ "$CLEANUP_STALE" == "1" ]]; then
  if [[ "$FORCE_KILL_SUSPECT_TEAMMATES" == "1" && ${#suspect_teammate_pids[@]} -gt 0 ]]; then
    for pid in "${suspect_teammate_pids[@]}"; do
      kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in "${suspect_teammate_pids[@]}"; do
      kill -9 "$pid" 2>/dev/null || true
    done
  fi
  if (( $(array_count stale_sockets) > 0 )); then
    for sock in "${stale_sockets[@]}"; do
      rm -f "$sock" 2>/dev/null || true
    done
  fi
  if (( $(array_count live_sockets) == 0 )); then
    teammate_pids=()
  fi
  orphan_teammate_pids=()
  suspect_teammate_pids=()
  stale_sockets=()
fi

recommended_mode="native_team_ready"
reason="native teams enabled and no stale tmux residue"

if (( ${#suspect_teammate_pids[@]} > 0 || $(array_count stale_sockets) > 0 )); then
  recommended_mode="cleanup_needed"
  if (( ${#suspect_teammate_pids[@]} > 0 && $(array_count stale_sockets) > 0 )); then
    reason="stale claude-swarm socket detected and teammate-mode processes need manual review"
  elif (( ${#suspect_teammate_pids[@]} > 0 )); then
    reason="teammate-mode processes detected without a live swarm socket; manual review required"
  else
    reason="stale claude-swarm socket detected"
  fi
elif (( $(array_count live_sockets) > 0 )); then
  reason="active live claude-swarm session detected; do not cleanup current teammate workers"
elif [[ "$teams_enabled" != "1" ]]; then
  recommended_mode="single_agent_only"
  reason="CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS is not enabled"
fi

write_state_event \
  --event omc_runtime_checked \
  --stage environment_checking \
  --status running \
  --event-status "$recommended_mode" \
  --message "$reason"

handoff_line=""
if [[ "$recommended_mode" == "cleanup_needed" ]]; then
  handoff_workspace="$(infer_workspace_dir 2>/dev/null || true)"
  handoff_renderer="$(find_handoff_renderer)"
  if [[ -n "$handoff_workspace" && -n "$handoff_renderer" ]]; then
    python3 "$handoff_renderer" --workspace-dir "$handoff_workspace" --repo-root "$(cd "$handoff_workspace/.." && pwd)" >/dev/null || true
    handoff_line="$handoff_workspace/handoff-summary.md"
  elif [[ -n "$handoff_workspace" ]]; then
    handoff_line="Run: python3 $handoff_workspace/bin/render-handoff-summary.py --workspace-dir $handoff_workspace"
  fi
fi

if [[ "$JSON_OUTPUT" == "1" ]]; then
  teammate_blob=""
  ignored_blob=""
  stale_blob=""
  live_blob=""
  if (( $(array_count teammate_pids) > 0 )); then
    teammate_blob="$(printf '%s\n' "${teammate_pids[@]}")"
  fi
  if (( ${#ignored_current_session_teammate_pids[@]} > 0 )); then
    ignored_blob="$(printf '%s\n' "${ignored_current_session_teammate_pids[@]}")"
  fi
  if (( $(array_count stale_sockets) > 0 )); then
    stale_blob="$(printf '%s\n' "${stale_sockets[@]}")"
  fi
  if (( $(array_count live_sockets) > 0 )); then
    live_blob="$(printf '%s\n' "${live_sockets[@]}")"
  fi
  python3 - <<'PY' \
    "$recommended_mode" \
    "$reason" \
    "$teams_enabled" \
    "$teammate_blob" \
    "$ignored_blob" \
    "$stale_blob" \
    "$live_blob" \
    "$handoff_line"
import json
import sys

mode, reason, teams_enabled, teammate_blob, ignored_blob, stale_blob, live_blob, handoff_line = sys.argv[1:9]

def lines(blob: str) -> list[str]:
    return [line for line in blob.splitlines() if line]

print(json.dumps({
    "recommended_mode": mode,
    "reason": reason,
    "teams_enabled": teams_enabled == "1",
    "orphan_teammate_pids": [],
    "suspect_teammate_pids": lines(teammate_blob) if "manual review" in reason else [],
    "ignored_current_session_teammate_pids": lines(ignored_blob),
    "stale_swarm_sockets": lines(stale_blob),
    "live_swarm_sockets": lines(live_blob),
    "handoff_summary": handoff_line,
}, ensure_ascii=False, indent=2))
PY
else
  teammate_line=""
  ignored_line=""
  stale_line=""
  live_line=""
  orphan_line=""
  if (( $(array_count teammate_pids) > 0 )); then
    teammate_line="${teammate_pids[*]}"
  fi
  if (( ${#suspect_teammate_pids[@]} > 0 )); then
    orphan_line="${suspect_teammate_pids[*]}"
  fi
  if (( ${#ignored_current_session_teammate_pids[@]} > 0 )); then
    ignored_line="${ignored_current_session_teammate_pids[*]}"
  fi
  if (( $(array_count stale_sockets) > 0 )); then
    stale_line="${stale_sockets[*]}"
  fi
  if (( $(array_count live_sockets) > 0 )); then
    live_line="${live_sockets[*]}"
  fi
  cat <<EOF
recommended_mode=$recommended_mode
reason=$reason
handoff_summary=$handoff_line
teams_enabled=$teams_enabled
teammate_pids=$teammate_line
orphan_teammate_pids=
suspect_teammate_pids=$orphan_line
ignored_current_session_teammate_pids=$ignored_line
stale_swarm_sockets=$stale_line
live_swarm_sockets=$live_line
EOF
fi
