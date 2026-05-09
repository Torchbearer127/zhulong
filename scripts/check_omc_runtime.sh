#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  check_omc_runtime.sh [--cleanup-stale] [--cleanup-suspect-pid <pid>] [--workspace-dir <dir>] [--json]

Purpose:
  Detect whether OMC multi-agent execution is safe to use in the current Claude Code session.

Modes:
  - native_team_ready: Claude Code native teams are enabled and no stale OMC residue was found.
  - cleanup_needed: stale socket residue or review-only teammate PID ambiguity was found before /team or /ultrawork.
  - single_agent_only: native teams are not enabled; continue single-agent.

Cleanup safety:
  - --cleanup-stale removes only stale claude-swarm sockets, and refuses when a live swarm socket exists.
  - --cleanup-suspect-pid <pid> is report-only for teammate PIDs. The apply flag does not change this.
  - PID review records process metadata and manual inspection guidance, but Zhulong never signals teammate PIDs.
  - --force-kill-suspect-teammates is deprecated and always refused.
USAGE
}

CLEANUP_STALE=0
CLEANUP_PID=""
APPLY=0
JSON_OUTPUT=0
WORKSPACE_DIR=""
LEGACY_FORCE_KILL=0

teammate_pids=()
teammate_cmds=()
teammate_meta=()
current_session_ancestor_pids=()
current_session_teammate_pids=()
ignored_current_session_teammate_pids=()
ignored_current_session_teammate_meta=()
stale_sockets=()
live_sockets=()
suspect_teammate_pids=()
suspect_teammate_meta=()
cleanup_actions=()
unresolved_review_only=()

append_action() {
  local kind="$1" value="$2" status="$3" reason="$4" signal="${5:-}"
  local line
  printf -v line '%s\t%s\t%s\t%s\t%s' "$kind" "$value" "$status" "$reason" "$signal"
  cleanup_actions+=("$line")
}

append_unresolved() {
  local kind="$1" value="$2" reason="$3" resume="$4"
  local line
  printf -v line '%s\t%s\t%s\t%s' "$kind" "$value" "$reason" "$resume"
  unresolved_review_only+=("$line")
}

process_record_line() {
  local pid="$1" ppid="${2:-unknown}" pgid="${3:-unknown}" sess="${4:-unknown}" tty="${5:-unknown}" stat="${6:-unknown}" command="${7:-}" active="${8:-true}"
  local line
  printf -v line '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$pid" "$ppid" "$pgid" "$sess" "$tty" "$stat" "$command" "$active"
  printf '%s\n' "$line"
}

unknown_process_record() {
  local pid="$1" command="${2:-}"
  process_record_line "$pid" "unknown" "unknown" "unknown" "unknown" "unknown" "$command" "true"
}

contains_line() {
  local needle="$1" blob="${2:-}"
  [[ -n "$needle" ]] || return 1
  while IFS= read -r line; do
    [[ "$line" == "$needle" ]] && return 0
  done <<< "$blob"
  return 1
}

array_contains() {
  local needle="$1"
  shift || true
  local item
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

is_valid_workspace_dir() {
  local candidate="${1:-}"
  [[ -n "$candidate" ]] || return 1
  [[ -f "$candidate/asr-config.json" ]] || return 1
}

infer_workspace_dir() {
  local script_dir inferred explicit
  if [[ -n "${WORKSPACE_DIR:-}" ]]; then
    explicit="${WORKSPACE_DIR/#\~/$HOME}"
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

collect_current_session_ancestors() {
  local current="$1" depth=0 max_depth=30 line parent pid
  while [[ -n "$current" && "$current" =~ ^[0-9]+$ && "$current" -gt 1 && "$depth" -lt "$max_depth" ]]; do
    line="$(ps -p "$current" -o pid=,ppid= 2>/dev/null | sed 's/^[[:space:]]*//' || true)"
    [[ -n "$line" ]] || break
    pid="$(printf '%s\n' "$line" | awk '{print $1}')"
    parent="$(printf '%s\n' "$line" | awk '{print $2}')"
    [[ -n "$pid" ]] && printf '%s\n' "$pid"
    current="$parent"
    depth=$((depth + 1))
  done
}

collect_current_session_teammate_ancestors() {
  local current="$1" depth=0 max_depth=30 line parent cmd pid
  while [[ -n "$current" && "$current" =~ ^[0-9]+$ && "$current" -gt 1 && "$depth" -lt "$max_depth" ]]; do
    line="$(ps -p "$current" -o pid=,ppid=,command= 2>/dev/null | sed 's/^[[:space:]]*//' || true)"
    [[ -n "$line" ]] || break
    pid="$(printf '%s\n' "$line" | awk '{print $1}')"
    parent="$(printf '%s\n' "$line" | awk '{print $2}')"
    cmd="$(printf '%s\n' "$line" | awk '{for (i=3;i<=NF;i++) printf "%s%s", $i, (i<NF ? " " : ""); print ""}')"
    if [[ "$cmd" == *"claude --teammate-mode tmux"* ]]; then
      printf '%s\n' "$pid"
    fi
    current="$parent"
    depth=$((depth + 1))
  done
}

read_lines_into_array() {
  local blob="$1" array_name="$2" line
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    eval "$array_name+=(\"\$line\")"
  done <<< "$blob"
  return 0
}

load_teams_enabled() {
  local settings teams_val
  if [[ -n "${ZHULONG_OMC_MOCK_TEAMS_ENABLED:-}" ]]; then
    [[ "$ZHULONG_OMC_MOCK_TEAMS_ENABLED" == "1" || "$ZHULONG_OMC_MOCK_TEAMS_ENABLED" == "true" ]] && return 0
    return 1
  fi
  settings="$HOME/.claude/settings.json"
  if [[ -f "$settings" ]]; then
    teams_val="$(python3 - <<'PY' "$settings"
import json
import sys
try:
    data = json.loads(open(sys.argv[1], encoding="utf-8").read())
    print(data.get("env", {}).get("CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS", ""))
except Exception:
    print("")
PY
)"
    if [[ "$teams_val" == "1" || "$teams_val" == "true" ]]; then
      return 0
    fi
  fi
  [[ "${CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS:-}" == "1" || "${CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS:-}" == "true" ]]
}

load_teammate_records() {
  local line pid cmd normalized ppid pgid sess tty stat
  if [[ -n "${ZHULONG_OMC_MOCK_TEAMMATE_RECORDS:-}" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      IFS='|' read -r pid ppid pgid sess tty stat cmd <<< "$line"
      if [[ -z "${cmd:-}" ]]; then
        cmd="${line#*|}"
        ppid="unknown"
        pgid="unknown"
        sess="unknown"
        tty="unknown"
        stat="unknown"
      fi
      teammate_pids+=("$pid")
      teammate_cmds+=("$cmd")
      teammate_meta+=("$(process_record_line "$pid" "$ppid" "$pgid" "$sess" "$tty" "$stat" "$cmd" "true")")
    done <<< "$ZHULONG_OMC_MOCK_TEAMMATE_RECORDS"
    return 0
  fi
  while IFS= read -r line; do
    normalized="$(printf '%s\n' "$line" | sed 's/^[[:space:]]*//')"
    [[ -n "$normalized" ]] || continue
    pid="$(printf '%s\n' "$normalized" | awk '{print $1}')"
    ppid="$(printf '%s\n' "$normalized" | awk '{print $2}')"
    pgid="$(printf '%s\n' "$normalized" | awk '{print $3}')"
    sess="$(printf '%s\n' "$normalized" | awk '{print $4}')"
    tty="$(printf '%s\n' "$normalized" | awk '{print $5}')"
    stat="$(printf '%s\n' "$normalized" | awk '{print $6}')"
    cmd="$(printf '%s\n' "$normalized" | awk '{for (i=7;i<=NF;i++) printf "%s%s", $i, (i<NF ? " " : ""); print ""}')"
    if [[ "$pid" =~ ^[0-9]+$ && "$cmd" == *"claude --teammate-mode tmux"* ]]; then
      teammate_pids+=("$pid")
      teammate_cmds+=("$cmd")
      teammate_meta+=("$(process_record_line "$pid" "$ppid" "$pgid" "$sess" "$tty" "$stat" "$cmd" "true")")
    fi
  done < <(ps -Ao pid=,ppid=,pgid=,sess=,tty=,stat=,command= 2>/dev/null || true)
  return 0
}

load_current_session_records() {
  if [[ -n "${ZHULONG_OMC_MOCK_CURRENT_SESSION_ANCESTOR_PIDS:-}" ]]; then
    read_lines_into_array "$ZHULONG_OMC_MOCK_CURRENT_SESSION_ANCESTOR_PIDS" current_session_ancestor_pids
  else
    read_lines_into_array "$(collect_current_session_ancestors "$$")" current_session_ancestor_pids
  fi
  if [[ -n "${ZHULONG_OMC_MOCK_CURRENT_SESSION_TEAMMATE_PIDS:-}" ]]; then
    read_lines_into_array "$ZHULONG_OMC_MOCK_CURRENT_SESSION_TEAMMATE_PIDS" current_session_teammate_pids
  else
    read_lines_into_array "$(collect_current_session_teammate_ancestors "$$")" current_session_teammate_pids
  fi
  return 0
}

load_sockets() {
  local tmux_dir sock name
  if [[ -n "${ZHULONG_OMC_MOCK_STALE_SOCKETS:-}" || -n "${ZHULONG_OMC_MOCK_LIVE_SOCKETS:-}" ]]; then
    read_lines_into_array "${ZHULONG_OMC_MOCK_STALE_SOCKETS:-}" stale_sockets
    read_lines_into_array "${ZHULONG_OMC_MOCK_LIVE_SOCKETS:-}" live_sockets
    return 0
  fi
  tmux_dir="/private/tmp/tmux-$(id -u)"
  [[ -d "$tmux_dir" ]] || return 0
  while IFS= read -r sock; do
    [[ -n "$sock" ]] || continue
    name="$(basename "$sock")"
    if tmux -L "$name" ls >/dev/null 2>&1; then
      live_sockets+=("$sock")
    else
      stale_sockets+=("$sock")
    fi
  done < <(find "$tmux_dir" -maxdepth 1 -name 'claude-swarm-*' -print 2>/dev/null || true)
  return 0
}

cmdline_for_pid() {
  local target="$1" idx
  if [[ -n "${ZHULONG_OMC_MOCK_CMDLINE_RECORDS:-}" ]]; then
    local line pid cmd
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      pid="${line%%|*}"
      cmd="${line#*|}"
      if [[ "$pid" == "$target" ]]; then
        printf '%s\n' "$cmd"
        return 0
      fi
    done <<< "$ZHULONG_OMC_MOCK_CMDLINE_RECORDS"
    return 1
  fi
  if [[ -n "${ZHULONG_OMC_MOCK_TEAMMATE_RECORDS:-}" ]]; then
    local line pid cmd
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      pid="${line%%|*}"
      cmd="${line#*|}"
      if [[ "$pid" == "$target" ]]; then
        printf '%s\n' "$cmd"
        return 0
      fi
    done <<< "$ZHULONG_OMC_MOCK_TEAMMATE_RECORDS"
    return 1
  fi
  for idx in "${!teammate_pids[@]}"; do
    if [[ "${teammate_pids[$idx]}" == "$target" ]]; then
      printf '%s\n' "${teammate_cmds[$idx]}"
      return 0
    fi
  done
  ps -p "$target" -o command= 2>/dev/null | sed 's/^[[:space:]]*//' || true
}

pid_exists() {
  local target="$1"
  if [[ -n "${ZHULONG_OMC_MOCK_PID_MISSING:-}" ]] && contains_line "$target" "$ZHULONG_OMC_MOCK_PID_MISSING"; then
    return 1
  fi
  if [[ -n "${ZHULONG_OMC_MOCK_PID_EXISTS:-}" ]]; then
    contains_line "$target" "$ZHULONG_OMC_MOCK_PID_EXISTS"
    return
  fi
  kill -0 "$target" 2>/dev/null
}

is_current_session_related() {
  local target="$1"
  if (( ${#current_session_ancestor_pids[@]} > 0 )) && array_contains "$target" "${current_session_ancestor_pids[@]}"; then
    return 0
  fi
  if (( ${#current_session_teammate_pids[@]} > 0 )) && array_contains "$target" "${current_session_teammate_pids[@]}"; then
    return 0
  fi
  if (( ${#ignored_current_session_teammate_pids[@]} > 0 )) && array_contains "$target" "${ignored_current_session_teammate_pids[@]}"; then
    return 0
  fi
  return 1
}

filter_current_session_teammates() {
  local filtered_pids=() filtered_cmds=() filtered_meta=() idx pid current_meta
  (( ${#teammate_pids[@]} > 0 )) || return 0
  for idx in "${!teammate_pids[@]}"; do
    pid="${teammate_pids[$idx]}"
    if is_current_session_related "$pid"; then
      ignored_current_session_teammate_pids+=("$pid")
      current_meta="$(printf '%s\n' "${teammate_meta[$idx]}" | awk -F '\t' 'BEGIN{OFS="\t"} {$8="false"; print}')"
      ignored_current_session_teammate_meta+=("$current_meta")
    else
      filtered_pids+=("$pid")
      filtered_cmds+=("${teammate_cmds[$idx]}")
      filtered_meta+=("${teammate_meta[$idx]}")
    fi
  done
  if (( ${#filtered_pids[@]} > 0 )); then
    teammate_pids=("${filtered_pids[@]}")
    teammate_cmds=("${filtered_cmds[@]}")
    teammate_meta=("${filtered_meta[@]}")
  else
    teammate_pids=()
    teammate_cmds=()
    teammate_meta=()
  fi
}

cleanup_stale_sockets() {
  local sock
  if (( ${#live_sockets[@]} > 0 )); then
    append_action "stale_swarm_socket_cleanup" "*" "refused" "live claude-swarm socket exists; finish or cancel the active team session before cleanup" ""
    append_unresolved "live_swarm_socket" "${live_sockets[*]}" "live socket makes cleanup uncertain" "Finish or cancel the active OMC team session, then rerun check_omc_runtime.sh."
    return 1
  fi
  (( ${#stale_sockets[@]} > 0 )) || return 0
  for sock in "${stale_sockets[@]}"; do
    if [[ "$(basename "$sock")" != claude-swarm-* ]]; then
      append_unresolved "stale_swarm_socket" "$sock" "refused non-claude-swarm socket cleanup" "Review this socket manually; Zhulong only removes stale claude-swarm-* sockets."
      continue
    fi
    if [[ -n "${ZHULONG_OMC_MOCK_SOCKET_CLEANUP_LOG:-}" ]]; then
      printf 'REMOVE_SOCKET %s\n' "$sock" >> "$ZHULONG_OMC_MOCK_SOCKET_CLEANUP_LOG"
    else
      rm -f "$sock" 2>/dev/null || true
    fi
    append_action "stale_swarm_socket_cleanup" "$sock" "removed" "stale socket removed" ""
  done
  stale_sockets=()
}

cleanup_exact_pid() {
  local target="$1" cmd
  if [[ ! "$target" =~ ^[0-9]+$ ]]; then
    append_action "cleanup_suspect_pid" "$target" "refused" "PID must be numeric" ""
    append_unresolved "suspect_teammate_pid" "$target" "invalid PID" "Pass an exact numeric PID from suspect_teammate_pids."
    return 1
  fi
  if ! pid_exists "$target"; then
    append_action "cleanup_suspect_pid" "$target" "refused" "PID no longer exists" ""
    return 1
  fi
  cmd="$(cmdline_for_pid "$target")"
  if [[ -z "$cmd" || "$cmd" != *"claude --teammate-mode tmux"* ]]; then
    append_action "cleanup_suspect_pid" "$target" "refused" "command line no longer matches claude --teammate-mode tmux" ""
    append_unresolved "suspect_teammate_pid" "$target" "command line mismatch or unreadable" "Re-run check_omc_runtime.sh and inspect ps -fp $target; Zhulong will not signal teammate PIDs."
    return 1
  fi
  if is_current_session_related "$target"; then
    append_unresolved "current_session_teammate_pid" "$target" "self-protection refused PID signaling" "Do not terminate current-session teammate PIDs; finish or cancel the active session first."
    return 1
  fi
  if (( ${#live_sockets[@]} > 0 )); then
    append_unresolved "live_swarm_socket" "${live_sockets[*]}" "live socket makes PID cleanup uncertain" "Finish or cancel the active OMC team session, then rerun check_omc_runtime.sh."
    return 1
  fi
  if [[ "$APPLY" != "1" ]]; then
    append_unresolved "suspect_teammate_pid" "$target" "review-only; no signal sent" "Inspect with ps -fp $target and the owning terminal/session. Zhulong will not signal teammate PIDs; if the operator confirms it is stale, terminate it manually outside Zhulong."
    return 0
  fi
  append_unresolved "suspect_teammate_pid" "$target" "refused --apply; teammate PID signaling is disabled" "Inspect with ps -fp $target and the owning terminal/session. Zhulong will not signal teammate PIDs; if the operator confirms it is stale, terminate it manually outside Zhulong."
  return 1
}

emit_status() {
  local workspace="$1" mode="$2" reason="$3" teams_enabled="$4" resume_step="$5" handoff_line="$6" clean="$7"
  local suspect_blob ignored_blob stale_blob live_blob cleanup_blob unresolved_blob suspect_meta_blob ignored_meta_blob status_path=""
  suspect_blob="$(printf '%s\n' "${suspect_teammate_pids[@]:-}" | sed '/^$/d')"
  ignored_blob="$(printf '%s\n' "${ignored_current_session_teammate_pids[@]:-}" | sed '/^$/d')"
  stale_blob="$(printf '%s\n' "${stale_sockets[@]:-}" | sed '/^$/d')"
  live_blob="$(printf '%s\n' "${live_sockets[@]:-}" | sed '/^$/d')"
  cleanup_blob="$(printf '%s\n' "${cleanup_actions[@]:-}" | sed '/^$/d')"
  unresolved_blob="$(printf '%s\n' "${unresolved_review_only[@]:-}" | sed '/^$/d')"
  suspect_meta_blob="$(printf '%s\n' "${suspect_teammate_meta[@]:-}" | sed '/^$/d')"
  ignored_meta_blob="$(printf '%s\n' "${ignored_current_session_teammate_meta[@]:-}" | sed '/^$/d')"
  if [[ -n "$workspace" ]]; then
    mkdir -p "$workspace/runtime"
    status_path="$workspace/runtime/runtime-hygiene-status.json"
  fi
  python3 - <<'PY' \
    "$mode" "$reason" "$teams_enabled" "$suspect_blob" "$ignored_blob" "$stale_blob" "$live_blob" \
    "$cleanup_blob" "$unresolved_blob" "$suspect_meta_blob" "$ignored_meta_blob" "$resume_step" "$handoff_line" "$clean" "$status_path" "$workspace" "$JSON_OUTPUT"
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

(
    mode,
    reason,
    teams_enabled,
    suspect_blob,
    ignored_blob,
    stale_blob,
    live_blob,
    cleanup_blob,
    unresolved_blob,
    suspect_meta_blob,
    ignored_meta_blob,
    resume_step,
    handoff_line,
    clean,
    status_path,
    workspace,
    json_output,
) = sys.argv[1:18]

def lines(blob: str) -> list[str]:
    return [line for line in blob.splitlines() if line]

def parse_cleanup(blob: str) -> list[dict[str, str]]:
    items = []
    for line in lines(blob):
        parts = (line.split("\t") + [""] * 5)[:5]
        kind, value, status, action_reason, signal = parts
        item = {"kind": kind, "value": value, "status": status, "reason": action_reason}
        if signal:
            item["signal"] = signal
        items.append(item)
    return items

def parse_unresolved(blob: str) -> list[dict[str, str]]:
    items = []
    for line in lines(blob):
        parts = (line.split("\t") + [""] * 4)[:4]
        kind, value, item_reason, item_resume = parts
        items.append({"kind": kind, "value": value, "reason": item_reason, "resume_step": item_resume})
    return items

def parse_processes(blob: str) -> list[dict[str, object]]:
    items = []
    for line in lines(blob):
        parts = (line.split("\t") + [""] * 8)[:8]
        pid, ppid, pgid, sess, tty, stat, command, uncertain = parts
        items.append({
            "pid": pid,
            "ppid": ppid,
            "pgid": pgid,
            "sess": sess,
            "tty": tty,
            "stat": stat,
            "command": command,
            "active_session_uncertain": uncertain != "false",
        })
    return items

cleanup_actions = parse_cleanup(cleanup_blob)
suspect_processes = parse_processes(suspect_meta_blob)
ignored_processes = parse_processes(ignored_meta_blob)
process_by_pid = {
    str(item.get("pid")): item
    for item in suspect_processes + ignored_processes
    if item.get("pid")
}
unresolved = parse_unresolved(unresolved_blob)
for item in unresolved:
    process = process_by_pid.get(str(item.get("value") or ""))
    if process:
        item["process"] = process
attempt_history = []
path = Path(status_path) if status_path else None
if path and path.exists():
    try:
        old = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(old.get("attempt_history"), list):
            attempt_history.extend(item for item in old["attempt_history"] if isinstance(item, dict))
    except Exception:
        pass
checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
for action in cleanup_actions:
    attempt = dict(action)
    attempt["at"] = checked_at
    attempt_history.append(attempt)
payload = {
    "checked_at": checked_at,
    "recommended_mode": mode,
    "reason": reason,
    "teams_enabled": teams_enabled == "1",
    "suspect_teammate_pids": lines(suspect_blob),
    "suspect_teammate_processes": suspect_processes,
    "stale_swarm_sockets": lines(stale_blob),
    "live_swarm_sockets": lines(live_blob),
    "ignored_current_session_teammate_pids": lines(ignored_blob),
    "ignored_current_session_teammate_processes": ignored_processes,
    "cleanup_actions": cleanup_actions,
    "attempt_history": attempt_history[-50:],
    "heartbeat_seen": bool(lines(live_blob)),
    "resume_step": resume_step,
    "unresolved_review_only": unresolved,
    "clean": clean == "1",
    "handoff_summary": handoff_line,
}
if path:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if json_output == "1":
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
PY
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cleanup-stale)
      CLEANUP_STALE=1
      shift
      ;;
    --force-kill-suspect-teammates)
      LEGACY_FORCE_KILL=1
      shift
      ;;
    --cleanup-suspect-pid)
      CLEANUP_PID="${2:-}"
      shift 2
      ;;
    --apply)
      APPLY=1
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

if [[ "$LEGACY_FORCE_KILL" == "1" ]]; then
  echo "Refusing deprecated --force-kill-suspect-teammates. Teammate PID cleanup is review-only; inspect with ps -fp <pid> and terminate manually outside Zhulong if an operator confirms it is stale." >&2
  exit 2
fi

teams_enabled=0
if load_teams_enabled; then
  teams_enabled=1
fi

load_teammate_records
load_current_session_records
load_sockets
filter_current_session_teammates

if (( ${#teammate_pids[@]} > 0 && ${#live_sockets[@]} == 0 )); then
  suspect_teammate_pids=("${teammate_pids[@]}")
  suspect_teammate_meta=("${teammate_meta[@]}")
fi

cleanup_exit=0
if [[ "$CLEANUP_STALE" == "1" ]]; then
  cleanup_stale_sockets || cleanup_exit=1
fi
if [[ -n "$CLEANUP_PID" ]]; then
  cleanup_exact_pid "$CLEANUP_PID" || cleanup_exit=1
fi

if (( ${#suspect_teammate_pids[@]} > 0 )); then
  for pid in "${suspect_teammate_pids[@]}"; do
    append_unresolved "suspect_teammate_pid" "$pid" \
      "teammate-mode process exists without a live swarm socket; active session status is uncertain" \
      "Inspect with ps -fp $pid and the owning terminal/session. Zhulong will not signal teammate PIDs; if the operator confirms it is stale, terminate it manually outside Zhulong."
  done
fi

recommended_mode="native_team_ready"
reason="native teams enabled and no stale OMC runtime residue"
resume_step="OMC native teams are available. Prefer /team before /ultrawork when parallelism is needed."

if (( ${#suspect_teammate_pids[@]} > 0 || ${#stale_sockets[@]} > 0 || ${#unresolved_review_only[@]} > 0 )); then
  recommended_mode="cleanup_needed"
  if (( ${#suspect_teammate_pids[@]} > 0 && ${#stale_sockets[@]} > 0 )); then
    reason="stale claude-swarm socket detected and teammate-mode processes need exact PID review"
  elif (( ${#suspect_teammate_pids[@]} > 0 )); then
    reason="teammate-mode processes detected without a live swarm socket; exact PID review required"
  elif (( ${#stale_sockets[@]} > 0 )); then
    reason="stale claude-swarm socket detected"
  else
    reason="runtime hygiene cleanup attempt remains unresolved review-only"
  fi
  resume_step="Before /team or /ultrawork, inspect suspect PIDs with ps -fp <pid> and the owning terminal/session. Zhulong will not signal teammate PIDs; if the operator confirms one is stale, terminate it manually outside Zhulong. Use --cleanup-stale only for stale sockets when no live socket is present."
elif (( ${#live_sockets[@]} > 0 )); then
  reason="active live claude-swarm session detected; do not cleanup current teammate workers"
  resume_step="Finish or cancel the active OMC team session before starting another multi-agent workflow."
elif [[ "$teams_enabled" != "1" ]]; then
  recommended_mode="single_agent_only"
  reason="CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS is not enabled"
  resume_step="Continue the audit single-agent; do not force /team, ulw, or OMC teammate mode."
fi

clean=0
if (( ${#suspect_teammate_pids[@]} == 0 && ${#stale_sockets[@]} == 0 && ${#unresolved_review_only[@]} == 0 )); then
  clean=1
fi

write_state_event \
  --event omc_runtime_checked \
  --stage environment_checking \
  --status running \
  --event-status "$recommended_mode" \
  --message "$reason" \
  --details-json "{\"runtime_hygiene_status\":\"runtime/runtime-hygiene-status.json\"}"

workspace="$(infer_workspace_dir 2>/dev/null || true)"
handoff_line=""
if [[ "$recommended_mode" == "cleanup_needed" ]]; then
  handoff_renderer="$(find_handoff_renderer)"
  if [[ -n "$workspace" && -n "$handoff_renderer" ]]; then
    handoff_line="$workspace/handoff-summary.md"
  elif [[ -n "$workspace" ]]; then
    handoff_line="Run: python3 $workspace/bin/render-handoff-summary.py --workspace-dir $workspace"
  fi
fi

emit_status "$workspace" "$recommended_mode" "$reason" "$teams_enabled" "$resume_step" "$handoff_line" "$clean"

if [[ "$recommended_mode" == "cleanup_needed" && -n "$workspace" && -n "${handoff_renderer:-}" ]]; then
  python3 "$handoff_renderer" --workspace-dir "$workspace" --repo-root "$(cd "$workspace/.." && pwd)" >/dev/null || true
fi

if [[ "$JSON_OUTPUT" != "1" ]]; then
  echo "recommended_mode=$recommended_mode"
  echo "reason=$reason"
  echo "handoff_summary=$handoff_line"
  echo "teams_enabled=$teams_enabled"
  echo "suspect_teammate_pids=${suspect_teammate_pids[*]:-}"
  echo "ignored_current_session_teammate_pids=${ignored_current_session_teammate_pids[*]:-}"
  echo "stale_swarm_sockets=${stale_sockets[*]:-}"
  echo "live_swarm_sockets=${live_sockets[*]:-}"
  echo "resume_step=$resume_step"
  echo "clean=$clean"
fi

exit "$cleanup_exit"
