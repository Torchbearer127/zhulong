#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/asr_start.sh --source <local-path|repo-url|owner/repo> [options]
  bash scripts/asr_start.sh --repo-root <repo-root> [options]

Purpose:
  One-shot entrypoint for the Zhulong workflow.
  It prepares or refreshes the workspace, performs safe runtime checks,
  runs tooling detection, and plans the repo-specific toolchain.

Options:
  --source VALUE              Local path, GitHub/GitLab/Gitee URL, or owner/repo
  --repo-root DIR             Existing repository root with or without prior audit workspaces
  --workspace-root DIR        Clone destination root when --source is remote
  --workspace-name NAME       Optional explicit audit workspace name
  --output-language LANG      zh-CN or en-US
  --summary-language LANG     zh-CN or en-US
  --ref REF                   Branch or tag for remote clone
  --force                     Recreate conflicting clone/workspace files when safe
  --skip-plan                 Skip toolchain planning
  --json                      Emit machine-readable summary at the end
  -h, --help                  Show help
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE=""
REPO_ROOT=""
WORKSPACE_ROOT="${PWD}"
WORKSPACE_NAME=""
OUTPUT_LANGUAGE=""
SUMMARY_LANGUAGE=""
REF=""
FORCE="0"
SKIP_PLAN="0"
JSON_OUTPUT="0"
docker_gate_status="unknown"
docker_gate_audit_log=""
docker_gate_message=""

run_with_optional_quiet() {
  if [[ "$JSON_OUTPUT" == "1" ]]; then
    "$@" >/dev/null
  else
    "$@"
  fi
}

read_latest_workspace_name() {
  local repo_root="$1"
  local marker="$repo_root/.asr-latest-workspace"
  if [[ -f "$marker" ]]; then
    tr -d '\n' < "$marker"
  fi
}

generate_workspace_name() {
  local repo_root="$1"
  local stamp base candidate suffix
  stamp="$(date '+%Y%m%d-%H%M%S')"
  base="security-research-$stamp"
  candidate="$base"
  suffix=1
  while [[ -e "$repo_root/$candidate" ]]; do
    candidate="${base}-${suffix}"
    suffix=$((suffix + 1))
  done
  printf '%s\n' "$candidate"
}

parse_runtime_json() {
  local json_input="$1"
  local parsed=""

  parsed="$(python3 - <<'PY' "$json_input"
import json
import sys

data = json.loads(sys.argv[1])
print(data.get("recommended_mode", ""))
print(data.get("reason", ""))
print("1" if data.get("teams_enabled") else "0")
print(",".join(data.get("orphan_teammate_pids", [])))
print(",".join(data.get("suspect_teammate_pids", [])))
print(",".join(data.get("ignored_current_session_teammate_pids", [])))
print(",".join(data.get("stale_swarm_sockets", [])))
print(",".join(data.get("live_swarm_sockets", [])))
PY
)"

  runtime_mode="$(printf '%s\n' "$parsed" | sed -n '1p')"
  runtime_reason="$(printf '%s\n' "$parsed" | sed -n '2p')"
  teams_enabled="$(printf '%s\n' "$parsed" | sed -n '3p')"
  orphan_pids="$(printf '%s\n' "$parsed" | sed -n '4p')"
  suspect_pids="$(printf '%s\n' "$parsed" | sed -n '5p')"
  ignored_current_session_pids="$(printf '%s\n' "$parsed" | sed -n '6p')"
  stale_sockets="$(printf '%s\n' "$parsed" | sed -n '7p')"
  live_sockets="$(printf '%s\n' "$parsed" | sed -n '8p')"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)
      SOURCE="${2:-}"
      shift 2
      ;;
    --repo-root)
      REPO_ROOT="${2:-}"
      shift 2
      ;;
    --workspace-root)
      WORKSPACE_ROOT="${2:-}"
      shift 2
      ;;
    --workspace-name)
      WORKSPACE_NAME="${2:-}"
      shift 2
      ;;
    --output-language)
      OUTPUT_LANGUAGE="${2:-}"
      shift 2
      ;;
    --summary-language)
      SUMMARY_LANGUAGE="${2:-}"
      shift 2
      ;;
    --ref)
      REF="${2:-}"
      shift 2
      ;;
    --force)
      FORCE="1"
      shift
      ;;
    --skip-plan)
      SKIP_PLAN="1"
      shift
      ;;
    --json)
      JSON_OUTPUT="1"
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

if [[ -z "$SOURCE" && -z "$REPO_ROOT" ]]; then
  echo "Either --source or --repo-root is required." >&2
  usage >&2
  exit 1
fi

if [[ -n "$SOURCE" && -n "$REPO_ROOT" ]]; then
  echo "Use either --source or --repo-root, not both." >&2
  exit 1
fi

resolve_repo_root_from_source() {
  local src="$1"
  local clone_root="$2"
  local basename=""

  if [[ -d "$src" ]]; then
    cd "$src" && pwd
    return
  fi

  if [[ "$src" =~ ^https://github\.com/([^/]+/[^/]+)/?$ ]]; then
    basename="$(basename "${BASH_REMATCH[1]}")"
  elif [[ "$src" =~ ^[^/[:space:]]+/[^/[:space:]]+$ ]]; then
    basename="$(basename "$src")"
  else
    basename="$(basename "$src")"
    basename="${basename%.git}"
  fi

  printf '%s/%s\n' "$clone_root" "$basename"
}

if [[ -n "$SOURCE" ]]; then
  PREPARE_ARGS=(--source "$SOURCE" --workspace-root "$WORKSPACE_ROOT")
  if [[ -n "$WORKSPACE_NAME" ]]; then
    PREPARE_ARGS+=(--workspace-name "$WORKSPACE_NAME")
  fi
  if [[ -n "$OUTPUT_LANGUAGE" ]]; then
    PREPARE_ARGS+=(--output-language "$OUTPUT_LANGUAGE")
  fi
  if [[ -n "$SUMMARY_LANGUAGE" ]]; then
    PREPARE_ARGS+=(--summary-language "$SUMMARY_LANGUAGE")
  fi
  if [[ -n "$REF" ]]; then
    PREPARE_ARGS+=(--ref "$REF")
  fi
  if [[ "$FORCE" == "1" ]]; then
    PREPARE_ARGS+=(--force)
  fi
  run_with_optional_quiet bash "$SCRIPT_DIR/prepare_target_repo.sh" "${PREPARE_ARGS[@]}"
  REPO_ROOT="$(resolve_repo_root_from_source "$SOURCE" "$WORKSPACE_ROOT")"
  if [[ -z "$WORKSPACE_NAME" ]]; then
    WORKSPACE_NAME="$(read_latest_workspace_name "$REPO_ROOT")"
  fi
else
  REPO_ROOT="${REPO_ROOT/#\~/$HOME}"
  REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"
  if [[ -z "$WORKSPACE_NAME" ]]; then
    WORKSPACE_NAME="$(read_latest_workspace_name "$REPO_ROOT")"
  fi
  if [[ -z "$WORKSPACE_NAME" ]]; then
    WORKSPACE_NAME="$(generate_workspace_name "$REPO_ROOT")"
  fi
  if [[ ! -d "$REPO_ROOT/$WORKSPACE_NAME" ]]; then
    BOOTSTRAP_ARGS=(--target-dir "$REPO_ROOT" --workspace-name "$WORKSPACE_NAME")
    if [[ -n "$OUTPUT_LANGUAGE" ]]; then
      BOOTSTRAP_ARGS+=(--output-language "$OUTPUT_LANGUAGE")
    fi
    if [[ -n "$SUMMARY_LANGUAGE" ]]; then
      BOOTSTRAP_ARGS+=(--summary-language "$SUMMARY_LANGUAGE")
    fi
    if [[ "$FORCE" == "1" ]]; then
      BOOTSTRAP_ARGS+=(--force)
    fi
    run_with_optional_quiet bash "$SCRIPT_DIR/bootstrap_verification_workspace.sh" "${BOOTSTRAP_ARGS[@]}"
  fi
fi

WORKSPACE_DIR="$REPO_ROOT/$WORKSPACE_NAME"
run_with_optional_quiet bash "$SCRIPT_DIR/refresh_workspace_helpers.sh" --workspace "$WORKSPACE_DIR"

docker_gate_output="$(bash "$WORKSPACE_DIR/bin/check-docker-gate.sh" --repo-root "$REPO_ROOT" --note "startup pre-verification advisory" 2>&1 || true)"
docker_gate_status="$(printf '%s\n' "$docker_gate_output" | awk -F= '/^docker_gate=/{print $2; exit}')"
docker_gate_audit_log="$(printf '%s\n' "$docker_gate_output" | awk -F= '/^audit_log=/{print $2; exit}')"
docker_gate_message="$(printf '%s\n' "$docker_gate_output" | sed -n 's/^message=//p' | head -n 1)"
if [[ -z "$docker_gate_status" ]]; then
  docker_gate_status="unknown"
fi

runtime_json="$(bash "$WORKSPACE_DIR/bin/check_omc_runtime.sh" --json)"
parse_runtime_json "$runtime_json"

cleanup_performed="0"

tooling_output="$(bash "$WORKSPACE_DIR/bin/check_security_tooling.sh")"

plan_output=""
if [[ "$SKIP_PLAN" != "1" ]]; then
  plan_output="$(python3 "$WORKSPACE_DIR/bin/plan-security-toolchain.py" --target-dir "$REPO_ROOT" --workspace-dir "$WORKSPACE_DIR")"
fi

if [[ "$JSON_OUTPUT" == "1" ]]; then
  python3 - <<'PY' \
    "$REPO_ROOT" \
    "$WORKSPACE_DIR" \
    "$runtime_mode" \
    "$runtime_reason" \
    "$teams_enabled" \
    "$cleanup_performed" \
    "$orphan_pids" \
    "$suspect_pids" \
    "$ignored_current_session_pids" \
    "$stale_sockets" \
    "$live_sockets" \
    "$docker_gate_status" \
    "$docker_gate_audit_log" \
    "$docker_gate_message" \
    "$tooling_output" \
    "$plan_output"
import json
import sys

repo_root, workspace_dir, runtime_mode, runtime_reason, teams_enabled, cleanup_performed, orphan_pids, suspect_pids, ignored_current_session_pids, stale_sockets, live_sockets, docker_gate_status, docker_gate_audit_log, docker_gate_message, tooling_output, plan_output = sys.argv[1:17]

print(json.dumps({
    "repo_root": repo_root,
    "workspace_dir": workspace_dir,
    "docker_gate": {
        "status": docker_gate_status,
        "audit_log": docker_gate_audit_log,
        "message": docker_gate_message,
    },
    "runtime": {
        "mode": runtime_mode,
        "reason": runtime_reason,
        "teams_enabled": teams_enabled == "1",
        "cleanup_performed": cleanup_performed == "1",
        "orphan_teammate_pids": [x for x in orphan_pids.split(",") if x],
        "suspect_teammate_pids": [x for x in suspect_pids.split(",") if x],
        "ignored_current_session_teammate_pids": [x for x in ignored_current_session_pids.split(",") if x],
        "stale_swarm_sockets": [x for x in stale_sockets.split(",") if x],
        "live_swarm_sockets": [x for x in live_sockets.split(",") if x],
    },
    "tooling_output": tooling_output,
    "plan_output": plan_output,
}, ensure_ascii=False, indent=2))
PY
  exit 0
fi

cat <<EOF
Zhulong workspace ready.

Repository root:
  $REPO_ROOT
Workspace:
  $WORKSPACE_DIR

Runtime status:
  mode=$runtime_mode
  reason=$runtime_reason
  teams_enabled=$teams_enabled
  cleanup_performed=$cleanup_performed
Docker gate:
  status=$docker_gate_status
EOF

if [[ -n "$ignored_current_session_pids" ]]; then
  cat <<EOF
Current-session teammate PIDs ignored automatically:
  $ignored_current_session_pids
These belong to the current Claude session and must not be terminated as stale residue.
EOF
fi

if [[ "$runtime_mode" == "cleanup_needed" ]]; then
  cat <<EOF

============================================================
OMC Runtime Attention Needed
============================================================
The audit startup did not auto-clean teammate-mode sessions.
Reason:
  $runtime_reason
EOF
  if [[ -n "$suspect_pids" ]]; then
    cat <<EOF
Suspect teammate-mode PIDs:
  $suspect_pids
EOF
  fi
  if [[ -n "$stale_sockets" ]]; then
    cat <<EOF
Stale swarm sockets:
  $stale_sockets
EOF
  fi
  cat <<EOF
Automatic cleanup is disabled to avoid killing unrelated Claude Code sessions.
If you are sure these are stale, inspect them first and then run manually:
  bash $WORKSPACE_DIR/bin/check_omc_runtime.sh --cleanup-stale
If teammate-mode processes still need termination after inspection, do it manually.
============================================================
EOF
fi

if [[ -n "$docker_gate_audit_log" ]]; then
  cat <<EOF
  audit_log=$docker_gate_audit_log
EOF
fi

if [[ -n "$docker_gate_message" ]]; then
  cat <<EOF
  message=$docker_gate_message
EOF
fi

if [[ "$docker_gate_status" == "blocked" ]]; then
  cat <<EOF

============================================================
Verification Paused By Docker Gate
============================================================
The audit did not crash. It paused because Docker is unavailable.
Do not switch to host-local verification.
Review the audit log:
  ${docker_gate_audit_log:-$WORKSPACE_DIR/audit-log.md}
Fix Docker/OrbStack first, then resume from the same repo workspace.
============================================================
EOF
fi

cat <<EOF

Tooling summary:
$tooling_output
EOF

if [[ -n "$plan_output" ]]; then
  cat <<EOF

Toolchain plan:
$plan_output
EOF
fi

cat <<'EOF'

Next:
  1. In Claude Code, invoke the `zhulong` skill directly.
  2. If this target is on GitHub, prefer `gh` for advisories, issues, pull requests, commits, releases, and patch-history lookup.
  3. If runtime mode is `native_team_ready`, prefer `/team` first.
  4. If runtime mode is `single_agent_only`, continue in single-agent mode.
  5. Before any PoC or exploit verification, check the Docker gate summary above.
  6. If `docker_gate=blocked`, do not verify on the host. Fix Docker, inspect $WORKSPACE_DIR/audit-log.md, and then resume from the same repo workspace.
  7. Run PoCs only inside Docker or Docker Compose.
EOF
