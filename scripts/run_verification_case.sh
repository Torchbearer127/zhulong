#!/usr/bin/env bash

set -euo pipefail

STABLE_LABELS="blocked_docker_unavailable blocked_missing_image failed_timeout failed_resource_limit rejected_not_reproducible confirmed_in_docker"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/run_verification_case.sh \
    --workspace-dir <audit-workspace> \
    --case-id <case-id> \
    --mode docker-run \
    --image <local-or-cached-image> \
    --timeout-seconds 300 \
    --expected-oracle <token-or-regex> \
    --network none|bridge|host|<docker-network> \
    -- <container command...>

  bash scripts/run_verification_case.sh \
    --workspace-dir <audit-workspace> \
    --case-id <case-id> \
    --mode docker-compose \
    --compose-file <compose.yml> \
    --compose-service <service> \
    --timeout-seconds 300 \
    --expected-oracle <token-or-regex> \
    -- <service command...>

Purpose:
  Run one Docker-only verification case with a mandatory timeout, explicit
  network setting, conservative docker-run resource limits, and structured
  evidence under <audit-workspace>/evidence/<case-id>/.
  In docker-compose mode, resource limits are managed by the Compose files;
  docker-run defaults are not reported as effective limits.

Stable outcome labels:
  blocked_docker_unavailable
  blocked_missing_image
  failed_timeout
  failed_resource_limit
  rejected_not_reproducible
  confirmed_in_docker

Safety contract:
  This helper never executes PoC logic directly on the host. It may invoke
  Docker or Docker Compose from the host only as the container boundary. If
  Docker is unavailable, verification is blocked and no host fallback is
  provided.

Common options:
  --workspace-dir DIR        Required audit workspace.
  --case-id ID               Required stable case identifier.
  --mode MODE                docker-run or docker-compose.
  --timeout-seconds N        Required positive timeout; cannot be disabled.
  --expected-oracle REGEX    Required for confirmation unless
                             --allow-exit-zero-oracle is set.
  --evidence-dir DIR         Default: <workspace>/evidence/<case-id>.
  --network NAME             docker-run network. Default: none.
  --pull-if-missing          Pull only when the image is missing locally.

docker-run options:
  --image IMAGE              Required image name or ID.
  --memory LIMIT             Default: 512m.
  --cpus LIMIT               Default: 1.
  --pids-limit N             Default: 256.
  --no-read-only             Disable read-only root filesystem when required.
  --docker-arg ARG           Extra docker run argument. Repeat as needed.
  --no-default-mounts        Do not mount workspace poc/ and evidence dirs.

docker-compose options:
  --compose-file FILE        Compose file. Repeat as needed.
  --compose-service SERVICE  Service used for verification.

Timeout rule:
  On failed_timeout, re-analyze the PoC for service readiness, waiting
  conditions, network blocking, infinite loops, or interactive prompts before
  retrying.
EOF
}

WORKSPACE_DIR=""
CASE_ID=""
MODE=""
IMAGE=""
TIMEOUT_SECONDS=""
EXPECTED_ORACLE=""
ALLOW_EXIT_ZERO_ORACLE="0"
EVIDENCE_DIR=""
NETWORK="none"
PULL_IF_MISSING="0"
MEMORY_LIMIT="512m"
CPU_LIMIT="1"
PIDS_LIMIT="256"
READ_ONLY="1"
DEFAULT_MOUNTS="1"
COMPOSE_SERVICE=""
COMPOSE_FILES=()
EXTRA_DOCKER_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace-dir)
      WORKSPACE_DIR="${2:-}"
      shift 2
      ;;
    --case-id)
      CASE_ID="${2:-}"
      shift 2
      ;;
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --image)
      IMAGE="${2:-}"
      shift 2
      ;;
    --timeout-seconds)
      TIMEOUT_SECONDS="${2:-}"
      shift 2
      ;;
    --expected-oracle)
      EXPECTED_ORACLE="${2:-}"
      shift 2
      ;;
    --allow-exit-zero-oracle)
      ALLOW_EXIT_ZERO_ORACLE="1"
      shift
      ;;
    --evidence-dir)
      EVIDENCE_DIR="${2:-}"
      shift 2
      ;;
    --network)
      NETWORK="${2:-}"
      shift 2
      ;;
    --pull-if-missing)
      PULL_IF_MISSING="1"
      shift
      ;;
    --memory)
      MEMORY_LIMIT="${2:-}"
      shift 2
      ;;
    --cpus)
      CPU_LIMIT="${2:-}"
      shift 2
      ;;
    --pids-limit)
      PIDS_LIMIT="${2:-}"
      shift 2
      ;;
    --no-read-only)
      READ_ONLY="0"
      shift
      ;;
    --docker-arg)
      EXTRA_DOCKER_ARGS+=("${2:-}")
      shift 2
      ;;
    --no-default-mounts)
      DEFAULT_MOUNTS="0"
      shift
      ;;
    --compose-file)
      COMPOSE_FILES+=("${2:-}")
      shift 2
      ;;
    --compose-service)
      COMPOSE_SERVICE="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

CASE_COMMAND=("$@")

fail_usage() {
  echo "ERROR: $1" >&2
  usage >&2
  exit 2
}

[[ -n "$WORKSPACE_DIR" ]] || fail_usage "--workspace-dir is required."
[[ -n "$CASE_ID" ]] || fail_usage "--case-id is required."
[[ -n "$MODE" ]] || fail_usage "--mode is required."
[[ -n "$TIMEOUT_SECONDS" ]] || fail_usage "--timeout-seconds is required and must be positive."
[[ "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] || fail_usage "--timeout-seconds must be a positive integer."
if [[ -z "$EXPECTED_ORACLE" && "$ALLOW_EXIT_ZERO_ORACLE" != "1" ]]; then
  fail_usage "--expected-oracle is required unless --allow-exit-zero-oracle is set."
fi

WORKSPACE_DIR="${WORKSPACE_DIR/#\~/$HOME}"
WORKSPACE_DIR="$(cd "$WORKSPACE_DIR" && pwd)"
if [[ ! -f "$WORKSPACE_DIR/asr-config.json" ]]; then
  echo "ERROR: not a Zhulong audit workspace: $WORKSPACE_DIR" >&2
  exit 2
fi

SAFE_CASE_ID="$(printf '%s' "$CASE_ID" | tr -c 'A-Za-z0-9_.-' '-')"
if [[ "$SAFE_CASE_ID" != "$CASE_ID" ]]; then
  echo "ERROR: --case-id may only contain letters, numbers, dot, underscore, and dash." >&2
  exit 2
fi

if [[ -z "$EVIDENCE_DIR" ]]; then
  EVIDENCE_DIR="$WORKSPACE_DIR/evidence/$CASE_ID"
else
  EVIDENCE_DIR="${EVIDENCE_DIR/#\~/$HOME}"
fi
mkdir -p "$EVIDENCE_DIR"
EVIDENCE_DIR="$(cd "$EVIDENCE_DIR" && pwd)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_LABEL="$(basename "$WORKSPACE_DIR")"

find_state_writer() {
  if [[ -f "$SCRIPT_DIR/write_audit_event.py" ]]; then
    printf '%s\n' "$SCRIPT_DIR/write_audit_event.py"
    return
  fi
  if [[ -f "$SCRIPT_DIR/write-audit-event.py" ]]; then
    printf '%s\n' "$SCRIPT_DIR/write-audit-event.py"
    return
  fi
  if [[ -f "$SCRIPT_DIR/../bin/write-audit-event.py" ]]; then
    printf '%s\n' "$SCRIPT_DIR/../bin/write-audit-event.py"
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

write_audit_log_block() {
  local status="$1"
  local message="$2"
  local timestamp
  timestamp="$(date '+%Y-%m-%d %H:%M:%S %z')"
  {
    echo ""
    echo "## $timestamp"
    echo ""
    echo "- verification_case: $CASE_ID"
    echo "- status: $status"
    echo "- message: $message"
    echo "- evidence_dir: $EVIDENCE_DIR"
  } >>"$WORKSPACE_DIR/audit-log.md"
}

emit_result_json() {
  local status="$1"
  local reason="$2"
  local exit_code="$3"
  local oracle_matched="$4"
  shift 4
  python3 - "$WORKSPACE_DIR" "$EVIDENCE_DIR" "$CASE_ID" "$MODE" "$status" "$reason" "$exit_code" "$oracle_matched" "$TIMEOUT_SECONDS" "$EXPECTED_ORACLE" "$IMAGE" "$NETWORK" "$MEMORY_LIMIT" "$CPU_LIMIT" "$PIDS_LIMIT" "$READ_ONLY" "$PULL_IF_MISSING" "$STDOUT_PATH" "$STDERR_PATH" "$COMMAND_JSON_PATH" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

(
workspace,
evidence_dir,
    case_id,
    mode,
    status,
    reason,
    exit_code,
    oracle_matched,
    timeout_seconds,
    expected_oracle,
    image,
    network,
    memory_limit,
    cpu_limit,
    pids_limit,
    read_only,
    pull_if_missing,
    stdout_path,
    stderr_path,
    command_json_path,
) = sys.argv[1:21]
workspace_path = Path(workspace).resolve()
evidence_path = Path(evidence_dir).resolve()

def workspace_rel(value: str) -> str:
    path = Path(value).resolve()
    try:
        return path.relative_to(workspace_path).as_posix()
    except ValueError:
        return path.name

command = json.loads(Path(command_json_path).read_text(encoding="utf-8"))
data = {
    "schema_version": 1,
    "case_id": case_id,
    "mode": mode,
    "status": status,
    "classification_reason": reason,
    "exit_code": None if exit_code == "" else int(exit_code),
    "oracle_matched": oracle_matched == "true",
    "expected_oracle": expected_oracle,
    "timeout_seconds": int(timeout_seconds),
    "workspace_dir": workspace_path.name,
    "evidence_dir": workspace_rel(str(evidence_path)),
    "stdout_path": workspace_rel(stdout_path),
    "stderr_path": workspace_rel(stderr_path),
    "command": command,
    "docker_boundary_only": True,
    "host_poc_execution_allowed": False,
    "image": image,
    "image_policy": "prefer_local_or_cached_image; pull_only_when_explicitly_requested_with_pull_if_missing",
    "network": network,
    "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
}
if mode == "docker-compose":
    data["resource_limits"] = {
        "managed_by_compose_file": True,
        "docker_run_defaults_applied": False,
        "note": "Docker Compose mode uses limits from the compose files; docker-run defaults are not applied.",
    }
else:
    data["resource_limits"] = {
        "memory": memory_limit,
        "cpus": cpu_limit,
        "pids_limit": pids_limit,
        "read_only_rootfs": read_only == "1",
    }
Path(evidence_dir, "verification-result.json").write_text(
    json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}

classify_and_exit() {
  local status="$1"
  local reason="$2"
  local exit_code="${3:-}"
  local oracle_matched="${4:-false}"
  emit_result_json "$status" "$reason" "$exit_code" "$oracle_matched"

  case "$status" in
    confirmed_in_docker)
      write_state_event \
        --workspace-dir "$WORKSPACE_DIR" \
        --target-repo "$(cd "$WORKSPACE_DIR/.." && pwd)" \
        --event verification_case_completed \
        --stage candidate_verifying \
        --status running \
        --event-status "$status" \
        --message "Verification case confirmed in Docker." \
        --detail "case_id=$CASE_ID" \
        --detail "evidence_dir=$EVIDENCE_DIR"
      ;;
    blocked_docker_unavailable|blocked_missing_image|failed_timeout|failed_resource_limit)
      write_state_event \
        --workspace-dir "$WORKSPACE_DIR" \
        --target-repo "$(cd "$WORKSPACE_DIR/.." && pwd)" \
        --event verification_case_blocked \
        --stage candidate_verifying \
        --status paused \
        --event-status "$status" \
        --message "Verification case paused: $status." \
        --blocker "$reason" \
        --resume-step "Review $EVIDENCE_DIR/verification-result.json and retry only inside Docker after fixing the blocker." \
        --detail "case_id=$CASE_ID" \
        --detail "evidence_dir=$EVIDENCE_DIR"
      write_audit_log_block "$status" "$reason"
      ;;
    rejected_not_reproducible)
      write_state_event \
        --workspace-dir "$WORKSPACE_DIR" \
        --target-repo "$(cd "$WORKSPACE_DIR/.." && pwd)" \
        --event verification_case_rejected \
        --stage candidate_verifying \
        --status running \
        --event-status "$status" \
        --message "Verification case did not reproduce in Docker." \
        --detail "case_id=$CASE_ID" \
        --detail "evidence_dir=$EVIDENCE_DIR"
      ;;
  esac

  echo "verification_status=$status"
  echo "evidence_dir=$EVIDENCE_DIR"
  echo "result_json=$EVIDENCE_DIR/verification-result.json"

  if [[ "$status" == "confirmed_in_docker" ]]; then
    exit 0
  fi
  exit 1
}

STDOUT_PATH="$EVIDENCE_DIR/stdout.log"
STDERR_PATH="$EVIDENCE_DIR/stderr.log"
COMMAND_JSON_PATH="$EVIDENCE_DIR/command.json"
: >"$STDOUT_PATH"
: >"$STDERR_PATH"

if ! docker info >/dev/null 2>&1; then
  printf 'Docker unavailable. This helper will not execute PoC logic on the host.\n' >"$STDERR_PATH"
  printf '[]\n' >"$COMMAND_JSON_PATH"
  classify_and_exit "blocked_docker_unavailable" "Docker daemon or socket is unavailable; no host fallback is provided."
fi

RUN_COMMAND=()
case "$MODE" in
  docker-run)
    [[ -n "$IMAGE" ]] || fail_usage "--image is required for docker-run mode."
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
      if [[ "$PULL_IF_MISSING" == "1" ]]; then
        if ! docker pull "$IMAGE" >"$EVIDENCE_DIR/image-pull.log" 2>&1; then
          printf 'Image pull failed for %s\n' "$IMAGE" >>"$STDERR_PATH"
          printf '[]\n' >"$COMMAND_JSON_PATH"
          classify_and_exit "blocked_missing_image" "Required image is missing locally and explicit pull failed."
        fi
      else
        printf 'Image is missing locally: %s\n' "$IMAGE" >>"$STDERR_PATH"
        printf '[]\n' >"$COMMAND_JSON_PATH"
        classify_and_exit "blocked_missing_image" "Required image is missing locally; rerun with --pull-if-missing only if network pull is acceptable."
      fi
    fi
    RUN_COMMAND=(
      docker run --rm
      --name "zhulong-${SAFE_CASE_ID}-$$"
      --label "org.zhulong.managed=true"
      --label "org.zhulong.workspace=$WORKSPACE_LABEL"
      --memory "$MEMORY_LIMIT"
      --cpus "$CPU_LIMIT"
      --pids-limit "$PIDS_LIMIT"
      --cap-drop ALL
      --security-opt no-new-privileges
      --network "$NETWORK"
    )
    if [[ "$READ_ONLY" == "1" ]]; then
      RUN_COMMAND+=(--read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m)
    fi
    if [[ "$DEFAULT_MOUNTS" == "1" ]]; then
      mkdir -p "$WORKSPACE_DIR/poc"
      RUN_COMMAND+=(
        --mount "type=bind,source=$WORKSPACE_DIR/poc,target=/workspace/poc,readonly"
        --mount "type=bind,source=$EVIDENCE_DIR,target=/workspace/evidence"
        --workdir /workspace/poc
      )
    fi
    if [[ "${#EXTRA_DOCKER_ARGS[@]}" -gt 0 ]]; then
      RUN_COMMAND+=("${EXTRA_DOCKER_ARGS[@]}")
    fi
    RUN_COMMAND+=("$IMAGE")
    if [[ "${#CASE_COMMAND[@]}" -gt 0 ]]; then
      RUN_COMMAND+=("${CASE_COMMAND[@]}")
    fi
    ;;
  docker-compose)
    [[ -n "$COMPOSE_SERVICE" ]] || fail_usage "--compose-service is required for docker-compose mode."
    [[ "${#COMPOSE_FILES[@]}" -gt 0 ]] || fail_usage "--compose-file is required for docker-compose mode."
    COMPOSE_ARGS=()
    for compose_file in "${COMPOSE_FILES[@]}"; do
      COMPOSE_ARGS+=(-f "$compose_file")
    done
    missing_images=()
    while IFS= read -r compose_image; do
      [[ -n "$compose_image" ]] || continue
      if ! docker image inspect "$compose_image" >/dev/null 2>&1; then
        missing_images+=("$compose_image")
      fi
    done < <(docker compose "${COMPOSE_ARGS[@]}" config --images 2>/dev/null || true)
    if [[ "${#missing_images[@]}" -gt 0 ]]; then
      if [[ "$PULL_IF_MISSING" == "1" ]]; then
        if ! docker compose "${COMPOSE_ARGS[@]}" pull "$COMPOSE_SERVICE" >"$EVIDENCE_DIR/image-pull.log" 2>&1; then
          printf 'Compose image pull failed for service %s\n' "$COMPOSE_SERVICE" >>"$STDERR_PATH"
          printf '[]\n' >"$COMMAND_JSON_PATH"
          classify_and_exit "blocked_missing_image" "One or more compose images are missing locally and explicit pull failed."
        fi
      else
        printf 'Compose images missing locally: %s\n' "${missing_images[*]}" >>"$STDERR_PATH"
        printf '[]\n' >"$COMMAND_JSON_PATH"
        classify_and_exit "blocked_missing_image" "One or more compose images are missing locally; rerun with --pull-if-missing only if network pull is acceptable."
      fi
    fi
    RUN_COMMAND=(docker compose "${COMPOSE_ARGS[@]}" run --rm -T "$COMPOSE_SERVICE")
    if [[ "${#CASE_COMMAND[@]}" -gt 0 ]]; then
      RUN_COMMAND+=("${CASE_COMMAND[@]}")
    fi
    ;;
  *)
    fail_usage "--mode must be docker-run or docker-compose."
    ;;
esac

python3 - "$COMMAND_JSON_PATH" "$WORKSPACE_DIR" "$EVIDENCE_DIR" "${RUN_COMMAND[@]}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
workspace = sys.argv[2]
evidence_dir = sys.argv[3]

def scrub(value: str) -> str:
    return value.replace(evidence_dir, "<evidence-dir>").replace(workspace, "<audit-workspace>")

path.write_text(json.dumps([scrub(arg) for arg in sys.argv[4:]], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

set +e
python3 - "$TIMEOUT_SECONDS" "$STDOUT_PATH" "$STDERR_PATH" "${RUN_COMMAND[@]}" <<'PY'
import subprocess
import sys
from pathlib import Path

timeout = int(sys.argv[1])
stdout_path = Path(sys.argv[2])
stderr_path = Path(sys.argv[3])
command = sys.argv[4:]

with stdout_path.open("ab") as stdout, stderr_path.open("ab") as stderr:
    try:
        proc = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        try:
            proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            sys.exit(124)
        sys.exit(proc.returncode)
    except FileNotFoundError as exc:
        stderr.write((str(exc) + "\n").encode("utf-8", errors="replace"))
        sys.exit(127)
PY
RUN_EXIT=$?
set -e

if [[ "$RUN_EXIT" -eq 124 ]]; then
  classify_and_exit "failed_timeout" "Verification command timed out. Re-analyze service readiness, waiting conditions, network blocking, loops, or interactive prompts before retrying." "$RUN_EXIT" "false"
fi

combined_output="$(cat "$STDOUT_PATH" "$STDERR_PATH" 2>/dev/null || true)"
if [[ "$RUN_EXIT" -eq 137 ]] || printf '%s\n' "$combined_output" | grep -Eiq 'out of memory|oom|memory limit|pids limit|cannot allocate memory|resource temporarily unavailable'; then
  classify_and_exit "failed_resource_limit" "Verification command appears to have hit memory, CPU, pids, or related container resource limits." "$RUN_EXIT" "false"
fi

oracle_matched="false"
if [[ -n "$EXPECTED_ORACLE" ]]; then
  if python3 - "$EXPECTED_ORACLE" "$STDOUT_PATH" "$STDERR_PATH" <<'PY'
import re
import sys
from pathlib import Path

pattern = sys.argv[1]
text = "\n".join(Path(path).read_text(encoding="utf-8", errors="ignore") for path in sys.argv[2:])
raise SystemExit(0 if re.search(pattern, text, flags=re.MULTILINE) else 1)
PY
  then
    oracle_matched="true"
  fi
fi

if [[ "$RUN_EXIT" -eq 0 ]]; then
  if [[ -n "$EXPECTED_ORACLE" && "$oracle_matched" == "true" ]]; then
    classify_and_exit "confirmed_in_docker" "Command exited zero and expected oracle matched Docker-collected output." "$RUN_EXIT" "$oracle_matched"
  fi
  if [[ -z "$EXPECTED_ORACLE" && "$ALLOW_EXIT_ZERO_ORACLE" == "1" ]]; then
    classify_and_exit "confirmed_in_docker" "Command exited zero and exit-zero oracle was explicitly allowed." "$RUN_EXIT" "true"
  fi
  classify_and_exit "rejected_not_reproducible" "Command exited zero but the expected oracle was not observed." "$RUN_EXIT" "$oracle_matched"
fi

classify_and_exit "rejected_not_reproducible" "Command failed or did not produce the expected oracle in Docker." "$RUN_EXIT" "$oracle_matched"
