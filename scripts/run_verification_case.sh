#!/usr/bin/env bash
# zhulong-tool-contract: docker-verification-v1; timeout=mandatory; sandbox-preflight=mandatory

set -euo pipefail

STABLE_LABELS="blocked_state_precondition blocked_authority_event_commit blocked_docker_unavailable blocked_missing_image failed_timeout failed_resource_limit rejected_unsafe_sandbox rejected_not_reproducible confirmed_in_docker"

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
    --network none|bridge|<docker-network> \
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
  rejected_unsafe_sandbox
  rejected_not_reproducible
  confirmed_in_docker
  blocked_state_precondition
  blocked_authority_event_commit

Safety contract:
  This helper never executes PoC logic directly on the host. It may invoke
  Docker or Docker Compose from the host only as the container boundary. If
  Docker is unavailable, verification is blocked and no host fallback is
  provided.
  R2 workspaces must already be in verification/running or
  verification/blocked. The wrapper never advances triage or another workflow
  stage. It commits a same-stage start event before the PoC container command.

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

if [[ ! "$CASE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ || "$CASE_ID" == "." || "$CASE_ID" == ".." ]]; then
  fail_usage "--case-id must start with a letter or number and contain only letters, numbers, dot, underscore, and dash."
fi

case "$MODE" in
  docker-run)
    [[ -n "$IMAGE" ]] || fail_usage "--image is required for docker-run mode."
    ;;
  docker-compose)
    [[ -n "$COMPOSE_SERVICE" ]] || fail_usage "--compose-service is required for docker-compose mode."
    [[ "${#COMPOSE_FILES[@]}" -gt 0 ]] || fail_usage "--compose-file is required for docker-compose mode."
    for compose_file in "${COMPOSE_FILES[@]}"; do
      [[ -n "$compose_file" && -f "$compose_file" && ! -L "$compose_file" ]] || fail_usage "--compose-file must reference an existing regular file."
    done
    ;;
  *)
    fail_usage "--mode must be docker-run or docker-compose."
    ;;
esac

SAFE_CASE_ID="$CASE_ID"

WORKSPACE_DIR="${WORKSPACE_DIR/#\~/$HOME}"
WORKSPACE_DIR="$(cd "$WORKSPACE_DIR" && pwd -P)"
if [[ ! -f "$WORKSPACE_DIR/asr-config.json" ]]; then
  echo "ERROR: not a Zhulong audit workspace: $WORKSPACE_DIR" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
validate_declared_verification_use() {
  local contract_root registry schema validator
  if [[ -f "$SCRIPT_DIR/tool-registry.json" ]]; then
    contract_root="$(cd "$SCRIPT_DIR/.." && pwd)"
    registry="$SCRIPT_DIR/tool-registry.json"
    schema="$SCRIPT_DIR/tool-registry.schema.json"
    validator="$SCRIPT_DIR/validate_tool_registry.py"
  else
    contract_root="$(cd "$SCRIPT_DIR/.." && pwd)"
    registry="$contract_root/assets/tool-registry.json"
    schema="$contract_root/assets/schemas/tool-registry.schema.json"
    validator="$contract_root/scripts/validate_tool_registry.py"
  fi
  if [[ ! -f "$validator" || ! -f "$registry" || ! -f "$schema" ]]; then
    echo "ERROR: Tool Registry R2 contract files are missing; refusing Docker verification." >&2
    exit 2
  fi
  if ! python3 "$validator" \
    --skill-root "$contract_root" \
    --registry "$registry" \
    --schema "$schema" \
    --tool docker-verification-wrapper \
    --stage verification \
    --boundary docker_exec \
    --effect target_code_execute \
    --json >/dev/null; then
    echo "ERROR: Tool Registry R2 declared-use validation failed; refusing Docker verification." >&2
    exit 2
  fi
}

CASE_EVIDENCE_REF="evidence/$SAFE_CASE_ID/verification-result.json"
COMMAND_EVIDENCE_REF="evidence/$SAFE_CASE_ID/command.json"
RESUME_CONTEXT_REF="evidence/$SAFE_CASE_ID/resume-context.json"

if [[ -z "$EVIDENCE_DIR" ]]; then
  EVIDENCE_DIR="$WORKSPACE_DIR/evidence/$CASE_ID"
else
  EVIDENCE_DIR="${EVIDENCE_DIR/#\~/$HOME}"
fi
EXPECTED_EVIDENCE_DIR="$WORKSPACE_DIR/evidence/$CASE_ID"
if ! python3 - "$WORKSPACE_DIR" "$CASE_ID" "$EVIDENCE_DIR" "$EXPECTED_EVIDENCE_DIR" <<'PY'
import os
import stat
import sys
from pathlib import Path

workspace = Path(sys.argv[1])
case_id = sys.argv[2]
supplied = Path(sys.argv[3])
expected = Path(sys.argv[4])
workspace = workspace.resolve()
expected = workspace / "evidence" / case_id
raw = supplied if supplied.is_absolute() else Path.cwd() / supplied
if "\\" in str(supplied) or any(part in {".", ".."} for part in supplied.parts):
    raise SystemExit("evidence directory must not contain dot or parent path components")
normalized = raw.resolve(strict=False)
if normalized != expected.resolve(strict=False):
    raise SystemExit("evidence directory must normalize exactly to workspace/evidence/case-id")

current = workspace
parts = (Path("evidence") / case_id).parts
for part in parts:
    current = current / part
    try:
        info = os.lstat(current)
    except FileNotFoundError:
        continue
    if stat.S_ISLNK(info.st_mode):
        raise SystemExit("evidence directory or an ancestor must not be a symlink")
    if current != expected and not stat.S_ISDIR(info.st_mode):
        raise SystemExit("evidence directory ancestor must be a real directory")
PY
then
  echo "ERROR: --evidence-dir must normalize exactly to <workspace>/evidence/<case-id> and must not traverse symlinks." >&2
  exit 2
fi
validate_declared_verification_use
EVIDENCE_DIR="$EXPECTED_EVIDENCE_DIR"
CONTAINER_OUTPUT_DIR="$EVIDENCE_DIR/container-output"

WORKSPACE_LABEL="$(basename "$WORKSPACE_DIR")"
AUTHORITY_MODE="no_state"
R2_STATE_REVISION=""
DOCKER_CLI_INVOKED="false"
POC_COMMAND_INVOKED="false"
WRAPPER_STATUS=""
AUTHORITY_EVENT_COMMITTED=""
AUTHORITY_EVENT_ERROR_CODE=""
CONTROL_EVIDENCE_UNSAFE="false"
CAPTURE_RESULT='{}'

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

find_sandbox_preflight() {
  if [[ -f "$SCRIPT_DIR/check_sandbox_preflight.py" ]]; then
    printf '%s\n' "$SCRIPT_DIR/check_sandbox_preflight.py"
    return
  fi
  if [[ -f "$SCRIPT_DIR/check-sandbox-preflight.py" ]]; then
    printf '%s\n' "$SCRIPT_DIR/check-sandbox-preflight.py"
    return
  fi
  if [[ -f "$SCRIPT_DIR/../bin/check-sandbox-preflight.py" ]]; then
    printf '%s\n' "$SCRIPT_DIR/../bin/check-sandbox-preflight.py"
    return
  fi
}

SANDBOX_PREFLIGHT_PAYLOAD=""
early_sandbox_preflight() {
  local preflight preflight_exit
  preflight="$(find_sandbox_preflight)"
  if [[ -z "$preflight" ]]; then
    echo "ERROR: Sandbox preflight helper is missing; no evidence or authority file was created." >&2
    exit 1
  fi
  local -a preflight_args
  preflight_args=(
    --workspace-dir "$WORKSPACE_DIR"
    --case-id "$CASE_ID"
    --mode "$MODE"
    --json
  )
  if [[ "$MODE" == "docker-run" ]]; then
    preflight_args+=(--network "$NETWORK")
    if [[ "${#EXTRA_DOCKER_ARGS[@]}" -gt 0 ]]; then
      for arg in "${EXTRA_DOCKER_ARGS[@]}"; do
        preflight_args+=("--docker-run-arg=$arg")
      done
    fi
  else
    for compose_file in "${COMPOSE_FILES[@]}"; do
      preflight_args+=(--compose-file "$compose_file")
    done
  fi
  set +e
  SANDBOX_PREFLIGHT_PAYLOAD="$(python3 "$preflight" "${preflight_args[@]}")"
  preflight_exit=$?
  set -e
  if [[ "$preflight_exit" -ne 0 ]]; then
    printf '%s\n' "$SANDBOX_PREFLIGHT_PAYLOAD" >&2
    echo "verification_status=rejected_unsafe_sandbox"
    echo "docker_invoked=false"
    echo "poc_command_invoked=false"
    echo "oracle_matched=false"
    exit 1
  fi
}

ensure_host_evidence_directories() {
  python3 - "$SCRIPT_DIR" "$WORKSPACE_DIR" "$EVIDENCE_DIR" "$CONTAINER_OUTPUT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir, workspace, evidence_dir, output_dir = sys.argv[1:]
sys.path.insert(0, script_dir)
from evidence_io import ensure_host_directory

root = Path(workspace)
ensure_host_directory(root, Path(evidence_dir))
ensure_host_directory(root, Path(output_dir))
PY
}

write_sandbox_preflight_evidence() {
  python3 - "$SCRIPT_DIR" "$EVIDENCE_DIR" "$SANDBOX_PREFLIGHT_JSON" "$SANDBOX_PREFLIGHT_PAYLOAD" <<'PY'
import json
import sys
from pathlib import Path

script_dir, evidence_dir, output_path, payload = sys.argv[1:]
sys.path.insert(0, script_dir)
from evidence_io import atomic_write_json

atomic_write_json(Path(evidence_dir), Path(output_path), json.loads(payload))
PY
}

write_host_text() {
  local path_value="$1"
  local text_value="$2"
  python3 - "$SCRIPT_DIR" "$EVIDENCE_DIR" "$path_value" "$text_value" <<'PY'
import sys
from pathlib import Path

script_dir, root_value, path_value, text_value = sys.argv[1:]
sys.path.insert(0, script_dir)
from evidence_io import atomic_write_bytes

atomic_write_bytes(Path(root_value), Path(path_value), text_value.encode("utf-8", errors="replace"))
PY
}

write_empty_command_json() {
  python3 - "$SCRIPT_DIR" "$EVIDENCE_DIR" "$COMMAND_JSON_PATH" <<'PY'
import sys
from pathlib import Path

script_dir, root_value, path_value = sys.argv[1:]
sys.path.insert(0, script_dir)
from evidence_io import atomic_write_json

atomic_write_json(Path(root_value), Path(path_value), [])
PY
}

check_control_targets() {
  python3 - "$SCRIPT_DIR" "$EVIDENCE_DIR" \
    "$COMMAND_JSON_PATH" "$SANDBOX_PREFLIGHT_JSON" "$STDOUT_PATH" "$STDERR_PATH" \
    "$EVIDENCE_DIR/verification-result.json" <<'PY'
import sys
from pathlib import Path

script_dir, root_value, *paths = sys.argv[1:]
sys.path.insert(0, script_dir)
from evidence_io import SafeEvidenceError, assert_publish_target_safe

root = Path(root_value)
try:
    for value in paths:
        assert_publish_target_safe(root, Path(value))
except SafeEvidenceError as exc:
    print(exc.code, file=sys.stderr)
    raise SystemExit(1)
PY
}

emit_state_precondition_blocker() {
  local state_issue_code="$1"
  local reason="$2"
  python3 - "$SCRIPT_DIR" "$EVIDENCE_DIR" "$EVIDENCE_DIR/verification-result.json" "$CASE_ID" "$MODE" "$state_issue_code" "$reason" "$TIMEOUT_SECONDS" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

script_dir, evidence_dir, path, case_id, mode, state_issue_code, reason, timeout_seconds = sys.argv[1:]
sys.path.insert(0, script_dir)
from evidence_io import atomic_write_json
path = Path(path)
atomic_write_json(
    Path(evidence_dir),
    path,
    {
            "schema_version": 1,
            "case_id": case_id,
            "mode": mode,
            "status": "blocked_state_precondition",
            "code": "VERIFICATION_STATE_PRECONDITION_FAILED",
            "state_issue_code": state_issue_code,
            "classification_reason": reason,
            "execution_phase": "pre_execution",
            "docker_invoked": False,
            "poc_command_invoked": False,
            "oracle_matched": False,
            "authority_event_committed": False,
            "workflow_transition_attempted": False,
            "required_state": "verification/running or explicit verification/blocked retry",
            "resume_step": "Complete triage and use the canonical stage transition entrypoint to enter verification/running before retrying this wrapper.",
            "timeout_seconds": int(timeout_seconds),
            "command": [],
            "docker_boundary_only": True,
            "host_poc_execution_allowed": False,
            "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    },
)
PY
  echo "verification_status=blocked_state_precondition"
  echo "verification_code=VERIFICATION_STATE_PRECONDITION_FAILED"
  echo "state_issue_code=$state_issue_code"
  echo "docker_invoked=false"
  echo "oracle_matched=false"
  echo "result_json=$CASE_EVIDENCE_REF"
  exit 1
}

read_authority_preflight() {
  local output
  if [[ ! -e "$WORKSPACE_DIR/audit-events.jsonl" && ! -L "$WORKSPACE_DIR/audit-events.jsonl" \
    && ! -e "$WORKSPACE_DIR/stage-status.json" && ! -L "$WORKSPACE_DIR/stage-status.json" ]]; then
    emit_state_precondition_blocker \
      "AUTHORITATIVE_STATE_MISSING" \
      "A committed audit journal and state view are required before Docker verification."
  fi
  set +e
  output="$(python3 - "$SCRIPT_DIR" "$WORKSPACE_DIR" <<'PY'
import json
import sys
from pathlib import Path

script_dir, workspace = sys.argv[1:]
sys.path.insert(0, script_dir)
from audit_state_io import AuditStateError, read_workspace_snapshot

try:
    snapshot = read_workspace_snapshot(Path(workspace), mode_policy="auto")
except AuditStateError as exc:
    print(json.dumps({"ok": False, "code": exc.code, "message": exc.message}, sort_keys=True))
    raise SystemExit(1)

payload = {"ok": True, "protocol_mode": snapshot.mode}
if snapshot.mode == "r2":
    state = snapshot.state or {}
    payload.update(
        {
            "stage": state.get("stage"),
            "status": state.get("status"),
            "state_revision": state.get("state_revision"),
        }
    )
print(json.dumps(payload, sort_keys=True))
PY
)"
  local preflight_exit=$?
  set -e
  if [[ "$preflight_exit" -ne 0 ]]; then
    local issue_code
    issue_code="$(python3 - "$output" <<'PY'
import json
import sys

try:
    print(json.loads(sys.argv[1]).get("code") or "STATE_PREFLIGHT_INVALID")
except Exception:
    print("STATE_PREFLIGHT_INVALID")
PY
)"
    emit_state_precondition_blocker "$issue_code" "R2 journal/state validation failed before Docker execution."
  fi

  AUTHORITY_MODE="$(python3 - "$output" <<'PY'
import json
import sys
print(json.loads(sys.argv[1])["protocol_mode"])
PY
)"
  if [[ "$AUTHORITY_MODE" != "r2" ]]; then
    return 0
  fi

  local stage status
  stage="$(python3 - "$output" <<'PY'
import json
import sys
print(json.loads(sys.argv[1]).get("stage") or "")
PY
)"
  status="$(python3 - "$output" <<'PY'
import json
import sys
print(json.loads(sys.argv[1]).get("status") or "")
PY
)"
  R2_STATE_REVISION="$(python3 - "$output" <<'PY'
import json
import sys
print(json.loads(sys.argv[1]).get("state_revision") or "")
PY
)"
  if [[ "$stage" != "verification" || ( "$status" != "running" && "$status" != "blocked" ) ]]; then
    emit_state_precondition_blocker \
      "WORKFLOW_STATE_NOT_VERIFICATION_READY" \
      "R2 verification requires verification/running or an explicit verification/blocked retry."
  fi
  R2_INITIAL_STATUS="$status"
}

write_state_event() {
  local writer
  writer="$(find_state_writer)"
  [[ -n "$writer" ]] || return 0
  python3 "$writer" "$@" --protocol-mode legacy-r1 --accept-current-revision >/dev/null
}

write_r2_state_event() {
  local expected_revision="$1"
  shift
  local writer output writer_exit
  writer="$(find_state_writer)"
  if [[ -z "$writer" ]]; then
    AUTHORITY_EVENT_ERROR_CODE="AUTHORITY_WRITER_MISSING"
    return 1
  fi
  set +e
  output="$(python3 "$writer" "$@" \
    --protocol-mode r2 \
    --expected-state-revision "$expected_revision" \
    --json)"
  writer_exit=$?
  set -e
  if [[ "$writer_exit" -ne 0 ]]; then
    AUTHORITY_EVENT_ERROR_CODE="$(python3 - "$output" <<'PY'
import json
import sys
try:
    print(json.loads(sys.argv[1]).get("code") or "AUTHORITY_EVENT_COMMIT_FAILED")
except Exception:
    print("AUTHORITY_EVENT_COMMIT_FAILED")
PY
)"
    return 1
  fi
  R2_STATE_REVISION="$(python3 - "$output" <<'PY'
import json
import sys
value = json.loads(sys.argv[1])
if not value.get("ok"):
    raise SystemExit(1)
print(value["state_revision"])
PY
)"
  AUTHORITY_EVENT_ERROR_CODE=""
}

commit_verification_result_event() {
  if [[ "$AUTHORITY_MODE" == "r2" ]]; then
    write_r2_state_event "$R2_STATE_REVISION" \
      "$@" \
      --from-stage verification \
      --from-status running
    return
  fi
  if ! write_state_event "$@"; then
    AUTHORITY_EVENT_ERROR_CODE="AUTHORITY_EVENT_COMMIT_FAILED"
    return 1
  fi
}

write_resume_context() {
  python3 - "$SCRIPT_DIR" "$EVIDENCE_DIR" "$EVIDENCE_DIR/resume-context.json" "$CASE_ID" "$CASE_EVIDENCE_REF" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

script_dir, evidence_dir, path_value, case_id, prior_ref = sys.argv[1:]
sys.path.insert(0, script_dir)
from evidence_io import atomic_write_json
path = Path(path_value)
atomic_write_json(
    Path(evidence_dir),
    path,
    {
            "schema_version": 1,
            "case_id": case_id,
            "kind": "manual_retry_after_resolved_blocker",
            "prior_result_ref": prior_ref,
            "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "note": "The operator explicitly started a new Docker-only verification attempt after prerequisites passed.",
    },
)
PY
}

resume_verification_if_blocked() {
  local action_json
  [[ "$AUTHORITY_MODE" == "r2" && "${R2_INITIAL_STATUS:-}" == "blocked" ]] || return 0

  write_resume_context
  action_json="$(python3 - "$CASE_ID" "$SAFE_CASE_ID" "$RESUME_CONTEXT_REF" <<'PY'
import json
import sys

case_id, safe_case_id, evidence_ref = sys.argv[1:]
print(json.dumps({
    "action_id": f"run-verification-{safe_case_id}",
    "action_type": "verify",
    "subject_ids": [f"verification:{case_id}"],
    "summary": "Run the explicitly requested Docker-only verification attempt.",
    "evidence_refs": [evidence_ref],
}, sort_keys=True))
PY
)"
  write_r2_state_event "$R2_STATE_REVISION" \
    --workspace-dir "$WORKSPACE_DIR" \
    --target-repo "$(cd "$WORKSPACE_DIR/.." && pwd)" \
    --event verification_case_resumed \
    --stage verification \
    --from-stage verification \
    --from-status blocked \
    --status running \
    --transition-kind resume \
    --event-status retry_started \
    --reason-code prerequisite_missing \
    --message "A manually requested Docker-only verification retry resumed blocked verification work." \
    --subject "verification:$CASE_ID" \
    --evidence-ref "$RESUME_CONTEXT_REF" \
    --next-action-json "$action_json" \
    --details-json '{"reason_detail":"The operator manually retried this case after Docker, image, and sandbox prerequisites were available."}'
  R2_INITIAL_STATUS="running"
}

write_audit_log_block() {
  local status="$1"
  local message="$2"
  local timestamp
  timestamp="$(date '+%Y-%m-%d %H:%M:%S %z')"
  python3 - "$SCRIPT_DIR" "$WORKSPACE_DIR" "$WORKSPACE_DIR/audit-log.md" "$timestamp" "$CASE_ID" "$status" "$message" "$EVIDENCE_DIR" <<'PY'
import sys
from pathlib import Path

script_dir, root_value, path_value, timestamp, case_id, status, message, evidence_dir = sys.argv[1:]
sys.path.insert(0, script_dir)
from evidence_io import append_host_text

append_host_text(
    Path(root_value),
    Path(path_value),
    f"\n## {timestamp}\n\n- verification_case: {case_id}\n- status: {status}\n- message: {message}\n- evidence_dir: {evidence_dir}\n",
)
PY
}

emit_result_json() {
  local status="$1"
  local reason="$2"
  local exit_code="$3"
  local oracle_matched="$4"
  shift 4
  if ! python3 - "$SCRIPT_DIR" "$WORKSPACE_DIR" "$EVIDENCE_DIR" "$CASE_ID" "$MODE" "$status" "$reason" "$exit_code" "$oracle_matched" "$TIMEOUT_SECONDS" "$EXPECTED_ORACLE" "$IMAGE" "$NETWORK" "$MEMORY_LIMIT" "$CPU_LIMIT" "$PIDS_LIMIT" "$READ_ONLY" "$PULL_IF_MISSING" "$STDOUT_PATH" "$STDERR_PATH" "$COMMAND_JSON_PATH" "$DOCKER_CLI_INVOKED" "$POC_COMMAND_INVOKED" "$WRAPPER_STATUS" "$AUTHORITY_EVENT_COMMITTED" "$AUTHORITY_EVENT_ERROR_CODE" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

(
script_dir,
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
    docker_invoked,
    poc_command_invoked,
    wrapper_status,
authority_event_committed,
authority_event_error_code,
) = sys.argv[1:27]
sys.path.insert(0, script_dir)
from evidence_io import SafeEvidenceError, atomic_write_json, safe_read_json
workspace_path = Path(workspace).resolve()
evidence_path = Path(evidence_dir).absolute()

def workspace_rel(value: str) -> str:
    path = Path(value).absolute()
    try:
        return path.relative_to(workspace_path).as_posix()
    except ValueError:
        return path.name

command = safe_read_json(evidence_path, Path(command_json_path))
data = {
    "schema_version": 1,
    "case_id": case_id,
    "mode": mode,
    "status": status,
    "classification_reason": reason,
    "exit_code": None if exit_code == "" else int(exit_code),
    "oracle_matched": oracle_matched == "true",
    "docker_invoked": docker_invoked == "true",
    "poc_command_invoked": poc_command_invoked == "true",
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
if wrapper_status:
    data["wrapper_status"] = wrapper_status
if authority_event_committed:
    data["authority_event_committed"] = authority_event_committed == "true"
if authority_event_error_code:
    data["authority_event_error_code"] = authority_event_error_code
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
try:
    atomic_write_json(evidence_path, Path(evidence_dir, "verification-result.json"), data)
except SafeEvidenceError as exc:
    print(exc.code, file=sys.stderr)
    raise SystemExit(1)
PY
  then
    return 1
  fi
}

emit_authority_preexecution_blocker() {
  local code="$1"
  local reason="$2"
  WRAPPER_STATUS="blocked_authority_event_commit"
  AUTHORITY_EVENT_COMMITTED="false"
  AUTHORITY_EVENT_ERROR_CODE="$code"
  emit_result_json "blocked_authority_event_commit" "$reason" "" "false"
  echo "verification_status=blocked_authority_event_commit"
  echo "verification_code=VERIFICATION_START_EVENT_COMMIT_FAILED"
  echo "authority_event_error_code=$code"
  echo "docker_invoked=$DOCKER_CLI_INVOKED"
  echo "poc_command_invoked=false"
  echo "oracle_matched=false"
  echo "result_json=$CASE_EVIDENCE_REF"
  exit 1
}

commit_verification_start_event() {
  [[ "$AUTHORITY_MODE" == "r2" ]] || return 0
  write_r2_state_event "$R2_STATE_REVISION" \
    --workspace-dir "$WORKSPACE_DIR" \
    --target-repo "$(cd "$WORKSPACE_DIR/.." && pwd)" \
    --event verification_case_started \
    --stage verification \
    --from-stage verification \
    --from-status running \
    --status running \
    --transition-kind observe \
    --event-status pre_execution \
    --reason-code normal_progress \
    --message "Docker-only verification case is ready to start." \
    --subject "verification:$CASE_ID" \
    --evidence-ref "$COMMAND_EVIDENCE_REF" \
    --detail "case_id=$CASE_ID" \
    --detail "execution_boundary=before_poc_container_command"
}

classify_and_exit() {
  local status="$1"
  local reason="$2"
  local exit_code="${3:-}"
  local oracle_matched="${4:-false}"
  local event_committed="true"
  WRAPPER_STATUS="authority_event_pending"
  AUTHORITY_EVENT_COMMITTED=""
  AUTHORITY_EVENT_ERROR_CODE=""
  if [[ "$CONTROL_EVIDENCE_UNSAFE" == "true" ]]; then
    WRAPPER_STATUS="blocked_authority_event_commit"
    AUTHORITY_EVENT_COMMITTED="false"
    AUTHORITY_EVENT_ERROR_CODE="EVIDENCE_TARGET_UNSAFE"
    emit_result_json "$status" "$reason" "$exit_code" "$oracle_matched" || true
    echo "verification_status=rejected_unsafe_sandbox"
    echo "docker_evidence_status=$status"
    echo "verification_code=EVIDENCE_TARGET_UNSAFE"
    echo "authority_event_committed=false"
    echo "docker_invoked=$DOCKER_CLI_INVOKED"
    echo "poc_command_invoked=$POC_COMMAND_INVOKED"
    echo "oracle_matched=false"
    echo "result_json=$CASE_EVIDENCE_REF"
    exit 1
  fi
  if ! emit_result_json "$status" "$reason" "$exit_code" "$oracle_matched"; then
    CONTROL_EVIDENCE_UNSAFE="true"
    classify_and_exit "$status" "Host-owned control evidence could not be safely published." "$exit_code" "false"
  fi

  case "$status" in
    confirmed_in_docker)
      if ! commit_verification_result_event \
        --workspace-dir "$WORKSPACE_DIR" \
        --target-repo "$(cd "$WORKSPACE_DIR/.." && pwd)" \
        --event verification_case_completed \
        --stage candidate_verifying \
        --status running \
        --transition-kind observe \
        --event-status "$status" \
        --message "Verification case confirmed in Docker." \
        --subject "verification:$CASE_ID" \
        --evidence-ref "$CASE_EVIDENCE_REF" \
        --detail "case_id=$CASE_ID" \
        --detail "verification_result=$CASE_EVIDENCE_REF"; then
        event_committed="false"
      fi
      ;;
    blocked_docker_unavailable|blocked_missing_image|failed_timeout|failed_resource_limit)
      if ! commit_verification_result_event \
        --workspace-dir "$WORKSPACE_DIR" \
        --target-repo "$(cd "$WORKSPACE_DIR/.." && pwd)" \
        --event verification_case_blocked \
        --stage candidate_verifying \
        --status blocked \
        --transition-kind block \
        --event-status "$status" \
        --message "Verification case paused: $status." \
        --blocker "$reason" \
        --resume-step "Review $CASE_EVIDENCE_REF and retry only inside Docker after fixing the blocker." \
        --subject "verification:$CASE_ID" \
        --evidence-ref "$CASE_EVIDENCE_REF" \
        --detail "case_id=$CASE_ID" \
        --detail "verification_result=$CASE_EVIDENCE_REF"; then
        event_committed="false"
      else
        write_audit_log_block "$status" "$reason"
      fi
      ;;
    rejected_unsafe_sandbox)
      if ! commit_verification_result_event \
        --workspace-dir "$WORKSPACE_DIR" \
        --target-repo "$(cd "$WORKSPACE_DIR/.." && pwd)" \
        --event verification_case_blocked \
        --stage candidate_verifying \
        --status blocked \
        --transition-kind block \
        --event-status "$status" \
        --message "Verification case rejected by sandbox preflight." \
        --blocker "$reason" \
        --resume-step "Rewrite the verification container or script to avoid privileged/host/docker.sock/root-mount behavior; keep this case out of confirmed/ until safe Docker verification succeeds." \
        --subject "verification:$CASE_ID" \
        --evidence-ref "$CASE_EVIDENCE_REF" \
        --detail "case_id=$CASE_ID" \
        --detail "verification_result=$CASE_EVIDENCE_REF" \
        --detail "sandbox_preflight_status=runtime/sandbox-preflight-status.json"; then
        event_committed="false"
      else
        write_audit_log_block "$status" "$reason"
      fi
      ;;
    rejected_not_reproducible)
      if ! commit_verification_result_event \
        --workspace-dir "$WORKSPACE_DIR" \
        --target-repo "$(cd "$WORKSPACE_DIR/.." && pwd)" \
        --event verification_case_rejected \
        --stage candidate_verifying \
        --status running \
        --transition-kind observe \
        --event-status "$status" \
        --message "Verification case did not reproduce in Docker." \
        --subject "verification:$CASE_ID" \
        --evidence-ref "$CASE_EVIDENCE_REF" \
        --detail "case_id=$CASE_ID" \
        --detail "verification_result=$CASE_EVIDENCE_REF"; then
        event_committed="false"
      fi
      ;;
  esac

  if [[ "$event_committed" == "true" ]]; then
    WRAPPER_STATUS="completed"
    AUTHORITY_EVENT_COMMITTED="true"
  else
    WRAPPER_STATUS="blocked_authority_event_commit"
    AUTHORITY_EVENT_COMMITTED="false"
    [[ -n "$AUTHORITY_EVENT_ERROR_CODE" ]] || AUTHORITY_EVENT_ERROR_CODE="AUTHORITY_EVENT_COMMIT_FAILED"
  fi
  if ! emit_result_json "$status" "$reason" "$exit_code" "$oracle_matched"; then
    CONTROL_EVIDENCE_UNSAFE="true"
    echo "verification_status=rejected_unsafe_sandbox"
    echo "docker_evidence_status=$status"
    echo "verification_code=EVIDENCE_TARGET_UNSAFE"
    echo "authority_event_committed=false"
    echo "docker_invoked=$DOCKER_CLI_INVOKED"
    echo "poc_command_invoked=$POC_COMMAND_INVOKED"
    echo "oracle_matched=false"
    echo "result_json=$CASE_EVIDENCE_REF"
    exit 1
  fi

  if [[ "$event_committed" != "true" ]]; then
    echo "verification_status=blocked_authority_event_commit"
    echo "docker_evidence_status=$status"
    echo "verification_code=VERIFICATION_RESULT_EVENT_COMMIT_FAILED"
    echo "authority_event_error_code=$AUTHORITY_EVENT_ERROR_CODE"
    echo "evidence_dir=evidence/$CASE_ID"
    echo "result_json=$CASE_EVIDENCE_REF"
    exit 1
  fi

  echo "verification_status=$status"
  echo "evidence_dir=$EVIDENCE_DIR"
  echo "result_json=$EVIDENCE_DIR/verification-result.json"

  if [[ "$status" == "confirmed_in_docker" ]]; then
    exit 0
  fi
  exit 1
}

early_sandbox_preflight
ensure_host_evidence_directories
EVIDENCE_DIR="$(cd "$EVIDENCE_DIR" && pwd -P)"
CONTAINER_OUTPUT_DIR="$EVIDENCE_DIR/container-output"
STDOUT_PATH="$EVIDENCE_DIR/stdout.log"
STDERR_PATH="$EVIDENCE_DIR/stderr.log"
COMMAND_JSON_PATH="$EVIDENCE_DIR/command.json"
SANDBOX_PREFLIGHT_JSON="$EVIDENCE_DIR/sandbox-preflight.json"
write_sandbox_preflight_evidence
read_authority_preflight

write_command_json() {
  python3 - "$SCRIPT_DIR" "$COMMAND_JSON_PATH" "$WORKSPACE_DIR" "$EVIDENCE_DIR" "$@" <<'PY'
import json
import sys
from pathlib import Path

script_dir, path_value, workspace, evidence_dir = sys.argv[1:5]
sys.path.insert(0, script_dir)
from evidence_io import atomic_write_json
path = Path(path_value)

def scrub(value: str) -> str:
    return value.replace(evidence_dir, "<evidence-dir>").replace(workspace, "<audit-workspace>")

atomic_write_json(Path(evidence_dir), path, [scrub(arg) for arg in sys.argv[5:]])
PY
}

DOCKER_CLI_INVOKED="true"
if ! docker info >/dev/null 2>&1; then
  write_host_text "$STDERR_PATH" 'Docker unavailable. This helper will not execute PoC logic on the host.'
  write_empty_command_json
  classify_and_exit "blocked_docker_unavailable" "Docker daemon or socket is unavailable; no host fallback is provided."
fi

RUN_COMMAND=()
case "$MODE" in
  docker-run)
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
      if [[ "$PULL_IF_MISSING" == "1" ]]; then
        set +e
        pull_output="$(docker pull "$IMAGE" 2>&1)"
        pull_exit=$?
        set -e
        write_host_text "$EVIDENCE_DIR/image-pull.log" "$pull_output"
        if [[ "$pull_exit" -ne 0 ]]; then
          write_host_text "$STDERR_PATH" "Image pull failed for $IMAGE\n$pull_output"
          write_empty_command_json
          classify_and_exit "blocked_missing_image" "Required image is missing locally and explicit pull failed."
        fi
      else
        write_host_text "$STDERR_PATH" "Image is missing locally: $IMAGE"
        write_empty_command_json
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
      python3 - "$SCRIPT_DIR" "$WORKSPACE_DIR" "$WORKSPACE_DIR/poc" "$CONTAINER_OUTPUT_DIR" <<'PY'
import sys
from pathlib import Path

script_dir, root_value, poc_value, output_value = sys.argv[1:]
sys.path.insert(0, script_dir)
from evidence_io import ensure_host_directory

root = Path(root_value)
ensure_host_directory(root, Path(poc_value))
ensure_host_directory(root, Path(output_value))
PY
      RUN_COMMAND+=(
        --mount "type=bind,source=$WORKSPACE_DIR/poc,target=/workspace/poc,readonly"
        --mount "type=bind,source=$EVIDENCE_DIR,target=/workspace/evidence,readonly"
        --mount "type=bind,source=$CONTAINER_OUTPUT_DIR,target=/workspace/output"
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
        set +e
        pull_output="$(docker compose "${COMPOSE_ARGS[@]}" pull "$COMPOSE_SERVICE" 2>&1)"
        pull_exit=$?
        set -e
        write_host_text "$EVIDENCE_DIR/image-pull.log" "$pull_output"
        if [[ "$pull_exit" -ne 0 ]]; then
          write_host_text "$STDERR_PATH" "Compose image pull failed for service $COMPOSE_SERVICE\n$pull_output"
          write_empty_command_json
          classify_and_exit "blocked_missing_image" "One or more compose images are missing locally and explicit pull failed."
        fi
      else
        write_host_text "$STDERR_PATH" "Compose images missing locally: ${missing_images[*]}"
        write_empty_command_json
        classify_and_exit "blocked_missing_image" "One or more compose images are missing locally; rerun with --pull-if-missing only if network pull is acceptable."
      fi
    fi
    RUN_COMMAND=(docker compose "${COMPOSE_ARGS[@]}" run --rm -T "$COMPOSE_SERVICE")
    if [[ "${#CASE_COMMAND[@]}" -gt 0 ]]; then
      RUN_COMMAND+=("${CASE_COMMAND[@]}")
    fi
    ;;
esac

write_command_json "${RUN_COMMAND[@]}"

# This is not an automatic retry: it is recorded only after an operator
# explicitly invokes this helper again and the Docker/image/sandbox
# prerequisites for that new attempt have passed.
if ! resume_verification_if_blocked; then
  emit_authority_preexecution_blocker \
    "${AUTHORITY_EVENT_ERROR_CODE:-VERIFICATION_RESUME_EVENT_COMMIT_FAILED}" \
    "The explicit verification retry could not be committed; no PoC container command was started."
fi
if ! commit_verification_start_event; then
  emit_authority_preexecution_blocker \
    "${AUTHORITY_EVENT_ERROR_CODE:-VERIFICATION_START_EVENT_COMMIT_FAILED}" \
    "The verification start event could not be committed; no PoC container command was started."
fi

POC_COMMAND_INVOKED="true"
set +e
CAPTURE_RESULT="$(python3 - "$SCRIPT_DIR" "$WORKSPACE_DIR" "$STDOUT_PATH" "$STDERR_PATH" "$TIMEOUT_SECONDS" "$EXPECTED_ORACLE" "${RUN_COMMAND[@]}" <<'PY'
import json
import sys
from pathlib import Path

script_dir, root_value, stdout_value, stderr_value, timeout_value, oracle_value = sys.argv[1:7]
command = sys.argv[7:]
sys.path.insert(0, script_dir)
from evidence_io import SafeEvidenceError, run_captured_command

try:
    result = run_captured_command(
        Path(root_value),
        Path(stdout_value),
        Path(stderr_value),
        command,
        timeout=int(timeout_value),
        expected_oracle=oracle_value,
    )
except SafeEvidenceError as exc:
    print(json.dumps({"ok": False, "code": exc.code, "message": exc.message}, sort_keys=True))
    raise SystemExit(3)
print(json.dumps({"ok": True, **result}, sort_keys=True))
PY
)"
CAPTURE_HELPER_EXIT=$?
set -e
if [[ "$CAPTURE_HELPER_EXIT" -ne 0 ]]; then
  CONTROL_EVIDENCE_UNSAFE="true"
  POC_COMMAND_INVOKED="false"
  capture_code="$(python3 - "$CAPTURE_RESULT" <<'PY'
import json
import sys
try:
    print(json.loads(sys.argv[1]).get("code") or "EVIDENCE_CAPTURE_FAILED")
except Exception:
    print("EVIDENCE_CAPTURE_FAILED")
PY
)"
  classify_and_exit "rejected_unsafe_sandbox" "Host-owned stdout/stderr capture could not be established safely ($capture_code)." "" "false"
fi

capture_value() {
  python3 - "$CAPTURE_RESULT" "$1" <<'PY'
import json
import sys
value = json.loads(sys.argv[1]).get(sys.argv[2])
if isinstance(value, bool):
    print("true" if value else "false")
elif value is None:
    print("")
else:
    print(value)
PY
}

RUN_EXIT="$(capture_value exit_code)"
oracle_matched="$(capture_value oracle_matched)"
capture_integrity="$(capture_value capture_integrity)"
resource_limit_detected="$(capture_value resource_limit_detected)"
command_started="$(capture_value command_started)"
POC_COMMAND_INVOKED="$command_started"
if [[ "$capture_integrity" != "true" ]]; then
  CONTROL_EVIDENCE_UNSAFE="true"
  classify_and_exit "rejected_unsafe_sandbox" "Docker-collected stdout/stderr pathname changed during execution; host FD evidence was not trusted." "$RUN_EXIT" "false"
fi
if ! check_control_targets; then
  CONTROL_EVIDENCE_UNSAFE="true"
  classify_and_exit "rejected_unsafe_sandbox" "A host-owned control evidence path was replaced or became unsafe during Docker execution." "$RUN_EXIT" "false"
fi

if [[ "$RUN_EXIT" -eq 124 ]]; then
  classify_and_exit "failed_timeout" "Verification command timed out. Re-analyze service readiness, waiting conditions, network blocking, loops, or interactive prompts before retrying." "$RUN_EXIT" "false"
fi

if [[ "$RUN_EXIT" -eq 137 || "$resource_limit_detected" == "true" ]]; then
  classify_and_exit "failed_resource_limit" "Verification command appears to have hit memory, CPU, pids, or related container resource limits." "$RUN_EXIT" "false"
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
