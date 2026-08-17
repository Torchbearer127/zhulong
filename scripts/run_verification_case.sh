#!/usr/bin/env bash
# zhulong-tool-contract: docker-verification-v1; timeout=mandatory; sandbox-preflight=mandatory
# zhulong-host-policy: docker-case-policy-v1

set -euo pipefail

STABLE_LABELS="blocked_state_precondition blocked_authority_event_commit blocked_docker_unavailable blocked_missing_image failed_timeout failed_resource_limit rejected_unsafe_sandbox rejected_not_reproducible confirmed_in_docker"
OUTPUT_TMPFS_SPEC="/workspace/output:rw,nosuid,nodev,noexec,size=64m"

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
  network setting, one bounded host resource policy, and structured
  evidence under <audit-workspace>/evidence/<case-id>/.
  Docker-run and Docker Compose both use the host-owned docker-case-policy-v1.
  Default mounts provide a 64 MiB container tmpfs at /workspace/output; images
  must provide a static sh so the wrapper can stream validated output before
  stopping the container. Missing markers or unsafe output fail closed.

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
  Compose inputs are copied into one-use host-owned snapshots before evidence
  or Docker access. Preflight, config, pull, and run use only those pinned
  bytes and the audit workspace as the explicit project directory.
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
  --memory LIMIT             Default: 512m; allowed range: 16m through 2g.
  --cpus LIMIT               Default: 1; allowed range: 0.1 through 4.
  --pids-limit N             Default: 256; allowed range: 1 through 1024.

docker-run options:
  --image IMAGE              Required image name or ID.
  --docker-arg ARG           Deprecated closed input; policy/boundary overrides
                             are rejected before Docker execution.
  --no-default-mounts        Do not mount workspace poc/ and evidence dirs.

docker-compose options:
  --compose-file FILE        Workspace-local Compose file. Relative paths are
                             resolved from the audit workspace, never caller CWD.
                             Repeat as needed; input order is preserved.
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

WORKSPACE_DIR="${WORKSPACE_DIR/#\~/$HOME}"
WORKSPACE_DIR="$(cd "$WORKSPACE_DIR" && pwd -P)"
if [[ ! -f "$WORKSPACE_DIR/asr-config.json" || -L "$WORKSPACE_DIR/asr-config.json" ]]; then
  echo "ERROR: not a Zhulong audit workspace: $WORKSPACE_DIR" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$MODE" in
  docker-run)
    [[ -n "$IMAGE" ]] || fail_usage "--image is required for docker-run mode."
    ;;
  docker-compose)
    [[ -n "$COMPOSE_SERVICE" ]] || fail_usage "--compose-service is required for docker-compose mode."
    [[ "$COMPOSE_SERVICE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail_usage "--compose-service must be a static safe service name."
    [[ "${#COMPOSE_FILES[@]}" -gt 0 ]] || fail_usage "--compose-file is required for docker-compose mode."
    for compose_file in "${COMPOSE_FILES[@]}"; do
      [[ -n "$compose_file" ]] || fail_usage "--compose-file must not be empty."
    done
    ;;
  *)
    fail_usage "--mode must be docker-run or docker-compose."
    ;;
esac

SAFE_CASE_ID="$CASE_ID"
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
VERIFICATION_DIAGNOSTIC_CODE=""
CONTROL_EVIDENCE_UNSAFE="false"
CAPTURE_RESULT='{}'
CAPTURE_HELPER_PID=""
CAPTURE_LAUNCH_STATE="idle"
PENDING_SIGNAL=""
OUTPUT_READY_MARKER=""
OUTPUT_SCRIPT=""
LIFECYCLE_ACTIVE="false"
LIFECYCLE_RECEIPT_PATH=""
LIFECYCLE_RECEIPT_SHA256=""
LIFECYCLE_OVERRIDE_PATH=""
LIFECYCLE_OVERRIDE_SHA256=""
LIFECYCLE_PROJECT_NAME=""
LIFECYCLE_CONTAINER_NAME=""
LIFECYCLE_TOKEN=""
LIFECYCLE_POLICY_JSON='{}'
DOCKER_CASE_MAY_EXIST="false"
CLEANUP_ATTEMPTED="false"
CLEANUP_VERIFIED="false"
CLEANUP_CONTAINERS_BEFORE="0"
CLEANUP_NETWORKS_BEFORE="0"
CLEANUP_VOLUMES_BEFORE="0"
CLEANUP_CONTAINERS_AFTER="0"
CLEANUP_NETWORKS_AFTER="0"
CLEANUP_VOLUMES_AFTER="0"
CLEANUP_SETTLEMENT_CHECKS="0"

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

find_case_lifecycle() {
  if [[ -f "$SCRIPT_DIR/docker_case_lifecycle.py" ]]; then
    printf '%s\n' "$SCRIPT_DIR/docker_case_lifecycle.py"
    return
  fi
  if [[ -f "$SCRIPT_DIR/docker-case-lifecycle.py" ]]; then
    printf '%s\n' "$SCRIPT_DIR/docker-case-lifecycle.py"
    return
  fi
  if [[ -f "$SCRIPT_DIR/../bin/docker-case-lifecycle.py" ]]; then
    printf '%s\n' "$SCRIPT_DIR/../bin/docker-case-lifecycle.py"
    return
  fi
}

validate_resource_policy_or_abort() {
  local lifecycle output policy_exit code
  lifecycle="$(find_case_lifecycle)"
  if [[ -z "$lifecycle" ]]; then
    echo "verification_status=rejected_unsafe_sandbox"
    echo "verification_code=DOCKER_CASE_LIFECYCLE_UNSAFE"
    echo "docker_invoked=false"
    echo "poc_command_invoked=false"
    echo "oracle_matched=false"
    exit 1
  fi
  if [[ "$READ_ONLY" != "1" ]]; then
    echo "verification_status=rejected_unsafe_sandbox"
    echo "verification_code=DOCKER_RESOURCE_OVERRIDE_FORBIDDEN"
    echo "docker_invoked=false"
    echo "poc_command_invoked=false"
    echo "oracle_matched=false"
    exit 1
  fi
  set +e
  output="$(python3 "$lifecycle" validate-policy --memory "$MEMORY_LIMIT" --cpus "$CPU_LIMIT" --pids-limit "$PIDS_LIMIT")"
  policy_exit=$?
  set -e
  if [[ "$policy_exit" -ne 0 ]]; then
    code="$(python3 - "$output" <<'PY'
import json
import sys
try:
    print(json.loads(sys.argv[1]).get("issue_code") or "DOCKER_RESOURCE_LIMIT_INVALID")
except Exception:
    print("DOCKER_RESOURCE_LIMIT_INVALID")
PY
)"
    echo "verification_status=rejected_unsafe_sandbox"
    echo "verification_code=$code"
    echo "docker_invoked=false"
    echo "poc_command_invoked=false"
    echo "oracle_matched=false"
    exit 1
  fi
}

prepare_case_lifecycle() {
  local lifecycle payload prepare_exit
  lifecycle="$(find_case_lifecycle)"
  local -a prepare_args
  prepare_args=(
    prepare
    --evidence-root "$EVIDENCE_DIR"
    --case-id "$CASE_ID"
    --mode "$MODE"
    --memory "$MEMORY_LIMIT"
    --cpus "$CPU_LIMIT"
    --pids-limit "$PIDS_LIMIT"
  )
  if [[ "$MODE" == "docker-compose" ]]; then
    prepare_args+=(--compose-service "$COMPOSE_SERVICE")
  fi
  set +e
  payload="$(python3 "$lifecycle" "${prepare_args[@]}")"
  prepare_exit=$?
  set -e
  if [[ "$prepare_exit" -ne 0 ]]; then
    printf '%s\n' "$payload" >&2
    echo "verification_status=rejected_unsafe_sandbox"
    echo "verification_code=DOCKER_CASE_LIFECYCLE_UNSAFE"
    echo "authority_event_committed=false"
    echo "docker_invoked=false"
    echo "poc_command_invoked=false"
    echo "oracle_matched=false"
    exit 1
  fi
  lifecycle_values=()
  while IFS= read -r lifecycle_value; do
    lifecycle_values+=("$lifecycle_value")
  done < <(python3 - "$payload" <<'PY'
import json
import sys
value = json.loads(sys.argv[1])
for key in ("receipt_path", "receipt_sha256", "override_path", "override_sha256", "project_name", "container_name", "token"):
    print(value[key])
print(json.dumps(value["resource_policy"], sort_keys=True, separators=(",", ":")))
PY
)
  if [[ "${#lifecycle_values[@]}" -ne 8 ]]; then
    echo "verification_status=rejected_unsafe_sandbox"
    echo "verification_code=DOCKER_CASE_RECEIPT_DRIFT"
    echo "authority_event_committed=false"
    echo "docker_invoked=false"
    echo "poc_command_invoked=false"
    echo "oracle_matched=false"
    exit 1
  fi
  LIFECYCLE_RECEIPT_PATH="${lifecycle_values[0]}"
  LIFECYCLE_RECEIPT_SHA256="${lifecycle_values[1]}"
  LIFECYCLE_OVERRIDE_PATH="${lifecycle_values[2]}"
  LIFECYCLE_OVERRIDE_SHA256="${lifecycle_values[3]}"
  LIFECYCLE_PROJECT_NAME="${lifecycle_values[4]}"
  LIFECYCLE_CONTAINER_NAME="${lifecycle_values[5]}"
  LIFECYCLE_TOKEN="${lifecycle_values[6]}"
  LIFECYCLE_POLICY_JSON="${lifecycle_values[7]}"
  if [[ "$DEFAULT_MOUNTS" == "1" ]]; then
    OUTPUT_READY_MARKER="ZHULONG_OUTPUT_READY_${LIFECYCLE_TOKEN}"
  else
    OUTPUT_READY_MARKER=""
  fi
  LIFECYCLE_ACTIVE="true"
}

prepare_output_handshake() {
  [[ "$DEFAULT_MOUNTS" == "1" ]] || return 0
  local quoted_command
  if [[ "${#CASE_COMMAND[@]}" -gt 0 ]]; then
    quoted_command="$(python3 - "${CASE_COMMAND[@]}" <<'PY'
import shlex
import sys
print(" ".join(shlex.quote(value) for value in sys.argv[1:]) or ":")
PY
    )"
  else
    quoted_command=":"
  fi
  OUTPUT_SCRIPT="set +e; ${quoted_command}; _zhulong_rc=\$?; printf '%s:%s\\n' '${OUTPUT_READY_MARKER}' \"\$_zhulong_rc\"; while :; do sleep 1; done"
}

ensure_case_cleanup() {
  if [[ "$DOCKER_CASE_MAY_EXIST" != "true" ]]; then
    CLEANUP_ATTEMPTED="false"
    CLEANUP_VERIFIED="true"
    return 0
  fi
  if [[ "$CLEANUP_VERIFIED" == "true" ]]; then
    return 0
  fi
  local lifecycle payload cleanup_exit
  lifecycle="$(find_case_lifecycle)"
  CLEANUP_ATTEMPTED="true"
  set +e
  payload="$(python3 "$lifecycle" cleanup \
    --evidence-root "$EVIDENCE_DIR" \
    --receipt "$LIFECYCLE_RECEIPT_PATH" \
    --receipt-sha256 "$LIFECYCLE_RECEIPT_SHA256" \
    --docker docker)"
  cleanup_exit=$?
  set -e
  cleanup_values=()
  while IFS= read -r cleanup_value; do
    cleanup_values+=("$cleanup_value")
  done < <(python3 - "$payload" <<'PY'
import json
import sys
try:
    value = json.loads(sys.argv[1])
except Exception:
    value = {}
before = value.get("residue_counts_before", {})
after = value.get("residue_counts_after", {})
print("true" if value.get("cleanup_verified") is True else "false")
for source in (before, after):
    for key in ("containers", "networks", "volumes"):
        item = source.get(key, 0)
        print(item if isinstance(item, int) and not isinstance(item, bool) and item >= 0 else 0)
print(value.get("settlement_checks", 0) if isinstance(value.get("settlement_checks", 0), int) else 0)
PY
)
  CLEANUP_VERIFIED="${cleanup_values[0]:-false}"
  CLEANUP_CONTAINERS_BEFORE="${cleanup_values[1]:-0}"
  CLEANUP_NETWORKS_BEFORE="${cleanup_values[2]:-0}"
  CLEANUP_VOLUMES_BEFORE="${cleanup_values[3]:-0}"
  CLEANUP_CONTAINERS_AFTER="${cleanup_values[4]:-0}"
  CLEANUP_NETWORKS_AFTER="${cleanup_values[5]:-0}"
  CLEANUP_VOLUMES_AFTER="${cleanup_values[6]:-0}"
  CLEANUP_SETTLEMENT_CHECKS="${cleanup_values[7]:-0}"
  [[ "$cleanup_exit" -eq 0 && "$CLEANUP_VERIFIED" == "true" ]]
}

cleanup_wrapper_resources() {
  local original_status="${1:-1}"
  trap - EXIT INT TERM
    if [[ "$LIFECYCLE_ACTIVE" == "true" && "$DOCKER_CASE_MAY_EXIST" == "true" && "$CLEANUP_VERIFIED" != "true" ]]; then
    if ! ensure_case_cleanup; then
      echo "verification_status=rejected_unsafe_sandbox"
      echo "verification_code=DOCKER_CASE_CLEANUP_FAILED"
      echo "oracle_matched=false"
      original_status=1
    fi
  fi
  if ! cleanup_pinned_compose; then
    original_status=1
  fi
  exit "$original_status"
}

handle_wrapper_signal() {
  local signal_name="$1" signal_exit=130
  [[ "$signal_name" == "TERM" ]] && signal_exit=143
  if [[ "$CAPTURE_LAUNCH_STATE" == "launching" ]]; then
    PENDING_SIGNAL="$signal_name"
    return 0
  fi
  if [[ -n "$CAPTURE_HELPER_PID" ]]; then
    kill -"$signal_name" "$CAPTURE_HELPER_PID" >/dev/null 2>&1 || true
    wait "$CAPTURE_HELPER_PID" >/dev/null 2>&1 || true
    CAPTURE_HELPER_PID=""
  fi
  if [[ "$LIFECYCLE_ACTIVE" == "true" && "$DOCKER_CASE_MAY_EXIST" == "true" ]]; then
    ensure_case_cleanup >/dev/null 2>&1 || true
  fi
  exit "$signal_exit"
}

COMPOSE_PIN_ACTIVE="false"
COMPOSE_PIN_MANIFEST=""
COMPOSE_PIN_MANIFEST_SHA256=""
COMPOSE_BIND_IDENTITIES_JSON=""

cleanup_pinned_compose() {
  local cleanup_status=0 preflight
  if [[ "$COMPOSE_PIN_ACTIVE" == "true" ]]; then
    preflight="$(find_sandbox_preflight)"
    set +e
    python3 "$preflight" \
      --compose-operation cleanup \
      --workspace-dir "$WORKSPACE_DIR" \
      --compose-manifest "$COMPOSE_PIN_MANIFEST" \
      --compose-manifest-sha256 "$COMPOSE_PIN_MANIFEST_SHA256" \
      --json >/dev/null
    cleanup_status=$?
    set -e
    if [[ "$cleanup_status" -ne 0 ]]; then
      echo "ERROR: pinned Compose input cleanup was refused because its identity changed." >&2
      return 1
    fi
    COMPOSE_PIN_ACTIVE="false"
  fi
  return 0
}

pin_compose_inputs() {
  [[ "$MODE" == "docker-compose" ]] || return 0
  local preflight pin_payload pin_exit manifest_path manifest_digest
  local -a pin_args raw_compose_files pinned_compose_files
  preflight="$(find_sandbox_preflight)"
  if [[ -z "$preflight" ]]; then
    echo "ERROR: Sandbox preflight helper is missing; Compose input cannot be pinned." >&2
    exit 1
  fi
  raw_compose_files=("${COMPOSE_FILES[@]}")
  pin_args=(
    --compose-operation pin
    --workspace-dir "$WORKSPACE_DIR"
    --case-id "$CASE_ID"
    --json
  )
  for compose_file in "${raw_compose_files[@]}"; do
    pin_args+=(--compose-file "$compose_file")
  done
  set +e
  pin_payload="$(python3 "$preflight" "${pin_args[@]}")"
  pin_exit=$?
  set -e
  if [[ "$pin_exit" -ne 0 ]]; then
    printf '%s\n' "$pin_payload" >&2
    echo "verification_status=rejected_unsafe_sandbox"
    echo "docker_invoked=false"
    echo "poc_command_invoked=false"
    echo "oracle_matched=false"
    exit 1
  fi
  manifest_path="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["manifest"])' <<<"$pin_payload")"
  manifest_digest="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["manifest_sha256"])' <<<"$pin_payload")"
  while IFS= read -r compose_file; do
    pinned_compose_files+=("$compose_file")
  done < <(python3 -c 'import json,sys; [print(value) for value in json.load(sys.stdin)["compose_files"]]' <<<"$pin_payload")
  if [[ -z "$manifest_path" || -z "$manifest_digest" || "${#pinned_compose_files[@]}" -ne "${#raw_compose_files[@]}" ]]; then
    python3 "$preflight" --compose-operation cleanup --workspace-dir "$WORKSPACE_DIR" \
      --compose-manifest "$manifest_path" --compose-manifest-sha256 "$manifest_digest" --json >/dev/null 2>&1 || true
    echo "ERROR: Compose pin helper returned an incomplete ordered input set." >&2
    exit 1
  fi
  COMPOSE_FILES=("${pinned_compose_files[@]}")
  COMPOSE_PIN_MANIFEST="$manifest_path"
  COMPOSE_PIN_MANIFEST_SHA256="$manifest_digest"
  COMPOSE_PIN_ACTIVE="true"
}

verify_pinned_compose_or_abort() {
  [[ "$MODE" == "docker-compose" ]] || return 0
  local preflight verify_payload verify_exit
  local -a verify_args
  preflight="$(find_sandbox_preflight)"
    verify_args=(
    --compose-operation verify
    --workspace-dir "$WORKSPACE_DIR"
      --case-id "$CASE_ID"
      --compose-service "$COMPOSE_SERVICE"
    --compose-manifest "$COMPOSE_PIN_MANIFEST"
    --compose-manifest-sha256 "$COMPOSE_PIN_MANIFEST_SHA256"
    --json
  )
  if [[ -n "$COMPOSE_BIND_IDENTITIES_JSON" ]]; then
    verify_args+=(--expected-bind-identities "$COMPOSE_BIND_IDENTITIES_JSON")
  fi
  for compose_file in "${COMPOSE_FILES[@]}"; do
    verify_args+=(--compose-file "$compose_file")
  done
  set +e
  verify_payload="$(python3 "$preflight" "${verify_args[@]}")"
  verify_exit=$?
  set -e
  if [[ "$verify_exit" -ne 0 ]]; then
    printf '%s\n' "$verify_payload" >&2
    local verification_code
    verification_code="$(python3 - "$verify_payload" <<'PY'
import json
import sys

try:
    print(json.loads(sys.argv[1]).get("issue_code") or "COMPOSE_INPUT_IDENTITY_DRIFT")
except Exception:
    print("COMPOSE_INPUT_IDENTITY_DRIFT")
PY
)"
    if ! ensure_case_cleanup; then
      VERIFICATION_DIAGNOSTIC_CODE="DOCKER_CASE_CLEANUP_FAILED"
      classify_and_exit "rejected_unsafe_sandbox" "Pinned Compose input changed and exact Docker case cleanup could not be verified." "" "false"
    fi
    echo "verification_status=rejected_unsafe_sandbox"
    echo "verification_code=$verification_code"
    echo "authority_event_committed=false"
    echo "docker_invoked=$DOCKER_CLI_INVOKED"
    echo "poc_command_invoked=$POC_COMMAND_INVOKED"
    echo "oracle_matched=false"
    exit 1
  fi
  COMPOSE_BIND_IDENTITIES_JSON="$(python3 - "$verify_payload" <<'PY'
import json
import sys

value = json.loads(sys.argv[1]).get("bind_identities", {})
if not isinstance(value, dict):
    raise SystemExit(1)
print(json.dumps(value, sort_keys=True, separators=(",", ":")))
PY
)"
}

verify_default_mounts_or_abort() {
  [[ "$MODE" == "docker-run" && "$DEFAULT_MOUNTS" == "1" ]] || return 0
  local preflight payload preflight_exit verification_code
  preflight="$(find_sandbox_preflight)"
  set +e
  payload="$(python3 "$preflight" \
    --workspace-dir "$WORKSPACE_DIR" \
    --case-id "$CASE_ID" \
    --mode docker-run \
    --verify-default-mounts \
    --json)"
  preflight_exit=$?
  set -e
  if [[ "$preflight_exit" -ne 0 ]]; then
    printf '%s\n' "$payload" >&2
    verification_code="$(python3 - "$payload" <<'PY'
import json
import sys

try:
    print(json.loads(sys.argv[1]).get("issue_codes", ["COMPOSE_BIND_SOURCE_FORBIDDEN"])[0])
except Exception:
    print("COMPOSE_BIND_SOURCE_FORBIDDEN")
PY
)"
    echo "verification_status=rejected_unsafe_sandbox"
    echo "verification_code=$verification_code"
    echo "authority_event_committed=false"
    echo "docker_invoked=$DOCKER_CLI_INVOKED"
    echo "poc_command_invoked=$POC_COMMAND_INVOKED"
    echo "oracle_matched=false"
    exit 1
  fi
}

SANDBOX_PREFLIGHT_PAYLOAD=""
early_sandbox_preflight() {
  local preflight preflight_exit preflight_code
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
    preflight_args+=(
      --compose-service "$COMPOSE_SERVICE"
      --compose-manifest "$COMPOSE_PIN_MANIFEST"
      --compose-manifest-sha256 "$COMPOSE_PIN_MANIFEST_SHA256"
      --compose-project-directory "$WORKSPACE_DIR"
    )
  fi
  set +e
  SANDBOX_PREFLIGHT_PAYLOAD="$(python3 "$preflight" "${preflight_args[@]}")"
  preflight_exit=$?
  set -e
  if [[ "$preflight_exit" -ne 0 ]]; then
    printf '%s\n' "$SANDBOX_PREFLIGHT_PAYLOAD" >&2
    preflight_code="$(python3 - "$SANDBOX_PREFLIGHT_PAYLOAD" <<'PY'
import json
import sys
try:
    codes = json.loads(sys.argv[1]).get("issue_codes", [])
    print(codes[0] if codes else "SANDBOX_PREFLIGHT_FAILED")
except Exception:
    print("SANDBOX_PREFLIGHT_FAILED")
PY
)"
    echo "verification_status=rejected_unsafe_sandbox"
    echo "verification_code=$preflight_code"
    echo "docker_invoked=false"
    echo "poc_command_invoked=false"
    echo "oracle_matched=false"
    exit 1
  fi
}

ensure_host_evidence_directories() {
  local output ensure_exit ensure_code
  set +e
  output="$(python3 - "$SCRIPT_DIR" "$WORKSPACE_DIR" "$EVIDENCE_DIR" "$MODE" "$DEFAULT_MOUNTS" <<'PY'
import sys
from pathlib import Path

script_dir, workspace, evidence_dir, mode, default_mounts = sys.argv[1:]
sys.path.insert(0, script_dir)
from evidence_io import SafeEvidenceError, ensure_host_directory

root = Path(workspace)
try:
    if mode == "docker-run" and default_mounts == "1":
        ensure_host_directory(root, root / "poc")
    ensure_host_directory(root, Path(evidence_dir))
except SafeEvidenceError as exc:
    print(exc.code)
    raise SystemExit(1)
PY
  )"
  ensure_exit=$?
  set -e
  if [[ "$ensure_exit" -ne 0 ]]; then
    ensure_code="$(printf '%s\n' "$output" | sed -n '1p')"
    [[ -n "$ensure_code" ]] || ensure_code="EVIDENCE_DIRECTORY_UNSAFE"
    echo "verification_status=rejected_unsafe_sandbox"
    echo "verification_code=$ensure_code"
    echo "authority_event_committed=false"
    echo "docker_invoked=$DOCKER_CLI_INVOKED"
    echo "poc_command_invoked=$POC_COMMAND_INVOKED"
    echo "oracle_matched=false"
    exit 1
  fi
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
  if ! python3 - "$SCRIPT_DIR" "$WORKSPACE_DIR" "$EVIDENCE_DIR" "$CASE_ID" "$MODE" "$status" "$reason" "$exit_code" "$oracle_matched" "$TIMEOUT_SECONDS" "$EXPECTED_ORACLE" "$IMAGE" "$NETWORK" "$MEMORY_LIMIT" "$CPU_LIMIT" "$PIDS_LIMIT" "$READ_ONLY" "$PULL_IF_MISSING" "$STDOUT_PATH" "$STDERR_PATH" "$COMMAND_JSON_PATH" "$DOCKER_CLI_INVOKED" "$POC_COMMAND_INVOKED" "$WRAPPER_STATUS" "$AUTHORITY_EVENT_COMMITTED" "$AUTHORITY_EVENT_ERROR_CODE" "$VERIFICATION_DIAGNOSTIC_CODE" "$LIFECYCLE_RECEIPT_SHA256" "$CLEANUP_ATTEMPTED" "$CLEANUP_VERIFIED" "$CLEANUP_CONTAINERS_BEFORE" "$CLEANUP_NETWORKS_BEFORE" "$CLEANUP_VOLUMES_BEFORE" "$CLEANUP_CONTAINERS_AFTER" "$CLEANUP_NETWORKS_AFTER" "$CLEANUP_VOLUMES_AFTER" "$CLEANUP_SETTLEMENT_CHECKS" "$LIFECYCLE_POLICY_JSON" <<'PY'
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
verification_code,
receipt_sha256,
cleanup_attempted,
cleanup_verified,
cleanup_containers_before,
cleanup_networks_before,
cleanup_volumes_before,
cleanup_containers_after,
cleanup_networks_after,
cleanup_volumes_after,
cleanup_settlement_checks,
resource_policy_json,
) = sys.argv[1:39]
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
    "docker_case_lifecycle": {
        "receipt_sha256": receipt_sha256,
        "cleanup_attempted": cleanup_attempted == "true",
        "cleanup_verified": cleanup_verified == "true",
        "residue_counts_before": {
            "containers": int(cleanup_containers_before),
            "networks": int(cleanup_networks_before),
            "volumes": int(cleanup_volumes_before),
        },
        "residue_counts_after": {
            "containers": int(cleanup_containers_after),
            "networks": int(cleanup_networks_after),
            "volumes": int(cleanup_volumes_after),
        },
        "settlement_checks": int(cleanup_settlement_checks),
        "resource_policy": json.loads(resource_policy_json),
    },
}
if wrapper_status:
    data["wrapper_status"] = wrapper_status
if authority_event_committed:
    data["authority_event_committed"] = authority_event_committed == "true"
if authority_event_error_code:
    data["authority_event_error_code"] = authority_event_error_code
if verification_code:
    data["verification_code"] = verification_code
data["resource_limits"] = {
    "policy_version": "docker-case-policy-v1",
    "memory": memory_limit,
    "cpus": cpu_limit,
    "pids_limit": int(pids_limit),
    "read_only_rootfs": read_only == "1",
    "managed_by_host_policy": True,
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
  local cleanup_failed="false"
  if ! ensure_case_cleanup; then
    status="rejected_unsafe_sandbox"
    reason="Docker case cleanup could not prove exact zero residue."
    oracle_matched="false"
    cleanup_failed="true"
    VERIFICATION_DIAGNOSTIC_CODE="DOCKER_CASE_CLEANUP_FAILED"
  fi
  if [[ "$MODE" == "docker-compose" && "$COMPOSE_PIN_ACTIVE" == "true" ]]; then
    if ! cleanup_pinned_compose; then
      status="rejected_unsafe_sandbox"
      reason="Pinned Compose input cleanup could not be verified before publication."
      oracle_matched="false"
      cleanup_failed="true"
      VERIFICATION_DIAGNOSTIC_CODE="COMPOSE_INPUT_CLEANUP_FAILED"
    fi
  fi
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
  if [[ -n "$VERIFICATION_DIAGNOSTIC_CODE" ]]; then
    echo "verification_code=$VERIFICATION_DIAGNOSTIC_CODE"
  fi
  if [[ "$cleanup_failed" == "true" ]]; then
    echo "oracle_matched=false"
  fi
  echo "evidence_dir=$EVIDENCE_DIR"
  echo "result_json=$EVIDENCE_DIR/verification-result.json"

  if [[ "$status" == "confirmed_in_docker" ]]; then
    exit 0
  fi
  exit 1
}

trap 'cleanup_wrapper_resources "$?"' EXIT
trap 'handle_wrapper_signal INT' INT
trap 'handle_wrapper_signal TERM' TERM
validate_resource_policy_or_abort
pin_compose_inputs
early_sandbox_preflight
ensure_host_evidence_directories
EVIDENCE_DIR="$(cd "$EVIDENCE_DIR" && pwd -P)"
CONTAINER_OUTPUT_DIR="$EVIDENCE_DIR/container-output"
STDOUT_PATH="$EVIDENCE_DIR/stdout.log"
STDERR_PATH="$EVIDENCE_DIR/stderr.log"
COMMAND_JSON_PATH="$EVIDENCE_DIR/command.json"
SANDBOX_PREFLIGHT_JSON="$EVIDENCE_DIR/sandbox-preflight.json"
prepare_case_lifecycle
prepare_output_handshake
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

prepare_compose_config_or_abort() {
  local lifecycle capture_payload capture_exit config_exit capture_integrity validation_payload validation_exit validation_code
  local config_path="$EVIDENCE_DIR/compose-config.json"
  local config_stderr="$EVIDENCE_DIR/compose-config.stderr.log"
  verify_pinned_compose_or_abort
  set +e
  capture_payload="$(python3 - "$SCRIPT_DIR" "$EVIDENCE_DIR" "$config_path" "$config_stderr" "${COMPOSE_ARGS[@]}" <<'PY'
import json
import sys
from pathlib import Path

script_dir, root_value, stdout_value, stderr_value = sys.argv[1:5]
command = ["docker", "compose", *sys.argv[5:], "config", "--format", "json"]
sys.path.insert(0, script_dir)
from evidence_io import SafeEvidenceError, run_captured_command
try:
    value = run_captured_command(
        Path(root_value), Path(stdout_value), Path(stderr_value), command,
        timeout=60, expected_oracle="",
    )
except SafeEvidenceError as exc:
    print(json.dumps({"ok": False, "code": exc.code}, sort_keys=True))
    raise SystemExit(3)
print(json.dumps({"ok": True, **value}, sort_keys=True))
PY
)"
  capture_exit=$?
  set -e
  verify_pinned_compose_or_abort
  if [[ "$capture_exit" -ne 0 ]]; then
    VERIFICATION_DIAGNOSTIC_CODE="COMPOSE_CONFIG_UNVERIFIABLE"
    write_empty_command_json
    classify_and_exit "rejected_unsafe_sandbox" "Merged Compose configuration could not be captured safely." "" "false"
  fi
  config_exit="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("exit_code", 127))' "$capture_payload")"
  capture_integrity="$(python3 -c 'import json,sys; print("true" if json.loads(sys.argv[1]).get("capture_integrity") is True else "false")' "$capture_payload")"
  if [[ "$config_exit" -ne 0 || "$capture_integrity" != "true" ]]; then
    VERIFICATION_DIAGNOSTIC_CODE="COMPOSE_CONFIG_UNVERIFIABLE"
    write_empty_command_json
    classify_and_exit "rejected_unsafe_sandbox" "Merged Compose configuration did not pass host-owned capture." "$config_exit" "false"
  fi
  lifecycle="$(find_case_lifecycle)"
  set +e
  validation_payload="$(python3 "$lifecycle" validate-config \
    --evidence-root "$EVIDENCE_DIR" \
    --receipt "$LIFECYCLE_RECEIPT_PATH" \
    --receipt-sha256 "$LIFECYCLE_RECEIPT_SHA256" \
    --override "$LIFECYCLE_OVERRIDE_PATH" \
    --config-json "$config_path")"
  validation_exit=$?
  set -e
  if [[ "$validation_exit" -ne 0 ]]; then
    validation_code="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("issue_code") or "COMPOSE_CONFIG_POLICY_MISMATCH")' "$validation_payload" 2>/dev/null || printf '%s' COMPOSE_CONFIG_POLICY_MISMATCH)"
    VERIFICATION_DIAGNOSTIC_CODE="$validation_code"
    write_empty_command_json
    classify_and_exit "rejected_unsafe_sandbox" "Merged Compose configuration failed the host resource policy." "" "false"
  fi
  IMAGE="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["selected_image"])' "$validation_payload")"
}

if [[ "$MODE" == "docker-compose" ]]; then
  verify_pinned_compose_or_abort
else
  verify_default_mounts_or_abort
fi

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
        docker pull "$IMAGE" >/dev/null 2>&1
        pull_exit=$?
        set -e
        if [[ "$pull_exit" -ne 0 ]]; then
          write_host_text "$STDERR_PATH" "The explicitly requested image pull failed."
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
      docker run
      --name "$LIFECYCLE_CONTAINER_NAME"
      --label "org.zhulong.managed=true"
      --label "org.zhulong.case=$LIFECYCLE_TOKEN"
      --label "org.zhulong.policy=docker-case-policy-v1"
      --label "org.zhulong.project=$LIFECYCLE_PROJECT_NAME"
      --label "org.zhulong.workspace=$WORKSPACE_LABEL"
      --memory "$MEMORY_LIMIT"
      --memory-swap "$MEMORY_LIMIT"
      --cpus "$CPU_LIMIT"
      --pids-limit "$PIDS_LIMIT"
      --restart no
      --cap-drop ALL
      --security-opt no-new-privileges
      --network "$NETWORK"
    )
    if [[ "$READ_ONLY" == "1" ]]; then
      RUN_COMMAND+=(--read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m)
    fi
    if [[ "$DEFAULT_MOUNTS" == "1" ]]; then
      python3 - "$SCRIPT_DIR" "$WORKSPACE_DIR" "$WORKSPACE_DIR/poc" <<'PY'
import sys
from pathlib import Path

script_dir, root_value, poc_value = sys.argv[1:]
sys.path.insert(0, script_dir)
from evidence_io import ensure_host_directory

root = Path(root_value)
ensure_host_directory(root, Path(poc_value))
PY
      RUN_COMMAND+=(
        --mount "type=bind,source=$WORKSPACE_DIR/poc,target=/workspace/poc,readonly"
        --mount "type=bind,source=$EVIDENCE_DIR,target=/workspace/evidence,readonly"
        --tmpfs "$OUTPUT_TMPFS_SPEC"
        --workdir /workspace/poc
      )
    fi
    RUN_COMMAND+=("$IMAGE")
    if [[ "$DEFAULT_MOUNTS" == "1" ]]; then
      RUN_COMMAND+=(sh -c "$OUTPUT_SCRIPT")
    elif [[ "${#CASE_COMMAND[@]}" -gt 0 ]]; then
      RUN_COMMAND+=("${CASE_COMMAND[@]}")
    fi
    ;;
  docker-compose)
    COMPOSE_ARGS=(-p "$LIFECYCLE_PROJECT_NAME" --project-directory "$WORKSPACE_DIR")
    for compose_file in "${COMPOSE_FILES[@]}"; do
      COMPOSE_ARGS+=(-f "$compose_file")
    done
    COMPOSE_ARGS+=(-f "$LIFECYCLE_OVERRIDE_PATH")
    prepare_compose_config_or_abort
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
      if [[ "$PULL_IF_MISSING" == "1" ]]; then
        verify_pinned_compose_or_abort
        set +e
        docker compose "${COMPOSE_ARGS[@]}" pull "$COMPOSE_SERVICE" >/dev/null 2>&1
        pull_exit=$?
        set -e
        verify_pinned_compose_or_abort
        if [[ "$pull_exit" -ne 0 ]]; then
          write_host_text "$STDERR_PATH" "Compose image pull failed for the selected service."
          write_empty_command_json
          classify_and_exit "blocked_missing_image" "The selected Compose image is missing locally and explicit pull failed."
        fi
        prepare_compose_config_or_abort
        if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
          write_host_text "$STDERR_PATH" "Selected Compose image is still missing after the explicit pull attempt."
          write_empty_command_json
          classify_and_exit "blocked_missing_image" "The selected Compose image remains missing after explicit pull."
        fi
      else
        write_host_text "$STDERR_PATH" "The selected Compose image is missing locally."
        write_empty_command_json
        classify_and_exit "blocked_missing_image" "The selected Compose image is missing locally; rerun with --pull-if-missing only if network pull is acceptable."
      fi
    fi
    verify_pinned_compose_or_abort
    prepare_compose_config_or_abort
    RUN_COMMAND=(docker compose "${COMPOSE_ARGS[@]}" run --no-deps --name "$LIFECYCLE_CONTAINER_NAME" -T \
      --label "org.zhulong.managed=true" \
      --label "org.zhulong.case=$LIFECYCLE_TOKEN" \
      --label "org.zhulong.policy=docker-case-policy-v1" \
      --label "org.zhulong.project=$LIFECYCLE_PROJECT_NAME" \
      "$COMPOSE_SERVICE")
    if [[ "$DEFAULT_MOUNTS" == "1" ]]; then
      RUN_COMMAND+=(sh -c "$OUTPUT_SCRIPT")
    elif [[ "${#CASE_COMMAND[@]}" -gt 0 ]]; then
      RUN_COMMAND+=("${CASE_COMMAND[@]}")
    fi
    ;;
esac

verify_pinned_compose_or_abort
write_command_json "${RUN_COMMAND[@]}"

# This is not an automatic retry: it is recorded only after an operator
# explicitly invokes this helper again and the Docker/image/sandbox
# prerequisites for that new attempt have passed.
if ! resume_verification_if_blocked; then
  emit_authority_preexecution_blocker \
    "${AUTHORITY_EVENT_ERROR_CODE:-VERIFICATION_RESUME_EVENT_COMMIT_FAILED}" \
    "The explicit verification retry could not be committed; no PoC container command was started."
fi
verify_pinned_compose_or_abort
if ! commit_verification_start_event; then
  emit_authority_preexecution_blocker \
    "${AUTHORITY_EVENT_ERROR_CODE:-VERIFICATION_START_EVENT_COMMIT_FAILED}" \
    "The verification start event could not be committed; no PoC container command was started."
fi

POC_COMMAND_INVOKED="true"
DOCKER_CASE_MAY_EXIST="true"
CAPTURE_RESPONSE_PATH="$EVIDENCE_DIR/capture-response.json"
CAPTURE_LAUNCH_STATE="launching"
set +e
python3 - "$SCRIPT_DIR" "$WORKSPACE_DIR" "$EVIDENCE_DIR" "$CAPTURE_RESPONSE_PATH" "$STDOUT_PATH" "$STDERR_PATH" "$TIMEOUT_SECONDS" "$EXPECTED_ORACLE" "$OUTPUT_READY_MARKER" "$LIFECYCLE_RECEIPT_PATH" "$LIFECYCLE_RECEIPT_SHA256" "$CONTAINER_OUTPUT_DIR" "${RUN_COMMAND[@]}" <<'PY' &
import json
import subprocess
import sys
from pathlib import Path

script_dir, root_value, evidence_root, response_value, stdout_value, stderr_value, timeout_value, oracle_value, completion_marker, receipt_path, receipt_digest, output_dir = sys.argv[1:13]
command = sys.argv[13:]
sys.path.insert(0, script_dir)
from evidence_io import SafeEvidenceError, atomic_write_json, run_captured_command

def import_output(_exit_code: int) -> None:
    if not completion_marker:
        return
    lifecycle = str(Path(script_dir) / "docker_case_lifecycle.py")
    result = subprocess.run(
        [sys.executable, lifecycle, "import-output", "--evidence-root", evidence_root,
         "--receipt", receipt_path, "--receipt-sha256", receipt_digest,
         "--output-dir", output_dir, "--docker", "docker"],
        check=False, capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        try:
            code = json.loads(result.stdout).get("issue_code") or "EVIDENCE_OUTPUT_IMPORT_FAILED"
        except (TypeError, json.JSONDecodeError):
            code = "EVIDENCE_OUTPUT_IMPORT_FAILED"
        raise SafeEvidenceError(code, "bounded container output import failed")

try:
    result = run_captured_command(
        Path(root_value),
        Path(stdout_value),
        Path(stderr_value),
        command,
        timeout=int(timeout_value),
        expected_oracle=oracle_value,
        completion_marker=completion_marker or None,
        on_completion=import_output if completion_marker else None,
    )
except SafeEvidenceError as exc:
    atomic_write_json(Path(evidence_root), Path(response_value), {"ok": False, "code": exc.code})
    raise SystemExit(3)
atomic_write_json(Path(evidence_root), Path(response_value), {"ok": True, **result})
PY
CAPTURE_HELPER_PID=$!
CAPTURE_LAUNCH_STATE="active"
if [[ -n "$PENDING_SIGNAL" ]]; then
  pending_signal="$PENDING_SIGNAL"
  PENDING_SIGNAL=""
  kill -"$pending_signal" "$CAPTURE_HELPER_PID" >/dev/null 2>&1 || true
fi
wait "$CAPTURE_HELPER_PID"
CAPTURE_HELPER_EXIT=$?
CAPTURE_HELPER_PID=""
CAPTURE_LAUNCH_STATE="idle"
set -e
set +e
CAPTURE_RESULT="$(python3 - "$SCRIPT_DIR" "$EVIDENCE_DIR" "$CAPTURE_RESPONSE_PATH" <<'PY'
import json
import sys
from pathlib import Path
script_dir, root_value, path_value = sys.argv[1:]
sys.path.insert(0, script_dir)
from evidence_io import SafeEvidenceError, safe_read_json
try:
    print(json.dumps(safe_read_json(Path(root_value), Path(path_value)), sort_keys=True))
except SafeEvidenceError:
    raise SystemExit(1)
PY
  )"
  CAPTURE_READ_EXIT=$?
  set -e
  if [[ "$CAPTURE_READ_EXIT" -ne 0 ]]; then
  CAPTURE_RESULT='{"ok":false,"code":"EVIDENCE_CAPTURE_FAILED"}'
  CAPTURE_HELPER_EXIT=3
fi
verify_pinned_compose_or_abort
if [[ "$CAPTURE_HELPER_EXIT" -ne 0 ]]; then
  capture_code="$(python3 - "$CAPTURE_RESULT" <<'PY'
import json
import sys
try:
    print(json.loads(sys.argv[1]).get("code") or "EVIDENCE_CAPTURE_FAILED")
except Exception:
    print("EVIDENCE_CAPTURE_FAILED")
PY
)"
  if [[ "$capture_code" == "EVIDENCE_SIZE_LIMIT" ]]; then
    VERIFICATION_DIAGNOSTIC_CODE="$capture_code"
    classify_and_exit "failed_resource_limit" "Docker stdout/stderr exceeded the host-owned bounded capture limit." "" "false"
  fi
  if [[ "$capture_code" == "EVIDENCE_OUTPUT_LIMIT" ]]; then
    VERIFICATION_DIAGNOSTIC_CODE="$capture_code"
    classify_and_exit "failed_resource_limit" "Container output exceeded the host-owned bounded import limit." "" "false"
  fi
  if [[ "$capture_code" == EVIDENCE_OUTPUT_* || "$capture_code" == "EVIDENCE_COMPLETION_MARKER_MISSING" ]]; then
    VERIFICATION_DIAGNOSTIC_CODE="$capture_code"
    classify_and_exit "rejected_unsafe_sandbox" "Container output could not be imported through the host-owned bounded staging path." "" "false"
  fi
  CONTROL_EVIDENCE_UNSAFE="true"
  POC_COMMAND_INVOKED="false"
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
