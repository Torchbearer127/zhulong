#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bootstrap_verification_workspace.sh --target-dir /path/to/repo [--workspace-name security-research-YYYYMMDD-HHMMSS] [--output-language zh-CN|en-US] [--summary-language zh-CN|en-US] [--force]

Purpose:
  Create a Docker-first vulnerability verification workspace under the target repository.

What it creates:
  <target>/<workspace-name>/
    asr-config.json
    stage-status.json
    audit-events.jsonl
    fingerprint.md
    attack-surface.md
    handoff-summary.md
    candidate-findings.md
    false-positives.md
    unverified-leads.md
    bin/
      asr-start.sh
      asr-exec.sh
      check-docker-gate.sh
      check_omc_runtime.sh
      check_security_tooling.sh
      validate-tool-registry.py
      tool-registry.json
      tool-registry.schema.json
      run-initial-probes.sh
      run-verification-case.sh
      manage-docker-resources.py
      render-handoff-summary.py
      render-handoff-state.py
      validate-handoff-state.py
      render-next-actions.py
      validate-next-actions.py
      render-audit-timeline.py
      validate-audit-timeline.py
      create-workspace-checkpoint.py
      validate-workspace-checkpoint.py
      plan-security-toolchain.py
      scaffold-bilingual-findings.py
      validate-report-bundle.py
      validate-all-report-bundles.py
      write-audit-event.py
      validate-workspace-state.py
      assert-finalized-workspace.py
    scripts/
      asr-start.sh
      asr-exec.sh
      check-docker-gate.sh
      check_omc_runtime.sh
      check_security_tooling.sh
      validate-tool-registry.py
      run-initial-probes.sh
      run-verification-case.sh
      manage-docker-resources.py
      render-handoff-summary.py
      render-handoff-state.py
      validate-handoff-state.py
      render-next-actions.py
      validate-next-actions.py
      render-audit-timeline.py
      validate-audit-timeline.py
      create-workspace-checkpoint.py
      validate-workspace-checkpoint.py
      plan-security-toolchain.py
      scaffold-bilingual-findings.py
      validate-report-bundle.py
      validate-all-report-bundles.py
      write-audit-event.py
      validate-workspace-state.py
      assert-finalized-workspace.py
    poc/
    evidence/
    docker/
      attacker-container/
        Dockerfile
      docker-compose.attacker.yml
    confirmed/
      findings.example.json
      confirmed-vuln-report-template.docx

Notes:
  - PoCs must still be executed inside Docker, never on the host.
  - Existing files are preserved unless --force is supplied.
EOF
}

TARGET_DIR=""
WORKSPACE_NAME=""
WORKSPACE_NAME_EXPLICIT="0"
OUTPUT_LANGUAGE="zh-CN"
SUMMARY_LANGUAGE="zh-CN"
FORCE="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-dir)
      TARGET_DIR="${2:-}"
      shift 2
      ;;
    --workspace-name)
      WORKSPACE_NAME="${2:-}"
      WORKSPACE_NAME_EXPLICIT="1"
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
    --force)
      FORCE="1"
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

if [[ -z "$TARGET_DIR" ]]; then
  echo "--target-dir is required." >&2
  usage >&2
  exit 1
fi

if [[ ! -d "$TARGET_DIR" ]]; then
  echo "Target directory does not exist: $TARGET_DIR" >&2
  exit 1
fi

generate_workspace_name() {
  local target_dir="$1"
  local stamp base candidate suffix
  stamp="$(date '+%Y%m%d-%H%M%S')"
  base="security-research-$stamp"
  candidate="$base"
  suffix=1
  while [[ -e "$target_dir/$candidate" ]]; do
    candidate="${base}-${suffix}"
    suffix=$((suffix + 1))
  done
  printf '%s\n' "$candidate"
}

normalize_language() {
  local raw
  raw="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$raw" in
    zh|zh-cn|zh-hans|cn|chinese|"中文")
      printf 'zh-CN\n'
      ;;
    en|en-us|en-gb|english|"英文")
      printf 'en-US\n'
      ;;
    "")
      printf 'zh-CN\n'
      ;;
    *)
      echo "Unsupported language: $1" >&2
      echo "Use zh-CN or en-US." >&2
      exit 1
      ;;
  esac
}

OUTPUT_LANGUAGE="$(normalize_language "$OUTPUT_LANGUAGE")"
SUMMARY_LANGUAGE="$(normalize_language "$SUMMARY_LANGUAGE")"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
if [[ -L "$TARGET_DIR" ]]; then
  echo "Target directory must not be a symlink." >&2
  exit 2
fi
TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
if [[ "$WORKSPACE_NAME_EXPLICIT" == "1" && -z "$WORKSPACE_NAME" ]]; then
  echo "--workspace-name must not be empty." >&2
  exit 2
fi
if [[ -z "$WORKSPACE_NAME" ]]; then
  WORKSPACE_NAME="$(generate_workspace_name "$TARGET_DIR")"
fi

validate_workspace_destination() {
  python3 - "$TARGET_DIR" "$WORKSPACE_NAME" <<'PY'
import os
import re
import stat
import sys
from pathlib import Path

target = Path(sys.argv[1])
name = sys.argv[2]
if not (1 <= len(name) <= 128):
    raise SystemExit("workspace name must contain 1..128 characters")
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
    raise SystemExit("workspace name must be one stable ASCII directory component")
if name in {".", ".."} or name.startswith("."):
    raise SystemExit("workspace name must not be dot-prefixed")

target_info = os.lstat(target)
if stat.S_ISLNK(target_info.st_mode) or not stat.S_ISDIR(target_info.st_mode):
    raise SystemExit("target directory must be a real directory")
candidate = target / name
if candidate.parent != target:
    raise SystemExit("workspace must be a direct child of the target directory")
try:
    candidate_info = os.lstat(candidate)
except FileNotFoundError:
    candidate_info = None
if candidate_info is not None:
    if stat.S_ISLNK(candidate_info.st_mode):
        raise SystemExit("workspace destination must not be a symlink")
    if not stat.S_ISDIR(candidate_info.st_mode):
        raise SystemExit("existing workspace destination must be a real directory")

latest = target / ".asr-latest-workspace"
try:
    latest_info = os.lstat(latest)
except FileNotFoundError:
    latest_info = None
if latest_info is not None and (stat.S_ISLNK(latest_info.st_mode) or not stat.S_ISREG(latest_info.st_mode)):
    raise SystemExit(".asr-latest-workspace must be absent or a regular file")
PY
}

if ! validate_workspace_destination; then
  echo "Unsafe --workspace-name or workspace destination; no workspace files were created." >&2
  exit 2
fi

PLUGIN_VERSION="$(python3 - <<'PY' "$SKILL_DIR/.codex-plugin/plugin.json"
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    print(json.loads(path.read_text(encoding="utf-8")).get("version", "unknown"))
except Exception:
    print("unknown")
PY
)"
WORKSPACE_DIR="$TARGET_DIR/$WORKSPACE_NAME"

copy_file() {
  local src="$1"
  local dst="$2"

  mkdir -p "$(dirname "$dst")"
  if [[ -e "$dst" && "$FORCE" != "1" ]]; then
    echo "preserve $dst"
    return
  fi
  cp "$src" "$dst"
  echo "write    $dst"
}

write_text_file() {
  local dst="$1"
  local content="$2"

  mkdir -p "$(dirname "$dst")"
  if [[ -e "$dst" && "$FORCE" != "1" ]]; then
    echo "preserve $dst"
    return
  fi
  printf '%s' "$content" > "$dst"
  echo "write    $dst"
}

write_state_event() {
  local writer="$SKILL_DIR/scripts/write_audit_event.py"
  [[ -f "$writer" ]] || return 0
  python3 "$writer" "$@" --accept-current-revision >/dev/null
}

mkdir -p \
  "$WORKSPACE_DIR/bin" \
  "$WORKSPACE_DIR/scripts" \
  "$WORKSPACE_DIR/docker/attacker-container" \
  "$WORKSPACE_DIR/poc" \
  "$WORKSPACE_DIR/evidence" \
  "$WORKSPACE_DIR/confirmed"

write_text_file "$WORKSPACE_DIR/fingerprint.md" "# Fingerprint\n\n- Stack:\n- Frameworks:\n- Entrypoints:\n- Sources:\n- Sinks:\n- Verification constraints:\n"
write_text_file "$WORKSPACE_DIR/attack-surface.md" "# Attack Surface Handoff\n\nThis is a concise handoff artifact for audit continuity. It is not a vulnerability report, not raw scanner output, and not a replacement for candidate-findings.md, false-positives.md, unverified-leads.md, or confirmed bundles.\n\n## Repository / Stack Summary\n\n- Repository:\n- Detected stack:\n- Frameworks:\n- Runtime / deployment notes:\n\n## External Entry Points\n\n| ID | Route / Command / API | Method | Handler / Controller | Auth Required | Input Sources | Downstream Sink / Service | Current Verification Status | Notes |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n\n## Trusted and Untrusted Input Sources / Trust Boundaries\n\n- Trusted sources:\n- Untrusted sources:\n- Boundary assumptions to verify:\n\n## Auth / Session / Permission Boundaries\n\n- Authentication mechanism:\n- Session / token handling:\n- Authorization checks:\n- Sensitive routes or roles:\n\n## High-Risk Sinks\n\n| ID | Sink Type | File / Function | Controlled Input | Current Evidence | Status |\n| --- | --- | --- | --- | --- | --- |\n\n## Source-to-Sink Hypotheses\n\n| ID | Source | Sink | Hypothesis | Missing Evidence | Docker Verification Status | Routing |\n| --- | --- | --- | --- | --- | --- | --- |\n\n## Docker Verification Status\n\n- Docker gate:\n- Running service target:\n- Verified commands / evidence paths:\n- Still blocked or missing:\n\n## Confirmed / False-Positive / Unverified Routing Reminder\n\n- Confirmed vulnerabilities require Docker reproduction and belong only under confirmed/<one-folder-per-vulnerability>/.\n- False positives and non-security defects stay in false-positives.md.\n- Plausible but unconfirmed leads stay in candidate-findings.md or unverified-leads.md.\n- Do not generate DOCX reports from attack-surface hypotheses.\n\n## Next Safe Audit Steps\n\n1. \n"
write_text_file "$WORKSPACE_DIR/candidate-findings.md" "# Candidate Findings\n\nCandidates are not confirmed vulnerabilities. Static scanning, source-to-sink reasoning, pattern matching, and LLM analysis can only add rows here until Docker confirmation succeeds.\n\n| Candidate ID | Suspected Weakness | Evidence So Far | Source-to-Sink Hypothesis | Docker Verification Plan | Status |\n| --- | --- | --- | --- | --- | --- |\n"
write_text_file "$WORKSPACE_DIR/false-positives.md" "# False Positives and Non-Security Defects\n\nRejected candidates stay here as workspace records. They must not be moved into confirmed/ and must not generate DOCX reports.\n\n| Candidate ID | Original Suspicion | Evidence Reviewed | Rejection Reason | Docker Verification Status | Next Action |\n| --- | --- | --- | --- | --- | --- |\n"
write_text_file "$WORKSPACE_DIR/unverified-leads.md" "# Unverified Leads\n\nPlausible but not Docker-confirmed leads stay here or in candidate-findings.md. They must not be moved into confirmed/, must not generate DOCX reports, and must not appear as confirmed vulnerabilities in the final summary.\n\n| Lead ID | Suspected Weakness | Evidence So Far | Missing Evidence | Docker Confirmation Status | Safe Resume Step | High-Confidence-Unverified? | Material blocker? | Default runtime scope? | Why completion is still safe? |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"
workspace_created_at="$(date '+%Y-%m-%d %H:%M:%S %z')"
write_text_file "$WORKSPACE_DIR/asr-config.json" "{
  \"output_language\": \"$OUTPUT_LANGUAGE\",
  \"summary_language\": \"$SUMMARY_LANGUAGE\",
  \"plugin_version\": \"$PLUGIN_VERSION\",
  \"workspace_root\": \"$WORKSPACE_NAME\",
  \"workspace_label\": \"security-research\",
  \"workspace_created_at\": \"$workspace_created_at\",
  \"project_root_name\": \"$(basename "$TARGET_DIR")\",
  \"confirmed_output_dir\": \"$WORKSPACE_NAME/confirmed\",
  \"forbidden_legacy_outputs\": [
    \"$WORKSPACE_NAME/vulnerability-packages\",
    \"$WORKSPACE_NAME/vulnerability-analysis\",
    \"$WORKSPACE_NAME/SECURITY-RESEARCH-SUMMARY.md\"
  ]
}
"
python3 - "$TARGET_DIR/.asr-latest-workspace" "$WORKSPACE_NAME" <<'PY'
import os
import stat
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
value = sys.argv[2]
try:
    info = os.lstat(path)
except FileNotFoundError:
    info = None
if info is not None and (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)):
    raise SystemExit(".asr-latest-workspace became unsafe")
fd, temporary = tempfile.mkstemp(prefix=".asr-latest-workspace.tmp-", dir=path.parent)
try:
    os.fchmod(fd, 0o600)
    os.write(fd, (value + "\n").encode("utf-8"))
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(temporary, path)
    temporary = ""
finally:
    if fd >= 0:
        os.close(fd)
    if temporary:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
PY
echo "write    $TARGET_DIR/.asr-latest-workspace"

write_state_event \
  --workspace-dir "$WORKSPACE_DIR" \
  --target-repo "$TARGET_DIR" \
  --plugin-version "$PLUGIN_VERSION" \
  --event workspace_created \
  --stage workspace_preparing \
  --status running \
  --transition-kind start \
  --event-status ok \
  --message "Audit workspace created." \
  --detail "workspace_name=$WORKSPACE_NAME"

copy_file \
  "$SKILL_DIR/scripts/asr_start.sh" \
  "$WORKSPACE_DIR/bin/asr-start.sh"
chmod +x "$WORKSPACE_DIR/bin/asr-start.sh"
write_text_file "$WORKSPACE_DIR/scripts/asr-start.sh" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/../bin/asr-start.sh" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/asr-start.sh"
copy_file \
  "$SKILL_DIR/scripts/asr_exec.sh" \
  "$WORKSPACE_DIR/bin/asr-exec.sh"
chmod +x "$WORKSPACE_DIR/bin/asr-exec.sh"
write_text_file "$WORKSPACE_DIR/scripts/asr-exec.sh" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/../bin/asr-exec.sh" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/asr-exec.sh"
copy_file \
  "$SKILL_DIR/scripts/check_docker_gate.sh" \
  "$WORKSPACE_DIR/bin/check-docker-gate.sh"
chmod +x "$WORKSPACE_DIR/bin/check-docker-gate.sh"
write_text_file "$WORKSPACE_DIR/scripts/check-docker-gate.sh" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/../bin/check-docker-gate.sh" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/check-docker-gate.sh"
copy_file \
  "$SKILL_DIR/scripts/check_omc_runtime.sh" \
  "$WORKSPACE_DIR/bin/check_omc_runtime.sh"
chmod +x "$WORKSPACE_DIR/bin/check_omc_runtime.sh"
write_text_file "$WORKSPACE_DIR/scripts/check_omc_runtime.sh" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/../bin/check_omc_runtime.sh" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/check_omc_runtime.sh"
copy_file \
  "$SKILL_DIR/scripts/check_sandbox_preflight.py" \
  "$WORKSPACE_DIR/bin/check-sandbox-preflight.py"
chmod +x "$WORKSPACE_DIR/bin/check-sandbox-preflight.py"
write_text_file "$WORKSPACE_DIR/scripts/check-sandbox-preflight.py" '#!/usr/bin/env bash
# zhulong-tool-contract: sandbox-preflight-v1
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/check-sandbox-preflight.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/check-sandbox-preflight.py"
copy_file \
  "$SKILL_DIR/scripts/validate_tool_registry.py" \
  "$WORKSPACE_DIR/bin/validate_tool_registry.py"
chmod +x "$WORKSPACE_DIR/bin/validate_tool_registry.py"
write_text_file "$WORKSPACE_DIR/scripts/validate-tool-registry.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/validate_tool_registry.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/validate-tool-registry.py"
copy_file \
  "$SKILL_DIR/assets/tool-registry.json" \
  "$WORKSPACE_DIR/bin/tool-registry.json"
copy_file \
  "$SKILL_DIR/assets/schemas/tool-registry.schema.json" \
  "$WORKSPACE_DIR/bin/tool-registry.schema.json"
copy_file \
  "$SKILL_DIR/scripts/check_security_tooling.sh" \
  "$WORKSPACE_DIR/bin/check_security_tooling.sh"
chmod +x "$WORKSPACE_DIR/bin/check_security_tooling.sh"
write_text_file "$WORKSPACE_DIR/scripts/check_security_tooling.sh" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/../bin/check_security_tooling.sh" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/check_security_tooling.sh"
copy_file \
  "$SKILL_DIR/scripts/run_initial_probes.sh" \
  "$WORKSPACE_DIR/bin/run-initial-probes.sh"
chmod +x "$WORKSPACE_DIR/bin/run-initial-probes.sh"
write_text_file "$WORKSPACE_DIR/scripts/run-initial-probes.sh" '#!/usr/bin/env bash
# zhulong-tool-contract: initial-probes-v1
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/../bin/run-initial-probes.sh" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/run-initial-probes.sh"
copy_file \
  "$SKILL_DIR/scripts/run_verification_case.sh" \
  "$WORKSPACE_DIR/bin/run-verification-case.sh"
chmod +x "$WORKSPACE_DIR/bin/run-verification-case.sh"
copy_file \
  "$SKILL_DIR/scripts/evidence_io.py" \
  "$WORKSPACE_DIR/bin/evidence_io.py"
write_text_file "$WORKSPACE_DIR/scripts/run-verification-case.sh" '#!/usr/bin/env bash
# zhulong-tool-contract: docker-verification-v1; timeout=mandatory; sandbox-preflight=mandatory
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/../bin/run-verification-case.sh" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/run-verification-case.sh"
copy_file \
  "$SKILL_DIR/scripts/manage_docker_resources.py" \
  "$WORKSPACE_DIR/bin/manage-docker-resources.py"
chmod +x "$WORKSPACE_DIR/bin/manage-docker-resources.py"
write_text_file "$WORKSPACE_DIR/scripts/manage-docker-resources.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/manage-docker-resources.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/manage-docker-resources.py"
copy_file \
  "$SKILL_DIR/scripts/render_handoff_summary.py" \
  "$WORKSPACE_DIR/bin/render-handoff-summary.py"
chmod +x "$WORKSPACE_DIR/bin/render-handoff-summary.py"
copy_file \
  "$SKILL_DIR/scripts/workspace_state.py" \
  "$WORKSPACE_DIR/bin/workspace_state.py"
copy_file "$SKILL_DIR/scripts/render_handoff_state.py" "$WORKSPACE_DIR/bin/render-handoff-state.py"
copy_file "$SKILL_DIR/scripts/validate_handoff_state.py" "$WORKSPACE_DIR/bin/validate-handoff-state.py"
copy_file "$SKILL_DIR/scripts/next_actions.py" "$WORKSPACE_DIR/bin/next_actions.py"
copy_file "$SKILL_DIR/scripts/render_next_actions.py" "$WORKSPACE_DIR/bin/render-next-actions.py"
copy_file "$SKILL_DIR/scripts/validate_next_actions.py" "$WORKSPACE_DIR/bin/validate-next-actions.py"
copy_file "$SKILL_DIR/scripts/audit_timeline.py" "$WORKSPACE_DIR/bin/audit_timeline.py"
copy_file "$SKILL_DIR/scripts/render_audit_timeline.py" "$WORKSPACE_DIR/bin/render-audit-timeline.py"
copy_file "$SKILL_DIR/scripts/validate_audit_timeline.py" "$WORKSPACE_DIR/bin/validate-audit-timeline.py"
copy_file "$SKILL_DIR/assets/schemas/audit-timeline.schema.json" "$WORKSPACE_DIR/bin/audit-timeline.schema.json"
copy_file "$SKILL_DIR/assets/schemas/audit-timeline.schema.json" "$WORKSPACE_DIR/assets/schemas/audit-timeline.schema.json"
copy_file "$SKILL_DIR/scripts/create_workspace_checkpoint.py" "$WORKSPACE_DIR/bin/create-workspace-checkpoint.py"
copy_file "$SKILL_DIR/scripts/validate_workspace_checkpoint.py" "$WORKSPACE_DIR/bin/validate-workspace-checkpoint.py"
copy_file "$SKILL_DIR/assets/schemas/handoff-state.schema.json" "$WORKSPACE_DIR/bin/handoff-state.schema.json"
copy_file "$SKILL_DIR/assets/schemas/workspace-checkpoint.schema.json" "$WORKSPACE_DIR/bin/workspace-checkpoint.schema.json"
copy_file "$SKILL_DIR/assets/schemas/next-actions.schema.json" "$WORKSPACE_DIR/bin/next-actions.schema.json"
write_text_file "$WORKSPACE_DIR/scripts/render-handoff-summary.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/render-handoff-summary.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/render-handoff-summary.py"
write_text_file "$WORKSPACE_DIR/scripts/render-handoff-state.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/render-handoff-state.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/render-handoff-state.py"
write_text_file "$WORKSPACE_DIR/scripts/validate-handoff-state.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/validate-handoff-state.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/validate-handoff-state.py"
write_text_file "$WORKSPACE_DIR/scripts/render-next-actions.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/render-next-actions.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/render-next-actions.py"
write_text_file "$WORKSPACE_DIR/scripts/validate-next-actions.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/validate-next-actions.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/validate-next-actions.py"
write_text_file "$WORKSPACE_DIR/scripts/render-audit-timeline.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/render-audit-timeline.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/render-audit-timeline.py"
write_text_file "$WORKSPACE_DIR/scripts/validate-audit-timeline.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/validate-audit-timeline.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/validate-audit-timeline.py"
write_text_file "$WORKSPACE_DIR/scripts/create-workspace-checkpoint.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/create-workspace-checkpoint.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/create-workspace-checkpoint.py"
write_text_file "$WORKSPACE_DIR/scripts/validate-workspace-checkpoint.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/validate-workspace-checkpoint.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/validate-workspace-checkpoint.py"
copy_file \
  "$SKILL_DIR/scripts/plan_security_toolchain.py" \
  "$WORKSPACE_DIR/bin/plan-security-toolchain.py"
chmod +x "$WORKSPACE_DIR/bin/plan-security-toolchain.py"
write_text_file "$WORKSPACE_DIR/scripts/plan-security-toolchain.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/plan-security-toolchain.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/plan-security-toolchain.py"
copy_file \
  "$SKILL_DIR/scripts/scaffold_bilingual_findings.py" \
  "$WORKSPACE_DIR/bin/scaffold-bilingual-findings.py"
chmod +x "$WORKSPACE_DIR/bin/scaffold-bilingual-findings.py"
write_text_file "$WORKSPACE_DIR/scripts/scaffold-bilingual-findings.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/scaffold-bilingual-findings.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/scaffold-bilingual-findings.py"
copy_file \
  "$SKILL_DIR/scripts/render_confirmed_vuln_docx.py" \
  "$WORKSPACE_DIR/bin/render-confirmed-vuln-docx.py"
chmod +x "$WORKSPACE_DIR/bin/render-confirmed-vuln-docx.py"
write_text_file "$WORKSPACE_DIR/scripts/render-confirmed-vuln-docx.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/render-confirmed-vuln-docx.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/render-confirmed-vuln-docx.py"
copy_file \
  "$SKILL_DIR/scripts/validate_report_bundle.py" \
  "$WORKSPACE_DIR/bin/validate-report-bundle.py"
chmod +x "$WORKSPACE_DIR/bin/validate-report-bundle.py"
write_text_file "$WORKSPACE_DIR/scripts/validate-report-bundle.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/validate-report-bundle.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/validate-report-bundle.py"
copy_file \
  "$SKILL_DIR/scripts/extract_variant_seed.py" \
  "$WORKSPACE_DIR/bin/extract_variant_seed.py"
chmod +x "$WORKSPACE_DIR/bin/extract_variant_seed.py"
write_text_file "$WORKSPACE_DIR/scripts/extract_variant_seed.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/extract_variant_seed.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/extract_variant_seed.py"
copy_file \
  "$SKILL_DIR/scripts/find_variant_candidates.py" \
  "$WORKSPACE_DIR/bin/find_variant_candidates.py"
chmod +x "$WORKSPACE_DIR/bin/find_variant_candidates.py"
write_text_file "$WORKSPACE_DIR/scripts/find_variant_candidates.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/find_variant_candidates.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/find_variant_candidates.py"
copy_file \
  "$SKILL_DIR/scripts/validate_all_report_bundles.py" \
  "$WORKSPACE_DIR/bin/validate-all-report-bundles.py"
chmod +x "$WORKSPACE_DIR/bin/validate-all-report-bundles.py"
write_text_file "$WORKSPACE_DIR/scripts/validate-all-report-bundles.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/validate-all-report-bundles.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/validate-all-report-bundles.py"
copy_file \
  "$SKILL_DIR/scripts/write_audit_event.py" \
  "$WORKSPACE_DIR/bin/write-audit-event.py"
chmod +x "$WORKSPACE_DIR/bin/write-audit-event.py"
copy_file \
  "$SKILL_DIR/scripts/audit_state_io.py" \
  "$WORKSPACE_DIR/bin/audit_state_io.py"
copy_file \
  "$SKILL_DIR/scripts/audit_text_safety.py" \
  "$WORKSPACE_DIR/bin/audit_text_safety.py"
copy_file \
  "$SKILL_DIR/scripts/audit_transition_policy.py" \
  "$WORKSPACE_DIR/bin/audit_transition_policy.py"
copy_file \
  "$SKILL_DIR/scripts/validate_audit_protocol.py" \
  "$WORKSPACE_DIR/bin/validate_audit_protocol.py"
copy_file \
  "$SKILL_DIR/scripts/recover_audit_state.py" \
  "$WORKSPACE_DIR/bin/recover-audit-state.py"
chmod +x "$WORKSPACE_DIR/bin/recover-audit-state.py"
write_text_file "$WORKSPACE_DIR/scripts/write-audit-event.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/write-audit-event.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/write-audit-event.py"
write_text_file "$WORKSPACE_DIR/scripts/recover-audit-state.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/recover-audit-state.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/recover-audit-state.py"
copy_file \
  "$SKILL_DIR/scripts/validate_workspace_state.py" \
  "$WORKSPACE_DIR/bin/validate-workspace-state.py"
chmod +x "$WORKSPACE_DIR/bin/validate-workspace-state.py"
copy_file \
  "$SKILL_DIR/scripts/workspace_state.py" \
  "$WORKSPACE_DIR/bin/workspace_state.py"
copy_file \
  "$SKILL_DIR/scripts/validate_recon_result.py" \
  "$WORKSPACE_DIR/bin/validate_recon_result.py"
copy_file \
  "$SKILL_DIR/scripts/validate_recon_result.py" \
  "$WORKSPACE_DIR/bin/validate-recon-result.py"
copy_file \
  "$SKILL_DIR/scripts/validate_triage_batch.py" \
  "$WORKSPACE_DIR/bin/validate-triage-batch.py"
copy_file \
  "$SKILL_DIR/assets/schemas/recon-result.schema.json" \
  "$WORKSPACE_DIR/assets/schemas/recon-result.schema.json"
copy_file \
  "$SKILL_DIR/assets/schemas/triage-batch.schema.json" \
  "$WORKSPACE_DIR/assets/schemas/triage-batch.schema.json"
chmod +x "$WORKSPACE_DIR/bin/validate_recon_result.py" \
  "$WORKSPACE_DIR/bin/validate-recon-result.py" \
  "$WORKSPACE_DIR/bin/validate-triage-batch.py"
write_text_file "$WORKSPACE_DIR/scripts/validate-workspace-state.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/validate-workspace-state.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/validate-workspace-state.py"
write_text_file "$WORKSPACE_DIR/scripts/validate-recon-result.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/validate-recon-result.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/validate-recon-result.py"
write_text_file "$WORKSPACE_DIR/scripts/validate-triage-batch.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/validate-triage-batch.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/validate-triage-batch.py"
copy_file \
  "$SKILL_DIR/scripts/assert_finalized_workspace.py" \
  "$WORKSPACE_DIR/bin/assert-finalized-workspace.py"
chmod +x "$WORKSPACE_DIR/bin/assert-finalized-workspace.py"
copy_file \
  "$SKILL_DIR/scripts/blocked_verification.py" \
  "$WORKSPACE_DIR/bin/blocked_verification.py"
copy_file \
  "$SKILL_DIR/scripts/validate_target_contract.py" \
  "$WORKSPACE_DIR/bin/validate_target_contract.py"
copy_file \
  "$SKILL_DIR/scripts/validate_candidate.py" \
  "$WORKSPACE_DIR/bin/validate_candidate.py"
copy_file "$SKILL_DIR/scripts/candidate_identity.py" "$WORKSPACE_DIR/bin/candidate_identity.py"
copy_file "$SKILL_DIR/scripts/upgrade_candidate_identity.py" "$WORKSPACE_DIR/bin/upgrade_candidate_identity.py"
copy_file "$SKILL_DIR/scripts/candidate_dedup.py" "$WORKSPACE_DIR/bin/candidate_dedup.py"
copy_file "$SKILL_DIR/scripts/build_candidate_dedup_plan.py" "$WORKSPACE_DIR/bin/build_candidate_dedup_plan.py"
copy_file "$SKILL_DIR/scripts/validate_candidate_dedup_plan.py" "$WORKSPACE_DIR/bin/validate_candidate_dedup_plan.py"
copy_file \
  "$SKILL_DIR/scripts/validate_verifier_verdict.py" \
  "$WORKSPACE_DIR/bin/validate_verifier_verdict.py"
copy_file \
  "$SKILL_DIR/scripts/verify_candidate.py" \
  "$WORKSPACE_DIR/bin/verify_candidate.py"
copy_file \
  "$SKILL_DIR/scripts/audit_disposition.py" \
  "$WORKSPACE_DIR/bin/audit_disposition.py"
write_text_file "$WORKSPACE_DIR/scripts/validate_target_contract.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/validate_target_contract.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/validate_target_contract.py"
write_text_file "$WORKSPACE_DIR/scripts/validate_candidate.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/validate_candidate.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/validate_candidate.py"
write_text_file "$WORKSPACE_DIR/scripts/upgrade-candidate-identity.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/upgrade_candidate_identity.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/upgrade-candidate-identity.py"
write_text_file "$WORKSPACE_DIR/scripts/build-candidate-dedup-plan.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/build_candidate_dedup_plan.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/build-candidate-dedup-plan.py"
write_text_file "$WORKSPACE_DIR/scripts/validate-candidate-dedup-plan.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/validate_candidate_dedup_plan.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/validate-candidate-dedup-plan.py"
write_text_file "$WORKSPACE_DIR/scripts/validate_verifier_verdict.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/validate_verifier_verdict.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/validate_verifier_verdict.py"
write_text_file "$WORKSPACE_DIR/scripts/verify_candidate.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/verify_candidate.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/verify_candidate.py"
write_text_file "$WORKSPACE_DIR/scripts/assert-finalized-workspace.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/assert-finalized-workspace.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/assert-finalized-workspace.py"
copy_file \
  "$SKILL_DIR/scripts/finalize_audit_workspace.py" \
  "$WORKSPACE_DIR/bin/finalize-audit-workspace.py"
chmod +x "$WORKSPACE_DIR/bin/finalize-audit-workspace.py"
write_text_file "$WORKSPACE_DIR/scripts/finalize-audit-workspace.py" '#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../bin/finalize-audit-workspace.py" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/finalize-audit-workspace.py"
copy_file \
  "$SKILL_DIR/assets/attacker-container/Dockerfile" \
  "$WORKSPACE_DIR/docker/attacker-container/Dockerfile"
copy_file \
  "$SKILL_DIR/assets/attacker-container/docker-compose.attacker.yml" \
  "$WORKSPACE_DIR/docker/docker-compose.attacker.yml"
copy_file \
  "$SKILL_DIR/assets/examples/confirmed-findings.example.json" \
  "$WORKSPACE_DIR/confirmed/findings.example.json"
copy_file \
  "$SKILL_DIR/assets/confirmed-vuln-report-template.docx" \
  "$WORKSPACE_DIR/confirmed/confirmed-vuln-report-template.docx"

python3 "$WORKSPACE_DIR/bin/manage-docker-resources.py" \
  --workspace-dir "$WORKSPACE_DIR" \
  --capture-baseline >/dev/null || \
  echo "[zhulong] WARNING: Docker resource baseline capture failed during bootstrap (non-fatal)." >&2

python3 "$WORKSPACE_DIR/bin/render-handoff-summary.py" \
  --workspace-dir "$WORKSPACE_DIR" \
  --repo-root "$TARGET_DIR" >/dev/null || \
  echo "[zhulong] WARNING: handoff summary render failed during bootstrap (non-fatal)." >&2

cat <<EOF

Workspace ready: $WORKSPACE_DIR

Suggested next steps:
  1. Preferred one-shot entrypoint:
       bash $WORKSPACE_DIR/bin/asr-start.sh --repo-root $TARGET_DIR
  2. Inspect $WORKSPACE_DIR/asr-config.json and keep output_language plus confirmed_output_dir consistent throughout the audit.
     Current defaults:
       output_language=$OUTPUT_LANGUAGE
       summary_language=$SUMMARY_LANGUAGE
  3. For a stable first-pass scan, prefer:
       bash $WORKSPACE_DIR/bin/run-initial-probes.sh --repo-root $TARGET_DIR
     Then read the lightweight handoff:
       python3 $WORKSPACE_DIR/bin/render-handoff-summary.py --workspace-dir $WORKSPACE_DIR --repo-root $TARGET_DIR
       $WORKSPACE_DIR/handoff-summary.md
  4. Before any PoC or exploit verification, enforce the Docker gate:
       bash $WORKSPACE_DIR/bin/check-docker-gate.sh --repo-root $TARGET_DIR
     If this fails, stop verification, keep the audit inside $WORKSPACE_DIR, and resume only after Docker is fixed.
     For individual verification cases, prefer the timeout/resource-limited runner:
       bash $WORKSPACE_DIR/bin/run-verification-case.sh --workspace-dir $WORKSPACE_DIR --case-id <case-id> --mode docker-run --image <local-image> --timeout-seconds 300 --expected-oracle <token-or-regex> -- <container command...>
  5. For any Bash command that uses relative paths, anchor it with:
       bash $WORKSPACE_DIR/bin/asr-exec.sh --repo-root -- <command...>
     or:
       bash $WORKSPACE_DIR/bin/asr-exec.sh --workspace-root -- <command...>
  6. Start the target service in Docker or Docker Compose.
  7. Attach the attacker container to the target Docker network.
  8. Write PoCs under $WORKSPACE_DIR/poc
  9. Save verification evidence under $WORKSPACE_DIR/evidence
  10. Fill $WORKSPACE_DIR/confirmed/findings.example.json with confirmed findings only.
  11. If you started from a single-language draft, scaffold bilingual fields with:
       python3 $WORKSPACE_DIR/bin/scaffold-bilingual-findings.py --input $WORKSPACE_DIR/confirmed/findings.json --output $WORKSPACE_DIR/confirmed/findings.bilingual.json --primary-language $OUTPUT_LANGUAGE
  12. Validate every final bundle with:
       python3 $WORKSPACE_DIR/bin/validate-report-bundle.py --bundle-dir $WORKSPACE_DIR/confirmed/<bundle-dir>
  13. Or batch-validate everything under confirmed/ with:
       python3 $WORKSPACE_DIR/bin/validate-all-report-bundles.py --confirmed-dir $WORKSPACE_DIR/confirmed

Reminder:
  PoCs must be sent and executed in Docker, never from the host shell against a host-local process.
EOF
