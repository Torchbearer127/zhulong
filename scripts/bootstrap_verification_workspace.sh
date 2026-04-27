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
    fingerprint.md
    candidate-findings.md
    false-positives.md
    bin/
      asr-start.sh
      asr-exec.sh
      check-docker-gate.sh
      check_omc_runtime.sh
      check_security_tooling.sh
      run-initial-probes.sh
      plan-security-toolchain.py
      scaffold-bilingual-findings.py
      validate-report-bundle.py
      validate-all-report-bundles.py
    scripts/
      asr-start.sh
      asr-exec.sh
      check-docker-gate.sh
      check_omc_runtime.sh
      check_security_tooling.sh
      run-initial-probes.sh
      plan-security-toolchain.py
      scaffold-bilingual-findings.py
      validate-report-bundle.py
      validate-all-report-bundles.py
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
TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
if [[ -z "$WORKSPACE_NAME" ]]; then
  WORKSPACE_NAME="$(generate_workspace_name "$TARGET_DIR")"
fi
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

mkdir -p \
  "$WORKSPACE_DIR/bin" \
  "$WORKSPACE_DIR/scripts" \
  "$WORKSPACE_DIR/docker/attacker-container" \
  "$WORKSPACE_DIR/poc" \
  "$WORKSPACE_DIR/evidence" \
  "$WORKSPACE_DIR/confirmed"

write_text_file "$WORKSPACE_DIR/fingerprint.md" "# Fingerprint\n\n- Stack:\n- Frameworks:\n- Entrypoints:\n- Sources:\n- Sinks:\n- Verification constraints:\n"
write_text_file "$WORKSPACE_DIR/candidate-findings.md" "# Candidate Findings\n\n| Finding | Evidence | Exploit Path | Verification Plan | Status |\n| --- | --- | --- | --- | --- |\n"
write_text_file "$WORKSPACE_DIR/false-positives.md" "# False Positives\n\n"
workspace_created_at="$(date '+%Y-%m-%d %H:%M:%S %z')"
write_text_file "$WORKSPACE_DIR/asr-config.json" "{
  \"output_language\": \"$OUTPUT_LANGUAGE\",
  \"summary_language\": \"$SUMMARY_LANGUAGE\",
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
printf '%s\n' "$WORKSPACE_NAME" > "$TARGET_DIR/.asr-latest-workspace"
echo "write    $TARGET_DIR/.asr-latest-workspace"

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
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/../bin/run-initial-probes.sh" "$@"
'
chmod +x "$WORKSPACE_DIR/scripts/run-initial-probes.sh"
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
  4. Before any PoC or exploit verification, enforce the Docker gate:
       bash $WORKSPACE_DIR/bin/check-docker-gate.sh --repo-root $TARGET_DIR
     If this fails, stop verification, keep the audit inside $WORKSPACE_DIR, and resume only after Docker is fixed.
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
