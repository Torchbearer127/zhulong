#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_ROOT="$(bash "$SCRIPT_DIR/resolve_skill_root.sh")"
ASR_START="$SKILL_ROOT/scripts/asr_start.sh"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/zhulong_audit.sh --source <local-path|repo-url|owner/repo> [asr_start options...]
  bash scripts/zhulong_audit.sh --repo-root <repo-root> [asr_start options...]
  bash scripts/zhulong_audit.sh --print-skill-root

Description:
  Platform-neutral Zhulong launcher. It resolves this skill/package root from
  its own script location, then delegates to scripts/asr_start.sh.
EOF
}

if [[ $# -gt 0 ]]; then
  case "$1" in
    --print-skill-root)
      if [[ $# -ne 1 ]]; then
        echo "--print-skill-root does not accept additional arguments." >&2
        exit 1
      fi
      printf '%s\n' "$SKILL_ROOT"
      exit 0
      ;;
    -h|--help)
      usage
      echo
      bash "$ASR_START" --help
      exit 0
      ;;
  esac
fi

exec bash "$ASR_START" "$@"
