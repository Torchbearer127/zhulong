#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  asr_exec.sh (--repo-root | --workspace-root) -- <command> [args...]

Purpose:
  Execute a command from a deterministic anchor directory inside a bootstrapped
  zhulong workspace.

Examples:
  # From the repository root
  bash <audit-workspace>/bin/asr-exec.sh --workspace-root -- \
    chmod +x vulnerability-packages/CVE-2024-XXXXX-credential-exposure/test.sh

  # From inside the current audit workspace
  bash scripts/asr-exec.sh --repo-root -- rg -n "child_process" .
EOF
}

ANCHOR=""
if [[ $# -lt 2 ]]; then
  usage >&2
  exit 1
fi

case "$1" in
  --repo-root)
    ANCHOR="repo"
    shift
    ;;
  --workspace-root)
    ANCHOR="workspace"
    shift
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    echo "Expected --repo-root or --workspace-root." >&2
    usage >&2
    exit 1
    ;;
esac

if [[ "${1:-}" != "--" ]]; then
  echo "Missing -- separator before the command to execute." >&2
  usage >&2
  exit 1
fi
shift

if [[ $# -eq 0 ]]; then
  echo "No command supplied." >&2
  usage >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$WORKSPACE_DIR/.." && pwd)"

case "$ANCHOR" in
  repo)
    cd "$REPO_ROOT"
    ;;
  workspace)
    cd "$WORKSPACE_DIR"
    ;;
esac

exec "$@"
