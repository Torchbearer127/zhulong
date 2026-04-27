#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  install_recommended_tooling.sh [--tier first-tier|second-tier|document-qa|mcp-hardening|all]

Purpose:
  Install recommended optional tooling for the plugin in a tiered way on Homebrew-based macOS systems.

Notes:
  - This script installs optional tooling only. The plugin still works with partial tool availability.
  - It currently targets Homebrew environments.
EOF
}

TIER="first-tier"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier)
      TIER="${2:-}"
      shift 2
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

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required for this installer." >&2
  exit 1
fi

FIRST_TIER=(trivy osv-scanner syft grype gitleaks ffuf)
SECOND_TIER=(maven gradle dependency-check gosec golangci-lint spotbugs)
DOCUMENT_QA=()
MCP_HARDENING=()

TOOLS=()
case "$TIER" in
  first-tier)
    TOOLS=("${FIRST_TIER[@]}")
    ;;
  second-tier)
    TOOLS=("${SECOND_TIER[@]}")
    ;;
  document-qa)
    TOOLS=("${DOCUMENT_QA[@]}")
    ;;
  mcp-hardening)
    TOOLS=("${MCP_HARDENING[@]}")
    ;;
  all)
    TOOLS=("${FIRST_TIER[@]}" "${SECOND_TIER[@]}" "${DOCUMENT_QA[@]}" "${MCP_HARDENING[@]}")
    ;;
  *)
    echo "Unsupported tier: $TIER" >&2
    exit 1
    ;;
esac

if [[ "${#TOOLS[@]}" -eq 0 ]]; then
  echo "No Homebrew-installable tools are configured for tier: $TIER"
  exit 0
fi

env -u HOMEBREW_API_DOMAIN -u HOMEBREW_BOTTLE_DOMAIN -u HOMEBREW_BREW_GIT_REMOTE -u HOMEBREW_CORE_GIT_REMOTE HOMEBREW_NO_AUTO_UPDATE=1 brew install "${TOOLS[@]}"
