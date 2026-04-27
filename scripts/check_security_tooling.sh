#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  check_security_tooling.sh

Purpose:
  Detect which recommended security-audit tools are available locally and summarize the current audit capability level.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

tool_status() {
  local label="$1"
  shift
  local cmd
  for cmd in "$@"; do
    if command -v "$cmd" >/dev/null 2>&1; then
      printf '%-22s %s (%s)\n' "$label" "yes" "$cmd"
      return 0
    fi
  done
  printf '%-22s %s\n' "$label" "no"
  return 1
}

count_available() {
  local count=0
  local item
  for item in "$@"; do
    if command -v "$item" >/dev/null 2>&1; then
      count=$((count + 1))
    fi
  done
  printf '%s\n' "$count"
}

echo "== Core Runtime =="
tool_status "docker" docker || true
tool_status "docker compose" docker || true
tool_status "gh" gh || true
tool_status "python3" python3 || true
tool_status "node" node || true
echo ""

echo "== Broad Probe / SAST =="
tool_status "ship-safe" ship-safe || true
tool_status "semgrep" semgrep || true
tool_status "codeql" codeql || true
echo ""

echo "== Dependency / SBOM =="
tool_status "npm audit" npm || true
tool_status "pip-audit" pip-audit || true
tool_status "cargo audit" cargo-audit || true
tool_status "maven" mvn || true
tool_status "gradle" gradle || true
tool_status "dependency-check" dependency-check dependency-check.sh || true
tool_status "govulncheck" govulncheck || true
tool_status "trivy" trivy || true
tool_status "osv-scanner" osv-scanner || true
tool_status "syft" syft || true
tool_status "grype" grype || true
echo ""

echo "== Language-Specific SAST =="
tool_status "spotbugs" spotbugs || true
tool_status "findsecbugs" findsecbugs || true
tool_status "gosec" gosec || true
tool_status "golangci-lint" golangci-lint || true
echo ""

echo "== Secrets =="
tool_status "gitleaks" gitleaks || true
tool_status "trufflehog" trufflehog || true
echo ""

echo "== DAST / Verification =="
tool_status "nuclei" nuclei || true
tool_status "ffuf" ffuf || true
tool_status "sqlmap" sqlmap || true
tool_status "owasp zap" zap.sh zaproxy zap-baseline.py || true
echo ""

echo "== MCP Hardening =="
tool_status "mcpserver-audit" mcpserver-audit || true
tool_status "mcp-scanner" mcp-scanner || true
echo ""

echo "== Document QA =="
tool_status "markitdown" markitdown || true
tool_status "libreoffice" soffice || true
echo ""

baseline_count="$(count_available docker python3)"
enhanced_count="$(count_available ship-safe semgrep trivy osv-scanner syft grype nuclei gitleaks govulncheck gosec mvn gradle)"
mcp_hardening_count="$(count_available mcpserver-audit mcp-scanner)"

recommended_mode="baseline_only"
if [[ "$baseline_count" -ge 2 && "$enhanced_count" -ge 3 ]]; then
  recommended_mode="enhanced_ready"
fi
if [[ "$baseline_count" -ge 2 && "$enhanced_count" -ge 6 && "$mcp_hardening_count" -ge 1 ]]; then
  recommended_mode="full_security_stack"
fi

echo "== Summary =="
echo "recommended_mode=$recommended_mode"

case "$recommended_mode" in
  baseline_only)
    echo "recommended_additions=semgrep,trivy,osv-scanner,syft,grype,gitleaks,nuclei,govulncheck,gosec,mvn,gradle"
    ;;
  enhanced_ready)
    echo "recommended_additions=mcpserver-audit,mcp-scanner,markitdown,soffice"
    ;;
  full_security_stack)
    echo "recommended_additions=optional_only"
    ;;
esac
