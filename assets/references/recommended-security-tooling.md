# Recommended Security Tooling

Use these tools to strengthen the audit and verification workflow around this skill.

## First Tier

These are the highest-value additions for a Docker-first autonomous security workflow.

- `Semgrep`
  - broad first-pass SAST
  - custom rules for project-specific sinks and sources
- `Trivy`
  - image, filesystem, dependency, secret, and misconfiguration scanning
- `OSV-Scanner`
  - dependency vulnerability confirmation with useful reachability / call-analysis support
  - use `run-initial-probes.sh` as the preferred wrapper; if raw `osv-scanner scan source -r <repo>` exits 128 with `No package sources found`, record it as skipped/no supported package source rather than a workflow failure
- `Syft`
  - SBOM generation for the project and the verification image
- `Grype`
  - vulnerability matching against SBOMs and images
- `Gitleaks` or `TruffleHog`
  - secret scanning for current tree and repository history
- `Nuclei`
  - fast template-based DAST / exposure checks once the target is running in Docker

## Second Tier

Add these when the target or workflow makes them useful.

- `govulncheck`
  - Go official vulnerability analysis for modules and reachable standard-library issues
- `gosec`
  - Go security pattern scanning for command execution, weak TLS, file permissions, and similar issues
- `golangci-lint`
  - Go quality linting that can expose bug patterns around error handling and unsafe code paths
- `Maven` / `Gradle`
  - Java dependency graph extraction with `mvn dependency:tree` or `gradle dependencies`
- `OWASP Dependency-Check`
  - Java dependency vulnerability analysis for Maven and Gradle projects
- `SpotBugs` + `FindSecBugs`
  - Java static analysis for security-sensitive patterns
- `OWASP ZAP`
  - deeper web / API DAST
- `ffuf`
  - focused endpoint and parameter fuzzing
- `sqlmap`
  - only after a likely injectable endpoint already exists in Docker
- `CodeQL`
  - slower than Semgrep, but useful for deeper static analysis on selected repositories

## MCP Hardening Tier

If you install third-party MCP servers, audit those MCP servers too.

- `mcpserver-audit`
  - source review for unsafe MCP server patterns
- `mcp-scanner`
  - malicious or risky MCP detection

Treat MCP servers as attack surface, not as automatically trusted tooling.

## Document QA Tier

These are optional confidence checks for final report bundles.

- `MarkItDown`
  - extraction smoke test from generated `.docx`
- `LibreOffice`
  - headless `.docx -> .pdf` conversion check

These are validation helpers only. Do not replace the primary deterministic `.docx` renderer with interactive Office automation.

## Recommended Order

For a new environment, prioritize installation in this order:

1. `Semgrep`
2. `Trivy`
3. `OSV-Scanner`
4. `Syft`
5. `Grype`
6. `Gitleaks`
7. `Nuclei`
8. `mcpserver-audit`
9. `mcp-scanner`
10. `MarkItDown`
11. `LibreOffice`

For Java Web repositories, also install Maven or Gradle plus Dependency-Check
and SpotBugs/FindSecBugs when possible. For Go Web repositories, also install
`govulncheck`, `gosec`, and optionally `golangci-lint`.

## Local Tooling Check

Use:

```bash
bash scripts/check_security_tooling.sh
```

From the repository root after bootstrap:

```bash
bash <audit-workspace>/bin/check_security_tooling.sh
```
