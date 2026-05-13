# Zhulong Workflow Details

This document collects the detailed operational notes that are useful after a
reader already understands the README-level positioning.

For Simplified Chinese, see [`WORKFLOW_DETAILS.zh-CN.md`](WORKFLOW_DETAILS.zh-CN.md).

## Human-Agent Collaboration

Zhulong treats the audit workspace as a shared working surface between agents
and humans. The important state is written to small, named files instead of
being trapped in a long chat transcript or raw scanner output.

- Agents can resume from `handoff-summary.md`, `stage-status.json`, and
  `audit-disposition.json`.
- Humans can review `attack-surface.md`, `candidate-findings.md`,
  `false-positives.md`, `unverified-leads.md`, and `SUMMARY.md` without reading
  every raw log.
- Maintainers can evolve behavior by editing scripts, reference contracts, and
  validators rather than inflating launch prompts.
- Reviewers can inspect confirmed bundles without reconstructing which
  evidence, command, payload, and report claim belong together.

## Runtime Residue And Cleanup

Zhulong separates Docker residue from OMC/PID runtime residue. Both are surfaced
in workspace artifacts and handoff summaries, but they use different safety
policies:

| Type | Where To Review | Default Behavior | What The User Or Agent May Do |
| --- | --- | --- | --- |
| Docker containers, images, networks, volumes, BuildKit cache | `docker/docker-cleanup-plan.json`, `docker/docker-cleanliness-status.json`, `handoff-summary.md` | Generate a cleanup plan first; dry-run by default; only remove resources proven to belong to the current audit. | After human review, the user may authorize the agent to clean exact resources with `--apply`. |
| OMC stale sockets | `runtime/runtime-hygiene-status.json`, `handoff-summary.md` | Remove only stale `claude-swarm-*` sockets when no live swarm socket exists. | Run `--cleanup-stale`, then re-check. |
| Suspect `claude --teammate-mode tmux` PIDs | `runtime/runtime-hygiene-status.json`, `handoff-summary.md` | Review-only; Zhulong does not send termination signals or force-kill commands. | Inspect `pid/ppid/pgid/sess/tty/stat/command`; if a PID is confirmed stale, handle it manually outside Zhulong. |

The recommended Docker cleanup flow is to inspect the plan first:

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py \
  --workspace-dir <audit-workspace> \
  --cleanup-created
```

After confirming the listed resources belong to the current audit, authorize
precise cleanup:

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py \
  --workspace-dir <audit-workspace> \
  --cleanup-created \
  --apply
```

If the plan lists unlabeled resources that are proven to belong to this audit,
use exact adoption flags such as `--adopt-compose-project`, `--adopt-image-ref`,
`--adopt-network-name`, `--adopt-volume-name`, or `--adopt-build-cache-id`.
Do not use wildcard, prefix, regex, or "clean every project" semantics.

After cleanup, verify strict cleanliness:

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py \
  --workspace-dir <audit-workspace> \
  --verify-clean \
  --strict
```

If `clean=false`, the workspace should remain blocked and the summary should
record the residue plus safe resume steps. Zhulong must not hide residue by
recapturing the Docker baseline, and it must not trust a stale
`docker-cleanliness-status.json` as a completion signal.

OMC/PID review is only a safety gate for multi-agent usage:

```bash
bash <audit-workspace>/bin/check_omc_runtime.sh --json
```

If only stale sockets exist and no live swarm socket exists, clean sockets and
re-check:

```bash
bash <audit-workspace>/bin/check_omc_runtime.sh --cleanup-stale --json
bash <audit-workspace>/bin/check_omc_runtime.sh --json
```

If suspect teammate PIDs are reported, Zhulong only shows review metadata. Even
when PID review or cleanup flags are supplied, current Zhulong does not signal
teammate PIDs. If the user confirms that a PID is stale, terminate it manually
outside Zhulong or explicitly authorize an agent to use normal system process
tools with full awareness of the risk. Do not merge PID cleanup into Docker
cleanup, and do not use broad process cleanup.

For details, see
[`../assets/references/docker-resource-hygiene.md`](../assets/references/docker-resource-hygiene.md)
and
[`../assets/references/omc-runtime-stability.md`](../assets/references/omc-runtime-stability.md).

## Report Quality Gates

Confirmed reports must state:

- attacker condition
- server condition
- concrete security impact
- real-world exploitability: attacker path, server-side reachability, observable
  impact channel, and the verified-vs-not-claimed impact boundary

The validator also checks for common contradiction patterns, including:

- title or wording claiming no-auth reachability while CVSS or reproduction
  evidence requires privileges
- unconditional success banners in PoC scripts without concrete success oracles
- fail-open success-oracle lines such as `grep ... || echo ...`,
  `grep ... || true`, `jq ... || true`, `curl ... || true`, or
  `docker logs ... | grep ... || echo ...` before final confirmation banners
- stale or malformed recording step labels
- bundle-root recording helper shell syntax and executable bit
- attachment Docker Compose consistency, including missing relative `env_file`
  entries, missing relative bind-mount sources, and forbidden absolute host paths
- long natural-language output in the wrong report language
- optional target/command consistency fields when structured evidence is present
- root/attachment scripts that escape the downloaded bundle through deep
  `../../..` traversal or parent-repository mounts
- PoC label drift between report materials and the root recording helper
- stale recording videos that are older than the current report, supplement,
  evidence JSON, or root reproduction script
- package manager install commands that may trigger lifecycle-script or network
  noise in the shortest reviewer path

These checks are intentionally conservative. They are meant to reduce false
positives without changing the confirmed bundle contract.

Reviewer-facing recording helpers should derive their own bundle directory,
refer to `attachments/` relative to that directory, and either bootstrap the
Docker environment from bundle-local attachments or fail early with the exact
bundle-local command the reviewer must run first. They should check required
containers before `docker exec`, run readiness checks when practical, and print
captured command errors instead of hiding critical failures with naked
`2>/dev/null`. Harmless `../` paths are acceptable inside nested attachment
directories only when they still resolve inside the per-vulnerability bundle;
scripts must not depend on the submitter's full local repository layout.

## Example Finding Shape

```text
State: confirmed
Title: SSRF through file import URL fetch
Severity: High
Evidence: Docker reproduction observed attacker-controlled callback
Attacker condition: authenticated low-privilege user with import permission
Server condition: default import endpoint enabled, outbound network reachable
Security impact: confidentiality risk through internal service probing or metadata access
Real-world exploitability: the authenticated attacker controls the import URL;
the default server-side deny list allows private ranges; the effect is visible
as stored response content or callback traffic; Docker evidence verifies SSRF
reachability but does not claim code execution.
Bundle: confirmed/<vulnerability-slug>/
```

This is the shape of a confirmed record, not a promise that every audit will
produce one.

## Validation

Run the plugin selftest:

```bash
python3 scripts/selftest_plugin.py
```

Sync and test the installed Claude skill layout:

```bash
bash scripts/sync_to_claude_skill.sh
python3 ~/.claude/skills/zhulong/scripts/selftest_plugin.py
```

Validate one confirmed bundle:

```bash
python3 scripts/validate_report_bundle.py --bundle-dir <bundle-dir>
```

Validate all bundles in a workspace:

```bash
python3 scripts/validate_all_report_bundles.py --confirmed-dir <repo>/<audit-workspace>/confirmed
```

Before publishing a release, run:

```bash
cat docs/RELEASE_CHECKLIST.md
```

## Limitations

- Zhulong does not guarantee vulnerability discovery.
- Zhulong does not replace expert review or responsible disclosure judgment.
- Zhulong does not automatically log in to registries or silently substitute
  non-equivalent Docker images.
- Zhulong does not clean uncertain Docker resources or OMC teammate PIDs.
- Zhulong does not run a hosted backend, dashboard, database, vector store, or
  RAG service.
