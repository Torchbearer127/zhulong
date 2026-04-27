# Attacker Container Pattern

Use this pattern whenever the target service can be run in Docker but the PoC would otherwise be launched from the host.

## Goal

Run exploit delivery from a disposable container on the same Docker network as the target service.

This keeps:

- payload execution off the host
- PoC dependencies isolated
- verification logs easier to preserve

## Default Layout

Create:

```text
<audit-workspace>/
├── docker/
│   ├── attacker-container/
│   │   ├── Dockerfile
│   │   └── docker-compose.attacker.yml
├── poc/
└── evidence/
```

Copy the reusable files from:

- `assets/attacker-container/Dockerfile`
- `assets/attacker-container/docker-compose.attacker.yml`

## Basic Usage

If the project's compose file already creates the application service and network:

1. Run `scripts/bootstrap_verification_workspace.sh --target-dir /path/to/repo`
2. Set `TARGET_NETWORK` to the compose network name if needed
3. Start the application container first
4. Start the attacker container
5. Enter the attacker container and run the PoC there

Example:

```bash
bash scripts/bootstrap_verification_workspace.sh --target-dir /path/to/repo
docker compose up -d --build app
TARGET_NETWORK=target_default docker compose -f docker-compose.yml -f <audit-workspace>/docker/docker-compose.attacker.yml up -d attacker
TARGET_NETWORK=target_default docker compose -f docker-compose.yml -f <audit-workspace>/docker/docker-compose.attacker.yml exec attacker bash
```

From inside the attacker container, run:

- `curl` probes
- Python PoCs
- Node.js PoCs
- `ffuf`, `sqlmap`, or other tools if you intentionally install them into the attacker image

## Verification Runner Contract

Prefer the reusable runner for individual verification cases when a case can be
expressed as a Docker or Docker Compose command:

```bash
bash <audit-workspace>/bin/run-verification-case.sh \
  --workspace-dir <audit-workspace> \
  --case-id <case-id> \
  --mode docker-run \
  --image <local-or-cached-attacker-image> \
  --timeout-seconds 300 \
  --expected-oracle <token-or-regex> \
  --network <target-docker-network> \
  -- <container command...>
```

The runner writes structured evidence to
`<audit-workspace>/evidence/<case-id>/`, including `stdout.log`, `stderr.log`,
`command.json`, and `verification-result.json`.

Stable runner labels:

- `blocked_docker_unavailable`
- `blocked_missing_image`
- `failed_timeout`
- `failed_resource_limit`
- `rejected_not_reproducible`
- `confirmed_in_docker`

Timeouts are not generic failures. If a case returns `failed_timeout`, inspect
the PoC for service readiness waits, network blocking, infinite loops, or
interactive prompts before retrying.

For `docker-run`, the runner defaults to memory, CPU, and pids limits,
read-only root filesystem, dropped capabilities, no-new-privileges, and an
explicit network setting. The default network is `none`; set `--network` to the
target Docker network only when the verification needs service traffic.
For `docker-compose`, resource limits are managed by the Compose files rather
than by docker-run command-line defaults. Add service-level limits to the
Compose recipe when a verification case needs strict bounds.

Image policy remains local-first: use a suitable local or cached image when
available. Use `--pull-if-missing` only when a network pull is acceptable and no
local image is suitable.

Runner evidence does not change the confirmed bundle contract. Copy relevant
runner evidence into the final bundle's `attachments/` only after Docker
confirmation succeeds, and keep blocked, timed-out, resource-limited, or
rejected cases out of `confirmed/`.

## Rules

- Do not send exploit traffic from the host shell if the traffic can instead be sent from the attacker container.
- Mount only the `poc/` and `evidence/` directories into the attacker container unless more is required.
- Keep the attacker container disposable. Rebuild or recreate it between materially different exploit attempts if contamination may affect results.
- Mention in the final report that the PoC was executed from the attacker container inside Docker.
