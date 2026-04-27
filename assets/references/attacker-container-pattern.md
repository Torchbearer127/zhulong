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

## Rules

- Do not send exploit traffic from the host shell if the traffic can instead be sent from the attacker container.
- Mount only the `poc/` and `evidence/` directories into the attacker container unless more is required.
- Keep the attacker container disposable. Rebuild or recreate it between materially different exploit attempts if contamination may affect results.
- Mention in the final report that the PoC was executed from the attacker container inside Docker.
