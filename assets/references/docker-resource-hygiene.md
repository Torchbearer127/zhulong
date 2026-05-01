# Docker Resource Hygiene

Zhulong audits should not leave unbounded Docker images, volumes, networks, or
stopped containers behind. Cleanup must be precise: remove only resources that
were created during this audit, and never remove Docker resources that existed
before the workspace was created.

## Local-First Image Policy

- Prefer suitable local images or cached base images before pulling from the
  network.
- Use `run-verification-case.sh --pull-if-missing` only when no suitable local
  image exists and a network pull is acceptable.
- Avoid launching duplicate `docker pull`, `docker build`, or `docker compose
  pull` commands for the same target. Reuse the current build or cached image
  when it is good enough for Docker-only verification.

## Resource Baseline

New workspaces attempt to capture a Docker resource baseline at:

```text
<audit-workspace>/docker/docker-resource-baseline.json
```

The baseline records images, volumes, networks, and containers present before
the audit's Docker activity. It is not sufficient by itself for deletion in
parallel dogfood runs. Automatic cleanup also requires Zhulong ownership labels
for the current workspace:

```text
org.zhulong.managed=true
org.zhulong.workspace=<audit-workspace-name>
```

Resources that were created after the baseline but do not carry those labels are
listed for manual review as unattributed resources and are not deleted by
`--apply`.

This protects parallel work: another Zhulong audit, another development stack,
or an unrelated application may create Docker resources after the baseline. Those
resources must not be deleted unless they carry this workspace's ownership label.

If Docker is unavailable during bootstrap, recapture the baseline before
verification:

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py \
  --workspace-dir <audit-workspace> \
  --capture-baseline
```

Do not recapture the baseline after starting target containers, pulling service
images, or building PoC images. The cleanup helper refuses to overwrite an
existing available baseline by default because a late baseline can hide
resources created by the current audit. Use `--force-overwrite-baseline` only
after a deliberate manual Docker reset and before new verification resources are
created.

## End-of-Audit Cleanup

If you started the target with Docker Compose, prefer a unique project name for
this audit so cleanup has an exact handle:

```bash
ZHULONG_COMPOSE_PROJECT="zhulong-<audit-workspace-name>-<target-name>"
docker compose -p "$ZHULONG_COMPOSE_PROJECT" -f <compose.yml> up -d
```

At the end of the audit, stop that exact stack before running the generic
resource cleanup:

```bash
docker compose -p "$ZHULONG_COMPOSE_PROJECT" -f <compose.yml> down -v --rmi local --remove-orphans
```

Only use the compose files and project name that this audit actually started.
Do not run `docker compose down` against unrelated projects.

At the end of a dogfood or audit run, first inspect the cleanup plan:

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py \
  --workspace-dir <audit-workspace> \
  --cleanup-created
```

This is a dry run. It writes:

```text
<audit-workspace>/docker/docker-cleanup-plan.json
```

After reviewing the plan, apply cleanup only if the listed resources belong to
this audit:

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py \
  --workspace-dir <audit-workspace> \
  --cleanup-created \
  --apply
```

For a target Compose project that this audit explicitly started, pass the exact
project name to adopt its post-baseline resources. If the Compose file pulled
service images that do not carry Compose labels, adopt only the exact image refs
that were absent from the baseline and are known to belong to this audit. If
Docker BuildKit cache remains, adopt build-cache cleanup only after reviewing
that the new cache records belong to this isolated audit run:

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py \
  --workspace-dir <audit-workspace> \
  --cleanup-created \
  --adopt-compose-project "$ZHULONG_COMPOSE_PROJECT" \
  --adopt-image-ref mysql:5.7 \
  --adopt-build-cache
```

Review the plan before adding `--apply`. Adoption never bypasses the baseline:
resources that existed before the audit are still protected.

Then verify that no current-workspace owned Docker resources remain:

```bash
python3 <audit-workspace>/bin/manage-docker-resources.py \
  --workspace-dir <audit-workspace> \
  --verify-clean \
  --strict
```

This writes:

```text
<audit-workspace>/docker/docker-cleanliness-status.json
```

`clean=true` with `--strict` means the Docker state has no current-workspace
owned resources and no post-baseline unattributed resources. If `clean=false`,
the final summary should report the cleanup blocker and safe resume command.
Unattributed resources are never auto-deleted because they may belong to a
parallel Zhulong audit or another application.

## Safety Rules

- Do not use broad `docker system prune`, `docker image prune`, `docker volume
  prune`, or `docker network prune` as a Zhulong cleanup path.
- Do not delete resources that existed in the baseline.
- Do not delete resources merely because they are absent from the baseline; in
  parallel Zhulong runs, they may belong to another audit. Automatic cleanup is
  limited to resources with this workspace's Zhulong ownership labels, or to an
  exact Compose project / image ref that this audit explicitly adopts for the
  current cleanup run.
- BuildKit cache is also baseline-aware. It is review-only by default and can be
  cleaned with `--adopt-build-cache`, which uses `docker buildx prune --filter
  id=<cache-id>` rather than broad cache pruning.
- Running containers are skipped by default. Stop them deliberately only after
  confirming they belong to this audit.
- Target project Docker Compose resources often do not carry Zhulong labels. The
  cleanup helper may list them for review, but it must not delete them
  automatically. Use a unique Compose project name plus exact
  `docker compose ... down -v --rmi local --remove-orphans` for stacks this
  audit started.
- When using the bundled attacker Compose file, set
  `ZHULONG_WORKSPACE_LABEL=<audit-workspace-name>` if you want its generated
  container/image labels to be eligible for precise cleanup.
- If cleanup fails because a resource is still in use, record the blocker and
  leave the resource in place rather than forcing global cleanup.
- If strict verification fails only because post-baseline unattributed resources
  remain, inspect them. Delete only resources proven to belong to this audit;
  otherwise report the ambiguity instead of guessing.
- Cleanup is an environment hygiene step. It does not change vulnerability
  confirmation status and must not alter confirmed bundle evidence.
