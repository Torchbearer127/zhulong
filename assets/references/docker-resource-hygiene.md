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

## End-of-Audit Cleanup

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

## Safety Rules

- Do not use broad `docker system prune`, `docker image prune`, `docker volume
  prune`, or `docker network prune` as a Zhulong cleanup path.
- Do not delete resources that existed in the baseline.
- Do not delete resources merely because they are absent from the baseline; in
  parallel Zhulong runs, they may belong to another audit. Automatic cleanup is
  limited to resources with this workspace's Zhulong ownership labels.
- Running containers are skipped by default. Stop them deliberately only after
  confirming they belong to this audit.
- Target project Docker Compose resources often do not carry Zhulong labels. The
  cleanup helper may list them for review, but it must not delete them
  automatically.
- When using the bundled attacker Compose file, set
  `ZHULONG_WORKSPACE_LABEL=<audit-workspace-name>` if you want its generated
  container/image labels to be eligible for precise cleanup.
- If cleanup fails because a resource is still in use, record the blocker and
  leave the resource in place rather than forcing global cleanup.
- Cleanup is an environment hygiene step. It does not change vulnerability
  confirmation status and must not alter confirmed bundle evidence.
