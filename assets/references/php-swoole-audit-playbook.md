# PHP / Swoole Web Audit Playbook

This concise playbook is for Appwrite-like PHP monorepos, Swoole/OpenSwoole
runtimes, Utopia-style frameworks, and Docker Compose PHP service stacks. It is
guidance only; source-to-sink reasoning and blocked Docker checks cannot confirm
a vulnerability by themselves.

## Fast Model

Minimum entry inventory fields:

| Route / Command / Worker | Method / Trigger | Handler / Controller | Authentication Requirement | Input Source | Downstream Sink / Service | Current Verification Status |
| --- | --- | --- | --- | --- | --- | --- |
| HTTP route, GraphQL endpoint, CLI task, queue worker | GET/POST/queue/cron/CLI | PHP class/function | scope/session/API key/internal | query/body/path/header/job payload | curl/filesystem/storage/DB/Redis/worker | candidate/blocked/confirmed_in_docker |

## Scope Notes

- Separate HTTP-exposed controllers from CLI-only install/maintenance tasks.
- Treat Swoole workers, queues, async jobs, and internal service calls as
  separate trust boundaries.
- In monorepos, frontend/test `package-lock.json` files are secondary unless
  the Node.js service is part of the runtime under Docker verification.

## Source-To-Sink Tracing Guidance

- Trace public API input through Utopia routing, validators, permissions,
  dependency injection, workers, and queues before reaching a sink.
- For SSRF, inspect `curl_exec`, `curl_setopt`, redirects, protocol limits,
  proxy behavior, and internal Docker service names.
- For filesystem/storage, track bucket/file IDs, generated paths, extensions,
  chunk metadata, archive handling, and storage adapter boundaries.
- For GraphQL, record depth, complexity, batching, introspection settings,
  authorization checks, and resolver-level data access.
- For async workers and queues, record who can enqueue the job, which fields
  are trusted, and which services the worker can reach.

## Docker-Only Verification Reminders

- Confirm only in Docker or Docker Compose with the PHP/Swoole runtime actually
  started.
- If Docker image pulls are blocked, route candidates to blocked verification;
  do not call the audit completed_no_confirmed_findings.
- Keep `verification_status=confirmed_in_docker` only for candidates with direct
  Docker evidence and a success oracle.

## Confirmed-Only Reminder

Blocked Docker verification, static source review, dependency alerts, and
source-to-sink hypotheses remain candidates or unverified leads. Do not generate
DOCX reports or write `confirmed/` bundles until Docker reproduction and bundle
validation succeed.
