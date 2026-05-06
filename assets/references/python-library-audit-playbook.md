# Python Library / Framework Audit Playbook

This is a lightweight first-read for Python library, framework, parser,
serializer, template, CLI, and HTTP-client repositories. It is guidance only:
playbook reasoning, unsafe-default concerns, known CVEs, dependency alerts, or
source-to-sink hypotheses cannot confirm a vulnerability by themselves.

## Scope and When To Use It

Use this when the target is primarily a reusable Python package rather than a
deployed web app. Relevant targets include Flask, Werkzeug, Jinja, Click,
Requests-like clients, parsers, serializers, framework extensions, and helper
libraries used by downstream applications.

Do not force a route / method / handler table for a pure library. Build a public
API and consumer-impact map instead.

## Fast Model

Minimum Python library inventory fields:

| Public API / Hook | Input Shape | Caller-Controlled Options | Transformation Path | High-Risk Sink | Consumer Impact Assumption | Current Verification Status |
| --- | --- | --- | --- | --- | --- | --- |
| function/class/CLI/extension hook | string/file/object/request-like input | config flags/env/options/callbacks | normalization/parsing/rendering/dispatch | file/path/template/deserialization/subprocess/network | realistic app behavior needed for impact | candidate/unverified/confirmed_in_docker |

## Source-To-Sink Tracing Guidance

- Start from exported functions/classes, decorators, CLI commands, extension
  hooks, plugin callbacks, parser entry points, and documented public APIs.
- Track consumer-controlled input through normalization, escaping, rendering,
  parsing, serialization, path joining, file opening, subprocess invocation,
  dynamic import, request construction, or redirect handling.
- Separate library-local behavior from application-level impact. A sharp edge,
  unsafe example, or permissive default is not a confirmed vulnerability until a
  realistic consumer path demonstrates attacker reachability and impact.
- For framework libraries, record which behavior is development-only, test-only,
  example-only, opt-in configuration, or production default.
- Treat example apps, docs snippets, tests, and development dependencies as
  isolation boundaries unless the package ships or enables them in a realistic
  downstream deployment.

## Docker-Only Verification Reminders

- Build a minimal Docker consumer app or script that imports the local package
  version under audit and exercises the public API exactly as a real consumer
  would.
- Keep the oracle concrete: file read/write, template output change, command
  execution marker, deserialization side effect, SSRF callback, redirect target,
  escaping bypass, parser crash/resource exhaustion, or privilege boundary
  bypass.
- Do not use host fallback. If a framework behavior depends on deployment
  settings, make those settings explicit in the Docker fixture.
- Keep `verification_status=confirmed_in_docker` only for candidates with a
  successful Docker reproduction and direct success oracle.

## Common Library Risk Areas

- Unsafe defaults that are reachable in realistic consumer deployments.
- Template rendering or escaping APIs where attacker input crosses a trust
  boundary.
- URL parsing, redirect, proxy, or client request behavior that can create SSRF
  or credential-forwarding impact in a consumer app.
- Path normalization, archive extraction, upload helpers, and file-serving
  utilities.
- Deserialization and dynamic configuration loaders, especially pickle, YAML,
  object hooks, import strings, or plugin registries.
- CLI argument handling, shell invocation, environment propagation, and path
  lookup behavior.
- Parser/resource-exhaustion cases with practical CPU, memory, recursion, or
  file descriptor impact under resource-limited Docker.

## Severity and Impact Evidence To Seek

- A realistic downstream entry point where untrusted input reaches the library
  API.
- Default or common configuration, not only contrived opt-in insecure settings.
- Concrete confidentiality, integrity, availability, auth/session, filesystem,
  network, or code-execution impact.
- Version and source/runtime alignment: the Docker reproduction must exercise
  the same code revision being reported.
- Evidence that examples/tests/development dependencies are actually part of the
  consumer risk claim, or a clear downgrade when they are not.

## Confirmed-Only Routing Reminder

Library misuse, unsafe defaults, known CVEs, dependency-only alerts, and static
source-to-sink reasoning are candidates only. Do not generate DOCX reports from
this playbook alone. Confirmed bundles require Docker evidence,
`verification_status=confirmed_in_docker`, successful bundle validation, and the
standard `confirmed/<one-folder-per-vulnerability>/` output contract.
