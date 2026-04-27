# Python Web Audit Playbook

Use this playbook when Zhulong identifies a Python Web repository, especially
Flask, Django, FastAPI, Starlette, or Python services with Docker/Kubernetes
deployment artifacts.

This is source-to-sink audit guidance only. Playbook reasoning, route matches,
and framework patterns cannot confirm a vulnerability by themselves.
This playbook is not exhaustive and must not narrow exploration. If the
repository uses a framework, data flow, sink class, or deployment pattern not
listed here, add it to `attack-surface.md`, candidate findings, and Docker
verification plans instead of ignoring it.

## Fast Model

Build an `attack-surface.md` note before deep verification.

Record:

- route or endpoint
- HTTP method
- handler, view, path operation, or controller-equivalent
- middleware, dependency, decorator, and authentication requirement
- input source from query, path, header, cookie, body, multipart, webhook, or config
- downstream sink or service reached
- current verification status

Minimum entry inventory fields:

| Route / Endpoint | Method | Handler / Controller | Authentication Requirement | Input Source | Downstream Sink / Service | Current Verification Status |
| --- | --- | --- | --- | --- | --- | --- |

## Entry Points

Prioritize:

- Flask `@app.route`, blueprints, `before_request`, error handlers, uploads, CLI/admin routes
- Django `urls.py`, `path`, `re_path`, class-based views, middleware, DRF viewsets, admin/custom management endpoints
- FastAPI `@app.get/post/...`, `APIRouter`, dependencies, security dependencies, background tasks, WebSockets
- Starlette routes, mounts, middleware, request handlers, background tasks, and lifespan hooks
- Other Python web frameworks such as Sanic, Falcon, Pyramid, or Tornado; model them with the same route, middleware/dependency, auth, input, and sink fields
- GraphQL handlers, webhook receivers, file upload endpoints, health/debug/metrics routes

## Trust Boundaries

Treat these as untrusted unless proven otherwise:

- Flask `request.args`, `request.form`, `request.json`, `request.files`, headers, cookies, session data
- Django `request.GET`, `request.POST`, `request.body`, `request.FILES`, headers, cookies, URL kwargs
- FastAPI/Starlette path/query/body/header/cookie parameters, `Request`, `UploadFile`, form fields, dependency outputs
- ORM rows, cache entries, Celery/RQ jobs, queue messages, third-party HTTP responses
- environment variables, settings modules, `.env` files, YAML/JSON config, plugin manifests

## High-Priority Sinks

Track source-to-sink flows into:

- ORM/query construction: Django `raw`, `.extra`, `RawSQL`, SQLAlchemy `text`, string-built SQL, unsafe filters
- template injection/XSS: Jinja2, Django templates, `Markup`, `safe`, `autoescape off`, template names from input
- SSRF: `requests`, `httpx`, `urllib.request`, `aiohttp`, redirects, proxy settings, internal service clients
- file/path handling: `open`, `Path`, `os.path.join`, `send_file`, `FileResponse`, upload storage, archive extraction
- deserialization: `pickle`, `marshal`, unsafe YAML loaders, signed-but-attacker-controlled data, cache/session serializers
- command execution: `subprocess`, `os.system`, shell wrappers, dynamic management commands
- auth/session/CORS/CSRF: decorator gaps, middleware ordering, cookie/session flags, CSRF exemptions, permissive CORS
- resource limits: request body limits, upload limits, parser depth, template recursion, worker timeouts, async fan-out

## Source-To-Sink Tracing Guidance

- Trace decorators, dependencies, middleware, permission classes, and router includes before assuming a route is protected.
- Record model/serializer/form validation boundaries and whether validation happens before the sink.
- For ORM issues, distinguish parameterized APIs from string-built SQL and note tainted identifiers separately from values.
- For SSRF, follow URL parsing, redirects, DNS/IP checks, timeout behavior, proxies, and final client call.
- For path handling, check decode, normalize, join, symlink handling, storage backend behavior, and final boundary check.
- For deserialization, prove attacker control of bytes or structured data and the dangerous loader path.

## Docker-Only Verification Reminders

- Confirm only with a Docker or Docker Compose reproduction and a direct success oracle.
- Use controlled listener, database fixture, filesystem sentinel, mock internal service, or minimal Python PoC containers.
- Record command, container/network settings, input payload, observed output, and why the result proves impact.
- Timeouts, blocked networking, scanner matches, source-to-sink hypotheses, and dependency alerts stay unconfirmed.

## Web Vulnerability Priorities

Audit Python Web services in this order:

1. authentication and authorization bypass, including missing decorators, dependencies, permissions, or object ownership checks
2. SQL/ORM injection through raw SQL, string interpolation, dynamic identifiers, or unsafe filters
3. SSRF with redirect, proxy, localhost, RFC1918, metadata, and DNS rebinding bypasses
4. command execution through shell interpolation or unsafe argument construction
5. path traversal, unsafe upload storage, archive extraction, symlink escape, and file disclosure
6. template injection, XSS, unsafe `safe`/`Markup`, and dynamic template names
7. deserialization and unsafe config/session/cache loading
8. CORS/CSRF/session mistakes for cookie-authenticated flows
9. sensitive data exposure through debug mode, tracebacks, logs, admin routes, or settings leaks
10. resource exhaustion from missing body, upload, timeout, parser, worker, or async concurrency limits

## Python Tooling Notes

Use tools as evidence collection, not as final proof:

- `pip-audit`, `osv-scanner`, `trivy fs`, or `grype dir:` for dependency inventory when manifests exist
- Semgrep Python rules for source patterns
- framework tests or minimal Docker PoCs for route, middleware, dependency, and settings behavior
- database fixtures for ORM and authorization checks

If tools are unavailable or noisy, record skipped or non-fatal status and keep
manual source-to-sink review moving. Confirm only with Docker evidence.

## Confirmed Finding Requirements

For each Python finding, the report should include:

- source file, route, handler/view, framework, and middleware/dependency/auth context
- controllable input and trust boundary
- exact sink and source-to-sink path
- why framework defaults, validation, decorators, permissions, settings, or parameterization do not block the issue
- Docker reproduction command and direct success oracle
- practical exploitation path and conservative severity rationale

Do not generate DOCX reports from playbook hypotheses alone. Confirmed
vulnerabilities belong only under `confirmed/<one-folder-per-vulnerability>/`
with `verification_status=confirmed_in_docker`.

## Reference Sources

- Flask quickstart and request APIs: https://flask.palletsprojects.com/en/stable/quickstart/
- Flask file uploads: https://flask.palletsprojects.com/en/stable/patterns/fileuploads/
- Flask web security: https://flask.palletsprojects.com/en/stable/web-security/
- Django security overview: https://docs.djangoproject.com/en/stable/topics/security/
- Django middleware: https://docs.djangoproject.com/en/stable/topics/http/middleware/
- Django file uploads: https://docs.djangoproject.com/en/stable/topics/http/file-uploads/
- Django raw SQL queries: https://docs.djangoproject.com/en/stable/topics/db/sql/
- Django REST framework viewsets: https://www.django-rest-framework.org/api-guide/viewsets/
- FastAPI path operations, dependencies, files, and security: https://fastapi.tiangolo.com/tutorial/path-params/, https://fastapi.tiangolo.com/tutorial/dependencies/, https://fastapi.tiangolo.com/tutorial/request-files/, https://fastapi.tiangolo.com/tutorial/security/
- Starlette routing, middleware, and requests: https://www.starlette.io/routing/, https://www.starlette.io/middleware/, https://www.starlette.io/requests/
- Python `pickle`, `subprocess`, `pathlib`, and `urllib.request`: https://docs.python.org/3/library/pickle.html, https://docs.python.org/3/library/subprocess.html, https://docs.python.org/3/library/pathlib.html, https://docs.python.org/3/library/urllib.request.html
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP XSS and CSRF Cheat Sheets: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html, https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
