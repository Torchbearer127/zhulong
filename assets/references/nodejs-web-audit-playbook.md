# Node.js Web Audit Playbook

Use this playbook when Zhulong identifies a Node.js Web repository, especially
Express, Koa, Fastify, Next.js API routes or route handlers, or services with
Docker/Kubernetes deployment artifacts.

This is source-to-sink audit guidance only. Playbook reasoning, route matches,
and framework patterns cannot confirm a vulnerability by themselves.

## Fast Model

Build an `attack-surface.md` note before deep verification.

Record:

- route or endpoint
- HTTP method
- handler, controller, API route, or route handler
- middleware chain and authentication requirement
- input source from query, path, header, cookie, body, multipart, webhook, or config
- downstream sink or service reached
- current verification status

Minimum entry inventory fields:

| Route / Endpoint | Method | Handler / Controller | Authentication Requirement | Input Source | Downstream Sink / Service | Current Verification Status |
| --- | --- | --- | --- | --- | --- | --- |

## Entry Points

Prioritize:

- Express `app.METHOD`, `router.METHOD`, `app.use`, error handlers, and mounted routers
- Koa `app.use`, `koa-router` routes, composed middleware, and context mutation
- Fastify `route`, `get/post/...`, hooks, plugins, schemas, and per-route config
- Next.js Pages API routes under `pages/api`, App Router route handlers, middleware, and server actions when present
- GraphQL handlers, webhook receivers, file upload endpoints, preview/debug routes, health/metrics routes

## Trust Boundaries

Treat these as untrusted unless proven otherwise:

- `req.query`, `req.params`, `req.body`, `req.headers`, cookies, multipart filenames and file contents
- Koa `ctx.query`, `ctx.params`, `ctx.request.body`, `ctx.headers`, and shared `ctx.state`
- Fastify `request.query`, `request.params`, `request.body`, `request.headers`, and decorators
- Next.js `req.query`, `NextRequest`, `request.json()`, route params, cookies, headers, and search params
- environment variables, JSON/YAML config, package metadata, plugin manifests, cache/queue messages, third-party HTTP responses

## High-Priority Sinks

Track source-to-sink flows into:

- command execution: `child_process.exec`, `execFile`, `spawn`, `fork`, shell wrappers, npm scripts
- file/path access: `fs.readFile`, `fs.writeFile`, streams, `path.join`, `path.resolve`, static serving, archive extraction
- SSRF: global `fetch`, `http.request`, `https.request`, `axios`, `got`, `node-fetch`, redirects and proxy agents
- prototype pollution: recursive merge, `lodash.merge`, `deepmerge`, `Object.assign`, object path setters, config merges
- template/XSS: EJS, Pug, Handlebars, Mustache, React/Next server-rendered output, `dangerouslySetInnerHTML`, trusted HTML helpers
- deserialization/config injection: JSON/YAML parsing into privileged options, `vm`, dynamic `require`/`import`, plugin loading
- auth/session/CORS/CSRF: route-specific middleware gaps, cookie flags, JWT verification, session fixation, overly broad CORS
- resource limits: body parser limits, file upload size/count, request timeouts, regex/parser exhaustion, unbounded concurrency

## Source-To-Sink Tracing Guidance

- Trace the exact middleware order before the handler, including mounted router prefixes and error paths.
- Record whether authentication, authorization, CSRF, CORS, validation, body limits, and file upload filters run before the sink.
- For SSRF, follow validation through redirects, URL parsing, DNS/IP checks, proxy settings, and final outbound request.
- For path traversal, check decode, normalize, join, symlink handling, and final resolved-path boundary checks.
- For prototype pollution, prove whether attacker-controlled keys reach a shared prototype or a security-sensitive option lookup.

## Docker-Only Verification Reminders

- Confirm only with a Docker or Docker Compose reproduction and a direct success oracle.
- Use controlled listener, filesystem sentinel, mock internal service, or minimal Node PoC containers rather than host execution.
- Record command, container/network settings, input payload, observed output, and why the result proves impact.
- Timeouts, blocked networking, scanner matches, source-to-sink hypotheses, and dependency alerts stay unconfirmed.

## Web Vulnerability Priorities

Audit Node.js Web services in this order:

1. authentication and authorization bypass, including missing middleware on mounted routers
2. SSRF with redirect, proxy, localhost, RFC1918, metadata, and DNS rebinding bypasses
3. command execution through shell interpolation, unsafe argument construction, or dynamic scripts
4. path traversal, unsafe upload storage, static serving, archive extraction, and symlink escape
5. prototype pollution that reaches a shared prototype or security-sensitive application behavior
6. template injection, XSS, trusted HTML helpers, and unsafe server-rendered content
7. deserialization, config injection, dynamic module loading, and plugin manifest trust
8. CORS/CSRF/session mistakes for cookie-authenticated flows
9. sensitive data exposure through logs, errors, debug endpoints, source maps, or Next.js build artifacts
10. resource exhaustion from missing body, upload, timeout, or parser limits

## Node.js Tooling Notes

Use tools as evidence collection, not as final proof:

- `npm audit` only when a lockfile is present
- `osv-scanner`, `trivy fs`, or `grype dir:` for dependency inventory when available
- Semgrep JavaScript/TypeScript rules for source patterns
- framework tests or minimal Docker PoCs for route and middleware behavior

If tools are unavailable or noisy, record skipped or non-fatal status and keep
manual source-to-sink review moving. Confirm only with Docker evidence.

## Confirmed Finding Requirements

For each Node.js finding, the report should include:

- source file, route, handler, framework, and middleware/auth context
- controllable input and trust boundary
- exact sink and source-to-sink path
- why framework defaults, validation, middleware, allowlists, or dependency versions do not block the issue
- Docker reproduction command and direct success oracle
- practical exploitation path and conservative severity rationale

Do not generate DOCX reports from playbook hypotheses alone. Confirmed
vulnerabilities belong only under `confirmed/<one-folder-per-vulnerability>/`
with `verification_status=confirmed_in_docker`.

## Reference Sources

- Express routing: https://expressjs.com/en/guide/routing.html
- Express middleware: https://expressjs.com/en/guide/using-middleware.html
- Express security best practices: https://expressjs.com/en/advanced/best-practice-security.html
- Koa documentation: https://koajs.com/
- Fastify routes: https://fastify.dev/docs/latest/Reference/Routes/
- Fastify hooks: https://fastify.dev/docs/latest/Reference/Hooks/
- Next.js API routes: https://nextjs.org/docs/pages/building-your-application/routing/api-routes
- Next.js route handlers: https://nextjs.org/docs/app/building-your-application/routing/route-handlers
- Node.js `child_process`: https://nodejs.org/api/child_process.html
- Node.js `fs`, `path`, and URL APIs: https://nodejs.org/api/fs.html, https://nodejs.org/api/path.html, https://nodejs.org/api/url.html
- OWASP Node.js Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP XSS and CSRF Cheat Sheets: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html, https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
