# Go Web Audit Playbook

Use this playbook when Zhulong identifies a Go Web repository, especially
`net/http`, Gin, Echo, Fiber, Chi, Beego, or Go services with Docker/Kubernetes
deployment artifacts.

This guide supports source-to-sink review. It does not relax Zhulong's Docker
verification or confirmed-bundle requirements.

## Fast Model

Build an `attack-surface.md` note before deep verification.

Record:

- route registration location
- HTTP method and path
- middleware and authentication requirement
- request parameters read from query, path, header, cookie, body, multipart, or webhook payload
- downstream services reached
- high-risk sink reached, if any

## Entry Points

Prioritize:

- `main.go` for server startup, middleware, config loading, and listen address
- router setup in `router`, `routes`, `handler`, `handlers`, `api`, `controller`, `cmd`
- `http.HandleFunc`, `http.Handle`, `ServeHTTP`
- Gin `gin.Engine`, `router.GET/POST/...`, `c.Query`, `c.Param`, `c.Bind`, `c.ShouldBind`
- Echo/Fiber/Chi/Beego route registration and middleware chains
- pprof, metrics, health/debug endpoints

## Trust Boundaries

Treat these as untrusted unless proven otherwise:

- `r.URL.Query`, `r.FormValue`, `r.PostForm`, `r.PathValue`, headers, cookies
- `json.NewDecoder(r.Body).Decode`, `xml.Decoder`, multipart uploads
- external DB, Redis, MQ, K8s API, third-party HTTP responses
- environment variables, config files, ConfigMap, Secret, command-line flags

## High-Priority Sinks

Track source-to-sink flows into:

- command execution: `exec.Command`, `exec.CommandContext`, `syscall.Exec`, shell wrappers such as `sh -c`
- file access: `os.Open`, `os.ReadFile`, `os.WriteFile`, `os.MkdirAll`, `os.RemoveAll`, archive extraction
- SQL/ORM: `db.Query`, `db.Exec`, `fmt.Sprintf` SQL construction, ORM `Raw`
- SSRF: `http.Get`, `http.Post`, `http.Client.Do`, custom transports, redirect handling
- templates/XSS: `html/template`, `text/template`, `template.HTML`, `template.JS`, `template.URL`, manual HTML concatenation
- deserialization and parsing: `gob`, YAML, JSON/XML into privileged structs, unlimited body/depth parsing
- auth/session: middleware gaps, role extraction from user-controlled token fields, cookie flags
- TLS/crypto: `InsecureSkipVerify`, weak hashes, hardcoded secrets
- DoS: missing server/client timeouts, unbounded request bodies, unbounded goroutines, regex or parser exhaustion

## Web Vulnerability Priorities

Audit in this order for Go Web services:

1. authentication and authorization bypass, especially missing middleware on sensitive routes
2. SSRF with redirect, localhost, RFC1918, metadata, DNS rebinding, and timeout issues
3. command injection through shell wrappers or unsafe argument construction
4. path traversal, unsafe upload storage, archive extraction, and symlink escape
5. SQL injection through string-built queries or unsafe ORM raw SQL
6. template/XSS issues through trusted template types or manual HTML construction
7. mass assignment / struct injection into privileged business structs
8. CORS/CSRF mistakes for cookie-authenticated APIs
9. sensitive data exposure through logs, debug, pprof, metrics, or error responses
10. resource exhaustion from missing `http.Server` timeouts or body limits

## Go Tooling Notes

Use tools as evidence collection, not as final proof:

- `govulncheck ./...` for known Go vulnerabilities when available
- `gosec ./...` for common security anti-patterns
- `golangci-lint run` when configured or installed
- `go list -m all` for dependency inventory
- Semgrep Go rules for quick source pattern checks

If tools are unavailable, lack module context, or return noisy non-zero exits,
record skipped or non-fatal status and keep manual source-to-sink review moving.
Confirm only with Docker evidence.

## Confirmed Finding Requirements

For each Go finding, the report should include:

- source file, function, route, and middleware context
- controllable input and trust boundary
- exact sink and source-to-sink path
- why middleware, validation, timeout, whitelist, or standard-library defaults do not block the issue
- Docker reproduction command and direct success oracle
- practical exploitation path and conservative severity rationale
