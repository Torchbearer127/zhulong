# SSRF Checklist

Use this concise checklist when a candidate involves attacker-controlled URLs,
webhooks, fetch/proxy features, import-from-URL flows, metadata callbacks, or
server-side HTTP clients.

## Scope and When To Use It

- Use for source-to-sink review of server-side outbound network requests.
- Prioritize routes that fetch user-provided URLs, follow redirects, proxy
  content, import remote files, or call internal services.
- This checklist is reasoning aid only; it cannot confirm a vulnerability.

## Common Sources

- Query, path, JSON body, form, header, cookie, webhook, or config URL fields.
- Redirect targets, callback URLs, avatar/image import URLs, RSS/feed URLs.
- Third-party responses that are later fetched by the server.

## High-Risk Sinks

- Java: `RestTemplate`, `WebClient`, `HttpURLConnection`, Apache HttpClient,
  OkHttp, JDK `HttpClient`.
- Go: `http.Get`, `http.Post`, `http.Client.Do`, custom redirect policies.
- Node/Python: `fetch`, `axios`, `request`, `got`, `requests`, `urllib`.
- DNS resolution, proxy connectors, cloud metadata endpoints, internal admin
  services, Redis/Memcached/HTTP admin ports.

## Source-To-Sink Tracing Hints

- Trace validation before and after redirects, DNS resolution, and proxy use.
- Check allowlist parsing, scheme restrictions, IP/range filtering, and DNS
  rebinding assumptions.
- Record whether the sink can reach localhost, RFC1918, link-local, IPv6, or
  cloud metadata addresses from inside Docker.

## Docker-Only Verification Ideas

- Run a target service and an attacker/listener container on the same Docker
  network.
- Use a controlled callback server and verify the target container makes the
  outbound request.
- For metadata/internal reachability claims, simulate the internal endpoint in
  Docker instead of probing real infrastructure.

## Severity-Escalation Evidence To Seek

- Unauthenticated reachability, cross-tenant reachability, internal service
  access, credential/token disclosure, redirect bypass, DNS rebinding, or
  write/action primitives beyond a blind callback.

## Common False Positives

- Client-side browser fetches mistaken for server-side requests.
- URL fields that are stored but never fetched by the server.
- Strong allowlists applied after redirects and after final IP resolution.
- Network egress blocked in the verified deployment.

## Confirmed-Only Routing Reminder

- Checklist matches and source-to-sink hypotheses stay in `candidate-findings.md`
  or `unverified-leads.md` until Docker evidence confirms impact.
- Do not generate DOCX reports from this checklist alone.
- Confirmed vulnerabilities belong only under
  `confirmed/<one-folder-per-vulnerability>/` with `verification_status=confirmed_in_docker`.
