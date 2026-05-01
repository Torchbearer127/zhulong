# Node.js Library Audit Playbook

Use this playbook when Zhulong identifies a Node.js package or pure library
instead of a web service. Typical examples are parsers, serializers, validators,
CLI helpers, build tools, SDKs, template helpers, and utility packages.

This is source-to-sink audit guidance only. Package metadata, API matches,
dependency alerts, and static hypotheses cannot confirm a vulnerability by
themselves. Confirmed findings still require Docker reproduction and a direct
success oracle.

## Fast Model

Build an `attack-surface.md` note before deep verification.

Record library-facing entry points rather than HTTP routes:

- exported function, class, parser, processor, transform stream, or CLI command
- input shape controlled by the caller or by attacker-supplied data
- security-relevant options and defaults
- transformation path through parser, normalizer, merge, resolver, renderer, or sink
- consumer impact assumption and whether the impact is library-local or application-level
- current verification status

Minimum library inventory fields:

| Public API / CLI | Input Shape | Caller-Controlled Options | Transformation Path | High-Risk Sink | Consumer Impact Assumption | Current Verification Status |
| --- | --- | --- | --- | --- | --- | --- |

## Entry Points

Prioritize:

- `main`, `module`, `exports`, `types`, and `bin` entries from `package.json`
- exported functions, classes, constructors, streams, parser callbacks, and processor hooks
- CLI argument parsing, file path arguments, environment variables, and config files
- plugin, callback, reviver/replacer, template helper, serializer, or deserializer extension points
- transitive data passed into object construction, merge, clone, path resolution, rendering, or child process helpers

## Trust Boundaries

Treat these as untrusted unless proven otherwise:

- XML/JSON/YAML/CSV/HTML/Markdown input parsed by the library
- object keys, attribute names, tag names, filenames, archive members, URLs, and template names
- caller-provided option objects when attackers can influence framework configuration or plugin manifests
- callback return values, plugin manifests, package metadata, cache entries, and third-party HTTP responses

## High-Priority Sinks

Track source-to-sink flows into:

- prototype property injection: `__proto__`, `constructor`, `prototype`, recursive merge, object path setters, `Object.defineProperty`, and option lookups
- path and archive handling: `fs`, `path.join`, `path.resolve`, symlink behavior, extraction targets, and glob expansion
- command execution: `child_process`, shell interpolation, npm script execution, and dynamic tool invocation
- rendering and injection: template engines, HTML/Markdown rendering, trusted HTML helpers, and escaping bypasses
- deserialization/config injection: YAML/JSON parsing into privileged options, dynamic `require`/`import`, `vm`, and function construction
- resource exhaustion: parser recursion, entity/attribute explosion, regex backtracking, large input buffering, and unbounded concurrency

## Source-To-Sink Tracing Guidance

- Start from the public API or CLI invocation, not from an HTTP route.
- Record required caller options separately from attacker-controlled payload fields.
- Prove whether the vulnerable behavior is only a surprising return shape, a local exception, or an application-level impact.
- For prototype issues, distinguish own-property injection from global prototype pollution and from security-sensitive option lookup impact.
- For parser issues, record malformed input, parser mode, default options, and whether the sink is reached before validation or normalization.

## Docker-Only Verification Reminders

- Use a minimal Node.js Docker image or project-specific container to run the library PoC.
- Keep PoCs small and deterministic: install the target package, run one script, assert one oracle.
- Record command, image, package version or local path, input payload, observed output, and why the result proves impact.
- Dependency alerts, static paths, and consumer-impact assumptions stay unconfirmed until Docker evidence proves the behavior.

## Confirmed Finding Requirements

For each Node.js library finding, the report should include:

- package name, version or commit, public API/CLI entry, and affected source file/function
- controllable input shape and any required caller-controlled options
- exact source-to-sink path and sink behavior
- distinction between library-local behavior and practical consumer impact
- Docker reproduction command and direct success oracle
- conservative severity rationale that does not overclaim application impact

Do not generate DOCX reports from playbook hypotheses alone. Confirmed
vulnerabilities belong only under `confirmed/<one-folder-per-vulnerability>/`
with `verification_status=confirmed_in_docker`.

## Reference Sources

- Node.js packages documentation: https://docs.npmjs.com/cli/v10/configuring-npm/package-json
- Node.js modules: https://nodejs.org/api/modules.html
- Node.js `child_process`: https://nodejs.org/api/child_process.html
- Node.js `fs`, `path`, and URL APIs: https://nodejs.org/api/fs.html, https://nodejs.org/api/path.html, https://nodejs.org/api/url.html
- OWASP Prototype Pollution Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html
- OWASP Node.js Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html
