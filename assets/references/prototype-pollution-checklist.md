# Prototype Pollution Checklist

Use this concise checklist when a JavaScript or TypeScript candidate involves
recursive merge, object path assignment, query/body parsing, configuration
merging, or deserialization into plain objects.

## Scope and When To Use It

- Use for Node.js, browser-build tooling, or JS libraries that merge or assign
  attacker-controlled keys into objects.
- Prioritize flows involving `__proto__`, `constructor`, `prototype`, deep merge,
  path setters, YAML/JSON parsing, or option/config merging.
- This checklist is reasoning aid only; it cannot confirm a vulnerability.

## Common Sources

- JSON request bodies, query strings, form data, YAML/JSON config, package
  metadata, plugin manifests, CLI options, and nested object path strings.
- Keys named `__proto__`, `prototype`, `constructor`, or dotted/bracket paths.

## High-Risk Sinks

- Recursive merge/clone helpers, `lodash.merge`, `merge`, `deepmerge`, `extend`,
  `Object.assign` with unsafe target, path setters, `set-value`, `object-path`,
  parser output merged into global/default options.
- Security-sensitive option lookups such as template escaping, command options,
  authorization flags, file paths, or request defaults.

## Source-To-Sink Tracing Hints

- Trace whether polluted keys reach `Object.prototype` or another shared
  prototype, not only a local object.
- Check key filtering before recursion and before path assignment.
- Record the polluted property, the victim lookup, and why defaults or cloning do
  not isolate the object.

## Docker-Only Verification Ideas

- Run a minimal Node PoC inside Docker that imports the affected package or starts
  the target service, sends controlled input, and reads a direct oracle.
- Good oracles include `({}).polluted === <value>`, changed security option,
  template escaping bypass, file path pivot, or command/SSRF follow-on behavior.

## Severity-Escalation Evidence To Seek

- Pollution leading to auth bypass, template injection/XSS, SSRF option override,
  path traversal pivot, command execution option control, or durable application
  state modification.

## Common False Positives

- Pollution affects only a local object and no shared prototype or security
  decision.
- Modern dependency version blocks dangerous keys.
- The PoC sets a property but no reachable application behavior reads it.
- The source is developer-controlled config, not attacker-controlled input.

## Confirmed-Only Routing Reminder

- Checklist matches and source-to-sink hypotheses stay in `candidate-findings.md`
  or `unverified-leads.md` until Docker evidence confirms impact.
- Do not generate DOCX reports from this checklist alone.
- Confirmed vulnerabilities belong only under
  `confirmed/<one-folder-per-vulnerability>/` with `verification_status=confirmed_in_docker`.
