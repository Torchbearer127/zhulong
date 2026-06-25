# Reviewer-Readiness Validator Gates

## Purpose And Boundary

Reviewer-readiness gates improve the quality of final confirmed-bundle review
materials. They are final-bundle quality gates: they do not discover
vulnerabilities, do not prove vulnerabilities, do not replace Docker evidence,
and do not turn candidate, scanner-only, static-only, blocked, or unverified
material into confirmed findings.

These gates must only add stricter rejection for reviewer-facing overclaims,
thin context, or unreadable replay helpers. They must never weaken existing
confirmed-bundle acceptance rules. Docker reproduction and successful final
confirmed-bundle validation remain required for confirmed status.

## SSRF Impact Overclaim

Purpose: keep SSRF impact wording aligned with the artifact-backed oracle.
Callback-only evidence supports a bounded outbound-request reachability claim,
not response content exposure, configuration leakage, credential disclosure, or
sensitive-data exposure.

What it prevents: a report, supplement, replay log, or reviewer index claiming
stronger SSRF impact than the bundle artifacts prove.

False-positive boundary: concise callback-only reports are accepted when they
state the verified boundary and explicitly avoid stronger exposure claims.
Stronger impact claims are accepted when the bundle contains concrete
artifact-backed oracle lines for response/configuration/credential/sensitive-data
exposure.

Accepted example: "Docker replay observed an attacker-controlled listener
callback. This bundle only claims outbound request reachability and does not
claim response content, configuration, credential, or sensitive-data exposure."

Rejected example: a replay log only shows "callback received" while the report
claims response content exposure, credential leakage, or sensitive-data exposure
without an artifact-backed oracle token.

Stable issue code: `SSRF_IMPACT_OVERCLAIM`.

Why it does not weaken confirmed-bundle gates: it narrows claims to the proven
impact tier or rejects the bundle. It does not accept any bundle without Docker
evidence or final validation.

## Code Context Minimum Quality

Purpose: make confirmed DOCX reports and reviewer material show enough source
context for a reviewer to understand the vulnerable chain.

What it prevents: sink-only one-liners, placeholder headings, or prose-only
context that hides the attacker-controlled input, propagation or branch,
dangerous sink, and missing or insufficient guard.

False-positive boundary: compact reports are accepted when they include a
project-relative path, line number or line range, multi-line code-like snippet,
input-to-sink explanation, missing guard, and verified impact boundary. If exact
line information is unavailable, the allowed case must explicitly justify that
unavailability while still supplying real source context.

Accepted example:

```text
src/import/fetcher.py:41-48
url = request.json["url"]
if not deny_private_host(url):
    body = requests.get(url, timeout=3).text
    return {"preview": body[:200]}

The attacker controls url. It reaches requests.get through the import path. The
private-network guard is incomplete, and Docker evidence only proves the stated
SSRF impact boundary.
```

Rejected example: `Key Code Context 1`, `待补充`, or a single sink-only line such
as `requests.get(url)` with no source path, line metadata, propagation, guard,
or impact-boundary explanation.

Stable issue code: `CODE_CONTEXT_MINIMUM_QUALITY`.

Why it does not weaken confirmed-bundle gates: it rejects thin reviewer context
for otherwise generated bundles. It does not relax Docker evidence, bundle
shape, or confirmed-only routing.

## Replay Helper Pause Contract

Purpose: keep the bundle-root replay helper readable for human reviewers and
screen recordings, not just machine automation, while keeping visual pauses
separate from functional readiness timing.

What it prevents: helpers that rush through identity, code context, analysis,
impact boundary, proof output, or evidence summary screens without readable
checkpoints; helpers that reuse reviewer pause variables for service readiness,
health polling, process startup, retry, or backoff waits; helpers that print a
machine-local evidence log path when a bundle-relative path is available.

False-positive boundary: quick mode may shorten pauses, and reviewers may set
`REVIEWER_PAUSE_SHORT=0 REVIEWER_PAUSE_LONG=0`, but the helper must still expose
overrideable pause variables and keep pause calls around reviewer-relevant
checkpoints. Functional waits may be shortened only through independent
readiness/backoff variables such as `READY_WAIT_SECONDS` or
`READY_RETRY_COUNT`.

Accepted example: the root helper defines `REVIEWER_PAUSE_SHORT` and
`REVIEWER_PAUSE_LONG`, derives `PAUSE_SHORT` and `PAUSE_LONG` from those
overrides, and calls `pause_step "$PAUSE_SHORT"` or `pause_step "$PAUSE_LONG"`
after the identity screen, code context, vulnerability analysis, impact-boundary
screen, proof command/output transitions, and final evidence summary. The same
helper defines independent readiness variables, for example
`READY_WAIT_SECONDS="${ZHULONG_READY_WAIT_SECONDS:-1}"`, and prints
`attachments/evidence/replay-output.log` instead of an absolute `$REPLAY_LOG`
path in reviewer-facing messages.

Rejected example: fixed `sleep 0`, hardcoded `pause_step 1`, quick mode that
overwrites reviewer pause settings, no pause around proof output, or no pause
after critical screens; a readiness loop that runs `sleep "$PAUSE_SHORT"` or
`sleep "$REVIEWER_PAUSE_SHORT"`; a failure message that prints `$REPLAY_LOG`
when that variable expands to a machine-local absolute path.

Stable issue codes: `REPLAY_HELPER_PAUSE_CONTRACT` for pause-specific failures
and `ROOT_SCRIPT_CONTEXT_MISSING` for missing context-screen failures.
`REPLAY_HELPER_READINESS_PAUSE_SEPARATION` covers readiness/backoff reuse of
reviewer pause variables. `REPLAY_HELPER_ABSOLUTE_EVIDENCE_PATH` covers
reviewer-facing evidence path messages that should be bundle-relative.

Why it does not weaken confirmed-bundle gates: it only rejects unreadable
reviewer replay helpers. It does not execute replay, manufacture evidence, or
relax proof-oracle requirements.

## Replay Transcript Trust Boundary

The replay transcript corpus under
`assets/fixtures/replay-transcript-corpus/` records positive and negative local
examples for replay-log trust. Replay logs must be real command/output/oracle
transcripts, but the gate does not require a single rigid log format.
Marker-only, placeholder-only, thin explanatory logs, and copied transcripts
without portable provenance are rejected.

## Maintenance Rule

Any new reviewer-readiness validator gate must add or update this
classification, add deterministic local-only positive and negative selftest
coverage, and add a release checklist entry in the same change. Tests for these
gates must not run Docker, replay scripts, PoCs, scanners, package managers,
network calls, or real target code.
