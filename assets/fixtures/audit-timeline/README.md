# Audit timeline golden fixtures

This corpus contains five sanitized protocol scenarios and canonical JSON/HTML
goldens. `workspace/` files are protocol fixtures only; they are not real audit
results or confirmed vulnerabilities.

`completed-confirmed` is materialized by the selftest in a temporary directory
with the existing production bundle builder and validators. No Docker, PoC,
replay, network, package manager, model, or Agent is executed.

The manifest records the event sequence, terminal state, expected flow and
bundle counts, stable mutation labels, and canonical output SHA-256 values.
Goldens are compared as independent committed bytes; the generator is not used
as its own acceptance oracle.

All five golden acceptance scenarios are R2. A separate selftest exercises the
restricted `legacy_r1` review projection and verifies that it invents no R2
sequence, revision, run identity, recovery chain, or confirmed flow.
