# Candidate identity and deduplication fixture corpus

The structured manifest names the base, mutation, and expected result for every
case. The production selftest materializes the sanitized corpus in a temporary
repository/workspace, invokes the public CLIs by subprocess, records each
executed case ID, and fails if any manifest case is unexecuted or any executed
case is undeclared. It never runs Docker, target code, PoCs, scanners, DAST,
package managers, or network access.

Fingerprint and duplicate results are candidate-only metadata. They never
create a verifier verdict, disposition, confirmed bundle, event, or finalization
state.
