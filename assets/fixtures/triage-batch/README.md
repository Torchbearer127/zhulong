# Triage batch fixture matrix

These sanitized fixtures describe the P9 triage contract test matrix. The
selftest materializes their candidates in a temporary workspace and invokes the
production validators and stage finalizer as subprocesses; no fixture executes
Docker, a PoC, replay, network access, or an LLM.

The matrix covers complete, partial, and blocked batches; all five advisory
recommendations; duplicate chains and invalid duplicate graphs; exact candidate
bindings; explicit completeness; forbidden downstream-authority fields; and
Recon/triage terminal-state writes with revision/digest CAS failures.

An empty inventory is intentionally invalid. It cannot stand for "no
vulnerabilities" and cannot finalize triage.
