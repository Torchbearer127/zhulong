# Recon result fixture matrix

This fixture tree is portable and sanitized.  It contains two positive Recon
results and a manifest-driven negative matrix.  The selftest invokes the real
`scripts/validate_recon_result.py` subprocess for every matrix row, including
the temporary symlink-escape case.  No fixture is a vulnerability finding or a
stage-completion event.

- `service/` models a Docker Compose service with an HTTP entrypoint.
- `library/` models a library with no public network entrypoint.  Its
  `not_applicable` entrypoint coverage is evidence-backed.
- `manifest.json` lists the positive results and every negative mutation.

The target contract and `attack-surface.md` are hashed after their bytes are
fixed.  Relative paths are intentionally used throughout.
