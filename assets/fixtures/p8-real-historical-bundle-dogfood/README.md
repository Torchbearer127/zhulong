# P8 Real Historical Bundle Dogfood Fixtures

This directory contains sanitized, local-only traces derived from historical
bundle-generation failures. They are intentionally neutral:

- no original target names
- no machine-local absolute paths
- no payloads
- no credentials or tokens
- no submitted bundle paths

The fixtures are for P8-post.4 generation-workflow dogfood only. They do not
execute Docker, PoCs, replay helpers, scanners, package managers, network calls,
or target code, and they do not confirm new vulnerabilities.

