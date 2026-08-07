# Sanitized Tool Registry Fixtures

The production selftest derives negative registry samples from the canonical
registry in a temporary directory. This avoids maintaining stale executable
tool configurations while still checking schema, authority, wrapper, path, and
declared-use failures. The manifest records the stable test cases and expected
issue codes; it contains no credentials, repositories, Docker image pulls,
network targets, PoCs, or scanner commands.
