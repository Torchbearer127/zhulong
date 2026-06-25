# P8 Dogfood Fixtures

These fixtures exercise the P8 bundle-contract retry-loop regression without
running Docker, replay helpers, PoCs, scanners, package managers, network
commands, or target code.

- `bad-contract.bundle-contract.json` intentionally combines several common
  generation mistakes so one contract preflight invocation can return multiple
  issue codes.
- `marker-only-replay-output.log` is a heading plus direct-impact marker only;
  final bundle validation must reject it as untrusted replay evidence.
