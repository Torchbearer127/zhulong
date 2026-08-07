# Attack Surface Handoff

This sanitized fixture records a human-readable attack-surface map.  It is not
a vulnerability report, not raw scanner output, and not a replacement for a
candidate or verifier record.

## External Entry Points

- `ENTRY-HTTP-IMPORT`: `POST /api/import`, authenticated user, JSON `url` input.

## Trust Boundaries

- `BOUNDARY-HTTP-APP`: external request enters the import handler.

## High-Risk Sinks

- `SINK-NETWORK-FETCH`: `urllib.request.urlopen` receives the import URL.

## Review Scope

- Prioritize URL import validation and network fetch handling.
- Defer generated documentation examples until the source map is complete.
