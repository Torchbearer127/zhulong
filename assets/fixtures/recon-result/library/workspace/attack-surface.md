# Attack Surface Handoff

This sanitized fixture describes a library API map.  No public HTTP, RPC, or
CLI deployment entrypoint is applicable to this target.  Consumer impact is a
separate verification concern and is not a Recon finding.

## Library API

- `ENTRY-LIBRARY-PARSE` is intentionally not a public network entrypoint.
- `FOCUS-LIBRARY-PARSER` covers the exported parser API and caller options.

## Trust Boundary

- `BOUNDARY-LIBRARY-CONSUMER`: a consumer passes text and options to the API.
