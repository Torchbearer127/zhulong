# Continuation and State

Use this reference when resuming an interrupted audit or handing it to another
local Agent.

## Authoritative and derived state

- `audit-events.jsonl` is the append-only authority; `stage-status.json` is its
  deterministic state view.
- `handoff-state.json`, checkpoints, `handoff-summary.md`, and
  `next-actions.json` are derived, advisory indexes. They cannot execute work,
  confirm findings, change disposition, create bundles, record success, or
  finalize an audit.
- `audit-timeline.json` and `audit-timeline.html` are deterministic, offline
  review projections of those validated facts. They add no authority and never
  replace the journal, state view, production validators, or finalization gate.

## Working path

1. Validate journal/state through the R2 protocol in
   `docs/runner-contracts/audit-state-protocol-r2.md`.
2. Read or render the structured handoff and checkpoint; verify their bound
   digests and revision.
3. Use `scripts/recover_audit_state.py` for read-only diagnostics or an explicit
   CAS-bound state-view rebuild. Never rewrite or truncate the journal.
4. Treat `scripts/render_next_actions.py` output as advice only; a local Agent
   still chooses and executes the next step under the applicable production gate.
5. For offline review, render and validate the static timeline with
   `scripts/render_audit_timeline.py` and `scripts/validate_audit_timeline.py`;
   do not infer confirmation from event text or directory names. Common
   credential shapes fail closed, and confirmed bundle links are shown only
   when the authority files prove one unique relationship. Visible URL text is
   not permission to create an external or active link.

## Exit

- Success: journal, state view, and derived indexes agree.
- Blocked: preserve diagnostics and resume instructions; do not hand-edit
  summary/state text to claim progress.
