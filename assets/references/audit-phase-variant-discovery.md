# Seeded Variant Discovery Phase

Use this reference only after a valid confirmed bundle supplies a source-bound
seed and deterministic Docker success oracle.

## Working path

1. Extract a final seed card offline with `scripts/extract_variant_seed.py`.
   Validate the confirmed bundle and seed card before candidate search.
2. Run `scripts/find_variant_candidates.py` only against local text in the same
   target repository. Its output stays `status=candidate`.
3. Validate candidate JSONL separately from bundle validation.
4. Independently reproduce each variant through Docker or Docker Compose and
   build a separate confirmed bundle before promotion.

The seed card and similarity ranking are auxiliary evidence. They cannot replace
severity escalation, a verifier verdict, disposition, Docker evidence, or final
bundle validation.

## Exit

- Success: final seed and candidate files pass their validators; any confirmed
  variant also has its own Docker reproduction and bundle.
- Blocked: retain draft/candidate/unverified material outside `confirmed/`.
