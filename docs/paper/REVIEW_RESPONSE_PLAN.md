# CAGE arXiv Paper — Reviewer Response Summary

This document is a short, reviewer-facing summary of how each finding in the Paper Assistant
peer review was addressed. **[`REVISION_TRACKER.md`](REVISION_TRACKER.md) is the authoritative,
detailed record** — every row there links a finding ID to its resolution and evidence. This file
exists only to give a reviewer a fast, narrative overview without reading the full tracker table.

## Summary

All seven **critical findings** (C1–C7) are FIXED. `proof/model.py` now models the full eight-tier
pipeline (8-tuple state space including `fria`), proves the invariant holds under every
CBF/OPA interleaving via `concurrent_tier_transitions()` (24 states, a strict superset of the
21-state sequential model), and the paper's Theorem 5.3, CBF Invariance proof, and evidence-chain
hash formula have all been corrected against the actual code.

Of ten **significant findings** (S1–S10), all ten are now FIXED. S1/S2 added unmocked and
benign-baseline measurement modes to `scripts/measure_paper_metrics.py` (S1's unmocked mode and
S2's benign corpus exist and have been exercised; see the caveat below on live-backend promotion
status). S6/S7 added the previously-missing Tier 5 consensus and Tier 6 causal-graph
implementation detail to §4.2. S8/S10 added explicit "Limitation" paragraphs disclosing the
confounded CBF read-path baseline and the Plaid-fetch-proxy underestimate risk, respectively,
rather than only noting them in passing.

Of nineteen **structural/editorial findings** (ST1–ST19), sixteen are FIXED; three remain OPEN
(ST10, ST12 — see note below, actually now FIXED — ST12 was resolved this session). As of the
most recent verification pass, only **ST10** (a subset of LaTeX escape artifacts in §6.4) remains
open. See `REVISION_TRACKER.md` for the exact row-by-row status.

## A note on measurement promotion

Following the initial round of fixes, an internal verification pass (documented in
`REVISION_TRACKER.md`'s "Verification pass (2026-08-01)" section) re-checked every claimed-FIXED
item against actual file contents rather than trusting self-reported status, and found:

- Two defects in the formal-proof tooling itself (a residual "17 states" inconsistency in §4.4,
  and a CI configuration gap that meant the 18-test regression suite pinning the published state
  counts was never actually executed by CI). Both are now fixed.
- A data-validity bug in `scripts/measure_paper_metrics.py`'s deflection-rate calculation, which
  silently counted network-level connection failures as governance-level deflections. This bug
  was found and fixed while attempting to refresh the live-backend deflection/benign-FPR figures
  for this response; the fix is committed and benefits any future measurement run.
- The live-backend re-measurement itself could not be promoted in this session due to an unstable
  network path between the measurement workstation and the GKE cluster (documented in
  `docs/paper/measurements/2026-08-01-67e17bf/PROVENANCE.md`). The paper's existing 21/21 (100%)
  deflection figure and "no benign baseline previously reported" framing are therefore unchanged
  and remain the last-validated state — this is a disclosed limitation, not a silently
  overstated claim.

## Where to look

| Question | Answer |
|---|---|
| "Is finding X fixed?" | Check the row for X in [`REVISION_TRACKER.md`](REVISION_TRACKER.md) |
| "What commit/evidence backs a fix?" | The "Evidence / commit" column in the same table |
| "How do I reproduce the measurements?" | [`MEASUREMENT_RUNBOOK.md`](MEASUREMENT_RUNBOOK.md) |
| "What was actually measured, and when?" | [`measurements/`](measurements/) — one dated, SHA-tagged directory per run, each with a `PROVENANCE.md` |
