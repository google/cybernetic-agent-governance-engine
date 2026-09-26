# Governor Golden Verdict Corpus

This directory contains the deterministic golden verdict corpus for the Symbolic Governor.

## Purpose

The golden verdict corpus captures baseline governance outcomes across the complete spectrum of governance scenarios and entry points:
- Entry points covered: `validate_action`, `govern`, `revalidate_post_hitl`, `verify`.
- Outcomes covered: `ALLOW`, `DENY` (via `GovernanceError` and refusal receipts), `DEFER`, `NARROW`, `REQUIRE_APPROVAL`, `ValueError` (for invalid actions), and simulation verdicts.
- Hard Guard: Guarantees that no internal programming faults (`TypeError`, `AttributeError`, `NameError`) are recorded as legitimate governance outcomes.

## Running the Golden Tests

Run the test suite against the frozen expectations:
```bash
uv run pytest tests/governor/golden/test_golden_verdicts.py -v -n0
```

## Regenerating the Golden Verdicts

When modifying the governor or underlying tiers intentionally, regenerate `expected.json`:
```bash
uv run pytest tests/governor/golden/test_golden_verdicts.py --regen-golden -v -n0
```

**PR Requirement:** Any pull request that changes `expected.json` MUST include an explicit rationale explaining why the verdicts, violations, seals, or collaborator invocation sequences shifted.
