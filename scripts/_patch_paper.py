#!/usr/bin/env python3
"""Patch CAGE_ARXIV.MD with all Phase 3/4/5 corrections.

Run: uv run python3 scripts/_patch_paper.py

Exit codes:
    0 — all replacements applied successfully (zero [MISS] lines)
    1 — one or more search strings were not found in CAGE_ARXIV.MD

A non-zero exit means the paper text has already been updated (or the
replacement block is stale).  Fix or remove the stale block before
committing.  Never suppress this exit code — it is the machine-enforceable
complement to the human evaluation gate in Step E of the measurement runbook
(docs/paper/MEASUREMENT_RUNBOOK.md).
"""
import sys
from pathlib import Path

paper = Path("CAGE_ARXIV.MD")
text = paper.read_text()

replacements = [
    # All Phase 3/4/5 corrections have been applied to CAGE_ARXIV.MD.
    # Blocks removed: 31 (all already-applied).
]

count_total = 0
miss_count = 0
for old, new in replacements:
    count = text.count(old)
    if count:
        text = text.replace(old, new)
        count_total += count
        print(f"  [{count}x] {old[:70].strip()!r}")
    else:
        print(f"  [MISS] {old[:70].strip()!r}")
        miss_count += 1

paper.write_text(text)
print(f"\nDone. {count_total} substitutions applied, {miss_count} missed.")

if miss_count:
    print(
        f"\nERROR: {miss_count} replacement block(s) did not match any text in "
        f"{paper}.\n"
        "The paper text may have already been updated, or the replacement block\n"
        "is stale. Fix or remove the stale block before committing.\n"
        "See docs/paper/MEASUREMENT_RUNBOOK.md Step F for guidance."
    )
    sys.exit(1)
