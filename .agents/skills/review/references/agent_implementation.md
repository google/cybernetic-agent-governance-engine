# AI Code Review — Subagent & Direct Execution Implementation

This reference defines the execution steps, JSON output schema, and Markdown
report format for the `review` skill.

## 1. Safety & Scope Invariants

- **Strictly Read-Only on Workspace Source Files**: Never modify, format, or
  delete tracked source files during the review phase.
- **No Temporary Files in Workspace Tree**: Write review outputs only to the
  caller-supplied `{output_file}` path outside the tracked repository tree.

## 2. Review Execution Procedure

1. **Inspect Target Scope (Diff Mode vs. Directory / Shard Mode)**:
   - **Diff Mode**: Determine modified files and unified diffs for the target
     revision/scope (e.g., `git diff HEAD`, `git diff main...HEAD`, or
     `git show <REV>`).
   - **Directory / Full-Repository Shard Mode**: Enumerate tracked files in the
     assigned shard or directory path (`git ls-files <paths>`), prioritizing
     entry points, governance boundaries, security-critical modules, and active
     configuration files.
2. **Load Applicable Rules & Standards**:
   - Read repository-level [`AGENTS.md`](../../../../AGENTS.md) and any
     directory-scoped rules or skills relevant to the target files:
     - Layer import boundaries (`src/gateway/` vs `src/cage_*/` vs
       `src/integrations/` vs `src/eval_harness/`, enforced by
       `scripts/check_import_boundaries.py`).
     - Governance Gate invariants (fail-closed execution via
       `verify_and_consume_seal()` and `ActuatorRegistry`, `SymbolicGovernor`
       composition root, trust-anchor `kid` resolution, advisor zero-governance
       state).
     - Secret hygiene, Apache 2.0 license headers, and pytest marker contracts.
3. **Evaluate Code Against Intent & Invariants**:
   - Check correctness, security/governance invariants, edge cases, test
     coverage, and documentation synchronization (`Gate G9`,
     `scripts/check_doc_references.py`).
   - Filter out low-signal nitpicks already enforced by automated formatters
     unless they violate an explicit repository standard.

## 3. Structured Review Result JSON Schema (`{output_file}`)

Write a UTF-8 JSON object to `{output_file}` (or `{shard_output_file}` when
running as a shard subagent) with the following structure:

```json
{
  "summary": "Concise 1-3 sentence assessment of the changes or shard against the stated intent and repository invariants.",
  "status": "APPROVED | NEEDS_CHANGES | COMMENTED",
  "scope": {
    "vcs": "git",
    "base_revision": "<base_sha_or_HEAD>",
    "target_revisions": ["<target_sha>"],
    "shard_id": "<optional_shard_id_or_all>",
    "changed_files": ["path/to/file.py"]
  },
  "findings": [
    {
      "finding_id": "1",
      "severity": "HIGH | MEDIUM | LOW | NIT",
      "category": "security | governance | bug | architecture | test | docs | style",
      "file": "src/path/to/file.py",
      "line_start": 42,
      "line_end": 48,
      "title": "Short summary of the issue",
      "description": "Clear explanation of why this is an issue and which invariant or requirement it affects.",
      "suggestion": "Concrete code fix or remediation steps."
    }
  ]
}
```

### Multi-Shard Consolidation Rules (Full-Repository Mode)

When consolidating multiple `{shard_output_file}` JSON documents into the final
`{output_file}`:
1. **Deduplicate & Sort Findings**: Deduplicate findings referencing the same
   `(file, line_start, title)`, sort by severity (`HIGH` → `MEDIUM` → `LOW` →
   `NIT`) and file path, and re-index `finding_id` sequentially (`"1"`, `"2"`,
   ...).
2. **Aggregate Status**:
   - `NEEDS_CHANGES` if any shard reported `NEEDS_CHANGES` or any finding has
     severity `HIGH` or `MEDIUM`.
   - `COMMENTED` if no `HIGH`/`MEDIUM` findings exist but at least one `LOW` or
     `NIT` finding is present.
   - `APPROVED` if all shards passed with zero findings.
3. **Merge Scope**: Union all `changed_files` across shards and synthesize an
   executive `summary` covering all audited shards.

## 4. Rendered Markdown Report Format

When rendering `{output_file}` without the Google3 Blaze `review_report_cli`
binary, format the report as follows:

```markdown
## 🔍 AI Code Review Report

**Status:** `{status}`
**Scope:** `{vcs}` (`{base_revision}..{target_revisions}`)
**Changed / Audited Files:** `{len(changed_files)}`

### Summary
{summary}

### Findings

#### [{finding_id}] `{severity}` — {title}
- **File:** [`{file}:{line_start}-{line_end}`](file:///{abs_path}#L{line_start}-L{line_end})
- **Category:** `{category}`
- **Issue:** {description}
- **Recommendation:**
  {suggestion}
```
If `findings` is empty, render `### Findings\n\nNo blocking issues or defects found.`

