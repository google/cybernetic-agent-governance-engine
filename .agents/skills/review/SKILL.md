---
name: review
description: "🔍 Performs an AI code review of workspace changes, specified revisions/PRs, individual directories/subsystems, or the entire repository (via sharded parallel subagents) by delegating to dynamic subagents or executing directly in the session. Use when the user asks to review changes, perform a self-review, review a specific commit/branch, or audit a directory or full repository. Don't use for preparing commits (like formatting, linting, description generation) or for running model evaluations."
metadata:
  icon: 👁️
---

# AI Code Review

Trigger an automated AI code review on code changes, specific packages, or the
entire repository by delegating to one or more dynamic subagents (when subagent
tools are available) or by directly executing the bundled
[`references/agent_implementation.md`](references/agent_implementation.md)
evaluation instructions in the current session. This skill is intended for
coding agents to review diffs interactively before opening PRs for human
review or to perform sharded architectural/governance audits across standard
version control systems (`git` or Jujutsu `jj`).

## Overview

This skill orchestrates AI code reviews across four granularities (working copy,
commit/branch diff, directory/subsystem, or sharded full-repository audit):

1.  **Scope Detection & Sharding**: Detects active VCS and determines the target
    scope (working copy, commit, stack, branch, directory, or full
    repository). Large or full-repository scopes are partitioned into
    architectural shards so each subagent inspects a focused, bounded file set.
2.  **Intent Extraction**: Extracts the goal and context of the changes (for
    diffs) or the architectural and governance invariants to verify (for
    directory/full-repo audits).
3.  **Review Execution**: Evaluates code against applicable review skills and
    project rules (`AGENTS.md`), delegating to a single `code_reviewer` subagent
    (for bounded diffs) or fanning out across concurrent shard subagents via a
    single `invoke_subagent` call (for full-repo/multi-shard audits).
4.  **Aggregation & Report Generation**: Merges shard JSON outputs (when
    sharded) into a unified `{output_file}` and renders structured findings into
    a Markdown review report.
5.  **Presentation & Fixes**: Presents findings to the user and applies
    requested fixes.

## When to Use

-   The user asks to "review my changes", "do a code review", "review this
    commit", "review the PR", "do a self-review", or something
    similar.
-   The user asks to "review the entire repo", "audit the repository", or
    "review `src/<package>/`" across a subsystem or directory.
-   You want to run an AI review on code changes before human review or
    submission.
-   **When not to use**: Do not use this skill for formatting, linting-only
    passes, commit message generation, or running model benchmark rollouts.

## Core Workflow

### Step 1: Infer Target Scope, Plan Shards & Record Start

Detect active workspace VCS (`git` or `jj`) and determine the exact review
scope:

1.  **Explicit Revision, Directory, or Full-Repository Scope**:
    -   **Revision / Branch**: If the user specified a target revision,
        commit SHA, or branch (e.g., `-r <REV>`, `HEAD~1`,
        `main..HEAD`, or `@-`), target that specific revision.
    -   **Directory / Subsystem Scope**: If the user specified one or more
        directory or file paths (e.g., "review `src/eval_harness/`"), target all
        tracked files under those paths at `HEAD` (`git ls-files <path>`).
    -   **Full-Repository Scope**: If the user asks to "review the entire repo"
        or "audit the whole codebase", select **Sharded Full-Repository Mode**
        at `HEAD` (`git rev-parse HEAD`) using the architectural shard map below.
2.  **Contextual Scope Inferencing (When Unspecified)**:
    -   **Commit Stack / Feature Branch**: If the user or agent worked on a
        feature branch or multi-commit stack, target the branch diff against
        `main` (`git diff main...HEAD` or `immutable()..@` in `jj`).
    -   **Parent Commit**: If the user asks to review the "last commit" or
        "previous change", target `HEAD` (`git show HEAD` or `@-` in `jj`).
    -   **Working Copy / Uncommitted Changes**: If there are modifications in
        the active working copy (`git status --porcelain`), target the working
        copy (`git diff HEAD` or `@` in `jj`).
    -   **Fallback**: If the working copy is empty and no revision was
        specified, inspect `git log -n 5 --oneline` to target `HEAD`
        or `main...HEAD`.
3.  **Architectural Sharding (Full-Repository or Large Cross-Layer Scopes)**:
    -   When reviewing the entire repository (or a diff/directory spanning $>25$
        files across multiple architectural layers), partition the scope into
        focused shards so each subagent can deeply inspect its assigned files
        without context truncation:

        | Shard ID | Paths Covered | Primary Review Focus |
        |---|---|---|
        | `kernel_core` | `src/gateway/core/`, `src/gateway/server/`, `src/gateway/client/`, `src/gateway/routing/` | Layer 1 purity (Gate G3), Linkerd mTLS workload identity (`l5d-client-id`), envelope integrity, zero vendor SDKs |
        | `kernel_governance` | `src/gateway/governance/` | `SymbolicGovernor` composition root, 5-state verdicts, routing seal single-use nonce consumption, `WarrantStage`, CBF/FTRA/OPA, PII & injection detectors |
        | `domains_and_advisor` | `src/cage_finance/`, `src/cage_healthcare/`, `src/governed_financial_advisor/` | Layer 2 `CagePlugin` contract, fail-closed `ActuatorRegistry` dispatch, advisor holds zero governance state or signing keys |
        | `integrations_and_bridge` | `src/integrations/`, `src/compliance_bridge/` | Layer 3 seam conformance (`NormativeProvider`, `AttestationProvider`), out-of-band `kid` trust-anchor resolution, `UNVERIFIED` vs cryptographic verification, WORM custody verifier |
        | `eval_and_proof` | `src/eval_harness/`, `proof/`, `scripts/` | Offline Eval split-plane isolation (`OFFLINE_EVAL_PATTERN`), Stage 0 `SKILL.md` linter, GEPA optimizer security screening, `proof/model.py` safety invariants |
        | `infra_compliance_docs` | `infra/`, `deployment/`, `compliance/`, `docs/`, `AGENTS.md`, `README.md` | Secret hygiene (`secretKeyRef`, no hardcoded credentials), OSCAL/Lula/STPA synchronization, Gate G9 documentation reference accuracy |

4.  **Generate a Run Identifier (`{run_id}`)**:

    -   Once the scope is known, generate a unique `{run_id}` (e.g.
        `run_id=$(uuidgen)`).

### Step 2: Determine & Communicate Change Intent (CRITICAL)

To perform a meaningful code review, the reviewer needs to understand the goal
and rationale of the changes or audit.

1.  **Extract Intent**:
    -   **Commit Descriptions (Diff Mode)**: Extract commit
        descriptions using the active VCS commands (e.g., `git log --format=%B
        -n 1 <REV>` for `git`, or `jj log -r <REV> --no-graph --no-pager
        --color=never -T description` for `jj`).
    -   **Architectural & Invariant Baseline (Directory / Full-Repo Mode)**:
        Run repository-wide deterministic verification gates once up front to
        supply concrete ground truth to the shard reviewers:
        ```bash
        uv run python scripts/check_import_boundaries.py
        uv run python scripts/check_doc_references.py
        uv run python scripts/check_stpa_freshness.py
        ```
    -   **Session Context**: Gather task objectives, bug details, or feature
        specs from the current conversation context.
2.  **Formulate Intent Summary**:
    -   Summarize:
        -   **Objective**: What problem is being solved, what feature is being
            added, or which architectural/governance invariants are being
            audited?
        -   **Key Logic Changes / Shard Scope**: High-level overview of modified
            components or the target shard boundaries.

### Step 3: Execute Code Review (Subagent Delegation or Direct Execution)

Set the review result output path `{output_file}` to a scratch/temp path outside
tracked repository files (e.g. `${TMPDIR:-/tmp}/review_result_{run_id}.json` or
the conversation artifact `scratch/review_result_{run_id}.json`; **never** write
temporary files inside the tracked workspace tree, to avoid polluting VCS
status). Then check whether subagent tools (`define_subagent` and
`invoke_subagent`) are available in your tool definitions:

#### Branch A: Multi-Agent Environment (Subagent Tools Available)

If `define_subagent` and `invoke_subagent` are available:

1.  **Define Subagent (`define_subagent`)**:

    -   **Name**: `code_reviewer` (if `code_reviewer` is already defined in the
        current session, reuse it directly via `invoke_subagent`).
    -   **Write Tools**: `enable_write_tools=true` (required so the subagent can
        run read-only VCS/verification commands, write the review result JSON,
        and perform customization discovery; instruct it in the system prompt
        never to modify workspace source files).
    -   **System Prompt**: Instruct the subagent to act as a strictly read-only
        code reviewer on workspace source files, read
        [`.agents/skills/review/references/agent_implementation.md`](references/agent_implementation.md),
        check workspace rules (`AGENTS.md` and `.agents/rules/`), evaluate code
        against discovered skills, scopes, and intent, and write the structured
        findings JSON to its assigned output file.

2.  **Invoke Subagent(s) (`invoke_subagent`)**:

    -   **Single-Scope Mode (Standard Diff or Single Subsystem)**:
        Launch one `code_reviewer` subagent writing directly to `{output_file}`
        with:
        -   **Reference Path**:
            `.agents/skills/review/references/agent_implementation.md`
        -   **Target Revision / Scope**: The requested scope (e.g., `HEAD`,
            `main...HEAD`, working copy, directory path, or CL number) and its
            resolved immutable commit hash(es).
        -   **Goal & Intent of Changes**: The formulated intent summary.
        -   **Output File**: `{output_file}`.
        -   **Instructions**: Read
            `.agents/skills/review/references/agent_implementation.md`, evaluate
            diffs/files against applicable rules and skills, write the review
            JSON to `{output_file}`, and return confirmation once written.

    -   **Sharded Full-Repo / Multi-Shard Mode**:
        Launch multiple concurrent `code_reviewer` entries in a **single**
        `invoke_subagent` call (`Subagents=[...]`), one per shard from Step 1.3:
        -   Assign each shard a distinct role (e.g.,
            `Role="Reviewer: kernel_governance"`) and a shard-specific output
            path `{shard_output_file}` =
            `scratch/review_result_{run_id}_{shard_id}.json`.
        -   Scope each subagent's prompt strictly to its shard's directories and
            invariants so subagents do not duplicate work across layers.
        -   Once all shard subagents report completion, merge all
            `{shard_output_file}` JSON documents into the consolidated
            `{output_file}` following the aggregation rules in
            [`references/agent_implementation.md`](references/agent_implementation.md).

#### Branch B: Single-Agent Environment (Subagent Tools Unavailable)

If `define_subagent` or `invoke_subagent` are NOT available in your toolset, do
NOT attempt to call missing tools or search for CLI workarounds. Read
[`references/agent_implementation.md`](references/agent_implementation.md) and
execute the review workflow directly in the current session (iterating shard by
shard when in full-repository mode) to write `{output_file}`.

### Step 4: Render Report

Once `{output_file}` is written:

1.  **Render Markdown Report**:
    -   Render the structured findings from `{output_file}` directly using the
        Markdown report format defined in
        [`references/agent_implementation.md`](references/agent_implementation.md).

### Step 5: Present Findings, Apply Fixes & Record Resolutions

Once review execution and report rendering complete:

1.  **Default Mode (Present Findings)**:
    -   Present the rendered Markdown report directly to the user without
        altering its structure.

2.  **Auto-Fix Mode**:
    -   If the user explicitly requested to address or fix findings immediately
        (e.g. "review and fix any issues"), parse the recommendations and apply
        code edits.
3.  **Record Resolutions (`record-resolution`)**:

    -   Whenever findings are addressed or dismissed — during an auto-fix pass
        or across later user follow-ups — write a top-level JSON array (`[...]`)
        of resolution objects (keyed by the `finding_id` from the review report)
        to `${TMPDIR:-/tmp}/review_resolutions_{run_id}.json` (or artifact
        `scratch/review_resolutions_{run_id}.json`; **never** write temporary
        files inside the tracked workspace tree):

        ```json
        [
          {
            "finding_id": "1",
            "status": "applied",
            "revision": "{commit_hash_of_the_fix}",
            "rationale": "Fixed as suggested.",
            "applied_diff": "{unified_diff}"
          },
          {
            "finding_id": "2",
            "status": "rejected",
            "rationale": "The type is already inferred from the return statement."
          }
        ]
        ```

    -   `status` is one of:
        -   `applied`: the suggested fix was applied as proposed.
        -   `modified`: the finding was addressed, but differently than
            suggested.
        -   `rejected`: the finding was dismissed, e.g. as a false positive.
        -   `acknowledged`: the finding is valid but deliberately left for a
            follow-up.

## Command Reference

-   **Git (Standalone Workspace)**:
    -   Check modified files: `git status --short` or `git diff --stat <REV>`
    -   Inspect descriptions: `git log -n 1 --format=%B <REV>`
-   **Jujutsu (`jj`)**:
    -   Check modified files: `jj diff --stat -r <REV> --no-pager --color=never`
    -   Inspect descriptions: `jj log -r <REV> --no-graph --no-pager --color=never -T description`

## Dependencies

-   [agent_implementation.md](references/agent_implementation.md) (Code review
    subagent instructions reference)

