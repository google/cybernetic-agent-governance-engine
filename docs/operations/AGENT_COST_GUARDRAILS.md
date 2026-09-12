# Agent Cost Guardrails & Dual-Engine Workflow Guide

> **Operational Standard — Dual-Engine Governance, Model Tier Routing, and Cache Economics.**
> This guide defines the operational configuration, tool separation, and cost-control guardrails
> implemented to eliminate runaway frontier model billing, cache-write penalty traps, and 200k+
> token context escalation boundaries.

---

## Table of Contents

1. [Economic Root-Cause Analysis](#1-economic-root-cause-analysis)
2. [Step 1: Repository Governance & In-Repo Configuration](#step-1-repository-governance--in-repo-configuration)
3. [Step 2: Google Antigravity Setup (Zero-Cost Ambient Tier)](#step-2-google-antigravity-setup-zero-cost-ambient-tier)
4. [Step 3: Zoo Code / Roo Code Setup (Targeted Execution Tier)](#step-3-zoo-code--roo-code-setup-targeted-execution-tier)
5. [Step 4: Keyboard Shortcuts & Tool Separation](#step-4-keyboard-shortcuts--tool-separation)
6. [Step 5: Day-to-Day Cost-Governed Workflow](#step-5-day-to-day-cost-governed-workflow)
7. [Step 6: Billing Safeguards & Metrics Auditing](#step-6-billing-safeguards--metrics-auditing)

---

## 1. Economic Root-Cause Analysis

Analysis of frontier AI coding agent billing indicates three primary drivers of runaway expense:

### 1.1 The Opus / Frontier Over-Utilization Trap
- **Empirical Billing Impact**: In our recent billing breakdown, Claude 5 (Opus 5) alone accounted for **over \$462 in 12 days**, driven by unconstrained context windows (200k–1M tokens) and cache-write penalties.
- **Frontier Pricing vs. Mid-Tier Pricing**: Claude 3.5/3.7 Opus costs \$15.00/M input tokens and \$75.00/M output tokens. Claude 3.7 Sonnet costs \$3.00/M input and \$15.00/M output (5x cheaper). Gemini 2.5 Flash costs \$0.075–\$0.15/M input (100x–200x cheaper).
- **Runaway Defect**: When an agent session defaults to Opus for general AST indexing, grep sweeps, boilerplate generation, or simple unit tests, massive context windows (100k–180k tokens) are repeatedly processed at frontier rates.
- **The Surgical Remedy**: Dropping Claude 5 completely compromises the quality of complex architectural design and tricky concurrency debugging. Instead, govern **when and how** it is invoked, treating it as an escalated, surgical consulting tool to keep its monthly share under **\$20–\$40/month**.

### 1.2 The Cache-Write Penalty Trap
- **Cache Read Discount**: Prompt caching offers a **90% price reduction** (\$0.30/M input tokens on Sonnet vs. \$3.00/M standard input).
- **Cache Write Surcharge**: Cache writes carry a **25% surcharge** (\$3.75/M input tokens on Sonnet).
- **Prefix Invalidation Defect**: Anthropic prompt caching relies on exact byte-for-byte prefix invariance. If dynamic timestamps (`YYYY-MM-DD HH:MM:SS`), randomized UUIDs, fluctuating git commit hashes, or changing file paths are inserted at the beginning of system prompts or headers, the entire cache is invalidated on every turn. The agent pays the 25% cache-write penalty on every turn instead of enjoying the 90% cache-read discount.
- **TTL Eviction**: The prompt cache has a 5-minute TTL. Pauses longer than 5 minutes between agent turns result in cache eviction, triggering another full cache write.
- **Remedy**: Prefix stability (zero dynamic headers in system prompts), compact turn times (< 5 minutes), and monitoring for an 80%+ Cache Read ratio.

### 1.3 The 200k+ Token Escalation Boundary
- **Empirical Billing Impact**: The billing audit revealed severe concentration in the **200,001 to 1,000,000 Token tier** (**\$165.45 in cache writes** and **\$152.07 in cache reads**).
- **Tier Escalation**: Model providers apply steep price escalations once context windows cross 200,000 tokens (often doubling the base per-million token rate).
- **Buffer Accumulation**: Large test execution outputs (e.g. running the entire enterprise test suite on every minor edit), unpruned diffs, and multiple open tabs push context beyond 200k tokens within 5–8 turns.
- **Remedy**: Strict sub-200k context ceiling, 1–2 open tabs maximum, two-phase testing lifecycle, and immediate context reset (`/clear`) upon task completion.

---

## Step 1: Repository Governance & In-Repo Configuration

Operational constraints are codified directly into the repository root:

1. **[`AGENTS.md`](../../AGENTS.md) Section 12**:
   - Codifies operational roles, tier enforcement, the 5-step tool cap, sub-200k ceiling, fail-fast rule, and cache invariance into the universal agent instructions ingested by Antigravity, Roo Code, Cline, Cursor, and Windsurf.
2. **[`.roomodes`](../../.roomodes)**:
   - Configures Roo Code / Zoo Code mode profiles (`code`, `architect`, `debug`, `ask`) directly in version control, ensuring all contributors inherit the strict Sonnet/Flash model routing and safety instructions.
3. **Two-Phase Testing Lifecycle**:
   - **Inner Loop (Active Turn)**: Target only the isolated test module:
     ```bash
     uv run pytest tests/unit/...::test_case -v
     ```
     This keeps terminal stdout buffers small (< 2k tokens) and avoids cache eviction.
   - **Gate Phase (Pre-Completion)**: Run the canonical fast suite once before handoff or PR creation:
     ```bash
     make test-fast
     ```

---

## Step 2: Google Antigravity Setup (Zero-Cost Ambient Tier)

Google Antigravity serves as the zero-cost ambient discovery and drafting tier.

### 2.1 Installation & Authentication
1. Install the **Google Antigravity** extension in VS Code.
2. Sign in with your Google account to enable standard quota tiers.

### 2.2 Model Backend Configuration
1. Open Antigravity Settings (`Cmd+,` or `Ctrl+,` $\rightarrow$ search `Antigravity`).
2. Set the default chat and agent model backend to **Gemini Flash** (e.g., `gemini-2.5-flash` or `gemini-3-flash`).
3. Enable **Inline Autocomplete / Ghost Text** in Antigravity settings to provide free, sub-second typing suggestions.

### 2.3 Subagent Workspace Isolation
To prevent concurrent file edit collisions and file lock contention:
- Configure Antigravity subagents to execute in an isolated Git Worktree or dedicated branch (`Workspace: branch` or `Workspace: share`).
- When executing concurrent research tasks, invoke the `research` subagent to isolate wide repository reads from the primary conversation context.

---

## Step 3: Zoo Code / Roo Code Setup (Targeted Execution Tier)

Zoo Code / Roo Code acts as the precision implementation engine.

### 3.1 Authentication & Provider Configuration

#### Primary: Google Cloud Vertex AI (Recommended)
Prioritizing Vertex AI consolidates billing within your Google Cloud project, maintains centralized budget alerts, and logs unified IAM audit trails:
1. Authenticate locally via Application Default Credentials (ADC):
   ```bash
   gcloud auth application-default login
   ```
2. In Zoo Code / Roo Code Settings $\rightarrow$ **API Provider**, select **Google Vertex AI**.
3. Set **Project ID** to your active GCP project (e.g., `laah-cybernetics`).
4. Set **Location** to your target region (e.g., `us-central1` or `us-east5`).

#### Fallback: Direct Anthropic API
If direct Anthropic routing is required:
1. In Zoo Code / Roo Code Settings $\rightarrow$ **API Provider**, select **Anthropic**.
2. Supply `ANTHROPIC_API_KEY` (stored securely in secret storage, never committed).

### 3.2 Mode-to-Model Assignment Matrix

The committed [`.roomodes`](../../.roomodes) file configures dedicated mode profiles separating daily Sonnet execution from surgical Claude 5 escalation:

| Mode | Assigned Model | Operational Scope & Guardrails |
|---|---|---|
| **Code** | `claude-3-7-sonnet` | **Mandatory daily driver.** Multi-file diffs, TDD loops, targeted refactoring. Max 5 tool calls per turn. |
| **Architect (Default)** | `claude-3-7-sonnet` | API route definitions, database migrations, component scaffolding, single-service interfaces. Delivers 95% of designs at ~1/5th cost. |
| **Escalated Architect** | `claude-opus-5` / `claude-fable-5.1` | **Surgical escalation only.** Multi-system boundaries, safety-critical state machines, distributed consensus, formal verification proofs. Max 1–3 turns. |
| **Debug (Default)** | `claude-3-7-sonnet` | Syntax errors, failed assertions, standard unit test failures, missing imports, single-function logic. Fail-fast after 2 turns. |
| **Escalated Debug** | `claude-opus-5` / `claude-fable-5.1` | **Surgical deep diagnosis only.** Elusive race conditions, distributed tracing anomalies, memory leaks, subtle deadlocks, or after Sonnet fails 2 turns. Max 1–3 turns. |
| **Ask** | `gemini-2.5-flash` / `claude-haiku` | General codebase Q&A. **Never** point Ask mode to Opus or Fable. |

### 3.3 The Three Affordability Rules for Claude 5 (Opus 5 / Fable 5.1)

To retain Claude 5's frontier reasoning while capping its billing share at **\$20–\$40/month**, every invocation of `escalated-architect` or `escalated-debug` must satisfy:

1. **Pre-Filter Context in the Free Tier (Antigravity + Gemini Flash)**:
   - Never let Claude 5 crawl directories or run wide greps to locate relevant files.
   - Use Gemini Flash in Google Antigravity to index the repo, locate the target modules, and produce a concise $\le$50-line briefing.
   - Paste only that briefing and the 1–2 target source files into Claude 5.
2. **Keep the Context Strictly Under 200k Tokens**:
   - The billing audit revealed severe cost escalation in the **200,001–1,000,000 token tier** (\$165.45 in cache writes and \$152.07 in cache reads).
   - Keeping sessions focused and below 200k tokens keeps prompt caching in the lower, non-penalized pricing bracket.
3. **Execute 1–3 Turns, Then Switch Back to Sonnet**:
   - Treat Claude 5 like a high-end external consulting architect: let it generate the spec or identify the root cause in Architect or Debug mode within 1–3 turns.
   - Once the design plan or bug diagnosis is written, switch Zoo Code back to **Code Mode (Sonnet)** to write the actual code and run tests.

### 3.4 Context & Cache Preservation Settings

Inside Roo Code / Zoo Code Extension Settings:
- **Prompt Caching**: Toggle **ON** (mandatory).
- **Max Consecutive Auto-Turns**: Set to **6–8** in the UI (enforcing the 5-step cap in `AGENTS.md`).
- **Open Tabs Context Limit**: Set to **1 or 2 tabs maximum**. Excess open tabs inject massive file contents into turn contexts.
- **Ghost Text / Inline Autocomplete**: Toggle **OFF** inside Zoo Code / Roo Code. This prevents extension UI collisions with Google Antigravity's free inline completions.

---

## Step 4: Keyboard Shortcuts & Tool Separation

To prevent accidental invocation of paid execution agents for simple questions, map distinct keyboard shortcuts in VS Code (`keybindings.json`):

| Action | Recommended Keybinding (macOS) | Recommended Keybinding (Linux/Win) | Target Engine & Purpose |
|---|---|---|---|
| **Antigravity Focus** | `Cmd+Alt+A` | `Ctrl+Alt+A` | Free repo discovery, AST lookup, general Q&A |
| **Antigravity Inline Explain / Docstring** | `Cmd+Alt+K` | `Ctrl+Alt+K` | Free docstring generation & inline code explanation |
| **Zoo Code / Roo Code Terminal Agent** | `Cmd+Shift+Z` | `Ctrl+Shift+Z` | Budgeted code execution, TDD edits, terminal commands |

---

## Step 5: Day-to-Day Cost-Governed Workflow

```
       [ FREE: Google Antigravity + Gemini Flash ]
                         │
         ┌───────────────┴───────────────┐
         │ • Whole-repo indexing & AST   │
         │ • "Where is this defined?"    │
         │ • Generate <=50-line briefing │
         └───────────────┬───────────────┘
                         │
                         ├─────────────────────────────────────────┐
                         │ (Standard Tasks & Daily Code)           │ (Complex Concurrency / Deep Architecture)
                         ▼                                         ▼
         [ BUDGETED: Zoo Code + Sonnet ]           [ SURGICAL ESCALATION: Claude 5 (1–3 Turns) ]
         ┌───────────────────────────────┐         ┌───────────────────────────────────────────┐
         │ • Code Mode: Multi-file diffs │         │ • Escalated Architect / Escalated Debug   │
         │ • TDD loops (Max 5 turns)     │ ◄────── │ • Strict sub-200k tokens                  │
         │ • Inner-loop unit tests       │ handoff │ • Produces spec or root-cause diagnosis   │
         │ • Full gate (make test-fast)  │         │ • Immediately hands off back to Sonnet    │
         │ • Context reset via /clear    │         └───────────────────────────────────────────┘
         └───────────────────────────────┘
```

### Phase 1: Free Exploration & Mapping (Google Antigravity)
- Run broad repository searches, trace caller hierarchies, and investigate dependency graphs in Antigravity.
- Let Gemini Flash absorb large multi-megabyte codebase contexts at zero or marginal cost.
- Synthesize findings into a concise, focused $\le$50-line briefing.

### Phase 2: Scoped Handoff & Model Selection
- Formulate a concise specification with exact target file paths and acceptance criteria.
- Open only the 1–2 target files in the editor.
- **Daily driver**: Select **Code Mode** (`claude-3-7-sonnet`) or **Architect Mode** (`claude-3-7-sonnet`).
- **Surgical escalation**: If and only if the task touches safety-critical distributed protocols, formal verification proofs, or elusive race conditions, invoke **Escalated Architect** or **Escalated Debug** (`claude-opus-5` / `claude-fable-5.1`).

### Phase 3: Governed Execution or Surgical Diagnosis
- **Under Sonnet**: Execute the diffs, run isolated unit tests (`uv run pytest tests/...::test_case -v`), and keep turns fast (< 5 min TTL).
- **Under Claude 5 (Surgical Escalation)**: Limit execution to 1–3 turns. Let Claude 5 output the architectural specification or identify the root-cause bug diagnosis. **Switch immediately back to Code Mode (Sonnet)** to write the code diffs and run tests.

### Phase 4: Full-Gate Verification & Immediate Context Reset
- Once the isolated test passes, execute `make test-fast` once to satisfy the repository full-gate invariant.
- The moment the test suite passes, issue `/clear`.
- Never carry terminal stdout histories, diff blobs, or compiler traces into the next task. Contexts crossing 200k tokens double the billing rate.

### Phase 5: Free Documentation & Annotation (Antigravity)
- Use Antigravity (`Cmd+Alt+K`) to generate docstrings, type hints, and comments without consuming paid token quotas.

---

## Step 6: Billing Safeguards & Metrics Auditing

### 6.1 GCP Cloud Console Budget Alerts
Configure organizational cost controls in Google Cloud Console:
1. Navigate to **Billing** $\rightarrow$ **Budgets & alerts**.
2. Create a budget scoped to your active project (e.g., `laah-cybernetics`) or billing account.
3. Configure alert thresholds at:
   - **\$500.00** (50% target ceiling — warning notification)
   - **\$1,000.00** (90% target ceiling — urgent operational review)
   - **\$1,500.00** (100% hard ceiling — stop paid agent execution)
4. Link alert channels to your primary developer email and Slack/notification webhook.

### 6.2 Session Token Metric Auditing
Inspect session metrics at the conclusion of each Zoo Code / Roo Code task:
- **Cache Read Ratio**: Should account for **80%+** of total input volume.
- **Cache Write Ratio**: Should remain **under 20%**.
- **Context Size**: Must remain **below 200,000 tokens** at all times.
- If Cache Write exceeds 25% or Cache Read drops below 70%, verify that system prompt prefixes do not contain dynamic timestamps, git hashes, or randomized session IDs.
