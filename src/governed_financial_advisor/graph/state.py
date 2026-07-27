# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from operator import add
from typing import Annotated, Any, Literal, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

# ---------------------------------------------------------------------------
# Transaction Ledger schema (Write-Ahead Log for Saga rollbacks)
# ---------------------------------------------------------------------------

LedgerEntryStatus = Literal[
    "PENDING",  # Intent written before API call (WAL)
    "COMPLETED",  # API call succeeded and ledger confirmed
    "ROLLED_BACK",  # Compensating action completed successfully
    "PARTIAL_FAILURE",  # Compensating action failed mid-way
]


class LedgerEntry(TypedDict):
    """A single record in the Saga transaction ledger.

    Fields:
        sequence_id:     Monotonically increasing int — used for LIFO rollback ordering.
        timestamp:       ISO-8601 UTC string — written at PENDING time.
        uca_ref:         The STPA UCA ID that governs this action (e.g. 'UCA-4').
        action:          The forward action name (e.g. 'execute_trade').
        idempotency_key: Derived key (hash of tx_id + action) to prevent double-refunds.
        status:          WAL transition state (PENDING → COMPLETED | ROLLED_BACK | PARTIAL_FAILURE).
        context_data:    Payload the compensating node needs to issue the reversal
                         (e.g. {'transaction_id': '...', 'amount': 500, 'account': 'A'}).
    """

    sequence_id: int
    timestamp: str
    uca_ref: str
    action: str
    idempotency_key: str
    status: LedgerEntryStatus
    context_data: dict[str, Any]


class AgentState(TypedDict):
    # The shared conversation history
    messages: Annotated[list[BaseMessage], add_messages]

    # Routing Control
    next_step: Literal[
        "data_analyst",
        "execution_analyst",
        "evaluator",
        "governed_trader",
        "explainer",
        "human_review",
        "FINISH",
    ]

    # Risk Loop Control
    risk_status: Literal["UNKNOWN", "APPROVED", "REJECTED_REVISE"]
    risk_feedback: str | None
    loop_count: int | None  # Track recursion depth for Safety Breaker

    # Safety & Optimization Control
    safety_status: Literal["APPROVED", "BLOCKED", "ESCALATED", "SKIPPED"]
    governance_signature: str | None  # Cryptographic-style approval from Evaluator

    # User Profile
    risk_attitude: str | None
    investment_period: str | None

    # Execution Data
    reasoning_output: str | None  # Holds the Thinker's logic for the Doer
    execution_plan_output: (
        str | dict | None
    )  # Holds the structured plan (System 4 Output)
    data_analyst_ticker: (
        str | None
    )  # Holds the ticker identified by Data Analyst Planner

    # CAGE / System 3 Control Signals
    evaluation_result: (
        dict[str, Any] | None
    )  # The Evaluator's Verdict & Simulation Results
    opa_results: dict[str, Any] | None  # Detailed policy engine outputs for the Auditor
    execution_result: (
        dict[str, Any] | None
    )  # The Executor's Technical Output (System 1)
    governance_summary: str | None  # Final auditor report for the UI

    user_id: str  # User Identity

    # Telemetry
    latency_stats: dict[str, float] | None  # For Bankruptcy Protocol (cumulative spend)

    # Saga Transaction Ledger (Write-Ahead Log)
    # Append-only via operator.add reducer — sorted by sequence_id DESC for LIFO rollback.
    # IMPORTANT: This field must be filtered out of any state passed to LLM-backed nodes
    # to prevent token bloat and information leakage about transaction internals.
    completed_transactions: Annotated[list[LedgerEntry], add]

    # Human-in-the-loop Approval (Phase 1b — LangGraph interrupt/Command pattern)
    approval_required: (
        bool  # default False — set True when trade value > $10k OR risk_score > 0.7
    )
    # approval_decision schema: {
    #   "approved":  bool,
    #   "reviewer":  str,   — ISO 42001 A.7.2 accountability attribution
    #   "rationale": str,   — mandatory justification; hashed into evidence chain
    #                         (ISO 42001 §6.1 / NIST AI RMF GOVERN-5)
    #   "comment":   str,   — optional supplementary note (legacy field)
    #   "timestamp": str,   — ISO-8601 UTC
    # }
    approval_decision: dict[str, Any] | None
    hitl_expires_at: str | None  # TTL expiration timestamp for pending state

    # NeMo Guardrail Gate (ADR 2026-03-09 — mandatory first-node enforcement)
    # Set by nemo_guardrail_node before any agent processes the input.
    # graph.py routes to END immediately when guardrail_blocked is True.
    guardrail_blocked: bool  # default False
    guardrail_reason: str  # empty string when not blocked

    # NeMo Output Rail (ADR 2026-03-09b — mandatory final-node enforcement)
    # Set True by nemo_output_rail_node after output screening/masking runs.
    # Every non-blocked execution path must pass through nemo_output_rail_node
    # before END.  Auditors can assert this field is True to confirm the rail
    # executed on a given trace.
    output_rail_applied: bool  # default False

    # FTRA — Forward-Looking Trajectory Reachability Analyzer (CTRL_FTRA_001)
    # Set by ftra_node (Tier 0.5 gate) between evaluator and safety_check.
    # ftra_status:    "CLEAR" | "HITL_REQUIRED" | "BLOCKED" | None (not yet run)
    # ftra_result:    Serialised ReachabilityResult dict from PlanGraphAnalyzer.
    # ftra_defer_id:  DeferQueue token ID when ftra_status == "HITL_REQUIRED".
    ftra_status: str | None  # default None
    ftra_result: dict[str, Any] | None  # default None
    ftra_defer_id: str | None  # default None
