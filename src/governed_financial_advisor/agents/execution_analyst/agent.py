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

"""Execution_analyst_agent (Planner) - System 4 Feedforward Engine"""

from typing import Any

from pydantic import BaseModel, Field, field_validator

from config.settings import MODEL_REASONING


# Define the Pydantic schema for the execution plan
#
# BUG-FTRA-SCHEMA-001 fix: plan_id/strategy_name/risk_factors and
# PlanStep.id/PlanStep.parameters were previously required with no defaults.
# The system prompt (EXECUTION_ANALYST_FALLBACK_PROMPT above) explicitly
# instructs the model to emit a minimal "Clarification Plan" — e.g. a single
# `ask_user` step with no strategy/risk-factor context — whenever the user's
# risk profile or investment horizon is missing. That minimal, prompt-mandated
# shape then failed strict Pydantic validation (5 "Field required" errors),
# which FTRA's dict->ExecutionPlan conversion (ftra/node_factory.py) treats as
# a parse failure and BLOCKs the request with CTRL_FTRA_001 — a plausible-
# looking governance denial that is actually a schema/prompt mismatch, not a
# governance decision. Giving these fields safe, empty defaults lets a valid
# Clarification Plan (steps=[ask_user], rationale=<why>, plan_id/strategy_name/
# risk_factors omitted) pass validation without forcing the LLM to fabricate
# placeholder strategy names or risk factors it has no basis for — the fields
# remain fully populated for any real trade-execution plan, since the model
# is still instructed (and, for the guided_json path, schema-constrained) to
# emit them whenever it has enough context to do so.
class PlanStep(BaseModel):
    id: str = Field(default="", description="Unique identifier for the step")
    action: str = Field(
        description="Action to perform (e.g., execute_trade, check_price)"
    )
    description: str = Field(description="Description of what this step does")
    parameters: dict[str, Any] = Field(
        default_factory=dict, description="Parameters for the action"
    )


class ExecutionPlan(BaseModel):
    plan_id: str = Field(default="", description="Unique identifier for the plan")
    strategy_name: str = Field(
        default="",
        description="Name of the strategy (e.g., 'Conservative Dividend Growth')",
    )
    rationale: str = Field(
        description="Detailed explanation of why this strategy fits the user profile"
    )
    risk_factors: list[str] = Field(
        default_factory=list, description="List of identified risk factors"
    )
    steps: list[PlanStep] = Field(description="Ordered list of execution steps")

    # Context Fields
    user_risk_attitude: str | None = Field(
        None, description="The user's stated risk attitude"
    )
    user_investment_period: str | None = Field(
        None, description="The user's investment horizon"
    )

    # P1 validators — catch semantically-incomplete plans that the guided_json
    # FSM can produce even when the schema is syntactically satisfied.  Both
    # validators raise ValueError on bad input so parse_execution_plan() and
    # the node's retry loop can detect and retry the generation.
    @field_validator("rationale")
    @classmethod
    def rationale_must_be_substantive(cls, v: str) -> str:
        """Reject empty or trivially short rationale strings.

        vLLM guided_json guarantees schema-valid JSON but not semantic
        completeness — it can produce rationale="" or rationale="N/A" while
        still satisfying the schema (no min_length constraint).  Enforcing a
        minimum length here causes parse_execution_plan() to raise ValueError,
        which the execution_analyst_node retry loop catches and retries.
        """
        stripped = v.strip()
        if len(stripped) < 20:  # noqa: PLR2004
            raise ValueError(
                f"rationale is too short ({len(stripped)} chars < 20); "
                "the model must provide a substantive explanation."
            )
        return stripped

    @field_validator("steps")
    @classmethod
    def steps_must_be_non_empty(cls, v: list[PlanStep]) -> list[PlanStep]:
        """Reject plans with no steps.

        An empty steps list is schema-valid but governance-fatal — FTRA's
        _parse_plan() returns None when steps=[] and the node_factory then
        BLOCKs the request with CTRL_FTRA_001.  Catching it here surfaces the
        defect as a ValueError so the retry loop can attempt regeneration.
        """
        if not v:
            raise ValueError(
                "steps list is empty; the model must produce at least one step."
            )
        return v


EXECUTION_ANALYST_FALLBACK_PROMPT = """You are the **Execution Analyst (Planner)**, the "System 4 Feedforward" engine of the CAGE architecture.
Your role is to translate high-level user intent into a concrete, machine-verifiable **Execution Plan**.

**Core Responsibilities:**
1.  **Strategy Formulation:** Analyze the user's risk attitude and investment period. If these are missing, your plan should be to ASK for them.
2.  **Decomposition:** Break down the goal into logical sub-tasks (e.g., "Check Market" -> "Verify Funds" -> "Execute Trade").
3.  **API Grounding:** You do NOT execute actions. You only select tools for the Executor to use later.
    - Available Actions: `execute_trade`, `check_market_status`, `check_balance`.
    - For `execute_trade`, you MUST specify `symbol`, `amount`, and `currency`.
    - Your plan should represent a "suggested set of specific trading strategies" (e.g., "Dollar Cost Averaging entry", "Stop-Loss setup") combined into a coherent execution flow.

**Input Context:**
- `market_data_analysis_output`: Use this to justify your strategy.
- `user_risk_attitude`: Conservative / Moderate / Aggressive (Look in Chat History if not provided).
- `user_investment_period`: Short / Medium / Long Term (Look in Chat History if not provided).

**Output Requirement:**
You must output a valid JSON object matching the `ExecutionPlan` schema.
DO NOT output any conversational text or markdown code blocks.
ONLY output the raw JSON.
- `steps`: A DAG (Directed Acyclic Graph) of actions. MUST contain at least one step.
- `rationale`: Explain *why* this plan is safe and suitable. MUST be at least one full sentence (≥20 characters). An empty string or "N/A" is NOT acceptable.

**Constraint - Missing Info:**
If the user says "buy Apple" but has not specified an amount, your plan should NOT include an `execute_trade` step.
Instead, your plan should be to ask the user for clarification.
HOWEVER, since you output a plan, if you cannot generate a trade plan, generate a "Clarification Plan"
where the action is to ask the user. But ideally, you should transfer back to the supervisor or use a "ask_user" tool if available.
For now, if info is missing, your plan MUST be to ask the user for clarification.
DO NOT assume a default risk profile or investment period.
You are called when a STRATEGY is needed, but you need context to generate it.

**Handling Rejections:**
If your previous plan was REJECTED by the Evaluator, you will receive `risk_feedback`.
You MUST revise your plan to address the specific feedback (e.g., "Market Closed" -> "Schedule for Open").

**Few-shot examples** (output ONLY the JSON — no markdown fences, no prose):

Example 1 — Trade execution plan (full context available):
{{
  "plan_id": "plan-001",
  "strategy_name": "Conservative Dollar Cost Averaging — NVDA",
  "rationale": "The user has a conservative risk profile with a medium-term horizon. NVDA shows strong fundamentals and the market is currently open. A single-tranche market-order entry minimises timing risk while keeping position size within the user's stated budget.",
  "risk_factors": ["equity market volatility", "semiconductor sector concentration"],
  "steps": [
    {{"id": "s1", "action": "check_market_status", "description": "Confirm NVDA market is open before placing order", "parameters": {{"symbol": "NVDA"}}}},
    {{"id": "s2", "action": "check_balance", "description": "Verify sufficient funds for $1000 purchase", "parameters": {{"required_amount": 1000, "currency": "USD"}}}},
    {{"id": "s3", "action": "execute_trade", "description": "Buy $1000 of NVDA at market price", "parameters": {{"symbol": "NVDA", "amount": 1000, "currency": "USD"}}}}
  ],
  "user_risk_attitude": "Conservative",
  "user_investment_period": "Medium"
}}

Example 2 — Clarification plan (risk profile missing):
{{
  "plan_id": "plan-002",
  "strategy_name": "Clarification Required",
  "rationale": "The user has not specified a risk tolerance or investment horizon. Without these parameters it is not possible to formulate a safe, personalised strategy. Clarification must be obtained before any trade can be planned.",
  "risk_factors": [],
  "steps": [
    {{"id": "s1", "action": "check_balance", "description": "Ask the user for their risk profile and investment horizon before proceeding", "parameters": {{}}}}
  ],
  "user_risk_attitude": null,
  "user_investment_period": null
}}
"""


def get_execution_analyst_instruction() -> str:
    from src.governed_financial_advisor.utils.langfuse_utils import get_managed_prompt

    return get_managed_prompt(
        "agent/execution_analyst", EXECUTION_ANALYST_FALLBACK_PROMPT
    )


import json as _json

from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI

from config.settings import Config


def create_execution_analyst_agent(model_name: str = MODEL_REASONING):
    """Factory to create execution analyst agent.

    Uses VLLM_REASONING_API_BASE for the inference endpoint — the gateway
    (GATEWAY_API_BASE / GATEWAY_URL) is an MCP/governance gateway, not an
    OpenAI-compatible LLM endpoint, so pointing the LLM client there returns 404.

    Uses vLLM's guided_json FSM decoder (extra_body={"guided_json": schema}) to
    guarantee the output conforms to ExecutionPlan without any tool-calling path.
    This completely bypasses the need for --enable-auto-tool-choice on vLLM.
    The FSM constrains token sampling at the logit level — no post-processing needed.
    """
    schema = ExecutionPlan.model_json_schema()

    llm = ChatOpenAI(
        model=model_name,
        base_url=Config.VLLM_REASONING_API_BASE,
        temperature=0.0,
        max_tokens=4096,
        model_kwargs={
            # Activate vLLM outlines FSM decoder — guarantees valid JSON schema output.
            # This is a vLLM-specific extra_body parameter passed directly to the API.
            # It does NOT use tool-calling, so no --enable-auto-tool-choice needed.
            "extra_body": {"guided_json": schema}
        },
    )

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", get_execution_analyst_instruction()),
            MessagesPlaceholder(variable_name="messages"),
        ]
    )

    chain = prompt | llm
    return chain


def parse_execution_plan(raw_content: str) -> ExecutionPlan:
    """Parse raw LLM text output into an ExecutionPlan, stripping <think> blocks.

    The guided_json FSM guarantees valid JSON, but DeepSeek may still prepend
    <think>...</think> reasoning blocks before the JSON payload.

    vLLM defect workaround: under certain guided-decoding (outlines FSM) code
    paths, vLLM has been observed to return the raw GPT-2-style byte-level BPE
    placeholder characters instead of properly detokenized whitespace —
    U+0120 "Ġ" for a literal space and U+010A "Ċ" for a literal newline (these
    are the byte-level BPE encodings ChatGPT-family tokenizers use internally
    for " " and "\n" respectively; they should never survive detokenization
    into user-facing text). When this happens, e.g. `{Ġ"steps":Ġ[Ċ]}`,
    `json.loads()` fails immediately with "Expecting property name enclosed
    in double quotes: line 1 column 2" because Ġ/Ċ are not valid JSON
    whitespace. Confirmed via live GKE trace (BUG-FTRA-JSON-001): every
    execution-plan generation failed this way, causing the downstream FTRA
    gate to BLOCK the trade with a plausible-looking but incorrect governance
    denial (CTRL_FTRA_001) — a generation/tokenizer defect masquerading as a
    real policy decision. Translating these markers back to real whitespace
    before parsing is a safe, targeted fix that does not affect normal
    (correctly detokenized) output, since Ġ/Ċ never appear in valid content.
    """
    import re

    # Strip DeepSeek <think>...</think> reasoning blocks
    cleaned = re.sub(r"<think>.*?</think>", "", raw_content, flags=re.DOTALL).strip()
    # Normalize raw GPT-2 byte-level BPE whitespace markers back to real
    # whitespace (see docstring above) before attempting to locate/parse JSON.
    cleaned = cleaned.replace("\u0120", " ").replace("\u010a", "\n")
    # Extract JSON object (first {...} block)
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON object found in response: {cleaned[:200]}")
    return ExecutionPlan.model_validate(_json.loads(match.group(0)))
