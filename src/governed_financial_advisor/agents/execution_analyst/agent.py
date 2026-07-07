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

from pydantic import BaseModel, Field

from config.settings import MODEL_REASONING


# Define the Pydantic schema for the execution plan
class PlanStep(BaseModel):
    id: str = Field(description="Unique identifier for the step")
    action: str = Field(
        description="Action to perform (e.g., execute_trade, check_price)"
    )
    description: str = Field(description="Description of what this step does")
    parameters: dict[str, Any] = Field(description="Parameters for the action")


class ExecutionPlan(BaseModel):
    plan_id: str = Field(description="Unique identifier for the plan")
    strategy_name: str = Field(
        description="Name of the strategy (e.g., 'Conservative Dividend Growth')"
    )
    rationale: str = Field(
        description="Detailed explanation of why this strategy fits the user profile"
    )
    risk_factors: list[str] = Field(description="List of identified risk factors")
    steps: list[PlanStep] = Field(description="Ordered list of execution steps")

    # Context Fields
    user_risk_attitude: str | None = Field(
        None, description="The user's stated risk attitude"
    )
    user_investment_period: str | None = Field(
        None, description="The user's investment horizon"
    )


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
- `steps`: A DAG (Directed Acyclic Graph) of actions.
- `rationale`: Explain *why* this plan is safe and suitable.

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
    """
    import re

    # Strip DeepSeek <think>...</think> reasoning blocks
    cleaned = re.sub(r"<think>.*?</think>", "", raw_content, flags=re.DOTALL).strip()
    # Extract JSON object (first {...} block)
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON object found in response: {cleaned[:200]}")
    return ExecutionPlan.model_validate(_json.loads(match.group(0)))
