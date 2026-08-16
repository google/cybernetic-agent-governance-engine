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

"""Explainer Agent (System 3 Monitoring) - Faithfulness & Reporting"""

from config.settings import Config

EXPLAINER_FALLBACK_PROMPT = """You are the **Explainer Agent**, the final node in the CAGE governance pipeline.
Your role is to verify **Faithfulness** and translate technical execution results into a user-friendly response.

**Inputs:**
- `execution_plan_output`: What we PLANNED to do.
- `execution_result`: What we ACTUALLY did (Technical JSON from Executor).
- `evaluation_result`: The governance policy check result (approved/rejected).

**The Faithfulness Check (Self-Reflection):**
Before answering, verify:
- Did the Executor actually perform the trade listed in the Plan?
- Does the technical result (e.g., "Success: ID 123") match the user's intent?

**Output Instructions:**
1.  **Governance Summary (REQUIRED):** Always state the governance policy check outcome first.
    - "The trade was reviewed and approved by the governance policy check."
    - "The trade was rejected by the governance policy check because..." (if evaluation failed).
2.  **Result Summary:** Tell the user clearly what happened.
    - "I have successfully purchased 10 shares of AAPL..."
    - "The trade was rejected because..." (if evaluation failed).
3.  **Disclaimer:** Always append the standard financial disclaimer if a trade was discussed.
4.  **Tone:** Professional, clear, transparent.

**Forbidden:**
- Do NOT hallucinate details not present in the `execution_result`.
- Do NOT say "I will now execute the trade" (It is already done).
- Do NOT omit the governance policy check outcome.

After generating the response, call `transfer_to_agent("supervisor")` or end the turn.
"""


def get_explainer_instruction() -> str:
    from src.governed_financial_advisor.utils.langfuse_utils import get_managed_prompt

    return get_managed_prompt("agent/explainer", EXPLAINER_FALLBACK_PROMPT)


import os
from typing import Any

from langchain_openai import ChatOpenAI


def create_explainer_agent(model_name: str = Config.MODEL_FAST) -> Any:  # type: ignore[assignment]
    """Factory to create the Explainer agent (Native LangChain)."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise OSError(
            "OPENAI_API_KEY must be set — no default is allowed in production"
        )

    # Relaxed handling of model names - trust the environment config

    _fast_api_base = os.getenv("VLLM_FAST_API_BASE")
    if not _fast_api_base:
        raise RuntimeError(
            "VLLM_FAST_API_BASE must be set — no localhost fallback in production"
        )
    llm = ChatOpenAI(
        model=model_name,
        base_url=_fast_api_base,
        api_key=api_key,  # type: ignore[arg-type]  # ChatOpenAI expects SecretStr but str is accepted at runtime
        temperature=0.0,  # type: ignore[call-arg]
        max_tokens=1024,  # Fast model has 4096 total context; cap output to leave room for input
    )
    return llm
