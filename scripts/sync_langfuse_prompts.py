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

import os
import sys

if os.environ.get("AGENT_RUNTIME") == "1":
    raise ImportError(
        "This ops script must not be imported in agent runtime context. "
        "Set AGENT_RUNTIME=1 is reserved for the financial advisor service."
    )

from dotenv import load_dotenv

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv(".env")

# Direct imports from agents to get fallback strings
from src.governed_financial_advisor.agents.data_analyst.agent import (
    EXECUTOR_PROMPT_TEXT,
    PLANNER_PROMPT_TEXT,
)
from src.governed_financial_advisor.agents.execution_analyst.agent import (
    EXECUTION_ANALYST_FALLBACK_PROMPT,
)
from src.governed_financial_advisor.agents.explainer.agent import (
    EXPLAINER_FALLBACK_PROMPT,
)
from src.governed_financial_advisor.agents.financial_advisor.prompt import (
    FINANCIAL_COORDINATOR_FALLBACK_PROMPT,
)
from src.governed_financial_advisor.agents.governed_trader.agent import (
    EXECUTOR_FALLBACK_PROMPT as GOVERNED_TRADER_FALLBACK_PROMPT,
)

PROMPTS_TO_SYNC = {
    "agent/financial_coordinator": FINANCIAL_COORDINATOR_FALLBACK_PROMPT,
    "agent/data_analyst_planner": PLANNER_PROMPT_TEXT,
    "agent/data_analyst_executor": EXECUTOR_PROMPT_TEXT,
    "agent/execution_analyst": EXECUTION_ANALYST_FALLBACK_PROMPT,
    "agent/explainer": EXPLAINER_FALLBACK_PROMPT,
    "agent/governed_trader": GOVERNED_TRADER_FALLBACK_PROMPT,
}


def sync_prompts():
    from langfuse import Langfuse

    client = Langfuse(
        public_key=os.environ["LANGFUSE_PUBLIC_KEY"],
        secret_key=os.environ["LANGFUSE_SECRET_KEY"],
        host=os.environ.get("LANGFUSE_HOST", "http://localhost:3000"),
    )

    print("Syncing prompts to Langfuse...")
    for name, content in PROMPTS_TO_SYNC.items():
        try:
            # Create the prompt in Langfuse
            client.create_prompt(
                name=name, prompt=content, type="text", labels=["production"]
            )
            print(f"✅ Successfully synced and labelled 'production' prompt: {name}")
        except Exception as e:
            print(f"❌ Failed to sync {name}: {e}")

    client.flush()


if __name__ == "__main__":
    sync_prompts()
