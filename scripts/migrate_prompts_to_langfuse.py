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

import os

import yaml
from langfuse import Langfuse


def _langfuse_client() -> Langfuse:
    return Langfuse(
        public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
        secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
        host=os.getenv("LANGFUSE_HOST", "http://localhost:3000"),
    )


def migrate_nemo_prompts(file_path: str) -> None:
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found.")
        return

    with open(file_path) as f:
        data = yaml.safe_load(f) or {}

    langfuse = _langfuse_client()
    prompts_list = data.get("prompts", [])

    for item in prompts_list:
        task_name = item.get("task")
        content = item.get("content")

        if task_name and content:
            print(f"Migrating task: {task_name}...")
            try:
                langfuse.create_prompt(
                    name=f"nemo/{task_name}",
                    prompt=content,
                    type="text",
                    labels=["production"],
                )
                print(f"✅ Successfully migrated {task_name}")
            except Exception as e:
                print(f"❌ Failed to migrate {task_name}: {e}")


def migrate_python_prompts() -> None:
    import importlib

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    langfuse = _langfuse_client()

    prompts_to_migrate = [
        (
            "agent/financial_coordinator",
            "src.governed_financial_advisor.agents.financial_advisor.prompt",
            "FINANCIAL_COORDINATOR_FALLBACK_PROMPT",
        ),
        (
            "agent/execution_analyst",
            "src.governed_financial_advisor.agents.execution_analyst.agent",
            "EXECUTION_ANALYST_FALLBACK_PROMPT",
        ),
        (
            "agent/explainer",
            "src.governed_financial_advisor.agents.explainer.agent",
            "EXPLAINER_FALLBACK_PROMPT",
        ),
        (
            "agent/governed_trader",
            "src.governed_financial_advisor.graph.subgraphs.governed_trader_graph",
            "EXECUTOR_FALLBACK_PROMPT",
        ),
        (
            "agent/evaluator",
            "src.governed_financial_advisor.agents.evaluator.agent",
            "_SYSTEM_PROMPT",
        ),
    ]

    for name, module_path, variable_name in prompts_to_migrate:
        print(f"Migrating python prompt: {name}...")
        try:
            module = importlib.import_module(module_path)
            prompt_text = str(getattr(module, variable_name))

            langfuse.create_prompt(
                name=name, prompt=prompt_text, type="text", labels=["production"]
            )
            print(f"✅ Successfully migrated {name}")
        except Exception as e:
            print(f"❌ Failed to migrate {name}: {e}")


if __name__ == "__main__":
    PATH_TO_PROMPTS = "config/rails/prompts.yml"
    migrate_nemo_prompts(PATH_TO_PROMPTS)
    migrate_python_prompts()
