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

import sys
import os

if os.environ.get("AGENT_RUNTIME") == "1":
    raise ImportError(
        "This ops script must not be imported in agent runtime context. "
        "Set AGENT_RUNTIME=1 is reserved for the financial advisor service."
    )

import yaml
from langfuse import Langfuse
import os

# Initialize Langfuse
langfuse = Langfuse(
    public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
    secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
    host=os.getenv("LANGFUSE_HOST", "http://localhost:3000"),
)

def migrate_nemo_prompts(file_path):
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found.")
        return

    with open(file_path, "r") as f:
        data = yaml.safe_load(f)

    # NeMo prompts are typically in a list under the 'prompts' key
    prompts_list = data.get("prompts", [])
    
    for item in prompts_list:
        task_name = item.get("task")
        content = item.get("content")
        
        if task_name and content:
            print(f"Migrating task: {task_name}...")
            try:
                # Create prompt in Langfuse
                langfuse.create_prompt(
                    name=f"nemo/{task_name}", # Namespacing for organization
                    prompt=content,
                    type="text",
                    labels=["production"] # Sets as default version
                )
                print(f"✅ Successfully migrated {task_name}")
            except Exception as e:
                print(f"❌ Failed to migrate {task_name}: {e}")

def migrate_python_prompts():
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    prompts_to_migrate = [
        ("agent/financial_coordinator", "src.governed_financial_advisor.agents.financial_advisor.prompt", "FINANCIAL_COORDINATOR_FALLBACK_PROMPT"),
        ("agent/execution_analyst", "src.governed_financial_advisor.agents.execution_analyst.agent", "EXECUTION_ANALYST_FALLBACK_PROMPT"),
        ("agent/explainer", "src.governed_financial_advisor.agents.explainer.agent", "EXPLAINER_FALLBACK_PROMPT"),
        ("agent/governed_trader", "src.governed_financial_advisor.agents.governed_trader.agent", "EXECUTOR_FALLBACK_PROMPT"),
        ("agent/data_analyst_planner", "src.governed_financial_advisor.agents.data_analyst.agent", "PLANNER_PROMPT_TEXT"),
        ("agent/data_analyst_executor", "src.governed_financial_advisor.agents.data_analyst.agent", "EXECUTOR_PROMPT_TEXT"),
    ]

    for name, module_path, variable_name in prompts_to_migrate:
        print(f"Migrating python prompt: {name}...")
        try:
            # Use importlib to dynamically load the module and get the variable
            import importlib
            module = importlib.import_module(module_path)
            prompt_text = getattr(module, variable_name)
            
            langfuse.create_prompt(
                name=name,
                prompt=prompt_text,
                type="text",
                labels=["production"]
            )
            print(f"✅ Successfully migrated {name}")
        except Exception as e:
            print(f"❌ Failed to migrate {name}: {e}")

    # Special case for Evaluator (Prompt object)
    try:
        from src.governed_financial_advisor.agents.evaluator.agent import EVALUATOR_PROMPT_OBJ
        prompt_text = EVALUATOR_PROMPT_OBJ.prompt_data.contents[0].parts[0].text
        print(f"Migrating python prompt: agent/evaluator...")
        langfuse.create_prompt(
            name="agent/evaluator",
            prompt=prompt_text,
            type="text",
            labels=["production"]
        )
        print("✅ Successfully migrated agent/evaluator")
    except Exception as e:
        print(f"❌ Failed to migrate agent/evaluator: {e}")

if __name__ == "__main__":
    # Update this path to your local prompts.yml
    PATH_TO_PROMPTS = "config/rails/prompts.yml"
    migrate_nemo_prompts(PATH_TO_PROMPTS)
    migrate_python_prompts()

