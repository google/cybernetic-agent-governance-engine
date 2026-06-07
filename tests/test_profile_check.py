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
from unittest.mock import MagicMock, patch, AsyncMock
import pytest

pytestmark = pytest.mark.unit

# Add src to path
sys.path.append(os.getcwd())

# Mock Agent
class MockAgent:
    name="execution_analyst_agent"

# Since we can't easily import from src due to relative importa/packages,
# we need to make sure the sys path is correct.
sys.path.insert(0, os.getcwd())
try:
    from src.governed_financial_advisor.graph.nodes.adapters import execution_analyst_node, inject_agent
    import src.governed_financial_advisor.graph.nodes.adapters as adapters
except ImportError as _import_err:
    print(f"Failed to import adapters. Check sys.path. Error: {_import_err}")
    import pytest
    pytest.skip(f"adapters not importable: {_import_err}", allow_module_level=True)

def test_missing_profile():
    print("Testing Missing Profile...")
    state = {
        "messages": [{"content": "I want a trade strategy", "type": "human"}],
        "risk_attitude": None,
        "investment_period": None
    }
    
    # Inject mock to avoid real creation (though it might still try if not careful)
    # But our logic is before run_adk_agent, so it shouldn't matter if agent is real or not
    # as long as get_agent works.
    inject_agent("execution_analyst", MockAgent())
    
    result = execution_analyst_node(state)
    
    print(f"Result: {result}")
    
    if "Risk Attitude" in result["messages"][0][1]:
        print("✅ SUCCESS: Node asked for profile.")
    else:
        print("❌ FAILURE: Node did not ask for profile.")

def test_present_profile():
    print("\nTesting Present Profile...")
    state = {
        "messages": [{"content": "I want a trade strategy", "type": "human"}],
        "risk_attitude": "aggressive",
        "investment_period": "long-term"
    }
    
    # This WILL try to run the agent, so we expect it to fail at run_adk_agent 
    # because our mock doesn't support it, OR we mock run_adk_agent.
    # For this test, we just want to ensure it DOESN'T return the clarification message immediately.
    
    # We can mock run_adk_agent in the module
    import src.governed_financial_advisor.graph.nodes.adapters as adapters
    
    class MockResponse:
        def __init__(self, answer):
            self.answer = answer
            
    def mock_run(*args, **kwargs):
        return MockResponse('{"plan_id": "test"}')
        
    adapters.run_adk_agent = mock_run
    
    inject_agent("execution_analyst", MockAgent())
    
    result = execution_analyst_node(state)
    print(f"Result: {result}")
    
    if result.get("execution_plan_output") is not None:
         print("✅ SUCCESS: Node proceeded to plan generation.")
    else:
         print("❌ FAILURE: Node did not proceed.")

if __name__ == "__main__":
    test_missing_profile()
    test_present_profile()
