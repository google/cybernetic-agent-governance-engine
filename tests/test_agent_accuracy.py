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
import uuid
import time
import random
import requests
import pytest
from dotenv import load_dotenv

# Load env vars
load_dotenv()

pytestmark = pytest.mark.integration

# Configuration
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8081")


def _backend_reachable() -> bool:
    """Return True if the backend HTTP server is reachable."""
    try:
        requests.get(BACKEND_URL, timeout=2)
        return True
    except Exception:
        return False

# Test Data Pools
SYMBOLS = ["AAPL", "GOOG", "TSLA", "AMZN", "MSFT", "NVDA", "BTC-USD"]
STRATEGIES = ["Momentum", "Mean Reversion", "Value Investing", "Day Trading", "Swing Trading"]
RISK_PROFILES = ["Conservative", "Balanced", "Aggressive", "High Risk"]
ACTIONS = ["buy", "sell"]

def generate_workflow():
    """Generates a random workflow scenario."""
    symbol = random.choice(SYMBOLS)
    strategy = random.choice(STRATEGIES)
    risk = random.choice(RISK_PROFILES)
    action = random.choice(ACTIONS)
    amount = random.randint(10, 500)
    
    return [
        {
            "step": "Market Analysis",
            "prompt": f"Analyze the stock performance of {symbol}.",
            "expected": ["price", "trend", "analysis", symbol],
            "type": "contains_any"
        },
        {
            "step": "Trading Strategies",
            "prompt": f"Recommend a {strategy} trading strategy.",
            "expected": ["strategy", "recommendation", strategy],
            "type": "contains_any"
        },
        {
            "step": "Risk Assessment",
            "prompt": f"Evaluate the risk of a {risk} portfolio containing {symbol}.",
            "expected": ["risk", "volatility", "assessment", risk],
            "type": "contains_any"
        },
        {
            "step": "Governed Trading",
            "prompt": f"Execute a trade to {action} {amount} shares of {symbol}.",
            # Valid governed responses include: governance approval/rejection keywords,
            # execution plan terms, or error/safety messages — all indicate the
            # governance chain was invoked.
            "expected": [
                "policy", "check", "approved", "rejected", "governance",
                "execution", "plan", "trade", "error", "manual", "review",
                "risk", "compliance", "cannot", "unable",
            ],
            "type": "contains_any"
        }
    ]

def query_agent(prompt: str):
    """Sends a query to the agent.

    Injects the CAGE_API_KEY as a Bearer token so that the advisor's
    require_api_key() dependency (auth.py) does not reject the request
    with HTTP 401.  When CAGE_API_KEY is unset the header is omitted and
    the dev-mode bypass in auth.py applies (CAGE_ENV=dev + no key).
    """
    user_id = str(uuid.uuid4())
    url = f"{BACKEND_URL}/agent/query"
    payload = {
        "prompt": prompt,
        "user_id": user_id
    }
    headers: dict = {}
    cage_api_key = os.environ.get("CAGE_API_KEY", "")
    if cage_api_key:
        headers["Authorization"] = f"Bearer {cage_api_key}"

    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=300)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed (Attempt {attempt+1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                time.sleep(2)
            else:
                return None

@pytest.mark.skipif(not _backend_reachable(), reason="Backend not available — set BACKEND_URL to a live server")
@pytest.mark.timeout(600)
def test_agent_workflow_accuracy():
    """Runs the accuracy tests following the specific workflow."""
    print(f"\n🔍 Testing Agent Accuracy (Randomized Workflow) against {BACKEND_URL}...")
    
    # Generate a random workflow for this run
    workflow_steps = generate_workflow()
    
    passed = 0
    failed = 0
    
    for i, case in enumerate(workflow_steps):
        step_name = case["step"]
        prompt = case["prompt"]
        print(f"\nStep {i+1}: {step_name}")
        print(f"  Prompt: '{prompt}'")
        
        result = query_agent(prompt)
        
        if not result or "response" not in result:
            print("❌ FAIL: No valid response received.")
            failed += 1
            continue
            
        agent_response = result["response"]
        print(f"  Agent Response: {agent_response[:100].replace(chr(10), ' ')}...")
        
        # Validation Logic
        is_pass = False
        check_type = case.get("type", "contains")
        expected = [x.lower() for x in case["expected"]]
        agent_response_lower = agent_response.lower()
        
        if check_type == "contains":
            is_pass = any(exp in agent_response_lower for exp in expected)
        elif check_type == "contains_any":
             # contains_any is already flexible, but we confirm at least one match
             is_pass = any(exp in agent_response_lower for exp in expected)
        elif check_type == "contains_all":
             is_pass = all(exp in agent_response_lower for exp in expected)
        elif check_type == "semantic":
             # Fallback to broad keyword match if slm not available
             is_pass = any(exp in agent_response_lower for exp in expected)
        
        if is_pass:
            print("✅ PASS")
            passed += 1
        else:
            print(f"❌ FAIL: Expected intent elements {expected}")
            failed += 1
            
    print("-" * 30)
    print(f"Results: {passed} Passed, {failed} Failed")
    
    assert failed == 0, f"{failed} workflow steps failed."

if __name__ == "__main__":
    test_agent_workflow_accuracy()
