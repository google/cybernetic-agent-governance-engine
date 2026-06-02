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

import random
import json
import time
from locust import HttpUser, task, between, events

# --- 1. Custom Metrics Hooks ---
# We use this to track "business logic" errors (e.g., Guardrail blocks)
# distinct from server crashes (HTTP 500).
REQUEST_TYPE = "Agent_Workflow"

@events.init_command_line_parser.add_listener
def _(parser):
    parser.add_argument("--agent-endpoint", type=str, env_var="AGENT_ENDPOINT", default="/agent/query", help="The endpoint to hit")

# --- 2. Data Generators ---
TICKERS = ["AAPL", "GOOGL", "MSFT", "AMZN", "TSLA", "JPM", "V", "NVDA", "BRK.B"]
RISK_LEVELS = ["low", "moderate", "high", "speculative"]
TIME_HORIZONS = ["short_term", "medium_term", "long_term"]

class FinancialAdvisorUser(HttpUser):
    # Agents are slow. Users won't hammer the enter key.
    # Wait 5-15 seconds between completion and next request.
    wait_time = between(5, 15)

    @task
    def execute_advisory_workflow(self):
        # Generate random inputs to defeat caching
        ticker = random.choice(TICKERS)
        risk = random.choice(RISK_LEVELS)
        horizon = random.choice(TIME_HORIZONS)

        # Note: The prompt structure here should match what the actual agent expects
        prompt = f"Analyze {ticker} for a {risk} risk portfolio with a {horizon} horizon. Research the stock, create a trading plan, and execute it."

        payload = {
            "prompt": prompt,
            "user_id": f"load_test_user_{random.randint(1, 1000)}",
            "thread_id": f"thread_{random.randint(1, 10000)}"
        }

        # We define a custom name so all random tickers group under one entry in the UI
        request_name = "POST /agent/query"

        # Use the configured endpoint or default
        endpoint = self.environment.parsed_options.agent_endpoint if self.environment.parsed_options else "/agent/query"

        if endpoint == "/health":
            with self.client.get(
                endpoint,
                name="GET /health",
                catch_response=True,
                timeout=10
            ) as response:
                if response.status_code == 200:
                    response.success()
                else:
                    response.failure(f"HTTP Error: {response.status_code}")
            return

        with self.client.post(
            endpoint,
            json=payload,
            name=request_name,
            catch_response=True,
            timeout=120 # Important: LLM agents can take 30s-60s to finish a full chain
        ) as response:

            # --- 3. Validation Logic ---
            if response.status_code == 200:
                try:
                    data = response.json()

                    # Check 1: Did the Guardrail block it?
                    resp_text = data.get("response", "")

                    # Heuristics for Governance Blocks
                    is_blocked = False
                    block_reasons = ["cannot answer", "policy", "unsafe", "violation", "blocked", "refuse"]
                    if any(r in resp_text.lower() for r in block_reasons):
                        is_blocked = True

                    if is_blocked:
                        # Track Rejection Rate explicitly
                        events.request.fire(
                            request_type="Verification_Failure",
                            name="Governance_Block",
                            response_time=response.elapsed.total_seconds() * 1000,
                            response_length=len(resp_text),
                            exception=None,
                        )
                        # We treat it as a "success" HTTP request but track the business event
                        response.success()
                        return

                    # Check 2: Retry/Rejection Indicator
                    # If the system had to retry (e.g. "Plan rejected, retrying..."), we count that.
                    # This depends on if the final response exposes the retry count.
                    # Assuming metadata might contain it:
                    trace_id = data.get("trace_id")
                    if trace_id:
                         # We could log this trace ID for correlation
                         pass

                    response.success()

                except json.JSONDecodeError:
                    response.failure("Response was not valid JSON")

            elif response.status_code == 504:
                response.failure("Gateway Timeout - Agent took too long")

            else:
                response.failure(f"HTTP Error: {response.status_code}")

    # Optional: Health check task to ensure basic connectivity isn't the bottleneck
    @task(weight=1)
    def health_check(self):
        self.client.get("/health", name="Health Check")
