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
REQUEST_TYPE = "Governance_Workflow"

# --- 2. Data Generators ---
# Tool names exercised by /governance/check
TOOL_NAMES = [
    "execute_trade",
    "write_db",
    "send_notification",
    "fetch_market_data",
    "update_portfolio",
    "place_order",
    "cancel_order",
    "transfer_funds",
]

# Action types exercised by /governance/validate-action
ACTION_TYPES = [
    "execute_trade",
    "write_db",
    "send_notification",
    "update_portfolio",
    "place_order",
    "cancel_order",
    "transfer_funds",
]

TICKERS = ["AAPL", "GOOGL", "MSFT", "AMZN", "TSLA", "JPM", "V", "NVDA", "BRK.B"]
RISK_LEVELS = ["low", "moderate", "high", "speculative"]
TIME_HORIZONS = ["short_term", "medium_term", "long_term"]

# Realistic HMAC test value — empty string is accepted in development/test
# environments where CAGE_ROUTING_SEAL_SECRET is not set.
_TEST_SEAL = ""


def _make_trade_params() -> dict:
    """Generate realistic trade parameters for governance checks."""
    return {
        "symbol": random.choice(TICKERS),
        "quantity": random.randint(1, 500),
        "price": round(random.uniform(10.0, 1500.0), 2),
        "confidence": round(random.uniform(0.70, 0.99), 2),
        "latency_ms": random.randint(10, 180),  # kept below 200 ms threshold
        "risk_level": random.choice(RISK_LEVELS),
        "horizon": random.choice(TIME_HORIZONS),
        "agent_id": f"load_test_agent_{random.randint(1, 50)}",
    }


def _make_db_params() -> dict:
    return {
        "query": f"SELECT * FROM portfolio WHERE user_id = {random.randint(1, 9999)}",
        "approval_token": f"tok_{random.randint(100000, 999999)}",
        "agent_id": f"load_test_agent_{random.randint(1, 50)}",
    }


def _make_notification_params() -> dict:
    return {
        "recipient": f"user_{random.randint(1, 1000)}@example.com",
        "message": f"Portfolio update for {random.choice(TICKERS)}",
        "channel": random.choice(["email", "sms", "push"]),
        "agent_id": f"load_test_agent_{random.randint(1, 50)}",
    }


def _random_params(tool_name: str) -> dict:
    """Return realistic params keyed to the given tool/action name."""
    if "trade" in tool_name or "order" in tool_name or "transfer" in tool_name:
        return _make_trade_params()
    if "db" in tool_name or "portfolio" in tool_name:
        return _make_db_params()
    return _make_notification_params()


class GovernanceUser(HttpUser):
    """Simulates upstream orchestrators calling the governance enforcement surface.

    Two task weights reflect realistic traffic split:
      - governance_check (weight=3): dry-run pre-flight checks before tool execution
      - validate_action  (weight=2): full 7-tier pipeline validation at execution time
      - health_check     (weight=1): basic liveness probe
    """

    # Governance calls are fast (sub-second) but orchestrators batch them;
    # wait 1–5 seconds between requests to model realistic concurrency.
    wait_time = between(1, 5)

    # ------------------------------------------------------------------ #
    # Task: POST /governance/check                                         #
    # Endpoint: governance_middleware.governance_check()                   #
    # Body: {"tool_name": str, "params": dict}                            #
    # Header: X-CAGE-Routing-Seal (HMAC-SHA256 of body bytes)             #
    # ------------------------------------------------------------------ #
    @task(3)
    def governance_check(self):
        """Dry-run governance check — mirrors what the GFA does before tool execution."""
        tool_name = random.choice(TOOL_NAMES)
        params = _random_params(tool_name)

        payload = {
            "tool_name": tool_name,
            "params": params,
        }

        with self.client.post(
            "/governance/check",
            json=payload,
            headers={"X-CAGE-Routing-Seal": _TEST_SEAL},
            name="POST /governance/check",
            catch_response=True,
            timeout=30,
        ) as response:
            if response.status_code == 200:
                try:
                    data = response.json()
                    status = data.get("status", "")
                    if status in ("APPROVED", "REJECTED"):
                        # Both are valid governance outcomes — not HTTP errors
                        if status == "REJECTED":
                            events.request.fire(
                                request_type="Governance_Block",
                                name="check_rejected",
                                response_time=response.elapsed.total_seconds() * 1000,
                                response_length=len(response.content),
                                exception=None,
                            )
                        response.success()
                    else:
                        response.failure(f"Unexpected status field: {status!r}")
                except json.JSONDecodeError:
                    response.failure("Response was not valid JSON")
            elif response.status_code == 400:
                response.failure(f"Bad request: {response.text[:200]}")
            elif response.status_code == 403:
                # Seal rejected — expected in strict enforcement mode
                response.success()
            else:
                response.failure(f"HTTP Error: {response.status_code}")

    # ------------------------------------------------------------------ #
    # Task: POST /governance/validate-action                               #
    # Endpoint: governance_middleware.validate_action_endpoint()           #
    # Body: {"action": str, "params": dict}                               #
    # ------------------------------------------------------------------ #
    @task(2)
    def validate_action(self):
        """Full 7-tier governance pipeline — mirrors what the GFA calls at execution time."""
        action = random.choice(ACTION_TYPES)
        params = _random_params(action)

        payload = {
            "action": action,
            "params": params,
        }

        with self.client.post(
            "/governance/validate-action",
            json=payload,
            headers={"X-Governance-Seal": _TEST_SEAL},
            name="POST /governance/validate-action",
            catch_response=True,
            timeout=30,
        ) as response:
            if response.status_code == 200:
                try:
                    data = response.json()
                    verdict = data.get("verdict", "")
                    if verdict in ("APPROVED", "DENIED"):
                        if verdict == "DENIED":
                            events.request.fire(
                                request_type="Governance_Block",
                                name="validate_action_denied",
                                response_time=response.elapsed.total_seconds() * 1000,
                                response_length=len(response.content),
                                exception=None,
                            )
                        response.success()
                    else:
                        response.failure(f"Unexpected verdict field: {verdict!r}")
                except json.JSONDecodeError:
                    response.failure("Response was not valid JSON")
            elif response.status_code == 403:
                # GovernanceError hard-denial — valid business outcome
                try:
                    data = response.json()
                    if data.get("verdict") == "DENIED":
                        events.request.fire(
                            request_type="Governance_Block",
                            name="validate_action_hard_denied",
                            response_time=response.elapsed.total_seconds() * 1000,
                            response_length=len(response.content),
                            exception=None,
                        )
                        response.success()
                        return
                except json.JSONDecodeError:
                    pass
                response.failure(f"HTTP 403 (non-governance): {response.text[:200]}")
            elif response.status_code == 422:
                response.failure(f"Validation error (schema mismatch): {response.text[:200]}")
            else:
                response.failure(f"HTTP Error: {response.status_code}")

    # ------------------------------------------------------------------ #
    # Task: GET /health                                                    #
    # ------------------------------------------------------------------ #
    @task(1)
    def health_check(self):
        """Basic liveness probe — ensures connectivity is not the bottleneck."""
        self.client.get("/health", name="GET /health")
