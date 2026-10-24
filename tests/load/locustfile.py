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

import itertools
import json
import os
import random
from typing import Any

try:
    from locust import HttpUser, between, events, task
except ImportError:  # pragma: no cover - fallback when locust is not installed

    class _FallbackEventHook:
        def fire(self, **kwargs: Any) -> None:
            pass

    class _FallbackEvents:
        request = _FallbackEventHook()

    class HttpUser:  # type: ignore[no-redef]
        client: Any = None

    def between(min_wait: float, max_wait: float) -> Any:
        return (min_wait, max_wait)

    def task(weight: int = 1) -> Any:
        def _decorator(fn: Any) -> Any:
            return fn

        return _decorator

    events = _FallbackEvents()  # type: ignore[assignment]

# --- 1. Custom Metrics Hooks ---
# We use this to track "business logic" errors (e.g., Guardrail blocks)
# distinct from server crashes (HTTP 500).
REQUEST_TYPE = "Governance_Workflow"

# Named failure categories for horizontal-scaling benchmarks (A2).
FAILURE_CATEGORY_RATE_LIMIT_429 = "rate_limit_429"
FAILURE_CATEGORY_CBF_EPOCH_CONTENDED = "cbf_epoch_contended"
FAILURE_CATEGORY_SEAL_EVIDENCE_CHAIN = "seal_failure_evidence_chain"
FAILURE_CATEGORY_MCP_404 = "mcp_session_404"

_PRINCIPAL_SEQ = itertools.count(1)


def classify_load_failure(
    status_code: int,
    body_text: str,
    endpoint: str = "",
) -> str | None:
    """Classify a load-test HTTP response into a canonical scaling failure category.

    Returns one of:
      - ``rate_limit_429``: HTTP 429 from per-client or per-principal rate limiting.
      - ``cbf_epoch_contended``: DENY or BLOCKED carrying ``Fence epoch`` or
        ``CBF_EPOCH_CONTENDED`` from cross-replica CBF epoch CAS contention.
      - ``seal_failure_evidence_chain``: seal minting / evidence append failure
        carrying ``EvidenceChainUnavailable``, ``EVIDENCE_CHAIN_UNAVAILABLE``,
        or the ``EvidenceStreamSink.ingest_sync()`` messages (``seal issuance
        blocked``, ``evidence commit failed``, ``evidence commit timeout``,
        ``evidence binding``).
      - ``mcp_session_404``: HTTP 404 on ``/mcp`` caused by pod-local SSE session
        affinity loss across multiple replicas.
      - ``None`` when the response does not match any tracked scaling failure mode.
    """
    if status_code == 429:
        return FAILURE_CATEGORY_RATE_LIMIT_429

    if status_code == 404 and "/mcp" in endpoint:
        return FAILURE_CATEGORY_MCP_404

    text = body_text or ""
    if "CBF_EPOCH_CONTENDED" in text or "Fence epoch" in text:
        return FAILURE_CATEGORY_CBF_EPOCH_CONTENDED

    lowered = text.lower()
    if (
        "EvidenceChainUnavailable" in text
        or "EVIDENCE_CHAIN_UNAVAILABLE" in text
        or "evidence chain unavailable" in lowered
        or "seal issuance blocked" in lowered
        or "evidence commit failed" in lowered
        or "evidence commit timeout" in lowered
        or "evidence binding" in lowered
    ):
        return FAILURE_CATEGORY_SEAL_EVIDENCE_CHAIN

    return None


# --- 2. Data Generators ---
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

# Verdicts /governance/validate-action returns with HTTP 200
# (GovernanceDecision vocabulary; DENY is a 403, external DEFER a 202).
_VERDICTS_200 = frozenset({"ALLOW", "NARROW", "REQUIRE_APPROVAL", "DEFER"})

TICKERS = ["AAPL", "GOOGL", "MSFT", "AMZN", "TSLA", "JPM", "V", "NVDA", "BRK.B"]
RISK_LEVELS = ["low", "moderate", "high", "speculative"]
TIME_HORIZONS = ["short_term", "medium_term", "long_term"]

# Caller authentication is mesh workload identity (POAM-2026-080): inside the
# Linkerd mesh, the inbound proxy overwrites l5d-client-id with the mTLS peer
# identity; for local/unmeshed load runs, inject the configured test identity.
_DEFAULT_CLIENT_ID = (
    "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)


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


def _make_committing_trade_params() -> dict:
    """Generate trade parameters for the committing POST /tools/execute path.

    No trader_role / trader_id: the gateway binds both from the caller's
    verified workload identity (GHSA-w39v-5v7h-fxg9), and execute_trade_action
    takes neither.
    """
    return {
        "symbol": random.choice(TICKERS),
        "amount": float(random.randint(10, 250)),
        "currency": "USD",
        "confidence": round(random.uniform(0.96, 0.99), 2),
        "dry_run": True,
        "side": "buy",
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

    Task weights reflect realistic traffic split:
      - validate_action  (weight=5): non-committing governance decision before
        tool execution (the removed POST /check route folded into this)
      - health_check     (weight=1): basic liveness probe
    """

    # Governance calls are fast (sub-second) but orchestrators batch them;
    # wait 1-5 seconds between requests to model realistic concurrency.
    wait_time = between(1, 5)

    def on_start(self) -> None:
        self.client.headers["l5d-client-id"] = _DEFAULT_CLIENT_ID

    # ------------------------------------------------------------------ #
    # Task: POST /governance/validate-action                               #
    # Endpoint: governance_middleware.validate_action_endpoint()           #
    # Body: {"action": str, "params": dict}                               #
    # ------------------------------------------------------------------ #
    @task(5)
    def validate_action(self) -> None:
        """Non-committing governance decision — what the GFA asks before tool execution."""
        action = random.choice(ACTION_TYPES)
        params = _random_params(action)

        payload = {
            "action": action,
            "params": params,
        }

        with self.client.post(
            "/governance/validate-action",
            json=payload,
            name="POST /governance/validate-action",
            catch_response=True,
            timeout=30,
        ) as response:
            if response.status_code == 200:
                try:
                    data = response.json()
                    # ALLOW / NARROW arrive wrapped in a signed envelope whose
                    # payload carries the verdict; other verdicts are bare.
                    verdict = data.get("verdict") or data.get("payload", {}).get(
                        "verdict", ""
                    )
                    if verdict in _VERDICTS_200:
                        if verdict == "REQUIRE_APPROVAL":
                            events.request.fire(
                                request_type="Governance_Block",
                                name="validate_action_require_approval",
                                response_time=response.elapsed.total_seconds() * 1000,
                                response_length=len(response.content),
                                exception=None,
                            )
                        response.success()
                    else:
                        response.failure(f"Unexpected verdict field: {verdict!r}")
                except json.JSONDecodeError:
                    response.failure("Response was not valid JSON")
            elif response.status_code == 202:
                # External DEFER hold — valid business outcome
                response.success()
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
                response.failure(
                    f"Validation error (schema mismatch): {response.text[:200]}"
                )
            else:
                response.failure(f"HTTP Error: {response.status_code}")

    # ------------------------------------------------------------------ #
    # Task: GET /health                                                    #
    # ------------------------------------------------------------------ #
    @task(1)
    def health_check(self) -> None:
        """Basic liveness probe — ensures connectivity is not the bottleneck."""
        self.client.get("/health", name="GET /health")


class GovernedTradeUser(HttpUser):
    """Exercises the full committing governance path across fixed replica counts.

    Each iteration executes:
      1. ``POST /governance/validate-action`` (``execute_trade`` preview);
      2. ``POST /tools/execute`` (``execute_trade_action``), which runs
         ``SymbolicGovernor.govern()``, mints a KMS routing seal, commits the
         CBF/fiscal reservations in Redis, and appends the signed evidence
         record;
      3. Optional ``POST /mcp/`` tool call when ``LOAD_TEST_ENABLE_MCP=true``.

    Every virtual user sets a distinct ``x-cage-principal`` header so per-principal
    rate limiting does not collapse all virtual users onto a single pod/proxy IP.
    """

    wait_time = between(0.5, 1.5)

    def on_start(self) -> None:
        seq = next(_PRINCIPAL_SEQ)
        self.principal_id = f"load_principal_{seq}"
        self.client.headers["l5d-client-id"] = _DEFAULT_CLIENT_ID
        self.client.headers["x-cage-principal"] = self.principal_id
        self._enable_mcp = os.environ.get("LOAD_TEST_ENABLE_MCP", "false").lower() in (
            "1",
            "true",
            "yes",
        )

    def _record_category_failure(
        self,
        response: Any,
        category: str,
        detail: str,
    ) -> None:
        # Record a single categorized failure on the HTTP response so Locust's
        # *_stats.csv and *_failures.csv count each failed HTTP request once.
        response.failure(f"[{category}] {detail[:200]}")

    @task(1)
    def governed_trade_flow(self) -> None:
        """Run validate-action followed by committing execute_trade_action."""
        trade_params = _make_committing_trade_params()

        # Step 1: Non-committing preview via POST /governance/validate-action
        validate_payload = {
            "action": "execute_trade",
            "params": {
                "symbol": trade_params["symbol"],
                "amount": trade_params["amount"],
                "currency": trade_params["currency"],
                "confidence": trade_params["confidence"],
                "side": trade_params["side"],
            },
        }
        with self.client.post(
            "/governance/validate-action",
            json=validate_payload,
            name="POST /governance/validate-action",
            catch_response=True,
            timeout=30,
        ) as response:
            category = classify_load_failure(
                response.status_code,
                response.text,
                endpoint="/governance/validate-action",
            )
            if category is not None:
                self._record_category_failure(response, category, response.text)
            elif response.status_code in (200, 202):
                response.success()
            elif response.status_code == 403:
                try:
                    data = response.json()
                    if data.get("verdict") == "DENIED":
                        response.success()
                    else:
                        response.failure(
                            f"HTTP 403 (non-governance): {response.text[:200]}"
                        )
                except json.JSONDecodeError:
                    response.failure(f"HTTP 403 (non-JSON): {response.text[:200]}")
            else:
                response.failure(f"HTTP {response.status_code}: {response.text[:200]}")

        # Step 2: Committing execution via POST /tools/execute
        execute_payload = {
            "tool_name": "execute_trade_action",
            "params": trade_params,
        }
        with self.client.post(
            "/tools/execute",
            json=execute_payload,
            name="POST /tools/execute",
            catch_response=True,
            timeout=30,
        ) as response:
            category = classify_load_failure(
                response.status_code,
                response.text,
                endpoint="/tools/execute",
            )
            if category is not None:
                self._record_category_failure(response, category, response.text)
            elif response.status_code == 200:
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    response.failure("POST /tools/execute returned invalid JSON")
                    return
                status = data.get("status")
                output_text = str(data.get("output") or data.get("error") or "")
                inner_category = classify_load_failure(
                    200, output_text, endpoint="/tools/execute"
                )
                if inner_category is not None:
                    self._record_category_failure(response, inner_category, output_text)
                elif status == "SUCCESS" and not output_text.startswith(
                    ("BLOCKED:", "ERROR:", "DEFERRED:")
                ):
                    response.success()
                else:
                    response.failure(f"Tool execution error: {output_text[:200]}")
            else:
                response.failure(f"HTTP {response.status_code}: {response.text[:200]}")

        # Step 3: Optional stateless MCP tool call (enabled post-A3 via LOAD_TEST_ENABLE_MCP=true)
        if self._enable_mcp:
            mcp_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "check_market_status",
                    "arguments": {"symbol": trade_params["symbol"]},
                },
            }
            with self.client.post(
                "/mcp/",
                json=mcp_payload,
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
                name="POST /mcp/",
                catch_response=True,
                timeout=30,
            ) as response:
                category = classify_load_failure(
                    response.status_code,
                    response.text,
                    endpoint="/mcp/",
                )
                if category is not None:
                    self._record_category_failure(response, category, response.text)
                elif response.status_code == 200:
                    response.success()
                else:
                    response.failure(
                        f"HTTP {response.status_code}: {response.text[:200]}"
                    )
