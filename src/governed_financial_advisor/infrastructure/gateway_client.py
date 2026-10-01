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

"""
GatewayClient — async HTTP client for the governed inference gateway.

Uses a lazy singleton pattern so the underlying httpx.AsyncClient is
created only on the first call, not at import time.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx
from opentelemetry.propagate import inject as otel_inject

from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governance_envelope import unwrap_governance_envelope
from src.governed_financial_advisor.graph.annotations import side_effect_node

logger = logging.getLogger("infrastructure.gateway_client")

_GATEWAY_URL_DEFAULT = "http://localhost:8080"

#: Verdicts the advisor may route on. DENY arrives as HTTP 403; anything else
#: (including a missing or legacy verdict string) is refused.
_ROUTABLE_VERDICTS = frozenset(
    {
        GovernanceDecision.ALLOW,
        GovernanceDecision.NARROW,
        GovernanceDecision.REQUIRE_APPROVAL,
        GovernanceDecision.DEFER,
        GovernanceDecision.PAUSE,
    }
)


def _violations(response: httpx.Response) -> list[str]:
    try:
        body = response.json()
    except ValueError:
        return ["governance denied"]
    violations = body.get("violations") if isinstance(body, dict) else None
    return [str(v) for v in violations] if violations else ["governance denied"]


def _is_policy_drift(response: httpx.Response) -> bool:
    return any("Substrate Policy Drift Detected" in v for v in _violations(response))


class GatewayClient:
    """Singleton async HTTP client that calls the governance gateway."""

    _instance: GatewayClient | None = None

    def __new__(cls) -> GatewayClient:
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._http: httpx.AsyncClient | None = None  # type: ignore[misc, has-type]  # non-self attribute assignment in __new__; type annotation on non-self attr
            instance._base_url: str = os.environ.get(  # type: ignore[misc, has-type, attr-defined]  # non-self attribute + has-type false positive
                "GATEWAY_URL", _GATEWAY_URL_DEFAULT
            )
            cls._instance = instance
        return cls._instance

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Lazily create the underlying AsyncClient."""
        if self._http is None or self._http.is_closed:  # type: ignore[has-type]  # _http type is determined by __new__; mypy cannot track non-self attribute types
            self._http = httpx.AsyncClient(
                base_url=self._base_url,  # type: ignore[attr-defined]
                timeout=60.0,
            )
        return self._http

    @side_effect_node(kind="api_call", external_system="gateway_api")
    async def chat(
        self,
        message: str,
        model: str = "default",
        **extra: Any,
    ) -> str:
        """Send a chat message to the gateway and return the response text.

        Args:
            message: The user message to send.
            model:   The model identifier to request.
            **extra: Additional JSON fields forwarded in the request body.

        Returns:
            The assistant response as a plain string.

        Raises:
            httpx.HTTPStatusError: on 4xx / 5xx responses.
        """
        client = await self._ensure_client()
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": message}],
            **extra,
        }
        response = await client.post("/v1/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "")
        return data.get("response", "")

    async def get_policy_version(self, timeout: float = 10.0) -> str:
        """Queries the Hybrid Gateway's discovery engine for the valid active baseline signature."""
        client = await self._ensure_client()
        response = await client.get("/governance/policy-version", timeout=timeout)
        response.raise_for_status()
        return response.json()["active_hash"]

    @side_effect_node(kind="api_call", external_system="gateway_api")
    async def validate_action(
        self,
        action: str,
        params: dict[str, Any],
        policy_version_id: str | None = None,
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """Ask the gateway how ``action`` must be routed; nothing is committed.

        Calls ``POST /governance/validate-action``. The gateway runs the
        non-committing (DRY_RUN) profile and never mints a routing seal: the
        single committing run happens inside the gateway when the governed tool
        (e.g. ``execute_trade_action``) executes.

        W3C Trace Context Propagation
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        The active OpenTelemetry span context is injected into the outbound
        HTTP headers via ``opentelemetry.propagate.inject(headers)`` so the
        gateway's ``cage.validate_action`` span is a child of the advisor's
        ``cage.tool_execute`` span in Langfuse (one trace tree, not two).

        Args:
            action:            Tool / policy action name (e.g. ``"execute_trade"``).
            params:            Structured execution plan parameters dict.
            policy_version_id: Pinned baseline policy version signature hash (optional).
            timeout:           HTTP timeout in seconds (default 60s; covers OPA
                               cold start after a pod rollout).

        Returns:
            The unwrapped result. ``verdict`` is a :class:`GovernanceDecision`
            value other than ``DENY``: ``ALLOW``, ``NARROW`` (with
            ``narrowed_params``), ``REQUIRE_APPROVAL`` (with the ``deferred_id``
            of the gateway-held approval token), ``DEFER`` or ``PAUSE``.

        Raises:
            PermissionError: On a refusal (HTTP 403 / ``DENY``) or any verdict
                outside the canonical vocabulary — the caller must block.
            httpx.HTTPStatusError: On other 4xx / 5xx Gateway errors.
            httpx.TimeoutException: If the Gateway does not respond within timeout.
        """
        client = await self._ensure_client()
        headers: dict[str, str] = {"Content-Type": "application/json"}
        otel_inject(headers)  # Injects W3C 'traceparent' from current span context
        payload = {
            "action": action,
            "params": params,
            "policy_version_id": policy_version_id,
        }

        async def _post() -> httpx.Response:
            return await client.post(
                "/governance/validate-action",
                json=payload,
                headers=headers,
                timeout=timeout,
            )

        response = await _post()
        if response.status_code == 403 and _is_policy_drift(response):
            logger.warning(
                "Substrate drift caught during session. Fetching updated baseline pin and replaying."
            )
            payload["policy_version_id"] = await self.get_policy_version(timeout=timeout)
            response = await _post()
        if response.status_code == 403:
            raise PermissionError(
                f"Governance DENIED '{action}': {'; '.join(_violations(response))}"
            )
        response.raise_for_status()

        result: dict[str, Any] = unwrap_governance_envelope(response.json())
        verdict = result.get("verdict")
        if verdict not in _ROUTABLE_VERDICTS:
            violations = [str(v) for v in result.get("violations") or []]
            logger.warning(
                "🚫 validate_action refused: action=%s verdict=%s violations=%s",
                action,
                verdict,
                violations,
            )
            raise PermissionError(
                f"Governance returned no routable verdict for '{action}' "
                f"(verdict={verdict!r}): {'; '.join(violations)}"
            )
        if verdict == GovernanceDecision.REQUIRE_APPROVAL and not result.get("deferred_id"):
            # No approval token was parked, so no human can ever approve it.
            raise PermissionError(
                f"Governance requires approval for '{action}' but parked no deferred_id"
            )
        logger.info(
            "validate_action: action=%s verdict=%s latency=%.1fms",
            action,
            verdict,
            result.get("latency_ms", 0),
        )
        return result

    @side_effect_node(kind="api_call", external_system="gateway_api")
    async def execute_tool(
        self,
        tool_name: str,
        params: dict[str, Any],
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """Run a gateway-hosted tool via ``POST /tools/execute``.

        Governed tools (``simulate_governance_check``, ``evaluate_policy``,
        ``execute_trade_action``, ...) execute in the gateway process, where the
        governor, OPA client and ``ActuatorRegistry`` live.

        Returns:
            The gateway's ``{"status": ..., "output"|"error": ...}`` body.
        """
        client = await self._ensure_client()
        headers: dict[str, str] = {"Content-Type": "application/json"}
        otel_inject(headers)
        response = await client.post(
            "/tools/execute",
            json={"tool_name": tool_name, "params": params},
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()
        body: dict[str, Any] = response.json()
        return body

    async def close(self) -> None:
        """Close the underlying HTTP client and release resources."""
        if self._http and not self._http.is_closed:
            await self._http.aclose()
            logger.info("GatewayClient: HTTP client closed")
