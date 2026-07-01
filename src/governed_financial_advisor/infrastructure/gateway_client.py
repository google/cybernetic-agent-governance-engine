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
from typing import Any, Dict, Optional

import httpx
from opentelemetry.propagate import inject as otel_inject

from src.governed_financial_advisor.graph.annotations import side_effect_node

logger = logging.getLogger("infrastructure.gateway_client")

_GATEWAY_URL_DEFAULT = "http://localhost:8080"


class GatewayClient:
    """Singleton async HTTP client that calls the governance gateway."""

    _instance: Optional["GatewayClient"] = None

    def __new__(cls) -> "GatewayClient":
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._http: Optional[httpx.AsyncClient] = None
            instance._base_url: str = os.environ.get("GATEWAY_URL", _GATEWAY_URL_DEFAULT)
            cls._instance = instance
        return cls._instance

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Lazily create the underlying AsyncClient."""
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                base_url=self._base_url,
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
        params: Dict[str, Any],
        policy_version_id: Optional[str] = None,
        timeout: float = 60.0,
    ) -> Dict[str, Any]:
        """Submit a tool execution plan to the Gateway for governance validation.

        This is the **Option 2: Unified Gateway Governance Routing** client
        method.  Calls ``POST /governance/validate-action`` on the Hybrid
        Gateway, which runs Tier 2 (CBF) + Tier 4 (OPA) and returns a verdict
        with an HMAC-SHA256 routing seal on approval.

        W3C Trace Context Propagation
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        The active OpenTelemetry span context is injected into the outbound
        HTTP headers via ``opentelemetry.propagate.inject(headers)``.  This
        injects the ``traceparent`` (and ``tracestate``) header so that the
        Gateway's ``cage.validate_action``, ``cage.cbf_action_check``, and
        ``cage.opa_action_check`` child spans are attached to the GFA's
        ``cage.tool_execute`` root span in Langfuse — producing a single unified
        trace tree rather than two disconnected fragments.

        Without this injection, Langfuse logs two separate orphan traces with no
        parent-child relationship, making the audit trail unreadable.

        Args:
            action:            Tool / policy action name (e.g. ``"execute_trade"``).
            params:            Structured execution plan parameters dict.
            policy_version_id: Pinned baseline policy version signature hash (optional).
            timeout:           HTTP timeout in seconds (default 60s).  OPA cold-start
                               can take up to 20s on the first evaluation after a pod
                               rollout; 60s covers that with a safety margin.  Warm
                               steady-state evaluations complete in 30–80ms.

        Returns:
            Dict with keys:
                - ``verdict``:     ``"APPROVED"`` | ``"DENIED"``
                - ``violations``:  list[str] — empty on approval
                - ``seal``:        HMAC routing seal string (empty on denial)
                - ``latency_ms``:  Gateway-reported governance check latency

        Raises:
            PermissionError: If the Gateway returns a DENIED verdict.
            httpx.HTTPStatusError: On 4xx / 5xx Gateway errors.
            httpx.TimeoutException: If the Gateway does not respond within timeout.
        """
        client = await self._ensure_client()

        # ── W3C Trace Context injection ───────────────────────────────────────
        # Inject the active OTel span context so the Gateway's governance child
        # spans (cage.validate_action → cage.cbf_action_check + cage.opa_action_check
        # → cage.routing_seal) attach to the GFA's cage.tool_execute parent span.
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        otel_inject(headers)  # Injects W3C 'traceparent' from current span context

        payload = {
            "action": action,
            "params": params,
            "policy_version_id": policy_version_id,
        }
        response = await client.post(
            "/governance/validate-action",
            json=payload,
            headers=headers,
            timeout=timeout,
        )

        if response.status_code == 403:
            try:
                result = response.json()
                if "violations" in result and any("Substrate Policy Drift Detected" in v for v in result["violations"]):
                    logger.warning("Substrate drift caught during session. Fetching updated baseline pin and replaying.")
                    fresh_version_id = await self.get_policy_version(timeout=timeout)
                    payload["policy_version_id"] = fresh_version_id
                    
                    retry_response = await client.post(
                        "/governance/validate-action",
                        json=payload,
                        headers=headers,
                        timeout=timeout,
                    )
                    if retry_response.status_code == 403:
                        logger.error("Consecutive policy drift check failed. Cluster synchronization boundary out-of-bounds.")
                    retry_response.raise_for_status()
                    result = retry_response.json()
                    
                    verdict = result.get("verdict", "DENIED")
                    if verdict == "DENIED":
                        violations = result.get("violations", ["governance denied"])
                        logger.warning(
                            "🚫 validate_action DENIED by Gateway (after retry): action=%s violations=%s",
                            action, violations,
                        )
                        raise PermissionError(
                            f"Governance DENIED '{action}': {'; '.join(violations)}"
                        )
                    logger.info(
                        "✅ validate_action APPROVED by Gateway (after retry): action=%s latency=%.1fms",
                        action, result.get("latency_ms", 0),
                    )
                    return result
            except PermissionError:
                raise
            except Exception as exc:
                logger.error("Failed to recover from policy drift: %s", exc)
                response.raise_for_status()

        response.raise_for_status()
        result: Dict[str, Any] = response.json()

        verdict = result.get("verdict", "DENIED")
        if verdict == "DENIED":
            violations = result.get("violations", ["governance denied"])
            logger.warning(
                "🚫 validate_action DENIED by Gateway: action=%s violations=%s",
                action, violations,
            )
            raise PermissionError(
                f"Governance DENIED '{action}': {'; '.join(violations)}"
            )

        logger.info(
            "✅ validate_action APPROVED by Gateway: action=%s latency=%.1fms",
            action, result.get("latency_ms", 0),
        )
        return result

    async def close(self) -> None:
        """Close the underlying HTTP client and release resources."""
        if self._http and not self._http.is_closed:
            await self._http.aclose()
            logger.info("GatewayClient: HTTP client closed")
