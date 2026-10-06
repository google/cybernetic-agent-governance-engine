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

"""CAGE PolicyProvider SPI implementation for NVIDIA OpenShell."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import httpx

from openshell_provider_cage.models import (
    PolicyEvaluationOutcome,
    PolicyProposal,
)

logger = logging.getLogger("OpenShell.Provider.CAGE")


class CagePolicyProvider:
    """NVIDIA OpenShell PolicyProvider backed by CAGE SymbolicGovernor."""

    def __init__(
        self,
        *,
        endpoint: str,
        client_identity: str = "spiffe://cluster.local/ns/cage/sa/openshell-supervisor",
        http_client: httpx.AsyncClient | None = None,
        timeout: float = 5.0,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"Invalid CAGE gateway endpoint URL scheme: {parsed.scheme!r}"
            )
        self._endpoint = endpoint.rstrip("/")
        self._client_identity = client_identity
        self._timeout = timeout
        self._http_client = http_client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = http_client is None

    async def aclose(self) -> None:
        if self._owns_client and self._http_client is not None:
            await self._http_client.aclose()

    async def evaluate(self, proposal: PolicyProposal) -> PolicyEvaluationOutcome:
        """Evaluate a dynamic OpenShell sandbox proposal against CAGE STERA engine."""
        payload = {
            "action": proposal.action,
            "params": {
                **proposal.params,
                "sandbox_id": proposal.sandbox_id,
                "requested_endpoint": proposal.requested_endpoint,
                "requested_http_verb": proposal.requested_http_verb,
                "_caller_principal": proposal.operator_urn,
            },
            "profile": "dry_run",
            "thread_id": proposal.thread_id,
        }
        headers = {
            "Content-Type": "application/json",
            "l5d-client-id": self._client_identity,
        }
        if proposal.correlation_id:
            headers["X-CAGE-Correlation-ID"] = proposal.correlation_id

        try:
            resp = await self._http_client.post(
                f"{self._endpoint}/v1/governance/validate",
                json=payload,
                headers=headers,
            )
        except Exception as exc:
            logger.error("[CAGE] Validation request failed (fail-closed): %s", exc)
            return PolicyEvaluationOutcome(
                allowed=False,
                deferred=False,
                rejected=True,
                decision="DENY",
                rejection_reason=f"CAGE governance engine unreachable: {type(exc).__name__}",
                violations=["FAIL_CLOSED_GATEWAY_UNREACHABLE"],
            )

        if resp.status_code == 200:
            data = resp.json()
            verdict = data.get("verdict", "DENY")
            if verdict == "ALLOW":
                return PolicyEvaluationOutcome(
                    allowed=True,
                    deferred=False,
                    rejected=False,
                    decision="ALLOW",
                    routing_seal=data.get("seal"),
                    metadata=data,
                )
            if verdict in ("REQUIRE_APPROVAL", "DEFER", "NARROW"):
                return PolicyEvaluationOutcome(
                    allowed=False,
                    deferred=True,
                    rejected=False,
                    decision=verdict,
                    defer_id=data.get("deferred_id") or data.get("defer_token"),
                    rejection_reason=data.get(
                        "classification_reason", "Dual-control approval required"
                    ),
                    violations=[str(v) for v in data.get("violations", [])],
                    metadata=data,
                )

        # Non-200 responses represent denial, barrier breaches, or refusal receipts
        try:
            body = resp.json()
        except Exception:
            body = {"message": resp.text}

        quarantined = bool(
            body.get("quarantined") or (body.get("payload") or {}).get("quarantined")
        )
        reason = (
            body.get("message")
            or body.get("error")
            or "Rejected by STERA hard constraint"
        )
        violations = body.get("violations") or [reason]

        return PolicyEvaluationOutcome(
            allowed=False,
            deferred=False,
            rejected=True,
            decision="DENY",
            rejection_reason=str(reason),
            violations=[str(v) for v in violations],
            quarantine_triggered=quarantined,
            metadata=body,
        )

    async def report_telemetry(self, ocsf_event: dict[str, Any]) -> bool:
        """Forward OpenShell OCSF v1.1.0 security event to CAGE WORM evidence stream."""
        headers = {
            "Content-Type": "application/json",
            "l5d-client-id": self._client_identity,
        }
        try:
            resp = await self._http_client.post(
                f"{self._endpoint}/v1/governance/evidence/ocsf",
                json=ocsf_event,
                headers=headers,
            )
            return resp.status_code in (200, 201, 202)
        except Exception as exc:
            logger.warning("[CAGE] Failed to forward OCSF telemetry to CAGE: %s", exc)
            return False
