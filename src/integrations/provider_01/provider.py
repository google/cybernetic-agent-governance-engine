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
provider.py — Provider 01 Normative Compliance Provider
=======================================================

Production normative provider backed by external cloud API.
Extracted from ``src/gateway/governance/normative_provider.py`` for
vendor isolation.

Implements the 3-endpoint HTTP contract defined in §2.5.2 of
EXTENSIBILITY_ARCHITECTURE.md:
  - GET  /legal-baseline/{region}      → Normative Data Supply
  - POST /validate/fria                → External Validation
  - GET  /evidence-chain/{thread_id}   → Attestation Logging

Authentication
--------------
API key passed as ``Authorization: Bearer {key}`` header.
Key sourced from CAGE_NORMATIVE_API_KEY_SECRET (direct value or
Secret Manager path — Secret Manager resolution is deferred to
container init via Workload Identity).

Environment variables
---------------------
  CAGE_NORMATIVE_ENDPOINT             — Base URL (required)
  CAGE_NORMATIVE_API_KEY_SECRET       — API key or Secret Manager path
  CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS — Per-request timeout (default: 5)

Status
------
**INTERFACE READY** — HTTP client is fully implemented.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import quote

logger = logging.getLogger("cage.integrations.provider_01")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENDPOINT: str = os.environ.get("CAGE_NORMATIVE_ENDPOINT", "").split("#")[0].strip()
_API_KEY_SECRET: str = (
    os.environ.get("CAGE_NORMATIVE_API_KEY_SECRET", "").split("#")[0].strip()
)
_GATE_TIMEOUT_SECONDS: float = float(
    os.environ.get("CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS", "5").split("#")[0].strip()
    or "5"
)

# ---------------------------------------------------------------------------
# FlowSignal Decision Values (tri-state)
# ---------------------------------------------------------------------------

_FLOWSIGNAL_ALLOW = "ALLOW"
_FLOWSIGNAL_REFUSE = "REFUSE"
_FLOWSIGNAL_ESCALATE = "ESCALATE"

# Finding codes for FlowSignal decision mapping
FINDING_CODE_FLOWSIGNAL_REFUSE = "FLOWSIGNAL_REFUSE"
FINDING_CODE_FLOWSIGNAL_HOLD = "FLOWSIGNAL_HOLD"
FINDING_CODE_PARSE_ERROR = "PARSE_ERROR"


def _map_flowsignal_decision(
    decision: str, data: dict[str, Any]
) -> tuple[bool, list[dict[str, Any]]]:
    """Map FlowSignal tri-state decision to CAGE (admitted, findings).

    This implements the ESCALATE contract mapping per §3.1 of the FlowSignal
    integration plan, mirroring provider_06's tri-state pattern.

    Mapping logic:
      - ALLOW    → admitted=True, findings=[] (informational only)
      - REFUSE   → admitted=False, findings with code=FLOWSIGNAL_REFUSE
      - ESCALATE → admitted=False, findings with code=FLOWSIGNAL_HOLD,
                   needs_human_review=True for DeferQueue parking

    Args:
        decision: The FlowSignal decision value (ALLOW, REFUSE, ESCALATE).
        data: The full response payload (for extracting message context).

    Returns:
        Tuple of (admitted: bool, findings: list[dict]).

    Raises:
        ValueError: If decision is unrecognized (fail-closed).
    """
    from src.gateway.governance.normative_provider import ValidationResult

    decision_upper = decision.upper().strip()

    if decision_upper == _FLOWSIGNAL_ALLOW:
        # ALLOW: admitted=True, no blocking findings
        return True, []

    if decision_upper == _FLOWSIGNAL_REFUSE:
        # REFUSE: hard deny with blocked severity
        message = data.get("message", "FlowSignal refused the transaction")
        return False, [
            {
                "code": FINDING_CODE_FLOWSIGNAL_REFUSE,
                "severity": "blocked",
                "message": message,
            }
        ]

    if decision_upper == _FLOWSIGNAL_ESCALATE:
        # ESCALATE: soft deny for human review (DeferQueue parking)
        message = data.get("message", "FlowSignal escalated — requires human approval")
        return False, [
            {
                "code": FINDING_CODE_FLOWSIGNAL_HOLD,
                "severity": "review",
                "message": message,
                "needs_human_review": True,  # CAGE-specific extension for DeferQueue
            }
        ]

    # Unrecognized decision value: fail-closed
    raise ValueError(f"Unrecognized FlowSignal decision: {decision!r}")


# ---------------------------------------------------------------------------
# Provider 01
# ---------------------------------------------------------------------------


class Provider01NormativeProvider:
    """Production normative provider backed by external cloud API.

    Implements the 3-endpoint HTTP contract defined in §2.5.2 of
    EXTENSIBILITY_ARCHITECTURE.md:
      - GET  /legal-baseline/{region}      → Normative Data Supply
      - POST /validate/fria                → External Validation
      - GET  /evidence-chain/{thread_id}   → Attestation Logging
    """

    def __init__(
        self,
        endpoint: str = "",
        api_key: str = "",
        timeout: float = _GATE_TIMEOUT_SECONDS,
    ) -> None:
        self._endpoint = (endpoint or _ENDPOINT).rstrip("/")
        self._api_key = api_key or _API_KEY_SECRET
        self._timeout = timeout

        if not self._endpoint:
            logger.error(
                "[Provider01] CAGE_NORMATIVE_ENDPOINT is required. "
                "Set CAGE_NORMATIVE_PROVIDER=static for dev/test."
            )

        logger.info(
            "[Provider01] Initialised: endpoint=%s timeout=%.1fs",
            self._endpoint or "(not set)",
            self._timeout,
        )

    def _headers(self) -> dict[str, str]:
        """Construct authorization headers."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def fetch_baseline(self, region: str):  # type: ignore[no-untyped-def]
        """Fetch the active legal baseline from provider."""
        import httpx

        from src.gateway.governance.normative_provider import NormativeBaseline

        url = f"{self._endpoint}/legal-baseline/{quote(region, safe='')}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(url, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()
                return NormativeBaseline(
                    region=region,
                    profile=data.get("profile", data),
                    etag=resp.headers.get("ETag", ""),
                )
        except httpx.HTTPStatusError as exc:
            logger.error(
                "[Provider01] fetch_baseline HTTP error: %s status=%d",
                url,
                exc.response.status_code,
            )
            return NormativeBaseline(
                region=region,
                profile={},
                error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
            )
        except httpx.RequestError as exc:
            logger.error("[Provider01] fetch_baseline request error: %s %s", url, exc)
            return NormativeBaseline(region=region, profile={}, error=str(exc))
        except Exception as exc:
            logger.error(
                "[Provider01] fetch_baseline unexpected error: %s %s", url, exc
            )
            return NormativeBaseline(region=region, profile={}, error=str(exc))

    async def validate_fria(self, payload: dict[str, Any]):  # type: ignore[no-untyped-def]
        """Submit FRIA validation (synchronous blocking gate).

        Supports two response formats:
          1. FlowSignal tri-state: {"decision": "ALLOW|REFUSE|ESCALATE", ...}
          2. Legacy binary: {"admitted": bool, "findings": [...]}

        If ``decision`` is present, it is mapped via _map_flowsignal_decision().
        If ``decision`` is absent, falls back to legacy admitted/findings parsing.
        If ``decision`` is present but unrecognized, fail-closed with PARSE_ERROR.
        """
        import httpx

        from src.gateway.governance.normative_provider import ValidationResult

        url = f"{self._endpoint}/validate/fria"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(url, json=payload, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()

                # FlowSignal tri-state decision mapping (Phase 1, §3.1)
                if "decision" in data:
                    decision = data["decision"]
                    try:
                        admitted, findings = _map_flowsignal_decision(decision, data)
                        return ValidationResult(admitted=admitted, findings=findings)
                    except ValueError as exc:
                        # Unrecognized decision value: fail-closed
                        logger.warning(
                            "[Provider01] FlowSignal decision parse error: %s",
                            exc,
                        )
                        return ValidationResult(
                            admitted=False,
                            error=str(exc),
                            findings=[
                                {
                                    "code": FINDING_CODE_PARSE_ERROR,
                                    "severity": "blocked",
                                    "message": f"Malformed FlowSignal decision: {decision!r}",
                                }
                            ],
                        )

                # Backward compatibility: legacy admitted/findings shape
                return ValidationResult(
                    admitted=data.get("admitted", False),
                    findings=data.get("findings", []),
                )
        except httpx.HTTPStatusError as exc:
            logger.error(
                "[Provider01] validate_fria HTTP error: %s status=%d",
                url,
                exc.response.status_code,
            )
            return ValidationResult(
                admitted=False,
                error=f"HTTP {exc.response.status_code}",
                findings=[
                    {
                        "code": "ENDPOINT_ERROR",
                        "severity": "blocked",
                        "message": f"Provider 01 HTTP error: {exc.response.status_code}",
                    }
                ],
            )
        except httpx.RequestError as exc:
            logger.error("[Provider01] validate_fria request error: %s %s", url, exc)
            return ValidationResult(
                admitted=False,
                error=str(exc),
                findings=[
                    {
                        "code": "ENDPOINT_ERROR",
                        "severity": "blocked",
                        "message": f"Provider 01 request failed: {exc}",
                    }
                ],
            )
        except Exception as exc:
            logger.error("[Provider01] validate_fria unexpected error: %s %s", url, exc)
            return ValidationResult(
                admitted=False,
                error=str(exc),
                findings=[
                    {
                        "code": "ENDPOINT_ERROR",
                        "severity": "blocked",
                        "message": f"Provider 01 unexpected error: {exc}",
                    }
                ],
            )

    async def submit_evidence(self, thread_id: str, evidence_hash: str):  # type: ignore[no-untyped-def]
        """Submit governance evidence hash for external sealing."""
        import httpx

        from src.gateway.governance.normative_provider import EvidenceSeal

        url = f"{self._endpoint}/evidence-chain/{quote(thread_id, safe='')}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    url,
                    headers=self._headers(),
                    params={"evidence_hash": evidence_hash},
                )
                resp.raise_for_status()
                data = resp.json()
                return EvidenceSeal(
                    thread_id=thread_id,
                    seal_hash=data.get("seal_hash", ""),
                )
        except httpx.HTTPStatusError as exc:
            logger.error(
                "[Provider01] submit_evidence HTTP error: %s status=%d",
                url,
                exc.response.status_code,
            )
            return EvidenceSeal(
                thread_id=thread_id,
                error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
            )
        except httpx.RequestError as exc:
            logger.error("[Provider01] submit_evidence request error: %s %s", url, exc)
            return EvidenceSeal(thread_id=thread_id, error=str(exc))
        except Exception as exc:
            logger.error(
                "[Provider01] submit_evidence unexpected error: %s %s", url, exc
            )
            return EvidenceSeal(thread_id=thread_id, error=str(exc))
