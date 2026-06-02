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
provider.py — TrustLayers Normative Compliance Provider
========================================================

Production normative provider backed by the TrustLayers cloud API.
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
**INTERFACE READY** — HTTP client is fully implemented.  Production
activation requires TrustLayers API credentials from Dani's team.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger("cage.integrations.trustlayers")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENDPOINT: str = os.environ.get("CAGE_NORMATIVE_ENDPOINT", "")
_API_KEY_SECRET: str = os.environ.get("CAGE_NORMATIVE_API_KEY_SECRET", "")
_GATE_TIMEOUT_SECONDS: float = float(
    os.environ.get("CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS", "5")
)


# ---------------------------------------------------------------------------
# TrustLayers Provider
# ---------------------------------------------------------------------------


class TrustLayersProvider:
    """Production normative provider backed by the TrustLayers cloud API.

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
                "[TrustLayersProvider] CAGE_NORMATIVE_ENDPOINT is required. "
                "Set CAGE_NORMATIVE_PROVIDER=static for dev/test."
            )

        logger.info(
            "[TrustLayersProvider] Initialised: endpoint=%s timeout=%.1fs",
            self._endpoint or "(not set)",
            self._timeout,
        )

    def _headers(self) -> dict[str, str]:
        """Construct authorization headers."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def fetch_baseline(self, region: str):
        """Fetch the active legal baseline from TrustLayers."""
        import httpx
        from src.gateway.governance.normative_provider import NormativeBaseline

        url = f"{self._endpoint}/legal-baseline/{region}"
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
        except Exception as exc:
            logger.error(
                "[TrustLayersProvider] fetch_baseline failed: %s %s", url, exc
            )
            return NormativeBaseline(
                region=region, profile={}, error=str(exc)
            )

    async def validate_fria(self, payload: dict[str, Any]):
        """Submit FRIA validation to TrustLayers (synchronous blocking gate)."""
        import httpx
        from src.gateway.governance.normative_provider import ValidationResult

        url = f"{self._endpoint}/validate/fria"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    url, json=payload, headers=self._headers()
                )
                resp.raise_for_status()
                data = resp.json()
                return ValidationResult(
                    admitted=data.get("admitted", False),
                    findings=data.get("findings", []),
                )
        except Exception as exc:
            logger.error(
                "[TrustLayersProvider] validate_fria failed: %s %s", url, exc
            )
            return ValidationResult(
                admitted=False,
                error=str(exc),
            )

    async def submit_evidence(
        self, thread_id: str, evidence_hash: str
    ):
        """Submit governance evidence hash for external sealing."""
        import httpx
        from src.gateway.governance.normative_provider import EvidenceSeal

        url = f"{self._endpoint}/evidence-chain/{thread_id}"
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
        except Exception as exc:
            logger.error(
                "[TrustLayersProvider] submit_evidence failed: %s %s", url, exc
            )
            return EvidenceSeal(
                thread_id=thread_id, error=str(exc)
            )
