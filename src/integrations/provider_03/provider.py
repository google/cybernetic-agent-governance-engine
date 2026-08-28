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
Provider 03 Normative Compliance Provider Adapter.
==================================================

Production normative provider connecting decision governance,
bind receipts, and provenance into CAGE's NormativeProvider seam.

Architecture:
  - Ingests bind receipts and maps them to CAGE authority context.
  - Implements the 3-endpoint NormativeProvider contract:
      1. fetch_baseline(region) -> NormativeBaseline
      2. validate_fria(payload) -> ValidationResult
      3. submit_evidence(thread_id, evidence_hash) -> EvidenceSeal

Environment variables:
  PROVIDER_03_NORMATIVE_ENDPOINT       — Base URL (required for HTTP mode)
  PROVIDER_03_NORMATIVE_API_KEY_SECRET — API key for authentication
  PROVIDER_03_NORMATIVE_TIMEOUT_SECONDS — Per-request timeout (default: 5)

Status:
  **INTERFACE READY** — HTTP client fully implemented per refactoring plan.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any
from urllib.parse import quote

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

logger = logging.getLogger("cage.integrations.provider_03")

_ENDPOINT: str = os.environ.get("PROVIDER_03_NORMATIVE_ENDPOINT", "")
_API_KEY_SECRET: str = os.environ.get("PROVIDER_03_NORMATIVE_API_KEY_SECRET", "")
_TIMEOUT_SECONDS: float = float(
    os.environ.get("PROVIDER_03_NORMATIVE_TIMEOUT_SECONDS", "5.0")
)

# Finding code for endpoint errors (consistent with provider_01 and provider_06)
FINDING_CODE_ENDPOINT_ERROR = "ENDPOINT_ERROR"


class Provider03NormativeProvider:
    """Normative provider adapter connecting Provider 03 with CAGE.

    Implements the 3-endpoint HTTP contract defined in §2.5.2 of
    EXTENSIBILITY_ARCHITECTURE.md:
      - GET  /baseline/{region}           → Normative Data Supply
      - POST /validate                    → External Validation
      - POST /evidence/{thread_id}        → Attestation Logging
    """

    def __init__(
        self,
        endpoint: str = "",
        api_key: str = "",
        timeout: float = _TIMEOUT_SECONDS,
    ) -> None:
        self._endpoint = (endpoint or _ENDPOINT).rstrip("/")
        self._api_key = api_key or _API_KEY_SECRET
        self._timeout = timeout

        if not self._endpoint:
            logger.warning(
                "[Provider03] PROVIDER_03_NORMATIVE_ENDPOINT not set. "
                "HTTP requests will fail until endpoint is configured."
            )

        logger.info(
            "[Provider03] Initialised: endpoint=%s timeout=%.1fs",
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
        """Fetch jurisdictional normative baseline from Provider 03.

        Returns:
            NormativeBaseline with the regional compliance profile.
        """
        import httpx

        from src.gateway.governance.normative_provider import NormativeBaseline

        if not self._endpoint:
            return NormativeBaseline(
                region=region,
                profile={},
                error="Provider 03 endpoint not configured",
            )

        url = f"{self._endpoint}/baseline/{quote(region, safe='')}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(url, headers=self._headers())
                resp.raise_for_status()
                try:
                    data = resp.json()
                except json.JSONDecodeError as jexc:
                    logger.error(
                        "[Provider03] fetch_baseline JSON parse error: %s %s",
                        url,
                        jexc,
                    )
                    return NormativeBaseline(
                        region=region,
                        profile={},
                        error=f"Invalid JSON response: {jexc}",
                    )
                return NormativeBaseline(
                    region=region,
                    profile=data.get("profile", data),
                    etag=resp.headers.get("ETag", ""),
                )
        except httpx.HTTPStatusError as exc:
            logger.error(
                "[Provider03] fetch_baseline HTTP error: %s status=%d",
                url,
                exc.response.status_code,
            )
            return NormativeBaseline(
                region=region,
                profile={},
                error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
            )
        except httpx.RequestError as exc:
            logger.error("[Provider03] fetch_baseline request error: %s %s", url, exc)
            return NormativeBaseline(region=region, profile={}, error=str(exc))

    async def validate_fria(self, payload: dict[str, Any]):  # type: ignore[no-untyped-def]
        """Validate execution intent against Provider 03 decision governance.

        Provider 03 may return an ESCALATE verdict which maps to CAGE's
        REVIEW/DEFER semantic via the needs_human_review marker.

        Returns:
            ValidationResult with admitted flag and findings.
        """
        import httpx

        from src.gateway.governance.normative_provider import ValidationResult

        if not self._endpoint:
            return ValidationResult(
                admitted=False,
                error="Provider 03 endpoint not configured",
                findings=[
                    {
                        "code": FINDING_CODE_ENDPOINT_ERROR,
                        "severity": "blocked",
                        "message": "PROVIDER_03_NORMATIVE_ENDPOINT not configured",
                    }
                ],
            )

        url = f"{self._endpoint}/validate"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(url, json=payload, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()

            # Map Provider 03's verdict to CAGE semantics
            verdict = data.get("verdict", "").upper()
            findings = data.get("findings", [])

            if verdict == "APPROVED":
                return ValidationResult(
                    admitted=True,
                    findings=findings,
                )
            elif verdict == "ESCALATE":
                # Provider 03's ESCALATE maps to CAGE's REVIEW/DEFER
                # Inject the needs_human_review marker so enforce_fria_boundary
                # routes to DeferQueue instead of hard deny
                review_findings = [
                    {
                        "code": "provider_03.escalate",
                        "severity": "review",
                        "message": "Provider 03 returned ESCALATE — requires human approval",
                        "needs_human_review": True,
                        "provider_03_verdict": verdict,
                        "provider_03_findings": findings,
                    }
                ]
                review_findings.extend(findings)
                return ValidationResult(
                    admitted=False,
                    findings=review_findings,
                )
            else:
                # REJECTED or unknown → hard deny
                return ValidationResult(
                    admitted=False,
                    findings=findings,
                )

        except httpx.HTTPStatusError as exc:
            logger.error(
                "[Provider03] validate_fria HTTP error: %s status=%d",
                url,
                exc.response.status_code,
            )
            return ValidationResult(
                admitted=False,
                error=f"HTTP {exc.response.status_code}",
                findings=[
                    {
                        "code": FINDING_CODE_ENDPOINT_ERROR,
                        "severity": "blocked",
                        "message": f"Provider 03 HTTP error: {exc.response.status_code}",
                    }
                ],
            )
        except httpx.RequestError as exc:
            logger.error("[Provider03] validate_fria request error: %s %s", url, exc)
            return ValidationResult(
                admitted=False,
                error=str(exc),
                findings=[
                    {
                        "code": FINDING_CODE_ENDPOINT_ERROR,
                        "severity": "blocked",
                        "message": f"Provider 03 request failed: {exc}",
                    }
                ],
            )

    async def submit_evidence(self, thread_id: str, evidence_hash: str):  # type: ignore[no-untyped-def]
        """Submit post-execution attestation evidence to Provider 03.

        Returns:
            EvidenceSeal with the sealed attestation hash.
        """
        import httpx

        from src.gateway.governance.normative_provider import EvidenceSeal

        if not self._endpoint:
            return EvidenceSeal(
                thread_id=thread_id,
                error="Provider 03 endpoint not configured",
            )

        url = f"{self._endpoint}/evidence/{quote(thread_id, safe='')}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    url,
                    json={"evidence_hash": evidence_hash},
                    headers=self._headers(),
                )
                resp.raise_for_status()
                data = resp.json()
                return EvidenceSeal(
                    thread_id=thread_id,
                    seal_hash=data.get("seal_hash", data.get("receipt_hash", "")),
                )
        except httpx.HTTPStatusError as exc:
            logger.error(
                "[Provider03] submit_evidence HTTP error: %s status=%d",
                url,
                exc.response.status_code,
            )
            return EvidenceSeal(
                thread_id=thread_id,
                error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
            )
        except httpx.RequestError as exc:
            logger.error("[Provider03] submit_evidence request error: %s %s", url, exc)
            return EvidenceSeal(thread_id=thread_id, error=str(exc))

    def ingest_bind_receipt(self, receipt: dict[str, Any]) -> str:
        """Ingest and verify a Provider 03 bind receipt, returning its canonical hash.

        This is a Provider 03-specific extension method, not part of the
        standard NormativeProvider protocol.

        v3.1.0: Migrated to RFC 8785 JCS canonicalization.
        """
        canon_bytes = jcs_canonicalize_plan(receipt)
        digest = hashlib.sha256(canon_bytes).hexdigest()
        logger.info(
            "[Provider03] Ingested bind receipt: id=%s hash=%s",
            receipt.get("receipt_id", "unknown"),
            digest[:16],
        )
        return digest
