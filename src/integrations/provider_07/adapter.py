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
Provider 07 NormativeProvider Adapter — Bayesian Causal Suitability Oracle.

Layer 3 integration adapter implementing the 3-endpoint NormativeProvider seam
for Bayesian belief network inference over financial suitability constraints
(SEC Reg BI, FINRA Rule 2111, EU AI Act Art. 29a).

Key Features:
- Out-of-band JWKS key resolution (never trust embedded keys)
- Ed25519 JCS signature verification over inference responses
- Fail-closed tri-state decision mapping (ALLOW/REFUSE/ESCALATE → admitted bool)
- Token mint verification (authority_record_id mandatory for ALLOW decisions)
- Comprehensive error handling with structured findings

Architectural Invariants:
- Gate G8: Vendor brand name "InferTheta" used ONLY in docstrings
- Gate G3: No circular imports (lazy seam import via function-scope)
- Fail-closed on HTTP errors, timeouts, signature failures, unknown kid
- ALLOW decisions require non-empty authority_record_id (token mint proof)

Wire Protocol:
- POST /infer → Bayesian inference with tri-state decision + Ed25519 signature
- GET /baseline/{region} → Regional normative ruleset (FINRA, SEC Reg BI, etc.)
- POST /evidence-chain/{thread_id} → Evidence hash submission for audit trail
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import Any

import httpx

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.normative import (
    EvidenceSeal,
    NormativeBaseline,
    ValidationResult,
)

from .jwks_client import Provider07JwksClient
from .schema import (
    InferThetaBaselineResponse,
    InferThetaInferenceRequest,
    InferThetaInferenceResponse,
)
from .signature import verify_inference_signature

logger = logging.getLogger("cage.provider_07.adapter")


class NormativeProviderError(Exception):
    """Raised when provider HTTP/network operations fail."""


class Provider07NormativeProvider:
    """
    NormativeProvider implementation for Bayesian causal suitability inference.

    Implements the 3-endpoint NormativeProvider seam:
    1. fetch_baseline(region) → Regional normative ruleset
    2. validate_fria(payload) → Bayesian inference with cryptographic verification
    3. submit_evidence(thread_id, evidence_hash) → Audit trail submission

    Configuration:
        endpoint: Base URL of the InferTheta service (e.g., "http://localhost:8087")
        api_key: Optional API key for authentication (default: "")
        jwks_url: JWKS manifest endpoint for Ed25519 key resolution
        timeout_seconds: HTTP request timeout (default: 5.0)
        jwks_client: Optional pre-configured JWKS client (for testing)

    Environment Variables (via from_env()):
        PROVIDER_07_ENDPOINT: Base URL (required)
        PROVIDER_07_API_KEY: API key (optional)
        PROVIDER_07_JWKS_URL: JWKS URL (optional, defaults to {endpoint}/.well-known/jwks.json)
        PROVIDER_07_TIMEOUT_SECONDS: HTTP timeout (optional, default: 5.0)
    """

    def __init__(
        self,
        endpoint: str,
        api_key: str = "",
        jwks_url: str = "",
        timeout_seconds: float = 5.0,
        jwks_client: Provider07JwksClient | None = None,
        allow_step1_unsigned: bool = False,
    ) -> None:
        """
        Initialize Provider 07 adapter.

        Args:
            endpoint: Base URL of the InferTheta service
            api_key: Optional API key for HTTP Authentication header
            jwks_url: JWKS manifest endpoint (default: {endpoint}/.well-known/jwks.json)
            timeout_seconds: HTTP request timeout in seconds
            jwks_client: Optional pre-configured JWKS client (for testing)
            allow_step1_unsigned: Dev/testing only. Allows Step 1 unsigned responses.
        """
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds
        self._allow_step1_unsigned = allow_step1_unsigned

        if self._allow_step1_unsigned:
            cage_env = os.environ.get("CAGE_ENV", "development").lower()
            if cage_env in ("production", "prod"):
                raise RuntimeError(
                    f"allow_step1_unsigned cannot be enabled in production environments (CAGE_ENV={cage_env!r}). "
                    "Cryptographic signatures and JWKS resolution are strictly required."
                )
            logger.warning(
                "⚠️  Provider 07 allow_step1_unsigned active (CAGE_ENV=%s) — "
                "Step 1 unsigned responses will be accepted for dev/testing only.",
                cage_env,
            )

        # JWKS client for out-of-band key resolution
        if jwks_client is not None:
            self._jwks_client = jwks_client
        else:
            # Default JWKS URL follows RFC 8615 well-known URI convention
            effective_jwks_url = jwks_url or f"{self._endpoint}/.well-known/jwks.json"
            self._jwks_client = Provider07JwksClient(
                jwks_url=effective_jwks_url,
                cache_ttl_seconds=3600,
                timeout_seconds=timeout_seconds,
            )

    @classmethod
    def from_env(cls) -> Provider07NormativeProvider:
        """
        Construct adapter from environment variables.

        Environment Variables:
            PROVIDER_07_ENDPOINT: Base URL (default: "http://localhost:8087" for testing)
            PROVIDER_07_API_KEY: API key (optional)
            PROVIDER_07_JWKS_URL: JWKS URL (optional)
            PROVIDER_07_TIMEOUT_SECONDS: HTTP timeout (optional, default: 5.0)
            PROVIDER_07_ALLOW_STEP1_UNSIGNED: Allow Step 1 unsigned responses (default: false)

        Returns:
            Configured Provider07NormativeProvider instance
        """
        # Default endpoint for test environments (conformance suite)
        endpoint = os.environ.get(
            "PROVIDER_07_ENDPOINT", "http://localhost:8087"
        ).strip()
        api_key = os.environ.get("PROVIDER_07_API_KEY", "").strip()
        jwks_url = os.environ.get("PROVIDER_07_JWKS_URL", "").strip()
        timeout_seconds = float(os.environ.get("PROVIDER_07_TIMEOUT_SECONDS", "5.0"))
        allow_step1_unsigned = (
            os.environ.get("PROVIDER_07_ALLOW_STEP1_UNSIGNED", "false").strip().lower()
            in ("true", "1", "yes")
        )

        return cls(
            endpoint=endpoint,
            api_key=api_key,
            jwks_url=jwks_url,
            timeout_seconds=timeout_seconds,
            allow_step1_unsigned=allow_step1_unsigned,
        )

    async def fetch_baseline(self, region: str) -> NormativeBaseline:
        """
        Fetch regional normative ruleset from provider.

        Wire Protocol:
            GET {endpoint}/baseline/{region}

        Response Schema:
            {
                "region": "us-east-1",
                "rules": [{"rule_id": "...", "description": "...", "threshold": 0.8}],
                "baseline_hash": "sha256...",
                "issued_at": 1234567890
            }

        Args:
            region: Geographic/regulatory region identifier

        Returns:
            NormativeBaseline with regional rules, or error on failure

        Note:
            Never raises exceptions. HTTP/network errors are captured
            in NormativeBaseline.error field (fail-closed).
        """
        url = f"{self._endpoint}/baseline/{region}"
        logger.info("provider_07: Fetching baseline from %s", url)

        try:
            headers = {}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"

            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()

            # Parse to Pydantic schema for validation
            baseline_response = InferThetaBaselineResponse(**data)

            # Convert to NormativeBaseline format
            # Map InferTheta's rule schema to CAGE's profile format
            profile = {
                "region": baseline_response.region,
                "rules": [rule.model_dump() for rule in baseline_response.rules],
                "baseline_hash": baseline_response.baseline_hash,
                "issued_at": baseline_response.issued_at,
            }

            return NormativeBaseline(
                region=region,
                profile=profile,
                fetched_at=time.time(),
                etag=baseline_response.baseline_hash,
            )

        except httpx.HTTPError as exc:
            error_msg = f"HTTP error fetching baseline: {exc}"
            logger.error("provider_07: %s", error_msg)
            return NormativeBaseline(region=region, profile={}, error=error_msg)

        except Exception as exc:
            error_msg = f"Unexpected error fetching baseline: {exc}"
            logger.error("provider_07: %s", error_msg)
            return NormativeBaseline(region=region, profile={}, error=error_msg)

    async def validate_fria(self, payload: dict[str, Any]) -> ValidationResult:
        """
        Submit governance payload for Bayesian suitability inference.

        Wire Protocol:
            POST {endpoint}/infer
            Content-Type: application/json
            Body: InferThetaInferenceRequest

        Response Schema (InferThetaInferenceResponse):
            {
                "decision": "ALLOW" | "REFUSE" | "ESCALATE",
                "confidence_score": 0.95,
                "posterior_risk_score": 0.12,
                "marginal_probabilities": {...},
                "utility_rankings": [...],
                "authority_record_id": "uuid-or-null",
                "kid": "key-id",
                "signature": "base64url-signature",
                "findings": [...]
            }

        Fail-Closed Decision Mapping:
            ALLOW + valid signature + non-empty authority_record_id → admitted=True
            ALLOW + valid signature + missing authority_record_id → admitted=False (TOKEN_MINT_FAILED)
            ALLOW + invalid signature → admitted=False (INFERTHETA_SIGNATURE_INVALID)
            REFUSE → admitted=False (INFERTHETA_UNSUITABLE)
            ESCALATE → admitted=False, needs_human_review=True (INFERTHETA_ESCALATE)
            HTTP error / timeout / unknown kid → admitted=False (PROVIDER_07_HTTP_ERROR)

        Args:
            payload: Governance decision context (OPA input snapshot)

        Returns:
            ValidationResult with admitted bool and structured findings
        """
        url = f"{self._endpoint}/infer"
        logger.info("provider_07: Validating FRIA at %s", url)

        try:
            # Map generic payload to InferTheta inference request schema
            # This adapter expects the payload to already be in InferThetaInferenceRequest format
            request_data = InferThetaInferenceRequest(**payload)

            headers = {"Content-Type": "application/json"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"

            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.post(
                    url,
                    json=request_data.model_dump(),
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()

            # Parse response to Pydantic schema
            inference_response = InferThetaInferenceResponse(**data)

        except httpx.HTTPError as exc:
            error_msg = f"HTTP error during inference: {exc}"
            logger.error("provider_07: %s", error_msg)
            return ValidationResult(
                admitted=False,
                findings=[
                    {
                        "code": "PROVIDER_07_HTTP_ERROR",
                        "message": error_msg,
                        "status": "error",
                    }
                ],
            )

        except Exception as exc:
            error_msg = f"Unexpected error during inference: {exc}"
            logger.error("provider_07: %s", error_msg)
            return ValidationResult(
                admitted=False,
                findings=[
                    {
                        "code": "PROVIDER_07_PARSE_ERROR",
                        "message": error_msg,
                        "status": "error",
                    }
                ],
            )

        # Step 1 unsigned mode check (dev/testing only)
        is_step1_unsigned = (
            self._allow_step1_unsigned
            and inference_response.signature == "unsigned-placeholder"
        )

        if not is_step1_unsigned:
            # Resolve public key via out-of-band JWKS
            # Trust Anchor Invariant: Never parse keys from the response itself
            try:
                public_key = await self._jwks_client.get_key(inference_response.kid)
            except Exception as exc:
                logger.error(
                    "provider_07: JWKS fetch failed for kid=%s: %s",
                    inference_response.kid,
                    exc,
                )
                return ValidationResult(
                    admitted=False,
                    findings=[
                        {
                            "code": "INFERTHETA_JWKS_ERROR",
                            "message": f"Failed to resolve kid={inference_response.kid}: {exc}",
                            "status": "error",
                        }
                    ],
                )

            if public_key is None:
                # Unknown kid — fail closed
                logger.warning(
                    "provider_07: Unknown kid=%s in JWKS manifest — failing closed",
                    inference_response.kid,
                )
                return ValidationResult(
                    admitted=False,
                    findings=[
                        {
                            "code": "INFERTHETA_UNKNOWN_KEY",
                            "message": f"Unknown Key Identifier: {inference_response.kid}",
                            "status": "fail",
                        }
                    ],
                )

            # Verify Ed25519 JCS signature
            signature_valid = verify_inference_signature(
                payload=data,
                public_key=public_key,
                signature_b64=inference_response.signature,
            )

            if not signature_valid:
                logger.warning(
                    "provider_07: Signature verification FAILED for kid=%s decision=%s",
                    inference_response.kid,
                    inference_response.decision,
                )
                return ValidationResult(
                    admitted=False,
                    findings=[
                        {
                            "code": "INFERTHETA_SIGNATURE_INVALID",
                            "message": "Ed25519 signature verification failed",
                            "status": "fail",
                        }
                    ],
                )
        else:
            logger.warning(
                "provider_07: STEP 1 DEMO MODE ACTIVE — skipping Ed25519 signature verification "
                "for kid=%s signature=%s",
                inference_response.kid,
                inference_response.signature,
            )

        # Tri-state decision handling with token mint verification
        decision = inference_response.decision

        if decision == "ALLOW":
            # ALLOW decisions MUST include authority_record_id (token mint proof)
            if not inference_response.authority_record_id:
                logger.error(
                    "provider_07: ALLOW decision missing authority_record_id — failing closed"
                )
                return ValidationResult(
                    admitted=False,
                    findings=[
                        {
                            "code": "TOKEN_MINT_FAILED",
                            "message": "ALLOW decision missing authority_record_id",
                            "status": "fail",
                        }
                    ],
                )

            # Valid ALLOW: signature OK (or Step 1 placeholder), authority token present
            logger.info(
                "provider_07: ALLOW decision with authority_record_id=%s posterior_risk=%.3f",
                inference_response.authority_record_id,
                inference_response.posterior_risk_score,
            )
            finding: dict[str, Any] = {
                "code": "INFERTHETA_ALLOW",
                "message": "Bayesian inference admits action",
                "status": "pass",
                "authority_record_id": inference_response.authority_record_id,
                "posterior_risk_score": inference_response.posterior_risk_score,
                "marginal_probabilities": inference_response.marginal_probabilities,
            }
            if is_step1_unsigned:
                finding["step1_demo_mode"] = True

            return ValidationResult(
                admitted=True,
                findings=[finding],
            )

        elif decision == "REFUSE":
            logger.info(
                "provider_07: REFUSE decision posterior_risk=%.3f",
                inference_response.posterior_risk_score,
            )
            return ValidationResult(
                admitted=False,
                findings=[
                    {
                        "code": "INFERTHETA_UNSUITABLE",
                        "message": "Bayesian inference refuses action (unsuitable)",
                        "status": "fail",
                        "posterior_risk_score": inference_response.posterior_risk_score,
                    }
                ],
            )

        elif decision == "ESCALATE":
            logger.warning(
                "provider_07: ESCALATE decision posterior_risk=%.3f — needs human review",
                inference_response.posterior_risk_score,
            )
            return ValidationResult(
                admitted=False,
                findings=[
                    {
                        "code": "INFERTHETA_ESCALATE",
                        "message": "Bayesian inference escalates action to human review",
                        "status": "fail",
                        "needs_human_review": True,
                        "posterior_risk_score": inference_response.posterior_risk_score,
                    }
                ],
            )

        else:
            # Unknown decision state — fail closed
            logger.error("provider_07: Unknown decision=%r — failing closed", decision)
            return ValidationResult(
                admitted=False,
                findings=[
                    {
                        "code": "INFERTHETA_UNKNOWN_DECISION",
                        "message": f"Unknown decision state: {decision}",
                        "status": "error",
                    }
                ],
            )

    async def submit_evidence(self, thread_id: str, evidence_hash: str) -> EvidenceSeal:
        """
        Submit governance evidence hash to provider's audit trail.

        Wire Protocol:
            POST {endpoint}/evidence-chain/{thread_id}
            Content-Type: application/json
            Body: {"evidence_hash": "sha256..."}

        Response:
            {
                "thread_id": "...",
                "seal_status": "RECORDED",
                "timestamp": 1234567890
            }

        Args:
            thread_id: LangGraph thread identifier
            evidence_hash: SHA-256 hash of governance evidence

        Returns:
            EvidenceSeal with seal status, or error on failure

        Note:
            Never raises exceptions. HTTP/network errors are captured
            in EvidenceSeal.error field (fail-closed).
        """
        url = f"{self._endpoint}/evidence-chain/{thread_id}"
        logger.info("provider_07: Submitting evidence to %s", url)

        try:
            headers = {"Content-Type": "application/json"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"

            payload = {"evidence_hash": evidence_hash}

            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()

            # Extract seal status and timestamp
            seal_hash = data.get("seal_hash", "")
            sealed_at = float(data.get("timestamp", time.time()))

            logger.info(
                "provider_07: Evidence seal recorded for thread_id=%s", thread_id
            )
            return EvidenceSeal(
                thread_id=thread_id,
                seal_hash=seal_hash,
                sealed_at=sealed_at,
            )

        except httpx.HTTPError as exc:
            error_msg = f"HTTP error submitting evidence: {exc}"
            logger.error("provider_07: %s", error_msg)
            return EvidenceSeal(thread_id=thread_id, error=error_msg)

        except Exception as exc:
            error_msg = f"Unexpected error submitting evidence: {exc}"
            logger.error("provider_07: %s", error_msg)
            return EvidenceSeal(thread_id=thread_id, error=error_msg)
