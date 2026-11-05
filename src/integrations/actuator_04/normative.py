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

"""Actuator04NormativeProvider delivering conformal p-value gating and normative data."""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.normative import (
    EvidenceSeal,
    FindingStatus,
    NormativeBaseline,
    NormativeProvider,
    ValidationResult,
)
from src.integrations.actuator_04.client import Actuator04Transport
from src.integrations.actuator_04.constants import (
    ENV_CONFORMAL_ALPHA,
    ENV_RECEIPT_KEY_MANIFEST_URL,
    HEADER_ENVELOPE_DIGEST,
    NORMATIVE_VALIDATION_DOMAIN_TAG,
)
from src.integrations.trust.key_manifest import (
    Ed25519KeyManifestClient,
    Ed25519KeyResolver,
)


class Actuator04NormativeProvider(NormativeProvider):
    """Normative provider interfacing with the host substrate's conformal validator."""

    def __init__(
        self,
        *,
        transport: Actuator04Transport,
        default_alpha: float = 0.05,
        receipt_key_resolver: Ed25519KeyResolver | None = None,
    ) -> None:
        self._transport = transport
        self._default_alpha = default_alpha
        self._receipt_key_resolver = receipt_key_resolver

    @classmethod
    def from_env(cls) -> Actuator04NormativeProvider:
        """Construct Actuator04NormativeProvider from environment configuration."""
        transport = Actuator04Transport.from_env()
        alpha = float(os.environ.get(ENV_CONFORMAL_ALPHA, "0.05"))
        manifest_url = os.environ.get(ENV_RECEIPT_KEY_MANIFEST_URL, "").strip()
        resolver: Ed25519KeyResolver | None = (
            Ed25519KeyManifestClient(manifest_url) if manifest_url else None
        )
        return cls(
            transport=transport, default_alpha=alpha, receipt_key_resolver=resolver
        )

    async def fetch_baseline(self, region: str) -> NormativeBaseline:
        """GET /v1/cage/normative-baseline/{region} — fetch conformal calibration parameters."""
        try:
            endpoints = self._transport.resolve_target_endpoints()
            responses = await self._transport.get_from_endpoints(
                f"/v1/cage/normative-baseline/{region}",
                endpoints=endpoints,
            )
            data = responses[0].json()
            return NormativeBaseline(
                region=region,
                profile=data.get("profile", {}),
                fetched_at=time.time(),
                signature=data.get("signature", ""),
                etag=data.get("etag", ""),
            )
        except Exception as exc:
            return NormativeBaseline(
                region=region,
                profile={},
                error=f"Failed to fetch baseline from host substrate: {exc}",
            )

    async def validate_fria(self, payload: dict[str, Any]) -> ValidationResult:
        """POST /v1/cage/conformal/validate — evaluate nonconformity p-value and consensus."""
        canonical_req = jcs_canonicalize_plan(payload)
        digest = hashlib.sha256(canonical_req).hexdigest()

        headers = {
            "Content-Type": "application/json",
            HEADER_ENVELOPE_DIGEST: digest,
        }

        try:
            endpoints = self._transport.resolve_target_endpoints()
            responses = await self._transport.post_to_endpoints(
                "/v1/cage/conformal/validate",
                content=canonical_req,
                headers=headers,
                endpoints=endpoints,
            )
            body = responses[0].json()
        except Exception as exc:
            return ValidationResult(
                admitted=False,
                findings=[
                    {
                        "code": "CONFORMAL_VALIDATE_FAILED",
                        "status": FindingStatus.ERROR,
                        "detail": str(exc),
                    }
                ],
                error=str(exc),
            )

        # Check signature over NORMATIVE_VALIDATION_DOMAIN_TAG + JCS(body_without_sig)
        from src.gateway.governance.seams.actuation import ReceiptVerification
        from src.integrations.actuator_04.adapter import (
            verify_substrate_receipt_signature,
        )

        v_status, finding = await verify_substrate_receipt_signature(
            body,
            domain_tag=NORMATIVE_VALIDATION_DOMAIN_TAG,
            expected_envelope_digest=digest,
            key_resolver=self._receipt_key_resolver,
        )

        if v_status != ReceiptVerification.VERIFIED or finding:
            detail = finding["detail"] if finding else "Receipt signature not verified"
            code = finding["code"] if finding else "RECEIPT_NOT_VERIFIED"
            return ValidationResult(
                admitted=False,
                findings=[
                    {"code": code, "status": FindingStatus.ERROR, "detail": detail}
                ],
                error="Signature verification failed",
            )

        p_value = float(body.get("p_value", 0.0))
        alpha = float(body.get("alpha", self._default_alpha))
        admitted = bool(body.get("admitted", False))

        if p_value <= alpha or not admitted:
            return ValidationResult(
                admitted=False,
                findings=[
                    {
                        "code": "CONFORMAL_NONCONFORMITY_EXCEEDED",
                        "status": FindingStatus.FAIL,
                        "detail": f"Conformal p-value {p_value:.4f} <= alpha {alpha:.4f}",
                    }
                ],
            )

        return ValidationResult(
            admitted=True,
            findings=[
                {
                    "code": "CONFORMAL_ADMISSION_CLEARED",
                    "status": FindingStatus.PASS,
                    "detail": f"Conformal p-value {p_value:.4f} > alpha {alpha:.4f}",
                }
            ],
            sealed_at=time.time(),
        )

    async def submit_evidence(self, thread_id: str, evidence_hash: str) -> EvidenceSeal:
        """GET /v1/cage/evidence-chain/{thread_id} — seal evidence hash into substrate."""
        try:
            endpoints = self._transport.resolve_target_endpoints()
            responses = await self._transport.get_from_endpoints(
                f"/v1/cage/evidence-chain/{thread_id}?hash={evidence_hash}",
                endpoints=endpoints,
            )
            data = responses[0].json()
            return EvidenceSeal(
                thread_id=thread_id,
                seal_hash=data.get("seal_hash", evidence_hash),
                sealed_at=time.time(),
            )
        except Exception as exc:
            return EvidenceSeal(thread_id=thread_id, error=str(exc))
