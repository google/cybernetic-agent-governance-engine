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
adapter.py — Concrete ExecutionActuator Implementation (Phase 3, Stream C)

``Actuator01Adapter`` implements the ``ExecutionActuator`` protocol defined in
``src/gateway/governance/execution_actuator.py``.  It orchestrates the full
pipeline from ``ExecutionClearance`` to ``ActuationReceipt``:

    ExecutionClearance
        → validate + build envelope (envelope_builder)
        → canonicalize per RFC 8785 (JCS)
        → enforce 4KB ceiling
        → compute digest
        → build 120-byte assertion (assertion)
        → sign for quorum (signatures)
        → submit over mTLS (client)
        → classify response (response_classifier)
        → ActuationReceipt

Fail-closed: any step that fails produces ``accepted=False`` with structured
findings.  Network timeouts, HTTP errors, and parse failures never produce a
silent success.

This module lives in ``src/integrations/actuator_01/`` (Layer 3) and imports
from the kernel (Layer 1) only through the vendor-neutral protocol.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone

import httpx

from src.gateway.governance.execution_actuator import (
    ActuationReceipt,
    ActuatorCapability,
    ExecutionActuator,
    ExecutionClearance,
)
from src.gateway.governance.kms_signer import KMSGovernanceSigner
from src.integrations.actuator_01.assertion import (
    AssertionBuildError,
    build_assertion,
)
from src.integrations.actuator_01.client import ActuatorHttpClient
from src.integrations.actuator_01.envelope_builder import (
    EnvelopeTooLargeError,
    InvalidClearanceError,
    build_and_canonicalize,
)
from src.integrations.actuator_01.response_classifier import (
    ResponseCategory,
    classify_network_error,
    classify_response,
)
from src.integrations.actuator_01.signatures import sign_for_quorum

logger = logging.getLogger(__name__)

# Environment variable keys for adapter configuration.
_ENV_ENDPOINT = "ACTUATOR_01_ENDPOINT"
_ENV_CERT_PATH = "ACTUATOR_01_CERT_PATH"
_ENV_KEY_PATH = "ACTUATOR_01_KEY_PATH"
_ENV_CA_PATH = "ACTUATOR_01_CA_PATH"
_ENV_TENANT_ID = "ACTUATOR_01_TENANT_ID"

# Capabilities declared by this actuator.
_CAPABILITIES: set[ActuatorCapability] = {
    ActuatorCapability.MULTI_SIG_QUORUM,
    ActuatorCapability.MTLS_REQUIRED,
    ActuatorCapability.DIGEST_ONLY_PAYLOAD,
    ActuatorCapability.REPLAY_PROTECTED,
}


class Actuator01Adapter:
    """Concrete implementation of ``ExecutionActuator`` for actuator_01.

    Orchestrates:
    - Envelope construction with RFC 8785 (JCS) canonicalization
    - 120-byte assertion building with domain-tagged KMS signature
    - Per-operator quorum signing
    - mTLS HTTP submission
    - Response classification with fail-closed semantics

    Configuration is sourced from environment variables:
    - ``ACTUATOR_01_ENDPOINT``: Base URL (required)
    - ``ACTUATOR_01_CERT_PATH``: Client certificate PEM (required)
    - ``ACTUATOR_01_KEY_PATH``: Client private key PEM (required)
    - ``ACTUATOR_01_CA_PATH``: CA bundle PEM (required)
    - ``ACTUATOR_01_TENANT_ID``: Secure tenant identifier (required)

    Args:
        client: Pre-configured ``ActuatorHttpClient``.  If ``None``,
            constructed from environment variables via ``from_env()``.
        signer: ``KMSGovernanceSigner`` for quorum and assertion signing.
    """

    def __init__(
        self,
        client: ActuatorHttpClient,
        signer: KMSGovernanceSigner,
    ) -> None:
        self._client = client
        self._signer = signer

    @classmethod
    def from_env(cls, signer: KMSGovernanceSigner) -> Actuator01Adapter:
        """Construct adapter from environment variables.

        Raises:
            RuntimeError: If any required environment variable is missing.
        """
        endpoint = os.environ.get(_ENV_ENDPOINT, "")
        cert_path = os.environ.get(_ENV_CERT_PATH, "")
        key_path = os.environ.get(_ENV_KEY_PATH, "")
        ca_path = os.environ.get(_ENV_CA_PATH, "")
        tenant_id = os.environ.get(_ENV_TENANT_ID, "")

        missing = []
        if not endpoint:
            missing.append(_ENV_ENDPOINT)
        if not cert_path:
            missing.append(_ENV_CERT_PATH)
        if not key_path:
            missing.append(_ENV_KEY_PATH)
        if not ca_path:
            missing.append(_ENV_CA_PATH)
        if not tenant_id:
            missing.append(_ENV_TENANT_ID)

        if missing:
            raise RuntimeError(
                f"[actuator_01/adapter] Missing required environment variables: "
                f"{', '.join(missing)}"
            )

        client = ActuatorHttpClient(
            base_url=endpoint,
            cert_path=cert_path,
            key_path=key_path,
            ca_path=ca_path,
            tenant_id=tenant_id,
        )

        return cls(client=client, signer=signer)

    # ── ExecutionActuator Protocol Implementation ─────────────────────────

    @property
    def actuator_id(self) -> str:
        """Unique identifier for this actuator."""
        return "actuator_01"

    async def health_check(self) -> bool:
        """Check if the actuator endpoint is reachable and healthy.

        Returns ``False`` (fail-closed) when mTLS material is unreadable,
        the endpoint is unreachable, or KMS is not active.
        """
        if not self._signer.is_kms_active:
            logger.warning(
                "[actuator_01/adapter] health_check: KMS not active"
            )
            return False

        return await self._client.health_check()

    def get_capabilities(self) -> set[ActuatorCapability]:
        """Declare this actuator's capabilities."""
        return _CAPABILITIES.copy()

    async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
        """Actuate an authorized action at the downstream execution boundary.

        Orchestrates the full pipeline per ``ExecutionActuator`` protocol:

        1. Validate clearance and build envelope (envelope_builder)
        2. Canonicalize per RFC 8785 (JCS), enforce 4KB ceiling, compute digest
        3. Build 120-byte assertion (assertion)
        4. Sign for quorum — one signature per operator (signatures)
        5. Submit over mTLS (client)
        6. Classify response (response_classifier)
        7. Return ActuationReceipt

        Fail-closed: any step that fails returns ``accepted=False`` with
        structured findings.

        Args:
            clearance: ``ExecutionClearance`` from the governance decision.

        Returns:
            ``ActuationReceipt`` with accept/reject status and evidence fields.
        """
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        # ── Step 1-2: Build, canonicalize, digest ─────────────────────────
        try:
            canonical_bytes, envelope_digest = build_and_canonicalize(clearance)
        except InvalidClearanceError as exc:
            logger.warning(
                "[actuator_01/adapter] Clearance validation failed: %s", exc
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[{
                    "code": "INVALID_CLEARANCE",
                    "severity": "TERMINAL",
                    "detail": str(exc),
                }],
                retryable=False,
                envelope_digest=None,
                timestamp_utc=timestamp_utc,
            )
        except EnvelopeTooLargeError as exc:
            logger.warning(
                "[actuator_01/adapter] Envelope exceeds 4KB ceiling: %s", exc
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[{
                    "code": "ENVELOPE_TOO_LARGE",
                    "severity": "TERMINAL",
                    "detail": str(exc),
                }],
                retryable=False,
                envelope_digest=None,
                timestamp_utc=timestamp_utc,
            )

        # ── Step 3: Build assertion ───────────────────────────────────────
        try:
            assertion_b64 = build_assertion(
                envelope_digest_hex=envelope_digest,
                nonce_hex=clearance.nonce,
                issued_at=clearance.issued_at,
                signer=self._signer,
            )
        except (AssertionBuildError, RuntimeError) as exc:
            logger.error(
                "[actuator_01/adapter] Assertion build failed: %s", exc
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[{
                    "code": "ASSERTION_BUILD_FAILED",
                    "severity": "TERMINAL",
                    "detail": str(exc),
                }],
                retryable=False,
                envelope_digest=envelope_digest,
                timestamp_utc=timestamp_utc,
            )

        # ── Step 4: Sign for quorum ───────────────────────────────────────
        #
        # In the current reference implementation, a single KMS key is used
        # for all operators (per docs/architecture/actuator_01_kms_iam_model.md).
        # Production adopters should supply per-operator signers via
        # per-ceremony OIDC downscoping (Option B).
        operator_urns: list[str] = []
        quorum_signatures: list[str] = []

        try:
            for approval in clearance.approvals:
                urn = approval.get("approver_urn", "")
                if not urn:
                    raise RuntimeError(
                        "Approval record missing approver_urn"
                    )
                operator_urns.append(urn)
                sig = sign_for_quorum(self._signer, canonical_bytes)
                quorum_signatures.append(sig)
        except RuntimeError as exc:
            logger.error(
                "[actuator_01/adapter] Quorum signing failed: %s", exc
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[{
                    "code": "QUORUM_SIGNING_FAILED",
                    "severity": "TERMINAL",
                    "detail": str(exc),
                }],
                retryable=False,
                envelope_digest=envelope_digest,
                timestamp_utc=timestamp_utc,
            )

        # ── Step 5: Submit over mTLS ──────────────────────────────────────
        try:
            response = await self._client.submit_envelope(
                canonical_bytes=canonical_bytes,
                operator_urns=operator_urns,
                signatures=quorum_signatures,
                assertion=assertion_b64,
                issued_at=clearance.issued_at,
            )
        except httpx.HTTPError as exc:
            classified = classify_network_error(exc)
            logger.error(
                "[actuator_01/adapter] Network error during submission: %s",
                exc,
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=classified.findings,
                retryable=classified.retryable,
                envelope_digest=envelope_digest,
                timestamp_utc=timestamp_utc,
            )
        except Exception as exc:
            # Catch-all for unexpected transport errors (fail-closed).
            logger.error(
                "[actuator_01/adapter] Unexpected error during submission: %s",
                exc,
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[{
                    "code": "UNEXPECTED_ERROR",
                    "severity": "TERMINAL",
                    "detail": str(exc),
                }],
                retryable=False,
                envelope_digest=envelope_digest,
                timestamp_utc=timestamp_utc,
            )

        # ── Step 6: Classify response ─────────────────────────────────────
        classified = classify_response(response)

        # ── Step 7: Build ActuationReceipt ────────────────────────────────
        receipt = ActuationReceipt(
            accepted=classified.category == ResponseCategory.ACCEPTED,
            receipt_id=classified.receipt_id,
            session_uuid=classified.session_uuid,
            raw_receipt=classified.raw_body,
            findings=classified.findings,
            retryable=classified.retryable,
            envelope_digest=envelope_digest,
            timestamp_utc=timestamp_utc,
        )

        if receipt.accepted:
            logger.info(
                "[actuator_01/adapter] Actuation ACCEPTED: receipt_id=%s "
                "session_uuid=%s digest=%s",
                receipt.receipt_id,
                receipt.session_uuid,
                envelope_digest[:16],
            )
        else:
            logger.warning(
                "[actuator_01/adapter] Actuation REJECTED: category=%s "
                "status=%d error=%s retryable=%s digest=%s",
                classified.category.value,
                classified.status_code,
                classified.error_code,
                classified.retryable,
                envelope_digest[:16],
            )

        return receipt

    async def close(self) -> None:
        """Close the underlying HTTP client connection pool."""
        await self._client.close()

    async def __aenter__(self) -> Actuator01Adapter:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()
