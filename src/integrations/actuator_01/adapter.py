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

Outcome classification (``ActuationOutcome``): a failure is ``REJECTED`` only
when the partner definitively did not execute — pre-wire gate failures, a
connection that was never established, or an explicit partner refusal.  A
failure after the envelope may have reached the partner (read timeout, reset
mid-request, 5xx gateway errors, a 200 without a parseable receipt) is
``UNKNOWN`` and non-retryable: the order may have executed, so the governor
confirms rather than releases its reservations and a blind retry could
double-execute.

This module lives in ``src/integrations/actuator_01/`` (Layer 3) and imports
from the kernel (Layer 1) only through the vendor-neutral protocol.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from datetime import datetime, timezone
from types import TracebackType

import httpx

from src.gateway.governance.execution_actuator import (
    ActuationOutcome,
    ActuationReceipt,
    ActuatorCapability,
    ExecutionClearance,
    ReceiptVerification,
)
from src.gateway.governance.execution_actuator import (
    ExecutionActuator as ExecutionActuator,
)
from src.gateway.governance.raw_signer_protocol import RawMessageSigner
from src.gateway.governance.seams.credential_broker import CredentialBrokerAdapter
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
from src.integrations.actuator_01.receipt_verifier import verify_partner_receipt
from src.integrations.actuator_01.response_classifier import (
    ResponseCategory,
    classify_network_error,
    classify_response,
)
from src.integrations.actuator_01.signatures import (
    SandboxSigningBundle,
    sign_for_quorum,
)
from src.integrations.trust.key_manifest import (
    Ed25519KeyManifestClient,
    Ed25519KeyResolver,
)

logger = logging.getLogger(__name__)

# Type alias for per-operator signer resolution
SignerResolver = Callable[[str], RawMessageSigner]

# Environment variable keys for adapter configuration.
_ENV_ENDPOINT = "ACTUATOR_01_ENDPOINT"
_ENV_CERT_PATH = "ACTUATOR_01_CERT_PATH"
_ENV_KEY_PATH = "ACTUATOR_01_KEY_PATH"
_ENV_CA_PATH = "ACTUATOR_01_CA_PATH"
_ENV_TENANT_ID = "ACTUATOR_01_TENANT_ID"
_ENV_SIGNING_KEYS_DIR = "ACTUATOR_01_SIGNING_KEYS_DIR"
_ENV_RECEIPT_KEY_MANIFEST_URL = "ACTUATOR_01_RECEIPT_KEY_MANIFEST_URL"
_ENV_REQUIRE_SIGNED_RECEIPTS = "ACTUATOR_01_REQUIRE_SIGNED_RECEIPTS"

# Capabilities declared by this actuator.
_CAPABILITIES: set[ActuatorCapability] = {
    ActuatorCapability.MULTI_SIG_QUORUM,
    ActuatorCapability.MTLS_REQUIRED,
    ActuatorCapability.DIGEST_ONLY_PAYLOAD,
    ActuatorCapability.REPLAY_PROTECTED,
}

# HTTP statuses that are an explicit partner refusal: the envelope was
# received and definitively NOT executed.  Every other non-accepted status
# (200 without a valid receipt, 408, 500, 502, 504, unrecognised) leaves the
# execution state indeterminate.
_DEFINITIVE_REFUSAL_STATUSES: frozenset[int] = frozenset(
    {400, 401, 403, 409, 421, 422, 429, 503}
)

# Transport errors raised before any request bytes leave the client.
_PRE_SEND_TRANSPORT_ERRORS: tuple[type[httpx.HTTPError], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
)


class Actuator01Adapter:
    """Concrete implementation of ``ExecutionActuator`` for actuator_01.

    Orchestrates:
    - Envelope construction with RFC 8785 (JCS) canonicalization
    - 120-byte assertion building with domain-tagged KMS signature
    - Per-operator quorum signing
    - mTLS HTTP submission
    - Response classification with fail-closed semantics
    - Optional credential broker integration for outbound authentication
    - Optional kid-resolved verification of partner-signed receipts

    Configuration is sourced from environment variables:
    - ``ACTUATOR_01_ENDPOINT``: Base URL (required)
    - ``ACTUATOR_01_CERT_PATH``: Client certificate PEM (required)
    - ``ACTUATOR_01_KEY_PATH``: Client private key PEM (required)
    - ``ACTUATOR_01_CA_PATH``: CA bundle PEM (required)
    - ``ACTUATOR_01_TENANT_ID``: Secure tenant identifier (required)
    - ``ACTUATOR_01_SIGNING_KEYS_DIR``: Optional directory containing
      ``sandbox_public_keys.json`` and Ed25519 ``*.key`` files for multi-key
      policy, assertion, and per-operator quorum signing
    - ``ACTUATOR_01_RECEIPT_KEY_MANIFEST_URL``: Partner receipt-signing JWKS
      (optional; enables receipt signature verification)
    - ``ACTUATOR_01_REQUIRE_SIGNED_RECEIPTS``: ``true`` to treat any partner
      response without a VERIFIED signature as an UNKNOWN outcome (requires
      the manifest URL)

    Args:
        client: Pre-configured ``ActuatorHttpClient``.
        signer: ``RawMessageSigner`` protocol instance for quorum and assertion signing.
        signer_resolver: Optional callable ``(operator_urn: str) -> RawMessageSigner``
            for per-operator signing keys. If ``None``, defaults to ``signer`` for all operators.
        policy_signer: Optional policy authority signer for dual-authority decision signatures.
        credential_broker: Optional ``CredentialBrokerAdapter`` for fetching outbound API credentials.
        receipt_key_resolver: Optional kid-resolved trust anchor for partner
            receipt signatures. Without it, signed receipts are ``UNVERIFIED``.
        require_signed_receipts: Strict mode — only a ``VERIFIED`` partner
            response may move the outcome off ``UNKNOWN``.

    Raises:
        ValueError: ``require_signed_receipts`` without a ``receipt_key_resolver``.
    """

    def __init__(
        self,
        client: ActuatorHttpClient,
        signer: RawMessageSigner,
        signer_resolver: SignerResolver | None = None,
        policy_signer: RawMessageSigner | None = None,
        credential_broker: CredentialBrokerAdapter | None = None,
        receipt_key_resolver: Ed25519KeyResolver | None = None,
        require_signed_receipts: bool = False,
    ) -> None:
        if require_signed_receipts and receipt_key_resolver is None:
            raise ValueError(
                "[actuator_01/adapter] require_signed_receipts needs a "
                "receipt_key_resolver (kid-resolved trust anchor)"
            )
        self._client = client
        self._signer = signer
        self._resolve_signer = signer_resolver or (lambda _urn: signer)
        self._policy_signer = policy_signer  # Optional dual-authority policy signer
        self._credential_broker = credential_broker  # Optional credential broker
        self._receipt_key_resolver = receipt_key_resolver
        self._require_signed_receipts = require_signed_receipts

    @classmethod
    def from_env(
        cls,
        signer: RawMessageSigner | None = None,
        signer_resolver: SignerResolver | None = None,
        policy_signer: RawMessageSigner | None = None,
        credential_broker: CredentialBrokerAdapter | None = None,
    ) -> Actuator01Adapter:
        """Construct adapter from environment variables.

        Args:
            signer: Base signer (RawMessageSigner) for assertions and default quorum signing.
                Defaults to get_governance_signer() if omitted.
            signer_resolver: Optional callable ``(operator_urn: str) -> RawMessageSigner``
                for per-operator signing keys. If ``None``, defaults to ``signer`` for all.
            policy_signer: Optional policy authority signer for dual-authority decision signatures.
            credential_broker: Optional ``CredentialBrokerAdapter`` for fetching outbound API credentials.

        Raises:
            RuntimeError: If any required environment variable is missing.
            ValueError: Strict receipts requested without a manifest URL, or a
                manifest URL with a disallowed scheme.
        """
        signing_keys_dir = os.environ.get(_ENV_SIGNING_KEYS_DIR, "").strip()
        if signing_keys_dir:
            bundle = SandboxSigningBundle.from_directory(signing_keys_dir)
            if signer is None:
                signer = bundle.assertion_signer
            if signer_resolver is None:
                signer_resolver = bundle.resolve_signer
            if policy_signer is None:
                policy_signer = bundle.policy_signer

        if signer is None:
            from src.gateway.governance.kms_signer import get_governance_signer

            signer = get_governance_signer()
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

        manifest_url = os.environ.get(_ENV_RECEIPT_KEY_MANIFEST_URL, "").strip()
        require_signed = os.environ.get(
            _ENV_REQUIRE_SIGNED_RECEIPTS, ""
        ).strip().lower() in ("1", "true", "yes")

        return cls(
            client=client,
            signer=signer,
            signer_resolver=signer_resolver,
            policy_signer=policy_signer,
            credential_broker=credential_broker,
            receipt_key_resolver=(
                Ed25519KeyManifestClient(manifest_url) if manifest_url else None
            ),
            require_signed_receipts=require_signed,
        )

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
            logger.warning("[actuator_01/adapter] health_check: KMS not active")
            return False

        return await self._client.health_check()

    def get_capabilities(self) -> set[ActuatorCapability]:
        """Declare this actuator's capabilities."""
        capabilities = _CAPABILITIES.copy()
        if self._receipt_key_resolver is not None:
            capabilities.add(ActuatorCapability.SIGNED_RECEIPTS)
        return capabilities

    async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
        """Actuate an authorized action at the downstream execution boundary.

        Orchestrates the full pipeline per ``ExecutionActuator`` protocol:

        1. Validate clearance and build envelope (envelope_builder)
        2. Canonicalize per RFC 8785 (JCS), enforce 4KB ceiling, compute digest
        3. Build 120-byte assertion (assertion)
        4. Sign for quorum — one signature per operator (signatures)
        5. Submit over mTLS (client)
        6. Classify response (response_classifier)
        7. Verify the partner's receipt signature (receipt_verifier) and
           return the ActuationReceipt

        Fail-closed: any step that fails returns ``accepted=False`` with
        structured findings.  Definitive refusals carry ``outcome=REJECTED``;
        failures after the envelope may have reached the partner carry
        ``outcome=UNKNOWN`` (non-retryable).  Evidence is recorded by the
        kernel's ``dispatch_actuation()``, never by this adapter.

        Args:
            clearance: ``ExecutionClearance`` from the governance decision.

        Returns:
            ``ActuationReceipt`` with accept/reject status and evidence fields.
        """
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        # ── v3.0 Security Gates ───────────────────────────────────────────

        # Gate 1: Identity validation
        if clearance.executor_id != self.actuator_id:
            logger.error(
                "[actuator_01/adapter] EXECUTOR_ID_MISMATCH: clearance.executor_id=%s, self.actuator_id=%s",
                clearance.executor_id,
                self.actuator_id,
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    {
                        "code": "EXECUTOR_ID_MISMATCH",
                        "severity": "TERMINAL",
                        "detail": f"Clearance executor_id '{clearance.executor_id}' does not match '{self.actuator_id}'",
                    }
                ],
                retryable=False,
                envelope_digest=None,
                timestamp_utc=timestamp_utc,
            )

        # Gate 2: Target route validation
        normalized_target = clearance.target_route.rstrip("/")
        normalized_client_base = (
            getattr(self._client, "base_url", "").rstrip("/") if self._client else ""
        )

        if normalized_target not in (normalized_client_base, "*", "local://default"):
            client_base = (
                getattr(self._client, "base_url", None) if self._client else None
            )
            logger.error(
                "[actuator_01/adapter] TARGET_ROUTE_MISMATCH: clearance.target_route=%s, client.base_url=%s",
                clearance.target_route,
                client_base,
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    {
                        "code": "TARGET_ROUTE_MISMATCH",
                        "severity": "TERMINAL",
                        "detail": f"Route '{clearance.target_route}' does not match client egress '{client_base}'",
                    }
                ],
                retryable=False,
                envelope_digest=None,
                timestamp_utc=timestamp_utc,
            )

        # ── Gate 3: Fetch outbound credentials (optional) ────────────────
        extra_headers: dict[str, str] = {}
        if self._credential_broker:
            try:
                # Use operator_urn as agent SVID for credential authorization
                agent_svid = clearance.operator_urn
                extra_headers = await self._credential_broker.fetch_credential(
                    agent_svid=agent_svid,
                    tool_name=clearance.action,
                    scope=None,
                )
                # Security: never log header values (not even a prefix) —
                # only which auth headers the broker supplied.
                logger.info(
                    "[actuator_01/adapter] Outbound auth headers fetched for "
                    "action=%s svid=%s header_names=%s",
                    clearance.action,
                    agent_svid[:20] + "..." if len(agent_svid) > 20 else agent_svid,
                    sorted(extra_headers),
                )
            except Exception as exc:
                # Fail-closed: Credential broker failures block execution
                # Component name + broker error; no credential value is logged.
                # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
                logger.error("[actuator_01/adapter] Credential broker failed: %s", exc)
                return ActuationReceipt(
                    accepted=False,
                    receipt_id=None,
                    session_uuid=None,
                    raw_receipt=None,
                    findings=[
                        {
                            "code": "CREDENTIAL_BROKER_FAILED",
                            "severity": "TERMINAL",
                            "detail": str(exc),
                        }
                    ],
                    retryable=False,
                    envelope_digest=None,
                    timestamp_utc=timestamp_utc,
                )

        # ── Step 1-2: Build, canonicalize, digest ─────────────────────────
        try:
            canonical_bytes, envelope_digest = build_and_canonicalize(
                clearance, policy_signer=self._policy_signer
            )
        except InvalidClearanceError as exc:
            logger.warning("[actuator_01/adapter] Clearance validation failed: %s", exc)
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    {
                        "code": "INVALID_CLEARANCE",
                        "severity": "TERMINAL",
                        "detail": str(exc),
                    }
                ],
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
                findings=[
                    {
                        "code": "ENVELOPE_TOO_LARGE",
                        "severity": "TERMINAL",
                        "detail": str(exc),
                    }
                ],
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
            logger.error("[actuator_01/adapter] Assertion build failed: %s", exc)
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    {
                        "code": "ASSERTION_BUILD_FAILED",
                        "severity": "TERMINAL",
                        "detail": str(exc),
                    }
                ],
                retryable=False,
                envelope_digest=envelope_digest,
                timestamp_utc=timestamp_utc,
            )

        # ── Step 4: Sign for quorum ───────────────────────────────────────
        #
        # Per-operator signing is supported via the signer_resolver callback.
        # If no resolver is provided, defaults to using the same signer for all
        # operators (reference implementation mode).
        operator_urns: list[str] = []
        quorum_signatures: list[str] = []

        try:
            # Collect URNs and check for duplicates before signing
            for approval in clearance.approvals:
                urn = approval.get("approver_urn", "")
                if not urn:
                    raise RuntimeError("Approval record missing approver_urn")
                operator_urns.append(urn)

            # Detect duplicate operator URNs (fail-closed)
            if len(operator_urns) != len(set(operator_urns)):
                logger.error(
                    "[actuator_01/adapter] Duplicate operator URNs detected in approvals"
                )
                return ActuationReceipt(
                    accepted=False,
                    receipt_id=None,
                    session_uuid=None,
                    raw_receipt=None,
                    findings=[
                        {
                            "code": "cage.quorum.duplicate_operators",
                            "severity": "TERMINAL",
                            "detail": "Duplicate operator URNs detected in approval set",
                        }
                    ],
                    retryable=False,
                    envelope_digest=envelope_digest,
                    timestamp_utc=timestamp_utc,
                )

            # Sign with per-operator signers
            for urn in operator_urns:
                operator_signer = self._resolve_signer(urn)
                sig = sign_for_quorum(operator_signer, canonical_bytes)
                quorum_signatures.append(sig)
        except (RuntimeError, KeyError, Exception) as exc:
            logger.error("[actuator_01/adapter] Quorum signing failed: %s", exc)
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    {
                        "code": "QUORUM_SIGNING_FAILED",
                        "severity": "TERMINAL",
                        "detail": str(exc),
                    }
                ],
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
                extra_headers=extra_headers if extra_headers else None,
            )
        except httpx.HTTPError as exc:
            classified = classify_network_error(exc)
            never_sent = isinstance(exc, _PRE_SEND_TRANSPORT_ERRORS)
            logger.error(
                "[actuator_01/adapter] Network error during submission (%s): %s",
                "never sent" if never_sent else "outcome indeterminate",
                exc,
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=classified.findings,
                # Only a request that never left the client is safe to retry.
                retryable=classified.retryable and never_sent,
                envelope_digest=envelope_digest,
                timestamp_utc=timestamp_utc,
                outcome=(
                    ActuationOutcome.REJECTED
                    if never_sent
                    else ActuationOutcome.UNKNOWN
                ),
            )
        except Exception as exc:
            # Catch-all for unexpected transport errors (fail-closed).  The
            # envelope may already be on the wire, so the outcome is unknown.
            logger.error(
                "[actuator_01/adapter] Unexpected error during submission: %s",
                exc,
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    {
                        "code": "UNEXPECTED_ERROR",
                        "severity": "TERMINAL",
                        "detail": str(exc),
                    }
                ],
                retryable=False,
                envelope_digest=envelope_digest,
                timestamp_utc=timestamp_utc,
                outcome=ActuationOutcome.UNKNOWN,
            )

        # ── Step 6: Classify response ─────────────────────────────────────
        classified = classify_response(response)

        # ── Step 7: Verify receipt signature, build ActuationReceipt ───────
        if classified.category == ResponseCategory.ACCEPTED:
            outcome = ActuationOutcome.ACCEPTED
        elif classified.status_code in _DEFINITIVE_REFUSAL_STATUSES:
            outcome = ActuationOutcome.REJECTED
        else:
            outcome = ActuationOutcome.UNKNOWN

        findings = list(classified.findings)
        check = await verify_partner_receipt(
            classified.raw_body,
            envelope_digest=envelope_digest,
            key_resolver=self._receipt_key_resolver,
        )
        if check.finding is not None:
            findings.append(check.finding)
        if check.verification is ReceiptVerification.INVALID:
            # A forged or mis-bound receipt cannot be trusted in either
            # direction: the partner may or may not have executed.
            outcome = ActuationOutcome.UNKNOWN
        elif (
            check.verification is ReceiptVerification.UNVERIFIED
            and self._require_signed_receipts
            and outcome is not ActuationOutcome.UNKNOWN
        ):
            findings.append(
                {
                    "code": "RECEIPT_UNVERIFIED",
                    "severity": "TERMINAL",
                    "detail": "signed receipts required; partner response not "
                    "verified — outcome indeterminate",
                }
            )
            outcome = ActuationOutcome.UNKNOWN

        receipt = ActuationReceipt(
            accepted=outcome is ActuationOutcome.ACCEPTED,
            receipt_id=classified.receipt_id,
            session_uuid=classified.session_uuid,
            raw_receipt=classified.raw_body,
            findings=findings,
            # An indeterminate outcome is never retryable: a retry could
            # double-execute an order the partner already filled.
            retryable=classified.retryable and outcome is ActuationOutcome.REJECTED,
            envelope_digest=envelope_digest,
            timestamp_utc=timestamp_utc,
            outcome=outcome,
            verification=check.verification,
        )

        if receipt.accepted:
            logger.info(
                "[actuator_01/adapter] Actuation ACCEPTED: receipt_id=%s "
                "session_uuid=%s verification=%s digest=%s",
                receipt.receipt_id,
                receipt.session_uuid,
                receipt.verification.value,
                envelope_digest[:16],
            )
        else:
            logger.warning(
                "[actuator_01/adapter] Actuation %s: category=%s "
                "status=%d error=%s retryable=%s digest=%s",
                outcome.value,
                classified.category.value,
                classified.status_code,
                classified.error_code,
                receipt.retryable,
                envelope_digest[:16],
            )

        return receipt

    async def close(self) -> None:
        """Close the underlying HTTP client connection pool."""
        await self._client.close()

    async def __aenter__(self) -> Actuator01Adapter:
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> None:
        await self.close()
