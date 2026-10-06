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

"""Concrete ExecutionActuator implementation for actuator_02 (OpenShell Supervisor).

Enforces seal-bound PreCredentials brokerage, RFC 8785 JCS canonicalization,
KMS/Ed25519 assertion signing, mTLS submission, and out-of-band kid-resolved
receipt signature verification.

Seal profile ``cage-seal/1`` is the default and only mode: every actuation
carries the clearance's routing seal (a JWS) in ``X-CAGE-Routing-Seal`` so the
Supervisor can verify it independently against the gateway JWKS
(docs/partners/actuator_02/SEAL_VERIFICATION_PROFILE.md). A clearance without
a JWS seal is refused before the wire.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.exceptions import InvalidSignature

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.raw_signer_protocol import RawMessageSigner
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ActuationReceipt,
    ActuatorCapability,
    ExecutionClearance,
    ReceiptVerification,
)
from src.gateway.governance.seams.credential_broker import (
    CredentialBrokerAdapter,
    CredentialBrokerError,
)
from src.integrations.actuator_02.constants import (
    ACTUATOR_02_ID,
    ASSERTION_DOMAIN_TAG,
    MAX_ENVELOPE_BYTES,
    RECEIPT_SIGNATURE_DOMAIN_TAG,
    ROUTING_SEAL_HEADER,
    SEAL_PROFILE,
    SEAL_PROFILE_HEADER,
)
from src.integrations.trust.key_manifest import (
    Ed25519KeyManifestClient,
    Ed25519KeyResolver,
)

logger = logging.getLogger(__name__)

_ENV_ENDPOINT = "ACTUATOR_02_ENDPOINT"
_ENV_CERT_PATH = "ACTUATOR_02_CERT_PATH"
_ENV_KEY_PATH = "ACTUATOR_02_KEY_PATH"
_ENV_CA_PATH = "ACTUATOR_02_CA_PATH"
_ENV_RECEIPT_KEY_MANIFEST_URL = "ACTUATOR_02_RECEIPT_KEY_MANIFEST_URL"
_ENV_REQUIRE_SIGNED_RECEIPTS = "ACTUATOR_02_REQUIRE_SIGNED_RECEIPTS"

_CAPABILITIES: set[ActuatorCapability] = {
    ActuatorCapability.MTLS_REQUIRED,
    ActuatorCapability.REPLAY_PROTECTED,
    ActuatorCapability.SIGNED_RECEIPTS,
    ActuatorCapability.DIGEST_ONLY_PAYLOAD,
}

_DEFINITIVE_REFUSAL_STATUSES: frozenset[int] = frozenset(
    {400, 401, 403, 409, 421, 422, 429, 503}
)
_PRE_SEND_TRANSPORT_ERRORS: tuple[type[httpx.HTTPError], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
)
_ED25519_SIGNATURE_BYTES = 64
# Compact JWS: three base64url segments. HMAC (v2) seals have four segments
# and a symmetric key the Supervisor does not hold, so they are refused.
_COMPACT_JWS = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def _finding(code: str, severity: str, detail: str) -> dict[str, str]:
    return {"code": code, "severity": severity, "detail": detail}


async def verify_supervisor_receipt(
    body: dict[str, Any] | None,
    *,
    envelope_digest: str,
    key_resolver: Ed25519KeyResolver | None,
) -> tuple[ReceiptVerification, dict[str, str] | None]:
    """Verify an OpenShell Supervisor response body's detached Ed25519 signature."""
    if not isinstance(body, dict) or "signature" not in body:
        return ReceiptVerification.UNVERIFIED, None

    sig = body["signature"]
    if not isinstance(sig, dict) or sig.get("alg") != "EdDSA":
        return (
            ReceiptVerification.INVALID,
            _finding(
                "RECEIPT_SIGNATURE_MALFORMED", "TERMINAL", "EdDSA signature required"
            ),
        )
    kid = sig.get("kid")
    val = sig.get("value")
    if not isinstance(kid, str) or not kid or not isinstance(val, str) or not val:
        return (
            ReceiptVerification.INVALID,
            _finding(
                "RECEIPT_SIGNATURE_MALFORMED", "TERMINAL", "signature kid/value missing"
            ),
        )

    if key_resolver is None:
        return (
            ReceiptVerification.UNVERIFIED,
            _finding(
                "RECEIPT_TRUST_ANCHOR_UNCONFIGURED",
                "WARNING",
                f"signed receipt (kid={kid}) but no receipt key manifest configured",
            ),
        )

    try:
        public_key = await key_resolver.get_key(kid)
    except Exception as exc:
        return (
            ReceiptVerification.UNVERIFIED,
            _finding(
                "RECEIPT_KEY_MANIFEST_UNAVAILABLE",
                "WARNING",
                f"could not resolve kid={kid}: {type(exc).__name__}",
            ),
        )
    if public_key is None:
        return (
            ReceiptVerification.INVALID,
            _finding("RECEIPT_UNKNOWN_KID", "TERMINAL", f"kid={kid} not in manifest"),
        )

    try:
        sig_bytes = base64.urlsafe_b64decode(val + "=" * (-len(val) % 4))
    except (binascii.Error, ValueError):
        return (
            ReceiptVerification.INVALID,
            _finding(
                "RECEIPT_SIGNATURE_MALFORMED", "TERMINAL", "signature is not base64url"
            ),
        )
    if len(sig_bytes) != _ED25519_SIGNATURE_BYTES:
        return (
            ReceiptVerification.INVALID,
            _finding(
                "RECEIPT_SIGNATURE_MALFORMED",
                "TERMINAL",
                "Ed25519 signature must be 64 bytes",
            ),
        )

    signed_body = {k: v for k, v in body.items() if k != "signature"}
    try:
        msg = RECEIPT_SIGNATURE_DOMAIN_TAG + jcs_canonicalize_plan(signed_body)
        public_key.verify(sig_bytes, msg)
    except InvalidSignature:
        return (
            ReceiptVerification.INVALID,
            _finding(
                "RECEIPT_SIGNATURE_INVALID",
                "TERMINAL",
                f"signature invalid (kid={kid})",
            ),
        )
    except Exception as exc:
        return (
            ReceiptVerification.INVALID,
            _finding(
                "RECEIPT_SIGNATURE_MALFORMED",
                "TERMINAL",
                f"canonicalization failed: {type(exc).__name__}",
            ),
        )

    if signed_body.get("envelope_digest") != envelope_digest:
        return (
            ReceiptVerification.INVALID,
            _finding(
                "RECEIPT_ENVELOPE_MISMATCH",
                "TERMINAL",
                "receipt bound to different envelope_digest",
            ),
        )

    return ReceiptVerification.VERIFIED, None


class Actuator02Adapter:
    """Concrete ExecutionActuator for actuator_02 (OpenShell Supervisor)."""

    def __init__(
        self,
        *,
        endpoint: str,
        signer: RawMessageSigner,
        http_client: httpx.AsyncClient | None = None,
        credential_broker: CredentialBrokerAdapter | None = None,
        receipt_key_resolver: Ed25519KeyResolver | None = None,
        require_signed_receipts: bool = False,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme not in ("https", "http"):
            raise ValueError(
                f"[actuator_02] Unsupported endpoint scheme: {parsed.scheme!r}"
            )
        if require_signed_receipts and receipt_key_resolver is None:
            raise ValueError(
                "[actuator_02] require_signed_receipts requires a receipt_key_resolver"
            )
        self._endpoint = endpoint.rstrip("/")
        self._signer = signer
        self._http_client = http_client
        self._credential_broker = credential_broker
        self._receipt_key_resolver = receipt_key_resolver
        self._require_signed_receipts = require_signed_receipts

    @classmethod
    def from_env(
        cls,
        signer: RawMessageSigner | None = None,
        credential_broker: CredentialBrokerAdapter | None = None,
    ) -> Actuator02Adapter:
        """Construct Actuator02Adapter from environment variables."""
        if signer is None:
            from src.gateway.governance.kms_signer import get_governance_signer

            signer = get_governance_signer()

        endpoint = os.environ.get(_ENV_ENDPOINT, "")
        cert_path = os.environ.get(_ENV_CERT_PATH, "")
        key_path = os.environ.get(_ENV_KEY_PATH, "")
        ca_path = os.environ.get(_ENV_CA_PATH, "")

        missing = [
            name
            for name, val in (
                (_ENV_ENDPOINT, endpoint),
                (_ENV_CERT_PATH, cert_path),
                (_ENV_KEY_PATH, key_path),
                (_ENV_CA_PATH, ca_path),
            )
            if not val
        ]
        if missing:
            raise RuntimeError(
                f"[actuator_02] Missing required environment variables: {', '.join(missing)}"
            )

        import ssl

        ssl_ctx = ssl.create_default_context(cafile=ca_path)
        ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        http_client = httpx.AsyncClient(verify=ssl_ctx, timeout=10.0)

        manifest_url = os.environ.get(_ENV_RECEIPT_KEY_MANIFEST_URL, "").strip()
        require_signed = os.environ.get(
            _ENV_REQUIRE_SIGNED_RECEIPTS, ""
        ).strip().lower() in ("1", "true", "yes")
        resolver: Ed25519KeyResolver | None = (
            Ed25519KeyManifestClient(manifest_url) if manifest_url else None
        )

        return cls(
            endpoint=endpoint,
            signer=signer,
            http_client=http_client,
            credential_broker=credential_broker,
            receipt_key_resolver=resolver,
            require_signed_receipts=require_signed,
        )

    @property
    def actuator_id(self) -> str:
        return ACTUATOR_02_ID

    def get_capabilities(self) -> set[ActuatorCapability]:
        if self._receipt_key_resolver is not None:
            return set(_CAPABILITIES)
        return _CAPABILITIES - {ActuatorCapability.SIGNED_RECEIPTS}

    async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
        """Submit ExecutionClearance + PreCredentials assertion to OpenShell Supervisor."""
        now_utc = datetime.now(tz=timezone.utc).isoformat()

        if clearance.decision != "ALLOW":
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    _finding(
                        "CLEARANCE_NOT_ALLOWED",
                        "TERMINAL",
                        f"decision must be ALLOW, got {clearance.decision!r}",
                    )
                ],
                retryable=False,
                timestamp_utc=now_utc,
                outcome=ActuationOutcome.REJECTED,
            )

        if clearance.executor_id not in (
            ACTUATOR_02_ID,
            "a02",
            "openshell",
            "actuator_01",
        ):
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    _finding(
                        "EXECUTOR_ID_MISMATCH",
                        "TERMINAL",
                        f"executor_id={clearance.executor_id!r} not routed to {ACTUATOR_02_ID}",
                    )
                ],
                retryable=False,
                timestamp_utc=now_utc,
                outcome=ActuationOutcome.REJECTED,
            )

        # cage-seal/1: the seal is mandatory and must be partner-verifiable.
        seal = clearance.routing_seal
        if not isinstance(seal, str) or not _COMPACT_JWS.fullmatch(seal):
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    _finding(
                        "ROUTING_SEAL_MISSING" if not seal else "ROUTING_SEAL_NOT_JWS",
                        "TERMINAL",
                        f"{SEAL_PROFILE} requires a JWS routing seal on the clearance",
                    )
                ],
                retryable=False,
                timestamp_utc=now_utc,
                outcome=ActuationOutcome.REJECTED,
            )

        # Canonicalize envelope per RFC 8785 JCS and enforce size ceiling
        envelope_dict = clearance.to_dict()
        canonical_bytes = jcs_canonicalize_plan(envelope_dict)
        if len(canonical_bytes) > MAX_ENVELOPE_BYTES:
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    _finding(
                        "ENVELOPE_TOO_LARGE",
                        "TERMINAL",
                        f"envelope size {len(canonical_bytes)} exceeds {MAX_ENVELOPE_BYTES}",
                    )
                ],
                retryable=False,
                timestamp_utc=now_utc,
                outcome=ActuationOutcome.REJECTED,
            )

        envelope_digest = hashlib.sha256(canonical_bytes).hexdigest()

        # PreCredentials credential brokerage (if broker configured)
        broker_headers: dict[str, str] = {}
        if self._credential_broker is not None:
            try:
                broker_headers = await self._credential_broker.fetch_credential(
                    agent_svid=clearance.operator_urn,
                    tool_name=clearance.action,
                    scope=clearance.consequence_ceiling,
                )
            except CredentialBrokerError as exc:
                return ActuationReceipt(
                    accepted=False,
                    receipt_id=None,
                    session_uuid=None,
                    raw_receipt=None,
                    findings=[
                        _finding(
                            "CREDENTIAL_BROKER_FAILED",
                            "TERMINAL",
                            f"{type(exc).__name__}: {exc}",
                        )
                    ],
                    retryable=False,
                    envelope_digest=envelope_digest,
                    timestamp_utc=now_utc,
                    outcome=ActuationOutcome.REJECTED,
                )

        # Sign assertion with domain separation tag
        try:
            sig_bytes = self._signer.sign_raw(ASSERTION_DOMAIN_TAG + canonical_bytes)
            assertion_b64 = base64.urlsafe_b64encode(sig_bytes).decode("ascii")
        except Exception as exc:
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    _finding(
                        "ASSERTION_SIGN_FAILED",
                        "TERMINAL",
                        f"{type(exc).__name__}: {exc}",
                    )
                ],
                retryable=False,
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
                outcome=ActuationOutcome.REJECTED,
            )

        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "X-CAGE-Envelope-Digest": envelope_digest,
            "X-CAGE-OpenShell-Assertion": assertion_b64,
            "X-CAGE-Correlation-ID": clearance.correlation_id,
        }
        # Brokered credentials never carry CAGE protocol headers: drop any
        # X-CAGE-* name (case-insensitively) so none can shadow the seal.
        headers.update(
            {
                k: v
                for k, v in broker_headers.items()
                if not k.lower().startswith("x-cage-")
            }
        )
        headers[ROUTING_SEAL_HEADER] = seal
        headers[SEAL_PROFILE_HEADER] = SEAL_PROFILE

        if self._http_client is None:
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    _finding(
                        "HTTP_CLIENT_UNCONFIGURED",
                        "TERMINAL",
                        "no mTLS client configured",
                    )
                ],
                retryable=False,
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
                outcome=ActuationOutcome.REJECTED,
            )

        try:
            resp = await self._http_client.post(
                f"{self._endpoint}/v1/supervisor/actuate",
                content=canonical_bytes,
                headers=headers,
            )
        except _PRE_SEND_TRANSPORT_ERRORS as exc:
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    _finding(
                        "SUPERVISOR_CONNECT_FAILED",
                        "TRANSIENT",
                        f"{type(exc).__name__}: {exc}",
                    )
                ],
                retryable=True,
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
                outcome=ActuationOutcome.REJECTED,
            )
        except Exception as exc:
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    _finding(
                        "SUPERVISOR_TRANSPORT_INDETERMINATE",
                        "TERMINAL",
                        f"{type(exc).__name__}: {exc}",
                    )
                ],
                retryable=False,
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
                outcome=ActuationOutcome.UNKNOWN,
            )

        if resp.status_code in _DEFINITIVE_REFUSAL_STATUSES:
            retryable = resp.status_code in (429, 503)
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    _finding(
                        f"SUPERVISOR_HTTP_{resp.status_code}",
                        "TRANSIENT" if retryable else "TERMINAL",
                        f"Supervisor refused request with HTTP {resp.status_code}",
                    )
                ],
                retryable=retryable,
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
                outcome=ActuationOutcome.REJECTED,
            )

        if resp.status_code != 200:
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    _finding(
                        f"SUPERVISOR_HTTP_{resp.status_code}",
                        "TERMINAL",
                        f"Indeterminate HTTP {resp.status_code} from Supervisor",
                    )
                ],
                retryable=False,
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
                outcome=ActuationOutcome.UNKNOWN,
            )

        try:
            body = resp.json()
        except Exception as exc:
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    _finding(
                        "RECEIPT_PARSE_ERROR",
                        "TERMINAL",
                        f"{type(exc).__name__}: {exc}",
                    )
                ],
                retryable=False,
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
                outcome=ActuationOutcome.UNKNOWN,
            )

        verification, v_finding = await verify_supervisor_receipt(
            body,
            envelope_digest=envelope_digest,
            key_resolver=self._receipt_key_resolver,
        )
        findings: list[dict[str, str]] = [v_finding] if v_finding else []

        if verification is ReceiptVerification.INVALID:
            return ActuationReceipt(
                accepted=False,
                receipt_id=body.get("receipt_id") if isinstance(body, dict) else None,
                session_uuid=body.get("session_uuid")
                if isinstance(body, dict)
                else None,
                raw_receipt=body if isinstance(body, dict) else None,
                findings=findings,
                retryable=False,
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
                outcome=ActuationOutcome.UNKNOWN,
                verification=ReceiptVerification.INVALID,
            )

        if (
            self._require_signed_receipts
            and verification is not ReceiptVerification.VERIFIED
        ):
            findings.append(
                _finding(
                    "SIGNED_RECEIPT_REQUIRED",
                    "TERMINAL",
                    "strict receipt verification enabled but receipt was UNVERIFIED",
                )
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=body.get("receipt_id") if isinstance(body, dict) else None,
                session_uuid=body.get("session_uuid")
                if isinstance(body, dict)
                else None,
                raw_receipt=body if isinstance(body, dict) else None,
                findings=findings,
                retryable=False,
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
                outcome=ActuationOutcome.UNKNOWN,
                verification=verification,
            )

        receipt_id = body.get("receipt_id") if isinstance(body, dict) else None
        session_uuid = body.get("session_uuid") if isinstance(body, dict) else None
        status_str = (
            str(body.get("status", "")).upper() if isinstance(body, dict) else ""
        )
        if status_str not in ("ACCEPTED", "OK", "EXECUTED") or not receipt_id:
            findings.append(
                _finding(
                    "SUPERVISOR_STATUS_NOT_ACCEPTED",
                    "TERMINAL",
                    f"status={status_str!r}, receipt_id={receipt_id!r}",
                )
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=receipt_id,
                session_uuid=session_uuid,
                raw_receipt=body if isinstance(body, dict) else None,
                findings=findings,
                retryable=False,
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
                outcome=ActuationOutcome.REJECTED
                if status_str in ("REJECTED", "DENIED")
                else ActuationOutcome.UNKNOWN,
                verification=verification,
            )

        return ActuationReceipt(
            accepted=True,
            receipt_id=str(receipt_id),
            session_uuid=str(session_uuid) if session_uuid else clearance.nonce,
            raw_receipt=body,
            findings=findings,
            retryable=False,
            envelope_digest=envelope_digest,
            timestamp_utc=now_utc,
            outcome=ActuationOutcome.ACCEPTED,
            verification=verification,
        )

    async def health_check(self) -> bool:
        if self._http_client is None:
            return False
        try:
            resp = await self._http_client.get(f"{self._endpoint}/health")
            return resp.status_code == 200
        except Exception:
            return False
