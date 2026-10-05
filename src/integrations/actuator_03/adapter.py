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

"""Concrete QuarantineActuator and ExecutionActuator implementation for actuator_03.

Signs QuarantineDirectives with CAGE_QUARANTINE_ASSERTION_V1:, submits over
mTLS, and verifies detached Ed25519 receipts against a kid-resolved key manifest.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import time
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
from src.gateway.governance.seams.quarantine import (
    QuarantineDirective,
    QuarantineReceipt,
    QuarantineTriggerReason,
)
from src.integrations.actuator_03.constants import (
    ACTUATOR_03_ID,
    QUARANTINE_ASSERTION_DOMAIN_TAG,
    QUARANTINE_RECEIPT_DOMAIN_TAG,
)
from src.integrations.trust.key_manifest import (
    Ed25519KeyManifestClient,
    Ed25519KeyResolver,
)

_ENV_ENDPOINT = "ACTUATOR_03_ENDPOINT"
_ENV_CERT_PATH = "ACTUATOR_03_CERT_PATH"
_ENV_KEY_PATH = "ACTUATOR_03_KEY_PATH"
_ENV_CA_PATH = "ACTUATOR_03_CA_PATH"
_ENV_RECEIPT_KEY_MANIFEST_URL = "ACTUATOR_03_RECEIPT_KEY_MANIFEST_URL"
_ENV_REQUIRE_SIGNED_RECEIPTS = "ACTUATOR_03_REQUIRE_SIGNED_RECEIPTS"

_ED25519_SIGNATURE_BYTES = 64
_DEFINITIVE_REFUSAL_STATUSES: frozenset[int] = frozenset(
    {400, 401, 403, 409, 421, 422, 429, 503}
)
_PRE_SEND_TRANSPORT_ERRORS: tuple[type[httpx.HTTPError], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
)


def _finding(code: str, severity: str, detail: str) -> dict[str, str]:
    return {"code": code, "severity": severity, "detail": detail}


async def verify_quarantine_receipt_sig(
    body: dict[str, Any] | None,
    *,
    envelope_digest: str,
    key_resolver: Ed25519KeyResolver | None,
) -> tuple[ReceiptVerification, dict[str, str] | None]:
    """Verify detached Ed25519 signature on a quarantine receipt."""
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
            _finding("RECEIPT_SIGNATURE_MALFORMED", "TERMINAL", "kid/value missing"),
        )

    if key_resolver is None:
        return (
            ReceiptVerification.UNVERIFIED,
            _finding(
                "RECEIPT_TRUST_ANCHOR_UNCONFIGURED",
                "WARNING",
                f"no manifest for kid={kid}",
            ),
        )

    try:
        pub = await key_resolver.get_key(kid)
    except Exception as exc:
        return (
            ReceiptVerification.UNVERIFIED,
            _finding(
                "RECEIPT_KEY_MANIFEST_UNAVAILABLE", "WARNING", f"{type(exc).__name__}"
            ),
        )
    if pub is None:
        return (
            ReceiptVerification.INVALID,
            _finding("RECEIPT_UNKNOWN_KID", "TERMINAL", f"kid={kid} not in manifest"),
        )

    try:
        sig_bytes = base64.urlsafe_b64decode(val + "=" * (-len(val) % 4))
    except (binascii.Error, ValueError):
        return (
            ReceiptVerification.INVALID,
            _finding("RECEIPT_SIGNATURE_MALFORMED", "TERMINAL", "invalid base64url"),
        )
    if len(sig_bytes) != _ED25519_SIGNATURE_BYTES:
        return (
            ReceiptVerification.INVALID,
            _finding(
                "RECEIPT_SIGNATURE_MALFORMED", "TERMINAL", "signature must be 64 bytes"
            ),
        )

    signed_body = {k: v for k, v in body.items() if k != "signature"}
    try:
        msg = QUARANTINE_RECEIPT_DOMAIN_TAG + jcs_canonicalize_plan(signed_body)
        pub.verify(sig_bytes, msg)
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
                "RECEIPT_SIGNATURE_MALFORMED", "TERMINAL", f"{type(exc).__name__}"
            ),
        )

    if signed_body.get("envelope_digest") != envelope_digest:
        return (
            ReceiptVerification.INVALID,
            _finding(
                "RECEIPT_ENVELOPE_MISMATCH", "TERMINAL", "envelope_digest mismatch"
            ),
        )

    return ReceiptVerification.VERIFIED, None


class Actuator03Adapter:
    """Out-of-band hardware quarantine adapter for actuator_03."""

    def __init__(
        self,
        *,
        endpoint: str,
        signer: RawMessageSigner,
        http_client: httpx.AsyncClient | None = None,
        receipt_key_resolver: Ed25519KeyResolver | None = None,
        require_signed_receipts: bool = False,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme not in ("https", "http"):
            raise ValueError(
                f"[actuator_03] Unsupported endpoint scheme: {parsed.scheme!r}"
            )
        if require_signed_receipts and receipt_key_resolver is None:
            raise ValueError(
                "[actuator_03] require_signed_receipts requires a receipt_key_resolver"
            )
        self._endpoint = endpoint.rstrip("/")
        self._signer = signer
        self._http_client = http_client
        self._receipt_key_resolver = receipt_key_resolver
        self._require_signed_receipts = require_signed_receipts

    @classmethod
    def from_env(cls, signer: RawMessageSigner | None = None) -> Actuator03Adapter:
        """Construct Actuator03Adapter from environment variables."""
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
                f"[actuator_03] Missing required environment variables: {', '.join(missing)}"
            )

        import ssl

        ssl_ctx = ssl.create_default_context(cafile=ca_path)
        ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        http_client = httpx.AsyncClient(verify=ssl_ctx, timeout=5.0)

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
            receipt_key_resolver=resolver,
            require_signed_receipts=require_signed,
        )

    @property
    def actuator_id(self) -> str:
        return ACTUATOR_03_ID

    def get_capabilities(self) -> set[ActuatorCapability]:
        caps = {
            ActuatorCapability.MTLS_REQUIRED,
            ActuatorCapability.REPLAY_PROTECTED,
            ActuatorCapability.DIGEST_ONLY_PAYLOAD,
        }
        if self._receipt_key_resolver is not None:
            caps.add(ActuatorCapability.SIGNED_RECEIPTS)
        return caps

    async def quarantine_workload(
        self, directive: QuarantineDirective
    ) -> QuarantineReceipt:
        """Issue signed out-of-band flow isolation directive over mTLS."""
        t0 = time.perf_counter()
        now_utc = datetime.now(tz=timezone.utc).isoformat()
        canonical_bytes = jcs_canonicalize_plan(directive.to_dict())
        envelope_digest = hashlib.sha256(canonical_bytes).hexdigest()

        try:
            sig_bytes = self._signer.sign_raw(
                QUARANTINE_ASSERTION_DOMAIN_TAG + canonical_bytes
            )
            assertion_b64 = base64.urlsafe_b64encode(sig_bytes).decode("ascii")
        except Exception as exc:
            return QuarantineReceipt(
                quarantined=False,
                enforcement_plane="IN_SILICON_DPU",
                rule_id=None,
                latency_us=None,
                outcome=ActuationOutcome.REJECTED,
                verification=ReceiptVerification.UNVERIFIED,
                findings=[
                    _finding(
                        "ASSERTION_SIGN_FAILED",
                        "TERMINAL",
                        f"{type(exc).__name__}: {exc}",
                    )
                ],
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        if self._http_client is None:
            return QuarantineReceipt(
                quarantined=False,
                enforcement_plane="IN_SILICON_DPU",
                rule_id=None,
                latency_us=None,
                outcome=ActuationOutcome.REJECTED,
                verification=ReceiptVerification.UNVERIFIED,
                findings=[
                    _finding(
                        "HTTP_CLIENT_UNCONFIGURED",
                        "TERMINAL",
                        "no mTLS client configured",
                    )
                ],
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        headers = {
            "Content-Type": "application/json",
            "X-CAGE-Envelope-Digest": envelope_digest,
            "X-CAGE-Quarantine-Assertion": assertion_b64,
            "X-CAGE-Correlation-ID": directive.correlation_id,
        }

        try:
            resp = await self._http_client.post(
                f"{self._endpoint}/v1/dpu/quarantine",
                content=canonical_bytes,
                headers=headers,
            )
        except _PRE_SEND_TRANSPORT_ERRORS as exc:
            return QuarantineReceipt(
                quarantined=False,
                enforcement_plane="IN_SILICON_DPU",
                rule_id=None,
                latency_us=(time.perf_counter() - t0) * 1_000_000.0,
                outcome=ActuationOutcome.REJECTED,
                verification=ReceiptVerification.UNVERIFIED,
                findings=[
                    _finding(
                        "DPU_CONNECT_FAILED",
                        "TRANSIENT",
                        f"{type(exc).__name__}: {exc}",
                    )
                ],
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )
        except Exception as exc:
            return QuarantineReceipt(
                quarantined=False,
                enforcement_plane="IN_SILICON_DPU",
                rule_id=None,
                latency_us=(time.perf_counter() - t0) * 1_000_000.0,
                outcome=ActuationOutcome.UNKNOWN,
                verification=ReceiptVerification.UNVERIFIED,
                findings=[
                    _finding(
                        "DPU_TRANSPORT_INDETERMINATE",
                        "TERMINAL",
                        f"{type(exc).__name__}: {exc}",
                    )
                ],
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        latency_us = (time.perf_counter() - t0) * 1_000_000.0

        if resp.status_code in _DEFINITIVE_REFUSAL_STATUSES:
            return QuarantineReceipt(
                quarantined=False,
                enforcement_plane="IN_SILICON_DPU",
                rule_id=None,
                latency_us=latency_us,
                outcome=ActuationOutcome.REJECTED,
                verification=ReceiptVerification.UNVERIFIED,
                findings=[
                    _finding(
                        f"DPU_HTTP_{resp.status_code}",
                        "TERMINAL",
                        f"HTTP {resp.status_code}",
                    )
                ],
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        if resp.status_code != 200:
            return QuarantineReceipt(
                quarantined=False,
                enforcement_plane="IN_SILICON_DPU",
                rule_id=None,
                latency_us=latency_us,
                outcome=ActuationOutcome.UNKNOWN,
                verification=ReceiptVerification.UNVERIFIED,
                findings=[
                    _finding(
                        f"DPU_HTTP_{resp.status_code}",
                        "TERMINAL",
                        f"HTTP {resp.status_code}",
                    )
                ],
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        try:
            body = resp.json()
        except Exception as exc:
            return QuarantineReceipt(
                quarantined=False,
                enforcement_plane="IN_SILICON_DPU",
                rule_id=None,
                latency_us=latency_us,
                outcome=ActuationOutcome.UNKNOWN,
                verification=ReceiptVerification.UNVERIFIED,
                findings=[
                    _finding(
                        "RECEIPT_PARSE_ERROR",
                        "TERMINAL",
                        f"{type(exc).__name__}: {exc}",
                    )
                ],
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        verification, v_finding = await verify_quarantine_receipt_sig(
            body,
            envelope_digest=envelope_digest,
            key_resolver=self._receipt_key_resolver,
        )
        findings: list[dict[str, Any]] = [v_finding] if v_finding else []

        if verification is ReceiptVerification.INVALID:
            return QuarantineReceipt(
                quarantined=False,
                enforcement_plane="IN_SILICON_DPU",
                rule_id=body.get("rule_id") if isinstance(body, dict) else None,
                latency_us=latency_us,
                outcome=ActuationOutcome.UNKNOWN,
                verification=ReceiptVerification.INVALID,
                findings=findings,
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        if (
            self._require_signed_receipts
            and verification is not ReceiptVerification.VERIFIED
        ):
            findings.append(
                _finding("SIGNED_RECEIPT_REQUIRED", "TERMINAL", "receipt UNVERIFIED")
            )
            return QuarantineReceipt(
                quarantined=False,
                enforcement_plane="IN_SILICON_DPU",
                rule_id=body.get("rule_id") if isinstance(body, dict) else None,
                latency_us=latency_us,
                outcome=ActuationOutcome.UNKNOWN,
                verification=verification,
                findings=findings,
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        rule_id = body.get("rule_id") if isinstance(body, dict) else None
        quarantined = bool(body.get("quarantined")) if isinstance(body, dict) else False
        if not quarantined or not rule_id:
            findings.append(
                _finding(
                    "DPU_QUARANTINE_NOT_CONFIRMED",
                    "TERMINAL",
                    f"quarantined={quarantined}",
                )
            )
            return QuarantineReceipt(
                quarantined=False,
                enforcement_plane="IN_SILICON_DPU",
                rule_id=rule_id,
                latency_us=latency_us,
                outcome=ActuationOutcome.REJECTED,
                verification=verification,
                findings=findings,
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        return QuarantineReceipt(
            quarantined=True,
            enforcement_plane="IN_SILICON_DPU",
            rule_id=str(rule_id),
            latency_us=latency_us,
            outcome=ActuationOutcome.ACCEPTED,
            verification=verification,
            findings=findings,
            envelope_digest=envelope_digest,
            timestamp_utc=now_utc,
        )

    async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
        """ExecutionActuator bridge converting an ExecutionClearance into a QuarantineDirective."""
        directive = QuarantineDirective(
            thread_id=clearance.thread_id,
            agent_svid=clearance.operator_urn,
            sandbox_id=str(clearance.params.get("sandbox_id", clearance.target)),
            reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
            violation_codes=tuple(
                clearance.params.get("violation_codes", ("CBF_BREACH",))
            ),
            issued_at=clearance.issued_at,
            correlation_id=clearance.correlation_id,
            governance_decision_digest=clearance.governance_decision_digest,
            nonce=clearance.nonce,
            ttl_seconds=clearance.ttl_seconds,
        )
        q_receipt = await self.quarantine_workload(directive)
        return ActuationReceipt(
            accepted=q_receipt.quarantined,
            receipt_id=q_receipt.rule_id,
            session_uuid=clearance.nonce if q_receipt.quarantined else None,
            raw_receipt={
                "enforcement_plane": q_receipt.enforcement_plane,
                "rule_id": q_receipt.rule_id,
            }
            if q_receipt.quarantined
            else None,
            findings=q_receipt.findings,
            retryable=False,
            envelope_digest=q_receipt.envelope_digest,
            timestamp_utc=q_receipt.timestamp_utc,
            outcome=q_receipt.outcome,
            verification=q_receipt.verification,
        )

    async def health_check(self) -> bool:
        if self._http_client is None:
            return False
        try:
            resp = await self._http_client.get(f"{self._endpoint}/health")
            return resp.status_code == 200
        except Exception:
            return False
