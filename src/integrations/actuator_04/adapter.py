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

"""Actuator04Adapter implementing QuarantineActuator, ExecutionActuator, and Quorum Release."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import time
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature

from src.gateway.governance.env_posture import is_enforcing, resolve_posture
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.raw_signer_protocol import RawMessageSigner
from src.gateway.governance.routing_seal import verify_and_consume_seal
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ActuationReceipt,
    ActuatorCapability,
    ExecutionActuator,
    ExecutionClearance,
    ReceiptVerification,
)
from src.gateway.governance.seams.quarantine import (
    QuarantineActuator,
    QuarantineDirective,
    QuarantineReceipt,
    QuarantineReleaseDirective,
    QuarantineReleaseReceipt,
)
from src.integrations.actuator_04.client import Actuator04Transport
from src.integrations.actuator_04.constants import (
    ACTUATOR_04_ID,
    ED25519_SIGNATURE_BYTES,
    ENFORCEMENT_PLANE_HOST_OS_KERNEL,
    ENV_RECEIPT_KEY_MANIFEST_URL,
    ENV_REQUIRE_SIGNED_RECEIPTS,
    HEADER_CORRELATION_ID,
    HEADER_ENVELOPE_DIGEST,
    HEADER_QUARANTINE_ASSERTION,
    HEADER_QUARANTINE_RELEASE,
    HEADER_ROUTING_SEAL,
    HEADER_SIGNER_KID,
    QUARANTINE_ASSERTION_DOMAIN_TAG,
    QUARANTINE_RECEIPT_DOMAIN_TAG,
    QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG,
    QUARANTINE_RELEASE_RECEIPT_DOMAIN_TAG,
)
from src.integrations.trust.key_manifest import (
    Ed25519KeyManifestClient,
    Ed25519KeyResolver,
)


def _finding(code: str, severity: str, detail: str) -> dict[str, str]:
    return {"code": code, "severity": severity, "detail": detail}


async def verify_substrate_receipt_signature(
    body: dict[str, Any] | None,
    *,
    domain_tag: bytes,
    expected_envelope_digest: str,
    key_resolver: Ed25519KeyResolver | None,
) -> tuple[ReceiptVerification, dict[str, str] | None]:
    """Verify Ed25519 detached signature on a substrate response receipt."""
    if not isinstance(body, dict):
        return (
            ReceiptVerification.INVALID,
            _finding(
                "RECEIPT_MALFORMED", "TERMINAL", "Receipt body is not a JSON object"
            ),
        )

    sig_raw = body.get("signature")
    kid = body.get("kid")

    if isinstance(sig_raw, dict):
        val = sig_raw.get("value")
        kid = sig_raw.get("kid", kid)
    elif isinstance(sig_raw, str):
        val = sig_raw
    else:
        val = None

    if not kid or not val:
        return (
            ReceiptVerification.UNVERIFIED,
            _finding(
                "RECEIPT_SIGNATURE_MISSING",
                "WARNING",
                "Missing kid or signature value on unsigned receipt",
            ),
        )

    if key_resolver is None:
        return (
            ReceiptVerification.UNVERIFIED,
            _finding(
                "RECEIPT_TRUST_ANCHOR_UNCONFIGURED",
                "WARNING",
                f"No key manifest client configured for kid={kid}",
            ),
        )

    try:
        pub = await key_resolver.get_key(kid)
    except Exception as exc:
        return (
            ReceiptVerification.UNVERIFIED,
            _finding("KEY_MANIFEST_UNAVAILABLE", "WARNING", str(exc)),
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
            _finding(
                "RECEIPT_SIGNATURE_MALFORMED", "TERMINAL", "Invalid base64url signature"
            ),
        )

    if len(sig_bytes) != ED25519_SIGNATURE_BYTES:
        return (
            ReceiptVerification.INVALID,
            _finding(
                "RECEIPT_SIGNATURE_LENGTH", "TERMINAL", "Signature must be 64 bytes"
            ),
        )

    # Verification preimage: DOMAIN_TAG + JCS(body_without_signature)
    signed_body = {
        k: v for k, v in body.items() if k not in ("signature", "raw_response")
    }
    canonical_body = jcs_canonicalize_plan(signed_body)
    preimage = domain_tag + canonical_body

    try:
        pub.verify(sig_bytes, preimage)
    except InvalidSignature:
        return (
            ReceiptVerification.INVALID,
            _finding(
                "RECEIPT_SIGNATURE_INVALID",
                "TERMINAL",
                f"Ed25519 verify failed (kid={kid})",
            ),
        )
    except Exception as exc:
        return (
            ReceiptVerification.INVALID,
            _finding("RECEIPT_VERIFY_EXCEPTION", "TERMINAL", str(exc)),
        )

    # Assert envelope digest binding
    resp_envelope = signed_body.get("envelope_digest")
    if resp_envelope != expected_envelope_digest:
        return (
            ReceiptVerification.INVALID,
            _finding(
                "RECEIPT_ENVELOPE_MISMATCH",
                "TERMINAL",
                f"Receipt envelope {resp_envelope!r} != expected {expected_envelope_digest!r}",
            ),
        )

    return ReceiptVerification.VERIFIED, None


class Actuator04Adapter(QuarantineActuator, ExecutionActuator):
    """Adapter bridging CAGE Layer 1 to Host OS Kernel substrate across all seams."""

    def __init__(
        self,
        *,
        transport: Actuator04Transport,
        signer: RawMessageSigner,
        receipt_key_resolver: Ed25519KeyResolver | None = None,
        require_signed_receipts: bool = True,
    ) -> None:
        self._transport = transport
        self._signer = signer
        self._receipt_key_resolver = receipt_key_resolver
        self._require_signed_receipts = require_signed_receipts

    @classmethod
    def from_env(cls, signer: RawMessageSigner | None = None) -> Actuator04Adapter:
        """Construct Actuator04Adapter from environment configuration."""
        if signer is None:
            from src.gateway.governance.kms_signer import get_governance_signer

            signer = get_governance_signer()

        transport = Actuator04Transport.from_env()

        manifest_url = os.environ.get(ENV_RECEIPT_KEY_MANIFEST_URL, "").strip()
        resolver: Ed25519KeyResolver | None = (
            Ed25519KeyManifestClient(manifest_url) if manifest_url else None
        )

        enforcing = is_enforcing(resolve_posture())
        req_signed_env = os.environ.get(ENV_REQUIRE_SIGNED_RECEIPTS, "").strip().lower()
        if req_signed_env in ("1", "true", "yes"):
            require_signed = True
        elif req_signed_env in ("0", "false", "no"):
            require_signed = False
        else:
            require_signed = enforcing or resolver is not None

        return cls(
            transport=transport,
            signer=signer,
            receipt_key_resolver=resolver,
            require_signed_receipts=require_signed,
        )

    @property
    def actuator_id(self) -> str:
        return ACTUATOR_04_ID

    def get_capabilities(self) -> set[ActuatorCapability]:
        caps = {
            ActuatorCapability.MTLS_REQUIRED,
            ActuatorCapability.REPLAY_PROTECTED,
            ActuatorCapability.DIGEST_ONLY_PAYLOAD,
        }
        if self._receipt_key_resolver is not None:
            caps.add(ActuatorCapability.SIGNED_RECEIPTS)
        return caps

    async def health_check(self) -> bool:
        """Probe substrate health across configured endpoints."""
        try:
            endpoints = self._transport.resolve_target_endpoints()
            responses = await self._transport.get_from_endpoints(
                "/v1/cage/attest", endpoints=endpoints
            )
            return all(r.status_code == 200 for r in responses)
        except Exception:
            return False

    async def quarantine_workload(
        self, directive: QuarantineDirective
    ) -> QuarantineReceipt:
        """Issue signed host-kernel quarantine directive with fail-closed fan-out."""
        t0 = time.perf_counter()
        now_utc = datetime.now(tz=timezone.utc).isoformat()
        canonical_bytes = jcs_canonicalize_plan(directive.to_dict())
        envelope_digest = hashlib.sha256(canonical_bytes).hexdigest()

        # Sign assertion: CAGE_QUARANTINE_ASSERTION_V1: + JCS(directive)
        try:
            sig_bytes = await self._signer.sign_raw_async(
                QUARANTINE_ASSERTION_DOMAIN_TAG + canonical_bytes
            )
            assertion_b64 = (
                base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")
            )
        except Exception as exc:
            return QuarantineReceipt(
                quarantined=False,
                enforcement_plane=ENFORCEMENT_PLANE_HOST_OS_KERNEL,
                rule_id=None,
                latency_us=None,
                outcome=ActuationOutcome.REJECTED,
                verification=ReceiptVerification.UNVERIFIED,
                findings=[_finding("ASSERTION_SIGN_FAILED", "TERMINAL", str(exc))],
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        headers = {
            "Content-Type": "application/json",
            HEADER_ENVELOPE_DIGEST: envelope_digest,
            HEADER_QUARANTINE_ASSERTION: assertion_b64,
            HEADER_CORRELATION_ID: directive.correlation_id,
            HEADER_SIGNER_KID: getattr(self._signer, "key_id", ""),
        }

        try:
            endpoints = self._transport.resolve_target_endpoints(
                sandbox_id=directive.sandbox_id
            )
            responses = await self._transport.post_to_endpoints(
                "/v1/cage/quarantine",
                content=canonical_bytes,
                headers=headers,
                endpoints=endpoints,
            )
        except Exception as exc:
            return QuarantineReceipt(
                quarantined=False,
                enforcement_plane=ENFORCEMENT_PLANE_HOST_OS_KERNEL,
                rule_id=None,
                latency_us=(time.perf_counter() - t0) * 1_000_000.0,
                outcome=ActuationOutcome.UNKNOWN,
                verification=ReceiptVerification.UNVERIFIED,
                findings=[_finding("SUBSTRATE_POST_FAILED", "TRANSIENT", str(exc))],
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        # Fail closed: verify every target node returned a valid, verified receipt
        combined_findings: list[dict[str, Any]] = []
        overall_rule_id: str | None = None
        has_invalid = False
        all_verified = True

        for resp in responses:
            if resp.status_code != 200:
                return QuarantineReceipt(
                    quarantined=False,
                    enforcement_plane=ENFORCEMENT_PLANE_HOST_OS_KERNEL,
                    rule_id=None,
                    latency_us=(time.perf_counter() - t0) * 1_000_000.0,
                    outcome=ActuationOutcome.REJECTED,
                    verification=ReceiptVerification.UNVERIFIED,
                    findings=[
                        _finding(
                            "SUBSTRATE_ERROR_STATUS",
                            "TERMINAL",
                            f"HTTP {resp.status_code}",
                        )
                    ],
                    envelope_digest=envelope_digest,
                    timestamp_utc=now_utc,
                )

            body = resp.json()
            rule_id = body.get("rule_id", "host-kernel-quarantine")
            overall_rule_id = overall_rule_id or rule_id

            v_status, finding = await verify_substrate_receipt_signature(
                body,
                domain_tag=QUARANTINE_RECEIPT_DOMAIN_TAG,
                expected_envelope_digest=envelope_digest,
                key_resolver=self._receipt_key_resolver,
            )

            if finding:
                combined_findings.append(finding)

            if v_status is ReceiptVerification.INVALID:
                has_invalid = True
            elif v_status is not ReceiptVerification.VERIFIED:
                all_verified = False

        if (self._require_signed_receipts and not all_verified) or has_invalid:
            return QuarantineReceipt(
                quarantined=False,
                enforcement_plane=ENFORCEMENT_PLANE_HOST_OS_KERNEL,
                rule_id=overall_rule_id,
                latency_us=(time.perf_counter() - t0) * 1_000_000.0,
                outcome=ActuationOutcome.UNKNOWN,
                verification=ReceiptVerification.INVALID,
                findings=combined_findings,
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        verification_status = (
            ReceiptVerification.VERIFIED
            if all_verified and self._receipt_key_resolver is not None
            else ReceiptVerification.UNVERIFIED
        )

        return QuarantineReceipt(
            quarantined=True,
            enforcement_plane=ENFORCEMENT_PLANE_HOST_OS_KERNEL,
            rule_id=overall_rule_id,
            latency_us=(time.perf_counter() - t0) * 1_000_000.0,
            outcome=ActuationOutcome.ACCEPTED,
            verification=verification_status,
            findings=combined_findings,
            envelope_digest=envelope_digest,
            timestamp_utc=now_utc,
        )

    async def release_workload(
        self, directive: QuarantineReleaseDirective
    ) -> QuarantineReleaseReceipt:
        """Issue quorum-approved quarantine release and advance monotonic generation epoch."""
        now_utc = datetime.now(tz=timezone.utc).isoformat()
        canonical_bytes = jcs_canonicalize_plan(directive.to_dict())
        envelope_digest = hashlib.sha256(canonical_bytes).hexdigest()

        try:
            sig_bytes = await self._signer.sign_raw_async(
                QUARANTINE_RELEASE_ASSERTION_DOMAIN_TAG + canonical_bytes
            )
            assertion_b64 = (
                base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")
            )
        except Exception as exc:
            return QuarantineReleaseReceipt(
                released=False,
                enforcement_plane=ENFORCEMENT_PLANE_HOST_OS_KERNEL,
                epoch_before=directive.expected_min_epoch,
                epoch_after=directive.expected_min_epoch,
                outcome=ActuationOutcome.REJECTED,
                verification=ReceiptVerification.UNVERIFIED,
                findings=[_finding("RELEASE_SIGN_FAILED", "TERMINAL", str(exc))],
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        headers = {
            "Content-Type": "application/json",
            HEADER_ENVELOPE_DIGEST: envelope_digest,
            HEADER_QUARANTINE_RELEASE: assertion_b64,
            HEADER_SIGNER_KID: getattr(self._signer, "key_id", ""),
            HEADER_CORRELATION_ID: directive.correlation_id,
        }

        try:
            endpoints = self._transport.resolve_target_endpoints(
                sandbox_id=directive.sandbox_id
            )
            responses = await self._transport.post_to_endpoints(
                "/v1/cage/release",
                content=canonical_bytes,
                headers=headers,
                endpoints=endpoints,
            )
        except Exception as exc:
            return QuarantineReleaseReceipt(
                released=False,
                enforcement_plane=ENFORCEMENT_PLANE_HOST_OS_KERNEL,
                epoch_before=directive.expected_min_epoch,
                epoch_after=directive.expected_min_epoch,
                outcome=ActuationOutcome.UNKNOWN,
                verification=ReceiptVerification.UNVERIFIED,
                findings=[_finding("RELEASE_POST_FAILED", "TRANSIENT", str(exc))],
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        if not responses:
            return QuarantineReleaseReceipt(
                released=False,
                enforcement_plane=ENFORCEMENT_PLANE_HOST_OS_KERNEL,
                epoch_before=directive.expected_min_epoch,
                epoch_after=directive.expected_min_epoch,
                outcome=ActuationOutcome.UNKNOWN,
                verification=ReceiptVerification.UNVERIFIED,
                findings=[
                    _finding(
                        "NO_RESPONSES",
                        "TERMINAL",
                        "No response received from any host endpoint",
                    )
                ],
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        combined_findings: list[dict[str, Any]] = []
        has_invalid = False
        all_verified = True
        consensus_epoch_before: int | None = None
        consensus_epoch_after: int | None = None

        for resp in responses:
            if resp.status_code != 200:
                return QuarantineReleaseReceipt(
                    released=False,
                    enforcement_plane=ENFORCEMENT_PLANE_HOST_OS_KERNEL,
                    epoch_before=directive.expected_min_epoch,
                    epoch_after=directive.expected_min_epoch,
                    outcome=ActuationOutcome.REJECTED,
                    verification=ReceiptVerification.UNVERIFIED,
                    findings=[
                        _finding(
                            "SUBSTRATE_ERROR_STATUS",
                            "TERMINAL",
                            f"HTTP {resp.status_code}",
                        )
                    ],
                    envelope_digest=envelope_digest,
                    timestamp_utc=now_utc,
                )

            body = resp.json()
            epoch_before = int(body.get("epoch_before", directive.expected_min_epoch))
            epoch_after = int(body.get("epoch_after", epoch_before + 1))

            # Monotonic epoch advancement invariant per node
            if epoch_after <= epoch_before:
                return QuarantineReleaseReceipt(
                    released=False,
                    enforcement_plane=ENFORCEMENT_PLANE_HOST_OS_KERNEL,
                    epoch_before=epoch_before,
                    epoch_after=epoch_before,
                    outcome=ActuationOutcome.UNKNOWN,
                    verification=ReceiptVerification.UNVERIFIED,
                    findings=[
                        _finding(
                            "NON_MONOTONIC_EPOCH",
                            "TERMINAL",
                            f"epoch_after {epoch_after} <= {epoch_before}",
                        )
                    ],
                    envelope_digest=envelope_digest,
                    timestamp_utc=now_utc,
                )

            # Check multi-node consensus on epoch
            if consensus_epoch_before is None:
                consensus_epoch_before = epoch_before
            elif consensus_epoch_before != epoch_before:
                return QuarantineReleaseReceipt(
                    released=False,
                    enforcement_plane=ENFORCEMENT_PLANE_HOST_OS_KERNEL,
                    epoch_before=directive.expected_min_epoch,
                    epoch_after=directive.expected_min_epoch,
                    outcome=ActuationOutcome.UNKNOWN,
                    verification=ReceiptVerification.UNVERIFIED,
                    findings=[
                        _finding(
                            "DIVERGENT_NODE_EPOCH",
                            "TERMINAL",
                            f"epoch_before mismatch: {consensus_epoch_before} vs {epoch_before}",
                        )
                    ],
                    envelope_digest=envelope_digest,
                    timestamp_utc=now_utc,
                )

            if consensus_epoch_after is None:
                consensus_epoch_after = epoch_after
            elif consensus_epoch_after != epoch_after:
                return QuarantineReleaseReceipt(
                    released=False,
                    enforcement_plane=ENFORCEMENT_PLANE_HOST_OS_KERNEL,
                    epoch_before=directive.expected_min_epoch,
                    epoch_after=directive.expected_min_epoch,
                    outcome=ActuationOutcome.UNKNOWN,
                    verification=ReceiptVerification.UNVERIFIED,
                    findings=[
                        _finding(
                            "DIVERGENT_NODE_EPOCH",
                            "TERMINAL",
                            f"epoch_after mismatch: {consensus_epoch_after} vs {epoch_after}",
                        )
                    ],
                    envelope_digest=envelope_digest,
                    timestamp_utc=now_utc,
                )

            v_status, finding = await verify_substrate_receipt_signature(
                body,
                domain_tag=QUARANTINE_RELEASE_RECEIPT_DOMAIN_TAG,
                expected_envelope_digest=envelope_digest,
                key_resolver=self._receipt_key_resolver,
            )

            if finding:
                combined_findings.append(finding)

            if v_status is ReceiptVerification.INVALID:
                has_invalid = True
            elif v_status is not ReceiptVerification.VERIFIED:
                all_verified = False

        if has_invalid or (self._require_signed_receipts and not all_verified):
            return QuarantineReleaseReceipt(
                released=False,
                enforcement_plane=ENFORCEMENT_PLANE_HOST_OS_KERNEL,
                epoch_before=consensus_epoch_before or directive.expected_min_epoch,
                epoch_after=consensus_epoch_before or directive.expected_min_epoch,
                outcome=ActuationOutcome.UNKNOWN,
                verification=ReceiptVerification.INVALID,
                findings=combined_findings
                or [
                    _finding(
                        "RECEIPT_NOT_VERIFIED",
                        "TERMINAL",
                        "Release receipt signature not verified",
                    )
                ],
                envelope_digest=envelope_digest,
                timestamp_utc=now_utc,
            )

        # Advance gateway epoch tracker
        from src.gateway.governance.quarantine_actuator import advance_workload_epoch

        final_epoch_before = (
            consensus_epoch_before
            if consensus_epoch_before is not None
            else directive.expected_min_epoch
        )
        final_epoch_after = (
            consensus_epoch_after
            if consensus_epoch_after is not None
            else final_epoch_before + 1
        )

        await advance_workload_epoch(directive.agent_svid, final_epoch_after)

        verification_status = (
            ReceiptVerification.VERIFIED
            if all_verified and self._receipt_key_resolver is not None
            else ReceiptVerification.UNVERIFIED
        )

        return QuarantineReleaseReceipt(
            released=True,
            enforcement_plane=ENFORCEMENT_PLANE_HOST_OS_KERNEL,
            epoch_before=final_epoch_before,
            epoch_after=final_epoch_after,
            outcome=ActuationOutcome.ACCEPTED,
            verification=verification_status,
            findings=combined_findings,
            envelope_digest=envelope_digest,
            timestamp_utc=now_utc,
        )

    async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
        """Actuate cleared host operation downstream of governor routing seal."""
        now_utc = datetime.now(tz=timezone.utc).isoformat()
        if clearance.decision != "ALLOW":
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    _finding("CLEARANCE_NOT_ALLOW", "TERMINAL", clearance.decision)
                ],
                outcome=ActuationOutcome.REJECTED,
                timestamp_utc=now_utc,
            )

        # ADR-008 fail-closed single-use routing seal verification
        if clearance.routing_seal:
            try:
                await verify_and_consume_seal(
                    clearance.routing_seal,
                    clearance.action,
                    clearance.params,
                )
            except Exception as exc:
                return ActuationReceipt(
                    accepted=False,
                    receipt_id=None,
                    session_uuid=None,
                    raw_receipt=None,
                    findings=[_finding("ROUTING_SEAL_INVALID", "TERMINAL", str(exc))],
                    outcome=ActuationOutcome.REJECTED,
                    timestamp_utc=now_utc,
                )

        canonical_clearance = jcs_canonicalize_plan(clearance.to_dict())
        envelope_digest = hashlib.sha256(canonical_clearance).hexdigest()

        headers = {
            "Content-Type": "application/json",
            HEADER_ENVELOPE_DIGEST: envelope_digest,
            HEADER_CORRELATION_ID: clearance.correlation_id,
            HEADER_ROUTING_SEAL: clearance.routing_seal or "",
        }

        try:
            endpoints = self._transport.resolve_target_endpoints()
            responses = await self._transport.post_to_endpoints(
                "/v1/cage/actuate",
                content=canonical_clearance,
                headers=headers,
                endpoints=endpoints,
            )
        except Exception as exc:
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[_finding("ACTUATION_POST_FAILED", "TRANSIENT", str(exc))],
                outcome=ActuationOutcome.UNKNOWN,
                timestamp_utc=now_utc,
            )

        if not responses or any(r.status_code != 200 for r in responses):
            status = responses[0].status_code if responses else 500
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    _finding("ACTUATION_ERROR_STATUS", "TERMINAL", f"HTTP {status}")
                ],
                outcome=ActuationOutcome.REJECTED,
                timestamp_utc=now_utc,
            )

        body = responses[0].json()
        receipt_id = body.get("receipt_id", f"act-rec-{envelope_digest[:12]}")
        session_uuid = body.get("session_uuid", clearance.nonce)

        return ActuationReceipt(
            accepted=True,
            receipt_id=receipt_id,
            session_uuid=session_uuid,
            raw_receipt=body,
            findings=[],
            envelope_digest=envelope_digest,
            outcome=ActuationOutcome.ACCEPTED,
            verification=ReceiptVerification.VERIFIED,
            timestamp_utc=now_utc,
        )
