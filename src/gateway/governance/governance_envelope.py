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
CAGE Governance Envelope Builder.

This module provides the envelope structure for wrapping governance decisions
in a cryptographically signed, canonicalized format suitable for:

1. **Compliance Evidence**: Long-term archival with provenance chain
2. **Cross-Service Attestation**: Gateway → Actuator trust boundary
3. **Audit Trail**: RFC 8785 canonical JSON for deterministic hashing

Envelope Structure (RFC 8785 JCS-canonicalized):
    {
        "envelope_version": "2.0",
        "envelope_type": "cage_governance_decision",
        "issued_at": "2026-08-21T12:00:00.000Z",  # ISO 8601 UTC
        "expires_at": "2026-08-21T12:00:30.000Z", # ISO 8601 UTC
        "issuer": {
            "service": "cage-gateway",
            "instance_id": "gke-governance-cluster-2-abc123",
            "region": "us-central1"
        },
        "subject": {
            "action": "execute_trade",
            "action_hash": "sha256:...",
            "record_hash": "sha256:...",  # Evidence chain binding
            "agent_id": "advisor-prod-v3"
        },
        "governance_context": {
            "policy_version": "sha256:...",
            "tiers_passed": ["stpa", "cbf", "opa", "consensus"],
            "deployment_region": "US_FED",
            "controls_satisfied": ["CTRL_OPA_001", "CTRL_CBF_002"]
        },
        "payload": { ... },  # Original governance decision
        "signature": {
            "algorithm": "ES256",
            "kid": "...",
            "value": "base64url(...)"
        }
    }

Usage:
    from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder

    builder = GovernanceEnvelopeBuilder()
    envelope = await builder.build(
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 1000},
        governance_result=result,
        record_hash="sha256:abc123...",
    )

    # Verify an envelope
    verified = builder.verify(envelope)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

logger = logging.getLogger("Gateway.Governance.GovernanceEnvelope")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENVELOPE_VERSION = "2.0"
_ENVELOPE_TYPE = "cage_governance_decision"

# Instance identification (from environment or generated)
_SERVICE_NAME = os.environ.get("CAGE_SERVICE_NAME", "cage-gateway")
_INSTANCE_ID = os.environ.get("CAGE_INSTANCE_ID", f"local-{uuid.uuid4().hex[:8]}")
_DEPLOYMENT_REGION = os.environ.get("CAGE_DEPLOYMENT_REGION", "LOCAL")

# Envelope TTL (default: 5 minutes for audit retention, not execution)
_ENVELOPE_TTL_S = int(os.environ.get("CAGE_ENVELOPE_TTL_S", "300"))


class EnvelopeType(str, Enum):
    """Envelope type identifiers for different governance artifacts."""

    GOVERNANCE_DECISION = "cage_governance_decision"
    EVIDENCE_RECORD = "cage_evidence_record"
    POLICY_ATTESTATION = "cage_policy_attestation"
    AUDIT_CHECKPOINT = "cage_audit_checkpoint"


@dataclass
class IssuerMetadata:
    """Metadata about the envelope issuer (gateway instance)."""

    service: str = _SERVICE_NAME
    instance_id: str = _INSTANCE_ID
    region: str = _DEPLOYMENT_REGION

    def to_dict(self) -> dict[str, str]:
        return {
            "service": self.service,
            "instance_id": self.instance_id,
            "region": self.region,
        }


@dataclass
class SubjectMetadata:
    """Metadata about the governance subject (action being governed)."""

    action: str
    action_hash: str
    record_hash: str | None = None
    agent_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "action": self.action,
            "action_hash": self.action_hash,
        }
        if self.record_hash:
            result["record_hash"] = self.record_hash
        if self.agent_id:
            result["agent_id"] = self.agent_id
        return result


@dataclass
class GovernanceContext:
    """Context about the governance evaluation."""

    policy_version: str
    tiers_passed: list[str] = field(default_factory=list)
    deployment_region: str = _DEPLOYMENT_REGION
    controls_satisfied: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "tiers_passed": self.tiers_passed,
            "deployment_region": self.deployment_region,
            "controls_satisfied": self.controls_satisfied,
        }


@dataclass
class SignatureBlock:
    """Cryptographic signature block."""

    algorithm: str
    kid: str
    value: str  # base64url-encoded signature

    def to_dict(self) -> dict[str, str]:
        return {
            "algorithm": self.algorithm,
            "kid": self.kid,
            "value": self.value,
        }


@dataclass
class GovernanceEnvelope:
    """The complete CAGE Governance Envelope."""

    envelope_version: str
    envelope_type: str
    envelope_id: str
    issued_at: str  # ISO 8601 UTC
    expires_at: str  # ISO 8601 UTC
    issuer: IssuerMetadata
    subject: SubjectMetadata
    governance_context: GovernanceContext
    payload: dict[str, Any]
    signature: SignatureBlock | None = None

    def to_dict(self, include_signature: bool = True) -> dict[str, Any]:
        """Convert envelope to dictionary for serialization.

        Args:
            include_signature: Whether to include the signature block.
                              Set to False when computing the signature input.
        """
        result: dict[str, Any] = {
            "envelope_version": self.envelope_version,
            "envelope_type": self.envelope_type,
            "envelope_id": self.envelope_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "issuer": self.issuer.to_dict(),
            "subject": self.subject.to_dict(),
            "governance_context": self.governance_context.to_dict(),
            "payload": self.payload,
        }
        if include_signature and self.signature:
            result["signature"] = self.signature.to_dict()
        return result

    def to_canonical_bytes(self, include_signature: bool = True) -> bytes:
        """Serialize envelope to RFC 8785 canonical JSON bytes."""
        return jcs_canonicalize_plan(self.to_dict(include_signature))

    def compute_digest(self) -> bytes:
        """Compute the SHA-256 digest of the unsigned envelope.

        This is the value that should be signed by KMS.
        """
        canonical = self.to_canonical_bytes(include_signature=False)
        return hashlib.sha256(canonical).digest()

    def compute_digest_hex(self) -> str:
        """Compute the SHA-256 digest as a hex string."""
        return self.compute_digest().hex()


class GovernanceEnvelopeBuilder:
    """Builder for constructing signed governance envelopes.

    Usage:
        builder = GovernanceEnvelopeBuilder()

        # Build with automatic signing
        envelope = await builder.build(
            action="execute_trade",
            params={"symbol": "AAPL"},
            governance_result=result,
        )

        # Or build unsigned for external signing
        envelope = builder.build_unsigned(
            action="execute_trade",
            params={"symbol": "AAPL"},
            governance_result=result,
        )
        digest = envelope.compute_digest()
        # ... sign digest externally ...
        signed_envelope = builder.attach_signature(envelope, sig, kid, alg)
    """

    def __init__(
        self,
        issuer: IssuerMetadata | None = None,
        ttl_s: int = _ENVELOPE_TTL_S,
    ):
        self._issuer = issuer or IssuerMetadata()
        self._ttl_s = ttl_s

    def _compute_action_hash(self, action: str, params: dict[str, Any]) -> str:
        """Compute the action hash from action name and parameters."""
        # Normalize params to safe types
        safe_params = {
            k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v))
            for k, v in params.items()
        }
        canon = jcs_canonicalize_plan({"action": action, **safe_params})
        return f"sha256:{hashlib.sha256(canon).hexdigest()}"

    def _get_policy_version(self) -> str:
        """Get the current policy version hash."""
        try:
            from src.gateway.governance.constants import ControlRegistry

            return f"sha256:{ControlRegistry().active_hash}"
        except Exception:
            return "sha256:unknown"

    def build_unsigned(
        self,
        action: str,
        params: dict[str, Any],
        governance_result: dict[str, Any],
        record_hash: str | None = None,
        agent_id: str | None = None,
        tiers_passed: list[str] | None = None,
        controls_satisfied: list[str] | None = None,
        envelope_type: EnvelopeType = EnvelopeType.GOVERNANCE_DECISION,
    ) -> GovernanceEnvelope:
        """Build an unsigned envelope for external signing.

        Args:
            action: The action name (e.g., "execute_trade").
            params: The action parameters.
            governance_result: The governance decision payload.
            record_hash: Optional evidence chain record hash.
            agent_id: Optional agent identifier.
            tiers_passed: List of governance tiers that passed.
            controls_satisfied: List of control IDs satisfied.
            envelope_type: The type of envelope to create.

        Returns:
            An unsigned GovernanceEnvelope ready for signing.
        """
        now = datetime.now(timezone.utc)
        expires = datetime.fromtimestamp(
            now.timestamp() + self._ttl_s, tz=timezone.utc
        )

        action_hash = self._compute_action_hash(action, params)

        subject = SubjectMetadata(
            action=action,
            action_hash=action_hash,
            record_hash=record_hash,
            agent_id=agent_id,
        )

        context = GovernanceContext(
            policy_version=self._get_policy_version(),
            tiers_passed=tiers_passed or [],
            deployment_region=_DEPLOYMENT_REGION,
            controls_satisfied=controls_satisfied or [],
        )

        return GovernanceEnvelope(
            envelope_version=_ENVELOPE_VERSION,
            envelope_type=envelope_type.value,
            envelope_id=f"cage-{uuid.uuid4().hex}",
            issued_at=now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            expires_at=expires.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            issuer=self._issuer,
            subject=subject,
            governance_context=context,
            payload=governance_result,
            signature=None,
        )

    def attach_signature(
        self,
        envelope: GovernanceEnvelope,
        signature_bytes: bytes,
        kid: str,
        algorithm: str = "ES256",
    ) -> GovernanceEnvelope:
        """Attach a signature to an unsigned envelope.

        Args:
            envelope: The unsigned envelope.
            signature_bytes: The raw signature bytes.
            kid: The key ID used for signing.
            algorithm: The signing algorithm (e.g., "ES256", "RS256").

        Returns:
            A new envelope with the signature attached.
        """
        import base64

        # base64url encode the signature
        sig_b64 = base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode("ascii")

        envelope.signature = SignatureBlock(
            algorithm=algorithm,
            kid=kid,
            value=sig_b64,
        )
        return envelope

    async def build(
        self,
        action: str,
        params: dict[str, Any],
        governance_result: dict[str, Any],
        record_hash: str | None = None,
        agent_id: str | None = None,
        tiers_passed: list[str] | None = None,
        controls_satisfied: list[str] | None = None,
        envelope_type: EnvelopeType = EnvelopeType.GOVERNANCE_DECISION,
    ) -> GovernanceEnvelope:
        """Build a signed envelope using the KMS signer.

        Args:
            action: The action name (e.g., "execute_trade").
            params: The action parameters.
            governance_result: The governance decision payload.
            record_hash: Optional evidence chain record hash.
            agent_id: Optional agent identifier.
            tiers_passed: List of governance tiers that passed.
            controls_satisfied: List of control IDs satisfied.
            envelope_type: The type of envelope to create.

        Returns:
            A signed GovernanceEnvelope.
        """
        envelope = self.build_unsigned(
            action=action,
            params=params,
            governance_result=governance_result,
            record_hash=record_hash,
            agent_id=agent_id,
            tiers_passed=tiers_passed,
            controls_satisfied=controls_satisfied,
            envelope_type=envelope_type,
        )

        try:
            from src.gateway.governance.kms_signer import get_governance_signer
            from src.gateway.governance.jwks import pem_to_jwk

            signer = get_governance_signer()
            if not signer.kms_active:
                logger.warning(
                    "⚠️ KMS not active — envelope will be unsigned"
                )
                return envelope

            # Use the direct digest signing method for efficiency
            digest = envelope.compute_digest()
            sig_hex = signer.sign_precomputed_digest(digest)
            signature_bytes = bytes.fromhex(sig_hex)

            # Get kid from the public key
            pem = signer.get_public_key_pem()
            jwk = pem_to_jwk(pem)
            kid = jwk["kid"]
            alg = jwk.get("alg", "ES256")

            return self.attach_signature(envelope, signature_bytes, kid, alg)

        except Exception as e:
            logger.error("❌ Failed to sign envelope: %s", e)
            return envelope

    def verify(
        self,
        envelope: GovernanceEnvelope | dict[str, Any],
    ) -> bool:
        """Verify an envelope's signature.

        Args:
            envelope: The envelope to verify (GovernanceEnvelope or dict).

        Returns:
            True if signature is valid, False otherwise.
        """
        if isinstance(envelope, dict):
            # Convert dict to envelope
            envelope = self._envelope_from_dict(envelope)

        if envelope.signature is None:
            logger.warning("⚠️ Envelope has no signature")
            return False

        try:
            from src.gateway.governance.jwks import get_jwks, pem_to_jwk
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
            import base64

            # Get the verification key
            kid = envelope.signature.kid
            pem = get_jwks().get_pem(kid)

            if pem is None:
                # Fallback to signer key
                from src.gateway.governance.kms_signer import get_governance_signer

                signer = get_governance_signer()
                pem = signer.get_public_key_pem()

            # Load the public key
            public_key = serialization.load_pem_public_key(pem)

            # Decode signature
            sig_b64 = envelope.signature.value
            # Add padding if needed
            padding = 4 - len(sig_b64) % 4
            if padding != 4:
                sig_b64 += "=" * padding
            signature_bytes = base64.urlsafe_b64decode(sig_b64)

            # Compute expected digest
            digest = envelope.compute_digest()

            # Verify based on key type
            alg = envelope.signature.algorithm
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                # Convert IEEE P1363 signature to DER if needed
                key_size = (public_key.curve.key_size + 7) // 8
                if len(signature_bytes) == key_size * 2:
                    # IEEE P1363 format (r || s) — convert to DER
                    r = int.from_bytes(signature_bytes[:key_size], "big")
                    s = int.from_bytes(signature_bytes[key_size:], "big")
                    signature_bytes = utils.encode_dss_signature(r, s)

                public_key.verify(
                    signature_bytes,
                    digest,
                    ec.ECDSA(utils.Prehashed(hashes.SHA256())),
                )
            elif isinstance(public_key, ed25519.Ed25519PublicKey):
                # Ed25519 uses message, not digest
                canonical = envelope.to_canonical_bytes(include_signature=False)
                public_key.verify(signature_bytes, canonical)
            else:
                # RSA
                from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

                public_key.verify(
                    signature_bytes,
                    digest,
                    rsa_padding.PKCS1v15(),
                    utils.Prehashed(hashes.SHA256()),
                )

            logger.debug("✅ Envelope signature verified: id=%s", envelope.envelope_id)
            return True

        except Exception as e:
            logger.warning("❌ Envelope signature verification failed: %s", e)
            return False

    def _envelope_from_dict(self, data: dict[str, Any]) -> GovernanceEnvelope:
        """Reconstruct a GovernanceEnvelope from a dictionary."""
        issuer_data = data.get("issuer", {})
        issuer = IssuerMetadata(
            service=issuer_data.get("service", _SERVICE_NAME),
            instance_id=issuer_data.get("instance_id", _INSTANCE_ID),
            region=issuer_data.get("region", _DEPLOYMENT_REGION),
        )

        subject_data = data.get("subject", {})
        subject = SubjectMetadata(
            action=subject_data.get("action", ""),
            action_hash=subject_data.get("action_hash", ""),
            record_hash=subject_data.get("record_hash"),
            agent_id=subject_data.get("agent_id"),
        )

        context_data = data.get("governance_context", {})
        context = GovernanceContext(
            policy_version=context_data.get("policy_version", ""),
            tiers_passed=context_data.get("tiers_passed", []),
            deployment_region=context_data.get("deployment_region", _DEPLOYMENT_REGION),
            controls_satisfied=context_data.get("controls_satisfied", []),
        )

        sig_data = data.get("signature")
        signature = None
        if sig_data:
            signature = SignatureBlock(
                algorithm=sig_data.get("algorithm", "ES256"),
                kid=sig_data.get("kid", ""),
                value=sig_data.get("value", ""),
            )

        return GovernanceEnvelope(
            envelope_version=data.get("envelope_version", _ENVELOPE_VERSION),
            envelope_type=data.get("envelope_type", _ENVELOPE_TYPE),
            envelope_id=data.get("envelope_id", ""),
            issued_at=data.get("issued_at", ""),
            expires_at=data.get("expires_at", ""),
            issuer=issuer,
            subject=subject,
            governance_context=context,
            payload=data.get("payload", {}),
            signature=signature,
        )


# ---------------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------------


def create_envelope_builder(
    issuer: IssuerMetadata | None = None,
    ttl_s: int = _ENVELOPE_TTL_S,
) -> GovernanceEnvelopeBuilder:
    """Create a new envelope builder with the given configuration.

    Args:
        issuer: Optional issuer metadata override.
        ttl_s: Envelope time-to-live in seconds.

    Returns:
        A configured GovernanceEnvelopeBuilder instance.
    """
    return GovernanceEnvelopeBuilder(issuer=issuer, ttl_s=ttl_s)


async def build_governance_envelope(
    action: str,
    params: dict[str, Any],
    governance_result: dict[str, Any],
    record_hash: str | None = None,
    **kwargs: Any,
) -> GovernanceEnvelope:
    """Convenience function to build a signed governance envelope.

    Args:
        action: The action name.
        params: The action parameters.
        governance_result: The governance decision payload.
        record_hash: Optional evidence chain record hash.
        **kwargs: Additional arguments passed to build().

    Returns:
        A signed GovernanceEnvelope.
    """
    builder = GovernanceEnvelopeBuilder()
    return await builder.build(
        action=action,
        params=params,
        governance_result=governance_result,
        record_hash=record_hash,
        **kwargs,
    )


