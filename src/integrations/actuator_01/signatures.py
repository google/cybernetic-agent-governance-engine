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
signatures.py — Ed25519 Quorum Signature Construction (Phase 2, Stream C)

Implements multi-operator quorum signing for execution authorization envelopes.
Quorum signatures use a domain-tagged construction to prevent cross-context replay.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.raw_signer_protocol import RawMessageSigner

logger = logging.getLogger(__name__)

# Domain tag for quorum signatures (prevents replay as assertion signatures)
# NOTE: This is the wire-load-bearing value required by Archytan kernel verification.
# The constant name is anonymized; the runtime value must match the kernel contract.
ACTUATOR_01_DOMAIN_TAG_QUORUM = b"ARCHYTAN_QUORUM_V1:"

# Domain tag for policy decision signatures (dual-authority model)
# Isolates institutional policy authority signatures from operator quorum signatures
ACTUATOR_01_DOMAIN_TAG_POLICY_DECISION = b"ARCHYTAN_POLICY_DECISION_V1:"


def sign_for_quorum(
    signer: RawMessageSigner,
    raw_body: bytes,
) -> str:
    """Sign a canonical envelope body for quorum verification.

    Per wire contract §7.2, quorum signatures sign the SHA-256 digest of the
    raw canonical body bytes (NOT the envelope dict, NOT a re-hash). The
    domain tag isolates quorum signatures from assertion signatures so neither
    can be replayed in the other's context.

    Format:
        Ed25519(operator_key, ACTUATOR_01_DOMAIN_TAG_QUORUM || SHA-256(raw_body))

    Args:
        signer: KMS signer instance for this operator.
        raw_body: The exact canonical envelope bytes (from JCS serialization).

    Returns:
        Lowercase hex-encoded signature string.

    Raises:
        RuntimeError: If KMS is not active or signing fails.

    Example:
        >>> from src.gateway.governance.kms_signer import get_governance_signer
        >>> from src.integrations.actuator_01.signatures import sign_for_quorum
        >>> signer = get_governance_signer()  # Returns RawMessageSigner protocol
        >>> canonical_bytes = b'{"action":"execute_trade",...}'
        >>> sig_hex = sign_for_quorum(signer, canonical_bytes)
        >>> len(sig_hex)
        128  # Ed25519 signature is 64 bytes = 128 hex chars
    """
    if not signer.is_kms_active:
        raise RuntimeError(
            "[actuator_01/signatures] sign_for_quorum() called but KMS is not active. "
            "Ensure KMS_GOVERNANCE_KEY is set and signer initialized successfully."
        )

    # Compute SHA-256 of the raw body
    body_digest = hashlib.sha256(raw_body).digest()

    # Prepend domain tag to isolate quorum signatures
    message = ACTUATOR_01_DOMAIN_TAG_QUORUM + body_digest

    # Sign the tagged message
    # KMSSigner.sign_raw() handles Ed25519 vs ECDSA/RSA logic internally
    signature_bytes = signer.sign_raw(message)

    # Return lowercase hex (wire contract requirement)
    signature_hex = signature_bytes.hex().lower()

    logger.info(
        "[actuator_01/signatures] Quorum signature generated: %s... (len=%d)",
        signature_hex[:16],
        len(signature_hex),
    )

    return signature_hex


def sign_policy_decision(
    signer: RawMessageSigner,
    action: str,
    target_digest: str,
    correlation_id: str,
    decision: str,
    decision_path: str,
    required_quorum: int,
    policy_version: str,
    evaluated_at: int,
    receipt_id: str | None = None,
    receipt_hash: str | None = None,
) -> str:
    """Sign a policy decision for dual-authority verification.

    Implements the canonical decision binding payload per Archytan Vector 3:
    action || 0x1F || target_digest || 0x1F || correlation_id || 0x1F ||
    decision || 0x1F || decision_path || 0x1F || required_quorum || 0x1F ||
    policy_version || 0x1F || evaluated_at || 0x1F || receipt_id || 0x1F || receipt_hash

    The 0x1F unit separator ensures unambiguous field boundaries and prevents
    cross-field substitution attacks.

    Format:
        Ed25519(policy_key, ACTUATOR_01_DOMAIN_TAG_POLICY_DECISION || SHA-256(binding_payload))

    Args:
        signer: KMS signer instance for the institutional policy authority.
        action: Action being authorized (e.g., "payment.wire.execute").
        target_digest: SHA-256 digest of the target parameters.
        correlation_id: Request correlation UUID.
        decision: Governance decision ("ALLOW", "DENY", "HOLD").
        decision_path: Decision path ("DIRECT", "ESCALATE").
        required_quorum: Number of operator approvals required.
        policy_version: Policy version identifier (e.g., "v1").
        evaluated_at: Unix timestamp when decision was evaluated.
        receipt_id: Optional partner receipt ID (if available).
        receipt_hash: Optional receipt hash (if available).

    Returns:
        Lowercase hex-encoded signature string.

    Raises:
        RuntimeError: If KMS is not active or signing fails.
        ValueError: If signer URN indicates operator quorum key (prohibited).

    Example:
        >>> from src.gateway.governance.kms_signer import get_governance_signer
        >>> signer = get_governance_signer()
        >>> sig = sign_policy_decision(
        ...     signer=signer,
        ...     action="payment.wire.execute",
        ...     target_digest="a" * 64,
        ...     correlation_id="550e8400-e29b-41d4-a716-446655440000",
        ...     decision="ALLOW",
        ...     decision_path="DIRECT",
        ...     required_quorum=2,
        ...     policy_version="v1",
        ...     evaluated_at=1785012000,
        ... )
    """
    if not signer.is_kms_active:
        raise RuntimeError(
            "[actuator_01/signatures] sign_policy_decision() called but KMS is not active. "
            "Ensure KMS_GOVERNANCE_KEY is set and signer initialized successfully."
        )

    # Guardrail: Ensure operator quorum keys cannot be used for policy decision signatures
    # Policy authority signers should have distinct URNs (e.g., "urn:actuator_01:policy:*")
    # vs operator quorum keys (e.g., "urn:actuator_01:op:*")
    signer_urn = getattr(signer, "signer_urn", "")
    if signer_urn and ":op:" in signer_urn:
        raise ValueError(
            f"[actuator_01/signatures] Policy decision signature attempted with "
            f"operator quorum key (URN: {signer_urn}). Policy authority keys must be isolated."
        )

    # Construct decision binding payload with 0x1F unit separators
    unit_sep = b"\x1f"
    binding_payload = unit_sep.join(
        [
            action.encode("utf-8"),
            target_digest.encode("utf-8"),
            correlation_id.encode("utf-8"),
            decision.encode("utf-8"),
            decision_path.encode("utf-8"),
            str(required_quorum).encode("utf-8"),
            policy_version.encode("utf-8"),
            str(evaluated_at).encode("utf-8"),
            (receipt_id or "").encode("utf-8"),
            (receipt_hash or "").encode("utf-8"),
        ]
    )

    # Compute SHA-256 digest of the binding payload
    decision_binding_sha256 = hashlib.sha256(binding_payload).digest()

    # Sign domain-tagged decision binding
    message = ACTUATOR_01_DOMAIN_TAG_POLICY_DECISION + decision_binding_sha256
    signature_bytes = signer.sign_raw(message)

    # Return lowercase hex (wire contract requirement)
    signature_hex = signature_bytes.hex().lower()

    logger.info(
        "[actuator_01/signatures] Policy decision signature generated: %s... (len=%d)",
        signature_hex[:16],
        len(signature_hex),
    )

    return signature_hex


class Ed25519KeyPairSigner:
    """Ed25519 ``RawMessageSigner`` bound to a specific authority or operator URN."""

    is_kms_active: bool = True

    def __init__(self, private_key: Ed25519PrivateKey, signer_urn: str) -> None:
        self._private_key = private_key
        self.signer_urn = signer_urn

    @classmethod
    def from_pem_file(
        cls, key_path: str | Path, signer_urn: str
    ) -> Ed25519KeyPairSigner:
        """Load an Ed25519 PKCS#8 PEM private key from disk."""
        pem_bytes = Path(key_path).read_bytes()
        loaded = serialization.load_pem_private_key(pem_bytes, password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise TypeError(f"{key_path} does not contain an Ed25519 private key")
        return cls(private_key=loaded, signer_urn=signer_urn)

    @classmethod
    def from_seed_hex(cls, seed_hex: str, signer_urn: str) -> Ed25519KeyPairSigner:
        """Construct an Ed25519 signer from a 32-byte hex seed."""
        raw_seed = bytes.fromhex(seed_hex)
        if len(raw_seed) != 32:
            raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(raw_seed)}")
        return cls(
            private_key=Ed25519PrivateKey.from_private_bytes(raw_seed),
            signer_urn=signer_urn,
        )

    @property
    def public_key_hex(self) -> str:
        """Return 64-character lowercase hex encoding of the 32-byte raw public key."""
        pub_raw = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return pub_raw.hex().lower()

    def sign_raw(self, message: bytes) -> bytes:
        """Sign raw message bytes using PureEdDSA (Ed25519)."""
        return self._private_key.sign(message)


@dataclass(frozen=True)
class SandboxSigningBundle:
    """Multi-key Ed25519 signing bundle for actuator_01 authority graph alignment."""

    policy_signer: Ed25519KeyPairSigner
    assertion_signer: Ed25519KeyPairSigner
    operator_signers: dict[str, Ed25519KeyPairSigner]
    approver_signer: Ed25519KeyPairSigner

    @property
    def operator_urns(self) -> list[str]:
        """Ordered list of registered quorum operator URNs."""
        return list(self.operator_signers.keys())

    @property
    def approver_urn(self) -> str:
        """URN bound to the step-up WebAuthn approver key."""
        return self.approver_signer.signer_urn

    def resolve_signer(self, urn: str) -> RawMessageSigner:
        """Resolve per-operator signer by URN (fail-closed on unknown URN)."""
        if urn in self.operator_signers:
            return self.operator_signers[urn]
        if urn == self.approver_signer.signer_urn:
            return self.approver_signer
        raise KeyError(
            f"[actuator_01/signatures] Unknown operator URN {urn!r}; "
            f"registered URNs: {sorted(self.operator_signers)}"
        )

    @classmethod
    def from_directory(cls, keys_dir: str | Path) -> SandboxSigningBundle:
        """Load a sandbox signing bundle from ``sandbox_public_keys.json`` + ``*.key`` files."""
        resolved_dir = Path(keys_dir).resolve()
        manifest_path = resolved_dir / "sandbox_public_keys.json"
        if not manifest_path.is_file():
            raise FileNotFoundError(
                f"Signing key manifest not found at {manifest_path}"
            )

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        keys_cfg = manifest.get("keys", {})

        def _load_role(role_id: str) -> Ed25519KeyPairSigner:
            entry = keys_cfg.get(role_id)
            if not isinstance(entry, dict):
                raise ValueError(f"Missing role {role_id!r} in {manifest_path}")
            filename = Path(str(entry["private_key_file"])).name
            key_path = (resolved_dir / filename).resolve()
            if not str(key_path).startswith(str(resolved_dir) + os.sep):
                raise ValueError(f"Key path escapes bundle directory: {key_path}")
            if not key_path.is_file():
                raise FileNotFoundError(f"Private key file missing: {key_path}")
            signer = Ed25519KeyPairSigner.from_pem_file(key_path, str(entry["urn"]))
            expected_hex = str(entry.get("public_key_hex", "")).lower()
            if expected_hex and signer.public_key_hex != expected_hex:
                raise ValueError(
                    f"Public key mismatch for role {role_id!r}: "
                    f"manifest={expected_hex} vs key={signer.public_key_hex}"
                )
            return signer

        policy_signer = _load_role("policy_authority")
        op1_signer = _load_role("operator_1_and_assertion")
        op2_signer = _load_role("operator_2")
        approver_signer = _load_role("step_up_approver")

        return cls(
            policy_signer=policy_signer,
            assertion_signer=op1_signer,
            operator_signers={
                op1_signer.signer_urn: op1_signer,
                op2_signer.signer_urn: op2_signer,
            },
            approver_signer=approver_signer,
        )


def build_webauthn_approval(
    *,
    action: str,
    target: str,
    approver_urn: str,
    decision: str,
    issued_at: int,
    signer: RawMessageSigner,
    approved_at_utc: str = "2026-08-01T12:00:00Z",
    webauthn_approver_urn: str | None = None,
    credential_id: str = "dGVzdC1jcmVkZW50aWFsLXZlY3Rvci0z",
    rp_id: str = "archytan.local",
    origin: str = "https://archytan.local",
    sign_count: int = 1,
) -> dict[str, Any]:
    """Construct a cryptographically valid FIDO2/WebAuthn approval block per Vector 3.

    Computes ``challenge_binding`` over ``action || 0x1f || target_digest || 0x1f ||
    effective_approver_urn || 0x1f || decision || 0x1f || issued_at``, embeds the raw
    32-byte challenge into ``client_data_json``, builds the 37-byte ``authenticator_data``
    with ``flags=0x05`` (UserPresent | UserVerified), and signs
    ``authenticator_data || SHA-256(client_data_json)`` with the approver's Ed25519 key.
    """
    if not signer.is_kms_active:
        raise RuntimeError(
            "[actuator_01/signatures] build_webauthn_approval() called with inactive signer"
        )

    effective_approver_urn = webauthn_approver_urn or approver_urn
    target_obj = {"account_hash": hashlib.sha256(target.encode("utf-8")).hexdigest()}
    target_digest = hashlib.sha256(jcs_canonicalize_plan(target_obj)).hexdigest()

    binding_payload = b"\x1f".join(
        [
            action.encode("utf-8"),
            target_digest.encode("utf-8"),
            effective_approver_urn.encode("utf-8"),
            decision.encode("utf-8"),
            str(issued_at).encode("utf-8"),
        ]
    )
    challenge_binding_bytes = hashlib.sha256(binding_payload).digest()
    challenge_binding_hex = challenge_binding_bytes.hex().lower()

    def _b64u(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    client_data_bytes = jcs_canonicalize_plan(
        {
            "challenge": _b64u(challenge_binding_bytes),
            "origin": origin,
            "type": "webauthn.get",
        }
    )
    # 37 bytes: SHA-256(rpId) [32] || flags 0x05 (UP|UV) [1] || uint32 counter [4]
    auth_data_bytes = (
        hashlib.sha256(rp_id.encode("utf-8")).digest()
        + b"\x05"
        + struct.pack(">I", sign_count)
    )
    sig_bytes = signer.sign_raw(
        auth_data_bytes + hashlib.sha256(client_data_bytes).digest()
    )

    record: dict[str, Any] = {
        "approver_urn": approver_urn,
        "approved_at_utc": approved_at_utc,
        "auth_method": "WEBAUTHN",
        "credential_id": credential_id,
        "client_data_json": _b64u(client_data_bytes),
        "authenticator_data": _b64u(auth_data_bytes),
        "challenge_binding": challenge_binding_hex,
        "signature": _b64u(sig_bytes),
    }
    if webauthn_approver_urn:
        record["webauthn_approver_urn"] = webauthn_approver_urn
    return record
