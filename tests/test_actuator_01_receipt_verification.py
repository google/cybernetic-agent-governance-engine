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

"""Kid-resolved verification of actuator_01 partner receipts.

Covers the verifier in isolation, the shared key-manifest client, and the
adapter's mapping of verification status onto the actuation outcome:
``INVALID`` (and ``UNVERIFIED`` in strict mode) can only ever be ``UNKNOWN``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ActuationReceipt,
    ActuatorCapability,
    ExecutionClearance,
    ReceiptVerification,
)
from src.integrations.actuator_01.adapter import Actuator01Adapter
from src.integrations.actuator_01.client import ActuatorHttpClient
from src.integrations.actuator_01.constants import RECEIPT_SIGNATURE_DOMAIN_TAG
from src.integrations.actuator_01.receipt_verifier import verify_partner_receipt
from src.integrations.trust.key_manifest import Ed25519KeyManifestClient

pytestmark = [pytest.mark.unit, pytest.mark.local]

_KID = "partner-receipt-2026"
_DIGEST = "d" * 64
_PARTNER_KEY = Ed25519PrivateKey.generate()


class _StaticResolver:
    """kid → key map standing in for an out-of-band manifest."""

    def __init__(self, keys: dict) -> None:
        self._keys = keys

    async def get_key(self, kid: str):
        return self._keys.get(kid)


class _FailingResolver:
    async def get_key(self, kid: str):
        raise httpx.ConnectError("manifest host down")


_RESOLVER = _StaticResolver({_KID: _PARTNER_KEY.public_key()})


def _sign(body: dict, key: Ed25519PrivateKey = _PARTNER_KEY, kid: str = _KID) -> dict:
    """Return ``body`` with a detached partner signature over tag || JCS(body)."""
    signature = key.sign(RECEIPT_SIGNATURE_DOMAIN_TAG + jcs_canonicalize_plan(body))
    return {
        **body,
        "signature": {
            "alg": "EdDSA",
            "kid": kid,
            "value": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
        },
    }


def _body(digest: str = _DIGEST) -> dict:
    return {
        "receipt_id": "r-1",
        "session_uuid": "s-1",
        "status": "ACCEPTED",
        "envelope_digest": digest,
    }


class TestVerifier:
    async def test_unsigned_body_is_unverified(self) -> None:
        check = await verify_partner_receipt(
            _body(), envelope_digest=_DIGEST, key_resolver=_RESOLVER
        )
        assert check.verification is ReceiptVerification.UNVERIFIED
        assert check.finding is None

    async def test_valid_signature_is_verified(self) -> None:
        check = await verify_partner_receipt(
            _sign(_body()), envelope_digest=_DIGEST, key_resolver=_RESOLVER
        )
        assert check.verification is ReceiptVerification.VERIFIED

    async def test_tampered_body_is_invalid(self) -> None:
        signed = _sign(_body())
        signed["receipt_id"] = "r-forged"
        check = await verify_partner_receipt(
            signed, envelope_digest=_DIGEST, key_resolver=_RESOLVER
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding["code"] == "RECEIPT_SIGNATURE_INVALID"

    async def test_unknown_kid_is_invalid(self) -> None:
        check = await verify_partner_receipt(
            _sign(_body(), kid="rotated-out"),
            envelope_digest=_DIGEST,
            key_resolver=_RESOLVER,
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding["code"] == "RECEIPT_UNKNOWN_KID"

    async def test_signature_by_an_unlisted_key_is_invalid(self) -> None:
        """A key embedded nowhere in the manifest cannot vouch for a receipt."""
        check = await verify_partner_receipt(
            _sign(_body(), key=Ed25519PrivateKey.generate()),
            envelope_digest=_DIGEST,
            key_resolver=_RESOLVER,
        )
        assert check.verification is ReceiptVerification.INVALID

    async def test_receipt_for_another_envelope_is_invalid(self) -> None:
        check = await verify_partner_receipt(
            _sign(_body(digest="e" * 64)),
            envelope_digest=_DIGEST,
            key_resolver=_RESOLVER,
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding["code"] == "RECEIPT_ENVELOPE_MISMATCH"

    @pytest.mark.parametrize(
        "signature",
        [
            "not-an-object",
            {"alg": "none", "kid": _KID, "value": "AAAA"},
            {"alg": "EdDSA", "kid": "", "value": "AAAA"},
            {"alg": "EdDSA", "kid": _KID, "value": "AAAA"},  # wrong length
        ],
    )
    async def test_malformed_signature_is_invalid(self, signature) -> None:
        check = await verify_partner_receipt(
            {**_body(), "signature": signature},
            envelope_digest=_DIGEST,
            key_resolver=_RESOLVER,
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding["code"] == "RECEIPT_SIGNATURE_MALFORMED"

    async def test_no_trust_anchor_is_unverified(self) -> None:
        check = await verify_partner_receipt(
            _sign(_body()), envelope_digest=_DIGEST, key_resolver=None
        )
        assert check.verification is ReceiptVerification.UNVERIFIED
        assert check.finding["code"] == "RECEIPT_TRUST_ANCHOR_UNCONFIGURED"

    async def test_manifest_unavailable_is_unverified(self) -> None:
        check = await verify_partner_receipt(
            _sign(_body()), envelope_digest=_DIGEST, key_resolver=_FailingResolver()
        )
        assert check.verification is ReceiptVerification.UNVERIFIED
        assert check.finding["code"] == "RECEIPT_KEY_MANIFEST_UNAVAILABLE"


class TestKeyManifestClient:
    async def test_resolves_by_kid_from_file_manifest(self, tmp_path: Path) -> None:
        raw = _PARTNER_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        manifest = tmp_path / "jwks.json"
        manifest.write_text(
            json.dumps(
                {
                    "keys": [
                        {
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "kid": _KID,
                            "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
                        }
                    ]
                }
            )
        )
        client = Ed25519KeyManifestClient(f"file://{manifest}")
        assert await client.get_key(_KID) is not None
        assert await client.get_key("unknown") is None

        check = await verify_partner_receipt(
            _sign(_body()), envelope_digest=_DIGEST, key_resolver=client
        )
        assert check.verification is ReceiptVerification.VERIFIED

    def test_rejects_disallowed_scheme(self) -> None:
        with pytest.raises(ValueError, match="scheme"):
            Ed25519KeyManifestClient("ftp://keys.example.com/jwks.json")


class TestReceiptInvariant:
    def test_invalid_signature_cannot_be_accepted(self) -> None:
        with pytest.raises(ValueError, match="INVALID"):
            ActuationReceipt(
                accepted=True,
                receipt_id="r",
                session_uuid=None,
                raw_receipt=None,
                verification=ReceiptVerification.INVALID,
            )


# ── Adapter integration ───────────────────────────────────────────────────


class _Signer:
    is_kms_active = True

    def sign_raw(self, message: bytes) -> bytes:
        return hashlib.sha512(message).digest()[:64]


def _clearance() -> ExecutionClearance:
    urns = ["urn:actuator_01:op:alice", "urn:actuator_01:op:bob"]
    return ExecutionClearance(
        thread_id="test-thread-123",
        decision="ALLOW",
        decision_path="DIRECT",
        action="execute_trade",
        target="account:1234567890",
        operator_urn=urns[0],
        issued_at=1785012000,
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id="550e8400-e29b-41d4-a716-446655440000",
        correlation_id_source="INGRESS_MINTED",
        governance_decision_digest="a" * 64,
        opa_input_digest="b" * 64,
        nonce="c" * 32,
        approvals=[
            {
                "approver_urn": urn,
                "approved_at_utc": f"2026-08-01T12:00:0{i}Z",
                "approval_signature": f"sig-{i}",
            }
            for i, urn in enumerate(urns)
        ],
        required_quorum=2,
        ttl_seconds=30,
    )


def _adapter(respond, **kwargs) -> Actuator01Adapter:
    """Adapter whose partner answers with ``respond(envelope_digest)``."""

    async def submit(canonical_bytes, **_):
        status, body = respond(hashlib.sha256(canonical_bytes).hexdigest())
        return httpx.Response(status, json=body)

    client = MagicMock(spec=ActuatorHttpClient)
    client.submit_envelope = submit
    return Actuator01Adapter(client=client, signer=_Signer(), **kwargs)  # type: ignore[arg-type]


class TestAdapterReceiptVerification:
    async def test_verified_acceptance(self) -> None:
        adapter = _adapter(
            lambda d: (200, _sign(_body(digest=d))), receipt_key_resolver=_RESOLVER
        )
        receipt = await adapter.actuate(_clearance())
        assert receipt.outcome is ActuationOutcome.ACCEPTED
        assert receipt.verification is ReceiptVerification.VERIFIED
        assert ActuatorCapability.SIGNED_RECEIPTS in adapter.get_capabilities()

    async def test_forged_acceptance_is_indeterminate(self) -> None:
        def respond(d):
            signed = _sign(_body(digest=d))
            signed["receipt_id"] = "r-forged"
            return 200, signed

        receipt = await _adapter(respond, receipt_key_resolver=_RESOLVER).actuate(
            _clearance()
        )
        assert receipt.outcome is ActuationOutcome.UNKNOWN
        assert receipt.verification is ReceiptVerification.INVALID
        assert receipt.retryable is False
        assert "RECEIPT_SIGNATURE_INVALID" in [f["code"] for f in receipt.findings]

    async def test_replayed_receipt_for_another_order_is_indeterminate(self) -> None:
        receipt = await _adapter(
            lambda d: (200, _sign(_body(digest="e" * 64))),
            receipt_key_resolver=_RESOLVER,
        ).actuate(_clearance())
        assert receipt.outcome is ActuationOutcome.UNKNOWN
        assert receipt.verification is ReceiptVerification.INVALID

    async def test_forged_refusal_is_indeterminate(self) -> None:
        """A forged 'not executed' must not release reservations either."""

        def respond(d):
            signed = _sign({"error": "VENUE_HALT", "envelope_digest": d})
            signed["error"] = "TAMPERED"
            return 409, signed

        receipt = await _adapter(respond, receipt_key_resolver=_RESOLVER).actuate(
            _clearance()
        )
        assert receipt.outcome is ActuationOutcome.UNKNOWN
        assert receipt.may_have_executed

    async def test_unsigned_acceptance_permissive_mode(self) -> None:
        receipt = await _adapter(
            lambda d: (200, _body(digest=d)), receipt_key_resolver=_RESOLVER
        ).actuate(_clearance())
        assert receipt.outcome is ActuationOutcome.ACCEPTED
        assert receipt.verification is ReceiptVerification.UNVERIFIED

    async def test_unsigned_acceptance_strict_mode_is_indeterminate(self) -> None:
        receipt = await _adapter(
            lambda d: (200, _body(digest=d)),
            receipt_key_resolver=_RESOLVER,
            require_signed_receipts=True,
        ).actuate(_clearance())
        assert receipt.outcome is ActuationOutcome.UNKNOWN
        assert "RECEIPT_UNVERIFIED" in [f["code"] for f in receipt.findings]

    async def test_verified_refusal_strict_mode_stays_rejected(self) -> None:
        receipt = await _adapter(
            lambda d: (409, _sign({"error": "VENUE_HALT", "envelope_digest": d})),
            receipt_key_resolver=_RESOLVER,
            require_signed_receipts=True,
        ).actuate(_clearance())
        assert receipt.outcome is ActuationOutcome.REJECTED
        assert receipt.verification is ReceiptVerification.VERIFIED

    def test_strict_mode_requires_trust_anchor(self) -> None:
        with pytest.raises(ValueError, match="receipt_key_resolver"):
            _adapter(lambda d: (200, {}), require_signed_receipts=True)

    def test_capability_absent_without_trust_anchor(self) -> None:
        adapter = _adapter(lambda d: (200, {}))
        assert ActuatorCapability.SIGNED_RECEIPTS not in adapter.get_capabilities()
