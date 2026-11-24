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
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import src.integrations.actuator_01.constants as actuator_constants
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
_INTENT_OBJ: dict[str, Any] = {
    "action": "execute_trade",
    "clearance_id": "c-receipt-test-001",
    "decision": "ALLOW",
    "nonce": "c" * 32,
    "thread_id": "test-thread-123",
}
_INTENT_JCS = jcs_canonicalize_plan(_INTENT_OBJ).decode("utf-8")
_DIGEST = hashlib.sha256(_INTENT_JCS.encode("utf-8")).hexdigest()
_OTHER_INTENT_JCS = jcs_canonicalize_plan({**_INTENT_OBJ, "nonce": "e" * 32}).decode(
    "utf-8"
)
_PARTNER_KEY = Ed25519PrivateKey.generate()


class _StaticResolver:
    """kid -> key map standing in for an out-of-band manifest."""

    def __init__(self, keys: dict) -> None:
        self._keys = keys

    async def get_key(self, kid: str):
        return self._keys.get(kid)


class _FailingResolver:
    async def get_key(self, kid: str):
        raise httpx.ConnectError("manifest host down")


class _SpyPublicKey:
    """Wraps an Ed25519PublicKey and counts verify() invocations."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.verify_calls: list[bytes] = []

    def verify(self, signature: bytes, data: bytes) -> None:
        self.verify_calls.append(data)
        self._inner.verify(signature, data)


_RESOLVER = _StaticResolver({_KID: _PARTNER_KEY.public_key()})


def _intent_sha256(intent_hash: str | dict[str, Any]) -> hashlib._Hash:
    if isinstance(intent_hash, str):
        return hashlib.sha256(intent_hash.encode("utf-8"))
    return hashlib.sha256(jcs_canonicalize_plan(intent_hash))


def _sign(
    body: dict[str, Any],
    key: Ed25519PrivateKey = _PARTNER_KEY,
    kid: str = _KID,
    *,
    raw_digest_bytes: bool = False,
) -> dict[str, Any]:
    """Return ``body`` with a detached partner signature over tag || SHA-256(intent_hash)."""
    digest = _intent_sha256(body["intent_hash"])
    suffix = digest.digest() if raw_digest_bytes else digest.hexdigest().encode("ascii")
    signature = key.sign(RECEIPT_SIGNATURE_DOMAIN_TAG + suffix)
    return {
        **body,
        "signature": {
            "alg": "EdDSA",
            "kid": kid,
            "value": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
        },
    }


def _body(intent_hash: Any = _INTENT_JCS) -> dict[str, Any]:
    return {
        "receipt_id": "r-1",
        "session_uuid": "s-1",
        "timestamp_ns": 1785012000000000000,
        "status": "ACCEPTED",
        "intent_hash": intent_hash,
    }


class TestVerifier:
    def test_legacy_domain_tag_retired(self) -> None:
        assert RECEIPT_SIGNATURE_DOMAIN_TAG == b"ARCHYTAN_RECEIPT_V1:"
        assert not hasattr(actuator_constants, "LEGACY_RECEIPT_SIGNATURE_DOMAIN_TAG")

    @pytest.mark.parametrize("non_signed", [None, _body()])
    async def test_unsigned_body_is_unverified(self, non_signed: Any) -> None:
        check = await verify_partner_receipt(
            non_signed, envelope_digest=_DIGEST, key_resolver=_RESOLVER
        )
        assert check.verification is ReceiptVerification.UNVERIFIED
        assert check.finding is None

    async def test_valid_signature_over_hex_sha256_intent_hash_is_verified(
        self,
    ) -> None:
        check = await verify_partner_receipt(
            _sign(_body()), envelope_digest=_DIGEST, key_resolver=_RESOLVER
        )
        assert check.verification is ReceiptVerification.VERIFIED
        assert check.finding is None

    async def test_valid_signature_over_dict_intent_hash_is_verified(self) -> None:
        check = await verify_partner_receipt(
            _sign(_body(intent_hash=_INTENT_OBJ)),
            envelope_digest=_DIGEST,
            key_resolver=_RESOLVER,
        )
        assert check.verification is ReceiptVerification.VERIFIED

    async def test_valid_signature_over_raw32_sha256_intent_hash_is_verified(
        self,
    ) -> None:
        check = await verify_partner_receipt(
            _sign(_body(), raw_digest_bytes=True),
            envelope_digest=_DIGEST,
            key_resolver=_RESOLVER,
        )
        assert check.verification is ReceiptVerification.VERIFIED

    async def test_uppercase_caller_envelope_digest_matches_case_insensitively(
        self,
    ) -> None:
        check = await verify_partner_receipt(
            _sign(_body()),
            envelope_digest=_DIGEST.upper(),
            key_resolver=_RESOLVER,
        )
        assert check.verification is ReceiptVerification.VERIFIED

    @pytest.mark.parametrize(
        "bad_intent",
        [None, "", "   ", {}, [], 123],
    )
    async def test_missing_or_empty_intent_hash_is_invalid(
        self, bad_intent: Any
    ) -> None:
        spy_key = _SpyPublicKey(_PARTNER_KEY.public_key())
        fake_sig = base64.urlsafe_b64encode(b"\x01" * 64).rstrip(b"=").decode("ascii")
        body: dict[str, Any] = {
            "receipt_id": "r-missing",
            "status": "ACCEPTED",
            "envelope_digest": _DIGEST,
            "signature": {"alg": "EdDSA", "kid": _KID, "value": fake_sig},
        }
        if bad_intent is not None:
            body["intent_hash"] = bad_intent
        check = await verify_partner_receipt(
            body,
            envelope_digest=_DIGEST,
            key_resolver=_StaticResolver({_KID: spy_key}),
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding is not None
        assert check.finding["code"] == "RECEIPT_MISSING_INTENT_HASH"
        assert spy_key.verify_calls == []

    async def test_non_canonicalizable_dict_intent_hash_is_malformed(self) -> None:
        fake_sig = base64.urlsafe_b64encode(b"\x02" * 64).rstrip(b"=").decode("ascii")
        check = await verify_partner_receipt(
            {
                "receipt_id": "r-nan",
                "status": "ACCEPTED",
                "intent_hash": {"bad": float("nan")},
                "signature": {"alg": "EdDSA", "kid": _KID, "value": fake_sig},
            },
            envelope_digest=_DIGEST,
            key_resolver=_RESOLVER,
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding is not None
        assert check.finding["code"] == "RECEIPT_SIGNATURE_MALFORMED"

    async def test_legacy_jcs_body_signature_is_rejected(self) -> None:
        """Signing JCS(body) instead of SHA-256(intent_hash) is rejected even when fields match."""
        base = {**_body(), "envelope_digest": _DIGEST}
        legacy_sig = _PARTNER_KEY.sign(
            RECEIPT_SIGNATURE_DOMAIN_TAG + jcs_canonicalize_plan(base)
        )
        check = await verify_partner_receipt(
            {
                **base,
                "signature": {
                    "alg": "EdDSA",
                    "kid": _KID,
                    "value": base64.urlsafe_b64encode(legacy_sig)
                    .rstrip(b"=")
                    .decode("ascii"),
                },
            },
            envelope_digest=_DIGEST,
            key_resolver=_RESOLVER,
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding is not None
        assert check.finding["code"] == "RECEIPT_SIGNATURE_INVALID"

    async def test_retired_legacy_domain_tag_signature_is_rejected(self) -> None:
        retired_tag = b"CAGE_ACTUATION_RECEIPT_V1:"
        retired_sig = _PARTNER_KEY.sign(retired_tag + _DIGEST.encode("ascii"))
        check = await verify_partner_receipt(
            {
                **_body(),
                "signature": {
                    "alg": "EdDSA",
                    "kid": _KID,
                    "value": base64.urlsafe_b64encode(retired_sig)
                    .rstrip(b"=")
                    .decode("ascii"),
                },
            },
            envelope_digest=_DIGEST,
            key_resolver=_RESOLVER,
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding is not None
        assert check.finding["code"] == "RECEIPT_SIGNATURE_INVALID"

    async def test_forged_signature_is_invalid(self) -> None:
        signed = _sign(_body())
        corrupted = bytearray(
            base64.urlsafe_b64decode(signed["signature"]["value"] + "==")
        )
        corrupted[0] ^= 0xFF
        signed["signature"]["value"] = (
            base64.urlsafe_b64encode(bytes(corrupted)).rstrip(b"=").decode("ascii")
        )
        check = await verify_partner_receipt(
            signed, envelope_digest=_DIGEST, key_resolver=_RESOLVER
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding is not None
        assert check.finding["code"] == "RECEIPT_SIGNATURE_INVALID"

    async def test_tampered_intent_hash_is_envelope_mismatch_before_verify(
        self,
    ) -> None:
        spy_key = _SpyPublicKey(_PARTNER_KEY.public_key())
        signed = _sign(_body())
        signed["intent_hash"] = _OTHER_INTENT_JCS
        check = await verify_partner_receipt(
            signed,
            envelope_digest=_DIGEST,
            key_resolver=_StaticResolver({_KID: spy_key}),
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding is not None
        assert check.finding["code"] == "RECEIPT_ENVELOPE_MISMATCH"
        assert spy_key.verify_calls == []

    async def test_conflicting_optional_envelope_digest_field_is_rejected(
        self,
    ) -> None:
        signed = _sign({**_body(), "envelope_digest": "f" * 64})
        check = await verify_partner_receipt(
            signed, envelope_digest=_DIGEST, key_resolver=_RESOLVER
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding is not None
        assert check.finding["code"] == "RECEIPT_ENVELOPE_MISMATCH"

    async def test_unknown_kid_is_invalid(self) -> None:
        check = await verify_partner_receipt(
            _sign(_body(), kid="rotated-out"),
            envelope_digest=_DIGEST,
            key_resolver=_RESOLVER,
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding is not None
        assert check.finding["code"] == "RECEIPT_UNKNOWN_KID"

    async def test_signature_by_an_unlisted_key_is_invalid(self) -> None:
        """A key embedded nowhere in the manifest cannot vouch for a receipt."""
        check = await verify_partner_receipt(
            _sign(_body(), key=Ed25519PrivateKey.generate()),
            envelope_digest=_DIGEST,
            key_resolver=_RESOLVER,
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding is not None
        assert check.finding["code"] == "RECEIPT_SIGNATURE_INVALID"

    async def test_receipt_for_another_envelope_is_invalid(self) -> None:
        check = await verify_partner_receipt(
            _sign(_body(intent_hash=_OTHER_INTENT_JCS)),
            envelope_digest=_DIGEST,
            key_resolver=_RESOLVER,
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding is not None
        assert check.finding["code"] == "RECEIPT_ENVELOPE_MISMATCH"

    async def test_flat_signed_receipt_without_intent_hash_is_invalid(self) -> None:
        """A flat-signed body with no intent_hash proves nothing about this clearance."""
        resolver = _StaticResolver({"k1": _PARTNER_KEY.public_key()})
        captured = {
            "receipt_id": "r-old",
            "session_uuid": "s-old",
            "status": "ACCEPTED",
            "kid": "k1",
        }
        sig_hex = _PARTNER_KEY.sign(
            RECEIPT_SIGNATURE_DOMAIN_TAG + jcs_canonicalize_plan(captured)
        ).hex()
        check = await verify_partner_receipt(
            {**captured, "signature": sig_hex},
            envelope_digest=_DIGEST,
            key_resolver=resolver,
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding is not None
        assert check.finding["code"] == "RECEIPT_MISSING_INTENT_HASH"

    @pytest.mark.parametrize(
        "signature",
        [
            "",
            "not-an-object",
            12345,
            {**_sign(_body())["signature"], "alg": "none"},
            {"alg": "EdDSA", "kid": "", "value": "AAAA"},
            {"alg": "EdDSA", "kid": _KID, "value": ""},
            {"alg": "EdDSA", "kid": _KID, "value": "AAAA"},  # wrong length
        ],
    )
    async def test_malformed_signature_is_invalid(self, signature: Any) -> None:
        check = await verify_partner_receipt(
            {**_body(), "signature": signature},
            envelope_digest=_DIGEST,
            key_resolver=_RESOLVER,
        )
        assert check.verification is ReceiptVerification.INVALID
        assert check.finding is not None
        assert check.finding["code"] == "RECEIPT_SIGNATURE_MALFORMED"

    async def test_no_trust_anchor_is_unverified(self) -> None:
        check = await verify_partner_receipt(
            _sign(_body()), envelope_digest=_DIGEST, key_resolver=None
        )
        assert check.verification is ReceiptVerification.UNVERIFIED
        assert check.finding is not None
        assert check.finding["code"] == "RECEIPT_TRUST_ANCHOR_UNCONFIGURED"

    @pytest.mark.covers(
        "src.integrations.actuator_01.receipt_verifier:verify_partner_receipt#RECEIPT_KEY_MANIFEST_UNAVAILABLE"
    )
    async def test_manifest_unavailable_is_unverified(self) -> None:
        check = await verify_partner_receipt(
            _sign(_body()), envelope_digest=_DIGEST, key_resolver=_FailingResolver()
        )
        assert check.verification is ReceiptVerification.UNVERIFIED
        assert check.finding is not None
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
            ),
            encoding="utf-8",
        )
        client = Ed25519KeyManifestClient(f"file://{manifest}")
        assert await client.get_key(_KID) is not None
        assert await client.get_key("unknown") is None

        check = await verify_partner_receipt(
            _sign(_body()), envelope_digest=_DIGEST, key_resolver=client
        )
        assert check.verification is ReceiptVerification.VERIFIED

    async def test_warm_cache_refreshes_once_on_rotated_kid(self) -> None:
        key_v1 = Ed25519PrivateKey.generate()
        key_v2 = Ed25519PrivateKey.generate()
        x1 = (
            base64.urlsafe_b64encode(
                key_v1.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            )
            .rstrip(b"=")
            .decode("ascii")
        )
        x2 = (
            base64.urlsafe_b64encode(
                key_v2.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            )
            .rstrip(b"=")
            .decode("ascii")
        )
        resp_v1 = MagicMock()
        resp_v1.json.return_value = {
            "keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k-v1", "x": x1}]
        }
        resp_v1.raise_for_status = MagicMock()

        resp_v2 = MagicMock()
        resp_v2.json.return_value = {
            "keys": [
                {"kty": "OKP", "crv": "Ed25519", "kid": "k-v1", "x": x1},
                {"kty": "OKP", "crv": "Ed25519", "kid": "k-v2", "x": x2},
            ]
        }
        resp_v2.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_http_cls:
            http_inst = AsyncMock()
            http_inst.get.side_effect = [resp_v1, resp_v2, resp_v2]
            mock_http_cls.return_value.__aenter__.return_value = http_inst

            client = Ed25519KeyManifestClient(
                "https://keys.example.com/jwks.json", cache_ttl_seconds=3600
            )
            resolved_1 = await client.get_key("k-v1")
            assert resolved_1 is not None
            assert http_inst.get.call_count == 1

            # Warm-cache hit does not re-fetch
            assert await client.get_key("k-v1") is not None
            assert http_inst.get.call_count == 1

            # Warm-cache miss triggers exactly one refresh and finds rotated k-v2
            resolved_2 = await client.get_key("k-v2")
            assert resolved_2 is not None
            assert (
                resolved_2.public_bytes_raw() == key_v2.public_key().public_bytes_raw()
            )
            assert http_inst.get.call_count == 2

            # Absent kid on warm cache refreshes once (total=3) and returns None
            assert await client.get_key("k-missing") is None
            assert http_inst.get.call_count == 3

    async def test_expired_cache_refreshes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        key_v1 = Ed25519PrivateKey.generate()
        key_v2 = Ed25519PrivateKey.generate()
        manifest = tmp_path / "jwks.json"
        x1 = (
            base64.urlsafe_b64encode(key_v1.public_key().public_bytes_raw())
            .rstrip(b"=")
            .decode("ascii")
        )
        x2 = (
            base64.urlsafe_b64encode(key_v2.public_key().public_bytes_raw())
            .rstrip(b"=")
            .decode("ascii")
        )
        manifest.write_text(
            json.dumps(
                {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k-same", "x": x1}]}
            ),
            encoding="utf-8",
        )
        now = 1000.0
        monkeypatch.setattr(
            "src.integrations.trust.key_manifest.time.time", lambda: now
        )

        client = Ed25519KeyManifestClient(f"file://{manifest}", cache_ttl_seconds=60)
        first = await client.get_key("k-same")
        assert first is not None
        assert first.public_bytes_raw() == key_v1.public_key().public_bytes_raw()

        # Overwrite manifest with rotated bytes under same kid; before TTL expiry cached key stays
        manifest.write_text(
            json.dumps(
                {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k-same", "x": x2}]}
            ),
            encoding="utf-8",
        )
        now = 1050.0
        cached = await client.get_key("k-same")
        assert cached is not None
        assert cached.public_bytes_raw() == key_v1.public_key().public_bytes_raw()

        # Past TTL expiry (> 60s), cache refreshes and loads new key
        now = 1061.0
        refreshed = await client.get_key("k-same")
        assert refreshed is not None
        assert refreshed.public_bytes_raw() == key_v2.public_key().public_bytes_raw()

    def test_rejects_disallowed_scheme_and_supports_scheme_narrowing(self) -> None:
        with pytest.raises(ValueError, match="Invalid JWKS URL scheme"):
            Ed25519KeyManifestClient("ftp://keys.example.com/jwks.json")

        with pytest.raises(ValueError, match="Invalid JWKS URL scheme"):
            Ed25519KeyManifestClient(
                "file:///tmp/jwks.json", allowed_schemes=("http", "https")
            )

        with pytest.raises(ValueError, match="allowed_schemes"):
            Ed25519KeyManifestClient(
                "https://keys.example.com/jwks.json", allowed_schemes=()
            )

        with pytest.raises(ValueError, match="allowed_schemes"):
            Ed25519KeyManifestClient(
                "https://keys.example.com/jwks.json", allowed_schemes=("ftp",)
            )

    async def test_rejects_malformed_jwks_and_skips_non_ed25519_entries(
        self, tmp_path: Path
    ) -> None:
        bad_manifest = tmp_path / "bad.json"
        bad_manifest.write_text(json.dumps({"keys": "not-a-list"}), encoding="utf-8")
        bad_client = Ed25519KeyManifestClient(f"file://{bad_manifest}")
        with pytest.raises(ValueError, match="missing 'keys' array"):
            await bad_client.get_key(_KID)

        raw = _PARTNER_KEY.public_key().public_bytes_raw()
        mixed_manifest = tmp_path / "mixed.json"
        mixed_manifest.write_text(
            json.dumps(
                {
                    "keys": [
                        "not-a-dict",
                        {
                            "kty": "RSA",
                            "crv": "Ed25519",
                            "kid": "rsa-1",
                            "x": base64.urlsafe_b64encode(raw)
                            .rstrip(b"=")
                            .decode("ascii"),
                        },
                        {
                            "kty": "OKP",
                            "crv": "X25519",
                            "kid": "x-1",
                            "x": base64.urlsafe_b64encode(raw)
                            .rstrip(b"=")
                            .decode("ascii"),
                        },
                        {"kty": "OKP", "crv": "Ed25519", "kid": "", "x": "AAAA"},
                        {
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "kid": "bad-bytes",
                            "x": "AAAA",
                        },
                        {
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "kid": _KID,
                            "x": base64.urlsafe_b64encode(raw)
                            .rstrip(b"=")
                            .decode("ascii"),
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        mixed_client = Ed25519KeyManifestClient(f"file://{mixed_manifest}")
        assert await mixed_client.get_key("rsa-1") is None
        assert await mixed_client.get_key("x-1") is None
        assert await mixed_client.get_key("bad-bytes") is None
        assert await mixed_client.get_key(_KID) is not None


class TestReceiptInvariant:
    def test_invalid_signature_cannot_be_accepted(self) -> None:
        with pytest.raises(ValueError, match="INVALID"):
            ActuationReceipt(
                accepted=True,
                receipt_id="r",
                session_uuid=None,
                raw_receipt=None,
                outcome=ActuationOutcome.ACCEPTED,
                verification=ReceiptVerification.INVALID,
            )


# ── Adapter integration ───────────────────────────────────────────────────


class _Signer:
    is_kms_active = True

    def sign_raw(self, message: bytes) -> bytes:
        return hashlib.sha512(message).digest()[:64]

    async def sign_raw_async(self, message: bytes) -> bytes:
        return self.sign_raw(message)


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
    """Adapter whose partner answers with ``respond(intent_jcs)``."""

    async def submit(canonical_bytes, **_):
        status, body = respond(canonical_bytes.decode("utf-8"))
        return httpx.Response(status, json=body)

    client = MagicMock(spec=ActuatorHttpClient)
    client.submit_envelope = submit
    return Actuator01Adapter(client=client, signer=_Signer(), **kwargs)  # type: ignore[arg-type]


class TestAdapterReceiptVerification:
    async def test_verified_acceptance(self) -> None:
        adapter = _adapter(
            lambda intent: (200, _sign(_body(intent_hash=intent))),
            receipt_key_resolver=_RESOLVER,
        )
        receipt = await adapter.actuate(_clearance())
        assert receipt.outcome is ActuationOutcome.ACCEPTED
        assert receipt.verification is ReceiptVerification.VERIFIED
        assert ActuatorCapability.SIGNED_RECEIPTS in adapter.get_capabilities()

    async def test_forged_acceptance_is_indeterminate(self) -> None:
        def respond(intent: str):
            signed = _sign(_body(intent_hash=intent), key=Ed25519PrivateKey.generate())
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
            lambda _intent: (200, _sign(_body(intent_hash=_OTHER_INTENT_JCS))),
            receipt_key_resolver=_RESOLVER,
        ).actuate(_clearance())
        assert receipt.outcome is ActuationOutcome.UNKNOWN
        assert receipt.verification is ReceiptVerification.INVALID
        assert "RECEIPT_ENVELOPE_MISMATCH" in [f["code"] for f in receipt.findings]

    async def test_replayed_flat_receipt_without_intent_hash_is_indeterminate(
        self,
    ) -> None:
        """A captured flat-signed receipt with no intent_hash must not count
        as proof that the partner executed this order."""
        resolver = _StaticResolver({"default": _PARTNER_KEY.public_key()})
        captured = {
            "receipt_id": "r-old",
            "session_uuid": "s-old",
            "status": "ACCEPTED",
        }
        sig_hex = _PARTNER_KEY.sign(
            RECEIPT_SIGNATURE_DOMAIN_TAG + jcs_canonicalize_plan(captured)
        ).hex()
        receipt = await _adapter(
            lambda _intent: (200, {**captured, "signature": sig_hex}),
            receipt_key_resolver=resolver,
        ).actuate(_clearance())
        assert receipt.outcome is ActuationOutcome.UNKNOWN
        assert receipt.verification is ReceiptVerification.INVALID
        assert "RECEIPT_MISSING_INTENT_HASH" in [f["code"] for f in receipt.findings]

    async def test_forged_refusal_is_indeterminate(self) -> None:
        """A forged 'not executed' must not release reservations either."""

        def respond(intent: str):
            signed = _sign(
                {"error": "VENUE_HALT", "intent_hash": intent},
                key=Ed25519PrivateKey.generate(),
            )
            return 409, signed

        receipt = await _adapter(respond, receipt_key_resolver=_RESOLVER).actuate(
            _clearance()
        )
        assert receipt.outcome is ActuationOutcome.UNKNOWN
        assert receipt.may_have_executed

    async def test_unsigned_acceptance_permissive_mode(self) -> None:
        receipt = await _adapter(
            lambda intent: (200, _body(intent_hash=intent)),
            receipt_key_resolver=_RESOLVER,
            require_signed_receipts=False,
        ).actuate(_clearance())
        assert receipt.outcome is ActuationOutcome.ACCEPTED
        assert receipt.verification is ReceiptVerification.UNVERIFIED

    async def test_unsigned_acceptance_rejected_by_default_when_resolver_configured(
        self,
    ) -> None:
        """When receipt_key_resolver is configured, require_signed_receipts defaults to True."""
        receipt = await _adapter(
            lambda intent: (200, _body(intent_hash=intent)),
            receipt_key_resolver=_RESOLVER,
        ).actuate(_clearance())
        assert receipt.outcome is ActuationOutcome.UNKNOWN
        assert receipt.verification is ReceiptVerification.UNVERIFIED
        assert "RECEIPT_UNVERIFIED" in [f["code"] for f in receipt.findings]

    async def test_unsigned_acceptance_strict_mode_is_indeterminate(self) -> None:
        receipt = await _adapter(
            lambda intent: (200, _body(intent_hash=intent)),
            receipt_key_resolver=_RESOLVER,
            require_signed_receipts=True,
        ).actuate(_clearance())
        assert receipt.outcome is ActuationOutcome.UNKNOWN
        assert "RECEIPT_UNVERIFIED" in [f["code"] for f in receipt.findings]

    async def test_verified_refusal_strict_mode_stays_rejected(self) -> None:
        receipt = await _adapter(
            lambda intent: (
                400,
                _sign({"error": "VENUE_HALT", "intent_hash": intent}),
            ),
            receipt_key_resolver=_RESOLVER,
            require_signed_receipts=True,
        ).actuate(_clearance())
        assert receipt.outcome is ActuationOutcome.REJECTED
        assert receipt.verification is ReceiptVerification.VERIFIED

    def test_strict_mode_requires_trust_anchor(self) -> None:
        with pytest.raises(ValueError, match="receipt_key_resolver"):
            _adapter(lambda _intent: (200, {}), require_signed_receipts=True)

    def test_capability_absent_without_trust_anchor(self) -> None:
        adapter = _adapter(lambda _intent: (200, {}))
        assert ActuatorCapability.SIGNED_RECEIPTS not in adapter.get_capabilities()

    async def test_actuator_01_flat_signature_and_ingress_signature_unverified_without_resolver(
        self,
    ) -> None:
        """Always-on flat signature + ingress_signature stays ACCEPTED when no manifest URL is set."""
        receipt = await _adapter(
            lambda intent: (
                200,
                {
                    "receipt_id": "r-actuator01-1",
                    "session_uuid": "s-actuator01-1",
                    "status": "ACCEPTED",
                    "intent_hash": intent,
                    "signature": "a" * 128,
                    "ingress_signature": "b" * 128,
                },
            ),
            receipt_key_resolver=None,
        ).actuate(_clearance())
        assert receipt.accepted is True
        assert receipt.outcome is ActuationOutcome.ACCEPTED
        assert receipt.verification is ReceiptVerification.UNVERIFIED

    async def test_actuator_01_flat_hex_signature_with_ingress_signature_verifies(
        self,
    ) -> None:
        """Flat 128-char hex signature verifies over tag || SHA-256(intent_hash) with ingress_signature present."""
        resolver = _StaticResolver({"default": _PARTNER_KEY.public_key()})

        def respond(intent: str):
            base = _body(intent_hash=intent)
            digest_hex = hashlib.sha256(intent.encode("utf-8")).hexdigest()
            sig_hex = (
                _PARTNER_KEY.sign(
                    RECEIPT_SIGNATURE_DOMAIN_TAG + digest_hex.encode("ascii")
                )
                .hex()
                .lower()
            )
            return 200, {
                **base,
                "signature": sig_hex,
                "ingress_signature": "c" * 128,
            }

        receipt = await _adapter(respond, receipt_key_resolver=resolver).actuate(
            _clearance()
        )
        assert receipt.accepted is True
        assert receipt.outcome is ActuationOutcome.ACCEPTED
        assert receipt.verification is ReceiptVerification.VERIFIED

    async def test_actuator_01_default_sandbox_kid_and_4xx_synthesized_session_uuid(
        self,
    ) -> None:
        """Flat receipt resolves archytan-sandbox-receipt-2026-01 by default and 4xx preserves session_uuid."""
        assert RECEIPT_SIGNATURE_DOMAIN_TAG == b"ARCHYTAN_RECEIPT_V1:"
        resolver = _StaticResolver(
            {"archytan-sandbox-receipt-2026-01": _PARTNER_KEY.public_key()}
        )
        synthesized_session = "b94f6f12-8b77-5c21-9b83-1029384756ab"

        def respond(intent: str):
            digest_hex = hashlib.sha256(intent.encode("utf-8")).hexdigest()
            base = {
                "error": "REPLAY_DETECTED",
                "message": "Nonce already consumed",
                "receipt_id": "r-rej-403",
                "session_uuid": synthesized_session,
                "intent_hash": intent,
            }
            sig_hex = _PARTNER_KEY.sign(
                b"ARCHYTAN_RECEIPT_V1:" + digest_hex.encode("ascii")
            ).hex()
            return 403, {
                **base,
                "signature": sig_hex,
                "ingress_signature": "d" * 128,
            }

        receipt = await _adapter(respond, receipt_key_resolver=resolver).actuate(
            _clearance()
        )
        assert receipt.accepted is False
        assert receipt.outcome is ActuationOutcome.REJECTED
        assert receipt.verification is ReceiptVerification.VERIFIED
        assert receipt.session_uuid == synthesized_session
        assert receipt.receipt_id == "r-rej-403"
