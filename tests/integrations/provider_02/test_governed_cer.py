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

"""Hermetic tests for Provider 02 CER sealing and receipt verification.

The positive vector is a real ``POST /api/attest`` exchange captured from the
partner node (``tests/fixtures/provider_02_native/attest_exchange_k1.json``),
so signature verification is checked against bytes the node actually signed.
The over-the-wire run lives in ``test_staging_e2e.py``.
"""

from __future__ import annotations

import base64
import copy
import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
from src.integrations.provider_02.governed_cer import (
    CER_BUNDLE_TYPE,
    GovernedCerError,
    certificate_hash_of,
    seal_governed_execution,
    topology_to_wire,
    verify_attestation,
    verify_governed_cer,
)
from src.integrations.provider_02.provider import (
    JWKCache,
    Provider02AttestationProvider,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "provider_02_native"
EXCHANGE = json.loads((FIXTURES / "attest_exchange_k1.json").read_text("utf-8"))


def _k1() -> Ed25519PublicKey:
    x = EXCHANGE["manifestKey"]["publicKeyJwk"]["x"]
    return Ed25519PublicKey.from_public_bytes(
        base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    )


def _resolver(kid: str) -> Ed25519PublicKey | None:
    return _k1() if kid == "k1" else None


def _exchange() -> tuple[dict[str, Any], dict[str, Any]]:
    return copy.deepcopy(EXCHANGE["cer"]), copy.deepcopy(EXCHANGE["response"])


def _bundle() -> dict[str, Any]:
    return json.loads((FIXTURES / "06_hitl_approval.json").read_text("utf-8"))


class TestSeal:
    def test_shape_and_hash(self) -> None:
        cer = seal_governed_execution(_bundle())
        assert cer["bundleType"] == CER_BUNDLE_TYPE
        assert cer["createdAt"] == _bundle()["completedAt"]
        assert "topology" not in cer["evidence"]
        assert cer["certificateHash"] == certificate_hash_of(cer)

    def test_deterministic(self) -> None:
        assert seal_governed_execution(_bundle()) == seal_governed_execution(_bundle())

    def test_captured_cer_hash_matches_node(self) -> None:
        cer, response = _exchange()
        assert certificate_hash_of(cer) == cer["certificateHash"]
        assert response["certificateHash"] == cer["certificateHash"]

    def test_topology_included_when_supplied(self) -> None:
        topo = topology_to_wire(FINANCIAL_ADVISOR_TOPOLOGY)
        cer = seal_governed_execution(_bundle(), topo)
        assert cer["evidence"]["topology"] == topo
        assert topo["terminalNode"] == FINANCIAL_ADVISOR_TOPOLOGY.terminal_node

    @pytest.mark.parametrize("completed_at", [None, "", "yesterday", "2026-10-06"])
    def test_requires_rfc3339_completed_at(self, completed_at: Any) -> None:
        bundle = _bundle()
        bundle["completedAt"] = completed_at
        with pytest.raises(GovernedCerError):
            seal_governed_execution(bundle)


class TestVerifyCapturedExchange:
    def test_real_receipt_verifies_against_k1(self) -> None:
        cer, response = _exchange()
        verdict = verify_attestation(cer, response, _resolver, topology_supplied=False)
        assert verdict.verified, verdict
        assert verdict.kid == "k1"
        assert verdict.attestation_id == response["attestationId"]

    def test_unknown_kid_fails_closed(self) -> None:
        cer, response = _exchange()
        verdict = verify_attestation(
            cer, response, lambda _kid: None, topology_supplied=False
        )
        assert verdict.code == "UNKNOWN_KEY"

    def test_wrong_key_fails(self) -> None:
        cer, response = _exchange()
        other = Ed25519PrivateKey.generate().public_key()
        verdict = verify_attestation(
            cer, response, lambda _kid: other, topology_supplied=False
        )
        assert verdict.code == "RECEIPT_SIGNATURE_INVALID"

    def test_tampered_receipt(self) -> None:
        cer, response = _exchange()
        response["receipt"]["timestamp"] = "1999-01-01T00:00:00Z"
        verdict = verify_attestation(cer, response, _resolver, topology_supplied=False)
        assert verdict.code == "RECEIPT_SIGNATURE_INVALID"

    def test_tampered_envelope_attestation(self) -> None:
        cer, response = _exchange()
        env_att = response["verificationEnvelope"]["attestation"]
        field = next(
            f
            for f in response["verificationEnvelope"]["signedFields"]["attestation"]
            if f not in {"attestationId", "kid"} and isinstance(env_att.get(f), str)
        )
        env_att[field] = env_att[field] + "x"
        verdict = verify_attestation(cer, response, _resolver, topology_supplied=False)
        assert verdict.code == "ENVELOPE_SIGNATURE_INVALID"

    def test_cer_altered_after_hashing(self) -> None:
        cer, response = _exchange()
        cer["evidence"]["bundle"]["terminalPath"] = "tampered"
        verdict = verify_attestation(cer, response, _resolver, topology_supplied=False)
        assert verdict.code == "CER_HASH_INCONSISTENT"

    def test_receipt_for_a_different_cer(self) -> None:
        _, response = _exchange()
        other = seal_governed_execution({**_bundle(), "terminalPath": "unknown"})
        verdict = verify_attestation(
            other, response, _resolver, topology_supplied=False
        )
        assert verdict.code == "CERTIFICATE_HASH_MISMATCH"

    def test_kid_mismatch(self) -> None:
        cer, response = _exchange()
        response["receipt"]["attestorKeyId"] = "k2"
        verdict = verify_attestation(cer, response, _resolver, topology_supplied=False)
        assert verdict.code == "KID_MISMATCH"

    def test_envelope_scope_insufficient(self) -> None:
        cer, response = _exchange()
        response["verificationEnvelope"]["signedFields"]["bundle"].remove("evidence")
        verdict = verify_attestation(cer, response, _resolver, topology_supplied=False)
        assert verdict.code == "ENVELOPE_SCOPE_INSUFFICIENT"

    def test_node_not_ok(self) -> None:
        cer, response = _exchange()
        response["ok"] = False
        verdict = verify_attestation(cer, response, _resolver, topology_supplied=False)
        assert verdict.code == "NODE_NOT_OK"

    def test_failed_governed_check(self) -> None:
        cer, response = _exchange()
        response["governedVerification"]["causalGraphValidity"] = "invalid"
        verdict = verify_attestation(cer, response, _resolver, topology_supplied=False)
        assert verdict.code == "GOVERNED_CHECK_FAILED"

    def test_topology_expectation(self) -> None:
        cer, response = _exchange()
        verdict = verify_attestation(cer, response, _resolver, topology_supplied=True)
        assert verdict.code == "GOVERNED_CHECK_FAILED"


def _provider_with_k1() -> Provider02AttestationProvider:
    provider = Provider02AttestationProvider(
        endpoint="https://provider02.example.com", jwk_endpoint=""
    )
    provider._jwk_cache = JWKCache(
        jwk_set={"keys": [EXCHANGE["manifestKey"]]}, last_synced=time.time()
    )
    return provider


class TestKeyResolution:
    def test_wrapped_manifest_entry(self) -> None:
        assert _provider_with_k1()._resolve_public_key("k1") is not None

    @pytest.mark.parametrize("override", [{"revoked": True}, {"status": "retired"}])
    def test_revoked_or_inactive_key_refused(self, override: dict[str, Any]) -> None:
        provider = _provider_with_k1()
        provider._jwk_cache = JWKCache(
            jwk_set={"keys": [{**EXCHANGE["manifestKey"], **override}]}
        )
        assert provider._resolve_public_key("k1") is None


def _mock_http(response: MagicMock | Exception) -> Any:
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    if isinstance(response, Exception):
        client.post = AsyncMock(side_effect=response)
    else:
        client.post = AsyncMock(return_value=response)
    return patch("httpx.AsyncClient", return_value=client), client


def _http_response(status: int, body: Any) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body
    return resp


class TestAttestBundle:
    @pytest.mark.asyncio
    async def test_posts_sealed_cer_and_verifies(self) -> None:
        cer, response = _exchange()
        patcher, client = _mock_http(_http_response(200, response))
        with (
            patcher,
            patch(
                "src.integrations.provider_02.provider.seal_governed_execution",
                return_value=cer,
            ),
        ):
            verdict = await _provider_with_k1().attest_bundle(cer["evidence"]["bundle"])
        assert verdict.verified, verdict
        url = client.post.call_args.args[0]
        assert url == "https://provider02.example.com/api/attest"
        assert client.post.call_args.kwargs["json"] == cer

    @pytest.mark.asyncio
    async def test_node_rejection_maps_reason_code(self) -> None:
        body = {
            "error": "INVALID_BUNDLE",
            "reasonCode": "TOPOLOGY_ERROR",
            "details": ["topology: cycle includes evaluator"],
        }
        patcher, _ = _mock_http(_http_response(400, body))
        with patcher:
            verdict = await _provider_with_k1().attest_bundle(_bundle())
        assert not verdict.verified
        assert verdict.code == "TOPOLOGY_ERROR"
        assert "cycle" in verdict.error

    @pytest.mark.asyncio
    async def test_transport_error_fails_closed(self) -> None:
        patcher, _ = _mock_http(httpx.ConnectError("refused"))
        with patcher:
            verdict = await _provider_with_k1().attest_bundle(_bundle())
        assert verdict.code == "TRANSPORT_ERROR"

    @pytest.mark.asyncio
    async def test_unsealable_bundle_is_not_sent(self) -> None:
        patcher, client = _mock_http(_http_response(200, {}))
        with patcher:
            verdict = await _provider_with_k1().attest_bundle(
                {**_bundle(), "completedAt": ""}
            )
        assert verdict.code == "CER_SEAL_FAILED"
        client.post.assert_not_called()


def _verify_response(
    cer: dict[str, Any], *, topology_validation: str = "valid"
) -> dict[str, Any]:
    cert_hash = cer["certificateHash"]
    return {
        "status": "verified",
        "reason": "All checks passed",
        "reasonCode": "OK",
        "certificateHash": cert_hash,
        "submittedCertificateHash": cert_hash,
        "computedCertificateHash": cert_hash,
        "governedVerification": {
            "certificateIntegrity": "valid",
            "cageSchemaValidity": "valid",
            "causalGraphValidity": "valid",
            "topologyValidation": topology_validation,
            "resourceSafety": "valid",
        },
    }


class TestVerifyGovernedCer:
    def test_valid_with_cyclic_topology(self) -> None:
        topo = topology_to_wire(FINANCIAL_ADVISOR_TOPOLOGY)
        cer = seal_governed_execution(_bundle(), topo)
        resp = _verify_response(cer, topology_validation="valid")
        verdict = verify_governed_cer(cer, resp, topology_supplied=True)
        assert verdict.verified, verdict
        assert verdict.code == "OK"
        assert verdict.certificate_hash == cer["certificateHash"]
        assert verdict.governed_verification["topologyValidation"] == "valid"

    def test_computed_hash_mismatch_rejected(self) -> None:
        topo = topology_to_wire(FINANCIAL_ADVISOR_TOPOLOGY)
        cer = seal_governed_execution(_bundle(), topo)
        resp = _verify_response(cer, topology_validation="valid")
        resp["computedCertificateHash"] = "sha256:" + "0" * 64
        verdict = verify_governed_cer(cer, resp, topology_supplied=True)
        assert not verdict.verified
        assert verdict.code == "CERTIFICATE_HASH_MISMATCH"

    def test_failed_status_maps_reason_code_and_preserves_checks(self) -> None:
        topo = topology_to_wire(FINANCIAL_ADVISOR_TOPOLOGY)
        cer = seal_governed_execution(_bundle(), topo)
        resp = _verify_response(cer, topology_validation="invalid")
        resp["status"] = "failed"
        resp["reasonCode"] = "TOPOLOGY_ERROR"
        resp["reason"] = "ILLEGAL_EXECUTED_EDGE"
        resp["computedCertificateHash"] = None
        verdict = verify_governed_cer(cer, resp, topology_supplied=True)
        assert not verdict.verified
        assert verdict.code == "TOPOLOGY_ERROR"
        assert "ILLEGAL_EXECUTED_EDGE" in verdict.error
        assert verdict.governed_verification["topologyValidation"] == "invalid"


class TestVerifyBundle:
    @pytest.mark.asyncio
    async def test_posts_sealed_cer_to_v1_cer_verify(self) -> None:
        topo = topology_to_wire(FINANCIAL_ADVISOR_TOPOLOGY)
        cer = seal_governed_execution(_bundle(), topo)
        resp = _verify_response(cer, topology_validation="valid")
        patcher, client = _mock_http(_http_response(200, resp))
        with patcher:
            verdict = await _provider_with_k1().verify_bundle(_bundle(), topo)
        assert verdict.verified, verdict
        url = client.post.call_args.args[0]
        assert url == "https://provider02.example.com/v1/cer/verify"
        assert client.post.call_args.kwargs["json"] == {"bundle": cer}
        assert verdict.governed_verification["topologyValidation"] == "valid"

    @pytest.mark.asyncio
    async def test_transport_error_fails_closed(self) -> None:
        patcher, _ = _mock_http(httpx.ConnectError("refused"))
        with patcher:
            verdict = await _provider_with_k1().verify_bundle(_bundle())
        assert not verdict.verified
        assert verdict.code == "TRANSPORT_ERROR"
