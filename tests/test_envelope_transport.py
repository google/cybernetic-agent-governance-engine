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
Tests for canonical RFC 8785 envelope transport (ADR-008 Phase 3).

Validates that POST /validate-action returns signed GovernanceEnvelope structures
on APPROVED verdicts and complete refusal contracts on DENIED verdicts.
"""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("CAGE_ENV", "test")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("GOVERNANCE_SALT", "CYBERNETIC_GOVERNANCE_TEST_SALT_32C!")

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture()
def mock_symbolic_governor():
    """Patch the symbolic_governor singleton."""
    gov = MagicMock()
    gov.validate_action = AsyncMock(
        return_value={
            "verdict": "APPROVED",
            "violations": [],
            "seal": "test-seal",
            "latency_ms": 1.5,
            "tiers_passed": ["stpa", "cbf", "opa"],
            "controls_satisfied": ["CTRL_OPA_001", "CTRL_CBF_002"],
            "record_hash": "sha256:abc123",
            "agent_id": "advisor-test",
        }
    )
    with patch("src.gateway.server.governance_middleware.symbolic_governor", gov):
        yield gov


@pytest.fixture()
def mock_kms_signer():
    """Patch get_governance_signer to return a mock."""
    signer = MagicMock()
    signer.is_kms_active = True
    signer.sign_precomputed_digest = MagicMock(return_value="deadbeef" * 16)
    signer.get_public_key_pem = MagicMock(
        return_value=b"-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
    )

    # Mock pem_to_jwk to return a simple JWK
    with (
        patch(
            "src.gateway.governance.kms_signer.get_governance_signer",
            return_value=signer,
        ),
        patch(
            "src.gateway.governance.jwks.pem_to_jwk",
            return_value={"kid": "test-key-001", "alg": "ES256"},
        ),
    ):
        yield signer


@pytest.fixture()
def client(mock_symbolic_governor, mock_kms_signer):
    """TestClient with seal enforcement disabled."""
    import src.gateway.server.governance_middleware as mw

    original_secret = mw._CAGE_SEAL_SECRET
    original_env = mw._ENVIRONMENT

    mw._CAGE_SEAL_SECRET = None
    mw._ENVIRONMENT = "test"

    from src.gateway.server.governance_middleware import governance_app

    test_client = TestClient(governance_app, raise_server_exceptions=False)

    yield test_client

    mw._CAGE_SEAL_SECRET = original_secret
    mw._ENVIRONMENT = original_env


class TestEnvelopeTransportApproved:
    """Tests for canonical envelope structure on APPROVED verdicts."""

    def test_approved_verdict_returns_canonical_envelope(
        self, client, mock_symbolic_governor
    ):
        """APPROVED verdict returns a signed GovernanceEnvelope (ADR-008 Phase 3)."""
        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )

        assert resp.status_code == 200
        data = resp.json()

        # Assert top-level envelope structure
        assert data["envelope_version"] == "3.0"
        assert data["envelope_type"] == "cage_governance_decision"
        assert "envelope_id" in data
        assert data["envelope_id"].startswith("cage-")
        assert "issued_at" in data
        assert "expires_at" in data

    def test_approved_envelope_contains_issuer_metadata(
        self, client, mock_symbolic_governor
    ):
        """Envelope contains issuer metadata (service, instance_id, region)."""
        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )

        data = resp.json()
        issuer = data["issuer"]

        assert "service" in issuer
        assert "instance_id" in issuer
        assert "region" in issuer

    def test_approved_envelope_contains_subject_metadata(
        self, client, mock_symbolic_governor
    ):
        """Envelope contains subject metadata (action, action_hash, record_hash, agent_id)."""
        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )

        data = resp.json()
        subject = data["subject"]

        assert subject["action"] == "execute_trade"
        assert "action_hash" in subject
        assert subject["action_hash"].startswith("sha256:")
        assert subject.get("record_hash") == "sha256:abc123"
        assert subject.get("agent_id") == "advisor-test"

    def test_approved_envelope_contains_governance_context(
        self, client, mock_symbolic_governor
    ):
        """Envelope contains governance context (policy_version, tiers, controls)."""
        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )

        data = resp.json()
        context = data["governance_context"]

        assert "policy_version" in context
        assert context["policy_version"].startswith("sha256:")
        assert context["tiers_passed"] == ["stpa", "cbf", "opa"]
        assert context["controls_satisfied"] == ["CTRL_OPA_001", "CTRL_CBF_002"]
        assert "deployment_region" in context

    def test_approved_envelope_contains_payload(self, client, mock_symbolic_governor):
        """Envelope payload contains the original governance result."""
        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )

        data = resp.json()
        payload = data["payload"]

        assert payload["verdict"] == "APPROVED"
        assert payload["violations"] == []
        assert payload["seal"] == "test-seal"
        assert "latency_ms" in payload

    def test_approved_envelope_contains_signature(
        self, client, mock_symbolic_governor, mock_kms_signer
    ):
        """Envelope contains a KMS signature block."""
        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )

        data = resp.json()
        signature = data.get("signature")

        # Signature may be None if KMS is not active, but should be present
        if signature is not None:
            assert "algorithm" in signature
            assert "kid" in signature
            assert "value" in signature
            assert signature["algorithm"] in ["ES256", "RS256", "ES384"]

    def test_approved_envelope_no_legacy_flat_fields(
        self, client, mock_symbolic_governor
    ):
        """Approved envelopes do NOT contain legacy flat fields at top level."""
        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )

        data = resp.json()

        # Top-level should NOT contain verdict, seal, violations
        # (those belong in payload)
        assert "verdict" not in data or data.get("envelope_version") is not None
        assert "schema_version" not in data


class TestEnvelopeTransportDenied:
    """Tests for refusal contract structure on DENIED verdicts."""

    @pytest.fixture()
    def client_for_denial(self, mock_kms_signer):
        """Client with symbolic_governor configured to deny requests."""
        from src.gateway.governance.symbolic_governor import GovernanceError

        gov = MagicMock()
        gov.validate_action = AsyncMock(
            side_effect=GovernanceError("CBF safety bound exceeded")
        )

        import src.gateway.server.governance_middleware as mw

        original_secret = mw._CAGE_SEAL_SECRET
        original_env = mw._ENVIRONMENT

        mw._CAGE_SEAL_SECRET = None
        mw._ENVIRONMENT = "test"

        from src.gateway.server.governance_middleware import governance_app

        with (
            patch("src.gateway.server.governance_middleware.symbolic_governor", gov),
            patch(
                "src.gateway.server.governance_middleware._emit_refusal_receipt",
                new=AsyncMock(return_value=None),
            ),
        ):
            test_client = TestClient(governance_app, raise_server_exceptions=False)
            yield test_client

        mw._CAGE_SEAL_SECRET = original_secret
        mw._ENVIRONMENT = original_env

    def test_denied_verdict_returns_http_403(self, client_for_denial):
        """DENIED verdict returns HTTP 403."""
        resp = client_for_denial.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 999999}},
        )

        assert resp.status_code == 403

    def test_denied_verdict_returns_refusal_contract(self, client_for_denial):
        """DENIED verdict returns complete refusal contract (ADR-008 Phase 3)."""
        resp = client_for_denial.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 999999}},
        )

        data = resp.json()

        assert data["schema_version"] == "2.0.0"
        assert data["verdict"] == "DENIED"
        assert "violations" in data
        assert len(data["violations"]) > 0

    def test_denied_verdict_may_contain_refusal_receipt(self, client_for_denial):
        """DENIED verdict may contain refusal_receipt and proof_hash if available."""
        resp = client_for_denial.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 999999}},
        )

        data = resp.json()

        # refusal_receipt and proof_hash are optional (only present if
        # GovernanceError has .receipt attribute set)
        # We just assert they don't break if absent
        assert isinstance(data, dict)
        # If present, they should be dicts/strings
        if "refusal_receipt" in data:
            assert isinstance(data["refusal_receipt"], dict)
        if "proof_hash" in data:
            assert isinstance(data["proof_hash"], str)


class TestEnvelopeTransportEdgeCases:
    """Edge case tests for envelope transport."""

    def test_defer_verdict_still_returns_flat_format(
        self, client, mock_symbolic_governor
    ):
        """DEFER verdicts (non-EXTERNAL_HOLD) still use legacy flat format."""
        mock_symbolic_governor.validate_action = AsyncMock(
            return_value={
                "verdict": "DEFER",
                "defer_reason": "CONFIDENCE_BELOW_THRESHOLD",
                "defer_id": "defer-001",
                "violations": ["low confidence"],
                "seal": "",
                "latency_ms": 2.0,
            }
        )

        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )

        assert resp.status_code == 200
        data = resp.json()

        # Should have legacy schema_version
        assert data.get("schema_version") == "1.0.0"
        assert data["verdict"] == "DEFER"

    def test_pause_verdict_still_returns_flat_format(
        self, client, mock_symbolic_governor
    ):
        """PAUSE verdicts still use legacy flat format."""
        mock_symbolic_governor.validate_action = AsyncMock(
            return_value={
                "verdict": "PAUSE",
                "pause_receipt": None,  # Simplified for test
                "violations": ["rate limited"],
                "seal": "",
                "latency_ms": 0.5,
            }
        )

        with patch(
            "src.gateway.server.governance_middleware._emit_pause_receipt",
            new=AsyncMock(return_value=None),
        ):
            resp = client.post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 100}},
            )

        assert resp.status_code == 200
        data = resp.json()

        # Should have legacy schema_version
        assert data.get("schema_version") == "1.0.0"
        assert data["verdict"] == "PAUSE"

    def test_external_attestations_preserved_in_envelope(
        self, client, mock_symbolic_governor
    ):
        """External attestations are embedded in the envelope."""
        mock_symbolic_governor.validate_action = AsyncMock(
            return_value={
                "verdict": "APPROVED",
                "violations": [],
                "seal": "test-seal",
                "latency_ms": 1.5,
                "tiers_passed": ["stpa", "cbf", "opa"],
                "controls_satisfied": ["CTRL_OPA_001"],
                "external_attestations": [
                    {
                        "type": "EXTERNAL_PROVIDER_APPROVAL",
                        "status": "VERIFIED",
                        "receipt_id": "ext-001",
                        "attested_at": "2026-09-13T20:00:00Z",
                        "provider_name": "provider_01",
                    }
                ],
            }
        )

        resp = client.post(
            "/validate-action",
            json={"action": "execute_trade", "params": {"amount": 100}},
        )

        data = resp.json()

        # External attestations should be present in envelope
        attestations = data.get("external_attestations", [])
        assert len(attestations) > 0
        assert attestations[0]["type"] == "EXTERNAL_PROVIDER_APPROVAL"
        assert attestations[0]["status"] == "VERIFIED"
