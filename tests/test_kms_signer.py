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

"""Unit tests for P4b-1 KMS provider isolation, Ed25519 hermetic signer & fail-closed verification."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.gateway.governance.kms_signer import (
    BatchGovernanceSigner,
    KMSGovernanceSigner,
    SignedRecord,
    SoftwareEd25519Provider,
    SoftwareHMACProvider,
)
from src.gateway.governance.reconciliation.daemon import (
    ExternalLedgerReconciler,
    LedgerReconciliationDaemon,
    ReconciliationResult,
)
from src.gateway.governance.signer_factory import (
    build_kms_provider,
    get_kms_provider_class,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestSoftwareEd25519HermeticSigner:
    """Test 1: SoftwareEd25519Provider end-to-end sign/verify via kid lookup and fail-closed paths."""

    def test_ed25519_sign_and_verify_decision_roundtrip_via_kid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "development")
        provider = SoftwareEd25519Provider(key_id="hermetic-ed25519-k1")
        signer = KMSGovernanceSigner(provider=provider)

        assert signer.is_kms_active is True
        assert signer.jose_alg == "EdDSA"
        assert signer.key_id == "hermetic-ed25519-k1"
        assert provider.expects_raw_message is True

        decision = {
            "action": "execute_order",
            "amount_usd": 12500.0,
            "account_id": "acct-42",
        }
        record = signer.sign_decision(decision)
        assert isinstance(record, SignedRecord)
        assert record.kid == "hermetic-ed25519-k1"
        assert record.algorithm == "SOFTWARE_ED25519"
        assert len(record.signature) == 128  # 64-byte Ed25519 signature in hex

        assert signer.verify_decision(record) is True
        assert signer.verify_decision(record.to_dict()) is True
        assert (
            signer.verify_decision(
                decision,
                record.signature,
                kid="hermetic-ed25519-k1",
            )
            is True
        )

    def test_ed25519_verify_decision_fails_closed_on_unknown_kid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "development")
        provider = SoftwareEd25519Provider(key_id="hermetic-ed25519-k1")
        signer = KMSGovernanceSigner(provider=provider)

        decision = {"action": "transfer", "amount_usd": 500.0}
        record = signer.sign_decision(decision)

        # Unknown kid must fail closed even if signature bytes are otherwise valid
        assert (
            signer.verify_decision(
                decision,
                record.signature,
                kid="unknown-rogue-kid",
            )
            is False
        )

        # Even if an attacker embeds a public key in the payload for an unknown kid,
        # verification must never use embedded keys and must fail closed.
        rogue_provider = SoftwareEd25519Provider(key_id="attacker-kid")
        rogue_signer = KMSGovernanceSigner(provider=rogue_provider)
        rogue_payload = {
            "action": "transfer",
            "amount_usd": 500.0,
            "public_key_pem": rogue_provider.get_public_key_pem().decode("utf-8"),
        }
        rogue_record = rogue_signer.sign_decision(rogue_payload)
        assert signer.verify_decision(rogue_record) is False

    def test_ed25519_verify_decision_fails_closed_on_tampered_payload(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "development")
        provider = SoftwareEd25519Provider(key_id="hermetic-ed25519-k1")
        signer = KMSGovernanceSigner(provider=provider)

        decision = {"action": "transfer", "amount_usd": 500.0}
        record = signer.sign_decision(decision)

        tampered_record = SignedRecord(
            payload={"action": "transfer", "amount_usd": 999999.0},
            signature=record.signature,
            algorithm=record.algorithm,
            kid=record.kid,
            signed_at=record.signed_at,
        )
        assert signer.verify_decision(tampered_record) is False


class TestEnforcingPostureRejectsSoftwareAndHmac:
    """Tests 2 & 3: Defect K3 fail-closed posture checks at init and verification."""

    def test_verify_decision_and_batch_reject_hmac_fallback_in_production(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # First create a signer with a non-software mock provider so init succeeds in production
        monkeypatch.setenv("CAGE_ENV", "development")
        ed_provider = SoftwareEd25519Provider(key_id="ed-key-1")
        signer = KMSGovernanceSigner(provider=ed_provider)
        valid_record = signer.sign_decision({"action": "rebalance", "amount": 100})
        assert signer.verify_decision(valid_record) is True

        # Switch to enforcing posture (production)
        monkeypatch.setenv("CAGE_ENV", "production")

        hmac_record = SignedRecord(
            payload={"action": "rebalance", "amount": 100},
            signature=valid_record.signature,
            algorithm="HMAC_SHA256_FALLBACK",
            kid="ed-key-1",
        )
        assert signer.verify_decision(hmac_record) is False
        assert (
            signer.verify_decision(
                {"action": "rebalance", "amount": 100},
                valid_record.signature,
                kid="ed-key-1",
                algorithm="HMAC_SHA256_FALLBACK",
            )
            is False
        )
        assert (
            signer.verify_decision(
                {"action": "rebalance", "amount": 100},
                "HMAC_SHA256_FALLBACK",
                kid="ed-key-1",
            )
            is False
        )

        batch_signer = BatchGovernanceSigner(signer=signer)
        assert batch_signer.verify_batch([hmac_record]) is False
        assert (
            batch_signer.verify_batch([valid_record], algorithm="HMAC_SHA256_FALLBACK")
            is False
        )

    def test_signer_init_raises_runtime_error_for_software_providers_in_production(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "production")

        ed_provider = SoftwareEd25519Provider(key_id="dev-ed25519")
        with pytest.raises(RuntimeError, match="forbidden in enforcing posture"):
            KMSGovernanceSigner(provider=ed_provider)

        hmac_provider = SoftwareHMACProvider(key_id="dev-hmac")
        with pytest.raises(RuntimeError, match="forbidden in enforcing posture"):
            KMSGovernanceSigner(provider=hmac_provider)

        with pytest.raises(RuntimeError, match="forbidden in enforcing posture"):
            build_kms_provider("ed25519")

        with pytest.raises(RuntimeError, match="forbidden in enforcing posture"):
            build_kms_provider("hmac")


class TestReconciliationDaemonFailClosedSigning:
    """Test 4: Defect K2 — reconciliation/daemon.py does NOT write to Redis when KMS signing fails."""

    def test_reconcile_aborts_redis_write_when_kms_signing_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "production")

        mock_provider = MagicMock()
        mock_provider.fetch_balance.return_value = ReconciliationResult(
            source="custody_live",
            state_scalar=250000.0,
            verified_at=1700000000.0,
        )

        redis_store: dict[str, str] = {}
        mock_redis = MagicMock()
        mock_pipe = MagicMock()

        def _setex(key: str, ttl: int, val: str) -> None:
            redis_store[key] = val

        mock_pipe.setex.side_effect = _setex
        mock_pipe.execute.return_value = []
        mock_redis.pipeline.return_value = mock_pipe
        mock_redis.incr.return_value = 1

        failing_signer = MagicMock()
        failing_signer.sign_decision.side_effect = RuntimeError(
            "Cloud KMS HSM unreachable"
        )

        daemon = LedgerReconciliationDaemon(
            provider=mock_provider,
            redis_client=mock_redis,
            account_id="acct-prod-01",
            signer=failing_signer,
        )
        assert isinstance(daemon, ExternalLedgerReconciler)

        result = daemon.reconcile()

        # Must NOT write verified_balance or any fallback signature to Redis
        assert redis_store == {}
        mock_pipe.execute.assert_not_called()
        assert daemon.failure_count == 1
        assert result.signature == ""
        assert result.error is not None
        assert "KMS signing failed" in result.error
        assert "HMAC_FALLBACK" not in str(redis_store)


class TestProviderIsolationAndFactory:
    """Verify Layer 3 provider isolation via signer_factory."""

    def test_get_kms_provider_class_resolves_cloud_and_hermetic_providers(self) -> None:
        gcp_cls = get_kms_provider_class("GCPKMSProvider")
        aws_cls = get_kms_provider_class("AWSKMSProvider")
        azure_cls = get_kms_provider_class("AzureKMSProvider")
        ed_cls = get_kms_provider_class("ed25519")
        hmac_cls = get_kms_provider_class("hmac")

        assert gcp_cls.__module__ == "src.integrations.gcp.kms_provider"
        assert aws_cls.__module__ == "src.integrations.aws.kms_provider"
        assert azure_cls.__module__ == "src.integrations.azure.kms_provider"
        assert ed_cls is SoftwareEd25519Provider
        assert hmac_cls is SoftwareHMACProvider
